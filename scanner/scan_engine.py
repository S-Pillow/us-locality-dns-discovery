"""DNS discovery scan engine using dnspython."""

from __future__ import annotations

import asyncio
import csv
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.zone

from scanner.delegation_verifier import DelegationVerificationResult, verify_delegated_child_zone
from scanner.dns_classifier import DNSResponseClass, classify_dns_response
from scanner.evidence_status import (
    is_confirmed_evidence_status,
    outcome_candidate_tested,
    outcome_ignored_unrelated_authority,
    outcome_inconclusive_dns_failure,
    outcome_suppressed_wildcard_match,
    outcome_withheld_wildcard_inconclusive,
    resolve_evidence_status,
    stamp_record_evidence_status,
)
from scanner.wildcard_attestation import (
    WildcardAttestation,
    WildcardAttestationStatus,
    candidate_differentiates,
    run_wildcard_attestation,
)
from scanner.evidence_trace import (
    _resolver_label,
    build_promotion_trace,
    build_rejection_trace,
    probe_traces_for_parent,
    promotion_traces_from_response,
)
from scanner.input_loader import load_domain_inputs, load_domains
from scanner.parent_gating import (
    decide_parent_gating_from_probe_classes,
    decision_for_fourth_level_tested_without_evidence,
    decision_for_known_parent,
    decision_for_validated_parent,
    outcome_from_parent_gating_skip,
    probe_parent_response_classes,
)
from scanner.models import (
    CancellationToken,
    DiscoveredRecord,
    DomainInputRecord,
    DomainLoadInfo,
    DomainScanResult,
    EvidenceOutcome,
    EvidenceStatus,
    FindingClassification,
    ParentGatingDecision,
    PreflightSummary,
    ProgressCallback,
    RecordType,
    ScanInput,
    ScanOptions,
    ScanPhase,
    ScanProfile,
    ScanProgressCallback,
    ScanProgressUpdate,
    ScanRunResult,
    ScanStatus,
    WordlistPlan,
)

DNS_TIMEOUT = 3.0
DNS_LIFETIME = 5.0
# Hard wall-clock cap on the async parallel record-sweep per candidate.
# The 6 queries run concurrently; worst-case latency is one query-lifetime
# (UDP timeout + TCP timeout = 2 × DNS_TIMEOUT = 6s).  We add a 1-second
# margin to absorb event-loop scheduling jitter without masking real hangs.
PER_CANDIDATE_ASYNC_BUDGET = DNS_TIMEOUT * 2 + 1.0
CANDIDATE_WARN_THRESHOLD = 250
CANDIDATE_STRONG_WARN_THRESHOLD = 500

# Recursive resolvers used for the delegation fallback (Path 3).
# Both must agree on the NS set before a DELEGATED_CHILD_ZONE_RECURSIVE finding
# is promoted.  Override via recursive_resolvers= if needed in tests.
RECURSIVE_FALLBACK_RESOLVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")

BASE_RECORD_TYPES = (
    RecordType.NS,
    RecordType.SOA,
    RecordType.A,
    RecordType.AAAA,
    RecordType.MX,
    RecordType.TXT,
    RecordType.CNAME,
    RecordType.CAA,
)

CANDIDATE_RECORD_TYPES = (
    RecordType.SOA,
    RecordType.A,
    RecordType.AAAA,
    RecordType.MX,
    RecordType.TXT,
    RecordType.CNAME,
)

# RFC 1480 geographic-locality branches used for broad 5th-level generation.
# Produces <label>.<branch>.<locality> candidates (e.g. fcs.pvt.k12.pa.us).
# Only fires when include_rfc_locality_baseline is True (NORMAL/DEEP); Light is
# unaffected because the fifth_level_enabled gate stays False in that profile.
#
# Included (7): ci=city, co=county, k12=school district, cc=community college,
#               tec=vocational-tech, pvt=private school, lib=public library.
# Excluded: state, dni, isa, nsn, fed (federal/state-level, not locality branches),
#           gen (generic, no clear US-locality evidence), mus (museum, archaic).
FIFTH_LEVEL_BRANCHES: tuple[str, ...] = ("ci", "co", "k12", "cc", "tec", "pvt", "lib")
FIFTH_LEVEL_PARENT_SOURCE = "fifth_level_parent_validation"
KNOWN_CHILD_APEX_SOURCE = "known_child_apex_delegation"
WILDCARD_PROBE_COUNT = 2
LOW_CONFIDENCE_TYPES = {RecordType.A, RecordType.AAAA, RecordType.CNAME}
SOA_AUTHORITY_NOTE = (
    "SOA discovered; zone exists even though requested record type may have no direct answer."
)
SOA_MNAME_INDICATOR_NOTE = "authoritative indicator from SOA"

# option field -> (log display name, wordlist filename)
WORDLIST_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("include_light_evidence", "Light Evidence labels", "light_evidence.txt"),
    ("include_rfc_locality_baseline", "RFC/locality baseline", "rfc1480.txt"),
    ("include_dns_common", "Common DNS/web labels", "dns_common.txt"),
    ("include_civic_departments", "Civic departments", "civic_departments.txt"),
    ("include_public_services", "Public services / portals", "public_services.txt"),
    ("include_schools_libraries", "Schools / libraries", "schools_libraries.txt"),
    ("include_delegated_manager_clues", "Delegated-manager clues", "delegated_manager_clues.txt"),
)

FIFTH_LEVEL_KNOWN_PREFIXES = (
    "www",
    "mail",
    "portal",
    "police",
    "fire",
    "library",
    "clerk",
    "records",
    "gis",
    "admin",
)

FIFTH_LEVEL_PREFIX_SOURCES = (
    "include_dns_common",
    "include_civic_departments",
    "include_public_services",
    "include_schools_libraries",
)

WILDCARD_ATTESTATION_PROBE_COUNT = 3  # ≥3 required by §2
CANDIDATE_CANCEL_CHECK_INTERVAL = 5
PARTIAL_SCAN_MESSAGE = (
    "This scan was cancelled before all domains were completed. Results are partial."
)

PHASE_HEARTBEAT_INTERVAL_SECONDS = 20

AXFR_LIGHT_PROFILE_WARNING = (
    "AXFR may slow down Light Evidence scans. For first-pass sampling, AXFR OFF is usually faster."
)


def apply_scan_profile(options: ScanOptions) -> ScanOptions:
    """Map operator scan profile to wordlist and DNS option defaults."""
    if options.scan_profile == ScanProfile.LIGHT:
        return ScanOptions(
            scan_profile=options.scan_profile,
            include_light_evidence=True,
            include_rfc_locality_baseline=False,
            include_dns_common=False,
            include_civic_departments=False,
            include_public_services=False,
            include_schools_libraries=False,
            include_delegated_manager_clues=False,
            include_custom_wordlist=options.include_custom_wordlist,
            custom_wordlist_path=options.custom_wordlist_path,
            attempt_axfr=False,
            query_authoritative_ns=True,
        )
    if options.scan_profile == ScanProfile.NORMAL:
        return ScanOptions(
            scan_profile=options.scan_profile,
            include_light_evidence=False,
            include_rfc_locality_baseline=True,
            include_dns_common=True,
            include_civic_departments=True,
            include_public_services=False,
            include_schools_libraries=False,
            include_delegated_manager_clues=False,
            include_custom_wordlist=options.include_custom_wordlist,
            custom_wordlist_path=options.custom_wordlist_path,
            attempt_axfr=options.attempt_axfr,
            query_authoritative_ns=options.query_authoritative_ns,
        )
    return ScanOptions(
        scan_profile=options.scan_profile,
        include_light_evidence=False,
        include_rfc_locality_baseline=options.include_rfc_locality_baseline,
        include_dns_common=options.include_dns_common,
        include_civic_departments=options.include_civic_departments,
        include_public_services=options.include_public_services,
        include_schools_libraries=options.include_schools_libraries,
        include_delegated_manager_clues=options.include_delegated_manager_clues,
        include_custom_wordlist=options.include_custom_wordlist,
        custom_wordlist_path=options.custom_wordlist_path,
        attempt_axfr=options.attempt_axfr,
        query_authoritative_ns=options.query_authoritative_ns,
    )


def profile_guidance(profile: ScanProfile) -> str:
    messages = {
        ScanProfile.LIGHT: (
            "Light Evidence is preferred for the first 10–25 known 3rd-level domain sample."
        ),
        ScanProfile.NORMAL: "Normal Evidence is recommended for 3–10 domains.",
        ScanProfile.DEEP: "Deep Targeted is for 1–3 domains with broader wordlists.",
    }
    return messages.get(profile, "")


def axfr_preflight_warning(scan_profile: ScanProfile, axfr_enabled: bool) -> str | None:
    """Return operator warning when Light Evidence is combined with AXFR enabled."""
    if scan_profile == ScanProfile.LIGHT and axfr_enabled:
        return AXFR_LIGHT_PROFILE_WARNING
    return None


def validate_domain_file(path: Path) -> tuple[bool, str]:
    """Validate that the domain input file exists and has an accepted extension."""
    if not path.exists():
        return False, f"Domain file not found: {path}"
    if not path.is_file():
        return False, f"Domain path is not a file: {path}"
    if path.suffix.lower() not in {".txt", ".csv"}:
        return False, f"Domain file must be .txt or .csv (got {path.suffix})"
    return True, f"Domain file OK: {path}"


def validate_wordlist_file(path: Path) -> tuple[bool, str]:
    """Validate an optional custom wordlist file."""
    if not path.exists():
        return False, f"Wordlist file not found: {path}"
    if not path.is_file():
        return False, f"Wordlist path is not a file: {path}"
    if path.suffix.lower() not in {".txt", ".csv"}:
        return False, f"Wordlist file must be .txt or .csv (got {path.suffix})"
    return True, f"Custom wordlist OK: {path}"


def _emit(message: str, progress: ProgressCallback | None, bucket: list[str]) -> None:
    bucket.append(message)
    if progress:
        progress(message)


def _display_name(name: str) -> str:
    return name.rstrip(".").lower()


def _query_name(name: str) -> str:
    return name.strip().lower().rstrip(".")


def validate_domain_input(path: Path) -> tuple[bool, str]:
    """Validate domain input file content and detect input type."""
    ok, message = validate_domain_file(path)
    if not ok:
        return ok, message

    loaded = load_domain_inputs(path)
    if loaded.error:
        return False, loaded.error
    if not loaded.domains:
        return False, "No domains found in input file after normalization."

    details = f" ({loaded.input_file_type}, {loaded.domains_loaded} domain(s))"
    if loaded.duplicate_domains_removed:
        details += f", {loaded.duplicate_domains_removed} duplicate(s) removed"
    return True, f"{message}{details}"


def _parse_label_rows(path: Path) -> list[str]:
    labels: list[str] = []
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if not row:
                    continue
                cell = row[0].strip().lower()
                if cell and not cell.startswith("#"):
                    labels.append(cell)
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            cell = line.strip().lower()
            if cell and not cell.startswith("#"):
                labels.append(cell)
    return labels


def _dedupe_labels(labels: list[str]) -> list[str]:
    return list(dict.fromkeys(label.lower() for label in labels if label))


def build_wordlist_plan(
    options: ScanOptions,
    wordlists_dir: Path,
    *,
    known_fourth_level_count: int = 0,
) -> WordlistPlan:
    """Load selected wordlist sources and compute candidate estimates."""
    resolved = apply_scan_profile(options)
    source_counts: dict[str, int] = {}
    combined: list[str] = []
    fifth_prefix: list[str] = []

    for option_field, display_name, filename in WORDLIST_SOURCES:
        if not getattr(resolved, option_field):
            continue
        path = wordlists_dir / filename
        labels = _parse_label_rows(path) if path.is_file() else []
        source_counts[display_name] = len(labels)
        combined.extend(labels)
        if option_field in FIFTH_LEVEL_PREFIX_SOURCES:
            fifth_prefix.extend(labels)

    if resolved.include_custom_wordlist and resolved.custom_wordlist_path:
        custom_labels = _parse_label_rows(resolved.custom_wordlist_path)
        source_counts["Custom wordlist"] = len(custom_labels)
        combined.extend(custom_labels)
        fifth_prefix.extend(custom_labels)

    unique_labels = _dedupe_labels(combined)
    fifth_prefix_labels = _dedupe_labels(fifth_prefix)
    fifth_level_enabled = resolved.include_rfc_locality_baseline and bool(fifth_prefix_labels)

    fourth_level_count = len(unique_labels)
    fifth_level_count = len(fifth_prefix_labels) * len(FIFTH_LEVEL_BRANCHES) if fifth_level_enabled else 0
    known_fifth = known_fourth_level_count * len(FIFTH_LEVEL_KNOWN_PREFIXES)

    return WordlistPlan(
        source_counts=source_counts,
        total_unique_labels=len(unique_labels),
        estimated_candidates_per_domain=fourth_level_count + fifth_level_count + known_fifth,
        fifth_level_enabled=fifth_level_enabled,
        fifth_level_prefix_count=len(fifth_prefix_labels),
        known_fifth_level_candidates=known_fifth,
        unique_labels=unique_labels,
        fifth_level_prefix_labels=fifth_prefix_labels,
    )


def compute_warning_level(total_candidates: int) -> str:
    """Return operator-facing warning level for total candidate estimate."""
    if total_candidates >= 50_000:
        return "very large"
    if total_candidates >= 10_000:
        return "large"
    if total_candidates >= 1_000:
        return "moderate"
    return "small"


def preflight_scan_guidance(total_candidates: int) -> tuple[str, str]:
    """Return scan-size label and operator guidance for preflight display."""
    level = compute_warning_level(total_candidates)
    messages = {
        "small": "Small scan. Good for quick validation.",
        "moderate": "Moderate scan. Good for pilot evidence batches.",
        "large": "Large scan. Consider splitting into smaller batches.",
        "very large": (
            "Very large scan. Not recommended for evidence sampling unless intentionally planned."
        ),
    }
    return level, messages[level]


def build_preflight_summary(scan_input: ScanInput) -> PreflightSummary | None:
    """Build pre-scan estimate from the current input file and options."""
    loaded = load_domain_inputs(scan_input.domain_file_path)
    if loaded.error or not loaded.domains:
        return None

    known_fourth_total = sum(len(record.known_fourth_level_domains) for record in loaded.domains)
    avg_known_fourth = known_fourth_total // max(len(loaded.domains), 1)
    plan = build_wordlist_plan(
        scan_input.options,
        scan_input.wordlists_dir,
        known_fourth_level_count=avg_known_fourth,
    )
    per_domain = plan.estimated_candidates_per_domain
    total = len(loaded.domains) * per_domain
    resolved = apply_scan_profile(scan_input.options)

    return PreflightSummary(
        domain_count=len(loaded.domains),
        wordlist_sources=plan.source_counts,
        total_unique_labels=plan.total_unique_labels,
        estimated_candidates_per_domain=per_domain,
        estimated_total_candidates=total,
        axfr_enabled=resolved.attempt_axfr,
        auth_ns_enabled=resolved.query_authoritative_ns,
        warning_level=compute_warning_level(total),
        scan_profile=scan_input.options.scan_profile.value,
        input_file_type=loaded.input_file_type,
        metadata_columns_detected=loaded.metadata_columns_detected,
        duplicate_domains_removed=loaded.duplicate_domains_removed,
        selected_domain_column=loaded.selected_domain_column,
        sample_domains_preview=loaded.sample_domains_preview,
        input_warnings=loaded.input_warnings,
        preferred_input_format_detected=loaded.preferred_input_format_detected,
    )


def _emit_progress(
    progress_update: ScanProgressCallback | None,
    *,
    domain_index: int,
    domain_total: int,
    current_domain: str,
    candidates_tested: int,
    candidates_total: int,
    domains_completed: int,
    started_at: datetime,
    phase: str = "",
    message: str = "",
    candidates_started: bool = False,
) -> None:
    if progress_update is None:
        return
    elapsed = (datetime.now() - started_at).total_seconds()
    progress_indeterminate = not (candidates_started and candidates_total > 0)
    progress_update(
        ScanProgressUpdate(
            domain_index=domain_index,
            domain_total=domain_total,
            current_domain=current_domain,
            candidates_tested=candidates_tested,
            candidates_total=candidates_total,
            domains_completed=domains_completed,
            elapsed_seconds=elapsed,
            phase=phase,
            message=message,
            candidates_started=candidates_started,
            progress_indeterminate=progress_indeterminate,
        )
    )


class _PhaseHeartbeat:
    """Emit a non-spammy log line when a slow DNS phase runs longer than expected."""

    def __init__(
        self,
        *,
        domain: str,
        phase: str,
        progress: ProgressCallback | None,
        messages: list[str],
        interval: float = PHASE_HEARTBEAT_INTERVAL_SECONDS,
    ) -> None:
        self._domain = domain
        self._phase = phase
        self._progress = progress
        self._messages = messages
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> _PhaseHeartbeat:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def _heartbeat_message(self) -> str:
        phase_lower = self._phase.lower()
        if "axfr" in phase_lower:
            return f"Still attempting AXFR for {self._domain}…"
        if "authoritative" in phase_lower or "nameserver" in phase_lower:
            return f"Still discovering authoritative nameservers for {self._domain}…"
        if "candidate" in phase_lower:
            return f"Still testing candidate names for {self._domain}…"
        if "base" in phase_lower or "soa" in phase_lower:
            return f"Still checking base SOA/NS for {self._domain}…"
        return f"Still {self._phase} for {self._domain}…"

    def _run(self) -> None:
        if self._stop.wait(self._interval):
            return
        while not self._stop.is_set():
            _emit(self._heartbeat_message(), self._progress, self._messages)
            if self._stop.wait(self._interval):
                break


def log_wordlist_plan(
    plan: WordlistPlan,
    options: ScanOptions,
    progress: ProgressCallback | None,
    messages: list[str],
) -> None:
    """Log selected wordlist sources, counts, and candidate estimates."""
    _emit("Wordlist sources used:", progress, messages)

    if not plan.source_counts:
        _emit("  (none selected — no candidate labels will be tested)", progress, messages)
    else:
        for name, count in plan.source_counts.items():
            _emit(f"  {name}: {count} labels", progress, messages)

    if options.custom_wordlist_path and not options.include_custom_wordlist:
        _emit(
            "  Custom wordlist file selected but not included (checkbox unchecked).",
            progress,
            messages,
        )
    elif not options.custom_wordlist_path:
        _emit("  Custom wordlist: not selected", progress, messages)

    _emit(f"  Total unique candidate labels: {plan.total_unique_labels}", progress, messages)
    _emit(
        f"  Estimated candidate names per base domain: {plan.estimated_candidates_per_domain}",
        progress,
        messages,
    )

    if plan.fifth_level_enabled:
        _emit(
            f"  5th-level candidate generation: enabled "
            f"({plan.fifth_level_prefix_count} prefix labels × {len(FIFTH_LEVEL_BRANCHES)} branches: "
            f"{', '.join(FIFTH_LEVEL_BRANCHES)})",
            progress,
            messages,
        )
    else:
        reason = (
            "RFC/locality baseline not selected"
            if not options.include_rfc_locality_baseline
            else "no prefix labels selected for 5th-level generation"
        )
        _emit(f"  5th-level candidate generation: disabled ({reason})", progress, messages)

    _emit(
        "  Note: selected wordlists are not complete; absence of discovered records "
        "is not proof that records or subdelegations do not exist.",
        progress,
        messages,
    )

    estimate = plan.estimated_candidates_per_domain
    if estimate > CANDIDATE_STRONG_WARN_THRESHOLD:
        _emit(
            f"  WARNING: estimated {estimate} candidates per domain is very large — "
            "scan time and noise may increase significantly.",
            progress,
            messages,
        )
    elif estimate > CANDIDATE_WARN_THRESHOLD:
        _emit(
            f"  Warning: estimated {estimate} candidates per domain may increase scan time and noise.",
            progress,
            messages,
        )


def generate_fourth_level_candidates(base_domain: str, plan: WordlistPlan) -> list[str]:
    """Build 4th-level candidate FQDNs from a wordlist plan."""
    base = _query_name(base_domain)
    return list(dict.fromkeys(f"{label}.{base}" for label in plan.unique_labels))


def generate_broad_fifth_level_candidates(base_domain: str, plan: WordlistPlan) -> list[str]:
    """Build RFC-locality 5th-level candidates when RFC baseline is enabled.

    Generates ``<prefix>.<branch>.<base_domain>`` for every combination of
    prefix label (from ``plan.fifth_level_prefix_labels``) and RFC 1480
    locality branch (``FIFTH_LEVEL_BRANCHES``).  Only runs when
    ``plan.fifth_level_enabled`` is True (requires ``include_rfc_locality_baseline``
    — always False in the Light profile).
    """
    if not plan.fifth_level_enabled:
        return []
    base = _query_name(base_domain)
    candidates: list[str] = []
    for branch in FIFTH_LEVEL_BRANCHES:
        for prefix in plan.fifth_level_prefix_labels:
            candidates.append(f"{prefix}.{branch}.{base}")
    return list(dict.fromkeys(candidates))


def generate_known_child_fifth_level_candidates(
    base_domain: str,
    input_record: DomainInputRecord | None,
) -> list[str]:
    """Targeted 5th-level probes under known 4th-level domains from system input."""
    if input_record is None:
        return []
    base = _query_name(base_domain)
    candidates: list[str] = []
    for known_fourth in input_record.known_fourth_level_domains:
        parent = _query_name(known_fourth)
        if not parent.endswith(f".{base}"):
            continue
        for prefix in FIFTH_LEVEL_KNOWN_PREFIXES:
            candidates.append(f"{prefix}.{parent}")
    return list(dict.fromkeys(candidates))


def generate_all_candidates(
    base_domain: str,
    plan: WordlistPlan,
    input_record: DomainInputRecord | None = None,
) -> tuple[list[str], list[str]]:
    """Return (4th-level candidates, 5th-level candidates) for a base domain."""
    fourth = generate_fourth_level_candidates(base_domain, plan)
    fifth = generate_broad_fifth_level_candidates(base_domain, plan)
    fifth.extend(generate_known_child_fifth_level_candidates(base_domain, input_record))
    fifth = list(dict.fromkeys(fifth))
    return fourth, fifth


def generate_candidates(base_domain: str, plan: WordlistPlan) -> list[str]:
    """Build all candidate FQDNs (legacy helper)."""
    fourth, fifth = generate_all_candidates(base_domain, plan)
    return list(dict.fromkeys(fourth + fifth))


def _implied_fourth_level_parent(candidate: str, base_domain: str) -> str | None:
    """Return the 4th-level parent implied by a 5th-level candidate name."""
    child = _display_name(candidate)
    base = _display_name(base_domain)
    if not child.endswith(f".{base}"):
        return None
    relative = child[: -(len(base) + 1)]
    parts = relative.split(".")
    if len(parts) < 2:
        return None
    parent_relative = ".".join(parts[1:])
    return f"{parent_relative}.{base}"


def _enumeration_parent(candidate: str) -> str:
    """Return the direct enumeration parent of *candidate* (first label stripped).

    For a 4th-level candidate ``mail.ci.lawrence.ma.us`` the parent is
    ``ci.lawrence.ma.us`` (the base domain).  For a 5th-level candidate
    ``admin.police.ci.lawrence.ma.us`` the parent is ``police.ci.lawrence.ma.us``.
    Used by the wildcard attestation gate to scope probes per-parent (§1).
    """
    parts = _display_name(candidate).split(".")
    return ".".join(parts[1:]) if len(parts) > 1 else candidate


def _has_delegation_signal(findings: list[DiscoveredRecord]) -> bool:
    """True when *findings* contain ZONE_SOA_DISCOVERED evidence from the record sweep.

    Used by the 29A signal gate: ``verify_delegated_child_zone`` is only invoked
    for candidates whose cheap system-resolver record sweep already shows SOA evidence
    at the candidate apex.  Real delegated zones respond with their own SOA when
    queried via the system resolver; ordinary candidates (A/CNAME/NXDOMAIN) never
    produce ZONE_SOA_DISCOVERED findings.

    Candidates with no signal — the vast majority of Light-mode candidates —
    skip the 6-auth-server NS delegation walk entirely, removing ~19 serial
    queries per candidate (the dominant M1 per-candidate cost).

    Gate condition: ``FindingClassification.ZONE_SOA_DISCOVERED`` in findings.
    """
    return any(f.classification == FindingClassification.ZONE_SOA_DISCOVERED for f in findings)


def _suppression_match_detail(
    candidate_records: list,  # list[DiscoveredRecord]
    attestation: WildcardAttestation,
) -> tuple[str, list[str]]:
    """Compute matched RR type(s) and values at wildcard-suppression time (R4c).

    Observational only — does not affect any promote/suppress decision.
    Called only after candidate_differentiates() returned None.

    Returns:
        matched_rrtype  — comma-separated RR type(s) that matched (e.g. "A")
        matched_values  — de-duplicated list of values that matched the signature
    """
    seen_type_list: list[str] = []
    seen_type_set: set[str] = set()
    value_list: list[str] = []
    value_set: set[str] = set()

    for record in candidate_records:
        rr_type = record.record_type.value if record.record_type else None
        if rr_type is None:
            continue
        if rr_type not in attestation.type_signatures:
            continue
        candidate_value = record.value or ""
        if not candidate_value:
            continue

        # Mirror the containment/membership checks from candidate_differentiates().
        if rr_type in ("A", "AAAA"):
            matched = candidate_value in attestation.address_pool
        else:
            matched = candidate_value in attestation.type_signatures[rr_type]

        if matched:
            if rr_type not in seen_type_set:
                seen_type_list.append(rr_type)
                seen_type_set.add(rr_type)
            if candidate_value not in value_set:
                value_list.append(candidate_value)
                value_set.add(candidate_value)

    return ",".join(seen_type_list), value_list


def _unique_fifth_level_parents(candidates: list[str], base_domain: str) -> set[str]:
    parents: set[str] = set()
    for candidate in candidates:
        parent = _implied_fourth_level_parent(candidate, base_domain)
        if parent:
            parents.add(_display_name(parent))
    return parents


def _name_has_usable_findings(fqdn: str, result: DomainScanResult) -> bool:
    """True when the scan already has direct DNS evidence for fqdn."""
    for record in result.records:
        if not _names_match(record.fqdn, fqdn):
            continue
        if record.classification in {
            FindingClassification.QUERY_ERROR,
            FindingClassification.SCAN_ERROR,
            FindingClassification.AXFR_BLOCKED,
            FindingClassification.NO_RECORDS_DISCOVERED,
            FindingClassification.AUTHORITATIVE_NS,
        }:
            continue
        if record.classification in {
            FindingClassification.BASE_DOMAIN_RECORD,
            FindingClassification.BASE_ZONE_EXISTS,
        }:
            continue
        return True
    return False


def _get_parent_ns_hosts(parent: str) -> list[str]:
    """Return NS hostnames for *parent* via recursive discovery."""
    hosts, _, _ = discover_authoritative_nameservers(parent)
    return hosts


def _validate_fourth_level_parent(
    parent: str,
    *,
    domain: str,
    resolver: dns.resolver.Resolver,
    result: DomainScanResult,
    wildcard_suspected: bool,
    progress: ProgressCallback | None,
    messages: list[str],
    unreachable_ns_ips: set[str] | None = None,
) -> ParentGatingDecision:
    """Directly test an implied 4th-level parent; return a structured gating decision."""
    added_records = 0
    probe_classes: list[DNSResponseClass] = []
    delegation = verify_delegated_child_zone(
        parent,
        base_domain=domain,
        send_query=_send_dns_query,
        resolve_ns_ips=_resolve_nameserver_ips,
        make_resolver=_make_resolver,
        get_parent_ns_hosts=_get_parent_ns_hosts,
        source_method=FIFTH_LEVEL_PARENT_SOURCE,
        log_sink=messages,
        recursive_resolvers=list(RECURSIVE_FALLBACK_RESOLVERS),
        unreachable_ns_ips=unreachable_ns_ips,
    )
    result.evidence_outcomes.extend(delegation.evidence_outcomes)
    ns_findings = [
        item
        for item in delegation.records
        if item.classification
        in {
            FindingClassification.DELEGATED_CHILD_ZONE,
            FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE,
        }
    ]
    ns_errors = list(delegation.errors)
    for item in delegation.records:
        if item.classification == FindingClassification.ZONE_SOA_DISCOVERED:
            item.confidence = _confidence_for(
                wildcard_suspected, item.record_type, item.classification
            )
            result.records.append(item)
            added_records += 1
    if ns_findings:
        for item in ns_findings:
            item.confidence = _confidence_for(
                wildcard_suspected, item.record_type, item.classification
            )
            result.records.append(item)
            added_records += 1
        _emit(
            f"    {delegation.log_message or f'4th-level parent: {parent} NS verified'}",
            progress,
            messages,
        )
    elif delegation.log_message:
        _emit(f"    {delegation.log_message}", progress, messages)

    parent_diagnostic_traces: list = []
    other_findings, parent_errors = _query_records(
        parent,
        CANDIDATE_RECORD_TYPES,
        resolver,
        source_method=FIFTH_LEVEL_PARENT_SOURCE,
        classification=FindingClassification.STANDARD_RECORD,
        base_domain=domain,
        log_sink=messages,
        evidence_outcomes=result.evidence_outcomes,
        response_classes=probe_classes,
        diagnostic_traces=parent_diagnostic_traces,
    )
    for item in other_findings:
        item.confidence = _confidence_for(
            wildcard_suspected, item.record_type, item.classification
        )
        result.records.append(item)
        added_records += 1

    for error in ns_errors + parent_errors:
        result.records.append(
            DiscoveredRecord(
                fqdn=parent,
                record_type=None,
                value=error,
                source_method=FIFTH_LEVEL_PARENT_SOURCE,
                classification=FindingClassification.QUERY_ERROR,
                evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
            )
        )

    if added_records > 0 or delegation.verified:
        decision = decision_for_validated_parent(parent, record_count=added_records)
        _emit(f"    {decision.diagnostic_message}", progress, messages)
        return decision

    classes_seen = set(probe_classes)
    parent_probe_traces = list(parent_diagnostic_traces)
    if not classes_seen:
        classes_seen = probe_parent_response_classes(
            parent,
            CANDIDATE_RECORD_TYPES,
            _send_dns_query,
            resolver,
        )
    if not parent_probe_traces:
        parent_probe_traces = probe_traces_for_parent(
            parent,
            CANDIDATE_RECORD_TYPES,
            _send_dns_query,
            resolver,
            source_method=FIFTH_LEVEL_PARENT_SOURCE,
        )
    saw_unrelated = any(
        item.evidence_status == EvidenceStatus.IGNORED_UNRELATED_AUTHORITY
        and _names_match(item.fqdn, parent)
        for item in delegation.evidence_outcomes
    ) or any(
        item.evidence_status == EvidenceStatus.IGNORED_UNRELATED_AUTHORITY
        and _names_match(item.fqdn, parent)
        for item in result.evidence_outcomes
    )
    decision = decide_parent_gating_from_probe_classes(
        parent,
        classes_seen,
        saw_unrelated_authority=saw_unrelated,
        evidence_trace=parent_probe_traces,
    )
    _emit(f"    {decision.diagnostic_message}", progress, messages)
    return decision


def _probe_known_child_apex_delegation(
    parent: str,
    *,
    domain: str,
    result: DomainScanResult,
    wildcard_suspected: bool,
    messages: list[str],
) -> None:
    """Probe a known 4th-level domain's apex for delegation via D2's Path-3 only.

    Authoritative paths are forced empty (``parent_ns_hosts=[]``, no
    ``get_parent_ns_hosts``) so ``verify_delegated_child_zone`` falls
    straight through to ``_verify_via_recursive_fallback``.  Any resulting
    ``DELEGATED_CHILD_ZONE_RECURSIVE`` records are appended to *result* with
    the same confidence logic used elsewhere for recursive findings.
    """
    delegation = verify_delegated_child_zone(
        parent,
        base_domain=domain,
        send_query=_send_dns_query,
        resolve_ns_ips=_resolve_nameserver_ips,
        make_resolver=_make_resolver,
        parent_ns_hosts=[],
        source_method=KNOWN_CHILD_APEX_SOURCE,
        log_sink=messages,
        recursive_resolvers=list(RECURSIVE_FALLBACK_RESOLVERS),
    )
    result.evidence_outcomes.extend(delegation.evidence_outcomes)
    ns_findings = [
        item
        for item in delegation.records
        if item.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
    ]
    if ns_findings:
        for item in ns_findings:
            # D2 already marks recursive records confidence="low"; preserve that.
            # _confidence_for is wildcard-aware but only lowers auth findings.
            result.records.append(item)
        _emit(
            f"    Known-child apex probe: {delegation.log_message or f'{parent} delegation confirmed (resolver-derived)'}",
            None,
            messages,
        )
    elif delegation.log_message:
        _emit(f"    Known-child apex probe: {delegation.log_message}", None, messages)


def _make_resolver(nameserver: str | None = None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    return resolver


def _format_rdata(record_type: RecordType, rdata) -> str:
    if record_type == RecordType.SOA:
        return (
            f"{rdata.mname} {rdata.rname} serial={rdata.serial} "
            f"refresh={rdata.refresh} retry={rdata.retry} expire={rdata.expire} minimum={rdata.minimum}"
        )
    if record_type == RecordType.MX:
        return f"{rdata.preference} {rdata.exchange}"
    if record_type == RecordType.TXT:
        return " ".join(part.decode() if isinstance(part, bytes) else str(part) for part in rdata.strings)
    if record_type == RecordType.CAA:
        value = rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
        return f"{rdata.flags} {rdata.tag} {value}"
    return rdata.to_text().rstrip(".")


def _dns_name(fqdn: str) -> dns.name.Name:
    return dns.name.from_text(_query_name(fqdn) + ".")


def _names_match(left: str, right: str) -> bool:
    return _display_name(left) == _display_name(right)


def _normalize_dns_error_text(error: str) -> str:
    """Map low-level DNS/transport errors to plain operator wording."""
    lower = error.lower()
    if "errno 10051" in lower or "network unreachable" in lower or "unreachable network" in lower:
        return "network unreachable"
    if "timeout" in lower:
        return "timed out"
    if "refused" in lower or "notauth" in lower or "servfail" in lower:
        return "query refused or blocked"
    if "no resolver" in lower:
        return "no resolver configured"
    if "unknown error" in lower and "errno" in lower:
        return "network unreachable / socket error"
    return "DNS query error"


def _is_unreachable_error(error: str) -> bool:
    """True for instant OS-level network-unreachable failures (ENETUNREACH / WSAENETUNREACH).

    These are cheap immediate OSError returns, not timeouts.  Only this shape
    triggers the 29B short-circuit — timeout, SERVFAIL, and REFUSED must not be
    short-circuited because they are real DNS responses or real network conditions.

    Checks both the normalised form (covers Windows/Linux "network unreachable"
    variants) and Linux-specific ``[Errno 101]`` which reads "Network is
    unreachable" rather than the canonical "network unreachable" substring.
    """
    normed = _normalize_dns_error_text(error)
    if normed in ("network unreachable", "network unreachable / socket error"):
        return True
    lower = error.lower()
    return "[errno 101]" in lower


def _summarize_auth_ns_query_errors(
    errors: list[str],
    *,
    ns_host: str,
    domain: str,
    record_type_count: int,
) -> str:
    if not errors:
        return ""
    normalized = {_normalize_dns_error_text(error) for error in errors}
    if len(normalized) == 1:
        reason = next(iter(normalized))
    else:
        reason = " / ".join(sorted(normalized))
    type_label = "record type" if record_type_count == 1 else "record types"
    return (
        f"Authoritative direct query warning for {ns_host} on {domain}: {reason} "
        f"while checking {record_type_count} {type_label}. "
        f"Continuing with recursive DNS results and candidate testing."
    )


def _send_dns_query(
    fqdn: str,
    record_type: RecordType,
    resolver: dns.resolver.Resolver,
) -> tuple[dns.message.Message | None, str | None]:
    """Send a DNS query and return the full response message."""
    qname = _dns_name(fqdn)
    if not resolver.nameservers:
        return None, f"{fqdn} {record_type.value}: no resolver nameservers configured"

    query = dns.message.make_query(qname, record_type.value)
    last_error: str | None = None
    for nameserver in resolver.nameservers:
        for query_fn in (dns.query.udp, dns.query.tcp):
            try:
                return query_fn(query, nameserver, timeout=DNS_TIMEOUT), None
            except dns.exception.Timeout:
                last_error = f"{fqdn} {record_type.value}: timeout via {nameserver}"
            except OSError as exc:
                last_error = f"{fqdn} {record_type.value}: {exc}"
            except dns.exception.DNSException as exc:
                last_error = f"{fqdn} {record_type.value}: {exc.__class__.__name__}"
    return None, last_error


# ---------------------------------------------------------------------------
# Ticket 29 — async parallel record sweep
# ---------------------------------------------------------------------------


async def _async_send_dns_query(
    fqdn: str,
    record_type: RecordType,
    resolver: dns.resolver.Resolver,
) -> tuple[dns.message.Message | None, str | None]:
    """Async counterpart of :func:`_send_dns_query` using ``dns.asyncquery``.

    Mirrors the sync path exactly: UDP first, TCP fallback, same timeout.
    """
    qname = _dns_name(fqdn)
    if not resolver.nameservers:
        return None, f"{fqdn} {record_type.value}: no resolver nameservers configured"

    query = dns.message.make_query(qname, record_type.value)
    last_error: str | None = None
    for nameserver in resolver.nameservers:
        for query_fn in (dns.asyncquery.udp, dns.asyncquery.tcp):
            try:
                return await query_fn(query, nameserver, timeout=DNS_TIMEOUT), None
            except dns.exception.Timeout:
                last_error = f"{fqdn} {record_type.value}: timeout via {nameserver}"
            except OSError as exc:
                last_error = f"{fqdn} {record_type.value}: {exc}"
            except dns.exception.DNSException as exc:
                last_error = f"{fqdn} {record_type.value}: {exc.__class__.__name__}"
    return None, last_error


async def _async_query_records(
    fqdn: str,
    record_types: tuple[RecordType, ...],
    resolver: dns.resolver.Resolver,
    source_method: str,
    classification: FindingClassification,
    nameserver: str | None = None,
    confidence: str = "normal",
    base_domain: str | None = None,
    log_sink: list[str] | None = None,
    evidence_outcomes: list[EvidenceOutcome] | None = None,
    response_classes: list[DNSResponseClass] | None = None,
    diagnostic_traces: list | None = None,
) -> tuple[list[DiscoveredRecord], list[str]]:
    """Parallel record sweep: dispatch all *record_types* queries concurrently.

    All queries are fired at once via ``asyncio.gather``; the wall-clock cost
    is max(individual latencies) instead of sum.  Results are fed through the
    unchanged :func:`_query_records` classifier via a pre-fetch injection.

    A ``PER_CANDIDATE_ASYNC_BUDGET`` hard cap ensures no candidate can stall
    indefinitely even when the resolver is unresponsive.

    Claim-to-code (async dispatch/gather site):
        tasks = [asyncio.create_task(_async_send_dns_query(...)) for rt in record_types]
        raw_results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=...)
    Results flow unchanged into _query_records via _send_fn=_prefetched_send.
    """
    # --- async dispatch / gather (the hot path) ---
    tasks = [
        asyncio.create_task(_async_send_dns_query(fqdn, rt, resolver))
        for rt in record_types
    ]
    try:
        raw_results: list[tuple[dns.message.Message | None, str | None]] = (
            await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=PER_CANDIDATE_ASYNC_BUDGET,
            )
        )
    except asyncio.TimeoutError:
        for t in tasks:
            t.cancel()
        budget_error = (
            f"{fqdn}: per-candidate async budget exceeded "
            f"({PER_CANDIDATE_ASYNC_BUDGET:.1f}s)"
        )
        return [], [budget_error]

    # Build a pre-fetch map: RecordType → (response, error).
    prefetch: dict[RecordType, tuple[dns.message.Message | None, str | None]] = dict(
        zip(record_types, raw_results)
    )

    def _prefetched_send(
        _fqdn: str,
        rt: RecordType,
        _resolver: dns.resolver.Resolver,
    ) -> tuple[dns.message.Message | None, str | None]:
        return prefetch[rt]

    # --- classification through the unchanged sync path ---
    return _query_records(
        fqdn,
        record_types,
        resolver,
        source_method=source_method,
        classification=classification,
        nameserver=nameserver,
        confidence=confidence,
        base_domain=base_domain,
        log_sink=log_sink,
        evidence_outcomes=evidence_outcomes,
        response_classes=response_classes,
        diagnostic_traces=diagnostic_traces,
        _send_fn=_prefetched_send,
    )


def _owner_matches_queried(owner: str, queried: str) -> bool:
    """True when a DNS RRset owner is the queried name (normalized FQDN)."""
    return _names_match(owner, queried)


def _soa_classification(fqdn: str, base_domain: str, from_authority: bool) -> FindingClassification:
    if _names_match(fqdn, base_domain):
        return FindingClassification.BASE_ZONE_EXISTS
    if from_authority:
        return FindingClassification.ZONE_SOA_DISCOVERED
    return FindingClassification.ZONE_SOA_DISCOVERED


def _append_soa_finding(
    findings: list[DiscoveredRecord],
    *,
    fqdn: str,
    base_domain: str,
    rdata,
    ttl: int | None,
    source_method: str,
    nameserver: str | None,
    from_authority: bool,
    authoritative_response: bool,
    evidence_trace: list | None = None,
) -> None:
    classification = _soa_classification(fqdn, base_domain, from_authority)
    confidence = "high" if authoritative_response else "medium"
    value = _format_rdata(RecordType.SOA, rdata)
    finding = DiscoveredRecord(
        fqdn=_display_name(fqdn),
        record_type=RecordType.SOA,
        value=value,
        source_method=source_method,
        classification=classification,
        confidence=confidence,
        nameserver=nameserver,
        ttl=ttl,
        evidence_trace=list(evidence_trace or []),
    )
    if not any(
        item.fqdn == finding.fqdn
        and item.record_type == finding.record_type
        and item.value == finding.value
        and item.classification == finding.classification
        for item in findings
    ):
        findings.append(finding)


def _parse_dns_response(
    response: dns.message.Message,
    fqdn: str,
    record_type: RecordType,
    *,
    base_domain: str,
    source_method: str,
    classification: FindingClassification,
    nameserver: str | None,
    confidence: str = "normal",
    resolver_or_server: str | None = None,
) -> list[DiscoveredRecord]:
    """Extract owner-matching ANSWER records and AUTHORITY-section SOA evidence."""
    findings: list[DiscoveredRecord] = []
    authoritative_response = bool(response.flags & dns.flags.AA)
    saw_soa_answer = False
    promotion_traces = promotion_traces_from_response(
        response,
        fqdn,
        record_type,
        source_method=source_method,
        resolver_or_server=resolver_or_server,
        classification=classification,
        evidence_status=None,
        format_rdata=_format_rdata,
    )
    trace_by_value: dict[tuple[str, str], object] = {}
    for trace in promotion_traces:
        if trace.rr_value is not None and trace.rr_owner is not None and trace.rr_type is not None:
            trace_by_value[(trace.rr_owner, trace.rr_type, trace.rr_value)] = trace

    queried = _display_name(fqdn)
    for rrset in response.answer:
        try:
            parsed_type = RecordType(dns.rdatatype.to_text(rrset.rdtype))
        except ValueError:
            continue
        owner = _display_name(rrset.name.to_text())
        if not _owner_matches_queried(owner, queried):
            continue
        if parsed_type == RecordType.SOA:
            saw_soa_answer = True
        ttl = rrset.ttl
        for rdata in rrset:
            if parsed_type == RecordType.SOA:
                soa_value = _format_rdata(parsed_type, rdata)
                soa_trace = trace_by_value.get((owner, parsed_type.value, soa_value))
                _append_soa_finding(
                    findings,
                    fqdn=owner,
                    base_domain=base_domain,
                    rdata=rdata,
                    ttl=ttl,
                    source_method=source_method,
                    nameserver=nameserver,
                    from_authority=False,
                    authoritative_response=authoritative_response,
                    evidence_trace=[soa_trace] if soa_trace else [],
                )
                continue
            item_classification = classification
            if item_classification == FindingClassification.DELEGATED_CHILD_ZONE:
                # Delegation Verification Mode: raw parse never promotes zones.
                item_classification = FindingClassification.STANDARD_RECORD
            rr_value = _format_rdata(parsed_type, rdata)
            matched_trace = trace_by_value.get((owner, parsed_type.value, rr_value))
            finding = DiscoveredRecord(
                fqdn=owner,
                record_type=parsed_type,
                value=rr_value,
                source_method=source_method,
                classification=item_classification,
                confidence="high" if authoritative_response else confidence,
                nameserver=nameserver,
                ttl=ttl,
                evidence_trace=[matched_trace] if matched_trace else [],
            )
            findings.append(finding)

    if not saw_soa_answer:
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.SOA:
                continue
            owner = _display_name(rrset.name.to_text())
            if not _owner_matches_queried(owner, queried):
                continue
            for rdata in rrset:
                soa_value = _format_rdata(RecordType.SOA, rdata)
                owner_norm = _display_name(owner)
                auth_trace = build_promotion_trace(
                    qname=fqdn,
                    qtype=record_type.value,
                    response=response,
                    section="authority",
                    rr_owner=owner_norm,
                    rr_type="SOA",
                    rr_value=soa_value,
                    source_method=source_method,
                    resolver_or_server=resolver_or_server,
                    response_class=DNSResponseClass.NODATA_EMPTY_ANSWER,
                    evidence_status=EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME,
                    finding_type=_soa_classification(fqdn, base_domain, True),
                    promotion_reason="Owner-matching SOA in AUTHORITY section",
                )
                _append_soa_finding(
                    findings,
                    fqdn=owner,
                    base_domain=base_domain,
                    rdata=rdata,
                    ttl=rrset.ttl,
                    source_method=source_method,
                    nameserver=nameserver,
                    from_authority=True,
                    authoritative_response=authoritative_response,
                    evidence_trace=[auth_trace],
                )

    return findings


def _extract_soa_mname_hosts(domain_result: DomainScanResult) -> list[str]:
    """Return SOA MNAME hostnames discovered for the base domain."""
    hosts: list[str] = []
    for record in domain_result.records:
        if record.record_type != RecordType.SOA:
            continue
        if not _names_match(record.fqdn, domain_result.domain):
            continue
        if record.classification not in {
            FindingClassification.BASE_ZONE_EXISTS,
            FindingClassification.BASE_DOMAIN_RECORD,
            FindingClassification.ZONE_SOA_DISCOVERED,
        }:
            continue
        mname = record.value.split()[0].rstrip(".")
        if mname:
            hosts.append(_query_name(mname))
    return list(dict.fromkeys(hosts))


def _query_records(
    fqdn: str,
    record_types: tuple[RecordType, ...],
    resolver: dns.resolver.Resolver,
    source_method: str,
    classification: FindingClassification,
    nameserver: str | None = None,
    confidence: str = "normal",
    base_domain: str | None = None,
    log_sink: list[str] | None = None,
    evidence_outcomes: list[EvidenceOutcome] | None = None,
    response_classes: list[DNSResponseClass] | None = None,
    diagnostic_traces: list | None = None,
    _send_fn: Callable[..., tuple] | None = None,
) -> tuple[list[DiscoveredRecord], list[str]]:
    """Query *fqdn* for each of *record_types*; return findings and error strings.

    Every raw DNS response is classified by :func:`classify_dns_response`
    before any finding creation code may inspect it.  Responses whose class
    does not permit findings are discarded; UNRELATED_AUTHORITY responses emit
    a diagnostic line to *log_sink* when provided.

    *_send_fn* is an internal injection point used by the async parallel sweep
    (Ticket 29): when provided it is called instead of :func:`_send_dns_query`,
    allowing pre-fetched responses to flow through the unchanged classifier.
    """
    findings: list[DiscoveredRecord] = []
    errors: list[str] = []
    qname = _query_name(fqdn)
    zone_base = _display_name(base_domain or fqdn)
    resolver_label = _resolver_label(resolver, nameserver)

    def _record_diagnostic_trace(
        rc: DNSResponseClass,
        response: dns.message.Message | None,
        transport_error: str | None,
        *,
        rejection_reason: str,
        evidence_status: EvidenceStatus | None = None,
    ) -> None:
        if diagnostic_traces is None:
            return
        diagnostic_traces.append(
            build_rejection_trace(
                qname=fqdn,
                qtype=record_type.value,
                response=response,
                transport_error=transport_error,
                response_class=rc,
                source_method=source_method,
                resolver_or_server=resolver_label,
                rejection_reason=rejection_reason,
                evidence_status=evidence_status,
            )
        )

    for record_type in record_types:
        if classification == FindingClassification.DELEGATED_CHILD_ZONE:
            # Delegated child-zone claims must go through verify_delegated_child_zone.
            continue

        response, transport_error = (_send_fn or _send_dns_query)(fqdn, record_type, resolver)

        rc = classify_dns_response(response, fqdn, transport_error)
        if response_classes is not None:
            response_classes.append(rc)

        if rc == DNSResponseClass.TIMEOUT:
            errors.append(transport_error or f"{qname} {record_type.value}: timeout")
            _record_diagnostic_trace(
                rc,
                response,
                transport_error,
                rejection_reason=transport_error or "DNS query timeout",
                evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
            )
            continue

        if rc == DNSResponseClass.MALFORMED_OR_UNUSABLE:
            if transport_error:
                errors.append(transport_error)
            elif response is not None:
                try:
                    errors.append(
                        f"{qname} {record_type.value}: {dns.rcode.to_text(response.rcode())}"
                    )
                except Exception:
                    pass
            _record_diagnostic_trace(
                rc,
                response,
                transport_error,
                rejection_reason="Malformed or unusable DNS response",
                evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
            )
            continue

        if rc == DNSResponseClass.SERVFAIL:
            errors.append(f"{qname} {record_type.value}: SERVFAIL")
            _record_diagnostic_trace(
                rc,
                response,
                transport_error,
                rejection_reason=f"{qname} {record_type.value}: SERVFAIL",
                evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
            )
            continue

        if rc == DNSResponseClass.NEGATIVE_NXDOMAIN:
            _record_diagnostic_trace(
                rc,
                response,
                transport_error,
                rejection_reason=f"{qname} returned NXDOMAIN for {record_type.value}",
                evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
            )
            continue

        if rc == DNSResponseClass.UNRELATED_AUTHORITY:
            if log_sink is not None:
                log_sink.append(
                    f"Ignored unrelated authority data while checking {fqdn} ({record_type.value})"
                )
            trace = build_rejection_trace(
                qname=fqdn,
                qtype=record_type.value,
                response=response,
                transport_error=transport_error,
                response_class=rc,
                source_method=source_method,
                resolver_or_server=resolver_label,
                rejection_reason=f"Unrelated authority while checking {record_type.value}",
                evidence_status=EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
            )
            if diagnostic_traces is not None:
                diagnostic_traces.append(trace)
            if evidence_outcomes is not None:
                evidence_outcomes.append(
                    outcome_ignored_unrelated_authority(
                        fqdn,
                        source_method=source_method,
                        detail=f"Unrelated authority while checking {record_type.value}",
                        evidence_trace=[trace],
                    )
                )
            continue

        if rc == DNSResponseClass.NODATA_EMPTY_ANSWER:
            _record_diagnostic_trace(
                rc,
                response,
                transport_error,
                rejection_reason=f"NODATA/empty answer for {record_type.value}",
                evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
            )
            continue

        # rc in {OWNER_MATCHING_ANSWER, CNAME_ALIAS, REFERRAL_DELEGATION}
        parsed = _parse_dns_response(
            response,
            fqdn,
            record_type,
            base_domain=zone_base,
            source_method=source_method,
            classification=classification,
            nameserver=nameserver,
            confidence=confidence,
            resolver_or_server=resolver_label,
        )
        findings.extend(parsed)

    deduped: list[DiscoveredRecord] = []
    seen: set[tuple[str, str | None, str, str]] = set()
    for item in findings:
        key = (
            item.fqdn,
            item.record_type.value if item.record_type else None,
            item.value,
            item.classification.value,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    for item in deduped:
        stamp_record_evidence_status(item, zone_base)
    return deduped, errors


def _resolve_nameserver_ips(ns_host: str) -> list[str]:
    host = _query_name(ns_host)
    ips: list[str] = []
    resolver = _make_resolver()
    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, rdtype)
            ips.extend(answer.address for answer in answers)
        except dns.exception.DNSException:
            continue
    return list(dict.fromkeys(ips))


def _dedupe_records(records: list[DiscoveredRecord]) -> list[DiscoveredRecord]:
    deduped: list[DiscoveredRecord] = []
    seen: set[tuple[str, str | None, str, str]] = set()
    for item in records:
        key = (
            item.fqdn,
            item.record_type.value if item.record_type else None,
            item.value,
            item.classification.value,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _parent_domain(domain: str) -> str | None:
    labels = _display_name(domain).split(".")
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])


def _nameservers_from_response_answer(response: dns.message.Message, base_domain: str) -> list[str]:
    hosts: list[str] = []
    queried = _display_name(base_domain)
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.NS:
            continue
        owner = _display_name(rrset.name.to_text())
        if not _owner_matches_queried(owner, queried):
            continue
        for rdata in rrset:
            hosts.append(_query_name(rdata.target.to_text()))
    return list(dict.fromkeys(hosts))


def discover_delegation_nameservers(base_domain: str) -> tuple[list[str], list[DiscoveredRecord], list[str]]:
    """Try parent-zone authoritative servers for child NS delegation."""
    parent = _parent_domain(base_domain)
    if not parent:
        return [], [], []

    parent_ns_hosts, _, parent_errors = discover_authoritative_nameservers(parent)
    findings: list[DiscoveredRecord] = []
    errors: list[str] = list(parent_errors)
    child_ns: list[str] = []

    for ns_host in parent_ns_hosts:
        for ns_ip in _resolve_nameserver_ips(ns_host):
            response, transport_error = _send_dns_query(
                base_domain,
                RecordType.NS,
                _make_resolver(ns_ip),
            )
            if transport_error or response is None:
                if transport_error:
                    errors.append(transport_error)
                continue
            if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                continue
            child_ns.extend(_nameservers_from_response_answer(response, base_domain))
            parsed = _parse_dns_response(
                response,
                base_domain,
                RecordType.NS,
                base_domain=base_domain,
                source_method="parent_authoritative_nameserver",
                classification=FindingClassification.AUTHORITATIVE_NS,
                nameserver=f"{ns_host} ({ns_ip})",
            )
            findings.extend(
                item for item in parsed if _names_match(item.fqdn, base_domain)
            )

    return list(dict.fromkeys(child_ns)), _dedupe_records(findings), errors


def discover_authoritative_nameservers(base_domain: str) -> tuple[list[str], list[DiscoveredRecord], list[str]]:
    """Return NS hostnames plus discovery records and any query errors."""
    resolver = _make_resolver()
    findings, errors = _query_records(
        base_domain,
        (RecordType.NS,),
        resolver,
        source_method="recursive_resolver",
        classification=FindingClassification.AUTHORITATIVE_NS,
        base_domain=base_domain,
    )
    ns_hosts = [_query_name(finding.value) for finding in findings if finding.record_type == RecordType.NS]
    return list(dict.fromkeys(ns_hosts)), findings, errors


def _attempt_axfr(base_domain: str, ns_host: str, ns_ip: str) -> tuple[list[DiscoveredRecord], str]:
    zone_name = _query_name(base_domain)
    findings: list[DiscoveredRecord] = []

    try:
        xfr = dns.query.xfr(where=ns_ip, zone=zone_name, lifetime=DNS_LIFETIME)
        zone = dns.zone.from_xfr(xfr)
        origin = zone.origin
        for node_name, node in zone.nodes.items():
            absolute = node_name.derelativize(origin)
            fqdn = _display_name(absolute.to_text())
            for rdataset in node.rdatasets:
                rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                try:
                    record_type = RecordType(rdtype)
                except ValueError:
                    record_type = None
                for rdata in rdataset:
                    value = rdata.to_text().rstrip(".")
                    findings.append(
                        DiscoveredRecord(
                            fqdn=fqdn,
                            record_type=record_type,
                            value=value,
                            source_method="axfr",
                            classification=FindingClassification.AXFR_SUCCESS,
                            nameserver=f"{ns_host} ({ns_ip})",
                            ttl=rdataset.ttl,
                        )
                    )
        return findings, f"AXFR succeeded — {len(findings)} record(s) via {ns_host}"
    except dns.exception.FormError:
        return [], f"AXFR refused/blocked via {ns_host} ({ns_ip}) — normal for most zones"
    except dns.zone.NoSOA:
        return [], f"AXFR refused/blocked via {ns_host} ({ns_ip}) — no SOA in transfer"
    except dns.exception.Timeout:
        return [], f"AXFR timed out via {ns_host} ({ns_ip})"
    except OSError as exc:
        return [], f"AXFR refused/blocked via {ns_host} ({ns_ip}): {exc}"
    except dns.exception.DNSException as exc:
        return [], f"AXFR refused/blocked via {ns_host} ({ns_ip}): {exc.__class__.__name__}"


def _wildcard_probe(base_domain: str) -> tuple[bool, list[str]]:
    """Query unlikely random names; similar positive answers suggest wildcard DNS."""
    base = _query_name(base_domain)
    resolver = _make_resolver()
    token = uuid.uuid4().hex[:10]
    probe_names = [f"_wcprobe{token}{index}.{base}" for index in range(WILDCARD_PROBE_COUNT)]
    signatures: list[str] = []
    log_lines: list[str] = []

    for probe in probe_names:
        hits: list[str] = []
        for record_type in (RecordType.A, RecordType.AAAA, RecordType.CNAME):
            found, _ = _query_records(
                probe,
                (record_type,),
                resolver,
                source_method="wildcard_probe",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=base,
            )
            for item in found:
                hits.append(f"{item.record_type.value}={item.value}")
        signatures.append("|".join(sorted(hits)) if hits else "")

    positive = [sig for sig in signatures if sig]
    if len(positive) >= 2 and positive[0] == positive[1]:
        log_lines.append(
            "Wildcard suspected: two unlikely probe names returned similar answers using tested methods."
        )
        return True, log_lines

    log_lines.append("Wildcard probe: no wildcard pattern detected using tested methods.")
    return False, log_lines


def _confidence_for(
    wildcard_suspected: bool,
    record_type: RecordType | None,
    classification: FindingClassification,
) -> str:
    if wildcard_suspected and record_type in LOW_CONFIDENCE_TYPES and classification in {
        FindingClassification.STANDARD_RECORD,
        FindingClassification.DELEGATED_CHILD_ZONE,
    }:
        return "low"
    return "normal"


def _test_candidates(
    *,
    candidates: list[str],
    domain: str,
    resolver: dns.resolver.Resolver,
    result: DomainScanResult,
    wildcard_suspected: bool,
    attestation_cache: dict[str, WildcardAttestation] | None = None,
    progress: ProgressCallback | None,
    messages: list[str],
    cancel_check: Callable[[], bool] | None,
    progress_update: ScanProgressCallback | None,
    domain_index: int,
    domain_total: int,
    domains_completed: int,
    started_at: datetime,
    phase: ScanPhase,
    candidates_offset: int,
    candidates_total: int,
    validate_fifth_level_parents: bool = False,
    parent_passed: set[str] | None = None,
    parent_decisions: dict[str, ParentGatingDecision] | None = None,
    parent_failed: set[str] | None = None,
    parent_ns_cache: dict[str, list[str]] | None = None,
    ns_ip_cache: dict[str, list[str]] | None = None,
    unreachable_ns_ips: set[str] | None = None,
) -> int:
    """Test a list of candidate names; return count tested."""
    _ = parent_failed  # legacy verify scripts; decisions cache replaces this set
    if parent_decisions is None:
        parent_decisions = {}
    subdelegation_count = 0
    candidate_record_count = 0
    tested = 0
    skipped_fifth = 0
    parent_skip_counts: dict[str, int] = {}
    if not candidates:
        return tested

    # 29A Change 1: cached NS-IP resolver — memoises _resolve_nameserver_ips
    # per run so the same NS host is never re-queried across candidates.
    def _cached_resolve_ns_ips(ns_host: str) -> list[str]:
        if ns_ip_cache is None:
            return _resolve_nameserver_ips(ns_host)
        if ns_host not in ns_ip_cache:
            ns_ip_cache[ns_host] = _resolve_nameserver_ips(ns_host)
        return ns_ip_cache[ns_host]

    with _PhaseHeartbeat(
        domain=domain,
        phase=phase.value,
        progress=progress,
        messages=messages,
    ):
        for candidate_index, candidate in enumerate(candidates, start=1):
            if cancel_check and cancel_check():
                result.notes.append(PARTIAL_SCAN_MESSAGE)
                _emit(
                    "  Scan cancellation requested; stopping candidate testing for this domain.",
                    progress,
                    messages,
                )
                break

            overall_index = candidates_offset + candidate_index
            if candidate_index == 1 or candidate_index % CANDIDATE_CANCEL_CHECK_INTERVAL == 0:
                _emit_progress(
                    progress_update,
                    domain_index=domain_index,
                    domain_total=domain_total,
                    current_domain=domain,
                    candidates_tested=overall_index,
                    candidates_total=candidates_total,
                    domains_completed=domains_completed,
                    started_at=started_at,
                    phase=phase.value,
                    message=(
                        f"{phase.value}: {overall_index} / {candidates_total} candidates tested"
                    ),
                    candidates_started=True,
                )

            if (
                validate_fifth_level_parents
                and parent_passed is not None
                and parent_decisions is not None
            ):
                parent = _implied_fourth_level_parent(candidate, domain)
                if parent:
                    parent_key = _display_name(parent)

                    if parent_key not in parent_passed:
                        cached = parent_decisions.get(parent_key)
                        if cached is None:
                            if _name_has_usable_findings(parent, result):
                                cached = decision_for_validated_parent(
                                    parent_key,
                                    record_count=0,
                                )
                            else:
                                cached = _validate_fourth_level_parent(
                                    parent,
                                    domain=domain,
                                    resolver=resolver,
                                    result=result,
                                    wildcard_suspected=wildcard_suspected,
                                    progress=progress,
                                    messages=messages,
                                    unreachable_ns_ips=unreachable_ns_ips,
                                )
                            parent_decisions[parent_key] = cached
                            if cached.allow_descendants:
                                parent_passed.add(parent_key)

                        if not cached.allow_descendants:
                            skipped_fifth += 1
                            parent_skip_counts[parent_key] = parent_skip_counts.get(parent_key, 0) + 1
                            result.evidence_outcomes.append(
                                outcome_from_parent_gating_skip(candidate, cached)
                            )
                            continue

            # --- Ticket 29: parallel record sweep (async dispatch/gather) ---
            # All 6 CANDIDATE_RECORD_TYPES queries are fired concurrently via
            # asyncio.gather, reducing per-candidate wall time from sum(latencies)
            # to max(latencies).  Results flow through the unchanged classifier
            # via _prefetched_send injection inside _async_query_records.
            # The PER_CANDIDATE_ASYNC_BUDGET hard cap prevents any candidate
            # from stalling the scan on a non-responsive resolver (Lawrence §3).
            other_findings, candidate_errors = asyncio.run(
                _async_query_records(
                    candidate,
                    CANDIDATE_RECORD_TYPES,
                    resolver,
                    source_method="generated_candidate",
                    classification=FindingClassification.STANDARD_RECORD,
                    base_domain=domain,
                    log_sink=messages,
                    evidence_outcomes=result.evidence_outcomes,
                )
            )

            if _has_delegation_signal(other_findings):
                # Delegation signal: SOA evidence found — run the auth-server walk.
                # Resolve parent NS from cache (29A Change 1) so the same parent's
                # NS set is only discovered once per run across all candidates.
                parent_key = _enumeration_parent(candidate)
                if parent_ns_cache is not None and parent_key not in parent_ns_cache:
                    parent_ns_cache[parent_key] = _get_parent_ns_hosts(parent_key)
                cached_hosts = (
                    parent_ns_cache.get(parent_key) if parent_ns_cache is not None else None
                )
                delegation = verify_delegated_child_zone(
                    candidate,
                    base_domain=domain,
                    send_query=_send_dns_query,
                    resolve_ns_ips=_cached_resolve_ns_ips,
                    make_resolver=_make_resolver,
                    parent_ns_hosts=cached_hosts,
                    source_method="generated_candidate",
                    log_sink=messages,
                    recursive_resolvers=list(RECURSIVE_FALLBACK_RESOLVERS),
                    unreachable_ns_ips=unreachable_ns_ips,
                )
            else:
                # No delegation signal — skip the auth-server NS walk entirely.
                delegation = DelegationVerificationResult(
                    verified=False,
                    method="none",
                    response_class=None,
                    reason="no delegation signal in record sweep",
                    matched_owner=None,
                    source_path="unknown",
                )

            result.evidence_outcomes.extend(delegation.evidence_outcomes)
            ns_findings = [
                item
                for item in delegation.records
                if item.classification
                in {
                    FindingClassification.DELEGATED_CHILD_ZONE,
                    FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE,
                }
            ]
            ns_candidate_errors = list(delegation.errors)
            for item in delegation.records:
                if item.classification == FindingClassification.ZONE_SOA_DISCOVERED:
                    item.confidence = _confidence_for(
                        wildcard_suspected, item.record_type, item.classification
                    )
                    result.records.append(item)
                    candidate_record_count += 1
            if ns_findings:
                # Authoritative delegations increment the summary counter;
                # recursive-corroborated ones are tracked separately in export.
                auth_delegated = any(
                    f.classification == FindingClassification.DELEGATED_CHILD_ZONE
                    for f in ns_findings
                )
                if auth_delegated:
                    subdelegation_count += 1
                for item in ns_findings:
                    item.confidence = _confidence_for(
                        wildcard_suspected, item.record_type, item.classification
                    )
                    result.records.append(item)
                _emit(f"    {delegation.log_message}", progress, messages)
            elif delegation.log_message:
                _emit(f"    {delegation.log_message}", progress, messages)

            # --- Wildcard attestation gate (R4a) ---
            # Gate promotion of other_findings against the per-enumeration-parent
            # attestation.  Delegation records (ns_findings / ZONE_SOA_DISCOVERED)
            # are never gated — they are differentiation evidence by definition (§5).
            wildcard_gate_applied = False
            if other_findings and attestation_cache is not None:
                parent_key = _enumeration_parent(candidate)
                if parent_key not in attestation_cache:
                    attestation_cache[parent_key] = run_wildcard_attestation(
                        parent_key,
                        _send_dns_query,
                        resolver,
                        probe_count=WILDCARD_ATTESTATION_PROBE_COUNT,
                    )
                attestation = attestation_cache[parent_key]

                # Combine delegation evidence + other_findings for the full
                # differentiation check so that delegation records can rescue
                # a candidate whose A/AAAA happen to fall inside the pool.
                all_candidate_evidence = [
                    item
                    for item in delegation.records
                    if item.classification
                    in (
                        FindingClassification.DELEGATED_CHILD_ZONE,
                        FindingClassification.ZONE_SOA_DISCOVERED,
                    )
                ] + list(other_findings)

                if attestation.status == WildcardAttestationStatus.DETECTED:
                    # candidate_differentiates now returns the named reason (str) or
                    # None on non-differentiation — §7 forward-compat.
                    differentiation_reason = candidate_differentiates(
                        all_candidate_evidence, attestation
                    )
                    if not differentiation_reason:
                        # Response matches wildcard signature — suppress to diagnostic.
                        # Gate code path: candidate_differentiates returned None,
                        # so the promotion branch is not taken and the outcome below
                        # routes the candidate to the diagnostics sheet via T31 routing.
                        suppressed_outcome = outcome_suppressed_wildcard_match(
                            candidate,
                            parent=parent_key,
                            source_method="generated_candidate",
                        )
                        # R4c: record match detail (observational — does not change
                        # the gate decision; _suppression_match_detail mirrors the
                        # containment/membership checks from candidate_differentiates).
                        _matched_type, _matched_vals = _suppression_match_detail(
                            all_candidate_evidence, attestation
                        )
                        suppressed_outcome.matched_rrtype = _matched_type or None
                        suppressed_outcome.matched_values = _matched_vals or None
                        result.evidence_outcomes.append(suppressed_outcome)
                        for item in other_findings:
                            item.attestation_status = attestation.status.value
                        other_findings = []
                        wildcard_gate_applied = True
                    else:
                        # Differentiates — stamp attestation status + reason (§7).
                        # wildcard_signature_matched=False: signature did NOT match
                        # (candidate differentiated); reason explains how.
                        for item in other_findings:
                            item.attestation_status = attestation.status.value
                            item.wildcard_signature_matched = False
                            item.wildcard_differentiation_reason = differentiation_reason
                elif attestation.status == WildcardAttestationStatus.INCONCLUSIVE:
                    # Withhold: Light default; Deep-mode override is deferred (§3).
                    result.evidence_outcomes.append(
                        outcome_withheld_wildcard_inconclusive(
                            candidate,
                            parent=parent_key,
                            source_method="generated_candidate",
                        )
                    )
                    for item in other_findings:
                        item.attestation_status = attestation.status.value
                    other_findings = []
                    wildcard_gate_applied = True
                else:  # CLEAN
                    for item in other_findings:
                        item.attestation_status = attestation.status.value

            findings_added = 0
            for item in other_findings:
                item.confidence = _confidence_for(
                    wildcard_suspected, item.record_type, item.classification
                )
                candidate_record_count += 1
                findings_added += 1
                result.records.append(item)
            for item in delegation.records:
                if item.classification == FindingClassification.DELEGATED_CHILD_ZONE:
                    findings_added += 1
                elif item.classification == FindingClassification.ZONE_SOA_DISCOVERED:
                    findings_added += 1

            tested = candidate_index

            candidate_errors_combined = ns_candidate_errors + candidate_errors
            if candidate_errors_combined:
                result.evidence_outcomes.append(
                    outcome_inconclusive_dns_failure(
                        candidate,
                        source_method="generated_candidate",
                        detail=candidate_errors_combined[0],
                    )
                )
            for error in candidate_errors_combined:
                result.records.append(
                    DiscoveredRecord(
                        fqdn=candidate,
                        record_type=None,
                        value=error,
                        source_method="recursive_resolver",
                        classification=FindingClassification.QUERY_ERROR,
                        evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
                    )
                )
            if (
                not ns_findings
                and not findings_added
                and not candidate_errors_combined
                and not wildcard_gate_applied
            ):
                result.evidence_outcomes.append(
                    outcome_candidate_tested(candidate, source_method="generated_candidate")
                )

    for parent_key, count in parent_skip_counts.items():
        _emit(
            f"  Skipped {count} 5th-level candidate(s) under {parent_key}: parent gating blocked deeper testing.",
            progress,
            messages,
        )
    skipped_note = f", {skipped_fifth} skipped (parent not validated)" if skipped_fifth else ""
    _emit(
        f"  {phase.value}: {tested} tested{skipped_note}, "
        f"{subdelegation_count} delegated child zone(s), "
        f"{candidate_record_count} DNS name(s) with records",
        progress,
        messages,
    )
    return tested


def scan_domain(
    base_domain: str,
    options: ScanOptions,
    plan: WordlistPlan,
    progress: ProgressCallback | None,
    messages: list[str],
    *,
    input_record: DomainInputRecord | None = None,
    cancel_check: Callable[[], bool] | None = None,
    progress_update: ScanProgressCallback | None = None,
    domain_index: int = 1,
    domain_total: int = 1,
    domains_completed: int = 0,
    started_at: datetime | None = None,
) -> DomainScanResult | None:
    """Run discovery for a single base domain. Returns None if cancelled before start."""
    domain = _display_name(base_domain)
    scan_started = started_at or datetime.now()
    resolved_options = apply_scan_profile(options)

    if cancel_check and cancel_check():
        return None

    result = DomainScanResult(domain=domain, input_record=input_record)

    _emit(f"--- Scanning {domain} ---", progress, messages)
    _emit_progress(
        progress_update,
        domain_index=domain_index,
        domain_total=domain_total,
        current_domain=domain,
        candidates_tested=0,
        candidates_total=0,
        domains_completed=domains_completed,
        started_at=scan_started,
        phase=ScanPhase.CHECKING_BASE.value,
        message=f"Checking base SOA/NS for {domain}",
        candidates_started=False,
    )

    wildcard_suspected = False
    attestation_cache: dict[str, WildcardAttestation] = {}
    with _PhaseHeartbeat(
        domain=domain,
        phase=ScanPhase.CHECKING_BASE.value,
        progress=progress,
        messages=messages,
    ):
        # Create the resolver first so it can be shared with attestation probes.
        resolver = _make_resolver()

        # Per-parent wildcard attestation replaces the old base-domain-scoped
        # _wildcard_probe.  The base domain attestation doubles as the 4th-level
        # parent cache entry (enumeration parent of every 4th-level candidate).
        base_attestation = run_wildcard_attestation(
            domain,
            _send_dns_query,
            resolver,
            probe_count=WILDCARD_ATTESTATION_PROBE_COUNT,
        )
        attestation_cache[_display_name(domain)] = base_attestation
        wildcard_suspected = base_attestation.status == WildcardAttestationStatus.DETECTED
        result.wildcard_suspected = wildcard_suspected
        if wildcard_suspected:
            _emit(
                f"  Wildcard detected at {domain}: "
                f"{len(base_attestation.type_signatures)} type(s) in signature "
                f"({', '.join(sorted(base_attestation.type_signatures))}). "
                "Promotion will be gated on differentiation.",
                progress,
                messages,
            )
        elif base_attestation.status == WildcardAttestationStatus.INCONCLUSIVE:
            _emit(
                f"  Wildcard attestation inconclusive at {domain} "
                f"({base_attestation.probes_with_answers}/{base_attestation.probes_attempted} "
                "probes responded). Promotion withheld.",
                progress,
                messages,
            )
        else:
            _emit(
                "  Wildcard probe: no wildcard pattern detected using tested methods.",
                progress,
                messages,
            )
        base_findings, base_errors = _query_records(
            domain,
            BASE_RECORD_TYPES,
            resolver,
            source_method="recursive_resolver",
            classification=FindingClassification.BASE_DOMAIN_RECORD,
            base_domain=domain,
            log_sink=messages,
            evidence_outcomes=result.evidence_outcomes,
        )
        result.records.extend(base_findings)

        base_zone_findings = [
            item
            for item in base_findings
            if item.classification == FindingClassification.BASE_ZONE_EXISTS
            or (item.record_type == RecordType.SOA and _names_match(item.fqdn, domain))
        ]
        other_base_findings = [item for item in base_findings if item not in base_zone_findings]

        if base_zone_findings:
            for item in base_zone_findings:
                _emit(
                    f"    [{item.classification.value}] {item.fqdn} SOA {item.value} "
                    f"({SOA_AUTHORITY_NOTE})",
                    progress,
                    messages,
                )
        if other_base_findings:
            _emit(f"  Base domain: {len(other_base_findings)} record(s) discovered", progress, messages)
            for item in other_base_findings:
                _emit(
                    f"    [{item.classification.value}] {item.fqdn} {item.record_type.value} {item.value}",
                    progress,
                    messages,
                )
        if not base_findings:
            _emit(
                f"  Base domain: No records discovered using tested methods for {domain}",
                progress,
                messages,
            )
            result.notes.append(f"No records discovered using tested methods for base domain {domain}")

        for error in base_errors:
            _emit(f"  Query error: {error}", progress, messages)
            result.records.append(
                DiscoveredRecord(
                    fqdn=domain,
                    record_type=None,
                    value=error,
                    source_method="recursive_resolver",
                    classification=FindingClassification.QUERY_ERROR,
                    evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
                )
            )

    resolver = _make_resolver()

    _emit_progress(
        progress_update,
        domain_index=domain_index,
        domain_total=domain_total,
        current_domain=domain,
        candidates_tested=0,
        candidates_total=0,
        domains_completed=domains_completed,
        started_at=scan_started,
        phase=ScanPhase.DISCOVERING_AUTH_NS.value,
        message=f"Discovering authoritative nameservers for {domain}",
        candidates_started=False,
    )
    ns_hosts: list[str] = []
    ns_findings: list[DiscoveredRecord] = []
    ns_errors: list[str] = []
    with _PhaseHeartbeat(
        domain=domain,
        phase=ScanPhase.DISCOVERING_AUTH_NS.value,
        progress=progress,
        messages=messages,
    ):
        ns_hosts, ns_findings, ns_errors = discover_authoritative_nameservers(domain)
        if not ns_hosts:
            delegated_ns, delegated_findings, delegated_errors = discover_delegation_nameservers(domain)
            if delegated_ns:
                ns_hosts = delegated_ns
                _emit(
                    f"  Authoritative nameservers discovered via parent-zone delegation lookup: "
                    f"{', '.join(ns_hosts)}",
                    progress,
                    messages,
                )
            for item in delegated_findings:
                if item not in result.records:
                    result.records.append(item)
            for error in delegated_errors:
                _emit(f"  Parent delegation NS lookup error: {error}", progress, messages)

        for item in ns_findings:
            if item not in result.records:
                result.records.append(item)
        for error in ns_errors:
            _emit(f"  Authoritative NS lookup error: {error}", progress, messages)

        if not ns_hosts:
            soa_mname_hosts = _extract_soa_mname_hosts(result)
            if soa_mname_hosts:
                ns_hosts = soa_mname_hosts
                _emit(
                    f"  Authoritative nameservers: none in NS answers; "
                    f"using {SOA_MNAME_INDICATOR_NOTE}: {', '.join(ns_hosts)}",
                    progress,
                    messages,
                )
                result.notes.append(
                    f"Authoritative indicator from SOA MNAME: {', '.join(ns_hosts)}"
                )
            else:
                _emit(
                    f"  Authoritative nameservers: No records discovered using tested methods for {domain}",
                    progress,
                    messages,
                )
        else:
            _emit(f"  Authoritative nameservers discovered: {', '.join(ns_hosts)}", progress, messages)

        if resolved_options.query_authoritative_ns and ns_hosts:
            for ns_host in ns_hosts:
                ns_ips = _resolve_nameserver_ips(ns_host)
                if not ns_ips:
                    _emit(f"  Could not resolve IP for nameserver {ns_host}", progress, messages)
                    continue
                ns_host_errors: list[str] = []
                for ns_ip in ns_ips:
                    # 29B: skip IPs already proven unreachable this run.
                    if ns_ip in unreachable_ns_ips:
                        _emit(
                            f"  Skipping auth NS {ns_host} ({ns_ip}): "
                            "known unreachable this run (29B short-circuit)",
                            progress,
                            messages,
                        )
                        continue
                    auth_resolver = _make_resolver(ns_ip)
                    auth_findings, auth_errors = _query_records(
                        domain,
                        BASE_RECORD_TYPES,
                        auth_resolver,
                        source_method="authoritative_nameserver",
                        classification=FindingClassification.BASE_DOMAIN_RECORD,
                        nameserver=f"{ns_host} ({ns_ip})",
                        base_domain=domain,
                        log_sink=messages,
                        evidence_outcomes=result.evidence_outcomes,
                    )
                    # 29B: detect and cache the first ENETUNREACH for this IP.
                    for err in auth_errors:
                        if _is_unreachable_error(err):
                            unreachable_ns_ips.add(ns_ip)
                    if auth_findings:
                        _emit(
                            f"  Auth NS {ns_host} ({ns_ip}): {len(auth_findings)} base record(s)",
                            progress,
                            messages,
                        )
                    for item in auth_findings:
                        if item not in result.records:
                            result.records.append(item)
                    ns_host_errors.extend(auth_errors)
                if ns_host_errors:
                    summary = _summarize_auth_ns_query_errors(
                        ns_host_errors,
                        ns_host=ns_host,
                        domain=domain,
                        record_type_count=len(BASE_RECORD_TYPES),
                    )
                    _emit(f"  {summary}", progress, messages)
                    result.records.append(
                        DiscoveredRecord(
                            fqdn=domain,
                            record_type=None,
                            value=summary,
                            source_method="authoritative_nameserver",
                            classification=FindingClassification.QUERY_ERROR,
                            nameserver=ns_host,
                            evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
                        )
                    )

    if not resolved_options.attempt_axfr:
        _emit(f"  AXFR skipped for {domain} (disabled in scan options)", progress, messages)
    elif not ns_hosts:
        _emit(f"  AXFR skipped for {domain} (no authoritative nameservers found)", progress, messages)
    elif resolved_options.attempt_axfr and ns_hosts:
        _emit(f"  AXFR attempted for {domain}", progress, messages)
        _emit_progress(
            progress_update,
            domain_index=domain_index,
            domain_total=domain_total,
            current_domain=domain,
            candidates_tested=0,
            candidates_total=0,
            domains_completed=domains_completed,
            started_at=scan_started,
            phase=ScanPhase.ATTEMPTING_AXFR.value,
            message=f"Attempting AXFR for {domain}",
            candidates_started=False,
        )
        axfr_any = False
        with _PhaseHeartbeat(
            domain=domain,
            phase=ScanPhase.ATTEMPTING_AXFR.value,
            progress=progress,
            messages=messages,
        ):
            for ns_host in ns_hosts:
                ns_ips = _resolve_nameserver_ips(ns_host)
                if not ns_ips:
                    continue
                for ns_ip in ns_ips:
                    axfr_records, axfr_message = _attempt_axfr(domain, ns_host, ns_ip)
                    _emit(f"  {axfr_message}", progress, messages)
                    if axfr_records:
                        axfr_any = True
                        result.records.extend(axfr_records)
                    else:
                        result.records.append(
                            DiscoveredRecord(
                                fqdn=domain,
                                record_type=None,
                                value=axfr_message,
                                source_method="axfr",
                                classification=FindingClassification.AXFR_BLOCKED,
                                nameserver=f"{ns_host} ({ns_ip})",
                            )
                        )
        if not axfr_any:
            _emit(
                "  AXFR: no zone transfers succeeded (refused/timeout is normal for most zones)",
                progress,
                messages,
            )

    fourth_candidates, fifth_candidates = generate_all_candidates(domain, plan, input_record)
    candidate_total = len(fourth_candidates) + len(fifth_candidates)

    # 29A Change 1: per-run NS caches — pre-seed parent cache with the
    # base-domain NS set already discovered above so no candidate ever
    # re-discovers the same parent's NS hosts from scratch.
    parent_ns_cache: dict[str, list[str]] = {_display_name(domain): list(ns_hosts)}
    ns_ip_cache: dict[str, list[str]] = {}
    # 29B: per-run auth-NS reachability cache — NS IPs that returned an instant
    # network-unreachable OSError are recorded here so the same query is never
    # re-issued per candidate.  Only ENETUNREACH/WSAENETUNREACH shape entries;
    # timeout/SERVFAIL are not cached (they are real DNS conditions).
    unreachable_ns_ips: set[str] = set()
    _emit(
        f"  Candidate names to test: {len(fourth_candidates)} 4th-level, "
        f"{len(fifth_candidates)} 5th-level ({candidate_total} total)",
        progress,
        messages,
    )
    _emit_progress(
        progress_update,
        domain_index=domain_index,
        domain_total=domain_total,
        current_domain=domain,
        candidates_tested=0,
        candidates_total=candidate_total,
        domains_completed=domains_completed,
        started_at=scan_started,
        phase=ScanPhase.TESTING_FOURTH_LEVEL.value,
        message=(
            f"Preparing candidate list ({candidate_total} names)"
            if candidate_total
            else "No candidate names to test for this domain"
        ),
        candidates_started=False,
    )

    fourth_tested = _test_candidates(
        candidates=fourth_candidates,
        domain=domain,
        resolver=resolver,
        result=result,
        wildcard_suspected=wildcard_suspected,
        attestation_cache=attestation_cache,
        progress=progress,
        messages=messages,
        cancel_check=cancel_check,
        progress_update=progress_update,
        domain_index=domain_index,
        domain_total=domain_total,
        domains_completed=domains_completed,
        started_at=scan_started,
        phase=ScanPhase.TESTING_FOURTH_LEVEL,
        candidates_offset=0,
        candidates_total=candidate_total,
        parent_ns_cache=parent_ns_cache,
        ns_ip_cache=ns_ip_cache,
        unreachable_ns_ips=unreachable_ns_ips,
    )
    result.fourth_level_candidates_tested = fourth_tested

    fifth_tested = 0
    if fifth_candidates and not (cancel_check and cancel_check()):
        fifth_parents = _unique_fifth_level_parents(fifth_candidates, domain)
        fourth_tested_names = {_display_name(name) for name in fourth_candidates}

        known_input_parents = {
            _display_name(d)
            for d in (input_record.known_fourth_level_domains if input_record else [])
        }
        parent_passed: set[str] = set()
        parent_decisions: dict[str, ParentGatingDecision] = {}

        apex_probed: set[str] = set()
        for p in fifth_parents:
            pk = _display_name(p)
            if pk in known_input_parents:
                parent_passed.add(pk)
                parent_decisions[pk] = decision_for_known_parent(pk)
                # D3: probe the apex of each known parent for recursive delegation.
                # Each apex is probed at most once per domain run even if it appears
                # as the parent of multiple 5th-level candidates.
                if pk not in apex_probed:
                    apex_probed.add(pk)
                    _probe_known_child_apex_delegation(
                        p,
                        domain=domain,
                        result=result,
                        wildcard_suspected=wildcard_suspected,
                        messages=messages,
                    )
            elif pk in fourth_tested_names:
                if _name_has_usable_findings(p, result):
                    parent_passed.add(pk)
                    parent_decisions[pk] = decision_for_validated_parent(pk, record_count=0)
                else:
                    parent_decisions[pk] = decision_for_fourth_level_tested_without_evidence(pk)

        additional_parent_checks = len(fifth_parents) - len(parent_decisions)
        _emit(
            "  5th-level parent gating: enabled "
            f"({len(fifth_parents)} unique parent name(s); "
            f"{len(parent_passed)} already known/validated; "
            f"{additional_parent_checks} to check via DNS). "
            "Deeper names are tested only when their 4th-level parent is known or validates in DNS.",
            progress,
            messages,
        )
        _emit_progress(
            progress_update,
            domain_index=domain_index,
            domain_total=domain_total,
            current_domain=domain,
            candidates_tested=fourth_tested,
            candidates_total=candidate_total,
            domains_completed=domains_completed,
            started_at=scan_started,
            phase=ScanPhase.TESTING_FIFTH_LEVEL.value,
            message=f"Testing 5th-level candidate names for {domain}",
            candidates_started=bool(fourth_tested or candidate_total),
        )
        fifth_tested = _test_candidates(
            candidates=fifth_candidates,
            domain=domain,
            resolver=resolver,
            result=result,
            wildcard_suspected=wildcard_suspected,
            attestation_cache=attestation_cache,
            progress=progress,
            messages=messages,
            cancel_check=cancel_check,
            progress_update=progress_update,
            domain_index=domain_index,
            domain_total=domain_total,
            domains_completed=domains_completed,
            started_at=scan_started,
            phase=ScanPhase.TESTING_FIFTH_LEVEL,
            candidates_offset=fourth_tested,
            candidates_total=candidate_total,
            validate_fifth_level_parents=True,
            parent_passed=parent_passed,
            parent_decisions=parent_decisions,
            parent_ns_cache=parent_ns_cache,
            ns_ip_cache=ns_ip_cache,
            unreachable_ns_ips=unreachable_ns_ips,
        )
    result.fifth_level_candidates_tested = fifth_tested
    candidates_tested = fourth_tested + fifth_tested

    if wildcard_suspected:
        _emit(
            "  Warning: wildcard suspected — some candidate A/AAAA/CNAME results marked lower confidence",
            progress,
            messages,
        )

    result.records = _dedupe_records(result.records)

    _emit(f"--- Completed {domain} ---", progress, messages)
    result.candidates_tested = candidates_tested or candidate_total
    return result


def run_scan(
    scan_input: ScanInput,
    progress_callback: ProgressCallback | None = None,
    progress_update: ScanProgressCallback | None = None,
    cancel_token: CancellationToken | None = None,
) -> ScanRunResult:
    """Run DNS discovery for all domains in the input file."""
    started_at = datetime.now()
    result = ScanRunResult(input=scan_input, scan_timestamp=started_at, started_at=started_at)
    messages = result.status_messages
    cancel_check = cancel_token.is_cancelled if cancel_token else None

    _emit("Starting child domain discovery scan.", progress_callback, messages)
    _emit(
        "Goal: find child DNS names beneath each known 3rd-level domain that are not "
        "already listed in the system input.",
        progress_callback,
        messages,
    )

    if progress_update:
        _emit_progress(
            progress_update,
            domain_index=0,
            domain_total=0,
            current_domain="",
            candidates_tested=0,
            candidates_total=0,
            domains_completed=0,
            started_at=started_at,
            phase=ScanPhase.PREPARING_INPUT.value,
            message="Preparing input",
            candidates_started=False,
        )

    resolved_options = apply_scan_profile(scan_input.options)
    scan_input = ScanInput(
        domain_file_path=scan_input.domain_file_path,
        options=resolved_options,
        output_dir=scan_input.output_dir,
        wordlists_dir=scan_input.wordlists_dir,
    )

    if progress_update:
        _emit_progress(
            progress_update,
            domain_index=0,
            domain_total=0,
            current_domain="",
            candidates_tested=0,
            candidates_total=0,
            domains_completed=0,
            started_at=started_at,
            phase=ScanPhase.LOADING_WORDLISTS.value,
            message="Loading wordlists",
            candidates_started=False,
        )

    plan = build_wordlist_plan(resolved_options, scan_input.wordlists_dir)
    result.wordlist_plan = plan
    log_wordlist_plan(plan, resolved_options, progress_callback, messages)

    try:
        loaded = load_domain_inputs(scan_input.domain_file_path)
    except OSError as exc:
        _emit(f"Failed to read domain file: {exc}", progress_callback, messages)
        return result

    if loaded.error:
        _emit(f"Failed to load domain file: {loaded.error}", progress_callback, messages)
        return result

    if not loaded.domains:
        _emit("No domains found in input file after normalization.", progress_callback, messages)
        return result

    result.domain_inputs = loaded.domains
    result.input_load_info = DomainLoadInfo(
        input_file_type=loaded.input_file_type,
        metadata_columns_detected=loaded.metadata_columns_detected,
        domains_loaded=loaded.domains_loaded,
        duplicate_domains_removed=loaded.duplicate_domains_removed,
        input_metadata_preserved=loaded.input_metadata_preserved,
        selected_domain_column=loaded.selected_domain_column,
        sample_domains_preview=loaded.sample_domains_preview,
        input_warnings=loaded.input_warnings,
        preferred_input_format_detected=loaded.preferred_input_format_detected,
    )

    domain_names = [record.domain for record in loaded.domains]
    _emit(
        f"Loaded {len(domain_names)} domain(s) from {loaded.input_file_type} input: {', '.join(domain_names)}",
        progress_callback,
        messages,
    )
    if loaded.metadata_columns_detected:
        _emit(
            f"  Input metadata columns: {', '.join(loaded.metadata_columns_detected)}",
            progress_callback,
            messages,
        )
    if loaded.input_warnings:
        for warning in loaded.input_warnings:
            _emit(warning, progress_callback, messages)
    if loaded.selected_domain_column:
        _emit(
            f"  Selected domain column: {loaded.selected_domain_column}",
            progress_callback,
            messages,
        )
    if loaded.sample_domains_preview:
        _emit(
            f"  First domains: {', '.join(loaded.sample_domains_preview)}",
            progress_callback,
            messages,
        )

    result.domains_total = len(domain_names)
    result.domains_planned = domain_names

    for index, input_record in enumerate(loaded.domains, start=1):
        domain = input_record.domain
        if cancel_check and cancel_check():
            _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
            break

        try:
            domain_result = scan_domain(
                domain,
                resolved_options,
                plan,
                progress_callback,
                messages,
                input_record=input_record,
                cancel_check=cancel_check,
                progress_update=progress_update,
                domain_index=index,
                domain_total=len(domain_names),
                domains_completed=len(result.domain_results),
                started_at=started_at,
            )
            if domain_result is None:
                _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
                break
            domain_result.input_record = input_record
            result.domain_results.append(domain_result)
            _emit_progress(
                progress_update,
                domain_index=index,
                domain_total=len(domain_names),
                current_domain=domain,
                candidates_tested=domain_result.candidates_tested,
                candidates_total=domain_result.candidates_tested,
                domains_completed=len(result.domain_results),
                started_at=started_at,
                message=f"Completed domain {len(result.domain_results)} of {len(domain_names)}: {domain}",
            )
            if cancel_check and cancel_check():
                _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
                break
        except Exception as exc:  # noqa: BLE001 — keep GUI alive on unexpected errors
            error_message = f"Scan interrupted by unexpected error: {exc}"
            _emit(f"Unexpected error scanning {domain}: {exc.__class__.__name__}: {exc}", progress_callback, messages)
            result.domain_results.append(
                DomainScanResult(
                    domain=domain,
                    input_record=input_record,
                    scan_failed=True,
                    notes=[error_message],
                    records=[
                        DiscoveredRecord(
                            fqdn=domain,
                            record_type=None,
                            value=str(exc),
                            source_method="scan_engine",
                            classification=FindingClassification.SCAN_ERROR,
                        )
                    ],
                )
            )

    if progress_update:
        _emit_progress(
            progress_update,
            domain_index=len(result.domain_results),
            domain_total=len(domain_names),
            current_domain="",
            candidates_tested=0,
            candidates_total=0,
            domains_completed=len(result.domain_results),
            started_at=started_at,
            phase=ScanPhase.BUILDING_RESULTS.value,
            message="Building results",
            candidates_started=False,
        )

    finished_at = datetime.now()
    result.finished_at = finished_at
    result.elapsed_seconds = (finished_at - started_at).total_seconds()

    cancelled = bool(cancel_check and cancel_check())
    result.cancelled = cancelled

    # partial_results=True for any cancellation: the operator interrupted the scan,
    # so results are partial regardless of how many domains had started.
    # This covers single-domain and last-domain mid-scan cancels.
    result.partial = cancelled

    result.scan_status = ScanStatus.CANCELLED if cancelled else ScanStatus.COMPLETED

    total_candidates = sum(item.candidates_tested for item in result.domain_results)
    wildcard_domains = [item.domain for item in result.domain_results if item.wildcard_suspected]

    total_confirmed = sum(
        1
        for item in result.domain_results
        for record in item.records
        if is_confirmed_evidence_status(resolve_evidence_status(record, item.domain))
    )

    if cancelled:
        _emit("=== Scan cancelled ===", progress_callback, messages)
        _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
    else:
        _emit("=== Scan complete ===", progress_callback, messages)

    _emit(
        f"Domains scanned: {len(result.domain_results)} of {len(domain_names)}; "
        f"confirmed findings: {total_confirmed}; "
        f"candidates tested: {total_candidates}; "
        f"elapsed: {result.elapsed_seconds:.1f}s",
        progress_callback,
        messages,
    )
    if wildcard_domains:
        _emit(
            f"Wildcard suspected for: {', '.join(wildcard_domains)}",
            progress_callback,
            messages,
        )
    _emit(
        "This tool does not claim complete DNS zone enumeration.",
        progress_callback,
        messages,
    )

    if progress_update:
        final_phase = ScanPhase.CANCELLED if cancelled else ScanPhase.COMPLETE
        _emit_progress(
            progress_update,
            domain_index=len(result.domain_results),
            domain_total=len(domain_names),
            current_domain="",
            candidates_tested=total_candidates,
            candidates_total=total_candidates,
            domains_completed=len(result.domain_results),
            started_at=started_at,
            phase=final_phase.value,
            message=final_phase.value,
            candidates_started=total_candidates > 0,
        )

    return result
