"""DNS discovery scan engine using dnspython."""

from __future__ import annotations

import csv
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from scanner.models import (
    CancellationToken,
    DiscoveredRecord,
    DomainScanResult,
    FindingClassification,
    PreflightSummary,
    ProgressCallback,
    RecordType,
    ScanInput,
    ScanOptions,
    ScanProgressCallback,
    ScanProgressUpdate,
    ScanRunResult,
    ScanStatus,
    WordlistPlan,
)

DNS_TIMEOUT = 3.0
DNS_LIFETIME = 5.0
CANDIDATE_WARN_THRESHOLD = 250
CANDIDATE_STRONG_WARN_THRESHOLD = 500

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

FIFTH_LEVEL_BRANCHES = ("ci", "co")
WILDCARD_PROBE_COUNT = 2
LOW_CONFIDENCE_TYPES = {RecordType.A, RecordType.AAAA, RecordType.CNAME}

# option field -> (log display name, wordlist filename)
WORDLIST_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("include_rfc_locality_baseline", "RFC/locality baseline", "rfc1480.txt"),
    ("include_dns_common", "Common DNS/web labels", "dns_common.txt"),
    ("include_civic_departments", "Civic departments", "civic_departments.txt"),
    ("include_public_services", "Public services / portals", "public_services.txt"),
    ("include_schools_libraries", "Schools / libraries", "schools_libraries.txt"),
    ("include_delegated_manager_clues", "Delegated-manager clues", "delegated_manager_clues.txt"),
)

FIFTH_LEVEL_PREFIX_SOURCES = (
    "include_dns_common",
    "include_civic_departments",
    "include_public_services",
    "include_schools_libraries",
)

CANDIDATE_CANCEL_CHECK_INTERVAL = 5
PARTIAL_SCAN_MESSAGE = (
    "This scan was cancelled before all domains were completed. Results are partial."
)


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


def load_domains(path: Path) -> list[str]:
    """Load and normalize domains from a .txt or .csv file."""
    raw = _parse_label_rows(path)
    seen: set[str] = set()
    domains: list[str] = []
    for item in raw:
        normalized = _display_name(item)
        if normalized and normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
    return domains


def _dedupe_labels(labels: list[str]) -> list[str]:
    return list(dict.fromkeys(label.lower() for label in labels if label))


def build_wordlist_plan(options: ScanOptions, wordlists_dir: Path) -> WordlistPlan:
    """Load selected wordlist sources and compute candidate estimates."""
    source_counts: dict[str, int] = {}
    combined: list[str] = []
    fifth_prefix: list[str] = []

    for option_field, display_name, filename in WORDLIST_SOURCES:
        if not getattr(options, option_field):
            continue
        path = wordlists_dir / filename
        labels = _parse_label_rows(path) if path.is_file() else []
        source_counts[display_name] = len(labels)
        combined.extend(labels)
        if option_field in FIFTH_LEVEL_PREFIX_SOURCES:
            fifth_prefix.extend(labels)

    if options.include_custom_wordlist and options.custom_wordlist_path:
        custom_labels = _parse_label_rows(options.custom_wordlist_path)
        source_counts["Custom wordlist"] = len(custom_labels)
        combined.extend(custom_labels)
        fifth_prefix.extend(custom_labels)

    unique_labels = _dedupe_labels(combined)
    fifth_prefix_labels = _dedupe_labels(fifth_prefix)
    fifth_level_enabled = options.include_rfc_locality_baseline and bool(fifth_prefix_labels)

    fourth_level_count = len(unique_labels)
    fifth_level_count = len(fifth_prefix_labels) * len(FIFTH_LEVEL_BRANCHES) if fifth_level_enabled else 0

    return WordlistPlan(
        source_counts=source_counts,
        total_unique_labels=len(unique_labels),
        estimated_candidates_per_domain=fourth_level_count + fifth_level_count,
        fifth_level_enabled=fifth_level_enabled,
        fifth_level_prefix_count=len(fifth_prefix_labels),
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
    return "low"


def build_preflight_summary(scan_input: ScanInput) -> PreflightSummary | None:
    """Build pre-scan estimate from the current input file and options."""
    try:
        domains = load_domains(scan_input.domain_file_path)
    except OSError:
        return None

    plan = build_wordlist_plan(scan_input.options, scan_input.wordlists_dir)
    per_domain = plan.estimated_candidates_per_domain
    total = len(domains) * per_domain

    return PreflightSummary(
        domain_count=len(domains),
        wordlist_sources=plan.source_counts,
        total_unique_labels=plan.total_unique_labels,
        estimated_candidates_per_domain=per_domain,
        estimated_total_candidates=total,
        axfr_enabled=scan_input.options.attempt_axfr,
        auth_ns_enabled=scan_input.options.query_authoritative_ns,
        warning_level=compute_warning_level(total),
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
    message: str = "",
) -> None:
    if progress_update is None:
        return
    elapsed = (datetime.now() - started_at).total_seconds()
    progress_update(
        ScanProgressUpdate(
            domain_index=domain_index,
            domain_total=domain_total,
            current_domain=current_domain,
            candidates_tested=candidates_tested,
            candidates_total=candidates_total,
            domains_completed=domains_completed,
            elapsed_seconds=elapsed,
            message=message,
        )
    )


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


def generate_candidates(base_domain: str, plan: WordlistPlan) -> list[str]:
    """Build 4th- and limited 5th-level candidate FQDNs from a wordlist plan."""
    base = _query_name(base_domain)
    candidates: list[str] = []

    for label in plan.unique_labels:
        candidates.append(f"{label}.{base}")

    if plan.fifth_level_enabled:
        for branch in FIFTH_LEVEL_BRANCHES:
            for prefix in plan.fifth_level_prefix_labels:
                candidates.append(f"{prefix}.{branch}.{base}")

    return list(dict.fromkeys(candidates))


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


def _query_records(
    fqdn: str,
    record_types: tuple[RecordType, ...],
    resolver: dns.resolver.Resolver,
    source_method: str,
    classification: FindingClassification,
    nameserver: str | None = None,
    confidence: str = "normal",
) -> tuple[list[DiscoveredRecord], list[str]]:
    findings: list[DiscoveredRecord] = []
    errors: list[str] = []
    qname = _query_name(fqdn)

    for record_type in record_types:
        try:
            answers = resolver.resolve(qname, record_type.value)
            ttl = answers.rrset.ttl if answers.rrset is not None else None
            for rdata in answers:
                findings.append(
                    DiscoveredRecord(
                        fqdn=_display_name(qname),
                        record_type=record_type,
                        value=_format_rdata(record_type, rdata),
                        source_method=source_method,
                        classification=classification,
                        confidence=confidence,
                        nameserver=nameserver,
                        ttl=ttl,
                    )
                )
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers:
            errors.append(f"{qname} {record_type.value}: no nameservers")
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            errors.append(f"{qname} {record_type.value}: timeout")
        except dns.resolver.NoMetaqueries:
            continue
        except dns.exception.DNSException as exc:
            errors.append(f"{qname} {record_type.value}: {exc.__class__.__name__}")

    return findings, errors


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


def discover_authoritative_nameservers(base_domain: str) -> tuple[list[str], list[DiscoveredRecord], list[str]]:
    """Return NS hostnames plus discovery records and any query errors."""
    resolver = _make_resolver()
    findings, errors = _query_records(
        base_domain,
        (RecordType.NS,),
        resolver,
        source_method="recursive_resolver",
        classification=FindingClassification.AUTHORITATIVE_NS,
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
        return findings, f"AXFR succeeded via {ns_host} ({ns_ip}) — {len(findings)} record(s) discovered"
    except dns.exception.FormError:
        return [], f"AXFR not allowed via {ns_host} ({ns_ip}): form error"
    except dns.zone.NoSOA:
        return [], f"AXFR failed via {ns_host} ({ns_ip}): no SOA in transfer"
    except dns.exception.Timeout:
        return [], f"AXFR timed out via {ns_host} ({ns_ip})"
    except OSError as exc:
        return [], f"AXFR refused/failed via {ns_host} ({ns_ip}): {exc}"
    except dns.exception.DNSException as exc:
        return [], f"AXFR blocked via {ns_host} ({ns_ip}): {exc.__class__.__name__}"


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
        FindingClassification.POSSIBLE_SUBDELEGATION,
    }:
        return "low"
    return "normal"


def scan_domain(
    base_domain: str,
    options: ScanOptions,
    plan: WordlistPlan,
    progress: ProgressCallback | None,
    messages: list[str],
    *,
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

    if cancel_check and cancel_check():
        return None

    result = DomainScanResult(domain=domain)

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
        message=f"Scanning domain {domain_index} of {domain_total}: {domain}",
    )

    wildcard_suspected, wildcard_logs = _wildcard_probe(domain)
    result.wildcard_suspected = wildcard_suspected
    for line in wildcard_logs:
        _emit(f"  {line}", progress, messages)

    resolver = _make_resolver()
    base_findings, base_errors = _query_records(
        domain,
        BASE_RECORD_TYPES,
        resolver,
        source_method="recursive_resolver",
        classification=FindingClassification.BASE_DOMAIN_RECORD,
    )
    result.records.extend(base_findings)

    if base_findings:
        _emit(f"  Base domain: {len(base_findings)} record(s) discovered", progress, messages)
        for item in base_findings:
            _emit(
                f"    [{item.classification.value}] {item.fqdn} {item.record_type.value} {item.value}",
                progress,
                messages,
            )
    else:
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
            )
        )

    ns_hosts, ns_findings, ns_errors = discover_authoritative_nameservers(domain)
    for item in ns_findings:
        if item not in result.records:
            result.records.append(item)
    for error in ns_errors:
        _emit(f"  Authoritative NS lookup error: {error}", progress, messages)

    if ns_hosts:
        _emit(f"  Authoritative nameservers discovered: {', '.join(ns_hosts)}", progress, messages)
    else:
        _emit(
            f"  Authoritative nameservers: No records discovered using tested methods for {domain}",
            progress,
            messages,
        )

    if options.query_authoritative_ns and ns_hosts:
        for ns_host in ns_hosts:
            ns_ips = _resolve_nameserver_ips(ns_host)
            if not ns_ips:
                _emit(f"  Could not resolve IP for nameserver {ns_host}", progress, messages)
                continue
            for ns_ip in ns_ips:
                auth_resolver = _make_resolver(ns_ip)
                auth_findings, auth_errors = _query_records(
                    domain,
                    BASE_RECORD_TYPES,
                    auth_resolver,
                    source_method="authoritative_nameserver",
                    classification=FindingClassification.BASE_DOMAIN_RECORD,
                    nameserver=f"{ns_host} ({ns_ip})",
                )
                if auth_findings:
                    _emit(
                        f"  Auth NS {ns_host} ({ns_ip}): {len(auth_findings)} base record(s)",
                        progress,
                        messages,
                    )
                for item in auth_findings:
                    if item not in result.records:
                        result.records.append(item)
                for error in auth_errors:
                    _emit(f"  Auth NS query error ({ns_host}): {error}", progress, messages)

    if options.attempt_axfr and ns_hosts:
        axfr_any = False
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
                "  AXFR: no successful zone transfers using tested methods (refused/timeout/failure is expected)",
                progress,
                messages,
            )

    candidates = generate_candidates(domain, plan)
    candidate_total = len(candidates)
    _emit(f"  Candidate names to test: {candidate_total}", progress, messages)
    _emit_progress(
        progress_update,
        domain_index=domain_index,
        domain_total=domain_total,
        current_domain=domain,
        candidates_tested=0,
        candidates_total=candidate_total,
        domains_completed=domains_completed,
        started_at=scan_started,
        message=f"Testing {candidate_total} candidate names for {domain}",
    )

    subdelegation_count = 0
    candidate_record_count = 0
    empty_candidates = 0
    candidates_tested = 0

    for candidate_index, candidate in enumerate(candidates, start=1):
        if cancel_check and cancel_check():
            result.notes.append(PARTIAL_SCAN_MESSAGE)
            _emit("  Scan cancellation requested; stopping candidate testing for this domain.", progress, messages)
            break

        if candidate_index % CANDIDATE_CANCEL_CHECK_INTERVAL == 0:
            _emit_progress(
                progress_update,
                domain_index=domain_index,
                domain_total=domain_total,
                current_domain=domain,
                candidates_tested=candidate_index,
                candidates_total=len(candidates),
                domains_completed=domains_completed,
                started_at=scan_started,
                message=(
                    f"Scanning domain {domain_index} of {domain_total}: {domain} | "
                    f"Candidates tested: {candidate_index} / {len(candidates)}"
                ),
            )

        ns_findings, ns_candidate_errors = _query_records(
            candidate,
            (RecordType.NS,),
            resolver,
            source_method="generated_candidate",
            classification=FindingClassification.POSSIBLE_SUBDELEGATION,
        )
        if ns_findings:
            subdelegation_count += 1
            for item in ns_findings:
                item.confidence = _confidence_for(
                    wildcard_suspected, item.record_type, item.classification
                )
                result.records.append(item)
            _emit(
                f"    Possible subdelegation: {candidate} NS {', '.join(item.value for item in ns_findings)}",
                progress,
                messages,
            )

        other_findings, candidate_errors = _query_records(
            candidate,
            CANDIDATE_RECORD_TYPES,
            resolver,
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
        )
        for item in other_findings:
            item.confidence = _confidence_for(
                wildcard_suspected, item.record_type, item.classification
            )
            candidate_record_count += 1
            result.records.append(item)

        if not ns_findings and not other_findings:
            empty_candidates += 1

        candidates_tested = candidate_index

        for error in ns_candidate_errors + candidate_errors:
            result.records.append(
                DiscoveredRecord(
                    fqdn=candidate,
                    record_type=None,
                    value=error,
                    source_method="recursive_resolver",
                    classification=FindingClassification.QUERY_ERROR,
                )
            )

    _emit(
        f"  Candidate summary: {candidates_tested} tested, "
        f"{subdelegation_count} possible subdelegation(s), "
        f"{candidate_record_count} other record(s), "
        f"{empty_candidates} with no records discovered using tested methods",
        progress,
        messages,
    )

    if wildcard_suspected:
        _emit(
            "  Warning: wildcard suspected — some candidate A/AAAA/CNAME results marked lower confidence",
            progress,
            messages,
        )

    _emit(f"--- Completed {domain} ---", progress, messages)
    result.candidates_tested = candidates_tested or len(candidates)
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

    _emit("Starting DNS discovery scan.", progress_callback, messages)
    _emit(
        "Discovery results reflect tested methods only; absence of discovered records "
        "is not proof that records or subdelegations do not exist.",
        progress_callback,
        messages,
    )

    plan = build_wordlist_plan(scan_input.options, scan_input.wordlists_dir)
    result.wordlist_plan = plan
    log_wordlist_plan(plan, scan_input.options, progress_callback, messages)

    try:
        domains = load_domains(scan_input.domain_file_path)
    except OSError as exc:
        _emit(f"Failed to read domain file: {exc}", progress_callback, messages)
        return result

    if not domains:
        _emit("No domains found in input file after normalization.", progress_callback, messages)
        return result

    _emit(f"Loaded {len(domains)} domain(s): {', '.join(domains)}", progress_callback, messages)
    result.domains_total = len(domains)
    result.domains_planned = domains

    for index, domain in enumerate(domains, start=1):
        if cancel_check and cancel_check():
            _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
            break

        try:
            domain_result = scan_domain(
                domain,
                scan_input.options,
                plan,
                progress_callback,
                messages,
                cancel_check=cancel_check,
                progress_update=progress_update,
                domain_index=index,
                domain_total=len(domains),
                domains_completed=len(result.domain_results),
                started_at=started_at,
            )
            if domain_result is None:
                _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
                break
            result.domain_results.append(domain_result)
            _emit_progress(
                progress_update,
                domain_index=index,
                domain_total=len(domains),
                current_domain=domain,
                candidates_tested=domain_result.candidates_tested,
                candidates_total=domain_result.candidates_tested,
                domains_completed=len(result.domain_results),
                started_at=started_at,
                message=f"Completed domain {len(result.domain_results)} of {len(domains)}: {domain}",
            )
            if cancel_check and cancel_check():
                _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
                break
        except Exception as exc:  # noqa: BLE001 — keep GUI alive on unexpected errors
            _emit(f"Unexpected error scanning {domain}: {exc.__class__.__name__}: {exc}", progress_callback, messages)
            result.domain_results.append(
                DomainScanResult(
                    domain=domain,
                    notes=[f"Scan interrupted by unexpected error: {exc}"],
                )
            )

    finished_at = datetime.now()
    result.finished_at = finished_at
    result.elapsed_seconds = (finished_at - started_at).total_seconds()

    cancelled = bool(cancel_check and cancel_check())
    result.cancelled = cancelled
    result.partial = cancelled and len(result.domain_results) < len(domains)
    result.scan_status = ScanStatus.CANCELLED if cancelled else ScanStatus.COMPLETED

    total_records = sum(len(item.records) for item in result.domain_results)
    total_candidates = sum(item.candidates_tested for item in result.domain_results)
    wildcard_domains = [item.domain for item in result.domain_results if item.wildcard_suspected]

    if cancelled:
        _emit("=== Scan cancelled ===", progress_callback, messages)
        _emit(PARTIAL_SCAN_MESSAGE, progress_callback, messages)
    else:
        _emit("=== Scan complete ===", progress_callback, messages)

    _emit(
        f"Domains scanned: {len(result.domain_results)} of {len(domains)}; "
        f"total findings: {total_records}; "
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

    return result
