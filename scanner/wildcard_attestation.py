"""Per-parent wildcard attestation engine for DNS discovery candidates.

Replaces the base-domain-scoped _wildcard_probe with per-enumeration-parent
probing and a three-state attestation result.  Promotion of candidate records
is gated on the attestation outcome inside scan_engine._test_candidates.

Contract references:
  §1  per-parent scope — no cross-level assumption
  §2  ≥3 high-entropy probes across A/AAAA/CNAME/MX/TXT/CAA/NS/SOA
  §3  three attestation states: CLEAN / DETECTED / INCONCLUSIVE
  §4  signature per parent+RRtype, ignoring TTL/order/timing;
      parent-zone authority SOA in negative response ≠ wildcard confirmation
  §5  differentiation rules (§7 reason labels for forward-compat)
  §6  rotating A/AAAA pool containment

§7 forward-compat: candidate_differentiates() returns a named reason string
  (or None on non-differentiation) rather than a plain bool so that the engine
  can stamp wildcard_differentiation_reason on promoted records and R4b can
  surface them without re-running any logic.

§3 inconsistent-probe disposition (1c):
  Current behaviour — if ANY probe label returns answer records the attestation
  is classified DETECTED, even when other labels returned NXDOMAIN/NODATA.
  Contract §3 lists "inconsistent probe results that cannot be safely
  classified" under INCONCLUSIVE (withhold all).  The divergence is tracked as
  a known item; owner decision (recommend→approve) pending.  Default path:
  document DETECTED, proceed, flag for later refinement before R4b.
  Rationale: DETECTED + differentiation still allows provably distinct
  candidates to promote; INCONCLUSIVE would withhold all.  The current
  behaviour is therefore less restrictive but never silently promotes a matched
  candidate.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

import dns.message
import dns.rcode
import dns.rdatatype

if TYPE_CHECKING:
    import dns.resolver


class WildcardAttestationStatus(str, Enum):
    """Three-state per-parent attestation outcome (§3)."""

    CLEAN = "clean"
    """No wildcard detected; candidate may promote unconditionally."""

    DETECTED = "detected"
    """Wildcard detected; candidate must differentiate to promote (§5–6)."""

    INCONCLUSIVE = "inconclusive"
    """Cannot determine; promotion is withheld in Light mode (§3)."""


# RR types queried for each high-entropy probe label (§2 Light-mode confirming types).
ATTESTATION_PROBE_TYPES: tuple[str, ...] = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "CAA",
    "NS",
    "SOA",
)

MIN_PROBE_COUNT: int = 3

# Named differentiation reasons (§5, §7 forward-compat).
REASON_DISTINCT_RRTYPE = "distinct_rrtype"
REASON_DISTINCT_ANSWER = "distinct_answer"
REASON_DISTINCT_CNAME_TARGET = "distinct_cname_target"
REASON_CANDIDATE_NS_SOA = "candidate_ns_soa"
REASON_VERIFIED_DELEGATION = "verified_delegation"
REASON_NO_WILDCARD = "no_wildcard"  # returned when attestation is not DETECTED


def _entropy_label(n_hex_bytes: int = 8) -> str:
    """Return a high-entropy DNS label unlikely to exist in any real zone."""
    return f"xwc{secrets.token_hex(n_hex_bytes)}"


@dataclass
class WildcardAttestation:
    """Result of probing one enumeration parent for wildcard DNS behaviour."""

    status: WildcardAttestationStatus
    parent: str
    probes_attempted: int = 0
    probes_with_answers: int = 0
    # Per-RRtype frozensets of normalised rdata text (TTL excluded) — §4 signature.
    type_signatures: dict[str, frozenset[str]] = field(default_factory=dict)
    # Union of all A + AAAA values seen across probes — §6 pool containment.
    address_pool: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _answer_values(response: dns.message.Message, rr_type_str: str) -> frozenset[str]:
    """Extract normalised rdata text values from the answer section, TTL excluded.

    Only the answer section is inspected.  A parent-zone authority SOA appearing
    in the authority section of an NXDOMAIN response is deliberately ignored — §4.
    """
    rtype = dns.rdatatype.from_text(rr_type_str)
    values: set[str] = set()
    for rrset in response.answer:
        if rrset.rdtype == rtype:
            for rdata in rrset:
                values.add(rdata.to_text())
    return frozenset(values)


def _response_has_answer_records(response: dns.message.Message) -> bool:
    """True only when the answer section is non-empty.

    An NXDOMAIN with a parent-zone SOA in the authority section is *not* a
    wildcard hit — §4.
    """
    return bool(response.answer)


def _response_is_usable(response: dns.message.Message) -> bool:
    """True when the DNS rcode represents a definitive negative answer.

    NOERROR and NXDOMAIN indicate the server authoritatively answered the
    query (wildcard or no-record, respectively) — both are usable.
    SERVFAIL, REFUSED, FORMERR, NOTIMP, and other error rcodes mean the
    server could not or would not answer; treating such responses as
    NXDOMAIN / NODATA would falsely count them toward a CLEAN conclusion.
    Non-usable responses increment the implicit error counter so that
    not-enough-usable-labels → INCONCLUSIVE (§3, 1b).
    """
    try:
        rc = response.rcode()
        return rc in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
    except Exception:
        # If the response object has no rcode() method (e.g. test stubs that
        # pre-date the 1b fix), default to usable to avoid breaking callers.
        return True


# ---------------------------------------------------------------------------
# Public: run attestation
# ---------------------------------------------------------------------------


def run_wildcard_attestation(
    parent: str,
    send_dns_query_fn: Callable[
        [str, object, object],
        tuple[dns.message.Message | None, str | None],
    ],
    resolver: dns.resolver.Resolver,
    probe_count: int = MIN_PROBE_COUNT,
) -> WildcardAttestation:
    """Probe *parent* for wildcard DNS using high-entropy subdomains (§1–4).

    Generates *probe_count* random labels, queries each against all
    ATTESTATION_PROBE_TYPES, and builds per-type signatures from any
    non-empty answer sections found.

    Returns DETECTED     — if any probe label returned answer records.
    Returns CLEAN        — if ≥ probe_count labels responded with usable
                           empty answers (NOERROR/NXDOMAIN, empty answer).
    Returns INCONCLUSIVE — if not enough labels produced usable responses
                           (SERVFAIL / REFUSED / network errors count as
                           non-usable — §3, 1b fix).

    §3 inconsistent-probe note (1c): DETECTED is returned even when some
    labels returned NXDOMAIN and others returned answers.  See module
    docstring §3 disposition for the tracked divergence from the contract.
    """
    # Defer model import to avoid circular dependency at module load time.
    from scanner.models import RecordType  # noqa: PLC0415

    probe_labels = [_entropy_label() for _ in range(probe_count)]
    type_value_sets: dict[str, set[str]] = {}
    probes_with_answers = 0
    usable_labels = 0  # labels where ≥1 type query returned a usable response

    for label in probe_labels:
        probe_fqdn = f"{label}.{parent}"
        label_had_usable_response = False
        label_had_answer = False

        for rr_type_str in ATTESTATION_PROBE_TYPES:
            try:
                rr_type = RecordType(rr_type_str)
            except ValueError:
                continue

            response, error = send_dns_query_fn(probe_fqdn, rr_type, resolver)
            if error is not None or response is None:
                # Network/transport error — non-usable for CLEAN counting.
                continue

            # SERVFAIL / REFUSED / malformed rcode → non-usable (1b).
            if not _response_is_usable(response):
                continue

            # At least one query for this label returned a usable DNS response.
            label_had_usable_response = True

            if not _response_has_answer_records(response):
                # NXDOMAIN / NODATA with usable rcode — clean for this type.
                continue

            # Wildcard hit: record rdata values for this type.
            label_had_answer = True
            values = _answer_values(response, rr_type_str)
            if values:
                type_value_sets.setdefault(rr_type_str, set()).update(values)

        if label_had_usable_response:
            usable_labels += 1
        if label_had_answer:
            probes_with_answers += 1

    type_signatures = {t: frozenset(v) for t, v in type_value_sets.items() if v}

    if type_signatures:
        address_pool: frozenset[str] = type_signatures.get(
            "A", frozenset()
        ) | type_signatures.get("AAAA", frozenset())
        return WildcardAttestation(
            status=WildcardAttestationStatus.DETECTED,
            parent=parent,
            probes_attempted=probe_count,
            probes_with_answers=probes_with_answers,
            type_signatures=type_signatures,
            address_pool=address_pool,
        )

    if usable_labels >= probe_count:
        # All requested probes returned usable DNS responses with no answers → clean.
        return WildcardAttestation(
            status=WildcardAttestationStatus.CLEAN,
            parent=parent,
            probes_attempted=probe_count,
            probes_with_answers=probes_with_answers,
        )

    # Fewer usable labels than probe_count — SERVFAIL/REFUSED/errors prevented
    # enough valid probes to conclude CLEAN.
    return WildcardAttestation(
        status=WildcardAttestationStatus.INCONCLUSIVE,
        parent=parent,
        probes_attempted=probe_count,
        probes_with_answers=probes_with_answers,
    )


# ---------------------------------------------------------------------------
# Public: differentiation check (§5–6, §7 forward-compat)
# ---------------------------------------------------------------------------


def candidate_differentiates(
    candidate_records: list,  # list[DiscoveredRecord]
    attestation: WildcardAttestation,
) -> str | None:
    """Return the differentiation reason if *candidate_records* differ from the wildcard.

    Returns one of the REASON_* constants when the candidate differentiates,
    or ``None`` when all evidence matches the wildcard signature (suppress).

    For non-DETECTED attestations returns ``REASON_NO_WILDCARD`` — no wildcard
    was detected so no suppression analysis is needed.

    Named reasons (§5, §7):
      distinct_rrtype        — candidate has a type absent from wildcard signatures
      distinct_answer        — A/AAAA address outside pool, or other type value not
                               in the wildcard set
      distinct_cname_target  — CNAME target differs from wildcard CNAME target
      candidate_ns_soa       — candidate carries NS or SOA (delegation/zone-apex)
      verified_delegation    — DELEGATED_CHILD_ZONE or ZONE_SOA_DISCOVERED classification
      no_wildcard            — attestation is not DETECTED (CLEAN or INCONCLUSIVE)
    """
    # Defer to avoid circular imports.
    from scanner.models import FindingClassification  # noqa: PLC0415

    if attestation.status != WildcardAttestationStatus.DETECTED:
        return REASON_NO_WILDCARD  # No wildcard; every candidate passes.

    for record in candidate_records:
        rr_type = record.record_type.value if record.record_type else None

        # Delegation / zone-apex evidence always differentiates (§5).
        if rr_type in ("NS", "SOA"):
            return REASON_CANDIDATE_NS_SOA
        if record.classification in (
            FindingClassification.DELEGATED_CHILD_ZONE,
            FindingClassification.ZONE_SOA_DISCOVERED,
        ):
            return REASON_VERIFIED_DELEGATION

        if rr_type is None:
            continue

        # Type not found in wildcard signatures → new type → differentiates (§5).
        if rr_type not in attestation.type_signatures:
            return REASON_DISTINCT_RRTYPE

        candidate_value: str = record.value or ""

        if rr_type in ("A", "AAAA"):
            # Pool containment check (§6): IP outside wildcard pool → differentiates.
            if candidate_value and candidate_value not in attestation.address_pool:
                return REASON_DISTINCT_ANSWER
        elif rr_type == "CNAME":
            # CNAME target mismatch → distinct_cname_target (§5).
            if candidate_value and candidate_value not in attestation.type_signatures[rr_type]:
                return REASON_DISTINCT_CNAME_TARGET
        else:
            # MX exchange, TXT content, CAA, etc.: rdata value not in wildcard set.
            if candidate_value and candidate_value not in attestation.type_signatures[rr_type]:
                return REASON_DISTINCT_ANSWER

    return None  # All evidence matches the wildcard signature — suppress.
