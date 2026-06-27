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
  §5  differentiation rules
  §6  rotating A/AAAA pool containment
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

import dns.message
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

    Returns DETECTED  — if any probe label returned answer records.
    Returns CLEAN     — if ≥ probe_count labels responded with empty answers.
    Returns INCONCLUSIVE — if not enough labels produced usable responses.
    """
    # Defer model import to avoid circular dependency at module load time.
    from scanner.models import RecordType  # noqa: PLC0415

    probe_labels = [_entropy_label() for _ in range(probe_count)]
    type_value_sets: dict[str, set[str]] = {}
    probes_with_answers = 0
    usable_labels = 0  # labels where ≥1 type query returned a response (even empty)

    for label in probe_labels:
        probe_fqdn = f"{label}.{parent}"
        label_had_response = False
        label_had_answer = False

        for rr_type_str in ATTESTATION_PROBE_TYPES:
            try:
                rr_type = RecordType(rr_type_str)
            except ValueError:
                continue

            response, error = send_dns_query_fn(probe_fqdn, rr_type, resolver)
            if error is not None or response is None:
                continue

            # At least one query for this label returned a real DNS response.
            label_had_response = True

            if not _response_has_answer_records(response):
                # NXDOMAIN / NODATA — clean for this type.
                continue

            # Wildcard hit: record rdata values for this type.
            label_had_answer = True
            values = _answer_values(response, rr_type_str)
            if values:
                type_value_sets.setdefault(rr_type_str, set()).update(values)

        if label_had_response:
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
        # All requested probes returned valid DNS responses with no answers → clean.
        return WildcardAttestation(
            status=WildcardAttestationStatus.CLEAN,
            parent=parent,
            probes_attempted=probe_count,
            probes_with_answers=probes_with_answers,
        )

    # Fewer usable labels than requested probes — too many errors to be confident.
    return WildcardAttestation(
        status=WildcardAttestationStatus.INCONCLUSIVE,
        parent=parent,
        probes_attempted=probe_count,
        probes_with_answers=probes_with_answers,
    )


# ---------------------------------------------------------------------------
# Public: differentiation check
# ---------------------------------------------------------------------------


def candidate_differentiates(
    candidate_records: list,  # list[DiscoveredRecord]
    attestation: WildcardAttestation,
) -> bool:
    """True when *candidate_records* contain evidence distinct from the wildcard.

    Differentiation criteria (§5–6):
    - Distinct RR type not present in any wildcard signature
    - Candidate NS or SOA record (delegation / zone-apex evidence)
    - DELEGATED_CHILD_ZONE or ZONE_SOA_DISCOVERED classification
    - A/AAAA address not contained in the wildcard address pool (§6)
    - Any other non-A/AAAA rdata value not in the wildcard type signature
    """
    # Defer to avoid circular imports.
    from scanner.models import FindingClassification  # noqa: PLC0415

    if attestation.status != WildcardAttestationStatus.DETECTED:
        return True  # No wildcard; every candidate passes.

    for record in candidate_records:
        rr_type = record.record_type.value if record.record_type else None

        # Delegation / zone-apex evidence always differentiates (§5).
        if rr_type in ("NS", "SOA"):
            return True
        if record.classification in (
            FindingClassification.DELEGATED_CHILD_ZONE,
            FindingClassification.ZONE_SOA_DISCOVERED,
        ):
            return True

        if rr_type is None:
            continue

        # Type not found in wildcard signatures → new type → differentiates (§5).
        if rr_type not in attestation.type_signatures:
            return True

        candidate_value: str = record.value or ""

        if rr_type in ("A", "AAAA"):
            # Pool containment check (§6): IP outside wildcard pool → differentiates.
            if candidate_value and candidate_value not in attestation.address_pool:
                return True
        else:
            # For all other types (CNAME target, MX exchange, TXT content, etc.)
            # the candidate rdata must differ from every wildcard rdata for that type.
            if candidate_value and candidate_value not in attestation.type_signatures[rr_type]:
                return True

    return False
