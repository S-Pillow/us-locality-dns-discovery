"""Evidence status resolution and helpers for DNS discovery results."""

from __future__ import annotations

from scanner.models import (
    DiscoveredRecord,
    EvidenceOutcome,
    EvidenceStatus,
    EvidenceTrace,
    FindingClassification,
)


CONFIRMED_EVIDENCE_STATUSES = frozenset(
    {
        EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME,
        EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
        EvidenceStatus.KNOWN_DOMAIN_VALIDATED,
    }
)

# Recursive-corroborated findings are intentionally kept separate from
# CONFIRMED_EVIDENCE_STATUSES so they are never counted in the authoritative total.
RECURSIVE_DELEGATION_STATUSES = frozenset(
    {EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE}
)

_DIAGNOSTIC_EVIDENCE_STATUSES = frozenset(
    {
        EvidenceStatus.CANDIDATE_TESTED,
        EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
        EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
        # Wildcard attestation diagnostics (R4a / WC-FIX.1)
        EvidenceStatus.SUPPRESSED_WILDCARD_MATCH,
        EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE,
        EvidenceStatus.WITHHELD_PARKING_ECHO,
        # WL-TRIM Change 4: branch timeout circuit breaker
        EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC,
    }
)


def _names_match(left: str, right: str) -> bool:
    return left.strip().lower().rstrip(".") == right.strip().lower().rstrip(".")


def is_confirmed_evidence_status(status: EvidenceStatus) -> bool:
    """True when *status* represents approved confirmation evidence."""
    return status in CONFIRMED_EVIDENCE_STATUSES


def is_recursive_delegation_status(status: EvidenceStatus) -> bool:
    """True when *status* is a resolver-corroborated delegation (lower confidence, never authoritative)."""
    return status in RECURSIVE_DELEGATION_STATUSES


def is_diagnostic_evidence_status(status: EvidenceStatus) -> bool:
    """True when *status* is report metadata, not a confirmed finding."""
    return status in _DIAGNOSTIC_EVIDENCE_STATUSES


def resolve_evidence_status(
    record: DiscoveredRecord,
    base_domain: str | None = None,
) -> EvidenceStatus:
    """Return structured evidence status for *record* (explicit or inferred)."""
    if record.evidence_status is not None:
        return record.evidence_status

    classification = record.classification
    source_method = record.source_method.lower()

    if classification == FindingClassification.QUERY_ERROR:
        return EvidenceStatus.INCONCLUSIVE_DNS_FAILURE
    if classification == FindingClassification.DELEGATED_CHILD_ZONE:
        return EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE
    if classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE:
        return EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE
    if classification == FindingClassification.STANDARD_RECORD:
        return EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME
    if classification in {
        FindingClassification.BASE_DOMAIN_RECORD,
        FindingClassification.BASE_ZONE_EXISTS,
        FindingClassification.AUTHORITATIVE_NS,
    }:
        return EvidenceStatus.KNOWN_DOMAIN_VALIDATED
    if classification == FindingClassification.ZONE_SOA_DISCOVERED:
        if base_domain and _names_match(record.fqdn, base_domain):
            return EvidenceStatus.KNOWN_DOMAIN_VALIDATED
        if any(
            token in source_method
            for token in (
                "delegation",
                "parent_authoritative",
                "candidate_authoritative",
            )
        ):
            return EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE
        return EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME

    return EvidenceStatus.NOT_RECORDED


def stamp_record_evidence_status(
    record: DiscoveredRecord,
    base_domain: str | None = None,
) -> None:
    """Set ``record.evidence_status`` when not already assigned."""
    if record.evidence_status is None:
        record.evidence_status = resolve_evidence_status(record, base_domain)


def evidence_status_export_value(
    record: DiscoveredRecord,
    base_domain: str | None = None,
) -> str:
    """Stable export string for workbook/CSV/JSON."""
    return resolve_evidence_status(record, base_domain).value


def outcome_skipped_by_parent_gating(
    fqdn: str,
    parent: str,
    *,
    evidence_trace: list[EvidenceTrace] | None = None,
) -> EvidenceOutcome:
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        source_method="generated_candidate",
        detail=f"Skipped: parent {parent} did not validate",
        evidence_trace=list(evidence_trace or []),
    )


def outcome_ignored_unrelated_authority(
    fqdn: str,
    *,
    source_method: str,
    detail: str,
    evidence_trace: list[EvidenceTrace] | None = None,
) -> EvidenceOutcome:
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
        source_method=source_method,
        detail=detail,
        evidence_trace=list(evidence_trace or []),
    )


def outcome_nodata_parent_authority(
    fqdn: str,
    *,
    source_method: str,
    detail: str,
    evidence_trace: list[EvidenceTrace] | None = None,
) -> EvidenceOutcome:
    """Ticket T32: NOERROR + no direct record + ancestor SOA in authority.

    The name is in-zone but has no direct record and is NOT delegated.
    This is NOT absence and NOT delegation — it is context only.
    """
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.NODATA_PARENT_AUTHORITY,
        source_method=source_method,
        detail=detail,
        evidence_trace=list(evidence_trace or []),
    )


def outcome_inconclusive_dns_failure(
    fqdn: str,
    *,
    source_method: str,
    detail: str,
    evidence_trace: list[EvidenceTrace] | None = None,
) -> EvidenceOutcome:
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
        source_method=source_method,
        detail=detail,
        evidence_trace=list(evidence_trace or []),
    )


def outcome_candidate_tested(fqdn: str, *, source_method: str) -> EvidenceOutcome:
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.CANDIDATE_TESTED,
        source_method=source_method,
        detail="Candidate tested; no confirmed DNS evidence",
    )


def outcome_skipped_by_branch_timeout_heuristic(
    fqdn: str,
    branch: str,
    breaker_n: int,
) -> EvidenceOutcome:
    """WL-TRIM Change 4: branch timeout circuit breaker fired.

    The candidate was NOT tested.  This is a heuristic performance cutoff only.
    The absence of the name is NOT proven by this skip.
    """
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC,
        source_method="generated_candidate",
        detail=(
            f"Stopped testing this branch after {breaker_n} consecutive "
            f"priority-ordered misses with zero findings. "
            f"This is a heuristic performance cutoff, not proof that no deeper names exist."
        ),
    )


def outcome_suppressed_wildcard_match(
    fqdn: str,
    *,
    parent: str,
    source_method: str = "generated_candidate",
) -> EvidenceOutcome:
    """Candidate response matches the wildcard signature at *parent* — suppressed (§5)."""
    from scanner.wildcard_attestation import WildcardAttestationStatus  # noqa: PLC0415

    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.SUPPRESSED_WILDCARD_MATCH,
        source_method=source_method,
        detail=f"Response matches wildcard signature at parent {parent}; suppressed to diagnostic",
        attestation_status=WildcardAttestationStatus.DETECTED.value,
    )


def outcome_withheld_wildcard_inconclusive(
    fqdn: str,
    *,
    parent: str,
    source_method: str = "generated_candidate",
) -> EvidenceOutcome:
    """Wildcard attestation was inconclusive at *parent*; promotion withheld (§3)."""
    from scanner.wildcard_attestation import WildcardAttestationStatus  # noqa: PLC0415

    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE,
        source_method=source_method,
        detail=f"Wildcard attestation inconclusive at parent {parent}; promotion withheld",
        attestation_status=WildcardAttestationStatus.INCONCLUSIVE.value,
    )


def outcome_withheld_parking_txt_backstop(
    fqdn: str,
    *,
    parent: str,
    attestation_status_value: str,
    source_method: str = "generated_candidate",
) -> EvidenceOutcome:
    """WC-FIX.1 §2B: parking-TXT backstop — candidate withheld regardless of attestation.

    Applied when the only evidence for a candidate is a TXT record whose value
    matches the known parking/availability pattern (e.g. "may be available …
    contact …@i-theta.com").  Wildcard detection is no longer the single gate
    between a parking-echo and a confirmed finding; this backstop catches the
    case independently of whether detection returned DETECTED, CLEAN, or
    INCONCLUSIVE.
    """
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.WITHHELD_PARKING_ECHO,
        source_method=source_method,
        detail=(
            f"Parking/availability TXT backstop at parent {parent}: "
            "all evidence matches a known registrar parking string; "
            "promotion withheld regardless of wildcard detection status"
        ),
        attestation_status=attestation_status_value,
    )
