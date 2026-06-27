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

_DIAGNOSTIC_EVIDENCE_STATUSES = frozenset(
    {
        EvidenceStatus.CANDIDATE_TESTED,
        EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
        EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
    }
)


def _names_match(left: str, right: str) -> bool:
    return left.strip().lower().rstrip(".") == right.strip().lower().rstrip(".")


def is_confirmed_evidence_status(status: EvidenceStatus) -> bool:
    """True when *status* represents approved confirmation evidence."""
    return status in CONFIRMED_EVIDENCE_STATUSES


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
