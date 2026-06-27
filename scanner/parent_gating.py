"""Parent-gating semantics for fifth-level candidate testing."""

from __future__ import annotations

from scanner.dns_classifier import DNSResponseClass, classify_dns_response
from scanner.models import (
    EvidenceOutcome,
    EvidenceStatus,
    ParentGatingConfidence,
    ParentGatingDecision,
    RecordType,
)

_POSITIVE_CLASSES = frozenset(
    {
        DNSResponseClass.OWNER_MATCHING_ANSWER,
        DNSResponseClass.CNAME_ALIAS,
        DNSResponseClass.REFERRAL_DELEGATION,
    }
)
_INCONCLUSIVE_CLASSES = frozenset(
    {
        DNSResponseClass.SERVFAIL,
        DNSResponseClass.TIMEOUT,
        DNSResponseClass.MALFORMED_OR_UNUSABLE,
    }
)


def decision_for_known_parent(parent_name: str) -> ParentGatingDecision:
    """Parent listed in system input — allow deeper testing without re-validation."""
    return ParentGatingDecision(
        allow_descendants=True,
        parent_name=parent_name,
        reason="Parent is known from system input",
        evidence_status=None,
        response_class=None,
        confidence=ParentGatingConfidence.KNOWN_PARENT,
        diagnostic_message=f"Known parent {parent_name}; deeper candidates may be tested.",
    )


def decision_for_validated_parent(parent_name: str, *, record_count: int) -> ParentGatingDecision:
    """Parent confirmed by direct DNS evidence during this scan."""
    detail = (
        f"4th-level parent validated: {parent_name} ({record_count} direct record(s))"
        if record_count
        else f"Parent {parent_name} validated with direct DNS evidence"
    )
    return ParentGatingDecision(
        allow_descendants=True,
        parent_name=parent_name,
        reason="Parent validated with direct DNS evidence",
        evidence_status=None,
        response_class=None,
        confidence=ParentGatingConfidence.VALIDATED_PARENT,
        diagnostic_message=detail,
    )


def decision_for_fourth_level_tested_without_evidence(parent_name: str) -> ParentGatingDecision:
    """Parent was tested as a 4th-level candidate but produced no direct evidence."""
    return ParentGatingDecision(
        allow_descendants=False,
        parent_name=parent_name,
        reason="Parent tested without direct DNS evidence",
        evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        response_class=DNSResponseClass.NODATA_EMPTY_ANSWER.value,
        confidence=ParentGatingConfidence.HEURISTIC_SKIP,
        diagnostic_message=(
            f"Skipped deeper candidates after NODATA/empty parent response for {parent_name}; "
            "this is a performance/evidence-quality choice, not proof that no deeper names exist."
        ),
    )


def probe_parent_response_classes(
    parent: str,
    record_types: tuple[RecordType, ...],
    send_query,
    resolver,
) -> set[DNSResponseClass]:
    """Classify synthetic parent probe responses (used when validation finds no records)."""
    classes: set[DNSResponseClass] = set()
    for record_type in record_types:
        response, transport_error = send_query(parent, record_type, resolver)
        classes.add(classify_dns_response(response, parent, transport_error))
    return classes


def decide_parent_gating_from_probe_classes(
    parent_name: str,
    classes_seen: set[DNSResponseClass],
    *,
    saw_unrelated_authority: bool = False,
) -> ParentGatingDecision:
    """Map aggregated parent probe classes to a conservative gating decision."""
    if classes_seen & _POSITIVE_CLASSES:
        return decision_for_validated_parent(parent_name, record_count=0)

    if classes_seen & _INCONCLUSIVE_CLASSES:
        return ParentGatingDecision(
            allow_descendants=False,
            parent_name=parent_name,
            reason="Parent validation inconclusive",
            evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
            response_class=next(iter(classes_seen & _INCONCLUSIVE_CLASSES)).value,
            confidence=ParentGatingConfidence.INCONCLUSIVE,
            diagnostic_message=(
                f"Skipped deeper candidates because parent validation was inconclusive for "
                f"{parent_name}."
            ),
        )

    if saw_unrelated_authority or DNSResponseClass.UNRELATED_AUTHORITY in classes_seen:
        return ParentGatingDecision(
            allow_descendants=False,
            parent_name=parent_name,
            reason="Ignored unrelated authority while validating parent",
            evidence_status=EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
            response_class=DNSResponseClass.UNRELATED_AUTHORITY.value,
            confidence=ParentGatingConfidence.IGNORED_AUTHORITY,
            diagnostic_message=(
                f"Ignored unrelated authority while validating parent {parent_name}; "
                "descendant testing was skipped because the parent was not validated."
            ),
        )

    if DNSResponseClass.NEGATIVE_NXDOMAIN in classes_seen:
        return ParentGatingDecision(
            allow_descendants=False,
            parent_name=parent_name,
            reason="Parent returned NXDOMAIN",
            evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
            response_class=DNSResponseClass.NEGATIVE_NXDOMAIN.value,
            confidence=ParentGatingConfidence.CONFIDENT_NEGATIVE,
            diagnostic_message=(
                f"Skipped deeper candidates because parent validation returned NXDOMAIN for "
                f"{parent_name}."
            ),
        )

    if classes_seen and classes_seen <= frozenset({DNSResponseClass.NODATA_EMPTY_ANSWER}):
        return ParentGatingDecision(
            allow_descendants=False,
            parent_name=parent_name,
            reason="Parent NODATA/empty response",
            evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
            response_class=DNSResponseClass.NODATA_EMPTY_ANSWER.value,
            confidence=ParentGatingConfidence.HEURISTIC_SKIP,
            diagnostic_message=(
                f"Skipped deeper candidates after NODATA/empty parent response for {parent_name}; "
                "this is a performance/evidence-quality choice, not proof that no deeper names exist."
            ),
        )

    return ParentGatingDecision(
        allow_descendants=False,
        parent_name=parent_name,
        reason="Parent validation inconclusive",
        evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
        response_class=None,
        confidence=ParentGatingConfidence.INCONCLUSIVE,
        diagnostic_message=(
            f"Skipped deeper candidates because parent validation was inconclusive for "
            f"{parent_name}."
        ),
    )


def outcome_from_parent_gating_skip(
    candidate: str,
    decision: ParentGatingDecision,
) -> EvidenceOutcome:
    """Build a descendant diagnostic outcome from a parent gating decision."""
    status = decision.evidence_status or EvidenceStatus.SKIPPED_BY_PARENT_GATING
    return EvidenceOutcome(
        fqdn=candidate,
        evidence_status=status,
        source_method="generated_candidate",
        detail=decision.diagnostic_message,
    )
