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


def decision_for_weak_parent_validation(
    parent_name: str,
    *,
    reason: str,
) -> ParentGatingDecision:
    """Parent has DNS records but only weak evidence (TXT-only or wildcard-pool echoes).

    Weak evidence does not open a full fifth-level sweep.  The weak-record path
    is triggered when a fresh apex probe returns records that are all TXT-only or
    all wildcard-pool A/AAAA echoes — none of which constitute strong validation.

    This is a performance and evidence-quality cutoff, not proof of absence.
    """
    return ParentGatingDecision(
        allow_descendants=False,
        parent_name=parent_name,
        reason=f"Weak parent evidence: {reason}",
        evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        response_class=None,
        confidence=ParentGatingConfidence.HEURISTIC_SKIP,
        diagnostic_message=(
            f"Skipped fifth-level sweep because the fourth-level parent {parent_name} "
            "was not strongly validated. "
            "This is a performance and evidence-quality cutoff, "
            "not proof that no deeper names exist."
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
    evidence_trace: list | None = None,
) -> ParentGatingDecision:
    """Map aggregated parent probe classes to a conservative gating decision."""
    traces = list(evidence_trace or [])

    def _finalize(decision: ParentGatingDecision) -> ParentGatingDecision:
        decision.evidence_trace = traces
        return decision

    if classes_seen & _POSITIVE_CLASSES:
        return decision_for_validated_parent(parent_name, record_count=0)

    if classes_seen & _INCONCLUSIVE_CLASSES:
        return _finalize(
            ParentGatingDecision(
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
        )

    if DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY in classes_seen and not (
        classes_seen & _POSITIVE_CLASSES
        or classes_seen & _INCONCLUSIVE_CLASSES
        or DNSResponseClass.UNRELATED_AUTHORITY in classes_seen
    ):
        # Ticket T32: branch apex is in-zone but has no direct records and is
        # not delegated.  Distinct from NXDOMAIN ("name absent") and from
        # UNRELATED_AUTHORITY ("non-parent authority").
        # EVIDENCE DISCIPLINE: this is NOT absence; do not say "does not exist."
        return _finalize(
            ParentGatingDecision(
                allow_descendants=False,
                parent_name=parent_name,
                reason="Parent apex has no direct DNS records (NODATA with parent authority)",
                evidence_status=EvidenceStatus.NODATA_PARENT_AUTHORITY,
                response_class=DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY.value,
                confidence=ParentGatingConfidence.HEURISTIC_SKIP,
                diagnostic_message=(
                    f"Skipped deeper candidates because {parent_name} had no direct DNS "
                    "records using tested methods (NODATA with parent-zone authority). "
                    "This does not prove descendants do not exist — the name is in-zone "
                    "but not delegated per this probe."
                ),
            )
        )

    if saw_unrelated_authority or DNSResponseClass.UNRELATED_AUTHORITY in classes_seen:
        return _finalize(
            ParentGatingDecision(
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
        )

    if DNSResponseClass.NEGATIVE_NXDOMAIN in classes_seen:
        return _finalize(
            ParentGatingDecision(
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
        )

    if classes_seen and classes_seen <= frozenset({DNSResponseClass.NODATA_EMPTY_ANSWER}):
        return _finalize(
            ParentGatingDecision(
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
        )

    return _finalize(
        ParentGatingDecision(
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
    )


def decision_for_rfc_branch_sentinel_hit(
    parent_name: str,
    *,
    sentinel_hit: str,
) -> ParentGatingDecision:
    """RFC branch opened because a sentinel probe found live DNS evidence.

    Tier 4 (Ticket 30): sentinel hit → allow_descendants=True so full 5th-level
    testing proceeds under this branch.
    """
    return ParentGatingDecision(
        allow_descendants=True,
        parent_name=parent_name,
        reason="RFC branch opened by sentinel probe",
        evidence_status=None,
        response_class=None,
        confidence=ParentGatingConfidence.VALIDATED_PARENT,
        diagnostic_message=(
            f"RFC branch {parent_name} opened because sentinel probe found live DNS evidence "
            f"({sentinel_hit}.{parent_name})."
        ),
    )


def decision_for_rfc_branch_sentinel_miss(parent_name: str) -> ParentGatingDecision:
    """RFC branch skipped after apex + sentinel probes found no evidence.

    Tier 3 miss (Ticket 30): heuristic-skip disclosure required.  A sentinel miss
    is NOT proof of absence — it means no tested sentinel name resolved, not that
    no deeper names exist under the branch.  The diagnostic_message carries the
    mandatory AIPF disclosure text.
    """
    return ParentGatingDecision(
        allow_descendants=False,
        parent_name=parent_name,
        reason="RFC branch skipped by parent-gating heuristic after apex and sentinel checks",
        evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        response_class=None,
        confidence=ParentGatingConfidence.HEURISTIC_SKIP,
        diagnostic_message=(
            f"Branch {parent_name} skipped by parent-gating heuristic after apex and sentinel "
            "checks found no evidence. This is not proof that no deeper names exist."
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
        evidence_trace=list(decision.evidence_trace),
    )
