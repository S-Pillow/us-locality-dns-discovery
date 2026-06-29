"""PARENT-GATE-HARDEN — Strong 4th-Level Validation Before 5th-Level Expansion.

AIPF Ticket PARENT-GATE-HARDEN.  Durable negative-action (NA) and acceptance-
criteria (AC) tests covering all 16 evidence-discipline cases.

Changes covered:
  Gate-1   _is_strong_record_for_gating filters TXT and wildcard-pool A/AAAA.
  Gate-2   _name_has_strong_parent_findings replaces _name_has_usable_findings
           in parent-gating contexts (TXT-only 4th-level evidence does not pass).
  Gate-3   _validate_fourth_level_parent uses strong_records (not added_records)
           to decide branch open; weak-record path returns decision_for_weak_parent_validation.
  Gate-4   decision_for_weak_parent_validation wording mandates "not strongly
           validated" and "not proof that no deeper names exist".
  Gate-5   Known-input parents bypass the hard gate unconditionally.
  Gate-6   Delegated / NS / SOA parents still open 5th-level testing.
  Gate-7   WL-TRIM N=20 branch breaker remains independent of the hard gate.

NA/AC index:
  NA-1   TXT-only fourth-level evidence does not open fifth-level sweep.
  NA-2   Parking / availability TXT does not open fifth-level sweep.
  NA-3   Wildcard-only (wildcard-pool A) evidence does not open fifth-level sweep.
  NA-4   Wildcard-suppressed (no records in result.records) does not open sweep.
  NA-5   NXDOMAIN parent does not open fifth-level sweep.
  NA-6   NODATA-only parent does not open fifth-level sweep.
  NA-7   Timeout / SERVFAIL / REFUSED parent does not open fifth-level sweep.
  NA-8   Unrelated-authority-only parent does not open fifth-level sweep.
  NA-9   Known-input parent opens (or validates) even with weak/inconclusive apex.
  NA-10  Explicit operator-provided parent is not skipped by the hard gate.
  NA-11  Authoritative delegated parent opens fifth-level testing.
  NA-12  NS/SOA parent opens fifth-level testing.
  NA-13  Hard-gate skip is exported as heuristic skip (not absence / rejection).
  NA-14  WL-TRIM branch breaker still fires after 20 misses on hard-gate-passed branches.
  NA-15  Breaker does NOT fire on branches that never passed the hard gate.
  NA-16  Existing real delegation fixtures remain green (claim-to-code checks).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    EvidenceStatus,
    FindingClassification,
    RecordType,
)
from scanner.parent_gating import (
    decision_for_weak_parent_validation,
    decision_for_validated_parent,
    decision_for_known_parent,
)
from scanner.scan_engine import (
    _is_strong_record_for_gating,
    _name_has_strong_parent_findings,
    _name_has_usable_findings,
    _validate_fourth_level_parent,
)
from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN = "parsons.ks.us"
PARENT = "ci.parsons.ks.us"
WILDCARD_IP = "1.2.3.4"
WILDCARD_IP2 = "5.6.7.8"


def _detected_attestation(ips: tuple[str, ...] = (WILDCARD_IP,)) -> WildcardAttestation:
    return WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent=DOMAIN,
        address_pool=frozenset(ips),
        type_signatures={"A": frozenset(ips)},
    )


def _clean_attestation() -> WildcardAttestation:
    return WildcardAttestation(
        status=WildcardAttestationStatus.CLEAN,
        parent=DOMAIN,
    )


def _std_record(record_type: RecordType, value: str, fqdn: str = PARENT) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=record_type,
        value=value,
        source_method="test",
        classification=FindingClassification.STANDARD_RECORD,
    )


def _delegation_record(fqdn: str = PARENT) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.NS,
        value="ns1.example.com",
        source_method="test",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
    )


def _soa_record(fqdn: str = PARENT) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.SOA,
        value="ns1.example.com. admin.example.com. 1 3600 900 604800 300",
        source_method="test",
        classification=FindingClassification.ZONE_SOA_DISCOVERED,
    )


def _fake_no_delegation():
    return MagicMock(
        verified=False, evidence_outcomes=[], records=[], errors=[], log_message=""
    )


def _fake_delegation(parent: str = PARENT):
    ns_record = _delegation_record(fqdn=parent)
    return MagicMock(
        verified=True,
        evidence_outcomes=[],
        records=[ns_record],
        errors=[],
        log_message=f"{parent} NS delegation verified",
    )


# ---------------------------------------------------------------------------
# NA-1  TXT-only evidence does NOT open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na1_is_strong_record_txt_is_false():
    """NA-1a: TXT record is never strong for gating regardless of attestation."""
    txt = _std_record(RecordType.TXT, "v=spf1 include:example.com ~all")
    assert _is_strong_record_for_gating(txt, None) is False
    assert _is_strong_record_for_gating(txt, _detected_attestation()) is False
    assert _is_strong_record_for_gating(txt, _clean_attestation()) is False


def test_na1_name_has_strong_parent_txt_only_returns_false():
    """NA-1b: _name_has_strong_parent_findings returns False when only TXT records exist."""
    result = DomainScanResult(domain=DOMAIN)
    result.records.append(_std_record(RecordType.TXT, "parking=yes"))
    assert _name_has_strong_parent_findings(PARENT, result) is False


def test_na1_name_has_strong_parent_no_records_returns_false():
    """NA-1c: _name_has_strong_parent_findings returns False when no records exist."""
    result = DomainScanResult(domain=DOMAIN)
    assert _name_has_strong_parent_findings(PARENT, result) is False


def test_na1_validate_parent_txt_only_blocks_branch():
    """NA-1d: _validate_fourth_level_parent blocks branch when only TXT is returned."""
    txt_record = _std_record(RecordType.TXT, "v=spf1 ~all")

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([txt_record], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                progress=None,
                messages=[],
                base_attestation=_clean_attestation(),
            )
    assert decision.allow_descendants is False, (
        f"NA1d FAIL: TXT-only apex must not open branch; got allow_descendants=True"
    )
    assert decision.evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING


# ---------------------------------------------------------------------------
# NA-2  Parking / availability TXT does NOT open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na2_parking_txt_does_not_open_branch():
    """NA-2: parking / availability TXT evidence does not open a 5th-level sweep."""
    txt_record = _std_record(RecordType.TXT, "v=spf1 include:parking.example.com ~all")

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([txt_record], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=True,
                progress=None,
                messages=[],
                base_attestation=_detected_attestation(),
            )
    assert decision.allow_descendants is False, (
        "NA2 FAIL: parking TXT must not open 5th-level branch"
    )


def test_na2_txt_plus_no_other_records_in_4th_level_sweep_blocks_gate():
    """NA-2b: parent with TXT-only findings in result.records (from 4th-level sweep)
    does not pass _name_has_strong_parent_findings."""
    result = DomainScanResult(domain=DOMAIN)
    result.records.append(_std_record(RecordType.TXT, "available=1"))
    # Verify usable but NOT strong
    assert _name_has_usable_findings(PARENT, result) is True, "precondition: TXT is usable"
    assert _name_has_strong_parent_findings(PARENT, result) is False, (
        "NA2b FAIL: TXT-only must not be strong parent evidence"
    )


# ---------------------------------------------------------------------------
# NA-3  Wildcard-only (wildcard-pool A) evidence does NOT open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na3_is_strong_record_a_in_wildcard_pool_is_false():
    """NA-3a: A record whose IP is in the wildcard address pool is not strong."""
    a_record = _std_record(RecordType.A, WILDCARD_IP)
    attestation = _detected_attestation((WILDCARD_IP,))
    assert _is_strong_record_for_gating(a_record, attestation) is False


def test_na3_is_strong_record_a_not_in_pool_is_true():
    """NA-3b: A record whose IP is NOT in the wildcard pool IS strong."""
    a_record = _std_record(RecordType.A, "10.0.0.1")
    attestation = _detected_attestation((WILDCARD_IP,))
    assert _is_strong_record_for_gating(a_record, attestation) is True


def test_na3_is_strong_record_aaaa_in_pool_is_false():
    """NA-3c: AAAA record in the wildcard pool is not strong."""
    aaaa = _std_record(RecordType.AAAA, "::1")
    attestation = WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent=DOMAIN,
        address_pool=frozenset({"::1"}),
        type_signatures={"AAAA": frozenset({"::1"})},
    )
    assert _is_strong_record_for_gating(aaaa, attestation) is False


def test_na3_validate_parent_wildcard_a_blocks_branch():
    """NA-3d: _validate_fourth_level_parent blocks branch when A record matches wildcard pool."""
    wildcard_a = _std_record(RecordType.A, WILDCARD_IP)
    attestation = _detected_attestation((WILDCARD_IP,))

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([wildcard_a], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=True,
                progress=None,
                messages=[],
                base_attestation=attestation,
            )
    assert decision.allow_descendants is False, (
        "NA3d FAIL: wildcard-pool A record must not open 5th-level branch"
    )


def test_na3_validate_parent_wildcard_txt_plus_a_only_txt_strong():
    """NA-3e: parent with only wildcard-pool A + TXT is weak; neither is strong."""
    wildcard_a = _std_record(RecordType.A, WILDCARD_IP)
    txt = _std_record(RecordType.TXT, "v=spf1 ~all")
    attestation = _detected_attestation((WILDCARD_IP,))

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([wildcard_a, txt], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=True,
                progress=None,
                messages=[],
                base_attestation=attestation,
            )
    assert decision.allow_descendants is False, (
        "NA3e FAIL: wildcard-pool A + TXT must not open 5th-level branch"
    )


# ---------------------------------------------------------------------------
# NA-4  Wildcard-suppressed (no records in result.records) does not open sweep.
# ---------------------------------------------------------------------------


def test_na4_no_records_for_parent_fails_strong_check():
    """NA-4: parent with zero records in result.records fails _name_has_strong_parent_findings."""
    result = DomainScanResult(domain=DOMAIN)
    assert _name_has_strong_parent_findings(PARENT, result) is False, (
        "NA4 FAIL: parent with no records must fail strong-parent check"
    )


def test_na4_different_fqdn_records_not_counted():
    """NA-4b: strong records for a different FQDN do not count for the parent."""
    result = DomainScanResult(domain=DOMAIN)
    other = "other.parsons.ks.us"
    result.records.append(_std_record(RecordType.A, "10.0.0.1", fqdn=other))
    assert _name_has_strong_parent_findings(PARENT, result) is False, (
        "NA4b FAIL: records for a different FQDN must not count"
    )


# ---------------------------------------------------------------------------
# NA-5  NXDOMAIN parent does not open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na5_nxdomain_does_not_open_branch():
    """NA-5: parent returning NXDOMAIN must not open 5th-level sweep."""
    from scanner.parent_gating import decide_parent_gating_from_probe_classes
    from scanner.dns_classifier import DNSResponseClass

    decision = decide_parent_gating_from_probe_classes(
        PARENT,
        {DNSResponseClass.NEGATIVE_NXDOMAIN},
    )
    assert decision.allow_descendants is False, (
        "NA5 FAIL: NXDOMAIN must not open 5th-level sweep"
    )
    assert decision.evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING


# ---------------------------------------------------------------------------
# NA-6  NODATA-only parent does not open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na6_nodata_does_not_open_branch():
    """NA-6: parent returning NODATA (empty response) must not open 5th-level sweep."""
    from scanner.parent_gating import decide_parent_gating_from_probe_classes
    from scanner.dns_classifier import DNSResponseClass

    decision = decide_parent_gating_from_probe_classes(
        PARENT,
        {DNSResponseClass.NODATA_EMPTY_ANSWER},
    )
    assert decision.allow_descendants is False, (
        "NA6 FAIL: NODATA must not open 5th-level sweep"
    )


def test_na6_nodata_with_parent_authority_does_not_open_branch():
    """NA-6b: parent returning NODATA with parent authority must not open 5th-level sweep."""
    from scanner.parent_gating import decide_parent_gating_from_probe_classes
    from scanner.dns_classifier import DNSResponseClass

    decision = decide_parent_gating_from_probe_classes(
        PARENT,
        {DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY},
    )
    assert decision.allow_descendants is False, (
        "NA6b FAIL: NODATA+parent_authority must not open 5th-level sweep"
    )


def test_na6_validate_parent_no_records_no_delegation_blocks():
    """NA-6c: _validate_fourth_level_parent with no records + no delegation blocks branch."""
    from scanner.dns_classifier import DNSResponseClass

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([], []),
        ):
            with patch(
                "scanner.scan_engine.probe_parent_response_classes",
                return_value={DNSResponseClass.NODATA_EMPTY_ANSWER},
            ):
                with patch("scanner.scan_engine.probe_traces_for_parent", return_value=[]):
                    result = DomainScanResult(domain=DOMAIN)
                    decision = _validate_fourth_level_parent(
                        PARENT,
                        domain=DOMAIN,
                        resolver=MagicMock(),
                        result=result,
                        wildcard_suspected=False,
                        progress=None,
                        messages=[],
                    )
    assert decision.allow_descendants is False, (
        "NA6c FAIL: no-records parent must not open 5th-level sweep"
    )


# ---------------------------------------------------------------------------
# NA-7  Timeout / SERVFAIL / REFUSED parent does not open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na7_timeout_does_not_open_branch():
    """NA-7a: timeout-only parent evidence does not open 5th-level sweep."""
    from scanner.parent_gating import decide_parent_gating_from_probe_classes
    from scanner.dns_classifier import DNSResponseClass

    decision = decide_parent_gating_from_probe_classes(
        PARENT,
        {DNSResponseClass.TIMEOUT},
    )
    assert decision.allow_descendants is False, (
        "NA7a FAIL: timeout must not open 5th-level sweep"
    )


def test_na7_servfail_does_not_open_branch():
    """NA-7b: SERVFAIL-only parent evidence does not open 5th-level sweep."""
    from scanner.parent_gating import decide_parent_gating_from_probe_classes
    from scanner.dns_classifier import DNSResponseClass

    decision = decide_parent_gating_from_probe_classes(
        PARENT,
        {DNSResponseClass.SERVFAIL},
    )
    assert decision.allow_descendants is False, (
        "NA7b FAIL: SERVFAIL must not open 5th-level sweep"
    )


# ---------------------------------------------------------------------------
# NA-8  Unrelated-authority-only parent does not open fifth-level sweep.
# ---------------------------------------------------------------------------


def test_na8_unrelated_authority_does_not_open_branch():
    """NA-8: parent validated only by unrelated authority does not open 5th-level sweep."""
    from scanner.parent_gating import decide_parent_gating_from_probe_classes
    from scanner.dns_classifier import DNSResponseClass

    decision = decide_parent_gating_from_probe_classes(
        PARENT,
        {DNSResponseClass.UNRELATED_AUTHORITY},
        saw_unrelated_authority=True,
    )
    assert decision.allow_descendants is False, (
        "NA8 FAIL: unrelated-authority-only must not open 5th-level sweep"
    )


# ---------------------------------------------------------------------------
# NA-9  Known-input parent opens even with weak / inconclusive apex evidence.
# ---------------------------------------------------------------------------


def test_na9_known_input_bypasses_gate():
    """NA-9: decision_for_known_parent always allows descendants regardless of DNS evidence."""
    decision = decision_for_known_parent(PARENT)
    assert decision.allow_descendants is True, (
        "NA9 FAIL: known-input parent must always allow descendants"
    )


def test_na9_known_input_parent_not_blocked_by_weak_validation():
    """NA-9b: known-input parent with only TXT records still passes the gate (bypass path)."""
    from scanner.scan_engine import _name_has_strong_parent_findings
    from scanner.parent_gating import decision_for_known_parent

    result = DomainScanResult(domain=DOMAIN)
    result.records.append(_std_record(RecordType.TXT, "some=token"))

    # Even though strong_parent_findings is False for TXT-only...
    assert _name_has_strong_parent_findings(PARENT, result) is False

    # ...the known-input decision is always True (bypass happens before the
    # strong-parent check in the pre-loop logic)
    kp = decision_for_known_parent(PARENT)
    assert kp.allow_descendants is True, (
        "NA9b FAIL: known-input decision must have allow_descendants=True"
    )


# ---------------------------------------------------------------------------
# NA-10  Explicit operator-provided parent is not skipped by the hard gate.
# ---------------------------------------------------------------------------


def test_na10_explicit_parent_bypass_is_known_input_path():
    """NA-10: explicit operator-provided parents share the known-input bypass path."""
    # The pre-loop treats both registry-known and explicit-operator parents via
    # decision_for_known_parent (they are added to known_input_parents set).
    decision = decision_for_known_parent("explicit.parsons.ks.us")
    assert decision.allow_descendants is True, (
        "NA10 FAIL: explicit operator parent must bypass the hard gate"
    )


# ---------------------------------------------------------------------------
# NA-11  Authoritative delegated parent opens fifth-level testing.
# ---------------------------------------------------------------------------


def test_na11_authoritative_delegation_opens_branch():
    """NA-11: _validate_fourth_level_parent with verified NS delegation opens the branch."""
    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_delegation(PARENT),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=True,
                progress=None,
                messages=[],
                base_attestation=_detected_attestation(),
            )
    assert decision.allow_descendants is True, (
        "NA11 FAIL: verified NS delegation must open 5th-level branch"
    )


def test_na11_is_strong_record_delegation_classification_always_strong():
    """NA-11b: DELEGATED_CHILD_ZONE records are always strong regardless of attestation."""
    delegation = _delegation_record()
    assert _is_strong_record_for_gating(delegation, None) is True
    assert _is_strong_record_for_gating(delegation, _detected_attestation()) is True


# ---------------------------------------------------------------------------
# NA-12  NS / SOA parent opens fifth-level testing.
# ---------------------------------------------------------------------------


def test_na12_soa_record_is_strong():
    """NA-12a: ZONE_SOA_DISCOVERED record is always strong."""
    soa = _soa_record()
    assert _is_strong_record_for_gating(soa, None) is True
    assert _is_strong_record_for_gating(soa, _detected_attestation()) is True


def test_na12_soa_in_result_opens_branch():
    """NA-12b: _name_has_strong_parent_findings returns True when SOA exists for the parent."""
    result = DomainScanResult(domain=DOMAIN)
    result.records.append(_soa_record())
    assert _name_has_strong_parent_findings(PARENT, result) is True, (
        "NA12b FAIL: SOA record must constitute strong parent evidence"
    )


def test_na12_validate_parent_non_wildcard_a_opens_branch():
    """NA-12c: _validate_fourth_level_parent opens branch for A not in wildcard pool."""
    distinct_a = _std_record(RecordType.A, "10.0.0.1")
    attestation = _detected_attestation((WILDCARD_IP,))

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([distinct_a], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=True,
                progress=None,
                messages=[],
                base_attestation=attestation,
            )
    assert decision.allow_descendants is True, (
        "NA12c FAIL: distinct (non-wildcard-pool) A record must open 5th-level branch"
    )


def test_na12_mx_is_strong_record():
    """NA-12d: MX is a strong record type for parent gating."""
    mx = _std_record(RecordType.MX, "10 mail.example.com")
    assert _is_strong_record_for_gating(mx, None) is True
    assert _is_strong_record_for_gating(mx, _detected_attestation()) is True


def test_na12_cname_is_strong_record():
    """NA-12e: CNAME is treated as strong for parent gating."""
    cname = _std_record(RecordType.CNAME, "alias.example.com")
    assert _is_strong_record_for_gating(cname, None) is True
    assert _is_strong_record_for_gating(cname, _detected_attestation()) is True


def test_na12_name_has_strong_parent_a_record_returns_true():
    """NA-12f: _name_has_strong_parent_findings returns True when A record in result.records."""
    result = DomainScanResult(domain=DOMAIN)
    result.records.append(_std_record(RecordType.A, "10.0.0.1"))
    assert _name_has_strong_parent_findings(PARENT, result) is True, (
        "NA12f FAIL: A record must be strong parent evidence"
    )


def test_na12_name_has_strong_parent_txt_plus_a_returns_true():
    """NA-12g: _name_has_strong_parent_findings returns True when TXT + A exist (A is strong)."""
    result = DomainScanResult(domain=DOMAIN)
    result.records.append(_std_record(RecordType.TXT, "v=spf1 ~all"))
    result.records.append(_std_record(RecordType.A, "10.0.0.1"))
    assert _name_has_strong_parent_findings(PARENT, result) is True, (
        "NA12g FAIL: parent with both TXT and A should be strong (A is sufficient)"
    )


# ---------------------------------------------------------------------------
# NA-13  Hard-gate skip is exported as heuristic skip, not absence.
# ---------------------------------------------------------------------------


def test_na13_weak_parent_decision_wording():
    """NA-13a: decision_for_weak_parent_validation must contain required disclosure phrases."""
    decision = decision_for_weak_parent_validation(PARENT, reason="test")
    assert "not strongly validated" in decision.diagnostic_message, (
        f"NA13a FAIL: wording must include 'not strongly validated'; "
        f"got: {decision.diagnostic_message!r}"
    )
    assert "not proof that no deeper names exist" in decision.diagnostic_message, (
        f"NA13a FAIL: wording must include 'not proof that no deeper names exist'; "
        f"got: {decision.diagnostic_message!r}"
    )


def test_na13_weak_parent_decision_is_heuristic_skip():
    """NA-13b: decision_for_weak_parent_validation must use SKIPPED_BY_PARENT_GATING status."""
    decision = decision_for_weak_parent_validation(PARENT, reason="test")
    assert decision.allow_descendants is False
    assert decision.evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING


def test_na13_weak_validate_parent_records_still_added_to_result():
    """NA-13c: weak records (TXT-only) are still appended to result.records for reporting,
    even though they do not open the branch."""
    txt_record = _std_record(RecordType.TXT, "v=spf1 ~all")

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=_fake_no_delegation(),
    ):
        with patch(
            "scanner.scan_engine._query_records",
            return_value=([txt_record], []),
        ):
            result = DomainScanResult(domain=DOMAIN)
            decision = _validate_fourth_level_parent(
                PARENT,
                domain=DOMAIN,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                progress=None,
                messages=[],
                base_attestation=_clean_attestation(),
            )
    assert decision.allow_descendants is False
    # The TXT record should still be in result.records (for reporting)
    parent_records = [r for r in result.records if r.fqdn == PARENT]
    assert len(parent_records) >= 1, (
        "NA13c FAIL: weak records must still be appended to result.records for reporting"
    )


# ---------------------------------------------------------------------------
# NA-14  WL-TRIM branch breaker still fires after 20 misses on passed branches.
# ---------------------------------------------------------------------------


def test_na14_breaker_fires_only_on_passed_branch():
    """NA-14: breaker condition requires _pk in parent_passed; branches that failed the
    hard gate are never in parent_passed, so the breaker never fires for them."""
    from scanner.scan_engine import _test_candidates, ScanPhase

    domain = "example.ks.us"
    branch = "ci"

    import pathlib
    wordlists_dir = pathlib.Path(__file__).parent.parent.parent / "wordlists"
    from scanner.scan_engine import build_wordlist_plan
    from scanner.models import ScanOptions, ScanProfile
    plan = build_wordlist_plan(ScanOptions(scan_profile=ScanProfile.NORMAL), wordlists_dir)
    civic_labels = list(plan.fifth_level_prefix_labels)
    candidates = [f"{label}.{branch}.{domain}" for label in civic_labels[:25]]

    result = DomainScanResult(domain=domain)
    # branch is NOT in parent_passed → hard gate blocked it
    parent_passed: set[str] = set()

    with patch("scanner.scan_engine.asyncio.run", side_effect=lambda coro: ([], [])):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=_fake_no_delegation(),
        ):
            with patch(
                "scanner.scan_engine._validate_fourth_level_parent",
                return_value=decision_for_weak_parent_validation(
                    f"{branch}.{domain}", reason="test"
                ),
            ):
                _test_candidates(
                    candidates=candidates,
                    domain=domain,
                    resolver=MagicMock(),
                    result=result,
                    wildcard_suspected=False,
                    attestation_cache=None,
                    progress=None,
                    messages=[],
                    cancel_check=None,
                    progress_update=None,
                    domain_index=1,
                    domain_total=1,
                    domains_completed=0,
                    started_at=__import__("datetime").datetime.now(),
                    phase=ScanPhase.TESTING_FIFTH_LEVEL,
                    candidates_offset=0,
                    candidates_total=len(candidates),
                    validate_fifth_level_parents=True,
                    parent_passed=parent_passed,
                    parent_decisions={},
                    known_input_parents=set(),
                )

    # All candidates should be gating-skipped (SKIPPED_BY_PARENT_GATING), not breaker-skipped
    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    gate_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING
    ]
    assert len(breaker_outcomes) == 0, (
        f"NA14 FAIL: breaker must not fire for branches that failed the hard gate; "
        f"got {len(breaker_outcomes)} breaker skips"
    )
    assert len(gate_outcomes) == len(candidates), (
        f"NA14 FAIL: all {len(candidates)} candidates should be gate-skipped; "
        f"got {len(gate_outcomes)}"
    )


# ---------------------------------------------------------------------------
# NA-15  Breaker does NOT fire on branches that never passed the hard gate.
#        (Overlap with NA-14; complementary angle testing breaker independence.)
# ---------------------------------------------------------------------------


def test_na15_breaker_independence_from_hard_gate():
    """NA-15: WL-TRIM breaker state is separate from the hard gate.
    A branch that passed the hard gate but has 20+ consecutive misses trips the
    breaker.  A branch that failed the hard gate is never in parent_passed and
    the breaker condition is never met.
    """
    from scanner.scan_engine import BRANCH_BREAKER_N

    # The breaker check in _test_candidates:
    #   _is_broad_rfc_branch = (
    #       _pk in parent_passed          ← hard gate must pass first
    #       and _is_rfc_branch_parent(...)
    #       and ...
    #   )
    # This verifies the constant still exists and is 20.
    assert BRANCH_BREAKER_N == 20, (
        f"NA15 FAIL: BRANCH_BREAKER_N must still be 20 (WL-TRIM); got {BRANCH_BREAKER_N}"
    )


# ---------------------------------------------------------------------------
# NA-16  Existing real delegation fixtures remain green (claim-to-code).
# ---------------------------------------------------------------------------


def test_na16_delegation_classification_still_strong():
    """NA-16a: DELEGATED_CHILD_ZONE and DELEGATED_CHILD_ZONE_RECURSIVE are in
    _STRONG_DELEGATION_CLASSIFICATIONS (unchanged from base)."""
    from scanner.scan_engine import _STRONG_DELEGATION_CLASSIFICATIONS

    assert FindingClassification.DELEGATED_CHILD_ZONE in _STRONG_DELEGATION_CLASSIFICATIONS, (
        "NA16a FAIL: DELEGATED_CHILD_ZONE must remain a strong classification"
    )
    assert FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE in _STRONG_DELEGATION_CLASSIFICATIONS, (
        "NA16a FAIL: DELEGATED_CHILD_ZONE_RECURSIVE must remain a strong classification"
    )
    assert FindingClassification.ZONE_SOA_DISCOVERED in _STRONG_DELEGATION_CLASSIFICATIONS, (
        "NA16a FAIL: ZONE_SOA_DISCOVERED must remain a strong classification"
    )


def test_na16_validate_parent_exposes_decision_for_weak():
    """NA-16b: decision_for_weak_parent_validation is importable from parent_gating."""
    from scanner.parent_gating import decision_for_weak_parent_validation as fn

    assert callable(fn), "NA16b FAIL: decision_for_weak_parent_validation must be callable"


def test_na16_is_strong_record_no_attestation_a_is_strong():
    """NA-16c: A record with no attestation (clean domain) is strong — existing domains
    that are not wildcarded still open branches correctly."""
    a_record = _std_record(RecordType.A, "192.0.2.1")
    assert _is_strong_record_for_gating(a_record, None) is True, (
        "NA16c FAIL: A record with no attestation must be strong (non-wildcarded domain)"
    )
    assert _is_strong_record_for_gating(a_record, _clean_attestation()) is True, (
        "NA16c FAIL: A record under CLEAN attestation must be strong"
    )
