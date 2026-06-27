#!/usr/bin/env python3
"""R4a verification: wildcard attestation engine + promotion gate.

Durable regression tests confirming all six acceptance criteria and their
negative-action guards.  All DNS interactions are synthetic (mocked); no
live network calls occur.

Acceptance criteria verified:
  AC1 — no wildcard + DNS evidence → candidate promotes
  AC2 — response matches wildcard signature → suppressed to diagnostic
  AC3 — wildcard detected but candidate differentiates → promotes
  AC4 — wildcard attestation inconclusive → not promoted in Light
  AC5 — TTL-only difference does NOT bypass suppression
  AC6 — parent-zone authority SOA in negative response is NOT wildcard confirmation

Additional contract checks:
  §1  per-parent scoping (wildcard at parent-A does not suppress under parent-B)
  §4  parent-SOA-in-negative-response gate
  §6  rotating A/AAAA pool containment
  R4a-gate — gate code path cited per claim-to-code rule (suppressed candidate does
              NOT appear as confirmed; inconclusive candidate does NOT promote)
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.regression._chain import run_durable_regression
from tests.regression._paths import REGRESSION_DIR

import dns.rdatatype

from scanner.evidence_status import (
    is_confirmed_evidence_status,
    outcome_suppressed_wildcard_match,
    outcome_withheld_wildcard_inconclusive,
)
from scanner.export_service import (
    build_confirmed_findings_rows,
    build_diagnostics_rows,
)
from scanner.models import (
    DomainInputRecord,
    DomainScanResult,
    DiscoveredRecord,
    EvidenceOutcome,
    EvidenceStatus,
    FindingClassification,
    RecordType,
    ScanInput,
    ScanOptions,
    ScanProfile,
    ScanRunResult,
    ScanStatus,
    WordlistPlan,
)
from scanner.paths import get_wordlists_dir
from scanner.wildcard_attestation import (
    WildcardAttestation,
    WildcardAttestationStatus,
    candidate_differentiates,
    run_wildcard_attestation,
)


# ---------------------------------------------------------------------------
# Fake DNS response helpers — no live network calls
# ---------------------------------------------------------------------------


class _FakeRdata:
    """Minimal dns.rdata stand-in: just enough for .to_text()."""

    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeRRset:
    """Minimal dns.rrset stand-in supporting rdtype + iteration over rdatas."""

    def __init__(self, rdtype: int, rdatas: list[_FakeRdata]) -> None:
        self.rdtype = rdtype
        self._rdatas = rdatas

    def __iter__(self):
        return iter(self._rdatas)


class _FakeResponse:
    """Minimal dns.message.Message stand-in: .answer and .authority lists."""

    def __init__(
        self,
        answer_rrsets: list[_FakeRRset] | None = None,
        authority_has_soa: bool = False,
    ) -> None:
        self.answer: list[_FakeRRset] = answer_rrsets or []
        # authority section included for realism in the SOA-only tests;
        # _response_has_answer_records only checks self.answer, so this is irrelevant
        # to wildcard detection — used to make the test intent explicit.
        self.authority: list[str] = ["soa.placeholder"] if authority_has_soa else []


def _a_response(ip: str) -> _FakeResponse:
    """Response with a single A record in the answer section."""
    return _FakeResponse(
        answer_rrsets=[
            _FakeRRset(dns.rdatatype.from_text("A"), [_FakeRdata(ip)])
        ]
    )


def _nxdomain_with_authority_soa() -> _FakeResponse:
    """NXDOMAIN-like response: empty answer section, SOA only in authority (§4).

    This is the normal negative answer from a delegated zone — the parent-zone
    SOA in the authority section must NOT be treated as wildcard confirmation.
    """
    return _FakeResponse(answer_rrsets=[], authority_has_soa=True)


# Reusable send-function stubs
def _error_send(fqdn, rr_type, resolver):
    """Simulates total network failure — every query returns an error."""
    return None, f"simulated timeout: {fqdn} {rr_type.value}"


def _clean_send(fqdn, rr_type, resolver):
    """Simulates a clean zone — all queries return NXDOMAIN with authority SOA."""
    return _nxdomain_with_authority_soa(), None


def _wildcard_a_send(fqdn, rr_type, resolver):
    """Simulates a wildcard zone that answers A queries with 1.2.3.4."""
    if rr_type.value == "A":
        return _a_response("1.2.3.4"), None
    return _FakeResponse(), None  # other types: empty answer


# ---------------------------------------------------------------------------
# DiscoveredRecord fixtures
# ---------------------------------------------------------------------------


def _a_record(fqdn: str, ip: str, ttl: int = 300) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.A,
        value=ip,
        source_method="generated_candidate",
        classification=FindingClassification.STANDARD_RECORD,
        ttl=ttl,
        evidence_status=EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME,
    )


def _ns_record(fqdn: str) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.NS,
        value="ns1.example.com",
        source_method="delegation_verifier",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
    )


# ---------------------------------------------------------------------------
# WildcardAttestation fixture builder
# ---------------------------------------------------------------------------


def _detected(type_sigs: dict[str, set[str]]) -> WildcardAttestation:
    """Build a DETECTED attestation from a dict of type → IP/value sets."""
    address_pool: frozenset[str] = frozenset(type_sigs.get("A", set())) | frozenset(
        type_sigs.get("AAAA", set())
    )
    return WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="ci.lawrence.ma.us",
        type_signatures={k: frozenset(v) for k, v in type_sigs.items()},
        address_pool=address_pool,
    )


# ---------------------------------------------------------------------------
# Minimal ScanRunResult builder (for export-layer tests)
# ---------------------------------------------------------------------------


def _make_run_result(
    base: str,
    records: list[DiscoveredRecord],
    evidence_outcomes: list[EvidenceOutcome],
) -> ScanRunResult:
    domain_result = DomainScanResult(
        domain=base,
        records=records,
        evidence_outcomes=evidence_outcomes,
        candidates_tested=len(records) + len(evidence_outcomes),
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(f"{base}\n")
        domain_file = Path(f.name)
    out_dir = Path(tempfile.mkdtemp())
    scan_input = ScanInput(
        domain_file_path=domain_file,
        options=ScanOptions(scan_profile=ScanProfile.LIGHT),
        output_dir=out_dir,
        wordlists_dir=get_wordlists_dir(),
    )
    return ScanRunResult(
        input=scan_input,
        domain_results=[domain_result],
        scan_timestamp=datetime(2026, 1, 1),
        scan_status=ScanStatus.COMPLETED,
        wordlist_plan=WordlistPlan(total_unique_labels=4, estimated_candidates_per_domain=4),
        domains_total=1,
        domains_planned=[base],
        domain_inputs=[],
    )


# ===========================================================================
# 0 — Prior regression chain
# ===========================================================================


def test_prior_chain() -> None:
    """T31 regression must pass before R4a tests run."""
    run_durable_regression(REGRESSION_DIR / "test_ticket31_report_contract.py")
    print("  prior chain: test_ticket31_report_contract passed")


# ===========================================================================
# 1 — run_wildcard_attestation unit tests
# ===========================================================================


def test_attestation_clean() -> None:
    """All probes return NXDOMAIN (empty answer) → CLEAN attestation."""
    att = run_wildcard_attestation("ci.lawrence.ma.us", _clean_send, None)
    assert att.status == WildcardAttestationStatus.CLEAN, (
        f"Expected CLEAN, got {att.status}"
    )
    assert att.type_signatures == {}, (
        f"No type signatures expected for CLEAN: {att.type_signatures}"
    )
    print("  PASS test_attestation_clean")


def test_attestation_detected() -> None:
    """Probes return A=1.2.3.4 → DETECTED with correct type signature and address pool."""
    att = run_wildcard_attestation("ci.lawrence.ma.us", _wildcard_a_send, None)
    assert att.status == WildcardAttestationStatus.DETECTED, (
        f"Expected DETECTED, got {att.status}"
    )
    assert "A" in att.type_signatures, "Expected A in type_signatures"
    assert "1.2.3.4" in att.type_signatures["A"], (
        "Expected 1.2.3.4 in A signature"
    )
    assert "1.2.3.4" in att.address_pool, "Expected 1.2.3.4 in address_pool (§6)"
    print("  PASS test_attestation_detected")


def test_attestation_inconclusive() -> None:
    """All probe queries error → INCONCLUSIVE attestation (not enough data)."""
    att = run_wildcard_attestation("ci.lawrence.ma.us", _error_send, None)
    assert att.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"Expected INCONCLUSIVE, got {att.status}"
    )
    print("  PASS test_attestation_inconclusive")


def test_ac6_parent_soa_in_authority_not_wildcard() -> None:
    """AC6: parent-zone authority SOA in negative response ≠ wildcard confirmation.

    _clean_send returns a response with an empty answer section and a non-empty
    authority section (the normal NXDOMAIN shape).  The attestation engine looks
    only at the answer section (_response_has_answer_records) so the parent SOA
    in authority must not trigger DETECTED.
    """
    att = run_wildcard_attestation("ci.lawrence.ma.us", _clean_send, None)
    assert att.status == WildcardAttestationStatus.CLEAN, (
        f"AC6 FAIL: authority-section SOA must NOT trigger wildcard DETECTED; got {att.status}"
    )
    print("  PASS test_ac6_parent_soa_in_authority_not_wildcard (AC6 negative-action)")


# ===========================================================================
# 2 — candidate_differentiates unit tests
# ===========================================================================


def test_ac1_clean_parent_always_promotes() -> None:
    """AC1: CLEAN parent → candidate_differentiates returns True unconditionally."""
    att = WildcardAttestation(
        status=WildcardAttestationStatus.CLEAN, parent="ci.lawrence.ma.us"
    )
    records = [_a_record("mail.ci.lawrence.ma.us", "1.2.3.4")]
    assert candidate_differentiates(records, att), (
        "AC1 FAIL: CLEAN parent must always allow promotion"
    )
    print("  PASS test_ac1_clean_parent_always_promotes (AC1)")


def test_ac2_wildcard_match_suppressed() -> None:
    """AC2 negative-action: candidate IP matches wildcard pool → does NOT differentiate.

    Gate code path: candidate_differentiates returns False → scan_engine routes
    the candidate to outcome_suppressed_wildcard_match (diagnostic), NOT to
    result.records as a confirmed finding.
    """
    att = _detected({"A": {"1.2.3.4"}})
    records = [_a_record("mail.ci.lawrence.ma.us", "1.2.3.4")]
    assert not candidate_differentiates(records, att), (
        "AC2 FAIL: candidate matching wildcard pool must NOT differentiate"
    )
    print("  PASS test_ac2_wildcard_match_suppressed (AC2 negative-action)")


def test_ac3_distinct_ip_differentiates() -> None:
    """AC3: candidate A address outside wildcard pool → differentiates → promotes."""
    att = _detected({"A": {"1.2.3.4"}})
    records = [_a_record("mail.ci.lawrence.ma.us", "5.6.7.8")]
    assert candidate_differentiates(records, att), (
        "AC3 FAIL: IP outside wildcard pool should differentiate"
    )
    print("  PASS test_ac3_distinct_ip_differentiates (AC3)")


def test_ac3_new_rr_type_differentiates() -> None:
    """AC3: candidate has a type absent from wildcard signatures → differentiates."""
    att = _detected({"A": {"1.2.3.4"}})
    aaaa_rec = DiscoveredRecord(
        fqdn="mail.ci.lawrence.ma.us",
        record_type=RecordType.AAAA,
        value="::1",
        source_method="generated_candidate",
        classification=FindingClassification.STANDARD_RECORD,
    )
    assert candidate_differentiates([aaaa_rec], att), (
        "AC3 FAIL: new RR type not in wildcard signatures should differentiate"
    )
    print("  PASS test_ac3_new_rr_type_differentiates (AC3)")


def test_ac3_ns_delegation_differentiates() -> None:
    """AC3: candidate NS record (delegation evidence) → differentiates even with matching A.

    Tests the delegation differentiation path: the NS record causes
    candidate_differentiates to return True before reaching the pool check.
    """
    att = _detected({"A": {"1.2.3.4"}})
    records = [
        _a_record("police.ci.lawrence.ma.us", "1.2.3.4"),  # matches wildcard pool
        _ns_record("police.ci.lawrence.ma.us"),             # but delegation differentiates
    ]
    assert candidate_differentiates(records, att), (
        "AC3 FAIL: NS delegation record must differentiate even when A is in pool"
    )
    print("  PASS test_ac3_ns_delegation_differentiates (AC3 delegation)")


def test_ac5_ttl_only_difference_does_not_bypass() -> None:
    """AC5 negative-action: TTL-only difference must NOT bypass suppression.

    The wildcard signature is built from rdata.to_text() which excludes TTL (§4).
    DiscoveredRecord.value stores the rdata text string (no TTL).  A candidate
    with the same rdata value but a different TTL produces identical .value → same
    signature match → does not differentiate → remains suppressed.
    """
    att = _detected({"A": {"1.2.3.4"}})
    # Different TTL values — value field is identical ("1.2.3.4") in both cases.
    record_ttl_300 = _a_record("mail.ci.lawrence.ma.us", "1.2.3.4", ttl=300)
    record_ttl_3600 = _a_record("mail.ci.lawrence.ma.us", "1.2.3.4", ttl=3600)
    assert not candidate_differentiates([record_ttl_300], att), (
        "AC5 FAIL: TTL=300 same-IP record must be suppressed"
    )
    assert not candidate_differentiates([record_ttl_3600], att), (
        "AC5 FAIL: TTL=3600 same-IP record (TTL-only difference) must NOT bypass suppression"
    )
    print("  PASS test_ac5_ttl_only_difference_does_not_bypass (AC5 negative-action)")


def test_ac4_inconclusive_candidate_differentiates_returns_true() -> None:
    """AC4 unit: candidate_differentiates returns True for INCONCLUSIVE attestation.

    candidate_differentiates is not the gate for INCONCLUSIVE — that logic lives
    in scan_engine._test_candidates which checks attestation.status directly and
    emits outcome_withheld_wildcard_inconclusive.  candidate_differentiates must
    return True for non-DETECTED attestations (no false suppression at the unit level).
    """
    att = WildcardAttestation(
        status=WildcardAttestationStatus.INCONCLUSIVE, parent="ci.lawrence.ma.us"
    )
    records = [_a_record("mail.ci.lawrence.ma.us", "1.2.3.4")]
    assert candidate_differentiates(records, att), (
        "AC4 FAIL: candidate_differentiates must return True for INCONCLUSIVE "
        "(promotion gate enforced in scan_engine, not here)"
    )
    print("  PASS test_ac4_inconclusive_unit (AC4)")


def test_rotating_pool_containment() -> None:
    """§6: rotating A/AAAA pool — in-pool address suppressed, out-of-pool promotes."""
    att = _detected({"A": {"1.2.3.4", "5.6.7.8", "9.10.11.12"}})
    in_pool = [_a_record("mail.ci.lawrence.ma.us", "5.6.7.8")]
    out_pool = [_a_record("mail.ci.lawrence.ma.us", "100.200.0.1")]
    assert not candidate_differentiates(in_pool, att), (
        "§6 FAIL: address inside rotating pool must be suppressed"
    )
    assert candidate_differentiates(out_pool, att), (
        "§6 FAIL: address outside rotating pool must differentiate"
    )
    print("  PASS test_rotating_pool_containment (§6)")


# ===========================================================================
# 3 — Per-parent scoping (§1)
# ===========================================================================


def test_per_parent_scoping() -> None:
    """§1: wildcard at parent-A must NOT suppress candidates under parent-B.

    A wildcard detected at ci.lawrence.ma.us does not automatically apply to
    candidates under police.ci.lawrence.ma.us — each parent requires its own probe.
    """
    att_base = _detected({"A": {"1.2.3.4"}})  # wildcard at ci.lawrence.ma.us
    att_police = WildcardAttestation(               # clean at police.ci.lawrence.ma.us
        status=WildcardAttestationStatus.CLEAN,
        parent="police.ci.lawrence.ma.us",
    )
    records = [_a_record("admin.police.ci.lawrence.ma.us", "1.2.3.4")]
    # Under base parent (DETECTED): suppressed
    assert not candidate_differentiates(records, att_base), (
        "§1: candidate should be suppressed under base-level wildcard"
    )
    # Under police parent (CLEAN): not suppressed — per-parent independence
    assert candidate_differentiates(records, att_police), (
        "§1 FAIL: wildcard at parent-A must NOT suppress under parent-B without its own probe"
    )
    print("  PASS test_per_parent_scoping (§1)")


# ===========================================================================
# 4 — EvidenceStatus routing (negative-action: suppressed ≠ confirmed)
# ===========================================================================


def test_suppressed_status_is_diagnostic_not_confirmed() -> None:
    """Negative-action: SUPPRESSED_WILDCARD_MATCH and WITHHELD_WILDCARD_INCONCLUSIVE
    must be diagnostic, NOT confirmed, and must NOT appear in confirmed findings.

    Gate code path: is_confirmed_evidence_status returns False for both statuses,
    so build_confirmed_findings_rows excludes them; T31 routing sends them to the
    Diagnostics sheet via build_diagnostics_rows.
    """
    assert not is_confirmed_evidence_status(EvidenceStatus.SUPPRESSED_WILDCARD_MATCH), (
        "SUPPRESSED_WILDCARD_MATCH must be diagnostic, not confirmed"
    )
    assert not is_confirmed_evidence_status(EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE), (
        "WITHHELD_WILDCARD_INCONCLUSIVE must be diagnostic, not confirmed"
    )
    print("  PASS test_suppressed_status_is_diagnostic_not_confirmed (negative-action)")


def test_suppressed_candidate_not_in_confirmed_findings() -> None:
    """Negative-action: suppressed candidate does NOT appear in confirmed findings rows.

    Gate code path (claim-to-code): scan_engine._test_candidates checks
    candidate_differentiates; on False, it calls outcome_suppressed_wildcard_match
    and clears other_findings (no record added to result.records).
    build_confirmed_findings_rows iterates result.records and filters by
    is_confirmed_evidence_status — the suppressed candidate never enters that list.
    """
    base = "ci.lawrence.ma.us"
    suppressed = outcome_suppressed_wildcard_match(
        f"mail.{base}", parent=base, source_method="generated_candidate"
    )
    run_result = _make_run_result(base, records=[], evidence_outcomes=[suppressed])

    confirmed_rows = build_confirmed_findings_rows(run_result)
    confirmed_names = [row.get("tested_name") for row in confirmed_rows]
    assert f"mail.{base}" not in confirmed_names, (
        "Suppressed candidate must NOT appear in confirmed findings rows"
    )
    print("  PASS test_suppressed_candidate_not_in_confirmed_findings (negative-action)")


def test_suppressed_candidate_appears_in_diagnostics() -> None:
    """Suppressed candidate routes to the Diagnostics sheet with correct evidence_status."""
    base = "ci.lawrence.ma.us"
    suppressed = outcome_suppressed_wildcard_match(
        f"mail.{base}", parent=base, source_method="generated_candidate"
    )
    run_result = _make_run_result(base, records=[], evidence_outcomes=[suppressed])

    diag_rows = build_diagnostics_rows(run_result)
    suppressed_names = [
        row.get("tested_name")
        for row in diag_rows
        if row.get("evidence_status") == EvidenceStatus.SUPPRESSED_WILDCARD_MATCH.value
    ]
    assert f"mail.{base}" in suppressed_names, (
        "Suppressed candidate must appear in diagnostics rows with SUPPRESSED_WILDCARD_MATCH"
    )
    print("  PASS test_suppressed_candidate_appears_in_diagnostics")


def test_withheld_candidate_not_in_confirmed_findings() -> None:
    """AC4 negative-action: inconclusive-withheld candidate does NOT promote."""
    base = "ci.lawrence.ma.us"
    withheld = outcome_withheld_wildcard_inconclusive(
        f"mail.{base}", parent=base, source_method="generated_candidate"
    )
    run_result = _make_run_result(base, records=[], evidence_outcomes=[withheld])

    confirmed_rows = build_confirmed_findings_rows(run_result)
    confirmed_names = [row.get("tested_name") for row in confirmed_rows]
    assert f"mail.{base}" not in confirmed_names, (
        "AC4 FAIL: withheld-inconclusive candidate must NOT appear in confirmed findings"
    )
    print("  PASS test_withheld_candidate_not_in_confirmed_findings (AC4 negative-action)")


def test_attestation_status_stamped_on_outcome() -> None:
    """Each outcome carries the per-parent attestation status (attestation_status field)."""
    suppressed = outcome_suppressed_wildcard_match(
        "mail.ci.lawrence.ma.us",
        parent="ci.lawrence.ma.us",
    )
    assert suppressed.attestation_status == WildcardAttestationStatus.DETECTED.value, (
        f"Expected attestation_status={WildcardAttestationStatus.DETECTED.value!r}; "
        f"got {suppressed.attestation_status!r}"
    )
    withheld = outcome_withheld_wildcard_inconclusive(
        "mail.ci.lawrence.ma.us",
        parent="ci.lawrence.ma.us",
    )
    assert withheld.attestation_status == WildcardAttestationStatus.INCONCLUSIVE.value, (
        f"Expected attestation_status={WildcardAttestationStatus.INCONCLUSIVE.value!r}; "
        f"got {withheld.attestation_status!r}"
    )
    print("  PASS test_attestation_status_stamped_on_outcome")


# ===========================================================================
# Main
# ===========================================================================


def main() -> None:
    print("=== R4a Wildcard Attestation Engine Regression ===")
    test_prior_chain()

    print("\n--- run_wildcard_attestation ---")
    test_attestation_clean()
    test_attestation_detected()
    test_attestation_inconclusive()
    test_ac6_parent_soa_in_authority_not_wildcard()

    print("\n--- candidate_differentiates ---")
    test_ac1_clean_parent_always_promotes()
    test_ac2_wildcard_match_suppressed()
    test_ac3_distinct_ip_differentiates()
    test_ac3_new_rr_type_differentiates()
    test_ac3_ns_delegation_differentiates()
    test_ac5_ttl_only_difference_does_not_bypass()
    test_ac4_inconclusive_candidate_differentiates_returns_true()
    test_rotating_pool_containment()

    print("\n--- per-parent scoping ---")
    test_per_parent_scoping()

    print("\n--- EvidenceStatus routing (negative-action) ---")
    test_suppressed_status_is_diagnostic_not_confirmed()
    test_suppressed_candidate_not_in_confirmed_findings()
    test_suppressed_candidate_appears_in_diagnostics()
    test_withheld_candidate_not_in_confirmed_findings()
    test_attestation_status_stamped_on_outcome()

    print("\n=== R4a: all assertions passed ===")


if __name__ == "__main__":
    main()
