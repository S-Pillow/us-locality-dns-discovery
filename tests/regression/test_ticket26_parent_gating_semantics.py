#!/usr/bin/env python3
"""Ticket 26 verification: parent-gating semantics and diagnostics.

All DNS interactions are synthetic (mocked); no live network calls occur.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rrset

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.regression._chain import run_durable_regression
from tests.regression._paths import REGRESSION_DIR, REPO_ROOT

from scanner.delegation_verifier import verify_delegated_child_zone
from scanner.export_service import build_csv_rows
from scanner.models import (
    DomainInputRecord,
    DomainScanResult,
    EvidenceStatus,
    FindingClassification,
    RecordType,
    ScanInput,
    ScanOptions,
    ScanPhase,
    ScanProfile,
    ScanRunResult,
    ScanStatus,
)
from scanner.parent_gating import decide_parent_gating_from_probe_classes
from scanner.dns_classifier import DNSResponseClass
from scanner.paths import get_wordlists_dir
from scanner.scan_engine import (
    _make_resolver,
    _test_candidates,
)

BASE = "lawrence.ma.us"
FP_CANDIDATES = [
    "webmail.ci.lawrence.ma.us",
    "smtp.ci.lawrence.ma.us",
    "mx.ci.lawrence.ma.us",
]

QueryKey = tuple[str, str]


def _servfail(qname: str, qtype: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), qtype)
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response


def _nxdomain(qname: str, qtype: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), qtype)
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return response


def _timeout(_qname: str, _qtype: str) -> tuple[None, str]:
    return None, "timed out"


def _nodata(qname: str, qtype: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), qtype)
    return dns.message.make_response(query)


def _owner_a_answer(qname: str, address: str = "203.0.113.10") -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), "A")
    response = dns.message.make_response(query)
    a = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, address)
    response.answer.append(dns.rrset.from_rdata(dns.name.from_text(qname), 300, a))
    return response


def _owner_ns_answer(qname: str, ns_target: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), "NS")
    response = dns.message.make_response(query)
    ns = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, f"{ns_target}.")
    response.answer.append(dns.rrset.from_rdata(dns.name.from_text(qname), 300, ns))
    return response


def _owner_soa_answer(qname: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), "SOA")
    response = dns.message.make_response(query)
    soa = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        "ns1.example.net. hostmaster.example.net. 1 3600 600 604800 3600",
    )
    response.answer.append(dns.rrset.from_rdata(dns.name.from_text(qname), 300, soa))
    return response


def _unrelated_com_authority(qname: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), "NS")
    response = dns.message.make_response(query)
    soa = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400",
    )
    response.authority.append(dns.rrset.from_rdata(dns.name.from_text("com."), 60, soa))
    return response


def _mock_scan_result(domain_result: DomainScanResult) -> ScanRunResult:
    return ScanRunResult(
        input=ScanInput(
            domain_file_path=Path("fake.csv"),
            options=ScanOptions(scan_profile=ScanProfile.NORMAL),
            output_dir=Path("."),
            wordlists_dir=get_wordlists_dir(),
        ),
        domain_inputs=[domain_result.input_record] if domain_result.input_record else [],
        domain_results=[domain_result],
        scan_timestamp=datetime(2026, 6, 26, 14, 0, 0),
        finished_at=datetime(2026, 6, 26, 14, 5, 0),
        scan_status=ScanStatus.COMPLETED,
    )


def _run_gated(
    *,
    base: str,
    candidates: list[str],
    responses: dict[QueryKey, dns.message.Message] | None = None,
    send_effect=None,
    parent_passed: set[str] | None = None,
    parent_decisions: dict | None = None,
) -> tuple[DomainScanResult, dict[str, int]]:
    result = DomainScanResult(domain=base)
    messages: list[str] = []
    query_counts: dict[str, int] = {}

    def fake_send(fqdn: str, record_type: RecordType, resolver):
        key = (fqdn.lower().rstrip("."), record_type.value)
        query_counts[key[0]] = query_counts.get(key[0], 0) + 1
        if send_effect is not None:
            return send_effect(fqdn, record_type, resolver)
        resp = (responses or {}).get(key)
        if resp is None:
            return _servfail(fqdn + ".", record_type.value), None
        return resp, None

    async def fake_send_async(fqdn: str, record_type: RecordType, resolver):
        return fake_send(fqdn, record_type, resolver)

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send), patch(
        "scanner.scan_engine._async_send_dns_query", side_effect=fake_send_async
    ), patch(
        "scanner.scan_engine._get_parent_ns_hosts", return_value=["ns.parent.example"]
    ), patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
        _test_candidates(
            candidates=candidates,
            domain=base,
            resolver=_make_resolver(),
            result=result,
            wildcard_suspected=False,
            progress=None,
            messages=messages,
            cancel_check=None,
            progress_update=None,
            domain_index=1,
            domain_total=1,
            domains_completed=0,
            started_at=datetime(2026, 6, 26, 14, 0, 0),
            phase=ScanPhase.TESTING_FIFTH_LEVEL,
            candidates_offset=0,
            candidates_total=len(candidates),
            validate_fifth_level_parents=True,
            parent_passed=set() if parent_passed is None else set(parent_passed),
            parent_decisions=dict(parent_decisions or {}),
        )
    return result, query_counts


def _diagnostic_rows(result: DomainScanResult) -> list[dict[str, str]]:
    return build_csv_rows(_mock_scan_result(result))


def _outcome_statuses(result: DomainScanResult) -> list[EvidenceStatus]:
    return [item.evidence_status for item in result.evidence_outcomes]


def _assert_diagnostic_row(row: dict[str, str], *, status: str) -> None:
    assert row["name_type"] == "diagnostic"
    assert row["discovered_name"] == ""
    assert row["finding_type"] == ""
    assert row["evidence_status"] == status


# ---------------------------------------------------------------------------
# Decision helper unit checks
# ---------------------------------------------------------------------------


def test_decision_nxdomain() -> None:
    decision = decide_parent_gating_from_probe_classes(
        "ci.lawrence.ma.us",
        {DNSResponseClass.NEGATIVE_NXDOMAIN},
    )
    assert not decision.allow_descendants
    assert decision.evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING
    assert "NXDOMAIN" in decision.diagnostic_message
    assert "does not exist" not in decision.diagnostic_message.lower()
    print("decision: NXDOMAIN -> SKIPPED_BY_PARENT_GATING: OK")


def test_decision_nodata_heuristic() -> None:
    decision = decide_parent_gating_from_probe_classes(
        "ci.lawrence.ma.us",
        {DNSResponseClass.NODATA_EMPTY_ANSWER},
    )
    assert not decision.allow_descendants
    assert decision.evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING
    assert "NODATA" in decision.diagnostic_message
    assert "does not exist" not in decision.diagnostic_message.lower()
    print("decision: NODATA -> heuristic SKIPPED: OK")


def test_decision_servfail_inconclusive() -> None:
    decision = decide_parent_gating_from_probe_classes(
        "ci.lawrence.ma.us",
        {DNSResponseClass.SERVFAIL},
    )
    assert decision.evidence_status == EvidenceStatus.INCONCLUSIVE_DNS_FAILURE
    assert "inconclusive" in decision.diagnostic_message.lower()
    print("decision: SERVFAIL -> INCONCLUSIVE: OK")


def test_decision_unrelated_ignored() -> None:
    decision = decide_parent_gating_from_probe_classes(
        "ci.lawrence.ma.us",
        {DNSResponseClass.UNRELATED_AUTHORITY},
    )
    assert decision.evidence_status == EvidenceStatus.IGNORED_UNRELATED_AUTHORITY
    print("decision: unrelated authority -> IGNORED: OK")


# ---------------------------------------------------------------------------
# Integration: parent response classes
# ---------------------------------------------------------------------------


def test_parent_nxdomain_skips_descendants() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    responses = {
        (parent, rt.value): _nxdomain(parent + ".", rt.value)
        for rt in RecordType
        if rt.value in {"SOA", "A", "AAAA", "MX", "TXT", "CNAME", "NS"}
    }
    result, counts = _run_gated(base=BASE, candidates=[child], responses=responses)
    assert counts.get(child, 0) == 0
    assert EvidenceStatus.SKIPPED_BY_PARENT_GATING in _outcome_statuses(result)
    assert any("NXDOMAIN" in item.detail for item in result.evidence_outcomes)
    print("integration: parent NXDOMAIN skips descendants: OK")


def test_parent_nodata_heuristic_skip() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    responses = {
        (parent, rt.value): _nodata(parent + ".", rt.value)
        for rt in RecordType
        if rt.value in {"SOA", "A", "AAAA", "MX", "TXT", "CNAME", "NS"}
    }
    result, counts = _run_gated(base=BASE, candidates=[child], responses=responses)
    assert counts.get(child, 0) == 0
    assert EvidenceStatus.SKIPPED_BY_PARENT_GATING in _outcome_statuses(result)
    assert any("NODATA" in item.detail for item in result.evidence_outcomes)
    print("integration: parent NODATA heuristic skip: OK")


def test_parent_servfail_inconclusive() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    result, counts = _run_gated(base=BASE, candidates=[child], responses={})
    assert counts.get(child, 0) == 0
    assert EvidenceStatus.INCONCLUSIVE_DNS_FAILURE in _outcome_statuses(result)
    rows = [r for r in _diagnostic_rows(result) if r["tested_name"] == child]
    assert rows
    _assert_diagnostic_row(rows[0], status="INCONCLUSIVE_DNS_FAILURE")
    print("integration: parent SERVFAIL inconclusive: OK")


def test_parent_timeout_inconclusive() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"

    def effect(fqdn, record_type, resolver):
        if fqdn.lower().rstrip(".") == parent:
            return _timeout(fqdn, record_type.value)
        return _servfail(fqdn + ".", record_type.value), None

    result, counts = _run_gated(base=BASE, candidates=[child], send_effect=effect)
    assert counts.get(child, 0) == 0
    assert EvidenceStatus.INCONCLUSIVE_DNS_FAILURE in _outcome_statuses(result)
    print("integration: parent TIMEOUT inconclusive: OK")


def test_parent_malformed_inconclusive() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"

    def effect(fqdn, record_type, resolver):
        if fqdn.lower().rstrip(".") == parent:
            return None, "malformed response"
        return _servfail(fqdn + ".", record_type.value), None

    result, counts = _run_gated(base=BASE, candidates=[child], send_effect=effect)
    assert counts.get(child, 0) == 0
    assert EvidenceStatus.INCONCLUSIVE_DNS_FAILURE in _outcome_statuses(result)
    print("integration: parent malformed inconclusive: OK")


def test_parent_unrelated_authority_ignored() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    responses = {(parent, "NS"): _unrelated_com_authority(parent + ".")}
    result, counts = _run_gated(base=BASE, candidates=[child], responses=responses)
    assert counts.get(child, 0) == 0
    statuses = _outcome_statuses(result)
    assert (
        EvidenceStatus.IGNORED_UNRELATED_AUTHORITY in statuses
        or EvidenceStatus.INCONCLUSIVE_DNS_FAILURE in statuses
    )
    assert not any(
        record.classification == FindingClassification.DELEGATED_CHILD_ZONE
        for record in result.records
    )
    print("integration: unrelated authority does not validate parent: OK")


def test_known_parent_tests_descendant() -> None:
    parent = "mc3.cc.pa.us"
    child = "admin.mc3.cc.pa.us"
    responses = {(child, "A"): _owner_a_answer(child + ".")}
    result, counts = _run_gated(
        base="cc.pa.us",
        candidates=[child],
        responses=responses,
        parent_passed={parent},
    )
    assert counts.get(child, 0) > 0
    assert counts.get(parent, 0) == 0
    print("integration: known parent allows descendant testing: OK")


def test_validated_parent_tests_descendant() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    responses = {
        (parent, "A"): _owner_a_answer(parent + "."),
        (parent, "NS"): _owner_ns_answer(parent + ".", "ns1.example"),
        (parent, "SOA"): _owner_soa_answer(parent + "."),
    }
    result, counts = _run_gated(base=BASE, candidates=[child], responses=responses)
    assert counts.get(parent, 0) > 0
    assert counts.get(child, 0) > 0
    print("integration: validated parent allows descendant testing: OK")


def test_false_positive_descendants_not_confirmed() -> None:
    parent = "ci.lawrence.ma.us"
    com_soa = (
        "a.gtld-servers.net. nstld.verisign-grs.com. 2026062601 1800 900 604800 86400"
    )

    def fake_send(fqdn, record_type, resolver):
        fqdn = fqdn.lower().rstrip(".")
        if fqdn == parent and record_type == RecordType.NS:
            query = dns.message.make_query(dns.name.from_text(fqdn + "."), "NS")
            response = dns.message.make_response(query)
            soa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, com_soa)
            response.authority.append(dns.rrset.from_rdata(dns.name.from_text("com."), 900, soa))
            return response, None
        return _servfail(fqdn + ".", record_type.value), None

    for candidate in FP_CANDIDATES:
        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            with patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
                with patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns.lawrence.ma.us"]):
                    delegation = verify_delegated_child_zone(
                        candidate,
                        base_domain=BASE,
                        send_query=fake_send,
                        resolve_ns_ips=lambda _h: ["127.0.0.1"],
                        make_resolver=_make_resolver,
                        parent_ns_hosts=["ns.lawrence.ma.us"],
                    )
        assert not delegation.verified
        result, counts = _run_gated(base=BASE, candidates=[candidate], send_effect=fake_send)
        assert counts.get(candidate, 0) == 0
        assert not any(
            record.classification == FindingClassification.DELEGATED_CHILD_ZONE
            for record in result.records
        )
    print("integration: false-positive descendants remain unconfirmed: OK")


def test_export_skipped_rows_are_diagnostic() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    result, _ = _run_gated(base=BASE, candidates=[child], responses={})
    rows = [r for r in _diagnostic_rows(result) if r["tested_name"] == child]
    assert rows
    _assert_diagnostic_row(rows[0], status="INCONCLUSIVE_DNS_FAILURE")
    print("export: skipped descendant rows are diagnostic: OK")


def _run_ticket25_regression() -> None:
    script = REGRESSION_DIR / "test_ticket25_evidence_status_model.py"
    print(f"\n--- Chaining Ticket 25 regression: {script.name} ---")
    run_durable_regression(script)


def main() -> None:
    print("Ticket 26 parent gating semantics verification")
    print(f"Repo: {REPO_ROOT}")
    test_decision_nxdomain()
    test_decision_nodata_heuristic()
    test_decision_servfail_inconclusive()
    test_decision_unrelated_ignored()
    test_parent_nxdomain_skips_descendants()
    test_parent_nodata_heuristic_skip()
    test_parent_servfail_inconclusive()
    test_parent_timeout_inconclusive()
    test_parent_malformed_inconclusive()
    test_parent_unrelated_authority_ignored()
    test_known_parent_tests_descendant()
    test_validated_parent_tests_descendant()
    test_false_positive_descendants_not_confirmed()
    test_export_skipped_rows_are_diagnostic()
    _run_ticket25_regression()
    print("\nTicket 26 parent gating semantics verification: ALL OK")


if __name__ == "__main__":
    main()
