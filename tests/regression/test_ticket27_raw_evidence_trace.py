#!/usr/bin/env python3
"""Ticket 27 verification: raw evidence trace for findings and diagnostics.

All DNS interactions are synthetic (mocked); no live network calls occur.
"""

from __future__ import annotations

import json
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
from scanner.evidence_status import is_confirmed_evidence_status, resolve_evidence_status
from scanner.evidence_trace import trace_to_dict, traces_to_dicts
from scanner.export_service import CSV_COLUMNS, build_csv_rows, build_json_document
from scanner.models import (
    DiscoveredRecord,
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
from scanner.paths import get_wordlists_dir
from scanner.scan_engine import (
    _make_resolver,
    _query_records,
    _test_candidates,
)

BASE = "lawrence.ma.us"
COM_SOA_RDATA = "a.gtld-servers.net. nstld.verisign-grs.com. 2026062601 1800 900 604800 86400"
REAL_SOA_RDATA = "ns1.lawrence.ma.us. hostmaster.lawrence.ma.us. 2026062601 3600 600 604800 3600"
FP_CANDIDATES = [
    "webmail.ci.lawrence.ma.us",
    "smtp.ci.lawrence.ma.us",
    "mx.ci.lawrence.ma.us",
]

QueryKey = tuple[str, str]

TRACE_KEYS = {
    "qname",
    "normalized_qname",
    "qtype",
    "rcode",
    "section",
    "rr_owner",
    "normalized_rr_owner",
    "rr_type",
    "rr_value",
    "resolver_or_server",
    "authoritative_flag",
    "source_path",
    "response_class",
    "evidence_status",
    "finding_type",
    "promotion_reason",
    "rejection_reason",
}


def _qname(name: str) -> dns.name.Name:
    return dns.name.from_text(name.rstrip(".") + ".")


def _make_response(qname: str, qtype: str, rcode_value: int = dns.rcode.NOERROR) -> dns.message.Message:
    query = dns.message.make_query(_qname(qname), qtype)
    response = dns.message.make_response(query)
    response.set_rcode(rcode_value)
    return response


def _add_answer_a(response: dns.message.Message, owner: str, ip: str) -> None:
    a = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip)
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, a))


def _add_answer_cname(response: dns.message.Message, owner: str, target: str) -> None:
    cname = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, target.rstrip(".") + ".")
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, cname))


def _add_answer_mx(response: dns.message.Message, owner: str, exchange: str) -> None:
    mx = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, f"10 {exchange.rstrip('.')}.")
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, mx))


def _add_answer_txt(response: dns.message.Message, owner: str, text: str) -> None:
    txt = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{text}"')
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, txt))


def _add_answer_soa(response: dns.message.Message, owner: str, rdata_text: str) -> None:
    soa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, rdata_text)
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, soa))


def _add_authority_ns(response: dns.message.Message, owner: str, ns_target: str) -> None:
    ns = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target.rstrip(".") + ".")
    response.authority.append(dns.rrset.from_rdata(_qname(owner), 300, ns))


def _add_authority_soa(response: dns.message.Message, owner: str, rdata_text: str) -> None:
    soa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, rdata_text)
    response.authority.append(dns.rrset.from_rdata(_qname(owner), 900, soa))


def _add_answer_ns(response: dns.message.Message, owner: str, ns_target: str) -> None:
    ns = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target.rstrip(".") + ".")
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, ns))


def _servfail(qname: str, qtype: str) -> dns.message.Message:
    response = _make_response(qname, qtype)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response


def _nxdomain(qname: str, qtype: str) -> dns.message.Message:
    response = _make_response(qname, qtype)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return response


def _nodata(qname: str, qtype: str) -> dns.message.Message:
    return _make_response(qname, qtype)


def _timeout(_qname: str, _qtype: str) -> tuple[None, str]:
    return None, "timed out"


def _assert_trace_dict(trace: dict) -> None:
    assert set(trace.keys()) >= TRACE_KEYS
    json.dumps(trace)


def _assert_record_traces(record: DiscoveredRecord, *, expect_promotion: bool = True) -> None:
    assert record.evidence_trace, f"Expected trace on {record.fqdn} {record.record_type}"
    for item in traces_to_dicts(record.evidence_trace):
        _assert_trace_dict(item)
        if expect_promotion:
            assert item["promotion_reason"]
            assert item["rejection_reason"] is None


def _mock_scan_result(domain_result: DomainScanResult) -> ScanRunResult:
    return ScanRunResult(
        input=ScanInput(
            domain_file_path=Path("fake.csv"),
            options=ScanOptions(scan_profile=ScanProfile.NORMAL),
            output_dir=Path("."),
            wordlists_dir=get_wordlists_dir(),
        ),
        domain_inputs=[],
        domain_results=[domain_result],
        scan_timestamp=datetime(2026, 6, 26, 15, 0, 0),
        finished_at=datetime(2026, 6, 26, 15, 5, 0),
        scan_status=ScanStatus.COMPLETED,
    )


def _run_gated(
    *,
    base: str,
    candidates: list[str],
    responses: dict[QueryKey, dns.message.Message] | None = None,
    send_effect=None,
    parent_passed: set[str] | None = None,
) -> DomainScanResult:
    result = DomainScanResult(domain=base)

    def fake_send(fqdn: str, record_type: RecordType, resolver):
        if send_effect is not None:
            return send_effect(fqdn, record_type, resolver)
        key = (fqdn.lower().rstrip("."), record_type.value)
        resp = (responses or {}).get(key)
        if resp is None:
            return _servfail(fqdn + ".", record_type.value), None
        return resp, None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send), patch(
        "scanner.scan_engine._get_parent_ns_hosts", return_value=["ns.parent.example"]
    ), patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
        _test_candidates(
            candidates=candidates,
            domain=base,
            resolver=_make_resolver(),
            result=result,
            wildcard_suspected=False,
            progress=None,
            messages=[],
            cancel_check=None,
            progress_update=None,
            domain_index=1,
            domain_total=1,
            domains_completed=0,
            started_at=datetime(2026, 6, 26, 15, 0, 0),
            phase=ScanPhase.TESTING_FIFTH_LEVEL,
            candidates_offset=0,
            candidates_total=len(candidates),
            validate_fifth_level_parents=True,
            parent_passed=set() if parent_passed is None else set(parent_passed),
            parent_decisions={},
        )
    return result


# ---------------------------------------------------------------------------
# Confirmed finding traces
# ---------------------------------------------------------------------------


def test_ordinary_a_finding_has_trace() -> None:
    candidate = "portal.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.A:
            r = _make_response(fqdn, "A")
            _add_answer_a(r, fqdn, "192.0.2.10")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, _ = _query_records(
            candidate,
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert findings
    _assert_record_traces(findings[0])
    trace = trace_to_dict(findings[0].evidence_trace[0])
    assert trace["qtype"] == "A"
    assert trace["rr_type"] == "A"
    assert trace["section"] == "answer"
    assert trace["source_path"] == "recursive"
    print("trace: ordinary A finding: OK")


def test_ordinary_cname_mx_txt_have_trace() -> None:
    cases = [
        ("mail.ci.lawrence.ma.us", RecordType.CNAME, _add_answer_cname, ("target.example.com",)),
        ("mx.ci.lawrence.ma.us", RecordType.MX, _add_answer_mx, ("mail.example.com",)),
        ("txt.ci.lawrence.ma.us", RecordType.TXT, _add_answer_txt, ("v=spf1 include:example.com",)),
    ]
    for fqdn, rtype, add_fn, args in cases:

        def fake_send(f, rt, resolver, *, _fqdn=fqdn, _rtype=rtype, _add=add_fn, _args=args):
            if rt == _rtype:
                r = _make_response(f, rt.value)
                _add(r, f, *_args)
                return r, None
            return _make_response(f, rt.value, dns.rcode.NXDOMAIN), None

        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            findings, _ = _query_records(
                fqdn,
                (rtype,),
                _make_resolver(),
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=BASE,
            )
        assert findings
        _assert_record_traces(findings[0])
        assert findings[0].evidence_trace[0].rr_type == rtype.value
    print("trace: CNAME/MX/TXT findings: OK")


def test_delegated_child_zone_finding_has_trace() -> None:
    candidate = "library.ci.lawrence.ma.us"
    child_ns = "ns1.child.example."

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS and fqdn == candidate:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, child_ns)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
        result = verify_delegated_child_zone(
            candidate,
            base_domain=BASE,
            send_query=fake_send,
            resolve_ns_ips=lambda _h: ["127.0.0.1"],
            make_resolver=_make_resolver,
            parent_ns_hosts=["ns.lawrence.ma.us"],
        )
    assert result.verified
    delegated = [
        item for item in result.records
        if item.classification == FindingClassification.DELEGATED_CHILD_ZONE
    ]
    assert delegated
    _assert_record_traces(delegated[0])
    trace = trace_to_dict(delegated[0].evidence_trace[0])
    assert trace["rr_type"] == "NS"
    assert trace["source_path"] in {"parent_authoritative", "candidate_authoritative", "delegation_verifier"}
    assert trace["promotion_reason"]
    print("trace: verified delegated child-zone NS: OK")


def test_soa_zone_apex_finding_has_trace() -> None:
    candidate = "library.ci.lawrence.ma.us"
    child_ns = "ns1.child.example."

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS and fqdn == candidate:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        if record_type == RecordType.SOA and fqdn == candidate:
            r = _make_response(fqdn, "SOA")
            _add_answer_soa(r, fqdn, REAL_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
        result = verify_delegated_child_zone(
            candidate,
            base_domain=BASE,
            send_query=fake_send,
            resolve_ns_ips=lambda _h: ["127.0.0.1"],
            make_resolver=_make_resolver,
            parent_ns_hosts=["ns.lawrence.ma.us"],
            delegation_child_ns_hosts=[child_ns],
        )
    soa_records = [item for item in result.records if item.record_type == RecordType.SOA]
    assert soa_records
    _assert_record_traces(soa_records[0])
    trace = trace_to_dict(soa_records[0].evidence_trace[0])
    assert trace["rr_type"] == "SOA"
    print("trace: candidate-apex SOA zone evidence: OK")


# ---------------------------------------------------------------------------
# Diagnostic traces
# ---------------------------------------------------------------------------


def test_parent_nxdomain_diagnostic_has_trace() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    responses = {
        (parent, rt.value): _nxdomain(parent + ".", rt.value)
        for rt in RecordType
        if rt.value in {"SOA", "A", "AAAA", "MX", "TXT", "CNAME", "NS"}
    }
    result = _run_gated(base=BASE, candidates=[child], responses=responses)
    outcomes = [o for o in result.evidence_outcomes if o.fqdn == child]
    assert outcomes
    assert outcomes[0].evidence_trace
    trace = trace_to_dict(outcomes[0].evidence_trace[0])
    _assert_trace_dict(trace)
    assert trace["response_class"] == "negative_nxdomain"
    assert trace["rejection_reason"]
    assert trace["source_path"] == "parent_gating"
    print("trace: parent NXDOMAIN diagnostic: OK")


def test_parent_nodata_diagnostic_has_trace() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    responses = {
        (parent, rt.value): _nodata(parent + ".", rt.value)
        for rt in RecordType
        if rt.value in {"SOA", "A", "AAAA", "MX", "TXT", "CNAME", "NS"}
    }
    result = _run_gated(base=BASE, candidates=[child], responses=responses)
    outcomes = [o for o in result.evidence_outcomes if o.fqdn == child]
    assert outcomes
    assert outcomes[0].evidence_trace
    trace = trace_to_dict(outcomes[0].evidence_trace[0])
    assert trace["response_class"] == "nodata_empty_answer"
    print("trace: parent NODATA diagnostic: OK")


def test_parent_servfail_timeout_malformed_diagnostic_has_trace() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"

    def servfail_effect(fqdn, record_type, resolver):
        if fqdn.lower().rstrip(".") == parent:
            return _servfail(fqdn + ".", record_type.value), None
        return _servfail(fqdn + ".", record_type.value), None

    result = _run_gated(base=BASE, candidates=[child], send_effect=servfail_effect)
    outcomes = [o for o in result.evidence_outcomes if o.fqdn == child]
    assert outcomes and outcomes[0].evidence_trace
    assert trace_to_dict(outcomes[0].evidence_trace[0])["response_class"] == "servfail"

    def timeout_effect(fqdn, record_type, resolver):
        if fqdn.lower().rstrip(".") == parent:
            return _timeout(fqdn, record_type.value)
        return _servfail(fqdn + ".", record_type.value), None

    result = _run_gated(base=BASE, candidates=[child], send_effect=timeout_effect)
    outcomes = [o for o in result.evidence_outcomes if o.fqdn == child]
    assert outcomes and outcomes[0].evidence_trace
    assert trace_to_dict(outcomes[0].evidence_trace[0])["response_class"] == "timeout"

    def malformed_effect(fqdn, record_type, resolver):
        if fqdn.lower().rstrip(".") == parent:
            return None, "malformed response"
        return _servfail(fqdn + ".", record_type.value), None

    result = _run_gated(base=BASE, candidates=[child], send_effect=malformed_effect)
    outcomes = [o for o in result.evidence_outcomes if o.fqdn == child]
    assert outcomes and outcomes[0].evidence_trace
    assert trace_to_dict(outcomes[0].evidence_trace[0])["response_class"] == "malformed_or_unusable"
    print("trace: SERVFAIL/TIMEOUT/malformed diagnostics: OK")


def test_unrelated_authority_diagnostic_has_trace() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        fqdn_norm = fqdn.lower().rstrip(".")
        if fqdn_norm == parent and record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        return _servfail(fqdn + ".", record_type.value), None

    result = _run_gated(base=BASE, candidates=[child], send_effect=fake_send)
    traces = []
    for outcome in result.evidence_outcomes:
        traces.extend(outcome.evidence_trace)
    assert traces
    unrelated = [
        trace_to_dict(item)
        for item in traces
        if item.response_class == "unrelated_authority"
    ]
    assert unrelated
    trace = unrelated[0]
    _assert_trace_dict(trace)
    assert trace["rejection_reason"]
    assert trace["rr_owner"] != parent
    print("trace: unrelated authority diagnostic: OK")


# ---------------------------------------------------------------------------
# False positives and negative-action
# ---------------------------------------------------------------------------


def test_false_positive_candidates_no_confirmed_traces() -> None:
    parent = "ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        fqdn_norm = fqdn.lower().rstrip(".")
        if fqdn_norm == parent and record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        return _servfail(fqdn + ".", record_type.value), None

    for candidate in FP_CANDIDATES:
        with patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
            delegation = verify_delegated_child_zone(
                candidate,
                base_domain=BASE,
                send_query=fake_send,
                resolve_ns_ips=lambda _h: ["127.0.0.1"],
                make_resolver=_make_resolver,
                parent_ns_hosts=["ns.lawrence.ma.us"],
            )
        assert not delegation.verified
        confirmed_delegated = [
            item for item in delegation.records
            if item.classification == FindingClassification.DELEGATED_CHILD_ZONE
        ]
        assert not confirmed_delegated

        result = _run_gated(base=BASE, candidates=[candidate], send_effect=fake_send)
        confirmed = [
            item for item in result.records
            if is_confirmed_evidence_status(resolve_evidence_status(item, BASE))
        ]
        assert not confirmed
    print("negative: false-positive candidates have no confirmed finding traces: OK")


def test_negative_ignored_does_not_promote_finding() -> None:
    candidate = "smtp.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
        result = verify_delegated_child_zone(
            candidate,
            base_domain=BASE,
            send_query=fake_send,
            resolve_ns_ips=lambda _h: ["127.0.0.1"],
            make_resolver=_make_resolver,
            parent_ns_hosts=["ns.lawrence.ma.us"],
        )
    assert not result.verified
    assert not any(
        item.classification == FindingClassification.DELEGATED_CHILD_ZONE
        for item in result.records
    )
    rejection_traces = [
        trace_to_dict(item)
        for outcome in result.evidence_outcomes
        for item in outcome.evidence_trace
        if item.rejection_reason
    ]
    assert rejection_traces
    print("negative: ignored authority keeps rejection trace only: OK")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_json_export_includes_evidence_trace() -> None:
    domain_result = DomainScanResult(
        domain=BASE,
        records=[
            DiscoveredRecord(
                fqdn="portal.ci.lawrence.ma.us",
                record_type=RecordType.A,
                value="192.0.2.1",
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                evidence_trace=[],
            ),
        ],
        evidence_outcomes=[],
    )

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.A:
            r = _make_response(fqdn, "A")
            _add_answer_a(r, fqdn, "192.0.2.1")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, _ = _query_records(
            "portal.ci.lawrence.ma.us",
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    domain_result.records = findings

    parent = "ci.lawrence.ma.us"
    child = "skip.ci.lawrence.ma.us"
    gated = _run_gated(
        base=BASE,
        candidates=[child],
        responses={(parent, rt.value): _nxdomain(parent + ".", rt.value) for rt in RecordType if rt.value in {"SOA", "A", "NS"}},
    )
    domain_result.evidence_outcomes = [o for o in gated.evidence_outcomes if o.fqdn == child]

    document = build_json_document(_mock_scan_result(domain_result))
    domain = document["domains"][0]
    finding = next(item for item in domain["findings"] if item["tested_name"] == "portal.ci.lawrence.ma.us")
    assert finding["evidence_trace"]
    _assert_trace_dict(finding["evidence_trace"][0])

    diagnostic = domain["evidence_diagnostics"][0]
    assert diagnostic["evidence_trace"]
    _assert_trace_dict(diagnostic["evidence_trace"][0])
    print("export: JSON includes evidence_trace for findings and diagnostics: OK")


def test_csv_diagnostics_not_findings() -> None:
    parent = "ci.lawrence.ma.us"
    child = "portal.ci.lawrence.ma.us"
    result = _run_gated(base=BASE, candidates=[child], responses={})
    rows = build_csv_rows(_mock_scan_result(result))
    diagnostic = [r for r in rows if r["tested_name"] == child]
    assert diagnostic
    assert diagnostic[0]["name_type"] == "diagnostic"
    assert diagnostic[0]["finding_type"] == ""
    assert diagnostic[0]["discovered_name"] == ""
    assert "evidence_trace" not in CSV_COLUMNS
    print("export: CSV remains readable without full trace columns: OK")


# ---------------------------------------------------------------------------
# Regression chain
# ---------------------------------------------------------------------------


def _run_ticket26_regression() -> None:
    script = REGRESSION_DIR / "test_ticket26_parent_gating_semantics.py"
    print(f"\n--- Chaining Ticket 26 regression: {script.name} ---")
    run_durable_regression(script)


def main() -> None:
    print("Ticket 27 raw evidence trace verification")
    print(f"Repo: {REPO_ROOT}")
    test_ordinary_a_finding_has_trace()
    test_ordinary_cname_mx_txt_have_trace()
    test_delegated_child_zone_finding_has_trace()
    test_soa_zone_apex_finding_has_trace()
    test_parent_nxdomain_diagnostic_has_trace()
    test_parent_nodata_diagnostic_has_trace()
    test_parent_servfail_timeout_malformed_diagnostic_has_trace()
    test_unrelated_authority_diagnostic_has_trace()
    test_false_positive_candidates_no_confirmed_traces()
    test_negative_ignored_does_not_promote_finding()
    test_json_export_includes_evidence_trace()
    test_csv_diagnostics_not_findings()
    _run_ticket26_regression()
    print("\nTicket 27 raw evidence trace verification: ALL OK")


if __name__ == "__main__":
    main()
