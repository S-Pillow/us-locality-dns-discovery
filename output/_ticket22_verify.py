#!/usr/bin/env python3
"""Ticket 22 verification: parent-first gating for 5th-level candidate testing."""

from __future__ import annotations

import subprocess
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.export_service import build_csv_rows, build_summary_rows
from scanner.models import (
    DomainInputRecord,
    DomainScanResult,
    FindingClassification,
    RecordType,
    ScanInput,
    ScanOptions,
    ScanPhase,
    ScanProfile,
    ScanRunResult,
    ScanStatus,
    WordlistPlan,
)
from scanner.paths import get_wordlists_dir
from scanner.scan_engine import (
    _implied_fourth_level_parent,
    _make_resolver,
    _test_candidates,
)

QueryKey = tuple[str, str]


def _servfail(qname: str, qtype: str) -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), qtype)
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.SERVFAIL)
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


def _owner_a_answer(qname: str, address: str = "203.0.113.10") -> dns.message.Message:
    query = dns.message.make_query(dns.name.from_text(qname), "A")
    response = dns.message.make_response(query)
    a = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, address)
    response.answer.append(dns.rrset.from_rdata(dns.name.from_text(qname), 300, a))
    return response


def _unrelated_com_authority(qname: str) -> dns.message.Message:
    """Response with only unrelated com. authority SOA — should not create findings."""
    query = dns.message.make_query(dns.name.from_text(qname), "NS")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.SERVFAIL)
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
        scan_timestamp=datetime(2026, 6, 26, 12, 0, 0),
        finished_at=datetime(2026, 6, 26, 12, 5, 0),
        scan_status=ScanStatus.COMPLETED,
    )


def _run_gated(
    *,
    base: str,
    candidates: list[str],
    responses: dict[QueryKey, dns.message.Message],
    parent_passed: set[str] | None = None,
    parent_failed: set[str] | None = None,
    input_record: DomainInputRecord | None = None,
) -> tuple[DomainScanResult, dict[str, int]]:
    """Run _test_candidates with parent gating; return (result, per-fqdn query counts)."""
    result = DomainScanResult(domain=base, input_record=input_record)
    messages: list[str] = []
    query_counts: dict[str, int] = {}

    def fake_send(
        fqdn: str, record_type: RecordType, resolver
    ) -> tuple[dns.message.Message | None, str | None]:
        key = (fqdn.lower().rstrip("."), record_type.value)
        query_counts[key[0]] = query_counts.get(key[0], 0) + 1
        resp = responses.get(key)
        if resp is None:
            return _servfail(fqdn + ".", record_type.value), None
        return resp, None

    pp: set[str] = set() if parent_passed is None else set(parent_passed)
    pf: set[str] = set() if parent_failed is None else set(parent_failed)

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
            messages=messages,
            cancel_check=None,
            progress_update=None,
            domain_index=1,
            domain_total=1,
            domains_completed=0,
            started_at=datetime(2026, 6, 26, 12, 0, 0),
            phase=ScanPhase.TESTING_FIFTH_LEVEL,
            candidates_offset=0,
            candidates_total=len(candidates),
            validate_fifth_level_parents=True,
            parent_passed=pp,
            parent_failed=pf,
        )
    return result, query_counts


def _usable_child_names(result: DomainScanResult, base: str) -> set[str]:
    scan_result = _mock_scan_result(result)
    rows = build_csv_rows(scan_result)
    return {
        row["discovered_name"]
        for row in rows
        if row["discovered_name"] != base
        and row.get("finding_type")
        not in {
            FindingClassification.QUERY_ERROR.value,
            FindingClassification.SCAN_ERROR.value,
        }
    }


def test_scenario_a_parent_fails_children_skipped() -> None:
    """Parent SERVFAIL → both 5th-level children must not be DNS-tested or found."""
    base = "lawrence.ma.us"
    portal = "portal.ci.lawrence.ma.us"
    msoid = "msoid.ci.lawrence.ma.us"
    parent = "ci.lawrence.ma.us"

    # No passing responses → parent gets SERVFAIL for every record type
    result, query_counts = _run_gated(base=base, candidates=[portal, msoid], responses={})

    names = _usable_child_names(result, base)
    assert portal not in names, f"portal should be skipped, found in names"
    assert msoid not in names, f"msoid should be skipped, found in names"
    assert parent not in names, f"failed parent should not appear as a finding"

    # Children must not have been queried (only parent queries allowed)
    assert query_counts.get(portal, 0) == 0, f"portal was DNS-queried despite parent failing"
    assert query_counts.get(msoid, 0) == 0, f"msoid was DNS-queried despite parent failing"

    summary = build_summary_rows(_mock_scan_result(result))[0]
    assert summary["new_child_domains_count"] == "0"
    assert summary["evidence_value"] in {"none", "context_only"}
    print("scenario A parent fails, children skipped: OK")


def test_scenario_b_parent_validates_child_fails() -> None:
    """Parent validates → child is DNS-tested; child SERVFAIL → child not found, parent is."""
    base = "lawrence.ma.us"
    parent = "ci.lawrence.ma.us"
    portal = "portal.ci.lawrence.ma.us"

    responses: dict[QueryKey, dns.message.Message] = {
        (parent, "NS"): _owner_ns_answer(parent + ".", "ns1.example"),
        (parent, "SOA"): _owner_soa_answer(parent + "."),
        (parent, "A"): _owner_a_answer(parent + "."),
    }

    result, query_counts = _run_gated(base=base, candidates=[portal], responses=responses)

    names = _usable_child_names(result, base)
    assert parent in names, "validated parent should be a finding"
    assert portal not in names, "child with no evidence should not be a finding"

    # Parent must have been queried; child must have been queried (parent passed)
    assert query_counts.get(parent, 0) > 0, "parent was not queried"
    assert query_counts.get(portal, 0) > 0, "child was not tested after parent validated"

    summary = build_summary_rows(_mock_scan_result(result))[0]
    assert parent in summary["new_child_domains_found"]
    assert portal not in summary.get("new_child_domains_found", "")
    print("scenario B parent validates, child fails: OK")


def test_scenario_c_known_parent_child_tested() -> None:
    """Known parent → child is tested directly without needing parent DNS validation."""
    base = "cc.pa.us"
    parent = "mc3.cc.pa.us"
    child = "admin.mc3.cc.pa.us"

    input_record = DomainInputRecord(
        domain=base,
        original_domain=base,
        known_fourth_level_domains=[parent],
    )

    # Parent is known; child has an A record
    responses: dict[QueryKey, dns.message.Message] = {
        (child, "A"): _owner_a_answer(child + "."),
    }

    # Seed parent_passed with the known parent (as scan_domain would)
    result, query_counts = _run_gated(
        base=base,
        candidates=[child],
        responses=responses,
        parent_passed={"mc3.cc.pa.us"},
        input_record=input_record,
    )

    names = _usable_child_names(result, base)
    assert child in names, "child under known parent should be found"

    # Parent DNS must NOT have been queried (it's already known)
    assert query_counts.get(parent, 0) == 0, f"known parent was unnecessarily queried"

    summary = build_summary_rows(_mock_scan_result(result))[0]
    assert child in summary["new_child_domains_found"]
    print("scenario C known parent, child tested: OK")


def test_scenario_d_unknown_parent_validates_child_validates() -> None:
    """Unknown parent validates AND child validates → both reported separately."""
    base = "cc.pa.us"
    parent = "mc3.cc.pa.us"
    child = "admin.mc3.cc.pa.us"

    responses: dict[QueryKey, dns.message.Message] = {
        (parent, "NS"): _owner_ns_answer(parent + ".", "ns1.mc3.example"),
        (parent, "SOA"): _owner_soa_answer(parent + "."),
        (parent, "A"): _owner_a_answer(parent + "."),
        (child, "A"): _owner_a_answer(child + "."),
    }

    result, query_counts = _run_gated(base=base, candidates=[child], responses=responses)

    names = _usable_child_names(result, base)
    assert parent in names, "validated parent should appear as finding"
    assert child in names, "child with direct evidence should appear as finding"

    summary = build_summary_rows(_mock_scan_result(result))[0]
    assert parent in summary["new_child_domains_found"]
    assert child in summary["new_child_domains_found"]
    assert int(summary["new_child_domains_count"]) >= 2
    print("scenario D unknown parent validates, child validates: OK")


def test_scenario_e_parent_fail_cache_dedup() -> None:
    """Failed parent cached → all three children skipped; parent queried exactly once."""
    base = "example.pa.us"
    parent = "ci.example.pa.us"
    candidates = [
        "portal.ci.example.pa.us",
        "msoid.ci.example.pa.us",
        "apps.ci.example.pa.us",
    ]

    # No responses → parent gets SERVFAIL
    result, query_counts = _run_gated(base=base, candidates=candidates, responses={})

    names = _usable_child_names(result, base)
    for c in candidates:
        assert c not in names, f"{c} should be skipped"
        assert query_counts.get(c, 0) == 0, f"{c} was queried despite parent failing"
    assert parent not in names

    # Parent should have been queried (to determine failure) but only once-worth
    parent_queries = query_counts.get(parent, 0)
    assert parent_queries > 0, "parent was never queried — cannot confirm it failed"
    # Should not be queried again for second or third child
    assert parent_queries <= len(RecordType.__members__) * 2, (
        f"parent queried too many times: {parent_queries}"
    )

    summary = build_summary_rows(_mock_scan_result(result))[0]
    assert summary["new_child_domains_count"] == "0"
    print("scenario E parent fail cache/dedup: OK")


def test_scenario_f_ticket20_unrelated_authority() -> None:
    """Ticket 20 preservation: unrelated com. SOA must not create .us child finding."""
    base = "lawrence.ma.us"
    parent = "ci.lawrence.ma.us"
    candidate = "portal.ci.lawrence.ma.us"

    # Parent responds with only unrelated com. authority — should fail validation
    responses: dict[QueryKey, dns.message.Message] = {
        (parent, "NS"): _unrelated_com_authority(parent + "."),
    }

    result, query_counts = _run_gated(base=base, candidates=[candidate], responses=responses)

    names = _usable_child_names(result, base)
    assert candidate not in names, "candidate must not be found"
    assert parent not in names, "parent with only unrelated authority must not be found"
    assert query_counts.get(candidate, 0) == 0, "candidate was queried despite parent failing"

    summary = build_summary_rows(_mock_scan_result(result))[0]
    assert summary["new_child_domains_count"] == "0"
    assert summary.get("new_delegated_domains_count", "0") == "0"
    print("scenario F Ticket 20 unrelated authority still rejected: OK")


def _run_regression(script_name: str) -> None:
    script = PROJECT_ROOT / "output" / script_name
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise AssertionError(f"{script_name} failed")


def main() -> None:
    test_scenario_a_parent_fails_children_skipped()
    test_scenario_b_parent_validates_child_fails()
    test_scenario_c_known_parent_child_tested()
    test_scenario_d_unknown_parent_validates_child_validates()
    test_scenario_e_parent_fail_cache_dedup()
    test_scenario_f_ticket20_unrelated_authority()
    for script in (
        "_ticket13_verify.py",
        "_ticket15_verify.py",
        "_ticket16_verify.py",
        "_ticket17_verify.py",
        "_ticket19_verify.py",
        "_ticket20_verify.py",
        "_ticket21_verify.py",
    ):
        _run_regression(script)
        print(f"{script}: OK")
    print("\nTicket 22 verification passed.")


if __name__ == "__main__":
    main()
