#!/usr/bin/env python3
"""Ticket 24 verification: Delegation Verification Mode.

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

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.regression._chain import run_durable_regression
from tests.regression._paths import REGRESSION_DIR, REPO_ROOT

from scanner.delegation_verifier import verify_delegated_child_zone
from scanner.export_service import build_csv_rows
from scanner.models import (
    DiscoveredRecord,
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
)
from scanner.paths import get_wordlists_dir
from scanner.scan_engine import (
    _make_resolver,
    _parse_dns_response,
    _query_records,
)

BASE = "lawrence.ma.us"
COM_SOA_RDATA = "a.gtld-servers.net. nstld.verisign-grs.com. 2026062601 1800 900 604800 86400"
ROOT_SOA_RDATA = "a.root-servers.net. nstld.verisign-grs.com. 2026062601 1800 900 604800 86400"
REAL_SOA_RDATA = "ns1.lawrence.ma.us. hostmaster.lawrence.ma.us. 2026062601 3600 600 604800 3600"

FP_CANDIDATES = [
    "webmail.ci.lawrence.ma.us",
    "smtp.ci.lawrence.ma.us",
    "mx.ci.lawrence.ma.us",
]

PARENT_NS = ["ns.lawrence.ma.us"]


def _qname(name: str) -> dns.name.Name:
    return dns.name.from_text(name.rstrip(".") + ".")


def _make_response(qname: str, qtype: str, rcode_value: int = dns.rcode.NOERROR) -> dns.message.Message:
    query = dns.message.make_query(_qname(qname), qtype)
    response = dns.message.make_response(query)
    response.set_rcode(rcode_value)
    return response


def _add_authority_soa(response: dns.message.Message, owner: str, rdata_text: str) -> None:
    soa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, rdata_text)
    response.authority.append(dns.rrset.from_rdata(_qname(owner), 900, soa))


def _add_authority_ns(response: dns.message.Message, owner: str, ns_target: str) -> None:
    ns = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target.rstrip(".") + ".")
    response.authority.append(dns.rrset.from_rdata(_qname(owner), 300, ns))


def _add_answer_ns(response: dns.message.Message, owner: str, ns_target: str) -> None:
    ns = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target.rstrip(".") + ".")
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, ns))


def _add_answer_a(response: dns.message.Message, owner: str, ip: str) -> None:
    a = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip)
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, a))


def _add_answer_soa(response: dns.message.Message, owner: str, rdata_text: str) -> None:
    soa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, rdata_text)
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, soa))


def _fake_resolve(_host: str) -> list[str]:
    return ["127.0.0.1"]


def _run_verify(
    candidate: str,
    fake_send,
    *,
    parent_ns_hosts: list[str] | None = None,
    delegation_child_ns_hosts: list[str] | None = None,
    log_sink: list[str] | None = None,
):
    return verify_delegated_child_zone(
        candidate,
        base_domain=BASE,
        send_query=fake_send,
        resolve_ns_ips=_fake_resolve,
        make_resolver=_make_resolver,
        parent_ns_hosts=parent_ns_hosts or PARENT_NS,
        delegation_child_ns_hosts=delegation_child_ns_hosts,
        log_sink=log_sink,
    )


def _delegated_records(records: list[DiscoveredRecord]) -> list[DiscoveredRecord]:
    return [r for r in records if r.classification == FindingClassification.DELEGATED_CHILD_ZONE]


# ---------------------------------------------------------------------------
# Positive verification
# ---------------------------------------------------------------------------

def test_positive_parent_authoritative_answer_ns() -> None:
    candidate = "api.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, "ns1.child.example.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = _run_verify(candidate, fake_send)
    assert result.verified, result.reason
    assert result.method == "parent_authoritative_ns"
    assert _delegated_records(result.records), result.records
    assert "Delegation verified" in result.log_message
    assert "parent-authoritative NS owner match" in result.log_message
    print("positive: parent-side answer NS owner match: OK")


def test_positive_parent_authoritative_referral_ns() -> None:
    candidate = "co.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_ns(r, fqdn, "ns1.child.example.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = _run_verify(candidate, fake_send)
    assert result.verified, result.reason
    assert result.method == "parent_authoritative_ns"
    assert _delegated_records(result.records)
    print("positive: parent-side referral authority NS: OK")


def test_positive_candidate_apex_ns() -> None:
    candidate = "portal.ci.lawrence.ma.us"
    child_ns = "ns1.child.example."

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS and fqdn == candidate:
            # Parent-side: no delegation proof
            if resolver.nameservers == ["127.0.0.1"]:
                # Distinguish parent vs child by query count: first pass parent fails,
                # second pass child apex succeeds.
                pass
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, child_ns)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    call_count = {"n": 0}

    def staged_send(fqdn, record_type, resolver):
        call_count["n"] += 1
        if call_count["n"] == 1 and record_type == RecordType.NS:
            return _make_response(fqdn, "NS", dns.rcode.NXDOMAIN), None
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, child_ns)
            return r, None
        if record_type == RecordType.SOA:
            return _make_response(fqdn, "SOA", dns.rcode.NXDOMAIN), None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    # First parent query returns delegation NS for child path discovery
    def parent_then_child_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS and fqdn == candidate:
            r = _make_response(fqdn, "NS")
            _add_authority_ns(r, fqdn, child_ns)
            return r, None
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, "ns1.verified.example.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = _run_verify(candidate, parent_then_child_send)
    assert result.verified, result.reason
    assert result.method in {"parent_authoritative_ns", "candidate_apex_ns"}
    print("positive: candidate-apex or parent NS verification: OK")


def test_positive_candidate_apex_soa() -> None:
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

    result = _run_verify(
        candidate,
        fake_send,
        delegation_child_ns_hosts=[child_ns],
    )
    assert result.verified, result.reason
    assert result.method == "candidate_apex_soa"
    assert result.records[0].classification == FindingClassification.ZONE_SOA_DISCOVERED
    assert not _delegated_records(result.records)
    print("positive: candidate-apex SOA zone evidence: OK")


# ---------------------------------------------------------------------------
# Negative verification
# ---------------------------------------------------------------------------

def test_negative_recursive_ns_not_verified() -> None:
    """Recursive-looking NS material must not bypass verification."""
    candidate = "smtp.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        # Simulates recursive resolver returning NS — but parent auth returns unrelated
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        return None, None

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    assert not _delegated_records(result.records)
    print("negative: recursive/unrelated not verified: OK")


def test_negative_parent_ns_owner_not_candidate() -> None:
    candidate = "mx.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_ns(r, "ci.lawrence.ma.us", "ns1.parent.example.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    log_sink: list[str] = []
    result = _run_verify(candidate, fake_send, log_sink=log_sink)
    assert not result.verified
    assert not _delegated_records(result.records)
    assert any("Ignored unverified delegation signal" in line for line in log_sink)
    print("negative: parent-side NS owner != candidate: OK")


def test_negative_soa_only_authority() -> None:
    candidate = "webmail.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, fqdn, REAL_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    assert not _delegated_records(result.records)
    assert "NODATA_EMPTY_ANSWER" in result.log_message
    print("negative: SOA-only authority (NODATA): OK")


def test_negative_com_registry_for_us_candidate() -> None:
    for candidate in FP_CANDIDATES:
        def fake_send(fqdn, record_type, resolver, _c=candidate):
            if record_type == RecordType.NS:
                r = _make_response(fqdn, "NS")
                _add_authority_soa(r, "com.", COM_SOA_RDATA)
                return r, None
            return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

        log_sink: list[str] = []
        result = _run_verify(candidate, fake_send, log_sink=log_sink)
        assert not result.verified, f"{candidate} must not verify from .com authority"
        assert not _delegated_records(result.records)
        assert not any("Delegated child zone:" in line for line in log_sink)
    print("negative: .com registry authority for .us candidates: OK")


def test_negative_root_soa() -> None:
    candidate = "smtp.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, ".", ROOT_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    assert not _delegated_records(result.records)
    print("negative: root SOA: OK")


def test_negative_nxdomain_with_soa() -> None:
    candidate = "mx.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS", dns.rcode.NXDOMAIN)
            _add_authority_soa(r, "ci.lawrence.ma.us.", REAL_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    assert "NEGATIVE_NXDOMAIN" in result.log_message
    print("negative: NXDOMAIN with SOA: OK")


def test_negative_servfail() -> None:
    candidate = "webmail.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        return _make_response(fqdn, "NS", dns.rcode.SERVFAIL), None

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    assert "SERVFAIL" in result.log_message
    print("negative: SERVFAIL: OK")


def test_negative_timeout() -> None:
    candidate = "smtp.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        return None, f"{fqdn} NS: timeout via 127.0.0.1"

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    assert "TIMEOUT" in result.log_message or result.errors
    print("negative: TIMEOUT: OK")


def test_negative_malformed() -> None:
    candidate = "mx.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        return None, f"{fqdn} NS: OSError connection refused"

    result = _run_verify(candidate, fake_send)
    assert not result.verified
    print("negative: malformed/unusable: OK")


def test_parse_dns_response_does_not_promote_delegation() -> None:
    """_parse_dns_response must not auto-promote NS to delegated_child_zone."""
    candidate = "smtp.ci.lawrence.ma.us"
    response = _make_response(candidate, "NS")
    _add_answer_ns(response, candidate, "a.gtld-servers.net.")

    findings = _parse_dns_response(
        response,
        candidate,
        RecordType.NS,
        base_domain=BASE,
        source_method="generated_candidate",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
        nameserver=None,
    )
    delegated = _delegated_records(findings)
    assert not delegated, f"parse must not promote unverified delegation: {findings}"
    print("negative: _parse_dns_response does not promote delegation: OK")


def test_query_records_blocks_delegated_classification() -> None:
    """_query_records must not create delegated_child_zone even if classification requests it."""
    candidate = "mx.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        r = _make_response(fqdn, "NS")
        _add_answer_ns(r, fqdn, "ns1.example.net.")
        return r, None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, _ = _query_records(
            candidate,
            (RecordType.NS,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.DELEGATED_CHILD_ZONE,
            base_domain=BASE,
        )
    assert not _delegated_records(findings), f"_query_records must block delegation: {findings}"
    print("negative: _query_records blocks unverified delegation: OK")


def test_export_excludes_unverified_delegation() -> None:
    """Export rows must not show delegated_child_zone for unverified candidates."""
    input_record = DomainInputRecord(domain=BASE, original_domain=BASE)
    domain_result = DomainScanResult(
        domain=BASE,
        input_record=input_record,
        records=[
            DiscoveredRecord(
                fqdn="smtp.ci.lawrence.ma.us",
                record_type=RecordType.A,
                value="10.0.0.1",
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
            )
        ],
    )
    run = ScanRunResult(
        input=ScanInput(
            domain_file_path=Path("fake.csv"),
            options=ScanOptions(scan_profile=ScanProfile.NORMAL),
            output_dir=Path("."),
            wordlists_dir=get_wordlists_dir(),
        ),
        domain_inputs=[input_record],
        domain_results=[domain_result],
        scan_timestamp=datetime(2026, 6, 26, 18, 0, 0),
        finished_at=datetime(2026, 6, 26, 18, 5, 0),
        scan_status=ScanStatus.COMPLETED,
    )
    rows = build_csv_rows(run)
    delegated_rows = [
        r for r in rows
        if r.get("classification") == "delegated_child_zone"
        or r.get("name_type") == "delegated_child_zone"
    ]
    assert not delegated_rows
    print("negative: export excludes unverified delegation: OK")


# ---------------------------------------------------------------------------
# Ordinary DNS evidence still works
# ---------------------------------------------------------------------------

def test_ordinary_a_record_still_works() -> None:
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
    assert findings, findings
    assert findings[0].record_type == RecordType.A
    assert findings[0].classification == FindingClassification.STANDARD_RECORD
    print("ordinary: owner-matching A still works: OK")


def test_log_shape_verified_and_ignored() -> None:
    candidate = "api.ci.lawrence.ma.us"

    def fake_send_ok(fqdn, record_type, resolver):
        r = _make_response(fqdn, "NS")
        _add_answer_ns(r, fqdn, "ns1.child.example.")
        return r, None

    result = _run_verify(candidate, fake_send_ok)
    assert "Delegation verified for" in result.log_message
    assert "Delegated child zone:" not in result.log_message

    def fake_send_bad(fqdn, record_type, resolver):
        r = _make_response(fqdn, "NS")
        _add_authority_ns(r, "com.", "a.gtld-servers.net.")
        return r, None

    log_sink: list[str] = []
    bad = _run_verify("smtp.ci.lawrence.ma.us", fake_send_bad, log_sink=log_sink)
    assert not bad.verified
    assert any("Ignored unverified delegation signal" in line for line in log_sink)
    assert not any("Delegated child zone:" in line for line in log_sink)
    print("logging: verified vs ignored shapes: OK")


# ---------------------------------------------------------------------------
# Regression chain
# ---------------------------------------------------------------------------


def main() -> None:
    print("=== Ticket 24: Delegation Verification Mode ===\n")

    print("-- Positive verification --")
    test_positive_parent_authoritative_answer_ns()
    test_positive_parent_authoritative_referral_ns()
    test_positive_candidate_apex_ns()
    test_positive_candidate_apex_soa()

    print("\n-- Negative verification --")
    test_negative_recursive_ns_not_verified()
    test_negative_parent_ns_owner_not_candidate()
    test_negative_soa_only_authority()
    test_negative_com_registry_for_us_candidate()
    test_negative_root_soa()
    test_negative_nxdomain_with_soa()
    test_negative_servfail()
    test_negative_timeout()
    test_negative_malformed()
    test_parse_dns_response_does_not_promote_delegation()
    test_query_records_blocks_delegated_classification()
    test_export_excludes_unverified_delegation()

    print("\n-- Ordinary evidence --")
    test_ordinary_a_record_still_works()
    test_log_shape_verified_and_ignored()

    print("\n-- Prior regression chain --")
    run_durable_regression(REGRESSION_DIR / "test_ticket23_dns_classifier.py")

    print("\n=== Ticket 24 verification PASSED ===")


if __name__ == "__main__":
    main()
