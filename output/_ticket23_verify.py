#!/usr/bin/env python3
"""Ticket 23 verification: DNS response classification firewall.

Tests all nine DNSResponseClass values, evidence rules, and the specific
false-positive regression fixtures from the ticket.

All DNS interactions are synthetic (mocked); no live network calls occur.
"""

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

from scanner.delegation_verifier import verify_delegated_child_zone
from scanner.dns_classifier import DNSResponseClass, classify_dns_response, is_no_finding_class
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
    _test_candidates,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

BASE = "lawrence.ma.us"
COM_SOA_RDATA = "a.gtld-servers.net. nstld.verisign-grs.com. 2026062601 1800 900 604800 86400"
ROOT_SOA_RDATA = "a.root-servers.net. nstld.verisign-grs.com. 2026062601 1800 900 604800 86400"
REAL_SOA_RDATA = "ns1.lawrence.ma.us. hostmaster.lawrence.ma.us. 2026062601 3600 600 604800 3600"

# The three false-positive candidates named in the ticket
FP_CANDIDATES = [
    "webmail.ci.lawrence.ma.us",
    "smtp.ci.lawrence.ma.us",
    "mx.ci.lawrence.ma.us",
]


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

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


def _add_answer_aaaa(response: dns.message.Message, owner: str, ip: str) -> None:
    aaaa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, ip)
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, aaaa))


def _add_answer_cname(response: dns.message.Message, owner: str, target: str) -> None:
    cname = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, target.rstrip(".") + ".")
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, cname))


def _add_answer_mx(response: dns.message.Message, owner: str, pref: int, exchange: str) -> None:
    mx = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, f"{pref} {exchange.rstrip('.')}.")
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, mx))


def _add_answer_txt(response: dns.message.Message, owner: str, text: str) -> None:
    txt = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{text}"')
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, txt))


def _add_answer_caa(response: dns.message.Message, owner: str) -> None:
    caa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CAA, '0 issue "letsencrypt.org"')
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, caa))


def _add_answer_soa(response: dns.message.Message, owner: str, rdata_text: str) -> None:
    soa = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, rdata_text)
    response.answer.append(dns.rrset.from_rdata(_qname(owner), 300, soa))


# ---------------------------------------------------------------------------
# Section 1: classify_dns_response — one test per required class
# ---------------------------------------------------------------------------

def test_classify_unrelated_authority_com_soa() -> None:
    """NOERROR + .com authority SOA while checking a .us candidate -> UNRELATED_AUTHORITY."""
    for candidate in FP_CANDIDATES:
        for qtype in ("NS", "SOA", "A"):
            response = _make_response(candidate, qtype, dns.rcode.NOERROR)
            _add_authority_soa(response, "com.", COM_SOA_RDATA)
            rc = classify_dns_response(response, candidate)
            assert rc == DNSResponseClass.UNRELATED_AUTHORITY, (
                f"{candidate} {qtype}: expected UNRELATED_AUTHORITY, got {rc}"
            )
    print("classify UNRELATED_AUTHORITY (.com SOA): OK")


def test_classify_unrelated_authority_root_soa() -> None:
    """NOERROR + root authority SOA -> UNRELATED_AUTHORITY."""
    candidate = "smtp.ci.lawrence.ma.us"
    response = _make_response(candidate, "A", dns.rcode.NOERROR)
    _add_authority_soa(response, ".", ROOT_SOA_RDATA)
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.UNRELATED_AUTHORITY, f"root SOA: expected UNRELATED_AUTHORITY, got {rc}"
    print("classify UNRELATED_AUTHORITY (root SOA): OK")


def test_classify_unrelated_authority_com_ns() -> None:
    """NOERROR + authority NS whose owner is .com (unrelated) -> UNRELATED_AUTHORITY."""
    candidate = "webmail.ci.lawrence.ma.us"
    response = _make_response(candidate, "NS", dns.rcode.NOERROR)
    _add_authority_ns(response, "com.", "a.gtld-servers.net.")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.UNRELATED_AUTHORITY, f"com NS: expected UNRELATED_AUTHORITY, got {rc}"
    print("classify UNRELATED_AUTHORITY (.com NS): OK")


def test_classify_servfail() -> None:
    """SERVFAIL response -> SERVFAIL."""
    response = _make_response("mail.ci.ma.us", "NS", dns.rcode.SERVFAIL)
    rc = classify_dns_response(response, "mail.ci.ma.us")
    assert rc == DNSResponseClass.SERVFAIL, f"expected SERVFAIL, got {rc}"
    print("classify SERVFAIL: OK")


def test_classify_timeout() -> None:
    """Transport timeout string -> TIMEOUT."""
    rc = classify_dns_response(None, "mail.ci.ma.us", transport_error="mail.ci.ma.us NS: timeout via 1.1.1.1")
    assert rc == DNSResponseClass.TIMEOUT, f"expected TIMEOUT, got {rc}"
    print("classify TIMEOUT: OK")


def test_classify_negative_nxdomain() -> None:
    """NXDOMAIN response (with or without authority SOA) -> NEGATIVE_NXDOMAIN."""
    candidate = "webmail.ci.lawrence.ma.us"
    # Without authority SOA
    response = _make_response(candidate, "A", dns.rcode.NXDOMAIN)
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.NEGATIVE_NXDOMAIN, f"plain NXDOMAIN: got {rc}"

    # With authority SOA for parent zone (denial proof) — must still be NEGATIVE_NXDOMAIN
    response2 = _make_response(candidate, "A", dns.rcode.NXDOMAIN)
    _add_authority_soa(response2, "ci.lawrence.ma.us.", REAL_SOA_RDATA)
    rc2 = classify_dns_response(response2, candidate)
    assert rc2 == DNSResponseClass.NEGATIVE_NXDOMAIN, f"NXDOMAIN+SOA: got {rc2}"

    # With .com authority SOA in NXDOMAIN (gtld server denial) — still NEGATIVE_NXDOMAIN
    response3 = _make_response(candidate, "A", dns.rcode.NXDOMAIN)
    _add_authority_soa(response3, "com.", COM_SOA_RDATA)
    rc3 = classify_dns_response(response3, candidate)
    assert rc3 == DNSResponseClass.NEGATIVE_NXDOMAIN, f"NXDOMAIN+com SOA: got {rc3}"
    print("classify NEGATIVE_NXDOMAIN: OK")


def test_classify_nodata_empty_answer() -> None:
    """NOERROR, empty answer, authority SOA for queried name -> NODATA_EMPTY_ANSWER."""
    candidate = "ci.lawrence.ma.us"
    response = _make_response(candidate, "A", dns.rcode.NOERROR)
    _add_authority_soa(response, candidate, REAL_SOA_RDATA)
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.NODATA_EMPTY_ANSWER, f"expected NODATA_EMPTY_ANSWER, got {rc}"

    # Also test: NOERROR with empty answer and empty authority
    response2 = _make_response("nxlike.ci.lawrence.ma.us", "A", dns.rcode.NOERROR)
    rc2 = classify_dns_response(response2, "nxlike.ci.lawrence.ma.us")
    assert rc2 == DNSResponseClass.NODATA_EMPTY_ANSWER, f"empty NOERROR: expected NODATA_EMPTY_ANSWER, got {rc2}"
    print("classify NODATA_EMPTY_ANSWER: OK")


def test_classify_owner_matching_answer_a() -> None:
    """NOERROR + owner-matching A in answer -> OWNER_MATCHING_ANSWER."""
    candidate = "portal.ci.lawrence.ma.us"
    response = _make_response(candidate, "A", dns.rcode.NOERROR)
    _add_answer_a(response, candidate, "10.0.0.1")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.OWNER_MATCHING_ANSWER, f"A: expected OWNER_MATCHING_ANSWER, got {rc}"
    print("classify OWNER_MATCHING_ANSWER (A): OK")


def test_classify_owner_matching_answer_aaaa() -> None:
    """NOERROR + owner-matching AAAA in answer -> OWNER_MATCHING_ANSWER."""
    candidate = "v6host.ci.lawrence.ma.us"
    response = _make_response(candidate, "AAAA", dns.rcode.NOERROR)
    _add_answer_aaaa(response, candidate, "2001:db8::1")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.OWNER_MATCHING_ANSWER, f"AAAA: expected OWNER_MATCHING_ANSWER, got {rc}"
    print("classify OWNER_MATCHING_ANSWER (AAAA): OK")


def test_classify_owner_matching_answer_ns() -> None:
    """NOERROR + owner-matching NS in answer -> OWNER_MATCHING_ANSWER."""
    candidate = "ci.lawrence.ma.us"
    response = _make_response(candidate, "NS", dns.rcode.NOERROR)
    _add_answer_ns(response, candidate, "ns1.example.net.")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.OWNER_MATCHING_ANSWER, f"NS: expected OWNER_MATCHING_ANSWER, got {rc}"
    print("classify OWNER_MATCHING_ANSWER (NS): OK")


def test_classify_owner_matching_answer_mx() -> None:
    """NOERROR + owner-matching MX in answer -> OWNER_MATCHING_ANSWER."""
    candidate = "ci.lawrence.ma.us"
    response = _make_response(candidate, "MX", dns.rcode.NOERROR)
    _add_answer_mx(response, candidate, 10, "mail.example.net.")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.OWNER_MATCHING_ANSWER, f"MX: expected OWNER_MATCHING_ANSWER, got {rc}"
    print("classify OWNER_MATCHING_ANSWER (MX): OK")


def test_classify_owner_matching_answer_txt() -> None:
    """NOERROR + owner-matching TXT in answer -> OWNER_MATCHING_ANSWER."""
    candidate = "ci.lawrence.ma.us"
    response = _make_response(candidate, "TXT", dns.rcode.NOERROR)
    _add_answer_txt(response, candidate, "v=spf1 include:example.com ~all")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.OWNER_MATCHING_ANSWER, f"TXT: expected OWNER_MATCHING_ANSWER, got {rc}"
    print("classify OWNER_MATCHING_ANSWER (TXT): OK")


def test_classify_owner_matching_answer_caa() -> None:
    """NOERROR + owner-matching CAA in answer -> OWNER_MATCHING_ANSWER."""
    candidate = "ci.lawrence.ma.us"
    response = _make_response(candidate, "CAA", dns.rcode.NOERROR)
    _add_answer_caa(response, candidate)
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.OWNER_MATCHING_ANSWER, f"CAA: expected OWNER_MATCHING_ANSWER, got {rc}"
    print("classify OWNER_MATCHING_ANSWER (CAA): OK")


def test_classify_cname_alias() -> None:
    """NOERROR + owner-matching CNAME in answer -> CNAME_ALIAS."""
    candidate = "www.ci.lawrence.ma.us"
    response = _make_response(candidate, "CNAME", dns.rcode.NOERROR)
    _add_answer_cname(response, candidate, "ci.lawrence.ma.us.")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.CNAME_ALIAS, f"CNAME: expected CNAME_ALIAS, got {rc}"
    print("classify CNAME_ALIAS: OK")


def test_classify_referral_delegation() -> None:
    """NOERROR + authority NS whose owner equals queried name -> REFERRAL_DELEGATION."""
    candidate = "ci.lawrence.ma.us"
    response = _make_response(candidate, "NS", dns.rcode.NOERROR)
    _add_authority_ns(response, candidate, "ns1.example.net.")
    rc = classify_dns_response(response, candidate)
    assert rc == DNSResponseClass.REFERRAL_DELEGATION, f"referral: expected REFERRAL_DELEGATION, got {rc}"
    print("classify REFERRAL_DELEGATION: OK")


def test_classify_malformed_or_unusable() -> None:
    """None response with non-timeout error -> MALFORMED_OR_UNUSABLE."""
    rc = classify_dns_response(None, "foo.ma.us", transport_error="foo.ma.us NS: OSError connection refused")
    assert rc == DNSResponseClass.MALFORMED_OR_UNUSABLE, f"expected MALFORMED_OR_UNUSABLE, got {rc}"

    rc2 = classify_dns_response(None, "foo.ma.us", transport_error=None)
    assert rc2 == DNSResponseClass.MALFORMED_OR_UNUSABLE, f"None response: expected MALFORMED_OR_UNUSABLE, got {rc2}"
    print("classify MALFORMED_OR_UNUSABLE: OK")


# ---------------------------------------------------------------------------
# Section 2: Evidence rules — only allowed (class, rr_type) pairs create findings
# ---------------------------------------------------------------------------

def _verify_delegation_with_mocks(
    candidate: str,
    base_domain: str,
    fake_send,
    *,
    parent_ns_hosts: list[str] | None = None,
) -> list[DiscoveredRecord]:
    """Run delegation verification with mocked DNS (Ticket 24 path)."""
    def fake_resolve(_host: str) -> list[str]:
        return ["127.0.0.1"]

    result = verify_delegated_child_zone(
        candidate,
        base_domain=base_domain,
        send_query=fake_send,
        resolve_ns_ips=fake_resolve,
        make_resolver=_make_resolver,
        parent_ns_hosts=parent_ns_hosts or ["ns.parent.example"],
    )
    return result.records if result.verified else []


def test_evidence_owner_matching_ns_creates_delegated_child_zone() -> None:
    """Owner-matching NS via parent-authoritative verification -> DELEGATED_CHILD_ZONE."""
    candidate = "portal.example.pa.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, "ns1.example.net.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        records = _verify_delegation_with_mocks(
            candidate, "example.pa.us", fake_send, parent_ns_hosts=["ns.parent.us"]
        )
    delegated = [f for f in records if f.classification == FindingClassification.DELEGATED_CHILD_ZONE]
    assert len(delegated) == 1, f"expected 1 delegated_child_zone, got {records}"
    assert delegated[0].fqdn == candidate
    assert delegated[0].record_type == RecordType.NS
    print("evidence: owner-matching NS -> delegated_child_zone: OK")


def test_evidence_owner_matching_soa_creates_zone_apex() -> None:
    """Owner-matching SOA in answer -> ZONE_SOA_DISCOVERED finding."""
    candidate = "ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.SOA:
            r = _make_response(fqdn, "SOA")
            _add_answer_soa(r, fqdn, REAL_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.SOA,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    soa_findings = [f for f in findings if f.record_type == RecordType.SOA]
    assert soa_findings, f"expected SOA zone finding, got {findings}"
    assert soa_findings[0].fqdn == candidate
    print("evidence: owner-matching SOA in answer -> zone/apex finding: OK")


def test_evidence_owner_matching_a_creates_standard_record() -> None:
    """Owner-matching A in answer -> STANDARD_RECORD finding."""
    candidate = "portal.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.A:
            r = _make_response(fqdn, "A")
            _add_answer_a(r, fqdn, "192.168.1.10")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    a_findings = [f for f in findings if f.record_type == RecordType.A]
    assert a_findings, f"expected A record finding, got {findings}"
    assert a_findings[0].fqdn == candidate
    assert a_findings[0].classification == FindingClassification.STANDARD_RECORD
    print("evidence: owner-matching A -> standard_record: OK")


def test_evidence_owner_matching_aaaa_creates_standard_record() -> None:
    """Owner-matching AAAA in answer -> STANDARD_RECORD finding."""
    candidate = "v6.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.AAAA:
            r = _make_response(fqdn, "AAAA")
            _add_answer_aaaa(r, fqdn, "2001:db8::42")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.AAAA,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert findings, f"expected AAAA record finding, got {findings}"
    assert findings[0].record_type == RecordType.AAAA
    print("evidence: owner-matching AAAA -> standard_record: OK")


def test_evidence_owner_matching_cname_creates_alias_evidence() -> None:
    """Owner-matching CNAME in answer -> ordinary alias finding (CNAME_ALIAS classification)."""
    candidate = "www.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.CNAME:
            r = _make_response(fqdn, "CNAME")
            _add_answer_cname(r, fqdn, "ci.lawrence.ma.us.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.CNAME,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    cname_findings = [f for f in findings if f.record_type == RecordType.CNAME]
    assert cname_findings, f"expected CNAME finding, got {findings}"
    assert cname_findings[0].fqdn == candidate
    print("evidence: owner-matching CNAME -> alias evidence: OK")


def test_evidence_owner_matching_mx_creates_standard_record() -> None:
    """Owner-matching MX in answer -> STANDARD_RECORD finding."""
    candidate = "ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.MX:
            r = _make_response(fqdn, "MX")
            _add_answer_mx(r, fqdn, 10, "mail.example.net.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.MX,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert [f for f in findings if f.record_type == RecordType.MX], f"expected MX finding, got {findings}"
    print("evidence: owner-matching MX -> standard_record: OK")


def test_evidence_owner_matching_txt_creates_standard_record() -> None:
    """Owner-matching TXT in answer -> STANDARD_RECORD finding."""
    candidate = "ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.TXT:
            r = _make_response(fqdn, "TXT")
            _add_answer_txt(r, fqdn, "v=spf1 include:example.com ~all")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.TXT,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert [f for f in findings if f.record_type == RecordType.TXT], f"expected TXT finding, got {findings}"
    print("evidence: owner-matching TXT -> standard_record: OK")


def test_evidence_owner_matching_caa_creates_standard_record() -> None:
    """Owner-matching CAA in answer -> STANDARD_RECORD finding."""
    candidate = "ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.CAA:
            r = _make_response(fqdn, "CAA")
            _add_answer_caa(r, fqdn)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.CAA,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert [f for f in findings if f.record_type == RecordType.CAA], f"expected CAA finding, got {findings}"
    print("evidence: owner-matching CAA -> standard_record: OK")


# ---------------------------------------------------------------------------
# Section 3: No-finding rules — each of these must produce zero findings
# ---------------------------------------------------------------------------

def test_no_finding_nxdomain_with_soa_authority() -> None:
    """NXDOMAIN + authority SOA creates no finding."""
    for candidate in FP_CANDIDATES:
        def fake_send(fqdn, record_type, resolver, _c=candidate):
            r = _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN)
            _add_authority_soa(r, "ci.lawrence.ma.us.", REAL_SOA_RDATA)
            return r, None

        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            findings, errors = _query_records(
                candidate,
                (RecordType.NS, RecordType.SOA),
                _make_resolver(),
                source_method="generated_candidate",
                classification=FindingClassification.DELEGATED_CHILD_ZONE,
                base_domain=BASE,
            )
        assert not findings, f"{candidate}: NXDOMAIN+SOA must not create findings: {findings}"
    print("no finding: NXDOMAIN with authority SOA: OK")


def test_no_finding_servfail() -> None:
    """SERVFAIL creates no finding and records an error."""
    candidate = "mail.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        return _make_response(fqdn, record_type.value, dns.rcode.SERVFAIL), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.NS, RecordType.SOA),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert not findings, f"SERVFAIL: must not create findings: {findings}"
    assert errors, "SERVFAIL: should be recorded as query error"
    print("no finding: SERVFAIL: OK")


def test_no_finding_timeout() -> None:
    """Timeout creates no finding and records an error."""
    candidate = "ftp.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        return None, f"{fqdn} {record_type.value}: timeout via 8.8.8.8"

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert not findings, f"timeout: must not create findings: {findings}"
    assert errors, "timeout: should be recorded as query error"
    print("no finding: TIMEOUT: OK")


def test_no_finding_noerror_empty_answer() -> None:
    """NOERROR empty answer with no authority creates no direct finding."""
    candidate = "unknown.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        return _make_response(fqdn, record_type.value, dns.rcode.NOERROR), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.A, RecordType.NS),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    delegated = [f for f in findings if f.classification == FindingClassification.DELEGATED_CHILD_ZONE]
    assert not delegated, f"empty NOERROR must not create delegated_child_zone: {findings}"
    print("no finding: NOERROR empty answer: OK")


def test_no_finding_malformed() -> None:
    """None response with no transport error -> MALFORMED_OR_UNUSABLE -> no finding."""
    rc = classify_dns_response(None, "foo.ma.us", transport_error=None)
    assert rc == DNSResponseClass.MALFORMED_OR_UNUSABLE
    print("no finding: MALFORMED_OR_UNUSABLE (None response): OK")


# ---------------------------------------------------------------------------
# Section 4: False-positive regression — the three named candidates
# ---------------------------------------------------------------------------

def _com_authority_response(qname: str, qtype: str) -> dns.message.Message:
    """NOERROR + .com authority SOA (gtld-server denial payload) for a .us candidate."""
    response = _make_response(qname, qtype, dns.rcode.NOERROR)
    _add_authority_soa(response, "com.", COM_SOA_RDATA)
    return response


def test_false_positive_regression_unrelated_com_authority() -> None:
    """webmail / smtp / mx .ci.lawrence.ma.us must not become delegated_child_zone
    when all responses carry unrelated .com authority data."""
    for candidate in FP_CANDIDATES:
        def fake_send(fqdn, record_type, resolver, _c=candidate):
            return _com_authority_response(fqdn, record_type.value), None

        log_sink: list[str] = []
        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            findings, errors = _query_records(
                candidate,
                (RecordType.NS, RecordType.SOA, RecordType.A),
                _make_resolver(),
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=BASE,
                log_sink=log_sink,
            )

        delegated = [f for f in findings if f.classification == FindingClassification.DELEGATED_CHILD_ZONE]
        assert not delegated, (
            f"{candidate}: MUST NOT be classified delegated_child_zone "
            f"from unrelated .com authority payload: {findings}"
        )
        assert not findings or all(
            f.classification != FindingClassification.ZONE_SOA_DISCOVERED for f in findings
        ), f"{candidate}: MUST NOT create zone_soa_discovered from unrelated authority: {findings}"

        # Diagnostic log must be present for the unrelated authority encounter
        assert any("Ignored unrelated authority" in line and candidate in line for line in log_sink), (
            f"{candidate}: expected 'Ignored unrelated authority ... {candidate}' in log_sink, got: {log_sink}"
        )
    print("false-positive regression (unrelated .com authority): OK")


def test_false_positive_regression_nxdomain_path() -> None:
    """webmail / smtp / mx via NXDOMAIN path must not create delegated_child_zone."""
    for candidate in FP_CANDIDATES:
        def fake_send(fqdn, record_type, resolver):
            r = _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN)
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None

        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            findings, errors = _query_records(
                candidate,
                (RecordType.NS, RecordType.SOA),
                _make_resolver(),
                source_method="generated_candidate",
                classification=FindingClassification.DELEGATED_CHILD_ZONE,
                base_domain=BASE,
            )
        assert not [f for f in findings if f.classification == FindingClassification.DELEGATED_CHILD_ZONE], (
            f"{candidate}: NXDOMAIN+com SOA must not create delegated_child_zone: {findings}"
        )
    print("false-positive regression (NXDOMAIN + .com authority): OK")


def test_false_positive_regression_servfail_path() -> None:
    """webmail / smtp / mx via SERVFAIL path must not create delegated_child_zone."""
    for candidate in FP_CANDIDATES:
        def fake_send(fqdn, record_type, resolver):
            return _make_response(fqdn, record_type.value, dns.rcode.SERVFAIL), None

        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            findings, errors = _query_records(
                candidate,
                (RecordType.NS, RecordType.SOA),
                _make_resolver(),
                source_method="generated_candidate",
                classification=FindingClassification.DELEGATED_CHILD_ZONE,
                base_domain=BASE,
            )
        assert not [f for f in findings if f.classification == FindingClassification.DELEGATED_CHILD_ZONE], (
            f"{candidate}: SERVFAIL must not create delegated_child_zone: {findings}"
        )
    print("false-positive regression (SERVFAIL): OK")


# ---------------------------------------------------------------------------
# Section 5: Known-good cases must still work
# ---------------------------------------------------------------------------

def test_known_good_delegated_child_zone_via_answer_ns() -> None:
    """Parent-authoritative NS delegation still creates delegated_child_zone."""
    real_child = "ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, "ns1.cityoflawrence.com.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        records = _verify_delegation_with_mocks(
            real_child, BASE, fake_send, parent_ns_hosts=["ns.lawrence.ma.us"]
        )
    delegated = [f for f in records if f.classification == FindingClassification.DELEGATED_CHILD_ZONE]
    assert delegated, f"known-good NS delegation must still produce findings: {records}"
    assert delegated[0].record_type == RecordType.NS
    assert delegated[0].fqdn == real_child
    print("known-good: delegated_child_zone via answer NS: OK")


def test_known_good_ordinary_a_record() -> None:
    """A real A record still creates ordinary evidence."""
    real_child = "portal.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.A:
            r = _make_response(fqdn, "A")
            _add_answer_a(r, fqdn, "67.200.100.10")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            real_child,
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert findings, f"known-good A record must still produce finding: {findings}"
    assert findings[0].record_type == RecordType.A
    print("known-good: ordinary A record evidence: OK")


def test_nodata_fail_closed_through_query_records() -> None:
    """NODATA_EMPTY_ANSWER must not call _parse_dns_response and creates no finding.

    Authority SOA for the queried name (zone exists, record type absent) is
    classified NODATA and fail-closed at the classifier gate.  Owner-matching
    SOA in the answer section (OWNER_MATCHING_ANSWER) is the supported path
    for zone/apex evidence via _query_records.
    """
    base = "fei.davis.ca.us"
    response = _make_response(base, "A", dns.rcode.NOERROR)
    _add_authority_soa(
        response,
        base,
        "ns-432.awsdns-54.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400",
    )

    rc = classify_dns_response(response, base)
    assert rc == DNSResponseClass.NODATA_EMPTY_ANSWER, (
        f"base-domain auth SOA: expected NODATA_EMPTY_ANSWER, got {rc}"
    )
    assert is_no_finding_class(rc), "NODATA_EMPTY_ANSWER must be a no-finding class"

    def fake_send(fqdn, record_type, resolver):
        return response, None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            base,
            (RecordType.A,),
            _make_resolver(),
            source_method="authoritative_nameserver",
            classification=FindingClassification.BASE_DOMAIN_RECORD,
            base_domain=base,
        )
    assert not findings, (
        "NODATA_EMPTY_ANSWER must fail-closed: no findings via _query_records"
    )
    print("fail-closed: NODATA_EMPTY_ANSWER bypasses _parse_dns_response: OK")


def test_known_good_log_diagnostic_for_unrelated_authority() -> None:
    """Verify the required log shape for ignored unrelated authority data."""
    candidate = "smtp.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        r = _make_response(fqdn, record_type.value, dns.rcode.NOERROR)
        _add_authority_soa(r, "com.", COM_SOA_RDATA)
        return r, None

    log_sink: list[str] = []
    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, errors = _query_records(
            candidate,
            (RecordType.NS,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
            log_sink=log_sink,
        )
    assert not findings, f"unrelated authority: must not create findings: {findings}"
    assert log_sink, "unrelated authority: log_sink must receive a diagnostic message"
    assert any(candidate in line for line in log_sink), (
        f"log diagnostic must mention the candidate name; got: {log_sink}"
    )
    assert not any("Delegated child zone" in line for line in log_sink), (
        f"Forbidden log shape 'Delegated child zone:' must not appear: {log_sink}"
    )
    print("known-good: log diagnostic for unrelated authority: OK")


# ---------------------------------------------------------------------------
# Section 6: Run prior regression chain
# ---------------------------------------------------------------------------

def _run_regression(script_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        print(f"REGRESSION FAIL: {script_path.name}\n{output}")
        sys.exit(1)
    print(f"  Regression chain: {script_path.name} passed")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Ticket 23: DNS Response Classification Firewall ===\n")

    print("-- Section 1: classify_dns_response --")
    test_classify_unrelated_authority_com_soa()
    test_classify_unrelated_authority_root_soa()
    test_classify_unrelated_authority_com_ns()
    test_classify_servfail()
    test_classify_timeout()
    test_classify_negative_nxdomain()
    test_classify_nodata_empty_answer()
    test_classify_owner_matching_answer_a()
    test_classify_owner_matching_answer_aaaa()
    test_classify_owner_matching_answer_ns()
    test_classify_owner_matching_answer_mx()
    test_classify_owner_matching_answer_txt()
    test_classify_owner_matching_answer_caa()
    test_classify_cname_alias()
    test_classify_referral_delegation()
    test_classify_malformed_or_unusable()

    print("\n-- Section 2: Evidence rules --")
    test_evidence_owner_matching_ns_creates_delegated_child_zone()
    test_evidence_owner_matching_soa_creates_zone_apex()
    test_evidence_owner_matching_a_creates_standard_record()
    test_evidence_owner_matching_aaaa_creates_standard_record()
    test_evidence_owner_matching_cname_creates_alias_evidence()
    test_evidence_owner_matching_mx_creates_standard_record()
    test_evidence_owner_matching_txt_creates_standard_record()
    test_evidence_owner_matching_caa_creates_standard_record()

    print("\n-- Section 3: No-finding rules --")
    test_no_finding_nxdomain_with_soa_authority()
    test_no_finding_servfail()
    test_no_finding_timeout()
    test_no_finding_noerror_empty_answer()
    test_no_finding_malformed()

    print("\n-- Section 4: False-positive regression fixtures --")
    test_false_positive_regression_unrelated_com_authority()
    test_false_positive_regression_nxdomain_path()
    test_false_positive_regression_servfail_path()

    print("\n-- Section 5: Known-good cases --")
    test_known_good_delegated_child_zone_via_answer_ns()
    test_known_good_ordinary_a_record()
    test_nodata_fail_closed_through_query_records()
    test_known_good_log_diagnostic_for_unrelated_authority()

    print("\n-- Section 6: Prior regression chain --")
    _run_regression(PROJECT_ROOT / "output" / "_ticket22_verify.py")

    print("\n=== Ticket 23 verification PASSED ===")


if __name__ == "__main__":
    main()
