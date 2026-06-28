#!/usr/bin/env python3
"""Ticket 25 verification: evidence status model for DNS findings.

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

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.regression._chain import run_durable_regression
from tests.regression._paths import REGRESSION_DIR, REPO_ROOT

from scanner.delegation_verifier import verify_delegated_child_zone
from scanner.evidence_status import (
    is_confirmed_evidence_status,
    resolve_evidence_status,
)
from scanner.export_service import CSV_COLUMNS, build_csv_rows, build_json_document
from scanner.models import (
    DiscoveredRecord,
    DomainInputRecord,
    DomainScanResult,
    EvidenceOutcome,
    EvidenceStatus,
    FindingClassification,
    ParentGatingConfidence,
    ParentGatingDecision,
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


def _fake_resolve(_host: str) -> list[str]:
    return ["127.0.0.1"]


def _mock_run(domain_result: DomainScanResult) -> ScanRunResult:
    return ScanRunResult(
        input=ScanInput(
            domain_file_path=Path("fake.csv"),
            options=ScanOptions(scan_profile=ScanProfile.NORMAL),
            output_dir=Path("."),
            wordlists_dir=get_wordlists_dir(),
        ),
        domain_inputs=[domain_result.input_record] if domain_result.input_record else [],
        domain_results=[domain_result],
        scan_timestamp=datetime(2026, 6, 26, 18, 0, 0),
        finished_at=datetime(2026, 6, 26, 18, 5, 0),
        scan_status=ScanStatus.COMPLETED,
    )


def _confirmed_statuses(records: list[DiscoveredRecord], base: str = BASE) -> set[EvidenceStatus]:
    return {
        resolve_evidence_status(record, base)
        for record in records
        if is_confirmed_evidence_status(resolve_evidence_status(record, base))
    }


# ---------------------------------------------------------------------------
# Confirmed evidence statuses
# ---------------------------------------------------------------------------


def test_ordinary_a_confirmed_status() -> None:
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
    assert resolve_evidence_status(findings[0], BASE) == EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME
    print("status: owner-matching A -> CONFIRMED_ORDINARY_DNS_NAME: OK")


def test_ordinary_cname_mx_txt_confirmed_status() -> None:
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
        assert findings, fqdn
        assert resolve_evidence_status(findings[0], BASE) == EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME
    print("status: CNAME/MX/TXT -> CONFIRMED_ORDINARY_DNS_NAME: OK")


def test_delegated_child_zone_confirmed_status() -> None:
    candidate = "api.ci.lawrence.ma.us"

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_answer_ns(r, fqdn, "ns1.child.example.")
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    result = verify_delegated_child_zone(
        candidate,
        base_domain=BASE,
        send_query=fake_send,
        resolve_ns_ips=_fake_resolve,
        make_resolver=_make_resolver,
        parent_ns_hosts=PARENT_NS,
    )
    assert result.verified
    assert result.records
    for record in result.records:
        status = resolve_evidence_status(record, BASE)
        assert status == EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE, status
    print("status: verified delegation -> CONFIRMED_DELEGATED_CHILD_ZONE: OK")


def test_known_base_domain_validated_status() -> None:
    record = DiscoveredRecord(
        fqdn=BASE,
        record_type=RecordType.A,
        value="198.51.100.1",
        source_method="recursive_resolver",
        classification=FindingClassification.BASE_DOMAIN_RECORD,
    )
    assert resolve_evidence_status(record, BASE) == EvidenceStatus.KNOWN_DOMAIN_VALIDATED

    soa = DiscoveredRecord(
        fqdn=BASE,
        record_type=RecordType.SOA,
        value=REAL_SOA_RDATA,
        source_method="recursive_resolver",
        classification=FindingClassification.BASE_ZONE_EXISTS,
    )
    assert resolve_evidence_status(soa, BASE) == EvidenceStatus.KNOWN_DOMAIN_VALIDATED
    print("status: base domain validation -> KNOWN_DOMAIN_VALIDATED: OK")


# ---------------------------------------------------------------------------
# Diagnostic evidence statuses
# ---------------------------------------------------------------------------


def test_parent_gating_skipped_status() -> None:
    base = BASE
    parent = "co.ci.lawrence.ma.us"
    fifth = f"portal.{parent}"
    parent_decisions = {
        parent: ParentGatingDecision(
            allow_descendants=False,
            parent_name=parent,
            reason="Parent returned NXDOMAIN",
            evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
            response_class="negative_nxdomain",
            confidence=ParentGatingConfidence.CONFIDENT_NEGATIVE,
            diagnostic_message=(
                f"Skipped deeper candidates because parent validation returned NXDOMAIN for {parent}."
            ),
        )
    }
    domain_result = DomainScanResult(domain=base)
    messages: list[str] = []

    def fake_send(*_args, **_kwargs):
        raise AssertionError("Skipped candidate must not be queried")

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        with patch("scanner.scan_engine.verify_delegated_child_zone") as mock_verify:
            _test_candidates(
                candidates=[fifth],
                domain=base,
                resolver=_make_resolver(),
                result=domain_result,
                wildcard_suspected=False,
                progress=None,
                messages=messages,
                cancel_check=None,
                progress_update=None,
                domain_index=1,
                domain_total=1,
                domains_completed=0,
                started_at=datetime.now(),
                phase=ScanPhase.TESTING_FIFTH_LEVEL,
                candidates_offset=0,
                candidates_total=1,
                validate_fifth_level_parents=True,
                parent_passed=set(),
                parent_decisions=parent_decisions,
            )
            mock_verify.assert_not_called()

    assert domain_result.evidence_outcomes
    assert domain_result.evidence_outcomes[0].evidence_status == EvidenceStatus.SKIPPED_BY_PARENT_GATING
    assert not _confirmed_statuses(domain_result.records)
    print("status: parent-gated skip -> SKIPPED_BY_PARENT_GATING: OK")


def test_inconclusive_servfail_timeout_status() -> None:
    candidate = "timeout.ci.lawrence.ma.us"
    outcomes: list[EvidenceOutcome] = []

    def fake_timeout(fqdn, record_type, resolver):
        return None, f"{fqdn} {record_type.value}: timeout"

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_timeout):
        _, errors = _query_records(
            candidate,
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
            evidence_outcomes=outcomes,
        )
    assert errors

    def fake_servfail(fqdn, record_type, resolver):
        return _make_response(fqdn, record_type.value, dns.rcode.SERVFAIL), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_servfail):
        findings, errors = _query_records(
            candidate,
            (RecordType.A,),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )
    assert not findings
    assert errors

    error_record = DiscoveredRecord(
        fqdn=candidate,
        record_type=None,
        value=errors[0],
        source_method="recursive_resolver",
        classification=FindingClassification.QUERY_ERROR,
        evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
    )
    assert resolve_evidence_status(error_record, BASE) == EvidenceStatus.INCONCLUSIVE_DNS_FAILURE
    assert not is_confirmed_evidence_status(resolve_evidence_status(error_record, BASE))
    print("status: timeout/SERVFAIL -> INCONCLUSIVE_DNS_FAILURE: OK")


def test_ignored_unrelated_authority_status() -> None:
    candidate = "webmail.ci.lawrence.ma.us"
    outcomes: list[EvidenceOutcome] = []
    log_sink: list[str] = []

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        findings, _ = _query_records(
            candidate,
            (RecordType.A, RecordType.NS),
            _make_resolver(),
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
            log_sink=log_sink,
            evidence_outcomes=outcomes,
        )
    assert not findings
    assert outcomes
    assert outcomes[0].evidence_status == EvidenceStatus.IGNORED_UNRELATED_AUTHORITY

    verify_result = verify_delegated_child_zone(
        candidate,
        base_domain=BASE,
        send_query=fake_send,
        resolve_ns_ips=_fake_resolve,
        make_resolver=_make_resolver,
        parent_ns_hosts=PARENT_NS,
    )
    assert not verify_result.verified
    assert verify_result.evidence_outcomes
    assert any(
        item.evidence_status == EvidenceStatus.IGNORED_UNRELATED_AUTHORITY
        for item in verify_result.evidence_outcomes
    )
    print("status: unrelated authority -> IGNORED_UNRELATED_AUTHORITY: OK")


# ---------------------------------------------------------------------------
# False-positive candidates must not be confirmed
# ---------------------------------------------------------------------------


def test_false_positive_candidates_not_confirmed() -> None:
    for candidate in FP_CANDIDATES:

        def fake_send(fqdn, record_type, resolver, *, _candidate=candidate):
            if record_type == RecordType.NS:
                r = _make_response(fqdn, "NS")
                _add_authority_soa(r, "com.", COM_SOA_RDATA)
                return r, None
            return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

        delegation = verify_delegated_child_zone(
            candidate,
            base_domain=BASE,
            send_query=fake_send,
            resolve_ns_ips=_fake_resolve,
            make_resolver=_make_resolver,
            parent_ns_hosts=PARENT_NS,
        )
        assert not delegation.verified
        assert not _confirmed_statuses(delegation.records)

        with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
            findings, _ = _query_records(
                candidate,
                (RecordType.A, RecordType.NS),
                _make_resolver(),
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=BASE,
            )
        assert not _confirmed_statuses(findings)
    print("negative: false-positive candidates not confirmed: OK")


def test_negative_ignored_does_not_promote_finding() -> None:
    # 29A: the delegation walk only runs when the cheap record sweep produces a
    # ZONE_SOA_DISCOVERED signal.  This candidate's mock returns NXDOMAIN for
    # all CANDIDATE_RECORD_TYPES (SOA/A/AAAA/MX/TXT/CNAME) — no signal — so the
    # delegation walk is skipped and IGNORED_UNRELATED_AUTHORITY is not produced.
    # The primary invariant (no confirmed finding) is still enforced.
    candidate = "smtp.ci.lawrence.ma.us"
    domain_result = DomainScanResult(domain=BASE)

    def fake_send(fqdn, record_type, resolver):
        if record_type == RecordType.NS:
            r = _make_response(fqdn, "NS")
            _add_authority_soa(r, "com.", COM_SOA_RDATA)
            return r, None
        return _make_response(fqdn, record_type.value, dns.rcode.NXDOMAIN), None

    with patch("scanner.scan_engine._send_dns_query", side_effect=fake_send):
        with patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]):
            with patch("scanner.scan_engine._get_parent_ns_hosts", return_value=PARENT_NS):
                _test_candidates(
                    candidates=[candidate],
                    domain=BASE,
                    resolver=_make_resolver(),
                    result=domain_result,
                    wildcard_suspected=False,
                    progress=None,
                    messages=[],
                    cancel_check=None,
                    progress_update=None,
                    domain_index=1,
                    domain_total=1,
                    domains_completed=0,
                    started_at=datetime.now(),
                    phase=ScanPhase.TESTING_FOURTH_LEVEL,
                    candidates_offset=0,
                    candidates_total=1,
                )

    # Primary invariant: unrelated authority must never produce a confirmed finding.
    assert not any(
        record.classification == FindingClassification.DELEGATED_CHILD_ZONE
        for record in domain_result.records
    )
    assert not _confirmed_statuses(domain_result.records)
    # 29A: IGNORED_UNRELATED_AUTHORITY is produced by verify_delegated_child_zone
    # (parent NS path), which the signal gate skips for no-signal candidates.
    # The diagnostic is absent here because the walk did not run — correct behavior.
    print("negative: ignored authority does not promote finding: OK")


# ---------------------------------------------------------------------------
# Export evidence_status
# ---------------------------------------------------------------------------


def test_export_csv_json_evidence_status() -> None:
    domain_result = DomainScanResult(
        domain=BASE,
        records=[
            DiscoveredRecord(
                fqdn="portal.ci.lawrence.ma.us",
                record_type=RecordType.A,
                value="192.0.2.1",
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
            ),
            DiscoveredRecord(
                fqdn=BASE,
                record_type=RecordType.A,
                value="198.51.100.2",
                source_method="recursive_resolver",
                classification=FindingClassification.BASE_DOMAIN_RECORD,
            ),
        ],
        evidence_outcomes=[
            EvidenceOutcome(
                fqdn="skip.co.ci.lawrence.ma.us",
                evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
                source_method="generated_candidate",
                detail="Skipped: parent ci.lawrence.ma.us did not validate",
            ),
        ],
    )
    run = _mock_run(domain_result)
    rows = build_csv_rows(run)
    assert "evidence_status" in CSV_COLUMNS
    assert CSV_COLUMNS.index("evidence_status") == CSV_COLUMNS.index("finding_type") + 1

    confirmed_rows = [r for r in rows if r["evidence_status"] == "CONFIRMED_ORDINARY_DNS_NAME"]
    assert confirmed_rows
    known_rows = [r for r in rows if r["evidence_status"] == "KNOWN_DOMAIN_VALIDATED"]
    assert known_rows
    skipped_rows = [r for r in rows if r["evidence_status"] == "SKIPPED_BY_PARENT_GATING"]
    assert skipped_rows
    assert skipped_rows[0]["finding_type"] == ""
    assert skipped_rows[0]["name_type"] == "diagnostic"
    assert skipped_rows[0]["discovered_name"] == ""
    assert skipped_rows[0]["tested_name"] == "skip.co.ci.lawrence.ma.us"

    document = build_json_document(run)
    domain = document["domains"][0]
    assert any(item.get("evidence_status") == "CONFIRMED_ORDINARY_DNS_NAME" for item in domain["findings"])
    assert any(
        item.get("evidence_status") == "SKIPPED_BY_PARENT_GATING"
        for item in domain["evidence_diagnostics"]
    )
    print("export: CSV/JSON evidence_status present and labeled: OK")


def test_export_inconclusive_not_confirmed() -> None:
    candidate = "fail.ci.lawrence.ma.us"
    domain_result = DomainScanResult(
        domain=BASE,
        evidence_outcomes=[
            EvidenceOutcome(
                fqdn=candidate,
                evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
                source_method="generated_candidate",
                detail=f"{candidate} A: SERVFAIL",
            )
        ],
    )
    rows = build_csv_rows(_mock_run(domain_result))
    inconclusive = [r for r in rows if r["tested_name"] == candidate]
    assert inconclusive
    assert inconclusive[0]["evidence_status"] == "INCONCLUSIVE_DNS_FAILURE"
    assert inconclusive[0]["finding_type"] == ""
    assert inconclusive[0]["name_type"] == "diagnostic"
    print("export: inconclusive row not labeled confirmed: OK")


# ---------------------------------------------------------------------------
# Regression chain
# ---------------------------------------------------------------------------


def _run_ticket24_regression() -> None:
    script = REGRESSION_DIR / "test_ticket24_delegation_verification.py"
    print(f"\n--- Chaining Ticket 24 regression: {script.name} ---")
    run_durable_regression(script)


def main() -> None:
    print("Ticket 25 evidence status model verification")
    print(f"Repo: {REPO_ROOT}")
    test_ordinary_a_confirmed_status()
    test_ordinary_cname_mx_txt_confirmed_status()
    test_delegated_child_zone_confirmed_status()
    test_known_base_domain_validated_status()
    test_parent_gating_skipped_status()
    test_inconclusive_servfail_timeout_status()
    test_ignored_unrelated_authority_status()
    test_false_positive_candidates_not_confirmed()
    test_negative_ignored_does_not_promote_finding()
    test_export_csv_json_evidence_status()
    test_export_inconclusive_not_confirmed()
    _run_ticket24_regression()
    print("\nTicket 25 evidence status model verification: ALL OK")


if __name__ == "__main__":
    main()
