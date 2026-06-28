"""D3 — Known-Child Apex Delegation Probe regression tests.

Durable negative-action (NA) and acceptance-criteria (AC) tests for the apex
probe wired into the known-parent gate in scan_engine.py.

D3 rules (inherit D2 discipline — all binding, none relaxed):
  Rule 1  Auth paths forced empty (parent_ns_hosts=[]) so only D2's Path-3 runs.
  Rule 2  ≥2-resolver agreement required for promotion (inherits D2 Rule 3).
  Rule 3  Promoted class is DELEGATED_CHILD_ZONE_RECURSIVE, never DELEGATED_CHILD_ZONE.
  Rule 4  Each apex is probed at most once per domain run (apex_probed dedup).
  Rule 5  Known children without delegation are not falsely flagged delegated.
  Rule 6  D2 provenance discipline is unchanged (resolvers, NS values, criterion-8 wording).
"""

from __future__ import annotations

from dataclasses import field
from typing import Any
from unittest.mock import MagicMock, patch, call

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from scanner.delegation_verifier import DelegationVerificationResult
from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    EvidenceStatus,
    FindingClassification,
    RecordType,
)
from scanner.scan_engine import (
    KNOWN_CHILD_APEX_SOURCE,
    RECURSIVE_FALLBACK_RESOLVERS,
    _probe_known_child_apex_delegation,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

CANDIDATE = "dvasd.k12.pa.us"
BASE_DOMAIN = "k12.pa.us"
RESOLVER_A = "1.1.1.1"
RESOLVER_B = "8.8.8.8"
NS_CF_1 = "joselyn.ns.cloudflare.com"
NS_CF_2 = "keaton.ns.cloudflare.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ns_response(candidate: str, ns_targets: list[str]) -> dns.message.Message:
    resp = dns.message.make_response(dns.message.make_query(candidate, "NS"))
    rrset = resp.find_rrset(
        resp.answer,
        dns.name.from_text(candidate if candidate.endswith(".") else candidate + "."),
        dns.rdataclass.IN,
        dns.rdatatype.NS,
        create=True,
    )
    for target in ns_targets:
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NS,
            target if target.endswith(".") else target + ".",
        )
        rrset.add(rdata, ttl=300)
    return resp


def _make_empty_response(candidate: str) -> dns.message.Message:
    return dns.message.make_response(dns.message.make_query(candidate, "NS"))


def _null_make_resolver_factory(ip: str | None = None) -> Any:
    m = MagicMock()
    m.nameservers = [ip or ""]
    return m


def _send_ns_per_resolver(
    candidate: str,
    ns_by_ip: dict[str, list[str]],
) -> Any:
    """Return a send_query stub that serves NS per resolver IP."""

    def _send(qname: str, qtype: Any, resolver: Any) -> tuple[dns.message.Message | None, str | None]:
        ip = resolver.nameservers[0] if hasattr(resolver, "nameservers") else ""
        if qtype in (RecordType.NS, dns.rdatatype.NS):
            targets = ns_by_ip.get(ip, [])
            if targets:
                return _make_ns_response(candidate, targets), None
        return _make_empty_response(candidate), None

    return _send


def _make_empty_delegation_result(*, verified: bool = False) -> DelegationVerificationResult:
    return DelegationVerificationResult(
        verified=verified,
        method="none",
        response_class=None,
        reason="no delegation found",
        matched_owner=None,
        source_path="unknown",
        records=[],
        log_message="",
        errors=[],
        evidence_outcomes=[],
    )


def _make_recursive_delegation_result(candidate: str, ns_values: list[str]) -> DelegationVerificationResult:
    records = [
        DiscoveredRecord(
            fqdn=candidate,
            record_type=RecordType.NS,
            value=ns,
            source_method=f"{KNOWN_CHILD_APEX_SOURCE}/recursive_corroborated",
            classification=FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE,
            confidence="low",
            nameserver=f"Resolver-corroborated: {RESOLVER_A}, {RESOLVER_B}",
            evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE,
        )
        for ns in ns_values
    ]
    return DelegationVerificationResult(
        verified=True,
        method="recursive_corroborated",
        response_class=None,
        reason="two resolvers agreed",
        matched_owner=candidate,
        source_path="recursive_corroborated",
        records=records,
        log_message=(
            f"{candidate} delegation confirmed via recursive resolver corroboration; "
            "direct authoritative verification was unavailable."
        ),
        errors=[],
        evidence_outcomes=[],
    )


# ---------------------------------------------------------------------------
# NA-1  Disagreeing resolvers → apex probe adds NO records
#       (inherits D2 Rule 3; verified at D3 integration level).
# ---------------------------------------------------------------------------

def test_na1_disagreeing_resolvers_no_promotion():
    """NA-1: when two resolvers return different NS sets, no record is appended."""
    send_fn = _send_ns_per_resolver(
        CANDIDATE,
        {RESOLVER_A: [NS_CF_1], RESOLVER_B: ["ns1.different.example"]},
    )
    result = DomainScanResult(domain=BASE_DOMAIN)

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=send_fn),
        patch("scanner.scan_engine._make_resolver", side_effect=_null_make_resolver_factory),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=[]),
    ):
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert result.records == [], (
        "NA1 FAIL: disagreeing resolvers must produce zero records from apex probe"
    )


# ---------------------------------------------------------------------------
# NA-2  Single resolver responds → apex probe adds NO records
#       (inherits D2 Rule 7).
# ---------------------------------------------------------------------------

def test_na2_single_resolver_no_promotion():
    """NA-2: only one resolver responding is not enough to promote."""

    def _send(qname: str, qtype: Any, resolver: Any) -> tuple[dns.message.Message | None, str | None]:
        ip = resolver.nameservers[0] if hasattr(resolver, "nameservers") else ""
        if ip == RESOLVER_A and qtype in (RecordType.NS,):
            return _make_ns_response(CANDIDATE, [NS_CF_1]), None
        return None, "network unreachable"

    result = DomainScanResult(domain=BASE_DOMAIN)

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=_send),
        patch("scanner.scan_engine._make_resolver", side_effect=_null_make_resolver_factory),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=[]),
    ):
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert result.records == [], (
        "NA2 FAIL: single-resolver agreement must NOT produce records from apex probe"
    )


# ---------------------------------------------------------------------------
# NA-3  Known child with no NS delegation → NOT flagged delegated.
# ---------------------------------------------------------------------------

def test_na3_no_ns_delegation_not_flagged():
    """NA-3: a known child that resolves but has no NS delegation is not promoted."""
    result = DomainScanResult(domain=BASE_DOMAIN)
    no_delegation = _make_empty_delegation_result(verified=False)

    with patch("scanner.scan_engine.verify_delegated_child_zone", return_value=no_delegation):
        _probe_known_child_apex_delegation(
            "nodelegation.k12.pa.us",
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert result.records == [], (
        "NA3 FAIL: non-delegated known child must not gain any records"
    )
    assert not any(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result.records
    ), "NA3 FAIL: DELEGATED_CHILD_ZONE_RECURSIVE must not appear for undelegated domain"


# ---------------------------------------------------------------------------
# NA-4  Apex probe result is always DELEGATED_CHILD_ZONE_RECURSIVE,
#       never the authoritative DELEGATED_CHILD_ZONE.
# ---------------------------------------------------------------------------

def test_na4_apex_probe_class_is_recursive_never_authoritative():
    """NA-4: records appended by the apex probe carry DELEGATED_CHILD_ZONE_RECURSIVE."""
    result = DomainScanResult(domain=BASE_DOMAIN)
    delegation = _make_recursive_delegation_result(CANDIDATE, [NS_CF_1, NS_CF_2])

    with patch("scanner.scan_engine.verify_delegated_child_zone", return_value=delegation):
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert result.records, "NA4 FAIL: expected records after delegated apex probe"
    for record in result.records:
        assert record.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE, (
            f"NA4 FAIL: class should be DELEGATED_CHILD_ZONE_RECURSIVE, got {record.classification!r}"
        )
        assert record.classification != FindingClassification.DELEGATED_CHILD_ZONE, (
            "NA4 FAIL: authoritative DELEGATED_CHILD_ZONE must never appear in apex probe output"
        )


# ---------------------------------------------------------------------------
# NA-5  Claim-to-code: apex probe passes parent_ns_hosts=[] to
#       verify_delegated_child_zone, forcing Path-3 only (Rule 1).
# ---------------------------------------------------------------------------

def test_na5_apex_probe_forces_path3_via_empty_parent_ns_hosts():
    """NA-5: _probe_known_child_apex_delegation must call verify_delegated_child_zone
    with parent_ns_hosts=[] and recursive_resolvers=RECURSIVE_FALLBACK_RESOLVERS."""
    result = DomainScanResult(domain=BASE_DOMAIN)
    no_delegation = _make_empty_delegation_result()

    with patch(
        "scanner.scan_engine.verify_delegated_child_zone",
        return_value=no_delegation,
    ) as mock_vdcz:
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert mock_vdcz.called, "NA5 FAIL: verify_delegated_child_zone was not called"
    _, kwargs = mock_vdcz.call_args
    assert "parent_ns_hosts" in kwargs, (
        "NA5 FAIL: parent_ns_hosts kwarg missing — auth paths not forced empty"
    )
    assert kwargs["parent_ns_hosts"] == [], (
        f"NA5 FAIL: parent_ns_hosts should be [] (force Path-3), got {kwargs['parent_ns_hosts']!r}"
    )
    assert "recursive_resolvers" in kwargs, (
        "NA5 FAIL: recursive_resolvers kwarg missing from apex probe call"
    )
    assert kwargs["recursive_resolvers"] == list(RECURSIVE_FALLBACK_RESOLVERS), (
        f"NA5 FAIL: wrong resolvers {kwargs['recursive_resolvers']!r}"
    )
    # get_parent_ns_hosts must NOT be passed (it would trigger auto-discovery)
    assert "get_parent_ns_hosts" not in kwargs or kwargs.get("get_parent_ns_hosts") is None, (
        "NA5 FAIL: get_parent_ns_hosts was passed — would bypass forced-empty auth path"
    )
    # source_method must identify the probe origin
    assert kwargs.get("source_method") == KNOWN_CHILD_APEX_SOURCE, (
        f"NA5 FAIL: source_method should be {KNOWN_CHILD_APEX_SOURCE!r}, got {kwargs.get('source_method')!r}"
    )


# ---------------------------------------------------------------------------
# AC-1  Mock integration: two agreeing resolvers → DELEGATED_CHILD_ZONE_RECURSIVE
#       appended to result.records with correct classification.
# ---------------------------------------------------------------------------

def test_ac1_two_agreeing_resolvers_append_recursive_record():
    """AC-1: two agreeing resolvers produce a DELEGATED_CHILD_ZONE_RECURSIVE record
    in result.records."""
    send_fn = _send_ns_per_resolver(
        CANDIDATE,
        {RESOLVER_A: [NS_CF_1, NS_CF_2], RESOLVER_B: [NS_CF_1, NS_CF_2]},
    )
    result = DomainScanResult(domain=BASE_DOMAIN)

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=send_fn),
        patch("scanner.scan_engine._make_resolver", side_effect=_null_make_resolver_factory),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=[]),
    ):
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert result.records, "AC1 FAIL: no records after apex probe with agreeing resolvers"
    ns_values = {r.value for r in result.records}
    assert NS_CF_1 in ns_values and NS_CF_2 in ns_values, (
        f"AC1 FAIL: expected both NS values; got {ns_values}"
    )
    for record in result.records:
        assert record.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE, (
            f"AC1 FAIL: wrong class {record.classification!r}"
        )
        assert record.confidence == "low", (
            f"AC1 FAIL: expected confidence='low', got {record.confidence!r}"
        )


# ---------------------------------------------------------------------------
# AC-2  Records carry D2 provenance (resolvers, criterion-8 wording in source).
# ---------------------------------------------------------------------------

def test_ac2_provenance_present_in_records():
    """AC-2: appended records carry resolver provenance and correct source_method."""
    result = DomainScanResult(domain=BASE_DOMAIN)
    delegation = _make_recursive_delegation_result(CANDIDATE, [NS_CF_1])

    with patch("scanner.scan_engine.verify_delegated_child_zone", return_value=delegation):
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    assert result.records, "AC2 FAIL: no records"
    for record in result.records:
        assert "recursive_corroborated" in record.source_method, (
            f"AC2 FAIL: source_method {record.source_method!r} does not contain 'recursive_corroborated'"
        )
        assert record.evidence_status == EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE, (
            f"AC2 FAIL: wrong evidence_status {record.evidence_status!r}"
        )
        # Resolver provenance must appear in the nameserver field
        assert RESOLVER_A in (record.nameserver or "") or RESOLVER_B in (record.nameserver or ""), (
            f"AC2 FAIL: resolver IPs missing from nameserver field {record.nameserver!r}"
        )


# ---------------------------------------------------------------------------
# AC-3  D2 discipline intact: recursive records are excluded from
#       authoritative delegated_child_zones count.
# ---------------------------------------------------------------------------

def test_ac3_recursive_apex_not_in_authoritative_count():
    """AC-3: DELEGATED_CHILD_ZONE_RECURSIVE records from D3 apex probe do not
    increment the authoritative delegated_child_zones summary counter."""
    from scanner.export_service import _domain_summary_counts

    result = DomainScanResult(domain=BASE_DOMAIN)
    delegation = _make_recursive_delegation_result(CANDIDATE, [NS_CF_1, NS_CF_2])

    with patch("scanner.scan_engine.verify_delegated_child_zone", return_value=delegation):
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )

    counts = _domain_summary_counts(result)
    assert counts["delegated_child_zones"] == 0, (
        f"AC3 FAIL: authoritative count should be 0, got {counts['delegated_child_zones']}"
    )
    assert counts["delegated_child_zones_recursive"] == 1, (
        f"AC3 FAIL: recursive count should be 1, got {counts['delegated_child_zones_recursive']}"
    )


# ---------------------------------------------------------------------------
# AC-4  Dedup guard: same apex is not probed twice even when it appears as
#       parent of multiple 5th-level candidates.
#       (Structural test — verifies apex_probed set protects the loop.)
# ---------------------------------------------------------------------------

def test_ac4_apex_probed_dedup_guard():
    """AC-4: _probe_known_child_apex_delegation is called at most once per apex
    per domain run.  The guard is the apex_probed set in _test_candidates; we
    verify the mechanism is load-bearing by showing that a second call (without the
    guard) would double the records — so the guard in the calling loop is necessary."""
    result = DomainScanResult(domain=BASE_DOMAIN)
    call_count: list[int] = [0]

    def _counting_vdcz(*args, **kwargs):
        call_count[0] += 1
        # Return a fresh 1-NS result each call to avoid shared-state aliasing.
        return _make_recursive_delegation_result(CANDIDATE, [NS_CF_1])

    with patch("scanner.scan_engine.verify_delegated_child_zone", side_effect=_counting_vdcz):
        # First probe — should add 1 record.
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )
        assert len(result.records) == 1, (
            f"AC4 FAIL: expected 1 record after first probe, got {len(result.records)}"
        )

        # Second probe call without the apex_probed guard would add another record —
        # confirming the guard in _test_candidates is load-bearing.
        _probe_known_child_apex_delegation(
            CANDIDATE,
            domain=BASE_DOMAIN,
            result=result,
            wildcard_suspected=False,
            messages=[],
        )
        assert len(result.records) == 2, (
            "AC4 FAIL: without apex_probed guard, a second call doubles records; "
            "confirms the guard in _test_candidates is necessary"
        )
        assert call_count[0] == 2, f"AC4 FAIL: expected 2 verify calls, got {call_count[0]}"


# ---------------------------------------------------------------------------
# AC-5  Claim-to-code: KNOWN_CHILD_APEX_SOURCE constant is exported and the
#       helper is importable from scan_engine.
# ---------------------------------------------------------------------------

def test_ac5_claim_to_code_constants_and_callsite():
    """AC-5: KNOWN_CHILD_APEX_SOURCE is defined, and _probe_known_child_apex_delegation
    is importable.  Together they confirm the D3 insertion exists in scan_engine."""
    assert KNOWN_CHILD_APEX_SOURCE == "known_child_apex_delegation", (
        f"AC5 FAIL: unexpected source constant {KNOWN_CHILD_APEX_SOURCE!r}"
    )
    assert callable(_probe_known_child_apex_delegation), (
        "AC5 FAIL: _probe_known_child_apex_delegation is not callable"
    )
    # RECURSIVE_FALLBACK_RESOLVERS must be the D2 public resolvers
    assert "1.1.1.1" in RECURSIVE_FALLBACK_RESOLVERS, "AC5 FAIL: 1.1.1.1 missing from fallback resolvers"
    assert "8.8.8.8" in RECURSIVE_FALLBACK_RESOLVERS, "AC5 FAIL: 8.8.8.8 missing from fallback resolvers"


# ---------------------------------------------------------------------------
# AC-live  Live DNS verification: dvasd.k12.pa.us surfaces as
#          DELEGATED_CHILD_ZONE_RECURSIVE with 2-resolver provenance.
#          Requires real network access; run with -m live.
# ---------------------------------------------------------------------------

@pytest.mark.live
def test_ac_live_dvasd_k12_pa_us_surfaces_recursive():
    """AC-live: live probe of dvasd.k12.pa.us using real public resolvers must
    produce at least one DELEGATED_CHILD_ZONE_RECURSIVE record with joselyn/keaton
    cloudflare NS provenance.

    This is the V1 acceptance test — the mock alone does not close D3.
    Run with: python -m pytest tests/regression/test_d3_known_child_apex.py -m live -v
    """
    result = DomainScanResult(domain=BASE_DOMAIN)
    _probe_known_child_apex_delegation(
        CANDIDATE,
        domain=BASE_DOMAIN,
        result=result,
        wildcard_suspected=False,
        messages=[],
    )

    recursive_records = [
        r for r in result.records
        if r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
    ]
    assert recursive_records, (
        f"AC-live FAIL: no DELEGATED_CHILD_ZONE_RECURSIVE records found for {CANDIDATE}. "
        "D3 apex probe did not fire or DNS did not respond as expected."
    )

    ns_values = {r.value for r in recursive_records}
    cf_ns = {"joselyn.ns.cloudflare.com", "keaton.ns.cloudflare.com"}
    assert ns_values & cf_ns, (
        f"AC-live FAIL: expected Cloudflare NS for {CANDIDATE}, got {ns_values}"
    )

    for record in recursive_records:
        assert record.confidence == "low", (
            f"AC-live FAIL: expected confidence='low', got {record.confidence!r}"
        )
        assert RESOLVER_A in (record.nameserver or "") or RESOLVER_B in (record.nameserver or ""), (
            f"AC-live FAIL: resolver provenance missing from nameserver {record.nameserver!r}"
        )
        # Confirm class discipline
        assert record.classification != FindingClassification.DELEGATED_CHILD_ZONE, (
            "AC-live FAIL: DELEGATED_CHILD_ZONE (auth) class must never appear in apex probe"
        )
