"""D2 — Recursive Delegation Fallback regression tests.

Durable negative-action (NA) tests are the load-bearing spine.  Every test
follows the locked rules from the owner spec:

  Rule 1  Fallback fires ONLY when auth paths fail — never alongside success.
  Rule 2  Query ≥2 configured recursive resolvers.
  Rule 3  Promote only when ≥2 resolvers agree on the NS set.
  Rule 4  Store which resolvers answered + NS values + verification_method.
  Rule 5  Mark finding resolver-derived / lower-confidence (not authoritative).
  Rule 6  Recursive evidence NEVER satisfies authoritative assertions.
  Rule 7  Single resolver does NOT promote (default config).
  Rule 8  Report wording: "Delegation evidence was corroborated through recursive
          resolvers; direct authoritative verification was unavailable."
  Rule 9  Auth path (Path 1/2) stays highest-confidence when reachable.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import patch, MagicMock

import dns.message
import dns.rdatatype
import pytest

from scanner.delegation_verifier import (
    DelegationVerificationResult,
    verify_delegated_child_zone,
)
from scanner.evidence_status import (
    is_confirmed_evidence_status,
    is_recursive_delegation_status,
    resolve_evidence_status,
)
from scanner.export_service import RECURSIVE_DELEGATION_WORDING, _collect_dns_discovered_children
from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    EvidenceStatus,
    FindingClassification,
    RecordType,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CANDIDATE = "dvasd.k12.pa.us"
BASE_DOMAIN = "k12.pa.us"
RESOLVER_A = "1.1.1.1"
RESOLVER_B = "8.8.8.8"
NS_CLOUDFLARE_1 = "joselyn.ns.cloudflare.com"
NS_CLOUDFLARE_2 = "keaton.ns.cloudflare.com"


def _make_ns_response(candidate: str, ns_targets: list[str]) -> dns.message.Message:
    """Build a minimal DNS NS response carrying *ns_targets* in the answer."""
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
            dns.rdataclass.IN, dns.rdatatype.NS,
            target if target.endswith(".") else target + "."
        )
        rrset.add(rdata, ttl=300)
    return resp


def _make_empty_response(candidate: str) -> dns.message.Message:
    """Return a NOERROR response with no records."""
    return dns.message.make_response(dns.message.make_query(candidate, "NS"))


def _null_resolve_ns_ips(_host: str) -> list[str]:
    return []


def _null_make_resolver(ip: str | None) -> Any:
    m = MagicMock()
    m.nameservers = [ip or ""]
    return m


def _send_unreachable(_qname: str, _qtype: Any, _resolver: Any) -> tuple[None, str]:
    """Simulates network-unreachable auth queries."""
    return None, "network unreachable"


def _send_ns_from_resolver(
    candidate: str,
    ns_targets_by_ip: dict[str, list[str]],
) -> Any:
    """Factory: returns a send_query that serves NS answers per resolver IP."""

    def _send(qname: str, qtype: Any, resolver: Any) -> tuple[dns.message.Message | None, str | None]:
        ip = resolver.nameservers[0] if hasattr(resolver, "nameservers") else ""
        if qtype in (RecordType.NS, dns.rdatatype.NS):
            targets = ns_targets_by_ip.get(ip, [])
            if targets:
                return _make_ns_response(candidate, targets), None
        return _make_empty_response(candidate), None

    return _send


# ---------------------------------------------------------------------------
# NA-1  Recursive ≠ authoritative: recursive-derived findings must never
#       be emitted as DELEGATED_CHILD_ZONE (high-confidence).
#       This is Rule 6 — the load-bearing test.
# ---------------------------------------------------------------------------

def test_na1_recursive_never_emits_delegated_child_zone():
    """Rule 6: DELEGATED_CHILD_ZONE_RECURSIVE must never be DELEGATED_CHILD_ZONE."""
    send_fn = _send_ns_from_resolver(
        CANDIDATE,
        {RESOLVER_A: [NS_CLOUDFLARE_1, NS_CLOUDFLARE_2],
         RESOLVER_B: [NS_CLOUDFLARE_1, NS_CLOUDFLARE_2]},
    )

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    # Must be resolver-corroborated, NOT authoritative high-confidence.
    for record in result.records:
        assert record.classification != FindingClassification.DELEGATED_CHILD_ZONE, (
            "NA1 FAIL: a recursive record was emitted as DELEGATED_CHILD_ZONE (auth class)"
        )
        assert record.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE, (
            f"NA1 FAIL: unexpected classification {record.classification!r}"
        )

    # The verification result must not be flagged as an authoritative path.
    assert result.method == "recursive_corroborated", (
        f"NA1 FAIL: result.method should be 'recursive_corroborated', got {result.method!r}"
    )
    assert result.source_path == "recursive_corroborated", (
        f"NA1 FAIL: result.source_path should be 'recursive_corroborated', got {result.source_path!r}"
    )

    # Resolved evidence status must NOT be CONFIRMED_DELEGATED_CHILD_ZONE.
    for record in result.records:
        status = resolve_evidence_status(record)
        assert status != EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE, (
            "NA1 FAIL: recursive finding resolved to CONFIRMED_DELEGATED_CHILD_ZONE (auth status)"
        )
        assert status == EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE, (
            f"NA1 FAIL: expected CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE, got {status!r}"
        )

    # is_confirmed_evidence_status must return False for recursive findings.
    for record in result.records:
        status = resolve_evidence_status(record)
        assert not is_confirmed_evidence_status(status), (
            "NA1 FAIL: is_confirmed_evidence_status returned True for a recursive finding"
        )
        assert is_recursive_delegation_status(status), (
            "NA1 FAIL: is_recursive_delegation_status returned False for a recursive finding"
        )


# ---------------------------------------------------------------------------
# NA-2  Single-resolver no-promote: one resolver returns NS, the other
#       errors → no promotion (default config, Rule 7).
# ---------------------------------------------------------------------------

def test_na2_single_resolver_does_not_promote():
    """Rule 7: single responding resolver must not promote."""

    def _send(qname: str, qtype: Any, resolver: Any) -> tuple[dns.message.Message | None, str | None]:
        ip = resolver.nameservers[0] if hasattr(resolver, "nameservers") else ""
        if ip == RESOLVER_A and qtype in (RecordType.NS,):
            return _make_ns_response(CANDIDATE, [NS_CLOUDFLARE_1]), None
        # RESOLVER_B returns empty / unreachable
        return None, "network unreachable"

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=_send,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is False, "NA2 FAIL: single-resolver agreement must NOT promote"
    assert not result.records or all(
        r.classification != FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result.records
    ), "NA2 FAIL: DELEGATED_CHILD_ZONE_RECURSIVE emitted with only one responding resolver"


# ---------------------------------------------------------------------------
# NA-3  Disagreement no-promote: two resolvers return *different* NS sets
#       → no promotion (Rule 3).
# ---------------------------------------------------------------------------

def test_na3_disagreeing_resolvers_do_not_promote():
    """Rule 3: resolvers with different NS sets must not promote."""
    send_fn = _send_ns_from_resolver(
        CANDIDATE,
        {
            RESOLVER_A: [NS_CLOUDFLARE_1],       # different NS sets
            RESOLVER_B: ["ns1.different.example"],
        },
    )

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is False, "NA3 FAIL: disagreeing resolvers must NOT promote"
    assert not any(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result.records
    ), "NA3 FAIL: DELEGATED_CHILD_ZONE_RECURSIVE emitted with disagreeing resolvers"


# ---------------------------------------------------------------------------
# NA-4  Auth-preferred: when direct-auth succeeds, the recursive path is
#       NOT invoked and the class stays DELEGATED_CHILD_ZONE (Rule 1 / Rule 9).
# ---------------------------------------------------------------------------

def test_na4_auth_path_preferred_when_reachable():
    """Rules 1 & 9: when auth verification succeeds, result is DELEGATED_CHILD_ZONE."""
    ns_host = "ns1.k12.pa.us"
    ns_ip = "192.0.2.1"

    # auth query: returns NS RRset owned by CANDIDATE
    def _send_auth(qname: str, qtype: Any, resolver: Any) -> tuple[dns.message.Message | None, str | None]:
        ip = resolver.nameservers[0] if hasattr(resolver, "nameservers") else ""
        if ip == ns_ip and qtype in (RecordType.NS,):
            return _make_ns_response(CANDIDATE, [NS_CLOUDFLARE_1]), None
        return None, "network unreachable"

    def _resolve_ns_ips(host: str) -> list[str]:
        return [ns_ip] if host == ns_host else []

    recursive_called: list[bool] = []

    # Wrap verify and track whether recursive path was entered by checking result method.
    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=_send_auth,
        resolve_ns_ips=_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        parent_ns_hosts=[ns_host],
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is True, "NA4 FAIL: auth path should succeed"
    assert result.method == "parent_authoritative_ns", (
        f"NA4 FAIL: expected parent_authoritative_ns, got {result.method!r}"
    )
    for record in result.records:
        assert record.classification == FindingClassification.DELEGATED_CHILD_ZONE, (
            f"NA4 FAIL: auth-verified finding has wrong class {record.classification!r}"
        )
    # No recursive records must be present.
    assert not any(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result.records
    ), "NA4 FAIL: recursive classification appeared in an auth-verified result"


# ---------------------------------------------------------------------------
# NA-5  Provenance present: promoted recursive findings carry resolvers +
#       NS values + source_method + verification method (Rule 4).
# ---------------------------------------------------------------------------

def test_na5_provenance_fields_populated():
    """Rule 4: promoted recursive findings must carry full provenance."""
    agreed_ns = sorted([NS_CLOUDFLARE_1, NS_CLOUDFLARE_2])
    send_fn = _send_ns_from_resolver(
        CANDIDATE,
        {RESOLVER_A: agreed_ns, RESOLVER_B: agreed_ns},
    )

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is True, "NA5 FAIL: two-resolver agreement should promote"
    assert result.records, "NA5 FAIL: no records in result"

    for record in result.records:
        # nameserver field must mention both resolvers
        assert RESOLVER_A in (record.nameserver or ""), (
            f"NA5 FAIL: {RESOLVER_A} not in nameserver provenance {record.nameserver!r}"
        )
        assert RESOLVER_B in (record.nameserver or ""), (
            f"NA5 FAIL: {RESOLVER_B} not in nameserver provenance {record.nameserver!r}"
        )
        # source_method must indicate recursive_corroborated
        assert "recursive_corroborated" in record.source_method, (
            f"NA5 FAIL: source_method {record.source_method!r} does not indicate recursive"
        )
        # NS values must be present
        assert record.value in (NS_CLOUDFLARE_1, NS_CLOUDFLARE_2), (
            f"NA5 FAIL: unexpected NS value {record.value!r}"
        )
        # confidence must be 'low' (lower than high/normal for auth)
        assert record.confidence == "low", (
            f"NA5 FAIL: expected confidence='low', got {record.confidence!r}"
        )
        # evidence_trace must carry the promotion reason
        assert record.evidence_trace, "NA5 FAIL: evidence_trace is empty"
        trace = record.evidence_trace[0]
        assert trace.promotion_reason and "recursive" in trace.promotion_reason.lower(), (
            f"NA5 FAIL: promotion_reason missing 'recursive': {trace.promotion_reason!r}"
        )

    # result.method and source_path
    assert result.method == "recursive_corroborated"
    assert result.source_path == "recursive_corroborated"


# ---------------------------------------------------------------------------
# AC-1  Two agreeing resolvers → DELEGATED_CHILD_ZONE_RECURSIVE promoted
#       with criterion-8 wording (Rules 3, 5, 8).
# ---------------------------------------------------------------------------

def test_ac1_two_agreeing_resolvers_promote_recursive():
    """AC-1: agreement → DELEGATED_CHILD_ZONE_RECURSIVE + criterion-8 wording."""
    agreed_ns = [NS_CLOUDFLARE_1, NS_CLOUDFLARE_2]
    send_fn = _send_ns_from_resolver(
        CANDIDATE,
        {RESOLVER_A: agreed_ns, RESOLVER_B: agreed_ns},
    )

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is True, "AC1 FAIL: agreement should promote"
    assert result.records, "AC1 FAIL: no records produced"

    ns_values = {r.value for r in result.records}
    assert NS_CLOUDFLARE_1 in ns_values and NS_CLOUDFLARE_2 in ns_values, (
        f"AC1 FAIL: expected both CF NS in result, got {ns_values}"
    )

    # Criterion-8 wording must appear in log_message
    assert "recursive" in result.log_message.lower(), (
        f"AC1 FAIL: criterion-8 wording absent in log_message: {result.log_message!r}"
    )
    assert "direct authoritative verification was unavailable" in result.log_message.lower(), (
        f"AC1 FAIL: criterion-8 wording absent in log_message: {result.log_message!r}"
    )


# ---------------------------------------------------------------------------
# AC-2  No recursive_resolvers configured → fallback is skipped entirely.
# ---------------------------------------------------------------------------

def test_ac2_fallback_skipped_when_no_resolvers_configured():
    """When recursive_resolvers=[] or not provided, fallback must not fire."""
    agreed_ns = [NS_CLOUDFLARE_1]
    send_fn = _send_ns_from_resolver(CANDIDATE, {RESOLVER_A: agreed_ns, RESOLVER_B: agreed_ns})

    result_no_config = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        # recursive_resolvers NOT passed
    )

    assert result_no_config.verified is False, "AC2 FAIL: without recursive_resolvers, must not promote"
    assert not any(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result_no_config.records
    ), "AC2 FAIL: DELEGATED_CHILD_ZONE_RECURSIVE emitted without recursive_resolvers"


# ---------------------------------------------------------------------------
# AC-3  Export: recursive findings visible and distinct, never in
#       authoritative delegated count.
# ---------------------------------------------------------------------------

def test_ac3_export_recursive_distinct_from_authoritative():
    """AC-3: recursive findings in export have distinct finding_type and
    are never summed into the delegated_child_zones authoritative count."""
    from scanner.export_service import _domain_summary_counts

    auth_record = DiscoveredRecord(
        fqdn=CANDIDATE,
        record_type=RecordType.NS,
        value=NS_CLOUDFLARE_1,
        source_method="generated_candidate/parent_authoritative",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
        confidence="high",
        nameserver="ns1.k12.pa.us",
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
    )
    recursive_record = DiscoveredRecord(
        fqdn="other.k12.pa.us",
        record_type=RecordType.NS,
        value=NS_CLOUDFLARE_2,
        source_method="generated_candidate/recursive_corroborated",
        classification=FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE,
        confidence="low",
        nameserver=f"Resolver-corroborated: {RESOLVER_A}, {RESOLVER_B}",
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE,
    )

    domain_result = DomainScanResult(domain=BASE_DOMAIN)
    domain_result.records = [auth_record, recursive_record]

    counts = _domain_summary_counts(domain_result)

    assert counts["delegated_child_zones"] == 1, (
        f"AC3 FAIL: auth delegated count should be 1, got {counts['delegated_child_zones']}"
    )
    assert counts["delegated_child_zones_recursive"] == 1, (
        f"AC3 FAIL: recursive delegated count should be 1, got {counts['delegated_child_zones_recursive']}"
    )


# ---------------------------------------------------------------------------
# AC-4  _collect_dns_discovered_children separates auth from recursive.
# ---------------------------------------------------------------------------

def test_ac4_collect_children_separates_auth_and_recursive():
    """AC-4: _collect_dns_discovered_children returns separate sets."""
    auth_rec = DiscoveredRecord(
        fqdn=CANDIDATE,
        record_type=RecordType.NS,
        value=NS_CLOUDFLARE_1,
        source_method="generated_candidate/parent_authoritative",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
        confidence="high",
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
    )
    recursive_rec = DiscoveredRecord(
        fqdn="other.k12.pa.us",
        record_type=RecordType.NS,
        value=NS_CLOUDFLARE_2,
        source_method="generated_candidate/recursive_corroborated",
        classification=FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE,
        confidence="low",
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE,
    )
    domain_result = DomainScanResult(domain=BASE_DOMAIN)
    domain_result.records = [auth_rec, recursive_rec]

    child_names, delegated_auth, delegated_recursive, base_only = _collect_dns_discovered_children(
        domain_result
    )

    assert CANDIDATE in child_names, "AC4 FAIL: auth candidate missing from child_names"
    assert "other.k12.pa.us" in child_names, "AC4 FAIL: recursive child missing from child_names"
    assert CANDIDATE in delegated_auth, "AC4 FAIL: auth candidate missing from delegated_auth"
    assert "other.k12.pa.us" not in delegated_auth, (
        "AC4 FAIL: recursive child must NOT be in authoritative delegated set"
    )
    assert "other.k12.pa.us" in delegated_recursive, (
        "AC4 FAIL: recursive child missing from delegated_recursive"
    )
    assert CANDIDATE not in delegated_recursive, (
        "AC4 FAIL: auth child must NOT be in recursive delegated set"
    )


# ---------------------------------------------------------------------------
# AC-5  Criterion-8 wording is present in RECURSIVE_DELEGATION_WORDING.
# ---------------------------------------------------------------------------

def test_ac5_criterion8_wording_constant():
    """AC-5: the constant carries the exact criterion-8 wording."""
    assert "recursive resolvers" in RECURSIVE_DELEGATION_WORDING.lower()
    assert "direct authoritative verification was unavailable" in RECURSIVE_DELEGATION_WORDING.lower()


# ---------------------------------------------------------------------------
# AC-6  Fallback trigger line and agreement gate: cite-to-code.
# ---------------------------------------------------------------------------

def test_ac6_claim_to_code_trigger_location():
    """AC-6: the fallback is triggered in delegation_verifier._verify_via_recursive_fallback
    and the agreement gate is the frozenset equality check inside that function.

    Verify the trigger by confirming the function is callable and that with only
    one resolver it returns None (pre-agreement gate) rather than a result.
    """
    from scanner.delegation_verifier import _verify_via_recursive_fallback

    # Single resolver → should return None (insufficient)
    result = _verify_via_recursive_fallback(
        CANDIDATE,
        recursive_resolvers=[RESOLVER_A],   # only one → must fail
        send_query=_send_ns_from_resolver(CANDIDATE, {RESOLVER_A: [NS_CLOUDFLARE_1]}),
        make_resolver=_null_make_resolver,
        source_method="generated_candidate",
        log_sink=None,
        errors=[],
        evidence_outcomes=[],
    )
    assert result is None, (
        "AC6 FAIL: single resolver must return None (agreement gate not reached)"
    )

    # Two agreeing resolvers → should return a valid result
    agreed_ns = [NS_CLOUDFLARE_1]
    result_ok = _verify_via_recursive_fallback(
        CANDIDATE,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
        send_query=_send_ns_from_resolver(CANDIDATE, {RESOLVER_A: agreed_ns, RESOLVER_B: agreed_ns}),
        make_resolver=_null_make_resolver,
        source_method="generated_candidate",
        log_sink=None,
        errors=[],
        evidence_outcomes=[],
    )
    assert result_ok is not None, "AC6 FAIL: two agreeing resolvers should produce a result"
    assert result_ok.method == "recursive_corroborated"


# ---------------------------------------------------------------------------
# AC-7  evidence_status helpers correctly categorise the new status.
# ---------------------------------------------------------------------------

def test_ac7_evidence_status_helpers():
    """AC-7: CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE is NOT in confirmed,
    IS in recursive_delegation."""
    assert not is_confirmed_evidence_status(
        EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE
    ), "AC7 FAIL: recursive status must NOT be in confirmed (would inflate auth count)"
    assert is_recursive_delegation_status(
        EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE_RECURSIVE
    ), "AC7 FAIL: recursive status must BE in recursive_delegation"


# ---------------------------------------------------------------------------
# AC-8  Order-insensitive NS agreement: TTL / order variation doesn't break.
# ---------------------------------------------------------------------------

def test_ac8_ns_agreement_is_order_insensitive():
    """AC-8: NS set agreement uses frozenset (order/TTL agnostic)."""
    # Same NS targets but delivered in reverse order by RESOLVER_B
    ns_a = [NS_CLOUDFLARE_1, NS_CLOUDFLARE_2]
    ns_b = [NS_CLOUDFLARE_2, NS_CLOUDFLARE_1]  # reversed
    send_fn = _send_ns_from_resolver(CANDIDATE, {RESOLVER_A: ns_a, RESOLVER_B: ns_b})

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,
        make_resolver=_null_make_resolver,
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is True, (
        "AC8 FAIL: order-reversed NS sets should still agree (frozenset comparison)"
    )
    for record in result.records:
        assert record.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE


# ---------------------------------------------------------------------------
# AC-9  Auth-blocked environment: no parent NS IPs → fallback fires.
# ---------------------------------------------------------------------------

def test_ac9_auth_blocked_fires_fallback():
    """AC-9: When no auth NS IPs are available and recursive resolvers agree,
    the recursive fallback promotes DELEGATED_CHILD_ZONE_RECURSIVE."""
    agreed_ns = [NS_CLOUDFLARE_1, NS_CLOUDFLARE_2]
    send_fn = _send_ns_from_resolver(
        CANDIDATE,
        {RESOLVER_A: agreed_ns, RESOLVER_B: agreed_ns},
    )

    result = verify_delegated_child_zone(
        CANDIDATE,
        base_domain=BASE_DOMAIN,
        send_query=send_fn,
        resolve_ns_ips=_null_resolve_ns_ips,   # no auth NS IPs → Path 1 empty
        make_resolver=_null_make_resolver,
        parent_ns_hosts=[],                     # explicitly no parent hosts
        recursive_resolvers=[RESOLVER_A, RESOLVER_B],
    )

    assert result.verified is True, "AC9 FAIL: blocked-auth + recursive agreement should promote"
    assert result.method == "recursive_corroborated"
    assert all(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result.records
    ), "AC9 FAIL: records should all be DELEGATED_CHILD_ZONE_RECURSIVE"
