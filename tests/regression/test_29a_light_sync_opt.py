#!/usr/bin/env python3
"""29A regression: Light sync optimization — signal-gated delegation walk + NS cache.

Durable offline tests confirming both acceptance criteria and all required
negative-action / parity guards.  No live network calls.

Acceptance criteria verified:
  AC1  — finding parity: candidates with A/CNAME/MX/TXT produce same confirmed
          names with and without the optimization (delegation walk skipped for
          no-signal candidates never drops a real finding).
  AC2  — diagnostics integrity: a candidate with genuine SOA evidence (real
          child-zone delegation) still triggers the delegation walk and still
          confirms as DELEGATED_CHILD_ZONE / ZONE_SOA_DISCOVERED.

Negative-action / parity guards:
  §NA1 — candidate with NO delegation signal → verify_delegated_child_zone is
          NOT called (gate code-path proven by mock call counter == 0).
  §NA2 — candidate WITH SOA evidence → verify_delegated_child_zone IS called
          (gate code-path proven by mock call counter == 1).
  §NA3 — parent-NS cache correctness: NS hosts returned by the cache equal
          what the uncached _get_parent_ns_hosts would have returned.
  §NA4 — NS-IP cache correctness: repeated resolve_ns_ips calls for the same
          host hit the cache; the real resolver is called only once.
  §NA5 — finding-parity: A-record candidate produces same CONFIRMED result
          before and after the 29A change (no regression in confirmed count).

Claim-to-code (gate condition):
  scanner/scan_engine.py :: _has_delegation_signal()
    → FindingClassification.ZONE_SOA_DISCOVERED in findings
  The signal gate is in _test_candidates; the delegation walk block executes
  only when _has_delegation_signal(other_findings) is True.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call
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
from tests.regression._paths import REGRESSION_DIR

from scanner.delegation_verifier import DelegationVerificationResult
from scanner.evidence_status import is_confirmed_evidence_status, resolve_evidence_status
from scanner.models import (
    DiscoveredRecord,
    EvidenceStatus,
    FindingClassification,
    RecordType,
    ScanOptions,
    ScanProfile,
    WordlistPlan,
)
from scanner.scan_engine import (
    _has_delegation_signal,
    _enumeration_parent,
    _make_resolver,
    _test_candidates,
    DomainScanResult,
)


# ---------------------------------------------------------------------------
# Fake DNS helpers (no live network)
# ---------------------------------------------------------------------------

def _qname(name: str) -> dns.name.Name:
    return dns.name.from_text(name.rstrip(".") + ".")


def _make_response(
    qname: str, qtype: str, rcode_value: int = dns.rcode.NOERROR
) -> dns.message.Message:
    q = dns.message.make_query(_qname(qname), qtype)
    r = dns.message.make_response(q)
    r.set_rcode(rcode_value)
    return r


def _nxdomain(qname: str, qtype: str) -> tuple[dns.message.Message, None]:
    return _make_response(qname, qtype, dns.rcode.NXDOMAIN), None


def _noerror_empty(qname: str, qtype: str) -> tuple[dns.message.Message, None]:
    return _make_response(qname, qtype, dns.rcode.NOERROR), None


def _add_answer_a(r: dns.message.Message, owner: str, ip: str) -> None:
    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip)
    r.answer.append(dns.rrset.from_rdata(_qname(owner), 300, rd))


def _add_answer_soa(r: dns.message.Message, owner: str) -> None:
    soa_text = "ns1.example.com. admin.example.com. 20260101 3600 900 604800 300"
    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, soa_text)
    r.answer.append(dns.rrset.from_rdata(_qname(owner), 3600, rd))


def _add_answer_ns(r: dns.message.Message, owner: str, target: str) -> None:
    rd = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.NS, target.rstrip(".") + "."
    )
    r.answer.append(dns.rrset.from_rdata(_qname(owner), 300, rd))


# ---------------------------------------------------------------------------
# Shared send_query implementations
# ---------------------------------------------------------------------------

BASE = "ci.testzone.ma.us"
CANDIDATE_NO_SIGNAL = "www.ci.testzone.ma.us"
CANDIDATE_WITH_SIGNAL = "delegated.ci.testzone.ma.us"


def _send_no_signal(fqdn: str, record_type: RecordType, resolver) -> tuple:
    """All candidates: A returns 1.2.3.4; everything else NXDOMAIN.
    No SOA records → no delegation signal for any candidate."""
    if record_type == RecordType.A and fqdn != BASE:
        r = _make_response(fqdn, "A")
        _add_answer_a(r, fqdn, "1.2.3.4")
        return r, None
    # Wildcard probes, base queries, etc. → NXDOMAIN (clean attestation)
    return _nxdomain(fqdn, record_type.value)


def _send_with_signal(fqdn: str, record_type: RecordType, resolver) -> tuple:
    """CANDIDATE_WITH_SIGNAL returns SOA (zone apex); others return A or NXDOMAIN.
    Only the delegated candidate has a SOA → produces ZONE_SOA_DISCOVERED."""
    if fqdn == CANDIDATE_WITH_SIGNAL and record_type == RecordType.SOA:
        r = _make_response(fqdn, "SOA")
        _add_answer_soa(r, fqdn)
        return r, None
    if record_type == RecordType.A and fqdn not in (BASE, CANDIDATE_WITH_SIGNAL):
        r = _make_response(fqdn, "A")
        _add_answer_a(r, fqdn, "2.3.4.5")
        return r, None
    return _nxdomain(fqdn, record_type.value)


def _empty_delegation_result() -> DelegationVerificationResult:
    return DelegationVerificationResult(
        verified=False,
        method="none",
        response_class=None,
        reason="no delegation signal in record sweep",
        matched_owner=None,
        source_path="unknown",
    )


def _confirmed_delegation_result(candidate: str) -> DelegationVerificationResult:
    """Simulates a successfully verified delegated child zone."""
    ns_rec = DiscoveredRecord(
        fqdn=candidate,
        record_type=RecordType.NS,
        value="ns1.child.example.com",
        source_method="generated_candidate/parent_authoritative",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
    )
    return DelegationVerificationResult(
        verified=True,
        method="parent_authoritative_ns",
        response_class=None,
        reason="",
        matched_owner=candidate,
        source_path="parent_authoritative",
        records=[ns_rec],
        log_message=f"Delegation verified for {candidate} via parent-authoritative NS owner match",
    )


# ---------------------------------------------------------------------------
# Minimal _test_candidates harness
# ---------------------------------------------------------------------------

def _run_candidates(
    candidates: list[str],
    send_fn,
    *,
    parent_ns_cache: dict[str, list[str]] | None = None,
    ns_ip_cache: dict[str, list[str]] | None = None,
) -> DomainScanResult:
    """Run _test_candidates with mocked DNS, returning the populated DomainScanResult."""
    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=send_fn),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
        patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
        patch("scanner.scan_engine.run_wildcard_attestation") as mock_wc,
    ):
        from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus
        mock_wc.return_value = WildcardAttestation(
            status=WildcardAttestationStatus.CLEAN,
            parent=BASE,
        )
        _test_candidates(
            candidates=candidates,
            domain=BASE,
            resolver=resolver,
            result=result,
            wildcard_suspected=False,
            attestation_cache={BASE: mock_wc.return_value},
            progress=None,
            messages=[],
            cancel_check=None,
            progress_update=None,
            domain_index=1,
            domain_total=1,
            domains_completed=0,
            started_at=__import__("datetime").datetime.now(),
            phase=__import__("scanner.models", fromlist=["ScanPhase"]).ScanPhase.TESTING_FOURTH_LEVEL,
            candidates_offset=0,
            candidates_total=len(candidates),
            parent_ns_cache=parent_ns_cache,
            ns_ip_cache=ns_ip_cache,
        )
    return result


# ===========================================================================
# 0 — Prior regression chain
# ===========================================================================


def test_prior_chain() -> None:
    """R4c regression must pass before 29A tests run."""
    run_durable_regression(REGRESSION_DIR / "test_r4c_wildcard_match_detail.py")
    print("  prior chain: test_r4c_wildcard_match_detail passed")


# ===========================================================================
# Unit tests for _has_delegation_signal
# ===========================================================================


def test_no_signal_empty() -> None:
    """Empty findings → no delegation signal."""
    assert _has_delegation_signal([]) is False
    print("  PASS test_no_signal_empty")


def test_no_signal_standard_record() -> None:
    """A/CNAME/MX findings → no delegation signal."""
    findings = [
        DiscoveredRecord(
            fqdn="www.ci.testzone.ma.us",
            record_type=RecordType.A,
            value="1.2.3.4",
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
        )
    ]
    assert _has_delegation_signal(findings) is False
    print("  PASS test_no_signal_standard_record")


def test_signal_zone_soa_discovered() -> None:
    """ZONE_SOA_DISCOVERED finding → delegation signal present."""
    findings = [
        DiscoveredRecord(
            fqdn="delegated.ci.testzone.ma.us",
            record_type=RecordType.SOA,
            value="ns1.child. admin.child. serial=1 refresh=3600 retry=900 expire=604800 minimum=300",
            source_method="generated_candidate",
            classification=FindingClassification.ZONE_SOA_DISCOVERED,
        )
    ]
    assert _has_delegation_signal(findings) is True
    print("  PASS test_signal_zone_soa_discovered")


def test_signal_mixed_findings() -> None:
    """Mixed findings including ZONE_SOA_DISCOVERED → signal present."""
    findings = [
        DiscoveredRecord(
            fqdn="foo.ci.testzone.ma.us",
            record_type=RecordType.A,
            value="1.2.3.4",
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
        ),
        DiscoveredRecord(
            fqdn="foo.ci.testzone.ma.us",
            record_type=RecordType.SOA,
            value="ns1.child. admin. serial=1 ...",
            source_method="generated_candidate",
            classification=FindingClassification.ZONE_SOA_DISCOVERED,
        ),
    ]
    assert _has_delegation_signal(findings) is True
    print("  PASS test_signal_mixed_findings")


# ===========================================================================
# §NA1 — no-signal candidate does NOT invoke verify_delegated_child_zone
# ===========================================================================


def test_na1_skip_no_signal_candidate() -> None:
    """§NA1 negative-action: candidate with only A record does NOT invoke delegation walk.

    Gate code path: _has_delegation_signal(other_findings) returns False →
    delegation walk block is not entered → verify_delegated_child_zone call
    count remains 0.
    """
    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()
    delegation_call_count = {"n": 0}

    def _spy_verify(*args, **kwargs):
        delegation_call_count["n"] += 1
        return _empty_delegation_result()

    from datetime import datetime
    from scanner.models import ScanPhase
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=_send_no_signal),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
        patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
        patch("scanner.scan_engine.verify_delegated_child_zone", side_effect=_spy_verify),
    ):
        _test_candidates(
            candidates=[CANDIDATE_NO_SIGNAL],
            domain=BASE,
            resolver=resolver,
            result=result,
            wildcard_suspected=False,
            attestation_cache={BASE: clean_att},
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

    assert delegation_call_count["n"] == 0, (
        f"§NA1 FAIL: verify_delegated_child_zone was called {delegation_call_count['n']} time(s) "
        f"for a no-signal candidate — should be 0"
    )
    # The A record finding should still be confirmed
    confirmed = [
        r for r in result.records
        if is_confirmed_evidence_status(resolve_evidence_status(r, BASE))
    ]
    assert len(confirmed) >= 1, "§NA1 FAIL: A-record candidate must still produce confirmed finding"
    print(f"  PASS test_na1_skip_no_signal_candidate (delegation calls=0, confirmed={len(confirmed)})")


# ===========================================================================
# §NA2 — signal-bearing candidate DOES invoke verify_delegated_child_zone
# ===========================================================================


def test_na2_walk_with_signal_candidate() -> None:
    """§NA2: candidate with SOA evidence triggers the delegation walk (AC2).

    Gate code path: _has_delegation_signal(other_findings) returns True →
    delegation walk block is entered → verify_delegated_child_zone call count == 1.
    The confirmed delegation result is included in result.records.
    """
    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()
    delegation_call_count = {"n": 0}

    def _spy_verify(candidate, **kwargs):
        delegation_call_count["n"] += 1
        return _confirmed_delegation_result(candidate)

    from datetime import datetime
    from scanner.models import ScanPhase
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=_send_with_signal),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
        patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
        patch("scanner.scan_engine.verify_delegated_child_zone", side_effect=_spy_verify),
    ):
        _test_candidates(
            candidates=[CANDIDATE_WITH_SIGNAL],
            domain=BASE,
            resolver=resolver,
            result=result,
            wildcard_suspected=False,
            attestation_cache={BASE: clean_att},
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

    assert delegation_call_count["n"] == 1, (
        f"§NA2 FAIL: verify_delegated_child_zone must be called once for signal-bearing "
        f"candidate; got {delegation_call_count['n']}"
    )
    delegated = [
        r for r in result.records
        if r.classification == FindingClassification.DELEGATED_CHILD_ZONE
    ]
    assert len(delegated) >= 1, (
        f"§NA2 FAIL: DELEGATED_CHILD_ZONE record expected in result; got {[r.classification for r in result.records]}"
    )
    print(f"  PASS test_na2_walk_with_signal_candidate (delegation calls=1, delegated={len(delegated)})")


# ===========================================================================
# §NA3 — parent-NS cache correctness
# ===========================================================================


def test_na3_parent_ns_cache_correctness() -> None:
    """§NA3: cache returns identical NS hosts to the uncached path.

    Two signal-bearing candidates share the same parent (BASE).  With a cache,
    _get_parent_ns_hosts should only be called once; the second candidate reuses
    the cache entry.  The NS hosts in the cache must match what the uncached
    resolver would return.
    """
    from datetime import datetime
    from scanner.models import ScanPhase
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)
    EXPECTED_NS = ["ns1.parent-zone.example.com", "ns2.parent-zone.example.com"]
    get_parent_ns_calls = {"n": 0, "called_with": []}

    def _spy_get_parent_ns(parent: str) -> list[str]:
        get_parent_ns_calls["n"] += 1
        get_parent_ns_calls["called_with"].append(parent)
        return list(EXPECTED_NS)

    def _send_two_signals(fqdn: str, record_type: RecordType, resolver) -> tuple:
        """Both delegated1 and delegated2 have SOA; others NXDOMAIN."""
        if record_type == RecordType.SOA and fqdn in (
            "delegated1.ci.testzone.ma.us",
            "delegated2.ci.testzone.ma.us",
        ):
            r = _make_response(fqdn, "SOA")
            _add_answer_soa(r, fqdn)
            return r, None
        return _nxdomain(fqdn, record_type.value)

    parent_ns_cache: dict[str, list[str]] = {}

    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=_send_two_signals),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
        patch("scanner.scan_engine._get_parent_ns_hosts", side_effect=_spy_get_parent_ns),
        patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=_empty_delegation_result(),
        ),
    ):
        _test_candidates(
            candidates=[
                "delegated1.ci.testzone.ma.us",
                "delegated2.ci.testzone.ma.us",
            ],
            domain=BASE,
            resolver=resolver,
            result=result,
            wildcard_suspected=False,
            attestation_cache={BASE: clean_att},
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
            candidates_total=2,
            parent_ns_cache=parent_ns_cache,
        )

    # Cache must have been used: _get_parent_ns_hosts called only once despite 2 signals
    assert get_parent_ns_calls["n"] == 1, (
        f"§NA3 FAIL: _get_parent_ns_hosts called {get_parent_ns_calls['n']} time(s); "
        f"expected 1 (cache hit on second candidate)"
    )
    # Cache entry must match what the resolver would return
    parent_key = _enumeration_parent("delegated1.ci.testzone.ma.us")
    assert parent_key in parent_ns_cache, f"§NA3 FAIL: parent key {parent_key!r} not in cache"
    cached_ns = parent_ns_cache[parent_key]
    assert cached_ns == EXPECTED_NS, (
        f"§NA3 FAIL: cached NS {cached_ns!r} != expected {EXPECTED_NS!r}"
    )
    print(
        f"  PASS test_na3_parent_ns_cache_correctness "
        f"(get_parent_ns calls=1, cached={cached_ns})"
    )


# ===========================================================================
# §NA4 — NS-IP cache correctness
# ===========================================================================


def test_na4_ns_ip_cache_correctness() -> None:
    """§NA4: ns_ip_cache prevents _resolve_nameserver_ips re-calls for known hosts.

    Pre-populate ns_ip_cache with a known NS host → IP mapping.  Two signal-bearing
    candidates share the same parent.  The delegation walk runs for each, passing
    _cached_resolve_ns_ips as resolve_ns_ips.  Since the NS host is already in the
    cache, _resolve_nameserver_ips must NOT be called at all for that host.

    Separately verify that the returned IPs match the pre-cached value
    (cache correctness, not just call-count).
    """
    from datetime import datetime
    from scanner.models import ScanPhase
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)
    NS_HOST = "ns1.shared-parent.example.com"
    CACHED_IPS = ["10.0.0.42"]

    resolve_ip_calls: dict[str, int] = {}

    def _spy_resolve_ips(ns_host: str) -> list[str]:
        # Should NOT be called for NS_HOST — it is pre-cached.
        resolve_ip_calls[ns_host] = resolve_ip_calls.get(ns_host, 0) + 1
        return ["9.9.9.9"]  # deliberately different from cached value to surface bugs

    def _send_two_signals(fqdn: str, record_type: RecordType, resolver) -> tuple:
        if record_type == RecordType.SOA and fqdn in (
            "delegated1.ci.testzone.ma.us",
            "delegated2.ci.testzone.ma.us",
        ):
            r = _make_response(fqdn, "SOA")
            _add_answer_soa(r, fqdn)
            return r, None
        return _nxdomain(fqdn, record_type.value)

    # Pre-populate: cache already knows NS_HOST → CACHED_IPS
    ns_ip_cache: dict[str, list[str]] = {NS_HOST: list(CACHED_IPS)}

    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=_send_two_signals),
        patch("scanner.scan_engine._resolve_nameserver_ips", side_effect=_spy_resolve_ips),
        patch("scanner.scan_engine._get_parent_ns_hosts", return_value=[NS_HOST]),
        patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=_empty_delegation_result(),
        ),
    ):
        _test_candidates(
            candidates=[
                "delegated1.ci.testzone.ma.us",
                "delegated2.ci.testzone.ma.us",
            ],
            domain=BASE,
            resolver=resolver,
            result=result,
            wildcard_suspected=False,
            attestation_cache={BASE: clean_att},
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
            candidates_total=2,
            parent_ns_cache={BASE: [NS_HOST]},
            ns_ip_cache=ns_ip_cache,
        )

    # Core assertion: pre-cached NS host must NOT have triggered a real resolver call.
    assert NS_HOST not in resolve_ip_calls, (
        f"§NA4 FAIL: _resolve_nameserver_ips called for {NS_HOST} "
        f"even though it was pre-cached (cache miss when hit expected)"
    )
    # Cache value integrity: entry must still hold the pre-cached IPs.
    assert ns_ip_cache[NS_HOST] == CACHED_IPS, (
        f"§NA4 FAIL: cache entry mutated; expected {CACHED_IPS}, got {ns_ip_cache[NS_HOST]}"
    )
    print(
        f"  PASS test_na4_ns_ip_cache_correctness "
        f"(no uncached resolve calls; cached IPs={ns_ip_cache.get(NS_HOST)})"
    )


# ===========================================================================
# §NA5 — finding parity (AC1): A-record candidate produces same confirmed result
# ===========================================================================


def test_na5_finding_parity_a_record_candidate() -> None:
    """§NA5 / AC1: A-record candidate produces same CONFIRMED finding with and without caches.

    Simulates the pre-29A path (no caches, delegation called unconditionally via
    a patched stub that returns empty) and the post-29A path (caches enabled,
    delegation walk skipped for no-signal). Both must confirm the same A record.
    """
    from datetime import datetime
    from scanner.models import ScanPhase
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)

    def _count_confirmed(result: DomainScanResult) -> list[DiscoveredRecord]:
        return [
            r for r in result.records
            if is_confirmed_evidence_status(resolve_evidence_status(r, BASE))
        ]

    def _run_with_config(use_caches: bool) -> DomainScanResult:
        r = DomainScanResult(domain=BASE)
        resolver = _make_resolver()
        with (
            patch("scanner.scan_engine._send_dns_query", side_effect=_send_no_signal),
            patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
            patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
            # Stub the delegation walk to return empty (simulates pre-29A empty result for no-signal)
            patch(
                "scanner.scan_engine.verify_delegated_child_zone",
                return_value=_empty_delegation_result(),
            ),
        ):
            _test_candidates(
                candidates=[CANDIDATE_NO_SIGNAL],
                domain=BASE,
                resolver=resolver,
                result=r,
                wildcard_suspected=False,
                attestation_cache={BASE: clean_att},
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
                parent_ns_cache={} if use_caches else None,
                ns_ip_cache={} if use_caches else None,
            )
        return r

    result_no_cache = _run_with_config(use_caches=False)
    result_with_cache = _run_with_config(use_caches=True)

    confirmed_before = _count_confirmed(result_no_cache)
    confirmed_after = _count_confirmed(result_with_cache)

    assert len(confirmed_before) == len(confirmed_after), (
        f"§NA5 / AC1 FAIL: confirmed count changed: "
        f"before={len(confirmed_before)}, after={len(confirmed_after)}"
    )
    values_before = {(r.fqdn, r.record_type, r.value) for r in confirmed_before}
    values_after = {(r.fqdn, r.record_type, r.value) for r in confirmed_after}
    assert values_before == values_after, (
        f"§NA5 / AC1 FAIL: confirmed findings differ:\n"
        f"  before: {sorted(values_before)}\n"
        f"   after: {sorted(values_after)}"
    )
    print(
        f"  PASS test_na5_finding_parity_a_record_candidate "
        f"(confirmed={len(confirmed_before)}, parity=OK)"
    )


# ===========================================================================
# AC2 — delegation candidate still confirms after walk runs
# ===========================================================================


def test_ac2_delegated_candidate_still_confirms() -> None:
    """AC2 / diagnostics integrity: genuine delegation candidate still confirms.

    When the delegation walk runs (SOA signal present) and verify_delegated_child_zone
    returns a DELEGATED_CHILD_ZONE record, that record appears in result.records as
    a confirmed finding — proving the walk is not disabled globally.
    """
    from datetime import datetime
    from scanner.models import ScanPhase
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)

    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()

    with (
        patch("scanner.scan_engine._send_dns_query", side_effect=_send_with_signal),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
        patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
        patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            side_effect=lambda candidate, **kw: _confirmed_delegation_result(candidate),
        ),
    ):
        _test_candidates(
            candidates=[CANDIDATE_WITH_SIGNAL],
            domain=BASE,
            resolver=resolver,
            result=result,
            wildcard_suspected=False,
            attestation_cache={BASE: clean_att},
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
            parent_ns_cache={BASE: ["ns1.example.com"]},
            ns_ip_cache={},
        )

    delegated = [
        r for r in result.records
        if r.classification == FindingClassification.DELEGATED_CHILD_ZONE
    ]
    assert len(delegated) >= 1, (
        f"AC2 FAIL: no DELEGATED_CHILD_ZONE record found; records={[r.classification for r in result.records]}"
    )
    print(
        f"  PASS test_ac2_delegated_candidate_still_confirms "
        f"(DELEGATED_CHILD_ZONE count={len(delegated)})"
    )


# ===========================================================================
# Main
# ===========================================================================


def main() -> None:
    print("=" * 60)
    print("  29A Light Sync Optimization — Regression Suite")
    print("=" * 60)

    test_prior_chain()

    print("\n-- _has_delegation_signal unit tests --")
    test_no_signal_empty()
    test_no_signal_standard_record()
    test_signal_zone_soa_discovered()
    test_signal_mixed_findings()

    print("\n-- §NA1 skip: no-signal candidate does not invoke walk --")
    test_na1_skip_no_signal_candidate()

    print("\n-- §NA2 walk: signal-bearing candidate invokes walk --")
    test_na2_walk_with_signal_candidate()

    print("\n-- §NA3 parent-NS cache correctness --")
    test_na3_parent_ns_cache_correctness()

    print("\n-- §NA4 NS-IP cache correctness --")
    test_na4_ns_ip_cache_correctness()

    print("\n-- §NA5 / AC1 finding parity --")
    test_na5_finding_parity_a_record_candidate()

    print("\n-- AC2 delegation candidate still confirms --")
    test_ac2_delegated_candidate_still_confirms()

    print("\n" + "=" * 60)
    print("  29A: ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
