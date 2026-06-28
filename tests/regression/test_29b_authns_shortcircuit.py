"""29B — Auth-NS Unreachable Short-Circuit regression tests.

Durable negative-action (NA) and acceptance-criteria (AC) tests for the
per-run reachability cache that prevents re-issuing doomed network-unreachable
queries to the same auth-NS IP across every SOA-triggered candidate.

29B rules:
  Rule 1  Only ENETUNREACH / WSAENETUNREACH (errno 10051 / errno 101) triggers
          the short-circuit.  Timeout, SERVFAIL, REFUSED must NOT be cached.
  Rule 2  An unreachable IP is skipped on every SUBSEQUENT query within the
          same domain run (not the first — the first discovers the status).
  Rule 3  Finding parity: the short-circuit must not suppress any finding that
          the pre-29B code would have produced.  Recursive/D2/D3 results are
          unaffected; Path 3 is never gated by the reachability cache.
  Rule 4  One per-host diagnostic record still appears in the report (from the
          first base-sweep failure); no wall of duplicate unreachable rows.
  Rule 5  The unreachable cache is scoped per-domain run (set[str] of IP strings);
          it is never shared across domain runs.
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch, MagicMock, call

import pytest

from scanner.delegation_verifier import (
    _is_unreachable_transport_error,
    verify_delegated_child_zone,
)
from scanner.scan_engine import (
    _is_unreachable_error,
    _normalize_dns_error_text,
)
from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    EvidenceStatus,
    FindingClassification,
    RecordType,
    ScanOptions,
    ScanProfile,
    ScanInput,
)

WORDLISTS_DIR = pathlib.Path(__file__).parent.parent.parent / "wordlists"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_send_returning(error: str | None):
    """Return a send_query fn that always returns (None, error)."""
    def send(fqdn, record_type, resolver):
        return None, error
    return send


def _make_resolver_stub(ip: str | None = "1.2.3.4"):
    resolver = MagicMock()
    resolver.nameservers = [ip] if ip else []
    return resolver


# ---------------------------------------------------------------------------
# NA-1  _is_unreachable_transport_error detects WSAENETUNREACH (Win 10051).
# ---------------------------------------------------------------------------

def test_na1_wsaenetunreach_detected():
    """NA-1 (Rule 1): WinError 10051 is detected as unreachable."""
    win_err = "admin.ci.k12.pa.us NS: [WinError 10051] A socket operation was attempted to an unreachable network"
    assert _is_unreachable_transport_error(win_err), "NA1 FAIL: WinError 10051 not detected"


def test_na1b_enetunreach_linux_detected():
    """NA-1b (Rule 1): errno 101 (Linux ENETUNREACH) is detected."""
    linux_err = "admin.ci.k12.pa.us NS: [Errno 101] Network is unreachable"
    assert _is_unreachable_transport_error(linux_err), "NA1b FAIL: errno 101 not detected"


# ---------------------------------------------------------------------------
# NA-2  Timeout is NOT detected as unreachable.
# ---------------------------------------------------------------------------

def test_na2_timeout_not_detected_as_unreachable():
    """NA-2 (Rule 1): timeout must NOT trigger the short-circuit."""
    timeout_err = "admin.ci.k12.pa.us NS: timeout via 1.2.3.4"
    assert not _is_unreachable_transport_error(timeout_err), (
        "NA2 FAIL: timeout incorrectly flagged as unreachable"
    )


# ---------------------------------------------------------------------------
# NA-3  SERVFAIL is NOT detected as unreachable.
# ---------------------------------------------------------------------------

def test_na3_servfail_not_detected_as_unreachable():
    """NA-3 (Rule 1): SERVFAIL must NOT trigger the short-circuit."""
    sf_err = "admin.ci.k12.pa.us NS: SERVFAIL"
    assert not _is_unreachable_transport_error(sf_err), (
        "NA3 FAIL: SERVFAIL incorrectly flagged as unreachable"
    )


# ---------------------------------------------------------------------------
# NA-4  None transport_error returns False.
# ---------------------------------------------------------------------------

def test_na4_none_not_unreachable():
    """NA-4: None (successful response) is not unreachable."""
    assert not _is_unreachable_transport_error(None)


# ---------------------------------------------------------------------------
# NA-5  _is_unreachable_error in scan_engine detects the same shapes.
# ---------------------------------------------------------------------------

def test_na5_scan_engine_unreachable_helper():
    """NA-5 (Rule 1): scan_engine._is_unreachable_error detects 'network unreachable'."""
    assert _is_unreachable_error("k12.pa.us A: [WinError 10051] unreachable network")
    assert _is_unreachable_error("k12.pa.us NS: [Errno 101] Network is unreachable")
    assert not _is_unreachable_error("k12.pa.us A: timeout via 8.8.8.8")
    assert not _is_unreachable_error("k12.pa.us A: SERVFAIL")
    assert not _is_unreachable_error("k12.pa.us A: query refused or blocked")


# ---------------------------------------------------------------------------
# NA-6  Path 3 (recursive fallback) is never gated by the unreachable cache.
# ---------------------------------------------------------------------------

def test_na6_path3_not_gated_by_cache():
    """NA-6 (Rule 3): recursive fallback fires even when all auth NS IPs are cached
    as unreachable.  The cache is only consulted for Path 1."""
    import dns.message, dns.rdatatype, dns.name, dns.rdataclass, dns.rdata

    cache: set[str] = {"1.2.3.4", "5.6.7.8"}  # all parent NS IPs pre-cached
    recursive_ips = {"1.1.1.1", "8.8.8.8"}

    def _make_ns_response(fqdn: str, ns_target: str) -> dns.message.Message:
        """Build a minimal DNS answer with one NS record."""
        msg = dns.message.Message()
        name = dns.name.from_text(fqdn if fqdn.endswith(".") else fqdn + ".")
        rrs = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.NS)
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target + ".")
        rrs.add(rdata)
        msg.answer.append(rrs)
        return msg

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else None
        if ip in recursive_ips:
            return _make_ns_response(fqdn, "ns1.example.com"), None
        return None, f"{fqdn}: timeout"

    result = verify_delegated_child_zone(
        "admin.ci.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda host: ["1.2.3.4"] if "k12" in host else [host],
        make_resolver=lambda ip: _make_resolver_stub(ip),
        parent_ns_hosts=["dns1.k12.pa.us"],
        recursive_resolvers=["1.1.1.1", "8.8.8.8"],
        unreachable_ns_ips=cache,
    )
    # Path 1 should be skipped (IP 1.2.3.4 is cached)
    # Path 3 should fire (recursive resolvers agree on ns1.example.com)
    assert result.verified, "NA6 FAIL: Path 3 did not fire when auth IPs cached as unreachable"
    assert result.method == "recursive_corroborated", (
        f"NA6 FAIL: expected recursive_corroborated, got {result.method}"
    )


# ---------------------------------------------------------------------------
# AC-1  Path 1 skips a cached IP on subsequent calls (core behavior).
# ---------------------------------------------------------------------------

def test_ac1_path1_skips_cached_ip():
    """AC-1 (Rule 2): Path 1 skips an IP that was cached as unreachable."""
    cache: set[str] = {"9.9.9.9"}  # pre-seeded as unreachable
    call_log: list[str] = []

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else "?"
        call_log.append(ip)
        return None, f"{fqdn}: timeout"

    verify_delegated_child_zone(
        "admin.ci.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda host: ["9.9.9.9"],
        make_resolver=lambda ip: _make_resolver_stub(ip),
        parent_ns_hosts=["dns1.k12.pa.us"],
        unreachable_ns_ips=cache,
    )
    assert "9.9.9.9" not in call_log, (
        "AC1 FAIL: 9.9.9.9 (cached as unreachable) was still queried"
    )


# ---------------------------------------------------------------------------
# AC-2  Path 1 adds IP to cache on first ENETUNREACH and skips on second call.
# ---------------------------------------------------------------------------

def test_ac2_first_unreachable_adds_to_cache():
    """AC-2 (Rule 2): first ENETUNREACH from Path 1 adds IP to cache;
    second call with same candidate skips it."""
    cache: set[str] = set()
    UNREACHABLE_ERR = "[WinError 10051] A socket operation was attempted to an unreachable network"
    call_count: dict[str, int] = {"9.9.9.9": 0}

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else "?"
        call_count[ip] = call_count.get(ip, 0) + 1
        return None, f"{fqdn} NS: {UNREACHABLE_ERR}"

    # First call: IP not in cache, fires, gets unreachable, adds to cache
    verify_delegated_child_zone(
        "candidate1.ci.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda host: ["9.9.9.9"],
        make_resolver=lambda ip: _make_resolver_stub(ip),
        parent_ns_hosts=["dns1.k12.pa.us"],
        unreachable_ns_ips=cache,
    )
    assert "9.9.9.9" in cache, "AC2 FAIL: IP not added to cache after ENETUNREACH"
    first_count = call_count.get("9.9.9.9", 0)

    # Second call: IP already in cache, must not fire
    verify_delegated_child_zone(
        "candidate2.ci.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda host: ["9.9.9.9"],
        make_resolver=lambda ip: _make_resolver_stub(ip),
        parent_ns_hosts=["dns1.k12.pa.us"],
        unreachable_ns_ips=cache,
    )
    second_count = call_count.get("9.9.9.9", 0)
    assert second_count == first_count, (
        f"AC2 FAIL: IP was queried {second_count - first_count} additional time(s) "
        "after being cached as unreachable"
    )


# ---------------------------------------------------------------------------
# AC-3  Timeout host is NOT cached; it is retried on subsequent calls.
# ---------------------------------------------------------------------------

def test_ac3_timeout_not_cached():
    """AC-3 (Rule 1): a timeout failure must NOT add the IP to the cache."""
    cache: set[str] = set()
    call_count: dict[str, int] = {}

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else "?"
        call_count[ip] = call_count.get(ip, 0) + 1
        return None, f"{fqdn} NS: timeout via {ip}"

    for i in range(3):
        verify_delegated_child_zone(
            f"candidate{i}.ci.k12.pa.us",
            base_domain="k12.pa.us",
            send_query=send,
            resolve_ns_ips=lambda host: ["8.8.8.8"],
            make_resolver=lambda ip: _make_resolver_stub(ip),
            parent_ns_hosts=["dns1.k12.pa.us"],
            unreachable_ns_ips=cache,
        )

    assert "8.8.8.8" not in cache, "AC3 FAIL: timeout host added to unreachable cache"
    assert call_count.get("8.8.8.8", 0) == 3, (
        f"AC3 FAIL: timeout host queried {call_count.get('8.8.8.8', 0)} times, expected 3"
    )


# ---------------------------------------------------------------------------
# AC-4  Finding parity: SERVFAIL host not cached; both paths still attempt it.
# ---------------------------------------------------------------------------

def test_ac4_servfail_not_cached():
    """AC-4 (Rule 1): SERVFAIL host must NOT be cached and must be retried."""
    cache: set[str] = set()
    call_count: dict[str, int] = {}

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else "?"
        call_count[ip] = call_count.get(ip, 0) + 1
        return None, f"{fqdn} NS: SERVFAIL"

    for i in range(2):
        verify_delegated_child_zone(
            f"candidate{i}.ci.k12.pa.us",
            base_domain="k12.pa.us",
            send_query=send,
            resolve_ns_ips=lambda host: ["7.7.7.7"],
            make_resolver=lambda ip: _make_resolver_stub(ip),
            parent_ns_hosts=["dns1.k12.pa.us"],
            unreachable_ns_ips=cache,
        )

    assert "7.7.7.7" not in cache, "AC4 FAIL: SERVFAIL host added to unreachable cache"
    assert call_count.get("7.7.7.7", 0) == 2, (
        f"AC4 FAIL: SERVFAIL host queried {call_count.get('7.7.7.7', 0)} times, expected 2"
    )


# ---------------------------------------------------------------------------
# AC-5  None cache (unreachable_ns_ips=None) is backward-compatible.
# ---------------------------------------------------------------------------

def test_ac5_none_cache_backward_compatible():
    """AC-5: passing unreachable_ns_ips=None leaves all behavior unchanged."""
    call_count: dict[str, int] = {}
    UNREACHABLE_ERR = "[WinError 10051] A socket operation was attempted to an unreachable network"

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else "?"
        call_count[ip] = call_count.get(ip, 0) + 1
        return None, f"{fqdn} NS: {UNREACHABLE_ERR}"

    # Two calls, both should fire (no caching)
    for i in range(2):
        verify_delegated_child_zone(
            f"cand{i}.ci.k12.pa.us",
            base_domain="k12.pa.us",
            send_query=send,
            resolve_ns_ips=lambda host: ["4.4.4.4"],
            make_resolver=lambda ip: _make_resolver_stub(ip),
            parent_ns_hosts=["dns1.k12.pa.us"],
            unreachable_ns_ips=None,  # disabled
        )

    assert call_count.get("4.4.4.4", 0) == 2, (
        f"AC5 FAIL: with unreachable_ns_ips=None, expected 2 queries, got {call_count.get('4.4.4.4', 0)}"
    )


# ---------------------------------------------------------------------------
# AC-6  claim-to-code: _is_unreachable_transport_error is present and exported.
# ---------------------------------------------------------------------------

def test_ac6_claim_to_code_helpers_present():
    """AC-6: both detection helpers are importable from their modules."""
    from scanner.delegation_verifier import _is_unreachable_transport_error as dv_fn
    from scanner.scan_engine import _is_unreachable_error as se_fn
    assert callable(dv_fn), "AC6 FAIL: _is_unreachable_transport_error not callable"
    assert callable(se_fn), "AC6 FAIL: _is_unreachable_error not callable"


# ---------------------------------------------------------------------------
# AC-7  verify_delegated_child_zone signature accepts unreachable_ns_ips kwarg.
# ---------------------------------------------------------------------------

def test_ac7_verify_accepts_unreachable_ips_kwarg():
    """AC-7: verify_delegated_child_zone accepts unreachable_ns_ips without error."""
    import inspect
    sig = inspect.signature(verify_delegated_child_zone)
    assert "unreachable_ns_ips" in sig.parameters, (
        "AC7 FAIL: unreachable_ns_ips parameter not present in verify_delegated_child_zone"
    )
    param = sig.parameters["unreachable_ns_ips"]
    assert param.default is None, (
        f"AC7 FAIL: default for unreachable_ns_ips should be None, got {param.default!r}"
    )


# ---------------------------------------------------------------------------
# AC-8  Multiple unreachable IPs for the same host all get cached individually.
# ---------------------------------------------------------------------------

def test_ac8_multiple_ips_per_host_each_cached():
    """AC-8 (Rule 2): when a host resolves to 2 IPs and both are unreachable,
    both get added to the cache and both are skipped on the second call."""
    cache: set[str] = set()
    UNREACHABLE_ERR = "[WinError 10051] unreachable network"
    call_log: list[str] = []

    def send(fqdn, record_type, resolver):
        ip = resolver.nameservers[0] if resolver.nameservers else "?"
        call_log.append(ip)
        return None, f"{fqdn} NS: {UNREACHABLE_ERR}"

    # First call: both IPs fire, both get cached
    verify_delegated_child_zone(
        "cand1.ci.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda host: ["10.0.0.1", "10.0.0.2"],
        make_resolver=lambda ip: _make_resolver_stub(ip),
        parent_ns_hosts=["dns1.k12.pa.us"],
        unreachable_ns_ips=cache,
    )
    assert cache == {"10.0.0.1", "10.0.0.2"}, (
        f"AC8 FAIL: expected both IPs cached, got {cache}"
    )

    call_log.clear()
    # Second call: both IPs should be skipped
    verify_delegated_child_zone(
        "cand2.ci.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda host: ["10.0.0.1", "10.0.0.2"],
        make_resolver=lambda ip: _make_resolver_stub(ip),
        parent_ns_hosts=["dns1.k12.pa.us"],
        unreachable_ns_ips=cache,
    )
    assert call_log == [], (
        f"AC8 FAIL: expected no queries on second call (all IPs cached), got {call_log}"
    )
