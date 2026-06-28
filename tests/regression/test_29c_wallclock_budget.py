"""29C — Delegation Verifier Wall-Clock Budget Cap regression tests.

Durable negative-action (NA) and acceptance-criteria (AC) tests for the
per-candidate auth-path wall-clock budget introduced in AIPF Ticket 29C.

29C rules (from spec):
  Rule 1  The budget wraps ONLY authoritative Paths 1/2.  Path 3 (recursive)
          ALWAYS runs after a budget-hit and is NEVER gated by the cap.
  Rule 2  A budget-hit is "inconclusive/budget-exceeded"; it is NEVER
          authoritative absence.  method=="auth_budget_exceeded", never "none".
  Rule 3  When auth produces a positive finding before budget expires, it is
          returned normally — the cap only fires on a timeout/over-budget path.
  Rule 4  Budget is configurable; the default constant (AUTH_VERIFIER_BUDGET_SECONDS)
          matches the measured value (2.0 s).
  Rule 5  29B ENETUNREACH short-circuit still fires in a mocked ICMP-unreachable
          case — 29B and 29C are additive, not mutually exclusive.
  Rule 6  The budget scales resolver.timeout so each UDP+TCP attempt gets
          min(DNS_TIMEOUT, remaining/2) — avoiding the hardcoded 3-s timeout.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, call
from typing import Any

import pytest

from scanner.delegation_verifier import (
    AUTH_BUDGET_EXCEEDED_REASON,
    DelegationVerificationResult,
    verify_delegated_child_zone,
    _is_unreachable_transport_error,
)
from scanner.scan_engine import AUTH_VERIFIER_BUDGET_SECONDS
from scanner.models import (
    EvidenceStatus,
    FindingClassification,
    RecordType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resolver(ip=None):
    """Return a mock resolver with timeout/lifetime attributes."""
    r = MagicMock()
    r.timeout = 3.0
    r.lifetime = 5.0
    r.nameservers = [ip or "127.0.0.1"]
    return r


def _send_returns_none(fqdn, record_type, resolver):
    """Simulates a query that returns no response (server failure or NXDOMAIN)."""
    return None, f"{fqdn} {record_type.value}: no response"


def _send_returns_timeout(fqdn, record_type, resolver):
    """Simulates a query that always times out after a fixed 0.3s."""
    time.sleep(0.3)   # fixed duration — always exceeds any test budget ≤ 0.25s
    return None, f"{fqdn} {record_type.value}: timeout via {getattr(resolver, 'nameservers', ['?'])[0]}"


def _make_ns_response(candidate: str, ns_target: str):
    """Build a minimal mock DNS message with an owner-matching NS entry."""
    import dns.message, dns.name, dns.rrset, dns.rdatatype, dns.rdataclass, dns.rdata
    msg = dns.message.Message()
    owner = dns.name.from_text(candidate + ".")
    rrset = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.NS)
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_target + ".")
    rrset.add(rdata)
    msg.answer.append(rrset)
    return msg


def _make_recursive_ns_response(candidate: str, ns_target: str):
    """Same as _make_ns_response — used for Path 3 responses."""
    return _make_ns_response(candidate, ns_target)


# ---------------------------------------------------------------------------
# NA-1  method=="auth_budget_exceeded" is distinct from "none" (no false absence)
# ---------------------------------------------------------------------------

def test_na1_budget_exceeded_method_not_none():
    """NA-1: a budget-hit with no auth evidence must NOT use method='none'."""
    calls = []

    def slow_send(fqdn, record_type, resolver):
        calls.append(fqdn)
        time.sleep(0.3)   # fixed 0.3s — always exceeds the 0.15s budget
        return None, f"{fqdn}: timeout"

    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=slow_send,
        resolve_ns_ips=lambda h: ["1.2.3.4"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        recursive_resolvers=[],   # no recursive resolvers → Path 3 returns None
        auth_budget_seconds=0.15,
    )
    assert result.verified is False, "NA-1 FAIL: should not be verified"
    assert result.method == "auth_budget_exceeded", (
        f"NA-1 FAIL: expected method='auth_budget_exceeded', got '{result.method}'"
    )
    assert result.auth_budget_exceeded is True, "NA-1 FAIL: auth_budget_exceeded flag must be True"
    assert AUTH_BUDGET_EXCEEDED_REASON in result.reason or AUTH_BUDGET_EXCEEDED_REASON in result.log_message, (
        "NA-1 FAIL: AUTH_BUDGET_EXCEEDED_REASON not reflected in reason/log_message"
    )


# ---------------------------------------------------------------------------
# NA-2  Path 3 still runs after a budget-hit (the spine)
# ---------------------------------------------------------------------------

def test_na2_path3_runs_after_budget_hit():
    """NA-2: when auth budget is exceeded, Path 3 (recursive) still executes."""
    path3_called = []

    def slow_send(fqdn, record_type, resolver):
        time.sleep(resolver.timeout + 0.05)
        return None, f"{fqdn}: timeout"

    def fast_recursive_send(fqdn, record_type, resolver):
        path3_called.append(getattr(resolver, "nameservers", [None])[0])
        # Return a valid NS response for the candidate
        if fqdn == "admin.k12.pa.us":
            return _make_recursive_ns_response("admin.k12.pa.us", "ns1.delegation.example"), None
        return None, "no response"

    def make_res(ip=None):
        r = MagicMock()
        r.timeout = 3.0
        r.lifetime = 5.0
        r.nameservers = [ip or "127.0.0.1"]
        return r

    # First call site: parent NS → will timeout → budget hit
    # Path 3: two recursive resolvers agree → should still produce a result
    call_count = [0]

    def mixed_send(fqdn, record_type, resolver):
            ns = getattr(resolver, "nameservers", [None])[0]
            if ns in ("8.8.8.8", "1.1.1.1"):
                return fast_recursive_send(fqdn, record_type, resolver)
            # Auth NS → always slow (fixed 0.3s, exceeds 0.15s budget)
            time.sleep(0.3)
            return None, f"{fqdn}: timeout"

    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=mixed_send,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=make_res,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        recursive_resolvers=["8.8.8.8", "1.1.1.1"],
        auth_budget_seconds=0.15,
    )

    assert "8.8.8.8" in path3_called or "1.1.1.1" in path3_called, (
        "NA-2 FAIL: Path 3 was not called after auth budget exceeded"
    )
    assert result.verified is True, "NA-2 FAIL: Path 3 should have verified via recursive"
    assert result.method == "recursive_corroborated", (
        f"NA-2 FAIL: expected 'recursive_corroborated', got '{result.method}'"
    )
    assert result.auth_budget_exceeded is True, (
        "NA-2 FAIL: auth_budget_exceeded flag should be True even when Path 3 succeeds"
    )


# ---------------------------------------------------------------------------
# NA-3  Budget does NOT trigger when auth NS responds quickly
# ---------------------------------------------------------------------------

def test_na3_budget_not_triggered_for_fast_auth():
    """NA-3: budget cap does not interfere when auth NS responds within budget."""
    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=_send_returns_none,   # fast (instant return, no delay)
        resolve_ns_ips=lambda h: ["1.2.3.4"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        recursive_resolvers=[],
        auth_budget_seconds=5.0,   # generous budget
    )
    assert result.auth_budget_exceeded is False, (
        "NA-3 FAIL: fast auth should not trigger budget exceeded"
    )
    assert result.method != "auth_budget_exceeded", (
        "NA-3 FAIL: method should not be 'auth_budget_exceeded' for fast auth"
    )


# ---------------------------------------------------------------------------
# NA-4  No false absence: budget-hit never produces an authoritative-negative
# ---------------------------------------------------------------------------

def test_na4_no_false_absence_from_budget_hit():
    """NA-4: budget-hit candidate must not be reported as authoritatively absent."""
    def always_timeout(fqdn, record_type, resolver):
        time.sleep(0.3)   # fixed 0.3s — always exceeds the 0.15s budget
        return None, f"{fqdn}: timeout"

    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=always_timeout,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["auth-ns.example.com"],
        source_method="test",
        recursive_resolvers=[],
        auth_budget_seconds=0.15,
    )
    # The result should be inconclusive, not a clean "none" (absence)
    assert result.method != "none", (
        "NA-4 FAIL: budget-hit must not map to method='none' (false absence)"
    )
    assert result.verified is False, "NA-4 FAIL: budget-hit with no Path 3 must be unverified"
    assert result.auth_budget_exceeded is True, "NA-4 FAIL: auth_budget_exceeded flag must be set"


# ---------------------------------------------------------------------------
# NA-5  29B ENETUNREACH short-circuit still fires (29B + 29C coexistence)
# ---------------------------------------------------------------------------

def test_na5_29b_shortcircuit_still_fires_with_budget():
    """NA-5: 29B ENETUNREACH cache short-circuit is unaffected by 29C budget."""
    unreachable_cache: set[str] = set()
    call_log: list[str] = []

    def send_unreachable(fqdn, record_type, resolver):
        ip = getattr(resolver, "nameservers", [None])[0]
        call_log.append(ip)
        return None, f"{fqdn}: [Errno 10051] Unknown error"

    # First call: cache empty → query fires, ENETUNREACH returned, ip added to cache
    result1 = verify_delegated_child_zone(
        "child1.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send_unreachable,
        resolve_ns_ips=lambda h: ["10.1.1.1"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        recursive_resolvers=[],
        unreachable_ns_ips=unreachable_cache,
        auth_budget_seconds=5.0,
    )
    assert "10.1.1.1" in unreachable_cache, "NA-5 FAIL: ENETUNREACH IP not cached (29B broken)"
    first_call_count = len(call_log)

    # Second call: ip is in cache → must be skipped (29B short-circuit)
    call_log.clear()
    result2 = verify_delegated_child_zone(
        "child2.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send_unreachable,
        resolve_ns_ips=lambda h: ["10.1.1.1"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        recursive_resolvers=[],
        unreachable_ns_ips=unreachable_cache,
        auth_budget_seconds=5.0,
    )
    assert len(call_log) == 0, (
        f"NA-5 FAIL: 29B short-circuit did not fire; send called {len(call_log)} times"
    )


# ---------------------------------------------------------------------------
# NA-6  Budget=None disables the cap entirely (backward compatibility)
# ---------------------------------------------------------------------------

def test_na6_no_budget_backward_compatible():
    """NA-6: when auth_budget_seconds=None (default), behaviour is unchanged."""
    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=_send_returns_none,
        resolve_ns_ips=lambda h: ["1.2.3.4"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        # auth_budget_seconds not passed → defaults to None
    )
    assert result.auth_budget_exceeded is False, (
        "NA-6 FAIL: auth_budget_exceeded should be False when budget is not set"
    )
    assert result.method in ("none", "parent_authoritative_ns", "recursive_corroborated"), (
        f"NA-6 FAIL: unexpected method '{result.method}' with no budget"
    )


# ---------------------------------------------------------------------------
# NA-7  Resolver.timeout is scaled by the budget (claim-to-code)
# ---------------------------------------------------------------------------

def test_na7_resolver_timeout_scaled_by_budget():
    """NA-7: resolver.timeout is set to min(DNS_TIMEOUT, remaining/2) before each query."""
    observed_timeouts: list[float] = []

    def capture_timeout(fqdn, record_type, resolver):
        observed_timeouts.append(resolver.timeout)
        return None, f"{fqdn}: no data"

    def make_res_with_default(ip=None):
        r = MagicMock()
        r.timeout = 3.0   # default DNS_TIMEOUT
        r.lifetime = 5.0
        r.nameservers = [ip or "127.0.0.1"]
        return r

    verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=capture_timeout,
        resolve_ns_ips=lambda h: ["1.2.3.4"],
        make_resolver=make_res_with_default,
        parent_ns_hosts=["ns1.example.com"],
        source_method="test",
        recursive_resolvers=[],
        auth_budget_seconds=0.8,   # budget → per_attempt = max(0.05, 0.8/2) = 0.4s
    )
    assert observed_timeouts, "NA-7 FAIL: no queries observed"
    # Each observed timeout must be ≤ budget/2 (i.e. 0.4s here)
    for t in observed_timeouts:
        assert t <= 0.41, (
            f"NA-7 FAIL: resolver.timeout {t:.3f}s > budget/2=0.4s — scaling not applied"
        )


# ---------------------------------------------------------------------------
# AC-1  Measurement: AUTH_VERIFIER_BUDGET_SECONDS == 2.0 (from Step-1 data)
# ---------------------------------------------------------------------------

def test_ac1_default_budget_matches_measured_value():
    """AC-1: AUTH_VERIFIER_BUDGET_SECONDS equals the Step-1-derived 2.0 s."""
    assert AUTH_VERIFIER_BUDGET_SECONDS == 2.0, (
        f"AC-1 FAIL: expected 2.0s (from measurement), got {AUTH_VERIFIER_BUDGET_SECONDS}"
    )


# ---------------------------------------------------------------------------
# AC-2  Budget-hit candidate → Path 3 executes → recursive finding produced
# ---------------------------------------------------------------------------

def test_ac2_path3_finding_produced_after_budget_hit():
    """AC-2: budget-hit candidate still produces a recursive finding via Path 3."""
    def make_res(ip=None):
        r = MagicMock()
        r.timeout = 3.0
        r.lifetime = 5.0
        r.nameservers = [ip or "127.0.0.1"]
        return r

    def send(fqdn, record_type, resolver):
        ip = getattr(resolver, "nameservers", [None])[0]
        if ip in ("8.8.8.8", "1.1.1.1"):
            return _make_recursive_ns_response("admin.k12.pa.us", "ns1.deleg.example"), None
        # Auth NS → fixed 0.3s (exceeds 0.15s budget)
        time.sleep(0.3)
        return None, f"{fqdn}: timeout"

    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=make_res,
        parent_ns_hosts=["auth-ns.example.com"],
        source_method="test",
        recursive_resolvers=["8.8.8.8", "1.1.1.1"],
        auth_budget_seconds=0.15,
    )
    assert result.verified is True, "AC-2 FAIL: Path 3 should have produced a finding"
    assert result.method == "recursive_corroborated", (
        f"AC-2 FAIL: expected 'recursive_corroborated', got '{result.method}'"
    )
    assert any(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE_RECURSIVE
        for r in result.records
    ), "AC-2 FAIL: no DELEGATED_CHILD_ZONE_RECURSIVE record produced"
    # Even though Path 3 succeeded, auth_budget_exceeded is True (auth was cut short)
    assert result.auth_budget_exceeded is True, (
        "AC-2 FAIL: auth_budget_exceeded should be True even when Path 3 succeeds"
    )


# ---------------------------------------------------------------------------
# AC-3  Auth positive before budget → returns authoritative result, no flag
# ---------------------------------------------------------------------------

def test_ac3_auth_positive_before_budget_returns_auth_result():
    """AC-3: when auth succeeds within budget, result is authoritative (no budget flag)."""
    def make_res(ip=None):
        r = MagicMock()
        r.timeout = 3.0
        r.lifetime = 5.0
        r.nameservers = [ip or "127.0.0.1"]
        return r

    def fast_auth_send(fqdn, record_type, resolver):
        ip = getattr(resolver, "nameservers", [None])[0]
        if ip == "10.0.0.1":
            return _make_ns_response(fqdn, "ns1.child.example"), None
        return None, "not called"

    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=fast_auth_send,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=make_res,
        parent_ns_hosts=["auth-ns.example.com"],
        source_method="test",
        recursive_resolvers=["8.8.8.8", "1.1.1.1"],
        auth_budget_seconds=2.0,
    )
    assert result.verified is True, "AC-3 FAIL: fast auth should verify"
    assert result.method == "parent_authoritative_ns", (
        f"AC-3 FAIL: expected 'parent_authoritative_ns', got '{result.method}'"
    )
    assert result.auth_budget_exceeded is False, (
        "AC-3 FAIL: auth_budget_exceeded should be False when auth succeeds quickly"
    )
    assert any(
        r.classification == FindingClassification.DELEGATED_CHILD_ZONE
        for r in result.records
    ), "AC-3 FAIL: no DELEGATED_CHILD_ZONE record produced"


# ---------------------------------------------------------------------------
# AC-4  Budget log message present when cap fires
# ---------------------------------------------------------------------------

def test_ac4_log_message_contains_budget_exceeded_reason():
    """AC-4: when budget is hit, log messages include the budget-exceeded reason."""
    log_messages: list[str] = []

    def slow_send(fqdn, record_type, resolver):
        time.sleep(0.3)   # fixed 0.3s — always exceeds the 0.15s budget
        return None, f"{fqdn}: timeout"

    verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=slow_send,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["auth-ns.example.com"],
        source_method="test",
        log_sink=log_messages,
        recursive_resolvers=[],
        auth_budget_seconds=0.15,
    )
    budget_related = [m for m in log_messages if "budget" in m.lower()]
    assert budget_related, (
        f"AC-4 FAIL: no 'budget' keyword in log messages: {log_messages}"
    )


# ---------------------------------------------------------------------------
# AC-5  Budget is configurable; non-default value is respected
# ---------------------------------------------------------------------------

def test_ac5_custom_budget_respected():
    """AC-5: a custom auth_budget_seconds value overrides the default."""
    send_calls: list[str] = []

    def slow_send(fqdn, record_type, resolver):
        send_calls.append(getattr(resolver, "nameservers", [None])[0])
        time.sleep(0.4)   # fixed 0.4s — exceeds custom_budget=0.3s
        return None, f"{fqdn}: timeout"

    custom_budget = 0.3
    t0 = time.monotonic()
    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=slow_send,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["ns1.e.com", "ns2.e.com"],   # 2 hosts → 2 IPs
        source_method="test",
        recursive_resolvers=[],
        auth_budget_seconds=custom_budget,
    )
    total = time.monotonic() - t0
    # 1st IP takes 0.4s (exceeds budget=0.3s after the query).
    # 2nd IP should be skipped (budget exhausted).
    # Total should be well under 2 × (3s default timeout) = 6s.
    assert len(send_calls) == 1, (
        f"AC-5 FAIL: expected 1 send call (2nd IP skipped), got {len(send_calls)}: {send_calls}"
    )
    assert total < 1.5, (
        f"AC-5 FAIL: custom budget {custom_budget}s not respected; total elapsed={total:.2f}s"
    )
    assert result.auth_budget_exceeded is True, (
        "AC-5 FAIL: auth_budget_exceeded should be set with custom small budget"
    )


# ---------------------------------------------------------------------------
# AC-6  AUTH_BUDGET_EXCEEDED_REASON constant is exported and non-empty
# ---------------------------------------------------------------------------

def test_ac6_budget_exceeded_reason_constant():
    """AC-6: AUTH_BUDGET_EXCEEDED_REASON is a non-empty string explaining the state."""
    assert isinstance(AUTH_BUDGET_EXCEEDED_REASON, str), "AC-6 FAIL: must be a string"
    assert len(AUTH_BUDGET_EXCEEDED_REASON) > 10, "AC-6 FAIL: too short"
    assert "budget" in AUTH_BUDGET_EXCEEDED_REASON.lower(), (
        "AC-6 FAIL: must mention 'budget'"
    )
    assert "recursive" in AUTH_BUDGET_EXCEEDED_REASON.lower(), (
        "AC-6 FAIL: must mention 'recursive fallback'"
    )


# ---------------------------------------------------------------------------
# AC-7  Path 3 not in budget cap: zero-budget still lets Path 3 run
# ---------------------------------------------------------------------------

def test_ac7_zero_budget_path3_still_runs():
    """AC-7: even with budget=0 (immediately exceeded), Path 3 always runs."""
    path3_called: list[str] = []

    def send(fqdn, record_type, resolver):
        ip = getattr(resolver, "nameservers", [None])[0]
        if ip in ("8.8.8.8", "1.1.1.1"):
            path3_called.append(ip)
            return _make_recursive_ns_response("admin.k12.pa.us", "ns1.deleg.example"), None
        return None, "auth query (should not be called)"

    result = verify_delegated_child_zone(
        "admin.k12.pa.us",
        base_domain="k12.pa.us",
        send_query=send,
        resolve_ns_ips=lambda h: ["10.0.0.1"],
        make_resolver=_make_resolver,
        parent_ns_hosts=["auth-ns.example.com"],
        source_method="test",
        recursive_resolvers=["8.8.8.8", "1.1.1.1"],
        auth_budget_seconds=0.0,   # immediately exceeded
    )
    assert path3_called, "AC-7 FAIL: Path 3 was not called with budget=0"
    assert result.verified is True, "AC-7 FAIL: Path 3 should succeed with budget=0"
    assert result.auth_budget_exceeded is True, "AC-7 FAIL: flag must be set"


# ---------------------------------------------------------------------------
# AC-8  Claim-to-code: AUTH_VERIFIER_BUDGET_SECONDS wired at both call sites
# ---------------------------------------------------------------------------

def test_ac8_budget_constant_wired_in_scan_engine():
    """AC-8: AUTH_VERIFIER_BUDGET_SECONDS is imported from scan_engine (call-site audit)."""
    import scanner.scan_engine as se
    assert hasattr(se, "AUTH_VERIFIER_BUDGET_SECONDS"), (
        "AC-8 FAIL: AUTH_VERIFIER_BUDGET_SECONDS not found in scan_engine"
    )
    assert se.AUTH_VERIFIER_BUDGET_SECONDS == AUTH_VERIFIER_BUDGET_SECONDS, (
        "AC-8 FAIL: constant value mismatch between scan_engine and delegation_verifier"
    )
    # Verify the budget is used in the two call-sites (_test_candidates and
    # _validate_fourth_level_parent) via source inspection.
    import inspect
    src = inspect.getsource(se)
    # Both call sites should have auth_budget_seconds=AUTH_VERIFIER_BUDGET_SECONDS
    occurrences = src.count("auth_budget_seconds=AUTH_VERIFIER_BUDGET_SECONDS")
    assert occurrences >= 2, (
        f"AC-8 FAIL: expected ≥2 call-sites with auth_budget_seconds=AUTH_VERIFIER_BUDGET_SECONDS, "
        f"found {occurrences}"
    )
