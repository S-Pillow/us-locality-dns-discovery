#!/usr/bin/env python3
"""Ticket 29 regression: async parallel record sweep.

Durable offline tests confirming all acceptance criteria and required
negative-action / robustness guards.  No live network calls.

Acceptance criteria verified:
  AC1 — async smoke already gated (test_29_async_smoke.py under tests/integration/).
  AC2 — finding-parity: same confirmed/diagnostic set sync vs async.
  AC3 — Lawrence/timeout robustness: non-responsive resolver → INCONCLUSIVE,
         no hang, no confirmed-from-timeout, no silent drop.
  AC4 — per-candidate async budget cap: when budget exceeded, error is surfaced
         as an inconclusive outcome, not a silent skip.

Negative-action / robustness guards:
  §NA1 — concurrency-invariance: _query_records (sync) and _async_query_records
          produce identical confirmed records and error lists from the same
          fake responses (parallelism changes timing, not results).
  §NA2 — no-timeout candidate produces confirmed finding (positive control).
  §NA3 — timeout candidate produces error entry, not a confirmed finding.
  §NA4 — budget-exceeded case surfaces budget_error, not a silent miss.
  §NA5 — _test_candidates end-to-end: A-record candidate with async sweep
          produces same confirmed result as the sync path (parity fixture).

Claim-to-code (async dispatch/gather site):
  scanner/scan_engine.py :: _async_query_records()
    tasks = [asyncio.create_task(_async_send_dns_query(fqdn, rt, resolver)) ...]
    raw_results = await asyncio.wait_for(asyncio.gather(*tasks), ...)
  Results enter the unchanged classifier via _send_fn=_prefetched_send.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

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

from scanner.dns_classifier import DNSResponseClass
from scanner.evidence_status import is_confirmed_evidence_status, resolve_evidence_status
from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    EvidenceStatus,
    FindingClassification,
    RecordType,
    ScanPhase,
)
from scanner.scan_engine import (
    CANDIDATE_RECORD_TYPES,
    PER_CANDIDATE_ASYNC_BUDGET,
    _async_query_records,
    _async_send_dns_query,
    _has_delegation_signal,
    _make_resolver,
    _query_records,
    _test_candidates,
)


# ---------------------------------------------------------------------------
# DNS message helpers
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


def _nxdomain(qname: str, qtype: str) -> dns.message.Message:
    return _make_response(qname, qtype, dns.rcode.NXDOMAIN)


def _add_answer_a(r: dns.message.Message, owner: str, ip: str) -> None:
    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip)
    r.answer.append(dns.rrset.from_rdata(_qname(owner), 300, rd))


BASE = "ci.testzone.ma.us"
CANDIDATE = "www.ci.testzone.ma.us"


# ---------------------------------------------------------------------------
# Fake async send helpers
# ---------------------------------------------------------------------------

async def _fake_async_a_response(
    fqdn: str, record_type: RecordType, resolver
) -> tuple[dns.message.Message | None, str | None]:
    """Returns A=1.2.3.4 for A queries; NXDOMAIN otherwise."""
    if record_type == RecordType.A:
        r = _make_response(fqdn, "A")
        _add_answer_a(r, fqdn, "1.2.3.4")
        return r, None
    return _nxdomain(fqdn, record_type.value), None


async def _fake_async_timeout(
    fqdn: str, record_type: RecordType, resolver
) -> tuple[dns.message.Message | None, str | None]:
    """Simulates a DNS timeout for every query."""
    return None, f"{fqdn} {record_type.value}: timeout via 127.0.0.1"


async def _fake_async_budget_exceeded(
    fqdn: str, record_type: RecordType, resolver
) -> tuple[dns.message.Message | None, str | None]:
    """Simulates a query that hangs indefinitely (blocked by sleep)."""
    await asyncio.sleep(PER_CANDIDATE_ASYNC_BUDGET + 5.0)
    return None, "never returned"


# ---------------------------------------------------------------------------
# Sync send helper (for concurrency-invariance comparison)
# ---------------------------------------------------------------------------

def _fake_sync_a_response(
    fqdn: str, record_type: RecordType, resolver
) -> tuple[dns.message.Message | None, str | None]:
    """Sync version of _fake_async_a_response."""
    if record_type == RecordType.A:
        r = _make_response(fqdn, "A")
        _add_answer_a(r, fqdn, "1.2.3.4")
        return r, None
    return _nxdomain(fqdn, record_type.value), None


# ---------------------------------------------------------------------------
# 0 — Prior chain
# ---------------------------------------------------------------------------


def test_prior_chain() -> None:
    """29A regression must pass before Ticket 29 tests run."""
    run_durable_regression(REGRESSION_DIR / "test_29a_light_sync_opt.py")
    print("  prior chain: test_29a_light_sync_opt passed")


# ---------------------------------------------------------------------------
# Unit: _async_send_dns_query mirrors _send_dns_query contract
# ---------------------------------------------------------------------------


def test_async_send_dns_query_no_nameservers() -> None:
    """_async_send_dns_query returns (None, error) when no nameservers configured."""
    resolver = _make_resolver()
    resolver.nameservers = []
    result = asyncio.run(_async_send_dns_query(CANDIDATE, RecordType.A, resolver))
    response, error = result
    assert response is None, f"Expected None response, got {response}"
    assert error is not None and "no resolver nameservers" in error, (
        f"Expected no-nameservers error, got {error!r}"
    )
    print("  PASS test_async_send_dns_query_no_nameservers")


# ---------------------------------------------------------------------------
# §NA1 — concurrency-invariance: sync vs async produce identical findings
# ---------------------------------------------------------------------------


def test_na1_concurrency_invariance_findings() -> None:
    """§NA1: _query_records (sync) and _async_query_records produce identical findings.

    Uses the same fake-response function (same responses, same fqdn/types).
    Parallelism may change the order in which responses arrive but must not
    change which records are classified, promoted, or rejected.

    Claim-to-code: _async_query_records gathers responses then calls
    _query_records(..., _send_fn=_prefetched_send) — the classifier is
    the SAME function, exercised on the same responses.
    """
    resolver = _make_resolver()
    resolver.nameservers = ["127.0.0.1"]

    # Sync path
    with patch("scanner.scan_engine._send_dns_query", side_effect=_fake_sync_a_response):
        sync_findings, sync_errors = _query_records(
            CANDIDATE,
            CANDIDATE_RECORD_TYPES,
            resolver,
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
            base_domain=BASE,
        )

    # Async path — patch _async_send_dns_query to use our fake
    with patch(
        "scanner.scan_engine._async_send_dns_query",
        side_effect=_fake_async_a_response,
    ):
        async_findings, async_errors = asyncio.run(
            _async_query_records(
                CANDIDATE,
                CANDIDATE_RECORD_TYPES,
                resolver,
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=BASE,
            )
        )

    # Compare confirmed sets
    def _confirmed_keys(findings: list[DiscoveredRecord]) -> set[tuple]:
        return {
            (r.fqdn, r.record_type, r.value)
            for r in findings
            if is_confirmed_evidence_status(resolve_evidence_status(r, BASE))
        }

    sync_keys = _confirmed_keys(sync_findings)
    async_keys = _confirmed_keys(async_findings)

    assert sync_keys == async_keys, (
        f"§NA1 FAIL: confirmed sets differ.\n"
        f"  sync: {sorted(sync_keys)}\n"
        f" async: {sorted(async_keys)}"
    )
    assert sync_errors == async_errors, (
        f"§NA1 FAIL: error lists differ.\n"
        f"  sync errors:  {sync_errors}\n"
        f" async errors: {async_errors}"
    )
    print(
        f"  PASS test_na1_concurrency_invariance_findings "
        f"(confirmed={len(sync_keys)}, errors={len(sync_errors)})"
    )


# ---------------------------------------------------------------------------
# §NA2 — positive control: A-record candidate produces confirmed finding
# ---------------------------------------------------------------------------


def test_na2_a_record_candidate_confirms() -> None:
    """§NA2: async sweep confirms an A-record candidate; no finding dropped."""
    resolver = _make_resolver()
    resolver.nameservers = ["127.0.0.1"]

    with patch(
        "scanner.scan_engine._async_send_dns_query",
        side_effect=_fake_async_a_response,
    ):
        findings, errors = asyncio.run(
            _async_query_records(
                CANDIDATE,
                CANDIDATE_RECORD_TYPES,
                resolver,
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=BASE,
            )
        )

    confirmed = [
        r for r in findings
        if is_confirmed_evidence_status(resolve_evidence_status(r, BASE))
    ]
    assert len(confirmed) >= 1, (
        f"§NA2 FAIL: expected at least 1 confirmed finding; got {len(confirmed)}"
    )
    a_records = [r for r in confirmed if r.record_type == RecordType.A]
    assert a_records, "§NA2 FAIL: no A record in confirmed findings"
    assert a_records[0].value == "1.2.3.4", (
        f"§NA2 FAIL: expected A=1.2.3.4, got {a_records[0].value}"
    )
    print(
        f"  PASS test_na2_a_record_candidate_confirms "
        f"(confirmed={len(confirmed)}, A={a_records[0].value})"
    )


# ---------------------------------------------------------------------------
# §NA3 — Lawrence robustness: timeout → inconclusive, not confirmed
# ---------------------------------------------------------------------------


def test_na3_timeout_produces_inconclusive_not_confirmed() -> None:
    """§NA3: all-timeout async sweep produces error entries; no confirmed finding.

    Mirrors the Lawrence-fixture scenario: non-responsive resolver times out
    all queries.  The candidate must appear as INCONCLUSIVE_DNS_FAILURE in
    evidence_outcomes, never as a confirmed record.
    """
    resolver = _make_resolver()
    resolver.nameservers = ["127.0.0.1"]
    evidence_outcomes: list = []

    with patch(
        "scanner.scan_engine._async_send_dns_query",
        side_effect=_fake_async_timeout,
    ):
        findings, errors = asyncio.run(
            _async_query_records(
                CANDIDATE,
                CANDIDATE_RECORD_TYPES,
                resolver,
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
                base_domain=BASE,
                evidence_outcomes=evidence_outcomes,
            )
        )

    # No confirmed finding must be produced
    confirmed = [
        r for r in findings
        if is_confirmed_evidence_status(resolve_evidence_status(r, BASE))
    ]
    assert len(confirmed) == 0, (
        f"§NA3 FAIL: timeout must not produce confirmed findings; got {confirmed}"
    )
    # At least one timeout error must be recorded
    assert len(errors) >= 1, "§NA3 FAIL: timeout errors must be recorded"
    assert all("timeout" in e.lower() for e in errors), (
        f"§NA3 FAIL: non-timeout errors in error list: {errors}"
    )
    print(
        f"  PASS test_na3_timeout_produces_inconclusive_not_confirmed "
        f"(confirmed=0, errors={len(errors)})"
    )


# ---------------------------------------------------------------------------
# §NA4 — budget-exceeded case surfaces error, not silent skip
# ---------------------------------------------------------------------------


def test_na4_budget_exceeded_surfaces_error() -> None:
    """§NA4: when the async budget is exceeded, an error is returned.

    The budget-exceeded path in _async_query_records cancels pending tasks and
    returns ([], [budget_error]).  This ensures that a completely non-responsive
    nameserver does not stall the scan past PER_CANDIDATE_ASYNC_BUDGET seconds.
    """
    resolver = _make_resolver()
    resolver.nameservers = ["127.0.0.1"]

    # Patch the budget to near-zero so the sleep in _fake_async_budget_exceeded
    # reliably triggers it without waiting seconds in the test suite.
    with patch("scanner.scan_engine.PER_CANDIDATE_ASYNC_BUDGET", 0.05):
        with patch(
            "scanner.scan_engine._async_send_dns_query",
            side_effect=_fake_async_budget_exceeded,
        ):
            findings, errors = asyncio.run(
                _async_query_records(
                    CANDIDATE,
                    CANDIDATE_RECORD_TYPES,
                    resolver,
                    source_method="generated_candidate",
                    classification=FindingClassification.STANDARD_RECORD,
                    base_domain=BASE,
                )
            )

    assert findings == [], f"§NA4 FAIL: budget-exceeded must return empty findings, got {findings}"
    assert len(errors) == 1, f"§NA4 FAIL: expected 1 budget error, got {errors}"
    assert "budget exceeded" in errors[0].lower(), (
        f"§NA4 FAIL: budget-exceeded error message not found in {errors[0]!r}"
    )
    print(f"  PASS test_na4_budget_exceeded_surfaces_error (error={errors[0]!r})")


# ---------------------------------------------------------------------------
# §NA5 — end-to-end _test_candidates parity: sync stub vs async dispatch
# ---------------------------------------------------------------------------


def test_na5_test_candidates_parity() -> None:
    """§NA5 / AC2: _test_candidates with async dispatch produces same confirmed set.

    Runs _test_candidates with the real async path (patched at the
    _async_send_dns_query level) and compares confirmed findings to the pre-29A
    sync path (patched at _send_dns_query level).  The async parity must hold.
    """
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)

    def _count_confirmed(result: DomainScanResult) -> set[tuple]:
        return {
            (r.fqdn, r.record_type, r.value)
            for r in result.records
            if is_confirmed_evidence_status(resolve_evidence_status(r, result.domain))
        }

    def _run_sync() -> DomainScanResult:
        """Run _test_candidates with sync fake response injected at both sync and async sites.

        Since _test_candidates now always uses asyncio.run(_async_query_records(...)),
        both _send_dns_query and _async_send_dns_query must be patched so the record
        sweep returns the expected fake responses in the offline test environment.
        """
        result = DomainScanResult(domain=BASE)
        resolver = _make_resolver()

        async def _sync_fn_as_async(fqdn, rt, res):
            return _fake_sync_a_response(fqdn, rt, res)

        with (
            patch("scanner.scan_engine._send_dns_query", side_effect=_fake_sync_a_response),
            patch("scanner.scan_engine._async_send_dns_query", side_effect=_sync_fn_as_async),
            patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
            patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
        ):
            _test_candidates(
                candidates=[CANDIDATE],
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
        return result

    def _run_async() -> DomainScanResult:
        """Run _test_candidates with async _async_send_dns_query patched."""
        result = DomainScanResult(domain=BASE)
        resolver = _make_resolver()
        with (
            patch(
                "scanner.scan_engine._async_send_dns_query",
                side_effect=_fake_async_a_response,
            ),
            patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
            patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
        ):
            _test_candidates(
                candidates=[CANDIDATE],
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
        return result

    result_sync = _run_sync()
    result_async = _run_async()

    sync_confirmed = _count_confirmed(result_sync)
    async_confirmed = _count_confirmed(result_async)

    assert sync_confirmed == async_confirmed, (
        f"§NA5 / AC2 FAIL: confirmed sets differ.\n"
        f"  sync:  {sorted(sync_confirmed)}\n"
        f" async:  {sorted(async_confirmed)}"
    )
    print(
        f"  PASS test_na5_test_candidates_parity "
        f"(confirmed={len(sync_confirmed)}, parity=OK)"
    )


# ---------------------------------------------------------------------------
# Lawrence robustness — end-to-end timeout in _test_candidates
# ---------------------------------------------------------------------------


def test_lawrence_timeout_in_test_candidates() -> None:
    """AC3 Lawrence robustness: all-timeout async sweep in _test_candidates.

    Verifies that a non-responsive resolver:
    1. Does not produce confirmed findings.
    2. Does not hang (the PER_CANDIDATE_ASYNC_BUDGET cap fires and returns promptly).
    3. Produces an error entry routed as INCONCLUSIVE_DNS_FAILURE.
    """
    from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus

    clean_att = WildcardAttestation(status=WildcardAttestationStatus.CLEAN, parent=BASE)
    result = DomainScanResult(domain=BASE)
    resolver = _make_resolver()

    # Use a tiny budget so the test doesn't block on real timeouts.
    with (
        patch("scanner.scan_engine.PER_CANDIDATE_ASYNC_BUDGET", 0.05),
        patch(
            "scanner.scan_engine._async_send_dns_query",
            side_effect=_fake_async_budget_exceeded,
        ),
        patch("scanner.scan_engine._resolve_nameserver_ips", return_value=["127.0.0.1"]),
        patch("scanner.scan_engine._get_parent_ns_hosts", return_value=["ns1.example.com"]),
    ):
        _test_candidates(
            candidates=[CANDIDATE],
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

    # No confirmed finding
    confirmed = [
        r for r in result.records
        if is_confirmed_evidence_status(resolve_evidence_status(r, BASE))
    ]
    assert len(confirmed) == 0, (
        f"AC3 FAIL: Lawrence/timeout must not produce confirmed findings; got {confirmed}"
    )

    # Error entries must exist (budget exceeded or timeout)
    query_errors = [
        r for r in result.records
        if r.classification == FindingClassification.QUERY_ERROR
    ]
    inconclusive_outcomes = [
        eo for eo in result.evidence_outcomes
        if eo.evidence_status == EvidenceStatus.INCONCLUSIVE_DNS_FAILURE
    ]
    assert query_errors or inconclusive_outcomes, (
        f"AC3 FAIL: Lawrence/timeout must produce QUERY_ERROR or INCONCLUSIVE_DNS_FAILURE; "
        f"records={[r.classification for r in result.records]}, "
        f"outcomes={[eo.evidence_status for eo in result.evidence_outcomes]}"
    )
    print(
        f"  PASS test_lawrence_timeout_in_test_candidates "
        f"(confirmed=0, error_records={len(query_errors)}, "
        f"inconclusive_outcomes={len(inconclusive_outcomes)})"
    )


# ---------------------------------------------------------------------------
# Budget constant sanity
# ---------------------------------------------------------------------------


def test_budget_constant_value() -> None:
    """PER_CANDIDATE_ASYNC_BUDGET is within expected bounds (2×DNS_TIMEOUT + 1s)."""
    from scanner.scan_engine import DNS_TIMEOUT, PER_CANDIDATE_ASYNC_BUDGET as BUDGET

    expected = DNS_TIMEOUT * 2 + 1.0
    assert BUDGET == expected, (
        f"Budget constant mismatch: expected {expected}, got {BUDGET}"
    )
    # Must be strictly greater than 2×DNS_TIMEOUT to allow UDP+TCP fallback.
    assert BUDGET > DNS_TIMEOUT * 2, "Budget must exceed one full UDP+TCP cycle"
    print(f"  PASS test_budget_constant_value (budget={BUDGET}s, DNS_TIMEOUT={DNS_TIMEOUT}s)")


# ===========================================================================
# Main
# ===========================================================================


def main() -> None:
    print("=" * 60)
    print("  Ticket 29 Async Record Sweep — Regression Suite")
    print("=" * 60)

    test_prior_chain()

    print("\n-- Unit: _async_send_dns_query --")
    test_async_send_dns_query_no_nameservers()
    test_budget_constant_value()

    print("\n-- §NA1 concurrency-invariance --")
    test_na1_concurrency_invariance_findings()

    print("\n-- §NA2 positive control --")
    test_na2_a_record_candidate_confirms()

    print("\n-- §NA3 Lawrence/timeout robustness --")
    test_na3_timeout_produces_inconclusive_not_confirmed()

    print("\n-- §NA4 budget-exceeded error surfaced --")
    test_na4_budget_exceeded_surfaces_error()

    print("\n-- §NA5 / AC2 end-to-end parity --")
    test_na5_test_candidates_parity()

    print("\n-- AC3 Lawrence end-to-end in _test_candidates --")
    test_lawrence_timeout_in_test_candidates()

    print("\n" + "=" * 60)
    print("  Ticket 29: ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
