"""
Ticket 29 — async smoke test (GATE).

Mirrors R5's sync smoke on the async path: exercises dns.asyncquery.udp and
dns.asyncquery.tcp on Python 3.14.6 against real stable DNS names, then
confirms the responses parse cleanly through classify_dns_response.

This test is a GATE for Ticket 29 implementation.  If it fails, the async
path is not viable on this runtime and the ticket must be parked.

Network: live DNS required.  Not part of the offline regression chain.

Usage (from repo root):
    python tests/integration/test_29_async_smoke.py
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import dns.asyncquery
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from scanner.dns_classifier import DNSResponseClass, classify_dns_response
from scanner.models import RecordType

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Stable authoritative nameserver for a well-operated .us domain.
# This is one of the Constellix NS servers used by ci.boston.ma.us.
# We query 8.8.8.8 (Google Public DNS) for well-known names as the smoke
# target — it is highly stable and accepts both UDP and TCP on port 53.
SMOKE_NAMESERVER = "8.8.8.8"
SMOKE_TIMEOUT = 5.0

# Stable names that should resolve cleanly.
SMOKE_NAMES = [
    ("google.com", RecordType.A),
    ("google.com", RecordType.NS),
]


# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------

def _qname(name: str) -> dns.name.Name:
    return dns.name.from_text(name.rstrip(".") + ".")


async def _udp_query(
    name: str, record_type: RecordType
) -> tuple[dns.message.Message | None, str | None]:
    query = dns.message.make_query(_qname(name), record_type.value)
    try:
        response = await dns.asyncquery.udp(query, SMOKE_NAMESERVER, timeout=SMOKE_TIMEOUT)
        return response, None
    except dns.exception.Timeout:
        return None, f"UDP timeout for {name} {record_type.value}"
    except Exception as exc:
        return None, f"UDP error for {name} {record_type.value}: {exc}"


async def _tcp_query(
    name: str, record_type: RecordType
) -> tuple[dns.message.Message | None, str | None]:
    query = dns.message.make_query(_qname(name), record_type.value)
    try:
        response = await dns.asyncquery.tcp(query, SMOKE_NAMESERVER, timeout=SMOKE_TIMEOUT)
        return response, None
    except dns.exception.Timeout:
        return None, f"TCP timeout for {name} {record_type.value}"
    except Exception as exc:
        return None, f"TCP error for {name} {record_type.value}: {exc}"


async def _parallel_smoke() -> list[dict]:
    """Dispatch all smoke queries concurrently; return list of result dicts."""
    results = []

    # Build tasks: both UDP and TCP for each name/type
    udp_tasks = [_udp_query(name, rt) for name, rt in SMOKE_NAMES]
    tcp_tasks = [_tcp_query(name, rt) for name, rt in SMOKE_NAMES]
    all_tasks = udp_tasks + tcp_tasks
    labels = (
        [f"UDP {name} {rt.value}" for name, rt in SMOKE_NAMES]
        + [f"TCP {name} {rt.value}" for name, rt in SMOKE_NAMES]
    )

    raw = await asyncio.gather(*all_tasks)

    for label, (name, rt), (response, error) in zip(
        labels,
        SMOKE_NAMES + SMOKE_NAMES,
        raw,
    ):
        rc = classify_dns_response(response, name, error)
        results.append({
            "label": label,
            "name": name,
            "record_type": rt.value,
            "response": response,
            "error": error,
            "response_class": rc,
        })

    return results


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

def _assert_smoke_results(results: list[dict]) -> None:
    failed = []
    for r in results:
        print(
            f"  {r['label']:<35}  rc={r['response_class'].name:<30}  "
            + (f"error={r['error']}" if r["error"] else "ok")
        )

        if r["error"]:
            failed.append(f"FAIL {r['label']}: {r['error']}")
            continue

        # Response must exist and be parseable
        assert r["response"] is not None, f"{r['label']}: response is None"
        assert isinstance(r["response"], dns.message.Message), (
            f"{r['label']}: response is not a dns.message.Message"
        )

        # Classifier must NOT return TIMEOUT, TRANSPORT_ERROR, or MALFORMED
        bad_classes = {
            DNSResponseClass.TIMEOUT,
            DNSResponseClass.MALFORMED_OR_UNUSABLE,
        }
        if r["response_class"] in bad_classes:
            failed.append(
                f"FAIL {r['label']}: classifier returned {r['response_class'].name} — "
                f"response not usable"
            )

        # For an A query to google.com, we expect an OWNER_MATCHING_ANSWER
        if r["record_type"] == "A" and r["response_class"] not in (
            DNSResponseClass.OWNER_MATCHING_ANSWER,
            DNSResponseClass.CNAME_ALIAS,
        ):
            failed.append(
                f"FAIL {r['label']}: expected OWNER_MATCHING_ANSWER or CNAME_ALIAS, "
                f"got {r['response_class'].name}"
            )

    if failed:
        for msg in failed:
            print(f"  {msg}")
        raise AssertionError(f"Async smoke FAILED ({len(failed)} assertion(s)). See above.")


def _assert_parallel_speedup(results_serial_ms: float, results_parallel_ms: float) -> None:
    """Soft check: parallel gather should be materially faster than sum."""
    if results_serial_ms <= 0:
        return
    ratio = results_serial_ms / results_parallel_ms
    print(
        f"\n  Parallelism ratio: {ratio:.1f}x  "
        f"(serial_sum={results_serial_ms:.0f}ms, parallel_wall={results_parallel_ms:.0f}ms)"
    )
    # Not a hard assertion — network jitter can collapse the gap.
    # We only warn if parallel is slower than serial.
    if results_parallel_ms > results_serial_ms * 1.5:
        print(
            f"  WARNING: parallel wall time ({results_parallel_ms:.0f}ms) is slower than "
            f"serial sum ({results_serial_ms:.0f}ms) — possible event-loop overhead or throttling."
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("  Ticket 29 — Async DNS Smoke Test (GATE)")
    print(f"  Python: {sys.version}")
    print(f"  Nameserver: {SMOKE_NAMESERVER}")
    print(f"  dns.asyncquery module: {dns.asyncquery.__file__}")
    print("=" * 60)

    print("\n--- Serial baseline (sync) ---")
    serial_times: list[float] = []
    for name, rt in SMOKE_NAMES + SMOKE_NAMES:
        t0 = time.perf_counter()
        try:
            q = dns.message.make_query(_qname(name), rt.value)
            _resp = dns.query.udp(q, SMOKE_NAMESERVER, timeout=SMOKE_TIMEOUT)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            serial_times.append(elapsed_ms)
            rc = classify_dns_response(_resp, name, None)
            print(f"  sync UDP {name} {rt.value:<6}  {elapsed_ms:.0f}ms  rc={rc.name}")
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            serial_times.append(elapsed_ms)
            print(f"  sync UDP {name} {rt.value:<6}  {elapsed_ms:.0f}ms  ERROR: {exc}")

    serial_sum_ms = sum(serial_times)
    print(f"  Serial sum: {serial_sum_ms:.0f}ms")

    print("\n--- Async parallel dispatch ---")
    t0 = time.perf_counter()
    results = asyncio.run(_parallel_smoke())
    parallel_wall_ms = (time.perf_counter() - t0) * 1000
    print(f"  Parallel wall: {parallel_wall_ms:.0f}ms")

    _assert_smoke_results(results)
    _assert_parallel_speedup(serial_sum_ms, parallel_wall_ms)

    print("\n--- Async TCP explicit check ---")
    async def _tcp_check():
        name, rt = "google.com", RecordType.NS
        q = dns.message.make_query(_qname(name), rt.value)
        t0 = time.perf_counter()
        resp = await dns.asyncquery.tcp(q, SMOKE_NAMESERVER, timeout=SMOKE_TIMEOUT)
        elapsed = (time.perf_counter() - t0) * 1000
        rc = classify_dns_response(resp, name, None)
        print(f"  async TCP {name} {rt.value:<6}  {elapsed:.0f}ms  rc={rc.name}")
        assert resp is not None, "TCP response is None"
        assert rc not in (DNSResponseClass.TIMEOUT, DNSResponseClass.MALFORMED_OR_UNUSABLE), (
            f"TCP query returned unusable class: {rc.name}"
        )

    asyncio.run(_tcp_check())

    print("\n" + "=" * 60)
    print("  ASYNC SMOKE PASS — dns.asyncquery UDP + TCP viable on this runtime.")
    print("  Ticket 29 implementation gate: GO")
    print("=" * 60)


if __name__ == "__main__":
    main()
