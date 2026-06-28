#!/usr/bin/env python3
"""R5 Integration Smoke — dnspython on Python 3.14 + real DNS path.

PURPOSE
-------
Prove that dnspython performs real UDP and TCP DNS queries and returns
parseable rrsets on Python 3.14.6, and that the existing dns_classifier
consumes those live responses without error.

This file is NETWORK-DEPENDENT and intentionally NOT part of the offline
durable regression chain (tests/regression/).  Run it separately:

    python tests/integration/test_dnspython_runtime_smoke.py

The offline chain (T22→R4c) remains hermetic and CI-safe — this script
is never imported or chained from there.

SCOPE (R5 ticket contract)
--------------------------
- Exactly 4 DNS queries total (≤ 6 limit).
- Targets: google.com / example.com / cloudflare.com — publicly-stable
  IANA and well-known names.  No scanning, no wordlist, no crt.sh.
- Resolvers: Cloudflare 1.1.1.1 and Google 8.8.8.8.
- Protocols: real UDP (dns.query.udp) + forced TCP (dns.query.tcp).
- RR types: SOA and A.
- Classifier integration: each live response passed through
  dns_classifier.classify_dns_response() to confirm no breakage on 3.14.

PASS CRITERIA
-------------
All 4 queries complete within timeout, return NOERROR, yield at least one
parseable rrset, and classify without error.

FAIL OUTCOME
------------
Any failure is printed explicitly and the script exits non-zero.
If a failure is caused by a genuine dnspython/3.14 incompatibility, it is
surfaced as a Ticket-29-affecting finding (see acceptance report).
If the network is unavailable the script exits with SMOKE_SKIPPED and
exit code 2 (neither PASS nor FAIL — network precondition not met).
"""

from __future__ import annotations

import sys
import platform
from pathlib import Path

# Ensure repo root is on path when run directly.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.exception

from scanner.dns_classifier import DNSResponseClass, classify_dns_response

# ---------------------------------------------------------------------------
# Configuration — bounded query set (≤ 6 total)
# ---------------------------------------------------------------------------

_TIMEOUT_SECONDS = 5.0

# (qname, rdtype_str, resolver_ip, transport)
_QUERIES: list[tuple[str, str, str, str]] = [
    ("google.com",     "SOA", "1.1.1.1", "UDP"),
    ("example.com",    "A",   "8.8.8.8", "UDP"),
    ("example.com",    "SOA", "1.1.1.1", "TCP"),
    ("cloudflare.com", "A",   "8.8.8.8", "TCP"),
]

_EXIT_PASS    = 0
_EXIT_FAIL    = 1
_EXIT_SKIPPED = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(qname: str, rdtype_str: str) -> dns.message.Message:
    return dns.message.make_query(qname, dns.rdatatype.from_text(rdtype_str))


def _rrsets_from_response(response: dns.message.Message) -> list[str]:
    """Return human-readable rrset summaries from answer + authority sections."""
    summaries: list[str] = []
    for section in (response.answer, response.authority):
        for rrset in section:
            rdtype_name = dns.rdatatype.to_text(rrset.rdtype)
            values = [rd.to_text() for rd in rrset]
            summaries.append(f"{rrset.name} {rdtype_name} [{', '.join(values[:3])}]")
    return summaries


def _run_query(
    qname: str,
    rdtype_str: str,
    resolver_ip: str,
    transport: str,
) -> tuple[dns.message.Message | None, str | None]:
    """Send one DNS query; return (response, error_str)."""
    request = _make_request(qname, rdtype_str)
    try:
        if transport == "UDP":
            response = dns.query.udp(request, resolver_ip, timeout=_TIMEOUT_SECONDS)
        else:
            response = dns.query.tcp(request, resolver_ip, timeout=_TIMEOUT_SECONDS)
        return response, None
    except dns.exception.Timeout:
        return None, f"timeout after {_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return None, f"network error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, f"unexpected error: {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Main smoke logic
# ---------------------------------------------------------------------------


def run_smoke() -> int:
    """Execute the smoke suite; return exit code."""
    print("=" * 68)
    print("R5 Integration Smoke — dnspython on Python 3.14 (NETWORK-DEPENDENT)")
    print("=" * 68)
    print(f"Python       : {platform.python_version()} ({platform.python_implementation()})")
    print(f"dnspython    : {dns.__version__}")
    print(f"Platform     : {platform.system()} {platform.release()}")
    print(f"Queries      : {len(_QUERIES)} (limit <= 6 per R5 contract)")
    print(f"Resolvers    : 1.1.1.1 (Cloudflare), 8.8.8.8 (Google)")
    print()

    results: list[dict] = []
    network_failures: list[str] = []

    for qname, rdtype_str, resolver_ip, transport in _QUERIES:
        label = f"{transport} {qname}/{rdtype_str} @{resolver_ip}"
        print(f"  QUERY  {label} ...", end=" ", flush=True)

        response, error = _run_query(qname, rdtype_str, resolver_ip, transport)

        if error:
            # Distinguish network-unavailable from dnspython errors.
            if "timeout" in error or "network error" in error:
                network_failures.append(f"{label}: {error}")
                print(f"NETWORK-ERROR ({error})")
            else:
                print(f"FAIL ({error})")
            results.append({"label": label, "ok": False, "error": error, "network": True})
            continue

        # --- Validate response -------------------------------------------------
        rcode_val = response.rcode()
        rcode_name = dns.rcode.to_text(rcode_val)

        if rcode_val != dns.rcode.NOERROR:
            msg = f"unexpected rcode {rcode_name}"
            print(f"FAIL ({msg})")
            results.append({"label": label, "ok": False, "error": msg, "network": False})
            continue

        rrsets = _rrsets_from_response(response)
        if not rrsets:
            msg = "NOERROR but no rrsets in answer or authority"
            print(f"FAIL ({msg})")
            results.append({"label": label, "ok": False, "error": msg, "network": False})
            continue

        # --- Classifier integration check -------------------------------------
        classifier_result = classify_dns_response(response, qname)
        if classifier_result is None:
            msg = "classify_dns_response returned None"
            print(f"FAIL ({msg})")
            results.append({"label": label, "ok": False, "error": msg, "network": False})
            continue

        print(f"PASS (rcode={rcode_name}, rrsets={len(rrsets)}, class={classifier_result.value})")
        for summary in rrsets:
            print(f"           {summary}")
        results.append({"label": label, "ok": True, "error": None, "network": False})

    # --- Summary --------------------------------------------------------------
    print()
    print("-" * 68)
    passed = sum(1 for r in results if r["ok"])
    total  = len(results)
    net_err_count = len(network_failures)

    if net_err_count == total:
        # Every query was a network failure — no network available.
        print("SMOKE_SKIPPED — all queries failed with network errors.")
        print("Network precondition not met; cannot determine pass/fail.")
        print("Re-run with network access to complete the R5 smoke.")
        for nf in network_failures:
            print(f"  network: {nf}")
        print("-" * 68)
        return _EXIT_SKIPPED

    if passed == total:
        print(f"SMOKE_PASS — {passed}/{total} queries passed.")
        print("dnspython 3.14 runtime unknown: CLEARED.")
        print("Ticket 29 (async) runtime precondition: GREEN.")
    else:
        non_network_failures = [r for r in results if not r["ok"] and not r.get("network")]
        print(f"SMOKE_FAIL — {passed}/{total} queries passed.")
        print()
        print("*** TICKET-29-AFFECTING FINDING ***")
        print("One or more live DNS queries failed in a way that is NOT a simple")
        print("network-unavailability issue.  This is a Ticket-29 runtime blocker.")
        print("Owner decision required before async work proceeds.")
        print()
        for r in non_network_failures:
            print(f"  FAIL: {r['label']} — {r['error']}")
        if network_failures:
            print()
            print("  (network errors, not counted as dnspython failures:)")
            for nf in network_failures:
                print(f"  net:  {nf}")

    print(f"dnspython    : {dns.__version__}")
    print(f"Python       : {platform.python_version()}")
    print("-" * 68)
    return _EXIT_PASS if passed == total else _EXIT_FAIL


if __name__ == "__main__":
    sys.exit(run_smoke())
