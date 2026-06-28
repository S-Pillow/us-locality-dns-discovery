"""
M1 Light-mode performance timing harness.

Runs the real scanner against a fixed set of .us base domains under two
candidate-load cases and records wall-clock elapsed, candidates_tested,
confirmed findings, diagnostics counts, and timeout/SERVFAIL tallies.

Usage (from repo root):
    python -m tests.integration.measure_light_timing
  or:
    python tests/integration/measure_light_timing.py

Network: live DNS required.  Not part of the offline regression chain.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

# Ensure the repo root is on sys.path when run as a script.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.models import (
    DomainScanResult,
    EvidenceStatus,
    ScanOptions,
    ScanProfile,
    ScanInput,
)
from scanner.scan_engine import run_scan
from scanner.evidence_status import is_confirmed_evidence_status, resolve_evidence_status


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WORDLISTS_DIR = _REPO_ROOT / "wordlists"

# Base domains: known real 3rd-level .us domains used throughout the test suite.
# Using a single well-known domain keeps runs consistent across cases.
LIGHT_DOMAIN = "ci.boston.ma.us"
# NOTE: ci.lawrence.ma.us (the offline test fixture domain) was the original target,
# but its authoritative nameservers are non-responsive (queries time out via 8.8.8.8).
# ci.boston.ma.us is a well-operated real .us municipality domain (Constellix NS),
# resolves cleanly via the system resolver, and is a valid representative for
# Light-mode performance measurement.

# Number of repeated runs per case.
SAMPLE_COUNT_LIGHT = 3
SAMPLE_COUNT_NORMAL = 2


# ---------------------------------------------------------------------------
# Helper: build a ScanInput from a single domain string
# ---------------------------------------------------------------------------

def _make_scan_input(domain: str, profile: ScanProfile, tmpdir: Path) -> ScanInput:
    domain_file = tmpdir / "domains.txt"
    domain_file.write_text(domain + "\n", encoding="utf-8")
    return ScanInput(
        domain_file_path=domain_file,
        options=ScanOptions(scan_profile=profile),
        output_dir=tmpdir / "out",
        wordlists_dir=WORDLISTS_DIR,
    )


# ---------------------------------------------------------------------------
# Helper: tally timeout / SERVFAIL from status message log
# ---------------------------------------------------------------------------

def _tally_errors(messages: list[str]) -> tuple[int, int]:
    """Return (timeout_count, servfail_count) from the run's message log."""
    timeouts = sum(1 for m in messages if "timeout" in m.lower())
    servfails = sum(1 for m in messages if "servfail" in m.lower())
    return timeouts, servfails


# ---------------------------------------------------------------------------
# Helper: count confirmed findings and diagnostics from a DomainScanResult
# ---------------------------------------------------------------------------

def _count_results(dr: DomainScanResult) -> tuple[int, int]:
    """Return (confirmed, diagnostics) for a single domain result."""
    confirmed = sum(
        1
        for rec in dr.records
        if is_confirmed_evidence_status(resolve_evidence_status(rec, dr.domain))
    )
    diagnostic_statuses = {
        EvidenceStatus.CANDIDATE_TESTED,
        EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
        EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
        EvidenceStatus.SUPPRESSED_WILDCARD_MATCH,
        EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE,
    }
    diagnostics = sum(
        1 for eo in dr.evidence_outcomes
        if eo.evidence_status in diagnostic_statuses
    )
    return confirmed, diagnostics


# ---------------------------------------------------------------------------
# Run one measurement case N times
# ---------------------------------------------------------------------------

def run_case(
    label: str,
    domain: str,
    profile: ScanProfile,
    samples: int,
) -> list[dict]:
    """Execute *samples* scan runs and return a list of result dicts."""
    print(f"\n{'='*60}")
    print(f"  CASE: {label}")
    print(f"  Domain: {domain}   Profile: {profile.value}   Samples: {samples}")
    print(f"{'='*60}")

    results = []

    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)

        for run_num in range(1, samples + 1):
            print(f"\n  [Run {run_num}/{samples}] starting ...", flush=True)
            scan_input = _make_scan_input(domain, profile, tmpdir)

            t0 = time.perf_counter()
            run_result = run_scan(scan_input)
            wall_elapsed = time.perf_counter() - t0

            # Use the engine's own elapsed_seconds if available, else fallback.
            engine_elapsed = run_result.elapsed_seconds or wall_elapsed

            # Aggregate across domain results (only 1 domain in these runs).
            total_candidates = sum(dr.candidates_tested for dr in run_result.domain_results)
            total_confirmed = 0
            total_diagnostics = 0
            for dr in run_result.domain_results:
                c, d = _count_results(dr)
                total_confirmed += c
                total_diagnostics += d

            timeouts, servfails = _tally_errors(run_result.status_messages)

            row = {
                "run": run_num,
                "elapsed_seconds": round(engine_elapsed, 2),
                "wall_seconds": round(wall_elapsed, 2),
                "candidates_tested": total_candidates,
                "confirmed_outside_system_dns_names": total_confirmed,
                "diagnostics": total_diagnostics,
                "timeouts": timeouts,
                "servfail": servfails,
                "scan_status": run_result.scan_status.value,
            }
            results.append(row)

            print(
                f"  -> elapsed={engine_elapsed:.2f}s  "
                f"candidates={total_candidates}  "
                f"confirmed={total_confirmed}  "
                f"diagnostics={total_diagnostics}  "
                f"timeouts={timeouts}  servfail={servfails}"
            )

    return results


# ---------------------------------------------------------------------------
# Print summary table
# ---------------------------------------------------------------------------

def _print_summary(label: str, rows: list[dict]) -> None:
    elapsed_vals = [r["elapsed_seconds"] for r in rows]
    cands = [r["candidates_tested"] for r in rows]

    print(f"\n  Summary -- {label}")
    print(f"  {'Run':<5} {'elapsed_s':>10} {'candidates':>11} {'confirmed':>10} {'diag':>6} {'to':>4} {'sf':>4}")
    for r in rows:
        print(
            f"  {r['run']:<5} {r['elapsed_seconds']:>10.2f} "
            f"{r['candidates_tested']:>11} {r['confirmed_outside_system_dns_names']:>10} "
            f"{r['diagnostics']:>6} {r['timeouts']:>4} {r['servfail']:>4}"
        )
    print(
        f"  {'RANGE':<5} {min(elapsed_vals):>10.2f}-{max(elapsed_vals):.2f}s  "
        f"candidates={min(cands)}-{max(cands)}"
    )
    avg = sum(elapsed_vals) / len(elapsed_vals)
    print(f"  AVG elapsed: {avg:.2f}s")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("  M1 -- Light-mode Performance Timing Harness")
    print(f"  Wordlists dir: {WORDLISTS_DIR}")
    print(f"  Python: {sys.version}")
    print("=" * 60)

    # Case A: Light profile (25 unique labels from light_evidence.txt)
    case_a_results = run_case(
        label="Case A -- Light profile (25 unique labels)",
        domain=LIGHT_DOMAIN,
        profile=ScanProfile.LIGHT,
        samples=SAMPLE_COUNT_LIGHT,
    )

    # Case B: Normal profile (rfc1480 14 + dns_common 48 + civic 90 = 152 unique labels)
    case_b_results = run_case(
        label="Case B -- Normal profile (152 unique labels, authoritative-NS-on)",
        domain=LIGHT_DOMAIN,
        profile=ScanProfile.NORMAL,
        samples=SAMPLE_COUNT_NORMAL,
    )

    # ---- Summary ----
    print("\n\n" + "=" * 60)
    print("  TIMING REPORT SUMMARY")
    print("=" * 60)

    _print_summary("Case A  (Light profile, 25 labels)", case_a_results)
    _print_summary("Case B  (Normal profile, 152 labels)", case_b_results)

    # PRD target check: 1 domain / 25 labels < 30s
    a_avg = sum(r["elapsed_seconds"] for r in case_a_results) / len(case_a_results)
    a_max = max(r["elapsed_seconds"] for r in case_a_results)
    a_min = min(r["elapsed_seconds"] for r in case_a_results)

    b_avg = sum(r["elapsed_seconds"] for r in case_b_results) / len(case_b_results)
    b_max = max(r["elapsed_seconds"] for r in case_b_results)
    b_min = min(r["elapsed_seconds"] for r in case_b_results)

    print()
    print("  PRD target: Light / 1 domain / 25 labels < 30s")
    prd_status = "PASS" if a_max < 30.0 else "FAIL"
    print(f"  Case A max={a_max:.2f}s  avg={a_avg:.2f}s  min={a_min:.2f}s  -> PRD {prd_status}")
    print(f"  Case B max={b_max:.2f}s  avg={b_avg:.2f}s  min={b_min:.2f}s")

    # Per-candidate rate
    a_cands_avg = sum(r["candidates_tested"] for r in case_a_results) / len(case_a_results)
    b_cands_avg = sum(r["candidates_tested"] for r in case_b_results) / len(case_b_results)
    if a_cands_avg > 0:
        print(f"\n  Case A per-candidate avg: {a_avg / a_cands_avg * 1000:.0f}ms/candidate ({a_cands_avg:.0f} cands avg)")
    if b_cands_avg > 0:
        print(f"  Case B per-candidate avg: {b_avg / b_cands_avg * 1000:.0f}ms/candidate ({b_cands_avg:.0f} cands avg)")

    print()
    print("=== M1 Measurement Complete ===")
    print()


if __name__ == "__main__":
    main()
