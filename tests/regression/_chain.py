"""Shared helpers for durable regression subprocess chaining."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.regression._paths import LEGACY_OUTPUT_DIR, REPO_ROOT

# Optional local compatibility wrappers under output/ — not required for closure.
LEGACY_VERIFICATION_SCRIPTS: tuple[str, ...] = (
    "_ticket13_verify.py",
    "_ticket15_verify.py",
    "_ticket16_verify.py",
    "_ticket17_verify.py",
    "_ticket19_verify.py",
    "_ticket20_verify.py",
    "_ticket21_verify.py",
)

DEFAULT_LEGACY_TIMEOUT_SECONDS = 120


def run_durable_regression(script_path: Path) -> None:
    """Run a durable regression script and fail fast on non-zero exit."""
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        print(f"REGRESSION FAIL: {script_path.name}\n{output}")
        raise SystemExit(1)
    print(f"  regression: {script_path.name} passed")


def run_legacy_regression_optional(
    script_name: str,
    *,
    timeout_seconds: int = DEFAULT_LEGACY_TIMEOUT_SECONDS,
) -> str:
    """Run an optional legacy output/ script with a bounded timeout.

    Returns one of: ``passed``, ``skipped_missing``, ``failed``, ``timed_out``.
    """
    script = LEGACY_OUTPUT_DIR / script_name
    if not script.is_file():
        print(f"  legacy optional: {script_name} skipped (not present)")
        return "skipped_missing"
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        print(f"  legacy optional: {script_name} timed out after {timeout_seconds}s")
        return "timed_out"
    if proc.returncode != 0:
        print(f"  legacy optional: {script_name} failed\n{proc.stdout}\n{proc.stderr}")
        return "failed"
    print(f"  legacy optional: {script_name} passed")
    return "passed"
