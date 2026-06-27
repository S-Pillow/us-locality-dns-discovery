"""Shared paths for durable regression scripts under tests/regression/."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REGRESSION_DIR = Path(__file__).resolve().parent
LEGACY_OUTPUT_DIR = REPO_ROOT / "output"
