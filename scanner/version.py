"""Application version and build metadata for source and packaged runs."""

from __future__ import annotations

import os
import subprocess

APP_NAME = "US Locality DNS Discovery"
APP_DISPLAY_NAME = ".US Locality DNS Discovery Tool"
APP_VERSION = "0.25.0"
"""Release version for the T31+T32 build (Lane 1 registry matrix + NODATA classification)."""
EVIDENCE_MODEL_VERSION = "2.0-child-domain-discovery"
SOURCE_BUILD_LABEL = "source"

# Stamped at build time by the PKG ticket; matches the release commit on main.
# Source-mode get_source_commit() calls git directly and ignores this value.
# Packaged exe (no git binary) falls back to this constant.
SOURCE_COMMIT = "a71f6ad"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_source_commit() -> str:
    """Return the HEAD commit hash when running from source, or the stamped constant.

    Priority:
      1. Live ``git rev-parse --short HEAD`` (works from source with git).
      2. ``SOURCE_COMMIT`` constant (stamped at build time for packaged exe).
      3. ``"unstamped"`` (fallback if both fail).
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            cwd=_REPO_ROOT,
            timeout=3,
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
            if commit:
                return commit
    except Exception:
        pass
    return SOURCE_COMMIT or "unstamped"
