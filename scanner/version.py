"""Application version and build metadata for source and packaged runs."""

from __future__ import annotations

import os
import subprocess

APP_NAME = "US Locality DNS Discovery"
APP_DISPLAY_NAME = ".US Locality DNS Discovery Tool"
APP_VERSION = "0.24.0-source"
EVIDENCE_MODEL_VERSION = "2.0-child-domain-discovery"
SOURCE_BUILD_LABEL = "source"

# Kept for packaging tickets that inject a static hash at build time.
# Source-mode code must call get_source_commit() instead of reading this.
SOURCE_COMMIT = "cfc987e"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_source_commit() -> str:
    """Return the HEAD commit hash when running from source, or 'unstamped'.

    Falls back to 'unstamped' when git is unavailable (packaged EXE, no git
    binary, or running outside a repository).
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
            return result.stdout.strip()
    except Exception:
        pass
    return "unstamped"
