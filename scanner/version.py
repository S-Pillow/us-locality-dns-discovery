"""Application version and build metadata for source and packaged runs."""

from __future__ import annotations

import os
import subprocess
import sys

APP_NAME = "US Locality DNS Discovery"
APP_DISPLAY_NAME = ".US Locality DNS Discovery Tool"
APP_VERSION = "0.26.0"
"""Release version for PKG.2: WC-FIX/WC-FIX.1/WL-TRIM/PARENT-GATE/EXPORT-REDESIGN/WC-FIX2/DELETE-DM."""
EVIDENCE_MODEL_VERSION = "2.0-child-domain-discovery"
SOURCE_BUILD_LABEL = "source"

# Stamped at build time by _build_pkg2.py before PyInstaller runs.
# The build script writes git rev-parse --short HEAD into this constant so
# the packaged exe (which cannot call git) reports its true provenance.
# Source-mode get_source_commit() reads live git and ignores this value.
SOURCE_COMMIT = "542ac83"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Module-level cache so get_source_commit() only shells out once per process.
# Prevents repeated subprocess spawns during export (one call per domain/row
# without caching), which on a windowed exe would pop a console window per call.
_SOURCE_COMMIT_CACHE: str | None = None


def get_source_commit() -> str:
    """Return the HEAD commit hash when running from source, or the stamped constant.

    Priority:
      1. Module cache (populated on first call — avoids repeated subprocess spawns).
      2. Live ``git rev-parse --short HEAD`` (works from source with git).
      3. ``SOURCE_COMMIT`` constant (stamped at build time for packaged exe).
      4. ``"unstamped"`` (fallback if both fail).

    Windows note: the subprocess call uses ``CREATE_NO_WINDOW`` so the git
    child process never pops a console window in a windowed (``console=False``)
    exe build.  Combined with the build-time stamp this subprocess is never
    reached in the packaged exe at all — the belt-and-suspenders guard is for
    any future path that calls this at runtime from a windowed context.
    """
    global _SOURCE_COMMIT_CACHE
    if _SOURCE_COMMIT_CACHE is not None:
        return _SOURCE_COMMIT_CACHE

    try:
        kwargs: dict = dict(
            capture_output=True,
            text=True,
            cwd=_REPO_ROOT,
            timeout=3,
        )
        if sys.platform == "win32":
            # Prevent the git subprocess from opening a console window when
            # called from a windowed (console=False) PyInstaller exe.
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], **kwargs)
        if result.returncode == 0:
            commit = result.stdout.strip()
            if commit:
                _SOURCE_COMMIT_CACHE = commit
                return _SOURCE_COMMIT_CACHE
    except Exception:
        pass

    _SOURCE_COMMIT_CACHE = SOURCE_COMMIT or "unstamped"
    return _SOURCE_COMMIT_CACHE
