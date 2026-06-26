"""Application path helpers for source and PyInstaller-packaged runs."""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    """Return True when running from a PyInstaller-built executable."""
    return bool(getattr(sys, "frozen", False))


def get_app_base_dir() -> Path:
    """
    Writable application base directory.

    Packaged: directory containing the EXE.
    Source: project root directory.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_output_dir() -> Path:
    """Writable output directory for scan reports."""
    output_dir = get_app_base_dir() / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def resource_path(relative_path: str | Path) -> Path:
    """
    Resolve a bundled or project resource path.

    Packaged read-only resources live under sys._MEIPASS.
    Source resources live under the project root.
    """
    relative = Path(relative_path)
    if is_frozen():
        bundle_root = Path(getattr(sys, "_MEIPASS", get_app_base_dir()))
        return bundle_root / relative
    return get_app_base_dir() / relative


def get_wordlists_dir() -> Path:
    """Directory containing built-in wordlist resource files."""
    return resource_path("wordlists")
