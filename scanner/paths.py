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


def get_default_output_dir() -> Path:
    """Default writable output directory beside the app or project root."""
    return get_app_base_dir() / "output"


def ensure_output_dir(path: Path) -> tuple[bool, str]:
    """
    Create the output directory if needed and verify it is writable.

    Returns (success, message).
    """
    target = path.resolve()
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"Could not create output folder: {target} ({exc})"

    probe = target / ".write_test"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        return False, f"Output folder is not writable: {target} ({exc})"

    return True, f"Output folder OK: {target}"


def get_output_dir() -> Path:
    """Return the default output directory, creating it when possible."""
    output_dir = get_default_output_dir()
    ok, message = ensure_output_dir(output_dir)
    if not ok:
        raise OSError(message)
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
