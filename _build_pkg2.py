"""PKG.2 build script — stamps SOURCE_COMMIT then runs PyInstaller.

Usage (run from repo root with git available):
    python _build_pkg2.py

What it does:
  1. Reads the real HEAD commit hash via git rev-parse --short HEAD.
  2. Rewrites the SOURCE_COMMIT line in scanner/version.py with that hash
     so the bundled exe reports its true provenance without a runtime git call.
  3. Clears the module-level _SOURCE_COMMIT_CACHE (no-op at build time;
     documents intent).
  4. Runs:  python -m PyInstaller USLocalityDNSDiscovery.spec --noconfirm
  5. Prints the artifact path and stamped commit for the §18.13 record.

The in-place edit of version.py is intentional — PyInstaller bundles the
source file as-is, so the constant must be correct *before* the build.
Commit scanner/version.py (with the stamped hash) alongside this build run
so the release branch carries the provenance record.

Note: dist/ and build/ are gitignored; only the .spec and version.py are
tracked.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


VERSION_PY = pathlib.Path("scanner/version.py")
SPEC_FILE = "USLocalityDNSDiscovery.spec"


def _get_head_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _stamp_version_py(commit: str) -> None:
    text = VERSION_PY.read_text(encoding="utf-8")
    pattern = re.compile(r'^(SOURCE_COMMIT\s*=\s*")[^"]*(")', re.MULTILINE)
    if not pattern.search(text):
        raise RuntimeError(
            f"SOURCE_COMMIT pattern not found in {VERSION_PY}; cannot stamp."
        )
    patched = pattern.sub(rf"\g<1>{commit}\g<2>", text)
    VERSION_PY.write_text(patched, encoding="utf-8")
    print(f"[stamp] {VERSION_PY}: SOURCE_COMMIT = {commit!r}")


def _run_pyinstaller() -> None:
    cmd = [sys.executable, "-m", "PyInstaller", SPEC_FILE, "--noconfirm"]
    print(f"[build] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main() -> None:
    commit = _get_head_commit()
    print(f"[build] HEAD commit: {commit}")

    _stamp_version_py(commit)
    _run_pyinstaller()

    artifact = pathlib.Path("dist/USLocalityDNSDiscovery.exe")
    size_mb = artifact.stat().st_size / 1_048_576 if artifact.exists() else -1
    print()
    print("=" * 60)
    print("PKG.2 BUILD COMPLETE")
    print(f"  Artifact : {artifact.resolve()}")
    print(f"  Size     : {size_mb:.1f} MB")
    print(f"  Commit   : {commit}")
    print(f"  Spec     : {SPEC_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
