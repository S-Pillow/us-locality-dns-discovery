"""PKG.2 automated verification — checks provenance, no-flash path, and bundled wordlists."""
import pathlib, re, sys

ROOT = pathlib.Path(".")

# --- 1. Exe exists ---
exe = ROOT / "dist" / "USLocalityDNSDiscovery.exe"
assert exe.exists(), f"FAIL: exe not found at {exe}"
print(f"[1] Exe exists: {exe.resolve()}")
print(f"    Size: {exe.stat().st_size / 1048576:.1f} MB")

# --- 2. SOURCE_COMMIT stamped correctly (not stale a71f6ad) ---
version_src = (ROOT / "scanner" / "version.py").read_text(encoding="utf-8")
m = re.search(r'^SOURCE_COMMIT\s*=\s*"([^"]+)"', version_src, re.MULTILINE)
assert m, "FAIL: SOURCE_COMMIT not found in version.py"
stamped = m.group(1)
print(f"[2] SOURCE_COMMIT = {stamped!r}")
assert stamped != "a71f6ad", f"FAIL: stale commit a71f6ad still present!"
assert stamped == "542ac83", f"FAIL: expected 542ac83, got {stamped!r}"
print(f"    PASS: not stale (a71f6ad), matches expected HEAD (542ac83)")

# --- 3. APP_VERSION updated ---
m2 = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', version_src, re.MULTILINE)
assert m2, "FAIL: APP_VERSION not found"
version = m2.group(1)
print(f"[3] APP_VERSION = {version!r}")
assert version == "0.26.0", f"FAIL: expected 0.26.0, got {version!r}"
print(f"    PASS")

# --- 4. Memoization cache present ---
assert "_SOURCE_COMMIT_CACHE" in version_src, "FAIL: cache missing from version.py"
print("[4] PASS: _SOURCE_COMMIT_CACHE memoization present")

# --- 5. CREATE_NO_WINDOW present ---
assert "CREATE_NO_WINDOW" in version_src, "FAIL: CREATE_NO_WINDOW missing"
print("[5] PASS: CREATE_NO_WINDOW present in version.py")

# --- 6. Spec is windowed (console=False) ---
spec_src = (ROOT / "USLocalityDNSDiscovery.spec").read_text(encoding="utf-8")
assert "console=False" in spec_src, "FAIL: console=False missing from spec"
print("[6] PASS: spec has console=False")

# --- 7. --batch-verify only in "not exposed" context (no entry_points / scripts list) ---
# It may appear in doc-string bullets/comments to state it is NOT exposed.
# Confirm every occurrence contains "not exposed" or "not surface" nearby.
bv_lines = [l.strip() for l in spec_src.splitlines() if "--batch-verify" in l]
assert all("not exposed" in l or "not surface" in l for l in bv_lines), \
    f"FAIL: --batch-verify in unexpected context: {bv_lines}"
print(f"[7] PASS: --batch-verify only in 'not exposed' doc/comment lines ({len(bv_lines)})")

# --- 8. Stale commit not in spec ---
assert "a71f6ad" not in spec_src, "FAIL: stale commit in spec"
print("[8] PASS: stale commit a71f6ad not in spec")

# --- 9. Build script _build_pkg2.py exists and trackable ---
build_script = ROOT / "_build_pkg2.py"
assert build_script.exists(), "FAIL: _build_pkg2.py missing"
print("[9] PASS: _build_pkg2.py present")

# --- 10. Wordlists are NOT removed (still in source for bundling) ---
wl_dir = ROOT / "wordlists"
wl_files = list(wl_dir.glob("*.txt"))
assert len(wl_files) >= 5, f"FAIL: expected >= 5 wordlists, found {len(wl_files)}"
print(f"[10] PASS: {len(wl_files)} wordlist files present for bundling")

print()
print("=" * 50)
print("PKG.2 VERIFICATION: ALL CHECKS PASS")
print("=" * 50)
