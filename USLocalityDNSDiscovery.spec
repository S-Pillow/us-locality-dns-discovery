# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for US Locality DNS Discovery Tool - PKG.2 windowed operator build.

Build command (use _build_pkg2.py to stamp SOURCE_COMMIT first):
    python _build_pkg2.py

Release version: 0.26.0
Source commit: stamped at build time by _build_pkg2.py (git rev-parse --short HEAD).

Windowed operator build:
  - console=False: no console window on launch or during any operation including export.
  - --batch-verify is intentionally not exposed in this artifact (code preserved in source).
  - All wordlists bundled; no runtime git subprocess (provenance is a baked-in constant).
"""

block_cipher = None

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=[
        # Wordlists: all label files bundled (civic_departments,
        # dns_common, light_evidence, public_services, rfc1480, schools_libraries).
        ("wordlists", "wordlists"),
    ],
    hiddenimports=[
        "dns",
        "dns.resolver",
        "dns.query",
        "dns.zone",
        "dns.rdatatype",
        "dns.rdataclass",
        "dns.rcode",
        "dns.name",
        "dns.message",
        "dns.flags",
        "dns.rdataset",
        "dns.rrset",
        "dns.exception",
        "openpyxl",
        "openpyxl.styles",
        "openpyxl.utils",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="USLocalityDNSDiscovery",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    # console=False: windowed operator build.
    # No console window on launch, during scan, or during export.
    # --batch-verify code is preserved in source but not exposed in this artifact.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
