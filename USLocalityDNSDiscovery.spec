# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for US Locality DNS Discovery Tool.

Build command: pyinstaller USLocalityDNSDiscovery.spec
Packaged artifact: dist/USLocalityDNSDiscovery.exe

Release version: 0.25.0
Source commit: a71f6ad  (main, post-T32: T31 Lane-1 registry matrix + T32 NODATA classification)

Verification:
  USLocalityDNSDiscovery.exe --batch-verify
  Windowed build: output written to batch_verify_report.txt (beside the exe or in output/).
  Console/source build: output goes to stdout as before.
"""

block_cipher = None

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=[
        # Wordlists: all 7 label files (civic_departments, delegated_manager_clues,
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
    # console=False: windowed operator build — no console on double-click.
    # --batch-verify detects the no-stdout context and writes to a file instead.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
