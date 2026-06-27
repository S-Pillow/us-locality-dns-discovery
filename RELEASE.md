# Release and verification — US Locality DNS Discovery

This project is a **standalone Windows desktop app** (Python 3.11+ / Tkinter),
packaged with PyInstaller. It is **not** a web application.

## Source of truth

- **Local Git** at the repository root is the only source control boundary today.
- **No remote** is configured. Commits exist on this machine only until a remote
  is added deliberately.
- **Cursor chat transcripts and workspace metadata are not source control.**

## How to run

| Mode | Command / path | Reflects latest source? |
|------|----------------|-------------------------|
| **Source** | `python app.py` from repo root | Yes |
| **Packaged** | `dist/USLocalityDNSDiscovery.exe` | Only after rebuild |

Source changes **do not** update the EXE automatically.

## Durable regression tests

Location: `tests/regression/`

```powershell
cd C:\Users\steven\us_locality_dns_discovery
python tests/regression/test_ticket24_delegation_verification.py
```

See `tests/regression/README.md` for the full list. Tests use mocked DNS only.
Source acceptance runs durable scripts under `tests/regression/`; gitignored
`output/_ticket*.py` legacy wrappers are optional and not part of the chain.

## Output folder policy

`output/` is for:

- Generated scan CSV/XLSX/JSON reports
- Smoke-test fixtures and temporary artifacts
- Runtime outputs beside the app

`output/` is **not** for durable verification scripts. Do not force-track regression
tests under `output/` after Ticket 24A.

Generated reports and `output/*` remain gitignored (except `output/.gitkeep`).

## Building the packaged EXE

When explicitly approved for a release ticket (not part of ordinary feature work):

```powershell
cd C:\Users\steven\us_locality_dns_discovery
.\build_exe.bat
```

Output: `dist/USLocalityDNSDiscovery.exe` (windowed GUI, no console).

PyInstaller intermediates under `build/` and the EXE under `dist/` must not be
committed.

## Release workflow (local desktop model)

1. Accept source on a stable local branch (for example `main` when created).
2. Update `scanner/version.py` (`APP_VERSION`) to reflect the accepted release
   version. **Do not update `SOURCE_COMMIT` manually** — it is now derived at
   runtime (see Version metadata below).
3. Run durable regression tests from `tests/regression/`.
4. Rebuild EXE with `build_exe.bat`.
5. **Verify the rebuilt EXE** — packaged mode behaves differently from
   `python app.py`. Do not assume source-only verification covers the EXE.
6. Copy `USLocalityDNSDiscovery.exe` (+ optional `Quick_Start.txt`) to the
   operator install location. Reports default to `output/` beside the EXE.

There is no auto-update mechanism.

## Version metadata

Source-controlled fields live in `scanner/version.py`:

- `APP_VERSION` — human-readable build label (for example `0.24.0-source`)
- `EVIDENCE_MODEL_VERSION` — evidence workbook model identifier
- `SOURCE_BUILD_LABEL` — `source` or future packaged label
- `SOURCE_COMMIT` — static fallback value used only by packaging tickets that
  inject a commit hash at build time; **not used for source-mode reporting**

Reports include `app_version`, `source_build_label`, and `source_commit` in
Scan Settings (XLSX), in JSON `scan_metadata`, and in the summary CSV when
exported.

In **source mode**, `source_commit` is derived at runtime by calling
`get_source_commit()` (added Ticket 31), which runs `git rev-parse --short HEAD`
and returns the live HEAD hash. If git is unavailable (packaged EXE, no git
binary, or outside a repository), the value falls back to `"unstamped"`.
Packaged-build commit stamping is a packaging-ticket concern and handled
separately from source-mode reporting.

JSON scan reports include structured `evidence_trace` arrays on findings and
`evidence_diagnostics` entries for auditability. CSV/XLSX workbooks remain
summary-oriented; use JSON for full raw DNS evidence trace.

## Packaged verification expectations

Before handing an EXE to an operator:

- Launch the **rebuilt** EXE locally.
- Confirm Scan Settings shows expected version metadata.
- Run approved regression or smoke checks; **live DNS scans require explicit
  operator approval**.

## What not to commit

- `dist/`, `build/`
- Generated CSV/XLSX/JSON scan reports
- Secrets, `.env`, operator runtime data
- `__pycache__/`
