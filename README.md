# .US Locality DNS Discovery Tool

Internal-use **standalone Windows desktop utility** (Python 3.11+) for discovering visible DNS activity and possible 4th/5th-level subdelegations under externally managed `.us` locality 3rd-level domains.

**What this tool does:** runs controlled DNS lookups against a list of 3rd-level domains and selected candidate labels, then exports discovery evidence for human review.

**What this tool cannot prove:** absence of discovered records is **not** proof that no subdelegations or DNS records exist. The tool does not perform complete zone enumeration, passive DNS, OSINT, or web scraping.

## Operator quick-start

1. Open `USLocalityDNSDiscovery.exe` (or run `python app.py` from source).
2. Select a `.txt` or `.csv` file containing 3rd-level domains (one per line; `#` comments allowed).
3. Choose **Wordlist Sources** for the batch size you are running (see [Recommended batch sizes](#recommended-batch-sizes)).
4. Review the **Preflight Summary** (domains, sources, estimated candidates, warning level).
5. Click **Run Scan**.
6. Wait for completion, or click **Cancel Scan** if you need to stop early (partial results may still be exported).
7. Click **Export Results**.
8. Choose **XLSX workbook (recommended)** for coworker review.
9. Open the workbook and review the **Summary** sheet first, then **Findings** for detail.

## Current status (working prototype)

This version includes a **functional DNS discovery scan engine** with **tiered wordlist source controls**. It performs controlled DNS lookups using `dnspython` when you click **Run Scan**.

What works today:

- Tkinter desktop GUI with threaded scan execution (GUI stays responsive)
- Domain list file picker (`.txt` / `.csv`) with normalization and `#` comment support
- **Wordlist Sources** checkboxes for transparent control over candidate label groups
- Optional custom wordlist file with an explicit include checkbox
- Scan options for authoritative NS queries and AXFR attempts
- Pre-scan logging of selected sources, label counts, and estimated candidate names
- Candidate-count warnings when estimates exceed 250 or 500 names per domain
- Real DNS discovery for base domains and generated candidate subdomains
- Wildcard suspicion detection with lower-confidence marking for affected A/AAAA/CNAME results
- **Export Results** to timestamped **XLSX workbook** (recommended), findings CSV, summary CSV, and JSON in `output/` after a completed scan
- **Preflight summary** with domain/candidate estimates and warning level before scanning
- **Progress bar and live progress text** during scans
- **Cancel Scan** with safe checkpoint cancellation and partial-result export

## Wordlist sources

Built-in wordlists are editable one-label-per-line text files under `wordlists/`:

| File | GUI checkbox | Default |
|------|--------------|---------|
| `rfc1480.txt` | RFC/locality baseline | On |
| `dns_common.txt` | Common DNS/web labels | On |
| `civic_departments.txt` | Civic departments | On |
| `public_services.txt` | Public services / portals | Off |
| `schools_libraries.txt` | Schools / libraries | Off |
| `delegated_manager_clues.txt` | Delegated-manager clues | Off |

**Custom wordlist:** browse for a `.txt` or `.csv` file, then use **Include custom wordlist** to control whether it is merged into the scan. If no file is selected, custom labels are not used. The scan log always shows which sources were included.

Before scanning, the log reports:

- Label count per selected source
- Total unique candidate labels (deduplicated across sources)
- Estimated candidate names per base domain (4th-level + optional 5th-level `ci`/`co` branches)
- Whether 5th-level generation is enabled
- Warnings when candidate estimates exceed 250 or 500

Selected wordlists are **not complete** — they are starting points for discovery only.

## Recommended batch sizes

Plan smaller batches for deeper wordlist coverage. For a full locality list (~157 external-DM domains), run multiple batches rather than one very-large scan.

| Batch type | Domains | Suggested wordlist sources |
|------------|---------|----------------------------|
| **Light scan** | 25–50 | RFC/locality baseline; optionally Common DNS/web labels |
| **Normal evidence scan** | 10–25 | RFC/locality baseline + Common DNS/web labels + Civic departments |
| **Deep scan** | 3–10 | Add Public services, Schools/libraries, Delegated-manager clues, and/or a custom wordlist |

Higher candidate counts mean longer run times. The preflight summary shows estimated candidates per domain and a warning level (`low`, `moderate`, `large`, `very large`). Confirm before starting when totals reach 10,000+ or 50,000+ candidates.

## How to choose wordlist sources

- **RFC/locality baseline** — start here for every batch; enables limited 5th-level `ci`/`co` branch testing.
- **Common DNS/web labels** — adds typical hostnames (`www`, `mail`, `ns1`, etc.); good for light/normal batches.
- **Civic departments** — department-style labels; use for normal evidence scans.
- **Public services / Schools / Delegated-manager clues** — broader label sets; reserve for deep scans on small domain counts.
- **Custom wordlist** — browse for a `.txt` or `.csv` file, then check **Include custom wordlist**. Preflight lists custom labels only when that box is checked.

Turn off sources you do not need to reduce scan time and noise.

## How to run

Requires **Python 3.11+** with Tkinter (included in standard Windows Python installers).

```powershell
cd us_locality_dns_discovery
python -m pip install -r requirements.txt
python app.py
```

Requires `dnspython` and `openpyxl` (see `requirements.txt`).

## Windows EXE packaging

Build a single-file, windowed executable (no console) with PyInstaller:

```powershell
cd us_locality_dns_discovery
python -m pip install -r requirements.txt
.\build_exe.bat
```

Or manually:

```powershell
python -m PyInstaller --noconfirm USLocalityDNSDiscovery.spec
```

Output:

- `dist/USLocalityDNSDiscovery.exe`

Double-click the EXE to launch the GUI. Python does **not** need to be installed on the target PC. The EXE runs windowed (no console window).

### Where reports are saved

| Mode | How to run | Report output folder |
|------|------------|----------------------|
| Source | `python app.py` | `output/` under the project root |
| Packaged EXE | `dist/USLocalityDNSDiscovery.exe` | `output/` next to the EXE (e.g. `dist/output/`) |

### Packaged paths and wordlists

| Mode | Built-in wordlists | Report output |
|------|-------------------|---------------|
| Source (`python app.py`) | Editable files in `wordlists/` | `output/` under project root |
| Packaged EXE | Bundled read-only defaults (PyInstaller `_MEIPASS`) | `output/` next to the EXE |

Custom wordlists remain selectable through the GUI file picker in both modes. Reports are **never** written to PyInstaller’s temporary extraction folder.

`build/`, `dist/`, generated `.exe` files, and scan reports are gitignored and must not be committed.

## Scan behavior

For each input domain the tool:

- Queries standard record types on the base domain: NS, SOA, A, AAAA, MX, TXT, CNAME, CAA
- Discovers authoritative nameservers and optionally queries them directly
- Optionally attempts AXFR (refused/timeout/failure is treated as a normal outcome)
- Generates 4th-level candidates from selected wordlist labels (e.g. `ci.example.ky.us`)
- Generates limited 5th-level candidates for `ci`/`co` branches when RFC/locality baseline is selected (e.g. `www.ci.example.ky.us`)
- Tests candidates for NS (delegated child zone) plus SOA, A, AAAA, MX, TXT, CNAME
- Captures SOA records from the DNS AUTHORITY section when the queried record type has no ANSWER (zone exists even without an apex A record)
- Probes for wildcard DNS using unlikely random names

Conservative DNS timeouts are used (3s per query, 5s lifetime) to avoid hanging the GUI.

## Exporting results

After a scan completes or is cancelled with partial results, **Export Results** becomes enabled.

**For coworker review, use the XLSX workbook** — it is the primary operator deliverable with Summary, Findings, settings, and warnings in one file.

Choose export format:

- **XLSX workbook (recommended)** — operator-facing Excel review package
- **Findings CSV** — technical findings export (15-column contract)
- **JSON** — advanced/debugging export
- **All formats** — XLSX, findings CSV, summary CSV, and JSON

Reports are written to the [output folder for your mode](#where-reports-are-saved) with timestamped filenames such as:

- `us_locality_dns_report_YYYYMMDD_HHMMSS.xlsx`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS.csv`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS_summary.csv`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS.json`

### XLSX workbook sheets

| Sheet | Purpose |
|-------|---------|
| **Summary** | **Start here.** One row per base domain with `scan_status`, evidence summary, nameserver/AXFR/wildcard flags, and counts. Use this sheet to triage which domains need follow-up. |
| **Findings** | Detailed rows for each discovered record, candidate test, or notable outcome (same columns as findings CSV). Use after Summary to inspect individual DNS evidence. |
| **Scan Settings** | Scan metadata, wordlist sources, DNS timeouts, completion/cancellation flags, and the discovery limitation note. |
| **Errors Warnings** | Domain-level AXFR issues, wildcard warnings, query errors, and partial-scan notices. |

Summary `scan_status` values use discovery-based wording such as *Possible delegated child zone discovered*, *DNS activity discovered*, *DNS activity discovered with scan errors*, *Base domain zone exists*, *Base domain records only*, *Scan incomplete / error*, *Scan errors only*, and *No records discovered using tested methods*. Row highlighting is applied for readability; status text carries the meaning.

**Summary columns to compare:**

| Column | Meaning |
|--------|---------|
| `base_zone_exists` | `true` when an SOA proves the base zone exists, even if no apex A record was found |
| `delegated_child_zones_found` | Count of candidate child names with NS records (delegated child zones) |
| `dns_names_with_records_found` | Count of base/candidate names with DNS records such as A/AAAA/CNAME/MX/TXT/SOA |
| `standard_records_found` | Count of non-NS record findings on tested candidate names |

**DNS activity vs. delegated child zones:** DNS activity means records such as A, AAAA, CNAME, MX, TXT, or SOA were found on the base domain or a candidate name. A delegated child zone requires an NS record on a candidate child name (for example `ci.example.pa.us`). Finding `www.example.pa.us` with an A record is DNS activity, not a delegated child zone.

**SOA / zone evidence:** A domain can have an authoritative SOA and exist as a zone even when the requested record type (such as A) has no ANSWER. SOA evidence means the zone exists under tested methods; it is not the same as finding a delegated child zone.

**Scan errors:** If a domain hits an unexpected scan error (for example `EOF`), its status is reported as *Scan incomplete / error* or *Scan errors only*, not as a clean no-result. Rerun affected domains before drawing conclusions.

**Actual 3rd-level domains:** When evaluating externally managed `.us` locality activity, prefer scanning your real 3rd-level domain list in small batches rather than placeholder domains. Some externally delegated zones may not be visible to public recursive resolvers until their authoritative nameservers are queried.

**Summary vs. Findings:** Summary is the per-domain rollup for batch review; Findings is the line-item evidence behind those rollups.

Every report includes:

> DNS discovery results show only records found through the tested methods. No records discovered does not prove that no subdelegations or DNS records exist.

Reports are created only when you click **Export Results** — scans do not auto-write report files.

### Cancellation and partial results

If you click **Cancel Scan**, the engine stops at the next safe checkpoint (between domains or during candidate batches). The log notes that the scan was cancelled and how many domains completed.

When at least one domain finished before cancellation:

- **Export Results** is enabled
- The XLSX **Scan Settings** sheet records `scan_cancelled=true`, `scan_completed=false`, and `partial_results=true`
- The **Errors Warnings** sheet includes a partial-scan notice
- Summary and Findings contain only domains scanned before cancellation

Partial exports are still valid discovery evidence for the domains that completed; they do not represent the full input list.

## Large scan controls

Before starting, the **Preflight Summary** shows:

- Domains loaded
- Selected wordlist sources
- Estimated candidate names per domain and total
- AXFR / authoritative NS settings
- Warning level: `low`, `moderate`, `large`, or `very large`

Confirmation is required when the estimated total candidate names is **10,000+** (large) or **50,000+** (very large). For example, ~157 domains with default wordlists (~428 candidates each) is about **67,000** total candidates and triggers the very-large warning.

During a scan:

- **Run Scan** and **Export Results** are disabled
- **Cancel Scan** requests cancellation at the next safe checkpoint (between domains or during candidate batches)
- Partial results may be exported if at least one domain completed before cancellation
- Exported reports note when results are partial/cancelled

## Discovery vs. authoritative truth

**Discovery** means records found through tested methods only.

- **No records discovered using tested methods** does **not** prove that no records or subdelegations exist. A domain may have labels the wordlists never tested, records only visible from other vantage points, or activity outside this tool’s query scope.
- **SOA evidence** means the zone exists under tested methods, even when no apex A/AAAA answer is present.
- **DNS activity discovered** (A/AAAA/CNAME/MX/TXT/SOA on a name) is not the same as **delegated child zone discovered** (NS on a candidate child name).
- This tool must not claim complete zone enumeration.
- Reports use discovery-based language, not assertions of absence.

Some `.us` locality 3rd-level domains are managed by GoDaddy Registry; others are managed by external Delegated Managers. For externally managed localities, internal portal views may not show 4th/5th-level subdelegations even when DNS activity exists in the external zone.

## Project layout

```
us_locality_dns_discovery/
├── app.py
├── scanner/
│   ├── __init__.py
│   ├── models.py
│   ├── paths.py
│   ├── scan_engine.py
│   └── export_service.py
├── wordlists/
│   ├── rfc1480.txt
│   ├── dns_common.txt
│   ├── civic_departments.txt
│   ├── public_services.txt
│   ├── schools_libraries.txt
│   └── delegated_manager_clues.txt
├── output/
├── USLocalityDNSDiscovery.spec
├── build_exe.bat
├── README.md
├── requirements.txt
└── .gitignore
```

## Out of scope (future tickets)

- Web UI, authentication, database, or cloud hosting
- External OSINT tools (Amass, dnsx, subfinder, etc.)

## License / use

Internal prototype. Not approved for merge or deployment.
