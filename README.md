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
- **Enriched CSV input** with spreadsheet metadata (delegated manager, zone, known 4th/5th-level domains) carried into XLSX Summary
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

Higher candidate counts mean longer run times. The preflight summary shows estimated candidates per domain and a scan-size label (`small`, `moderate`, `large`, `very large`) with operator guidance. Confirm before starting when totals reach 10,000+ or 50,000+ candidates.

## Recommended Evidence Workflow

Use this workflow for coworker-ready visibility-gap evidence from a **small targeted sample**, not the full ~2,000-domain list:

1. Start with a **small enriched CSV sample** exported from your spreadsheet (not the full list).
2. Prefer **10–25 actual externally managed 3rd-level domains** for the first run.
3. Include a **mix of Delegated Managers** when possible.
4. Use **normal evidence settings**:
   - RFC/locality baseline **ON**
   - Common DNS/web labels **ON**
   - Civic departments **ON** for locality/government domains
   - Schools/libraries **ON** only for school/K12-related domains
   - AXFR **ON**
   - Authoritative NS querying **ON**
5. Export **XLSX** after the scan completes or is cancelled with partial results.
6. Open the **Evidence Review** sheet first (rows are sorted strong → moderate → limited → inconclusive → none).
7. Sort or filter by `evidence_support_level` if you need to re-prioritize within Summary.
8. Manually verify a few **strong/moderate** rows using the `manual_verification_hint` dig commands.
9. **Rerun inconclusive/error rows** before drawing conclusions.
10. Word conclusions carefully:
    - The scan can support that DNS activity may exist outside registry/locality portal visibility.
    - The scan does **not** provide complete zone enumeration.
    - **No records discovered** does not prove absence.

## Performance and safety

- **You do not need to scan all ~2,000 domains** for this evidence task. A small sample with strong examples is enough.
- **Large scans take a long time** because DNS queries run sequentially with conservative timeouts.
- **Suggested batch sizes for evidence work:**
  - **10–25 domains** — normal evidence batches (recommended starting point)
  - **5–10 domains** — deep targeted batches with more wordlist sources
  - **25–50 domains** — light settings only (RFC baseline + maybe Common DNS)
- **Cancel Scan** preserves partial results; export them if at least one domain completed.
- **Scan errors** (`Scan incomplete / error`) should be **rerun** before conclusions.
- **AXFR refused/blocked/timeout** is normal and is **not** a scan failure by itself.

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

## Domain input files

The tool accepts three input shapes:

| Input type | Format | Notes |
|------------|--------|-------|
| **TXT** | One domain per line | `#` comments supported |
| **Simple CSV** | One domain per row (first column) | No header row required |
| **Enriched CSV** | Header row with domain + metadata columns | Metadata is preserved in XLSX Summary |

**Enriched CSV domain column** — detected automatically from headers such as `third_level_domain`, `domain`, `domain_name`, `Domain Name`, or `Third Level Domain` (case/spacing/underscore insensitive).

**Recognized metadata columns** (preserved when present):

- `second_level_domain`
- `zone`
- `companyname` / `delegated_manager` (exported as `delegated_manager`)
- `fourth_level_domains` / `fifth_level_domains` (semicolon-separated lists)
- `fourth_level_count` / `fifth_level_count`

Duplicate domains are deduplicated; first-seen metadata is kept. Blank rows are ignored. If an enriched CSV has no recognizable domain column, validation fails with a clear error.

Use enriched CSV when scanning a sample from a larger spreadsheet so the workbook can explain **why each domain matters** (delegated manager, zone, known child domains) alongside DNS findings.

### Known input child domains vs DNS-discovered names

The workbook separates two sources of child-domain information:

| Source | Meaning |
|--------|---------|
| **Known child domains (input)** | 4th/5th-level names already listed in your spreadsheet (`fourth_level_domains`, `fifth_level_domains`). These are system-known, not new discoveries. |
| **DNS-discovered child names (scan)** | Child names found through live DNS testing (`standard_record`, `delegated_child_zone`, candidate `zone_soa_discovered`, AXFR child records). |

Summary comparison columns include:

- `known_child_domains_from_input` — normalized names from input metadata
- `dns_discovered_child_names` — child names found by the scan
- `dns_discovered_child_names_not_in_input` — live DNS names **not** listed in the input (strongest visibility-gap evidence)
- `delegated_child_zones_not_in_input` — NS-based child zones not listed in the input
- `evidence_support_level` — `strong` / `moderate` / `limited` / `none` / `inconclusive` support for the visibility-gap claim
- `analysis_note` — plain-language comparison of input metadata vs live DNS findings

**How to read evidence:**

- **Strong:** delegated child zone or AXFR child name found that was not in the input child-domain fields.
- **Moderate:** other DNS-discovered child activity not listed in the input.
- **Limited:** base-zone evidence only, or DNS activity only on input-known child names.
- **None / inconclusive:** no useful DNS evidence, or scan error — rerun before drawing conclusions.

Lack of DNS-discovered names does **not** prove absence of activity. Scan a **small targeted subset** (not all ~2,000 domains) using the batch guidance above.

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

| Mode | Default output folder | Operator override |
|------|----------------------|-------------------|
| Source | `output/` under the project root | Use **Output Folder** in the GUI to choose any writable folder (including a network share) |
| Packaged EXE | `output/` next to the EXE | Same **Output Folder** picker; set a shared path before export if needed |

Reports never write to PyInstaller’s temporary `_MEIPASS` folder. The GUI **Preflight Summary** and log show the selected output folder before you scan or export.

## Coworker handoff (packaged EXE)

For handing the tool to a coworker who will run the packaged EXE:

**What the coworker needs**

- `USLocalityDNSDiscovery.exe`
- Optional: this README or a short Quick Start note
- Optional: a custom wordlist file **only if** they need extra labels beyond the built-in defaults

**What they do not need**

- Python installed
- A separate `wordlists/` folder for built-in labels — packaged mode bundles read-only default wordlists inside the EXE

**Where reports go**

- By default: `output/` beside the EXE (for example `dist\output\` if the EXE lives in `dist\`)
- To save elsewhere: use **Output Folder → Browse…** and pick a local or shared folder before **Export Results**
- Use **Open Folder** to open the selected output directory after export

**Network share / SmartScreen tips**

- If running directly from a network share causes Windows SmartScreen, Defender, or permission issues:
  1. Copy `USLocalityDNSDiscovery.exe` to a local folder (for example `C:\Tools\USLocalityDNS\`)
  2. Run the EXE locally
  3. Set **Output Folder** to the shared team folder where reports should land

**Custom wordlists**

- Built-in wordlists are bundled in packaged mode and are not editable after packaging.
- To use additional labels, browse for a custom `.txt` or `.csv` wordlist in the GUI — no project `wordlists/` copy is required unless the coworker wants to edit built-in defaults in source mode.

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

Reports are written to the **selected Output Folder** (default shown in the GUI) with timestamped filenames such as:

- `us_locality_dns_report_YYYYMMDD_HHMMSS.xlsx`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS.csv`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS_summary.csv`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS.json`

### XLSX workbook sheets

| Sheet | Purpose |
|-------|---------|
| **Summary** | Full per-domain rollup with input metadata, DNS evidence counts, comparison fields, `evidence_support_level`, `recommended_review_action`, and `manual_verification_hint`. |
| **Evidence Review** | **Open this first for coworker review.** Short prioritized view (strong → moderate → limited → inconclusive → none) with review actions and dig hints. |
| **Findings** | Detailed rows for each discovered record, candidate test, or notable outcome (same columns as findings CSV). |
| **Scan Settings** | Scan metadata, input file type, detected metadata columns, limitation notes, and recommended review path. |
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
- Scan size: `small`, `moderate`, `large`, or `very large`

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
