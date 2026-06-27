# .US Locality DNS Discovery Tool

Internal-use **standalone Windows desktop utility** (Python 3.11+) for **unknown child domain discovery** under known 3rd-level `.us` domains from your system.

**Plain-language goal:** use this tool to scan known 3rd-level `.us` domains from our system and look for **child DNS names beneath them that are not already known in the system**.

**What this tool does:** compares known child domains from your input against child DNS names found by live DNS testing, then exports a workbook for human review.

**What this tool cannot prove:** absence of discovered child names is **not** proof that no child domains exist. The tool does not perform complete zone enumeration, passive DNS, OSINT, or web scraping. A few good new examples may be enough for the business question.

## Operator quick-start

1. Open `USLocalityDNSDiscovery.exe` (or run `python app.py` from source).
2. Select a `.txt` or `.csv` file with known 3rd-level domains (recommended enriched CSV below).
3. Choose **Light Evidence** for a first 10–25 domain sample (default).
4. Review **Preflight Summary** (selected domain column, first domains, profile, candidate estimate).
5. Click **Run Scan** and watch the **phase/progress** text.
6. Click **Export Results** → **XLSX workbook (recommended)**.
7. Open **Evidence Review** first (sorted Strong → Moderate → Limited → etc.).
8. Read the **Why** column for plain-English context; use **How to Read** for definitions.
8. Review `new_child_domains_found`, `evidence_value`, and **Verification guidance** (XLSX) / `manual_verification_hint` (CSV/JSON).
9. Use optional dig commands from Verification guidance for independent confirmation when helpful.

## Current status (working prototype)

This version includes a **functional DNS discovery scan engine** with **tiered wordlist source controls**. It performs controlled DNS lookups using `dnspython` when you click **Run Scan**.

What works today:

- **Child domain discovery focus** — compares known system domains vs live DNS-discovered child names
- **Scan profiles** — Light Evidence (fast 10–25 domain sample), Normal Evidence, Deep Targeted
- **Evidence model** — `known_domain`, `name_type`, `evidence_value`, `new_child_domains_found`
- Tkinter desktop GUI with threaded scan execution, phase/progress display, and scrollable layout
- Domain list file picker (`.txt` / `.csv`) with duplicate-header detection and FQDN validation
- **Enriched CSV input** with `domain`, `known_fourth_level_domains`, `known_fifth_level_domains`, and metadata
- Targeted 5th-level probing under known 4th-level domains from input (bounded)
- Optional custom wordlist file with an explicit include checkbox
- Scan options for authoritative NS queries and AXFR attempts
- Configurable **Output Folder** for all export formats
- **Export Results** to XLSX (Evidence Review first), CSV, JSON
- **Cancel Scan** with safe checkpoint cancellation and partial-result export

## Evidence model (workbook)

| Field | Meaning |
|-------|---------|
| `known_domain` | `yes` / `no` — was this discovered name already listed in the input known-child fields? |
| `name_type` | `delegated_child_zone`, `organizational_child_name`, `service_hostname`, `generic_hostname`, `technical_vendor_hostname`, etc. |
| `evidence_value` | `strong`, `moderate`, `limited`, `validation_only`, `context_only`, `none`, `inconclusive` |
| `new_child_domains_found` | Child DNS names found in live DNS that were **not** already known in the system input |
| `known_domains_validated` | Known child domains from input that were confirmed in live DNS |

**How to read names:**

- `www`, `mail`, `autodiscover`, `smtp`, `msoid`, `lyncdiscover` are valid DNS child names but usually **limited** evidence value.
- `police`, `portal`, `library`, `court`, `fire`, etc. are more meaningful organizational examples (**moderate** when new).
- NS/SOA delegated child zones not already known in the system are **strong** evidence.

## Scan profiles

| Profile | Purpose | Typical batch |
|---------|---------|---------------|
| **Light Evidence** | Fast first pass; ~25 high-value labels; AXFR off | 10–25 domains |
| **Normal Evidence** | RFC + Common + Civic wordlists; AXFR optional | 3–10 domains |
| **Deep Targeted** | Broader wordlist controls enabled | 1–3 domains |

Light Evidence is the recommended first run for a pilot sample. Do not run all ~2,000 domains unless intentionally planned.

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
8. Review **Verification guidance** on strong/moderate rows for optional independent dig checks (`manual_verification_hint` in CSV/JSON).
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
| **Enriched CSV** | Header row with `domain` + known-child columns | **Recommended for real use** |

### Recommended enriched CSV (six columns)

For real use, keep the input file focused on what the tool needs:

```csv
domain,delegated_manager,known_fourth_level_domains,known_fifth_level_domains,fourth_level_count,fifth_level_count
state.wv.us,Example Manager,,,0,0
auburn.in.us,Mirage Computers,ci.auburn.in.us,,1,0
```

| Column | Purpose |
|--------|---------|
| `domain` | Known 3rd-level `.us` domain from the system (for example `state.wv.us`) |
| `delegated_manager` | Manager/operator context for the base domain |
| `known_fourth_level_domains` | 4th-level domains already known in the system (semicolon-separated if multiple) |
| `known_fifth_level_domains` | 5th-level domains already known in the system |
| `fourth_level_count` | Count from the system (context only) |
| `fifth_level_count` | Count from the system (context only) |

The tool compares **known domains from the input** against **child DNS names discovered from live DNS**. Keep the input file focused on the domain to scan and the known 4th/5th-level domains already in the system. Extra spreadsheet columns (`zone`, `locality_label`, `second_level_domain`, `companyname`, `sample_reason`, `notes`, etc.) are **not required** for the main purpose.

Leave `known_fourth_level_domains` and `known_fifth_level_domains` blank when none are known. Do not include duplicate domain columns.

**Legacy enriched CSV** — older exports with `third_level_domain`, `companyname`, `fourth_level_domains`, `zone`, and other columns still work. The loader prefers the `domain` column when duplicate domain-like headers exist.

**Domain column detection** — recognized from headers such as `domain`, `third_level_domain`, `domain_name`, or `Domain Name` (case/spacing/underscore insensitive).

Duplicate domains are deduplicated; first-seen metadata is kept. Blank rows and null-like known-domain values (`null`, `N/A`, `*`, etc.) are ignored.

### Known input child domains vs DNS-discovered names

The workbook separates two sources of child-domain information:

| Source | Meaning |
|--------|---------|
| **Known domains from system (input)** | Names in `known_fourth_level_domains` / `known_fifth_level_domains` — already in your system, not new discoveries |
| **DNS-discovered child names (scan)** | Child names found through live DNS testing |

Summary and Evidence Review columns include:

- `known_domains_from_system` — from `known_fourth_level_domains` and `known_fifth_level_domains`
- `known_domains_validated` — known input names confirmed in live DNS
- `new_child_domains_found` — live DNS names **not** already in the input
- `evidence_value` — `strong` / `moderate` / `limited` / `validation_only` / `context_only` / `none` / `inconclusive`
- `analysis_note` — plain-language comparison of input vs live DNS findings

**How to read evidence:**

- **Strong:** new delegated child zone (NS/SOA) not already in the known-child fields
- **Moderate:** new organizational/service child name (for example `police`, `portal`, `library`)
- **Limited:** new generic/technical hostname (for example `www`, `autodiscover`, `mail`) or base-zone-only context
- **validation_only:** known child confirmed in DNS — informational, not a new discovery
- **None / inconclusive:** no useful child-domain evidence, or scan error — rerun before conclusions

Lack of discovered child names does **not** prove absence. Scan a **small targeted subset** using the scan profile guidance above.

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
- Optional: this README or `Quick_Start.txt` (short operator steps)
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
| **Evidence Review** | **Open this first for coworker review.** One row per base domain with human-readable headers, **Why** explanations, and evidence-value highlighting. |
| **How to Read** | Short definitions of Known domain, evidence values, and what the report can and cannot prove. |
| **Summary** | Full per-domain rollup with input context, known/new domain lists, evidence value, scan status, and dig hints. |
| **Findings** | Detailed rows per DNS finding. Readable columns first (Discovered name, Known domain, Name type, Evidence value, Why), then technical fields. |
| **Scan Settings** | Scan profile, input format, evidence model definitions, `packaged_mode`, and `output_folder`. |
| **Errors Warnings** | Domain-level AXFR issues, wildcard warnings, query errors, and partial-scan notices. |

**Coworker review path:** Evidence Review → **How to Read** (if needed) → Summary for detail → Findings for line-item DNS evidence. Focus on **Strong** and **Moderate** rows; **Limited** rows are often generic hostnames; **Validation only** confirms known input domains, not new discoveries.

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
│   ├── light_evidence.txt
│   ├── rfc1480.txt
│   ├── dns_common.txt
│   ├── civic_departments.txt
│   ├── public_services.txt
│   ├── schools_libraries.txt
│   └── delegated_manager_clues.txt
├── output/
├── tests/
│   └── regression/
├── RELEASE.md
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

For source vs packaged EXE workflow, regression tests, and release steps, see
[RELEASE.md](RELEASE.md).
