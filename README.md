# .US Locality DNS Discovery Tool

Internal-use **standalone Windows desktop utility** (Python 3.11+) for discovering visible DNS activity and possible 4th/5th-level subdelegations under externally managed `.us` locality 3rd-level domains.

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
- **Export Results** to timestamped CSV and JSON reports in `output/` after a completed scan

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

## How to run

Requires **Python 3.11+** with Tkinter (included in standard Windows Python installers).

```powershell
cd us_locality_dns_discovery
python -m pip install -r requirements.txt
python app.py
```

Requires `dnspython` (see `requirements.txt`). PyInstaller packaging is planned for a future ticket.

## Scan behavior

For each input domain the tool:

- Queries standard record types on the base domain: NS, SOA, A, AAAA, MX, TXT, CNAME, CAA
- Discovers authoritative nameservers and optionally queries them directly
- Optionally attempts AXFR (refused/timeout/failure is treated as a normal outcome)
- Generates 4th-level candidates from selected wordlist labels (e.g. `ci.example.ky.us`)
- Generates limited 5th-level candidates for `ci`/`co` branches when RFC/locality baseline is selected (e.g. `www.ci.example.ky.us`)
- Tests candidates for NS (possible subdelegation) plus SOA, A, AAAA, MX, TXT, CNAME
- Probes for wildcard DNS using unlikely random names

Conservative DNS timeouts are used (3s per query, 5s lifetime) to avoid hanging the GUI.

## Exporting results

After a scan completes, **Export Results** becomes enabled. Choose **CSV**, **JSON**, or **Both**. Reports are written to `output/` with timestamped filenames such as:

- `us_locality_dns_discovery_YYYYMMDD_HHMMSS.csv`
- `us_locality_dns_discovery_YYYYMMDD_HHMMSS.json`

CSV columns document each finding with scan metadata, wordlist sources, wildcard status, and AXFR status. JSON includes `scan_metadata`, per-domain `findings`, `summary_counts`, and `errors`.

Every report includes this discovery limitation:

> DNS discovery results show only records found through the tested methods. No records discovered does not prove that no subdelegations or DNS records exist.

Reports are created only when you click **Export Results** — scans do not auto-write report files.

## Discovery vs. authoritative truth

**Discovery** means records found through tested methods only.

- **No records discovered using tested methods** does **not** prove that no records or subdelegations exist.
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
├── README.md
├── requirements.txt
└── .gitignore
```

## Out of scope (future tickets)

- PyInstaller packaging
- Web UI, authentication, database, or cloud hosting
- External OSINT tools (Amass, dnsx, subfinder, etc.)

## License / use

Internal prototype. Not approved for merge or deployment.
