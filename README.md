# .US Locality DNS Discovery Tool

Internal-use **standalone Windows desktop utility** (Python 3.11+) for discovering visible DNS activity and possible 4th/5th-level subdelegations under externally managed `.us` locality 3rd-level domains.

## Current status (working prototype)

This version includes a **functional DNS discovery scan engine** wired to the Tkinter GUI. It performs controlled DNS lookups using `dnspython` when you click **Run Scan**.

What works today:

- Tkinter desktop GUI with threaded scan execution (GUI stays responsive)
- Domain list file picker (`.txt` / `.csv`) with normalization and `#` comment support
- Optional custom wordlist file picker (`.txt` / `.csv`)
- Scan option checkboxes controlling wordlists, authoritative NS queries, and AXFR attempts
- Real DNS discovery for base domains and generated candidate subdomains
- Progress and results logged to the status area
- Wildcard suspicion detection with lower-confidence marking for affected A/AAAA/CNAME results
- Disabled **Export Results** button (future ticket)

Built-in wordlists are editable text files under `wordlists/`:

| File | Purpose |
|------|---------|
| `rfc1480.txt` | RFC 1480-style locality labels (e.g. `ci`, `co`, `town`) |
| `civic.txt` | Common civic / government service labels |
| `dns_common.txt` | Common DNS host labels (e.g. `www`, `mail`, `portal`) |

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
- Generates 4th-level candidates from wordlists (e.g. `ci.example.ky.us`)
- Generates limited 5th-level candidates for `ci`/`co` branches (e.g. `www.ci.example.ky.us`)
- Tests candidates for NS (possible subdelegation) plus SOA, A, AAAA, MX, TXT, CNAME
- Probes for wildcard DNS using unlikely random names

Conservative DNS timeouts are used (3s per query, 5s lifetime) to avoid hanging the GUI.

## Discovery vs. authoritative truth

**Discovery** means records found through tested methods only.

- **No records discovered using tested methods** does **not** prove that no records or subdelegations exist.
- This tool must not claim complete zone enumeration.
- Reports will use discovery-based language, not assertions of absence.

Some `.us` locality 3rd-level domains are managed by GoDaddy Registry; others are managed by external Delegated Managers. For externally managed localities, internal portal views may not show 4th/5th-level subdelegations even when DNS activity exists in the external zone.

## Project layout

```
us_locality_dns_discovery/
├── app.py                 # GUI entry point
├── scanner/
│   ├── __init__.py
│   ├── models.py          # Scan input/result dataclasses
│   └── scan_engine.py     # DNS discovery engine
├── wordlists/
│   ├── rfc1480.txt
│   ├── civic.txt
│   └── dns_common.txt
├── output/                # Future scan reports (gitignored except .gitkeep)
├── README.md
├── requirements.txt
└── .gitignore
```

## Out of scope (future tickets)

- CSV/JSON export
- PyInstaller packaging
- Web UI, authentication, database, or cloud hosting
- External OSINT tools (Amass, dnsx, subfinder, etc.)

## License / use

Internal prototype. Not approved for merge or deployment.
