# .US Locality DNS Discovery Tool

Internal-use **standalone Windows desktop utility** (Python 3.11+) for discovering visible DNS activity and possible 4th/5th-level subdelegations under externally managed `.us` locality 3rd-level domains.

## Current status (prototype scaffold)

This first version is a **UI and project scaffold only**. It does **not** perform live DNS lookups, zone transfers (AXFR), or any external network calls.

What works today:

- Tkinter desktop GUI
- Domain list file picker (`.txt` / `.csv`)
- Optional custom wordlist file picker (`.txt` / `.csv`)
- Scan option checkboxes (stored for future use)
- Input validation and status logging
- Placeholder **Run Scan** flow that reports: *Scan engine not implemented in this ticket.*
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
python app.py
```

No third-party packages are required for this ticket. See `requirements.txt` for planned future dependencies (`dnspython`, `PyInstaller`).

## Future scan behavior (not implemented yet)

Planned discovery targets include:

- DNS records on the 3rd-level locality domain itself
- Possible 4th-level subdelegations (e.g. `ci.locality.state.us`, `co.locality.state.us`)
- Possible 5th-level names (e.g. `www.ci.locality.state.us`)
- Record types: NS, SOA, A, AAAA, MX, TXT, CNAME, CAA
- AXFR results when zone transfer is allowed
- Direct queries to authoritative nameservers

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
│   └── scan_engine.py     # Placeholder engine (future ticket)
├── wordlists/
│   ├── rfc1480.txt
│   ├── civic.txt
│   └── dns_common.txt
├── output/                # Future scan reports (gitignored except .gitkeep)
├── README.md
├── requirements.txt
└── .gitignore
```

## Out of scope for this ticket

- Live DNS queries or AXFR
- CSV/JSON export
- PyInstaller packaging
- Web UI, authentication, database, or cloud hosting
- External OSINT tools (Amass, dnsx, subfinder, etc.)

## License / use

Internal prototype. Not approved for merge or deployment.
