# Durable regression verification

Run from the repository root:

```powershell
python tests/regression/test_ticket27_raw_evidence_trace.py
python tests/regression/test_ticket26_parent_gating_semantics.py
python tests/regression/test_ticket25_evidence_status_model.py
python tests/regression/test_ticket24_delegation_verification.py
python tests/regression/test_ticket23_dns_classifier.py
python tests/regression/test_ticket22_parent_gating.py
```

Ticket 27 chains through Ticket 26, which chains through Ticket 25, which chains
through Ticket 24, which chains through Ticket 23, which chains through Ticket 22.
Ticket 22 may invoke legacy scripts under `output/` (for example `_ticket20_verify.py`)
when those files exist on disk. Legacy scripts are not source-controlled; durable
Tickets 22–27 live here.

All regression tests use mocked DNS responses. No live network calls are made.

Full raw evidence trace (`evidence_trace`) is included in JSON export only. CSV/XLSX
workbooks keep existing human-readable columns without per-field trace expansion.

The `output/` folder is for generated scan reports, smoke artifacts, and runtime
outputs — not durable verification logic.
