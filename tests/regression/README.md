# Durable regression verification

Run from the repository root:

```powershell
python tests/regression/test_ticket27_raw_evidence_trace.py
```

That command chains through Tickets 26 → 25 → 24 → 23 → 22 and completes without
hanging. Each script can also be run standalone:

```powershell
python tests/regression/test_ticket26_parent_gating_semantics.py
python tests/regression/test_ticket25_evidence_status_model.py
python tests/regression/test_ticket24_delegation_verification.py
python tests/regression/test_ticket23_dns_classifier.py
python tests/regression/test_ticket22_parent_gating.py
```

## Durable vs legacy

- **Durable tests** live under `tests/regression/` and are required for source
  acceptance (Tickets 22–27).
- **Legacy scripts** under `output/_ticket*.py` are gitignored local convenience
  wrappers. They are **not** required for closure and are **not** invoked by the
  normal durable regression chain.
- Optional legacy checks (bounded timeout, skip if missing) are available via
  `tests/regression/_chain.py` → `run_legacy_regression_optional()`.

All durable regression tests use mocked DNS responses. No live network calls are made.

Full raw evidence trace (`evidence_trace`) is included in JSON export only. CSV/XLSX
workbooks keep existing human-readable columns without per-field trace expansion.

The `output/` folder is for generated scan reports, smoke artifacts, and runtime
outputs — not durable verification logic.
