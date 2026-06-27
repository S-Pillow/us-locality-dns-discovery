# Durable regression verification

Run from the repository root:

```powershell
python tests/regression/test_ticket24_delegation_verification.py
python tests/regression/test_ticket23_dns_classifier.py
python tests/regression/test_ticket22_parent_gating.py
```

Ticket 24 chains through Ticket 23, which chains through Ticket 22. Ticket 22 may
invoke legacy scripts under `output/` (for example `_ticket20_verify.py`) when
those files exist on disk. Legacy scripts are not source-controlled; durable
Tickets 22–24 live here.

All regression tests use mocked DNS responses. No live network calls are made.

The `output/` folder is for generated scan reports, smoke artifacts, and runtime
outputs — not durable verification logic.
