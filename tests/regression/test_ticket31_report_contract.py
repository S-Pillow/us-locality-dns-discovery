#!/usr/bin/env python3
"""Ticket 31 verification: report/contract integrity.

Confirms:
- confirmed counter counts only confirmed-status records (negative-action guard)
- no diagnostic row appears on the Findings sheet / confirmed-findings CSV
- a diagnostic row for a known-input name exports known_domain=yes
- a cancelled single-domain run sets partial_results=true
- source_commit in all export formats matches git rev-parse --short HEAD (or labeled fallback)

All DNS interactions are synthetic (mocked); no live network calls occur.
"""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.regression._chain import run_durable_regression
from tests.regression._paths import REGRESSION_DIR, REPO_ROOT

from scanner.evidence_status import is_confirmed_evidence_status, resolve_evidence_status
from scanner.export_service import (
    CSV_COLUMNS,
    build_confirmed_findings_rows,
    build_diagnostics_rows,
    build_json_document,
    build_summary_rows,
    export_csv,
    export_diagnostics_csv,
    export_json,
    export_xlsx_report,
)
from scanner.models import (
    CancellationToken,
    DiscoveredRecord,
    DomainInputRecord,
    DomainScanResult,
    EvidenceOutcome,
    EvidenceStatus,
    FindingClassification,
    RecordType,
    ScanInput,
    ScanOptions,
    ScanProfile,
    ScanRunResult,
    ScanStatus,
    WordlistPlan,
)
from scanner.paths import get_wordlists_dir
from scanner.version import get_source_commit


# ---------------------------------------------------------------------------
# Shared fixture builder
# ---------------------------------------------------------------------------

def _minimal_scan_input(domain_file: Path, output_dir: Path) -> ScanInput:
    return ScanInput(
        domain_file_path=domain_file,
        options=ScanOptions(scan_profile=ScanProfile.LIGHT),
        output_dir=output_dir,
        wordlists_dir=get_wordlists_dir(),
    )


def _make_result(
    base_domain: str,
    records: list[DiscoveredRecord],
    evidence_outcomes: list[EvidenceOutcome] | None = None,
    *,
    input_record: DomainInputRecord | None = None,
    candidates_tested: int = 4,
    output_dir: Path | None = None,
) -> ScanRunResult:
    """Build a minimal ScanRunResult containing one DomainScanResult."""
    domain_result = DomainScanResult(
        domain=base_domain,
        records=records,
        evidence_outcomes=evidence_outcomes or [],
        candidates_tested=candidates_tested,
        input_record=input_record,
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, dir=output_dir
    ) as f:
        f.write(f"{base_domain}\n")
        domain_file = Path(f.name)

    out = output_dir or Path(tempfile.mkdtemp())
    scan_input = _minimal_scan_input(domain_file, out)
    result = ScanRunResult(
        input=scan_input,
        domain_results=[domain_result],
        scan_timestamp=datetime(2026, 1, 1, 0, 0, 0),
        scan_status=ScanStatus.COMPLETED,
        wordlist_plan=WordlistPlan(
            total_unique_labels=4,
            estimated_candidates_per_domain=4,
        ),
        domains_total=1,
        domains_planned=[base_domain],
        domain_inputs=[],
    )
    return result


def _confirmed_a_record(fqdn: str, base: str) -> DiscoveredRecord:
    """A confirmed standard A-record finding."""
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.A,
        value="1.2.3.4",
        source_method="generated_candidate",
        classification=FindingClassification.STANDARD_RECORD,
        evidence_status=EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME,
    )


def _query_error_record(fqdn: str) -> DiscoveredRecord:
    """A QUERY_ERROR record — diagnostic, not a confirmed finding."""
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=None,
        value="timed out",
        source_method="generated_candidate",
        classification=FindingClassification.QUERY_ERROR,
        evidence_status=EvidenceStatus.INCONCLUSIVE_DNS_FAILURE,
    )


def _axfr_blocked_record(fqdn: str) -> DiscoveredRecord:
    """An AXFR_BLOCKED record — diagnostic, not a confirmed finding."""
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=None,
        value="AXFR blocked by server",
        source_method="axfr",
        classification=FindingClassification.AXFR_BLOCKED,
    )


def _authoritative_ns_record(fqdn: str) -> DiscoveredRecord:
    """An AUTHORITATIVE_NS record — confirmed (KNOWN_DOMAIN_VALIDATED)."""
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.NS,
        value="ns1.example.ma.us.",
        source_method="authoritative_nameserver",
        classification=FindingClassification.AUTHORITATIVE_NS,
        evidence_status=EvidenceStatus.KNOWN_DOMAIN_VALIDATED,
    )


def _skipped_outcome(fqdn: str, parent: str) -> EvidenceOutcome:
    return EvidenceOutcome(
        fqdn=fqdn,
        evidence_status=EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        source_method="generated_candidate",
        detail=f"Skipped: parent {parent} did not validate",
    )


# ---------------------------------------------------------------------------
# Negative-action guard (core contract test)
# ---------------------------------------------------------------------------

def test_confirmed_counter_excludes_diagnostics() -> None:
    """QUERY_ERROR + AXFR_BLOCKED must not be counted in total_findings.

    AUTHORITATIVE_NS → KNOWN_DOMAIN_VALIDATED → is confirmed, so it IS counted.
    """
    base = "ci.example.ma.us"
    confirmed_a = _confirmed_a_record(f"portal.{base}", base)
    auth_ns = _authoritative_ns_record(base)
    query_err = _query_error_record(f"mail.{base}")
    axfr_blk = _axfr_blocked_record(base)

    # QUERY_ERROR + AXFR_BLOCKED are diagnostic; STANDARD_RECORD +
    # AUTHORITATIVE_NS are confirmed → expected confirmed count = 2
    expected_confirmed = 2

    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_result(
            base,
            [confirmed_a, auth_ns, query_err, axfr_blk],
            output_dir=Path(tmpdir),
        )

        # --- export layer counter check ---
        from scanner.export_service import _domain_summary_counts

        counts = _domain_summary_counts(result.domain_results[0])
        assert counts["total_findings"] == expected_confirmed, (
            f"total_findings={counts['total_findings']} but expected {expected_confirmed}; "
            f"QUERY_ERROR and AXFR_BLOCKED must not be counted as findings"
        )

        # --- confirmed-findings rows: no diagnostic row ---
        confirmed_rows = build_confirmed_findings_rows(result)
        for row in confirmed_rows:
            ev = row.get("evidence_status", "")
            assert ev not in (
                EvidenceStatus.INCONCLUSIVE_DNS_FAILURE.value,
                EvidenceStatus.CANDIDATE_TESTED.value,
                EvidenceStatus.SKIPPED_BY_PARENT_GATING.value,
                EvidenceStatus.IGNORED_UNRELATED_AUTHORITY.value,
            ), (
                f"Diagnostic row with evidence_status={ev!r} must not appear "
                f"on the Findings sheet"
            )

        # --- diagnostics rows: only non-confirmed ---
        diag_rows = build_diagnostics_rows(result)
        for row in diag_rows:
            ev = row.get("evidence_status", "")
            ft = row.get("finding_type", "")
            # not_recorded rows (e.g. AXFR_BLOCKED) may have evidence_status NOT_RECORDED
            status_val = ev or EvidenceStatus.NOT_RECORDED.value
            if status_val != EvidenceStatus.NOT_RECORDED.value:
                resolved = EvidenceStatus(status_val)
                assert not is_confirmed_evidence_status(resolved), (
                    f"Confirmed status {status_val!r} must not appear on Diagnostics sheet"
                )

    print("confirmed counter and sheet separation: OK")


def test_no_diagnostic_row_on_findings_csv() -> None:
    """EvidenceOutcome diagnostic rows must not appear in confirmed-findings CSV."""
    base = "ci.example.ma.us"
    confirmed_a = _confirmed_a_record(f"portal.{base}", base)
    skipped = _skipped_outcome(f"mail.{base}", base)

    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_result(
            base,
            [confirmed_a],
            evidence_outcomes=[skipped],
            output_dir=Path(tmpdir),
        )

        csv_path, row_count = export_csv(result, Path(tmpdir))
        with csv_path.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)

        for row in rows:
            assert row.get("evidence_status") != EvidenceStatus.SKIPPED_BY_PARENT_GATING.value, (
                "SKIPPED_BY_PARENT_GATING row must not appear in confirmed-findings CSV"
            )
            assert row.get("name_type") != "diagnostic", (
                "diagnostic name_type must not appear in confirmed-findings CSV"
            )

        # diagnostics CSV must contain the skipped outcome
        diag_path = export_diagnostics_csv(result, Path(tmpdir))
        with diag_path.open(encoding="utf-8") as fh:
            diag_reader = csv.DictReader(fh)
            diag_rows = list(diag_reader)

        diag_statuses = {r.get("evidence_status") for r in diag_rows}
        assert EvidenceStatus.SKIPPED_BY_PARENT_GATING.value in diag_statuses, (
            "SKIPPED_BY_PARENT_GATING outcome must appear in diagnostics CSV"
        )

    print("no diagnostic row on findings CSV: OK")


# ---------------------------------------------------------------------------
# Known-input label on diagnostic rows
# ---------------------------------------------------------------------------

def test_diagnostic_known_domain_label() -> None:
    """A diagnostic row for a known-input name must export known_domain=yes."""
    base = "ci.example.ma.us"
    known_child = f"portal.{base}"
    unknown_child = f"mail.{base}"

    input_record = DomainInputRecord(
        domain=base,
        original_domain=base,
        known_fourth_level_domains=[known_child],
    )

    skipped_known = _skipped_outcome(known_child, base)
    skipped_unknown = _skipped_outcome(unknown_child, base)

    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_result(
            base,
            [],
            evidence_outcomes=[skipped_known, skipped_unknown],
            input_record=input_record,
            output_dir=Path(tmpdir),
        )

        diag_rows = build_diagnostics_rows(result)
        by_fqdn = {r["tested_name"]: r for r in diag_rows}

        assert known_child in by_fqdn, f"Expected diagnostic row for {known_child}"
        assert by_fqdn[known_child]["known_domain"] == "yes", (
            f"Diagnostic row for known-input {known_child!r} must export known_domain=yes, "
            f"got {by_fqdn[known_child]['known_domain']!r}"
        )

        if unknown_child in by_fqdn:
            assert by_fqdn[unknown_child]["known_domain"] == "no", (
                f"Diagnostic row for unknown {unknown_child!r} must export known_domain=no"
            )

    print("diagnostic known_domain label: OK")


# ---------------------------------------------------------------------------
# partial_results — single-domain mid-scan cancel
# ---------------------------------------------------------------------------

def test_partial_results_single_domain_cancel() -> None:
    """A cancelled single-domain scan must set partial_results=true.

    partial_results=True for any cancellation: even if a domain started, the
    operator interrupted the scan so results are partial.  This covers
    single-domain and last-domain mid-scan cancels.
    """
    from scanner.scan_engine import run_scan

    token = CancellationToken()
    call_count: list[int] = [0]

    def _mock_send(fqdn, record_type, resolver):
        call_count[0] += 1
        if call_count[0] >= 2:
            token.cancel()
        return None, f"{fqdn} {record_type.value}: mocked no-response"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        domain_file = tmpdir_path / "domains.txt"
        domain_file.write_text("ci.example.ma.us\n", encoding="utf-8")

        scan_input = ScanInput(
            domain_file_path=domain_file,
            options=ScanOptions(scan_profile=ScanProfile.LIGHT),
            output_dir=tmpdir_path,
            wordlists_dir=get_wordlists_dir(),
        )

        with patch("scanner.scan_engine._send_dns_query", side_effect=_mock_send):
            result = run_scan(scan_input, cancel_token=token)

        assert result.cancelled is True, "Expected scan to be marked cancelled"
        assert result.partial is True, (
            f"Expected partial_results=True for single-domain mid-scan cancel; "
            f"got partial={result.partial}"
        )

    print("partial_results single-domain cancel: OK")


# ---------------------------------------------------------------------------
# source_commit in all three export formats
# ---------------------------------------------------------------------------

def test_source_commit_in_all_formats() -> None:
    """source_commit must appear in JSON, XLSX Scan Settings, and summary CSV."""
    base = "ci.example.ma.us"
    confirmed_a = _confirmed_a_record(f"portal.{base}", base)
    expected_commit = get_source_commit()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        result = _make_result(base, [confirmed_a], output_dir=tmpdir_path)

        # JSON
        doc = build_json_document(result)
        json_commit = doc["scan_metadata"].get("source_commit")
        assert json_commit == expected_commit, (
            f"JSON scan_metadata.source_commit={json_commit!r} "
            f"expected {expected_commit!r}"
        )
        assert json_commit not in (None, ""), "source_commit must not be empty in JSON"
        assert json_commit != "d46779c", (
            "source_commit must not be the stale hardcoded value d46779c"
        )

        # Summary CSV
        summary_rows = build_summary_rows(result)
        assert summary_rows, "Expected at least one summary row"
        csv_commit = summary_rows[0].get("source_commit")
        assert csv_commit == expected_commit, (
            f"Summary CSV source_commit={csv_commit!r} expected {expected_commit!r}"
        )

        # XLSX Scan Settings (check via build_settings_rows)
        from scanner.export_service import build_settings_rows

        settings = dict(build_settings_rows(result))
        xlsx_commit = settings.get("source_commit")
        assert xlsx_commit == expected_commit, (
            f"XLSX Scan Settings source_commit={xlsx_commit!r} expected {expected_commit!r}"
        )

    print(f"source_commit in all formats: OK (commit={expected_commit!r})")


# ---------------------------------------------------------------------------
# JSON findings[] / evidence_diagnostics[] separation preserved
# ---------------------------------------------------------------------------

def test_json_findings_diagnostics_separation() -> None:
    """JSON findings[] must contain only confirmed records; diagnostics[] get their own key."""
    base = "ci.example.ma.us"
    confirmed_a = _confirmed_a_record(f"portal.{base}", base)
    query_err = _query_error_record(f"mail.{base}")
    skipped = _skipped_outcome(f"smtp.{base}", base)

    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_result(
            base,
            [confirmed_a, query_err],
            evidence_outcomes=[skipped],
            output_dir=Path(tmpdir),
        )

        doc = build_json_document(result)
        domain_doc = doc["domains"][0]

        findings = domain_doc.get("findings", [])
        diagnostics = domain_doc.get("evidence_diagnostics", [])

        for f in findings:
            ev = f.get("evidence_status", "")
            if ev:
                resolved = EvidenceStatus(ev)
                assert is_confirmed_evidence_status(resolved), (
                    f"JSON findings[] contains non-confirmed status {ev!r}"
                )

        diag_statuses = {d.get("evidence_status") for d in diagnostics}
        assert EvidenceStatus.SKIPPED_BY_PARENT_GATING.value in diag_statuses, (
            "SKIPPED_BY_PARENT_GATING must appear in JSON evidence_diagnostics[]"
        )

        # summary_counts.total_findings must agree with confirmed findings count
        counts = domain_doc.get("summary_counts", {})
        confirmed_in_json = len([
            f for f in findings
            if f.get("finding_type") != FindingClassification.NO_RECORDS_DISCOVERED.value
        ])
        assert counts.get("total_findings") == confirmed_in_json, (
            f"summary_counts.total_findings={counts.get('total_findings')} "
            f"but JSON findings[] has {confirmed_in_json} non-empty rows"
        )

    print("JSON findings/diagnostics separation: OK")


# ---------------------------------------------------------------------------
# Regression chain
# ---------------------------------------------------------------------------

def _run_ticket27_regression() -> None:
    run_durable_regression(REGRESSION_DIR / "test_ticket27_raw_evidence_trace.py")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("Ticket 31: report/contract integrity verification")
    print("  [chain] running T22–T27 durable regressions...")
    _run_ticket27_regression()
    print("  [chain] T22–T27 passed")

    test_confirmed_counter_excludes_diagnostics()
    test_no_diagnostic_row_on_findings_csv()
    test_diagnostic_known_domain_label()
    test_partial_results_single_domain_cancel()
    test_source_commit_in_all_formats()
    test_json_findings_diagnostics_separation()

    print("All Ticket 31 contract tests passed.")


if __name__ == "__main__":
    main()
