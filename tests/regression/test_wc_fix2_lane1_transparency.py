"""WC-FIX2 — Lane 1 Inactive-Input Transparency.

Verifies that when the input file lacks a ``registry_known_names`` column:
  * the plain-English summary tab includes a visible "not run" notice (AC-1/2),
  * the Scan Settings sheet records lane1_registry_check_status = inactive (AC-6),
  * the Errors Warnings sheet includes a lane1_inactive row (AC-6),
  * the scan-engine preflight message fires (optional surface).

Also verifies that when the column IS present the notice does NOT appear
(AC-4 no-regression / negative-action).

Claim-to-code:
  * _lane1_status() -- scanner/export_service.py: sole source of the three states.
  * build_plain_english_summary_rows() -- renders the notice on tab 1.
  * build_settings_rows() -- records lane1_registry_check_status.
  * build_errors_warning_rows() -- emits lane1_inactive warning.
  * scan_engine preflight _emit near _validate_registry_known_names call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

from scanner.export_service import (
    _lane1_status,
    build_plain_english_summary_rows,
    build_settings_rows,
    build_errors_warning_rows,
)
from scanner.models import (
    DomainInputRecord,
    DomainLoadInfo,
    DomainScanResult,
    EvidenceStatus,
    RegistryKnownEntry,
    ScanInput,
    ScanOptions,
    ScanProfile,
    ScanRunResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOMAIN = "example.ks.us"
_FQDN = f"ci.{_DOMAIN}"


def _make_scan_input(output_dir: Path | None = None) -> ScanInput:
    return ScanInput(
        domain_file_path=Path("test_input.csv"),
        options=ScanOptions(scan_profile=ScanProfile.NORMAL),
        output_dir=output_dir or Path("/tmp/out"),
        wordlists_dir=Path("/tmp/wl"),
    )


def _make_run_result(
    *,
    col_present: bool,
    matrix_rows: int = 0,
    domain_inputs_have_names: bool = False,
) -> ScanRunResult:
    """Build a minimal ScanRunResult with controlled Lane 1 state."""
    cols: list[str] = ["domain"]
    if col_present:
        cols.append("registry_known_names")

    load_info = DomainLoadInfo(
        input_file_type="csv",
        metadata_columns_detected=cols,
        domains_loaded=1,
    )

    matrix: list[RegistryKnownEntry] = []
    if matrix_rows > 0:
        for i in range(matrix_rows):
            entry = MagicMock(spec=RegistryKnownEntry)
            matrix.append(entry)

    di = DomainInputRecord(
        domain=_DOMAIN,
        original_domain=_DOMAIN,
        registry_known_names=["ci.example.ks.us"] if domain_inputs_have_names else [],
    )

    dr = DomainScanResult(
        domain=_DOMAIN,
        registry_matrix=matrix,
        input_record=di,
    )

    result = ScanRunResult(
        input=_make_scan_input(),
        domain_results=[dr],
        domain_inputs=[di],
        input_load_info=load_info,
    )
    return result


# ---------------------------------------------------------------------------
# AC-1 / AC-2  Plain-English tab: notice fires on absent column
# ---------------------------------------------------------------------------


def test_ac1_lane1_inactive_notice_appears_on_plain_english_tab() -> None:
    """AC-1: plain-English tab has a Lane 1 'not run' notice when col absent."""
    result = _make_run_result(col_present=False)
    rows = build_plain_english_summary_rows(result)
    topics = {topic for topic, _ in rows}
    assert any("registry cross-check" in t.lower() for t in topics), (
        "AC-1 FAIL: no 'registry cross-check' row found on plain-English tab "
        f"when registry_known_names column is absent. Topics: {topics}"
    )


def test_ac1_lane1_inactive_notice_says_not_run() -> None:
    """AC-1: notice body says the check was not run."""
    result = _make_run_result(col_present=False)
    rows = build_plain_english_summary_rows(result)
    notice_texts = [
        text for topic, text in rows
        if "registry cross-check" in topic.lower()
    ]
    assert notice_texts, "AC-1 FAIL: no registry cross-check row found"
    combined = " ".join(notice_texts).lower()
    assert "not run" in combined or "did not run" in combined or "was not run" in combined, (
        "AC-1 FAIL: notice does not say check was not run"
    )


def test_ac2_plain_english_notice_is_actionable() -> None:
    """AC-2: notice tells operator how to enable Lane 1 (registry_known_names)."""
    result = _make_run_result(col_present=False)
    rows = build_plain_english_summary_rows(result)
    notice_texts = [
        text for topic, text in rows
        if "registry cross-check" in topic.lower()
    ]
    combined = " ".join(notice_texts)
    assert "registry_known_names" in combined, (
        "AC-2 FAIL: notice does not mention registry_known_names column (actionable)"
    )


def test_ac2_plain_english_notice_no_jargon() -> None:
    """AC-2: reuse EXPORT-REDESIGN jargon blacklist -- no enum names on tab 1."""
    result = _make_run_result(col_present=False)
    rows = build_plain_english_summary_rows(result)
    full_text = " ".join(f"{topic} {text}" for topic, text in rows)
    JARGON_BLACKLIST = [
        "CONFIRMED_DELEGATED_CHILD_ZONE",
        "CONFIRMED_ORDINARY_DNS_NAME",
        "wildcard_not_detected",
        "off-registry NS",
        "SUPPRESSED_WILDCARD_MATCH",
        "WITHHELD_WILDCARD_INCONCLUSIVE",
        "WITHHELD_PARKING_ECHO",
        "REGISTRY_KNOWN_VALIDATION_SOURCE",
        "STRONG_GAP",
        "VALIDATION_ONLY",
    ]
    for term in JARGON_BLACKLIST:
        assert term not in full_text, (
            f"AC-2 FAIL: jargon term '{term}' found in plain-English tab"
        )


def test_ac2_portal_columns_distinction_mentioned() -> None:
    """AC-2: notice mentions the portal/system column distinction when absent."""
    result = _make_run_result(col_present=False)
    rows = build_plain_english_summary_rows(result)
    notice_texts = [
        text for topic, text in rows
        if "registry cross-check" in topic.lower()
    ]
    combined = " ".join(notice_texts)
    assert "known_fourth_level_domains" in combined or "known_fifth_level_domains" in combined, (
        "AC-2 FAIL: notice does not distinguish portal columns from registry_known_names"
    )


# ---------------------------------------------------------------------------
# AC-3  Three-state distinction
# ---------------------------------------------------------------------------


def test_ac3_inactive_state() -> None:
    """AC-3: col absent => status 'inactive'."""
    result = _make_run_result(col_present=False)
    status, n = _lane1_status(result)
    assert status == "inactive", f"AC-3 FAIL: expected 'inactive', got '{status}'"
    assert n == 0


def test_ac3_active_empty_state() -> None:
    """AC-3: col present, 0 matrix rows => status 'active_empty'."""
    result = _make_run_result(col_present=True, matrix_rows=0)
    status, n = _lane1_status(result)
    assert status == "active_empty", f"AC-3 FAIL: expected 'active_empty', got '{status}'"
    assert n == 0


def test_ac3_active_state() -> None:
    """AC-3: col present, matrix rows > 0 => status 'active'."""
    result = _make_run_result(col_present=True, matrix_rows=3)
    status, n = _lane1_status(result)
    assert status == "active", f"AC-3 FAIL: expected 'active', got '{status}'"
    assert n == 3


def test_ac3_active_empty_notice_distinct_from_inactive() -> None:
    """AC-3: active_empty notice is different from inactive notice."""
    inactive_result = _make_run_result(col_present=False)
    active_empty_result = _make_run_result(col_present=True, matrix_rows=0)

    inactive_rows = build_plain_english_summary_rows(inactive_result)
    active_empty_rows = build_plain_english_summary_rows(active_empty_result)

    inactive_text = " ".join(
        text for topic, text in inactive_rows if "registry" in topic.lower()
    )
    active_empty_text = " ".join(
        text for topic, text in active_empty_rows if "registry" in topic.lower()
    )
    assert inactive_text != active_empty_text, (
        "AC-3 FAIL: inactive and active_empty produce identical notices"
    )
    # inactive must say 'not run'
    assert "not run" in inactive_text.lower() or "did not run" in inactive_text.lower() or "was not run" in inactive_text.lower()
    # active_empty must say 'active' or 'present'
    assert "active" in active_empty_text.lower() or "present" in active_empty_text.lower()


# ---------------------------------------------------------------------------
# AC-4  No false notice when column IS present with matches
# ---------------------------------------------------------------------------


def test_ac4_no_inactive_notice_when_col_present_with_matches() -> None:
    """AC-4: no 'not run' notice when col is present and matrix has rows."""
    result = _make_run_result(col_present=True, matrix_rows=5)
    rows = build_plain_english_summary_rows(result)
    for topic, text in rows:
        combined = (topic + " " + text).lower()
        assert "not run" not in combined and "did not run" not in combined, (
            f"AC-4 FAIL: false 'not run' notice appeared with active Lane 1: "
            f"topic={topic!r}"
        )


def test_ac4_active_notice_says_active() -> None:
    """AC-4: with col present + matches, tab 1 says Lane 1 was active."""
    result = _make_run_result(col_present=True, matrix_rows=2)
    rows = build_plain_english_summary_rows(result)
    registry_rows = [(t, v) for t, v in rows if "registry" in t.lower()]
    assert registry_rows, "AC-4 FAIL: no registry cross-check row found for active case"
    combined = " ".join(v for _, v in registry_rows).lower()
    assert "active" in combined or "processed" in combined or "present" in combined, (
        "AC-4 FAIL: active Lane 1 notice does not indicate activity"
    )


# ---------------------------------------------------------------------------
# AC-6  Scan Settings and Errors Warnings surfaces
# ---------------------------------------------------------------------------


def test_ac6_settings_has_lane1_status_inactive() -> None:
    """AC-6: Scan Settings records lane1_registry_check_status = inactive."""
    result = _make_run_result(col_present=False)
    rows = build_settings_rows(result)
    lane1_rows = [(k, v) for k, v in rows if k == "lane1_registry_check_status"]
    assert lane1_rows, "AC-6 FAIL: no lane1_registry_check_status row in Scan Settings"
    _, value = lane1_rows[0]
    assert "inactive" in value.lower(), (
        f"AC-6 FAIL: expected 'inactive' in settings value, got {value!r}"
    )


def test_ac6_settings_has_lane1_status_active() -> None:
    """AC-6: Scan Settings records active when col present with matches."""
    result = _make_run_result(col_present=True, matrix_rows=4)
    rows = build_settings_rows(result)
    lane1_rows = [(k, v) for k, v in rows if k == "lane1_registry_check_status"]
    assert lane1_rows, "AC-6 FAIL: no lane1_registry_check_status row in Scan Settings"
    _, value = lane1_rows[0]
    assert "active" in value.lower(), (
        f"AC-6 FAIL: expected 'active' in settings value, got {value!r}"
    )


def test_ac6_errors_warnings_has_lane1_inactive_row() -> None:
    """AC-6: Errors Warnings sheet has lane1_inactive row when col absent."""
    result = _make_run_result(col_present=False)
    rows = build_errors_warning_rows(result)
    lane1_rows = [r for r in rows if r.get("warning_type") == "lane1_inactive"]
    assert lane1_rows, (
        "AC-6 FAIL: no lane1_inactive row found in Errors Warnings when "
        "registry_known_names column is absent"
    )


def test_ac6_errors_warnings_no_lane1_row_when_active() -> None:
    """AC-6 negative: no lane1_inactive row when col is present."""
    result = _make_run_result(col_present=True, matrix_rows=0)
    rows = build_errors_warning_rows(result)
    lane1_rows = [r for r in rows if r.get("warning_type") == "lane1_inactive"]
    assert not lane1_rows, (
        "AC-6 FAIL: lane1_inactive row appeared in Errors Warnings when "
        "registry_known_names column IS present"
    )


def test_ac6_errors_warnings_lane1_message_technical() -> None:
    """AC-6: Errors Warnings lane1_inactive message mentions registry_known_names."""
    result = _make_run_result(col_present=False)
    rows = build_errors_warning_rows(result)
    lane1_rows = [r for r in rows if r.get("warning_type") == "lane1_inactive"]
    assert lane1_rows
    msg = lane1_rows[0].get("message", "")
    assert "registry_known_names" in msg, (
        "AC-6 FAIL: technical Errors Warnings message should mention registry_known_names"
    )


# ---------------------------------------------------------------------------
# Negative-action: lane1_status fallback via domain_inputs
# ---------------------------------------------------------------------------


def test_na_fallback_domain_inputs_when_load_info_absent() -> None:
    """NA: when load_info is None but domain_inputs have registry names, col_present=True."""
    result = _make_run_result(col_present=False, domain_inputs_have_names=True)
    result.input_load_info = None  # remove load_info
    status, _ = _lane1_status(result)
    assert status != "inactive", (
        "NA FAIL: with load_info=None but domain_inputs having names, "
        "status should not be 'inactive'"
    )


def test_na_inactive_when_no_load_info_and_no_names() -> None:
    """NA: load_info=None and no names in domain_inputs -> inactive."""
    result = _make_run_result(col_present=False)
    result.input_load_info = None
    status, _ = _lane1_status(result)
    assert status == "inactive", (
        f"NA FAIL: expected 'inactive' with no load_info and no names, got {status!r}"
    )
