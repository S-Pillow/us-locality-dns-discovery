"""DELETE-DM-CLUES — Remove Delegated Manager Clues from UI, Config, Docs, and Candidate Surface.

AIPF Ticket DELETE-DM-CLUES.  Durable negative-action (NA) and acceptance-criteria
tests covering the complete removal of the ``delegated_manager_clues`` candidate-source
concept.

NA/AC index:
  NA-1   UI/setup model does not include delegated-manager clues field.
  NA-2   Normal profile does not include delegated-manager clues.
  NA-3   Light profile does not include delegated-manager clues.
  NA-4   Deep profile does not include delegated-manager clues.
  NA-5   Candidate-source construction cannot produce delegated_manager_clues.
  NA-6   New scan settings do not export delegated-manager clues.
  NA-7   Logs do not list delegated-manager clues as a wordlist source.
  NA-8   Legacy include_delegated_manager_clues input, if encountered, raises TypeError
         so callers know to update (field is fully removed, not silently ignored).
  NA-9   Delegation verifier import remains intact.
  NA-10  Input-metadata delegated_manager field on DomainInputRecord is preserved.
  NA-11  Grep-based claim-to-code: no active candidate-source references remain.
"""

from __future__ import annotations

import importlib
import pathlib
import sys

import pytest

# ---------------------------------------------------------------------------
# Paths / imports
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
WORDLISTS_DIR = REPO_ROOT / "wordlists"

# Ensure repo root is on path for imports
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanner.models import ScanOptions, ScanProfile, DomainInputRecord  # noqa: E402
from scanner.scan_engine import (  # noqa: E402
    WORDLIST_SOURCES,
    apply_scan_profile,
)


# ---------------------------------------------------------------------------
# NA-1  ScanOptions does not have include_delegated_manager_clues field.
# ---------------------------------------------------------------------------


def test_na1_scan_options_field_absent():
    """NA-1: ScanOptions must not have include_delegated_manager_clues attribute."""
    opts = ScanOptions()
    assert not hasattr(opts, "include_delegated_manager_clues"), (
        "NA1 FAIL: ScanOptions must not have include_delegated_manager_clues "
        "(DELETE-DM-CLUES ticket removed the field)"
    )


# ---------------------------------------------------------------------------
# NA-2  Normal profile does not include delegated-manager clues.
# ---------------------------------------------------------------------------


def test_na2_normal_profile_no_delegated_manager():
    """NA-2: Normal profile ScanOptions must not reference delegated_manager_clues."""
    opts = ScanOptions(scan_profile=ScanProfile.NORMAL)
    resolved = apply_scan_profile(opts)
    assert not hasattr(resolved, "include_delegated_manager_clues"), (
        "NA2 FAIL: Normal profile result must not have include_delegated_manager_clues"
    )


# ---------------------------------------------------------------------------
# NA-3  Light profile does not include delegated-manager clues.
# ---------------------------------------------------------------------------


def test_na3_light_profile_no_delegated_manager():
    """NA-3: Light profile ScanOptions must not reference delegated_manager_clues."""
    opts = ScanOptions(scan_profile=ScanProfile.LIGHT)
    resolved = apply_scan_profile(opts)
    assert not hasattr(resolved, "include_delegated_manager_clues"), (
        "NA3 FAIL: Light profile result must not have include_delegated_manager_clues"
    )


# ---------------------------------------------------------------------------
# NA-4  Deep profile does not include delegated-manager clues.
# ---------------------------------------------------------------------------


def test_na4_deep_profile_no_delegated_manager():
    """NA-4: Deep profile ScanOptions must not reference delegated_manager_clues."""
    opts = ScanOptions(scan_profile=ScanProfile.DEEP)
    resolved = apply_scan_profile(opts)
    assert not hasattr(resolved, "include_delegated_manager_clues"), (
        "NA4 FAIL: Deep profile result must not have include_delegated_manager_clues"
    )


# ---------------------------------------------------------------------------
# NA-5  WORDLIST_SOURCES cannot produce delegated_manager_clues candidates.
# ---------------------------------------------------------------------------


def test_na5_wordlist_sources_excludes_delegated_manager():
    """NA-5: WORDLIST_SOURCES must not reference include_delegated_manager_clues."""
    option_fields = {entry[0] for entry in WORDLIST_SOURCES}
    wordlist_files = {entry[2] for entry in WORDLIST_SOURCES}
    assert "include_delegated_manager_clues" not in option_fields, (
        "NA5 FAIL: include_delegated_manager_clues must not be in WORDLIST_SOURCES option fields"
    )
    assert "delegated_manager_clues.txt" not in wordlist_files, (
        "NA5 FAIL: delegated_manager_clues.txt must not be in WORDLIST_SOURCES file list"
    )


def test_na5b_wordlist_file_does_not_exist():
    """NA-5b: delegated_manager_clues.txt must not exist in the wordlists directory."""
    clues_path = WORDLISTS_DIR / "delegated_manager_clues.txt"
    assert not clues_path.exists(), (
        f"NA5b FAIL: {clues_path} must be deleted (DELETE-DM-CLUES ticket)"
    )


# ---------------------------------------------------------------------------
# NA-6  Scan settings export does not contain delegated-manager clues key.
# ---------------------------------------------------------------------------


def test_na6_build_settings_rows_no_delegated_manager(tmp_path):
    """NA-6: build_settings_rows must not include any delegated_manager_clues key."""
    from scanner.export_service import build_settings_rows
    from scanner.models import (
        ScanRunResult,
        ScanStatus,
        ScanInput,
        DomainLoadInfo,
    )

    scan_input = ScanInput(
        domain_file_path=tmp_path / "domains.csv",
        options=ScanOptions(scan_profile=ScanProfile.NORMAL),
        output_dir=tmp_path,
        wordlists_dir=WORDLISTS_DIR,
    )
    result = ScanRunResult(
        input=scan_input,
        scan_timestamp=None,
        domain_results=[],
        domain_inputs=[],
        scan_status=ScanStatus.COMPLETED,
    )
    rows = build_settings_rows(result)
    keys = [row[0] for row in rows]
    assert "include_delegated_manager_clues" not in keys, (
        "NA6 FAIL: include_delegated_manager_clues must not appear in scan settings rows"
    )
    assert not any("delegated_manager_clues" in k for k in keys), (
        "NA6 FAIL: no settings key must contain 'delegated_manager_clues'"
    )
    assert not any("Delegated" in str(v) and "clue" in str(v).lower() for _, v in rows), (
        "NA6 FAIL: no settings value must mention delegated-manager clues"
    )


# ---------------------------------------------------------------------------
# NA-7  Wordlist source display text does not mention delegated-manager clues.
# ---------------------------------------------------------------------------


def test_na7_wordlist_source_display_names_clean():
    """NA-7: WORDLIST_SOURCES display names must not mention delegated-manager or manager clues."""
    display_names = [entry[1].lower() for entry in WORDLIST_SOURCES]
    bad = [n for n in display_names if "delegated" in n or "manager clue" in n]
    assert not bad, (
        f"NA7 FAIL: WORDLIST_SOURCES display names must not mention delegated-manager clues: {bad}"
    )


# ---------------------------------------------------------------------------
# NA-8  Constructing ScanOptions with include_delegated_manager_clues keyword
#       raises TypeError (field is fully removed, not silently ignored).
# ---------------------------------------------------------------------------


def test_na8_scan_options_rejects_legacy_keyword():
    """NA-8: ScanOptions() with include_delegated_manager_clues=True must raise TypeError."""
    with pytest.raises(TypeError):
        ScanOptions(include_delegated_manager_clues=True)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# NA-9  Delegation verifier module is still importable and functional.
# ---------------------------------------------------------------------------


def test_na9_delegation_verifier_importable():
    """NA-9: scanner.delegation_verifier must import without error."""
    mod = importlib.import_module("scanner.delegation_verifier")
    assert mod is not None, "NA9 FAIL: delegation_verifier must be importable"


def test_na9b_dns_classifier_importable():
    """NA-9b: scanner.dns_classifier must import without error."""
    mod = importlib.import_module("scanner.dns_classifier")
    assert mod is not None, "NA9b FAIL: dns_classifier must be importable"


# ---------------------------------------------------------------------------
# NA-10  Input-metadata delegated_manager field on DomainInputRecord is preserved.
# ---------------------------------------------------------------------------


def test_na10_domain_input_record_metadata_field_preserved():
    """NA-10: DomainInputRecord.delegated_manager input-metadata field must survive cleanup."""
    record = DomainInputRecord(
        domain="test.ks.us",
        original_domain="test.ks.us",
        delegated_manager="Example DM",
    )
    assert record.delegated_manager == "Example DM", (
        "NA10 FAIL: DomainInputRecord.delegated_manager must be preserved "
        "(it is CSV input metadata, not a candidate source)"
    )


def test_na10b_domain_input_record_default_empty():
    """NA-10b: DomainInputRecord.delegated_manager defaults to empty string."""
    record = DomainInputRecord(domain="test.ks.us", original_domain="test.ks.us")
    assert record.delegated_manager == "", (
        "NA10b FAIL: DomainInputRecord.delegated_manager default must be empty string"
    )


# ---------------------------------------------------------------------------
# NA-11  Grep-based claim-to-code: no active candidate-source references remain
#        in scan_engine.py, models.py, or app.py.
# ---------------------------------------------------------------------------


def test_na11_scan_engine_no_candidate_source_reference():
    """NA-11a: scan_engine.py must not reference include_delegated_manager_clues."""
    engine_src = (REPO_ROOT / "scanner" / "scan_engine.py").read_text(encoding="utf-8")
    assert "include_delegated_manager_clues" not in engine_src, (
        "NA11a FAIL: scan_engine.py must not contain include_delegated_manager_clues"
    )


def test_na11b_models_no_candidate_source_field():
    """NA-11b: scanner/models.py must not define include_delegated_manager_clues."""
    models_src = (REPO_ROOT / "scanner" / "models.py").read_text(encoding="utf-8")
    assert "include_delegated_manager_clues" not in models_src, (
        "NA11b FAIL: scanner/models.py must not contain include_delegated_manager_clues"
    )


def test_na11c_app_no_delegated_manager_var():
    """NA-11c: app.py must not reference delegated_manager_var or include_delegated_manager_clues."""
    app_src = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    assert "delegated_manager_var" not in app_src, (
        "NA11c FAIL: app.py must not contain delegated_manager_var"
    )
    assert "include_delegated_manager_clues" not in app_src, (
        "NA11c FAIL: app.py must not contain include_delegated_manager_clues"
    )


def test_na11d_app_no_delegated_manager_clues_log():
    """NA-11d: app.py must not log 'Delegated-manager clues' as a scan option."""
    app_src = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    assert "Delegated-manager clues" not in app_src, (
        "NA11d FAIL: app.py must not contain 'Delegated-manager clues' log line"
    )
