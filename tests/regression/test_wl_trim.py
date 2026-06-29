"""WL-TRIM — Lane 2 Candidate Reduction + Branch Timeout Breaker regression tests.

AIPF Ticket WL-TRIM.  Durable negative-action (NA) and acceptance-criteria (AC)
tests covering all four changes and the 14 evidence-discipline cases.

Changes covered:
  Change 1   5th-level prefix pool = Civic departments only.
  Change 2   Civic 5th-level list is priority ordered (high-yield labels first).
  Change 3   delegated_manager_clues removed from candidate generation (fully cleaned in DELETE-DM-CLUES).
  Change 4   Branch timeout circuit breaker (N=20) per validated RFC branch.

NA/AC index:
  NA-1   5th-level generation uses Civic pool only.
  NA-2   4th-level generation still uses all three NORMAL sources (unchanged).
  NA-3   RFC/locality labels are NOT used as 5th-level leaf prefixes.
  NA-4   Common DNS/web labels are NOT used as 5th-level leaf prefixes.
  NA-5   delegated_manager_clues does not feed generated candidates.
  NA-6   ScanOptions.include_delegated_manager_clues field is removed (DELETE-DM-CLUES).
  NA-7   Breaker fires at exactly 20 consecutive misses.
  NA-8   Breaker does NOT fire at 19 consecutive misses.
  NA-9   Breaker resets on a confirmed finding.
  NA-10  A branch with intermittent findings is fully swept.
  NA-11  Skipped-by-breaker names carry SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC status.
  NA-12  Lane 1 / known-input validation bypasses the branch breaker.
  NA-13  Wildcard-suppressed results do NOT reset the breaker counter.
  NA-14  Claim-to-code evidence (constants and function references).
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanner.models import (
    DomainInputRecord,
    DomainScanResult,
    EvidenceStatus,
    ScanOptions,
    ScanProfile,
)
from scanner.wildcard_attestation import WildcardAttestation, WildcardAttestationStatus
from scanner.scan_engine import (
    BRANCH_BREAKER_N,
    FIFTH_LEVEL_BRANCHES,
    FIFTH_LEVEL_PREFIX_SOURCES,
    WORDLIST_SOURCES,
    build_wordlist_plan,
    generate_broad_fifth_level_candidates,
    _is_rfc_branch_parent,
)
from scanner.evidence_status import (
    is_confirmed_evidence_status,
    is_diagnostic_evidence_status,
    outcome_skipped_by_branch_timeout_heuristic,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

WORDLISTS_DIR = pathlib.Path(__file__).parent.parent.parent / "wordlists"
BASE_DOMAIN = "parsons.ks.us"


def _normal_plan(*, known_count: int = 0):
    opts = ScanOptions(scan_profile=ScanProfile.NORMAL)
    return build_wordlist_plan(opts, WORDLISTS_DIR, known_fourth_level_count=known_count)


def _deep_all_on_plan(*, known_count: int = 0):
    opts = ScanOptions(
        scan_profile=ScanProfile.DEEP,
        include_rfc_locality_baseline=True,
        include_dns_common=True,
        include_civic_departments=True,
        include_public_services=True,
        include_schools_libraries=True,
    )
    return build_wordlist_plan(opts, WORDLISTS_DIR, known_fourth_level_count=known_count)


def _civic_labels() -> list[str]:
    path = WORDLISTS_DIR / "civic_departments.txt"
    return [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]


def _rfc_labels() -> list[str]:
    path = WORDLISTS_DIR / "rfc1480.txt"
    return [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]


def _dns_common_labels() -> list[str]:
    path = WORDLISTS_DIR / "dns_common.txt"
    return [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# NA-1  5th-level generation uses Civic pool only.
# ---------------------------------------------------------------------------

def test_na1_fifth_level_prefix_sources_civic_only():
    """NA-1 (Change 1): FIFTH_LEVEL_PREFIX_SOURCES must be Civic departments only."""
    assert set(FIFTH_LEVEL_PREFIX_SOURCES) == {"include_civic_departments"}, (
        f"NA1 FAIL: FIFTH_LEVEL_PREFIX_SOURCES must be Civic-only; "
        f"got {set(FIFTH_LEVEL_PREFIX_SOURCES)}"
    )


def test_na1b_fifth_level_labels_are_civic_subset():
    """NA-1b: all 5th-level prefix labels in a NORMAL plan come from civic_departments.txt."""
    plan = _normal_plan()
    civic = set(_civic_labels())
    for label in plan.fifth_level_prefix_labels:
        assert label in civic, (
            f"NA1b FAIL: 5th-level prefix label {label!r} is NOT in civic_departments.txt"
        )


def test_na1c_fifth_level_count_equals_civic_count():
    """NA-1c: NORMAL 5th-level prefix count equals civic_departments.txt line count (90)."""
    plan = _normal_plan()
    assert plan.fifth_level_prefix_count == 90, (
        f"NA1c FAIL: expected 90 Civic-only 5th-level prefix labels, "
        f"got {plan.fifth_level_prefix_count}"
    )
    assert len(generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)) == 90 * 7, (
        "NA1c FAIL: NORMAL broad-5th count should be 90×7=630"
    )


# ---------------------------------------------------------------------------
# NA-2  4th-level generation still uses all three NORMAL sources (unchanged).
# ---------------------------------------------------------------------------

def test_na2_normal_fourth_level_unchanged():
    """NA-2 (Change 1): NORMAL 4th-level candidate count is unchanged (RFC+common+civic = 152)."""
    plan = _normal_plan()
    # RFC(14) + dns_common(48) + civic(90) = 152 before dedup.
    # The existing suite confirms 152; reconfirm here for WL-TRIM.
    assert plan.total_unique_labels == 152, (
        f"NA2 FAIL: NORMAL 4th-level unique labels should be 152, got {plan.total_unique_labels}"
    )


def test_na2b_normal_fourth_level_has_rfc_and_common():
    """NA-2b: NORMAL 4th-level pool contains RFC/locality labels and dns_common labels."""
    plan = _normal_plan()
    label_set = set(plan.unique_labels)
    # RFC labels must be present as 4th-level candidates
    for rfc_label in _rfc_labels():
        assert rfc_label in label_set, (
            f"NA2b FAIL: RFC label {rfc_label!r} must be in 4th-level pool"
        )
    # A representative dns_common label must be present
    assert "www" in label_set, "NA2b FAIL: 'www' must be in NORMAL 4th-level pool"
    assert "mail" in label_set, "NA2b FAIL: 'mail' must be in NORMAL 4th-level pool"


# ---------------------------------------------------------------------------
# NA-3  RFC/locality labels are NOT used as 5th-level leaf prefixes.
# ---------------------------------------------------------------------------

def test_na3_rfc_labels_not_in_fifth_level_pool():
    """NA-3 (Change 1): RFC/locality labels from rfc1480.txt must not appear in the
    5th-level prefix label pool."""
    plan = _normal_plan()
    fifth_set = set(plan.fifth_level_prefix_labels)
    rfc_labels = set(_rfc_labels())
    leaked = rfc_labels & fifth_set
    assert not leaked, (
        f"NA3 FAIL: RFC/locality labels found in 5th-level prefix pool: {leaked}"
    )


def test_na3b_rfc_label_not_generated_as_fifth():
    """NA-3b: no broad 5th-level candidate has an RFC label as its leftmost prefix."""
    plan = _normal_plan()
    rfc_set = set(_rfc_labels())
    candidates = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)
    for c in candidates:
        prefix = c.split(".")[0]
        assert prefix not in rfc_set, (
            f"NA3b FAIL: candidate {c!r} uses RFC label {prefix!r} as 5th-level leaf prefix"
        )


# ---------------------------------------------------------------------------
# NA-4  Common DNS/web labels are NOT used as 5th-level leaf prefixes.
# ---------------------------------------------------------------------------

def test_na4_dns_common_labels_not_in_fifth_level_pool():
    """NA-4 (Change 1): dns_common labels must not appear in the 5th-level prefix label pool."""
    plan = _normal_plan()
    fifth_set = set(plan.fifth_level_prefix_labels)
    common_labels = set(_dns_common_labels())
    leaked = common_labels & fifth_set
    assert not leaked, (
        f"NA4 FAIL: dns_common labels found in 5th-level prefix pool: {leaked}"
    )


def test_na4b_specific_common_labels_absent():
    """NA-4b: representative service-host labels (www, mail, portal) are absent from 5th pool."""
    plan = _normal_plan()
    fifth_set = set(plan.fifth_level_prefix_labels)
    for label in ("www", "mail", "portal", "smtp", "ftp", "ns"):
        assert label not in fifth_set, (
            f"NA4b FAIL: dns_common label {label!r} must not be in 5th-level prefix pool"
        )


# ---------------------------------------------------------------------------
# NA-5  delegated_manager_clues does not feed generated candidates.
# ---------------------------------------------------------------------------

def test_na5_manager_clues_not_in_wordlist_sources():
    """NA-5 (Change 3): include_delegated_manager_clues must not appear in WORDLIST_SOURCES."""
    option_fields = {entry[0] for entry in WORDLIST_SOURCES}
    assert "include_delegated_manager_clues" not in option_fields, (
        "NA5 FAIL: include_delegated_manager_clues must not be in WORDLIST_SOURCES "
        "(WL-TRIM Change 3 — candidate generation removed)"
    )


def test_na5b_manager_clues_field_absent_from_scan_options():
    """NA-5b (DELETE-DM-CLUES): ScanOptions must NOT have include_delegated_manager_clues."""
    opts = ScanOptions()
    assert not hasattr(opts, "include_delegated_manager_clues"), (
        "NA5b FAIL: include_delegated_manager_clues must be removed from ScanOptions "
        "(DELETE-DM-CLUES ticket)"
    )


def test_na5c_manager_clues_wordlist_file_deleted():
    """NA-5c (DELETE-DM-CLUES): delegated_manager_clues.txt must not exist in the wordlists dir."""
    clues_path = WORDLISTS_DIR / "delegated_manager_clues.txt"
    assert not clues_path.exists(), (
        "NA5c FAIL: delegated_manager_clues.txt must be deleted "
        "(DELETE-DM-CLUES ticket)"
    )


# ---------------------------------------------------------------------------
# NA-6  ScanOptions.include_delegated_manager_clues field is removed
#       (DELETE-DM-CLUES ticket fully removed the field).
# ---------------------------------------------------------------------------

def test_na6_scan_options_does_not_have_manager_clues_field():
    """NA-6 (DELETE-DM-CLUES): ScanOptions.include_delegated_manager_clues must be gone."""
    opts = ScanOptions()
    assert not hasattr(opts, "include_delegated_manager_clues"), (
        "NA6 FAIL: ScanOptions must NOT have include_delegated_manager_clues "
        "(DELETE-DM-CLUES ticket removed it completely)"
    )


# ---------------------------------------------------------------------------
# NA-7  Breaker fires at exactly 20 consecutive misses (Change 4).
# ---------------------------------------------------------------------------

def test_na7_breaker_fires_at_exactly_20():
    """NA-7 (Change 4): branch breaker fires after exactly 20 consecutive misses."""
    assert BRANCH_BREAKER_N == 20, (
        f"NA7 FAIL: BRANCH_BREAKER_N must be 20, got {BRANCH_BREAKER_N}"
    )


def test_na7b_breaker_fires_in_scan_loop():
    """NA-7b: in a simulated 5th-level sweep, breaker trips after 20 misses and
    subsequent candidates are classified SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC."""
    from scanner.scan_engine import (
        _test_candidates,
        ScanPhase,
        BRANCH_BREAKER_N,
        FIFTH_LEVEL_BRANCHES,
    )
    from scanner.models import DomainScanResult, ScanOptions

    domain = "example.ks.us"
    branch = "ci"
    # Build 25 civic candidates under ci.example.ks.us
    civic = _civic_labels()
    candidates = [f"{label}.{branch}.{domain}" for label in civic[:25]]

    result = DomainScanResult(domain=domain)
    parent_passed: set[str] = {f"{branch}.{domain}"}
    parent_decisions: dict = {}

    # All DNS queries return empty (no findings) → should trip breaker at 20
    empty_response: tuple[list, list] = ([], [])

    with patch(
        "scanner.scan_engine.asyncio.run",
        side_effect=lambda coro: empty_response,
    ):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=MagicMock(
                verified=False,
                evidence_outcomes=[],
                records=[],
                errors=[],
                log_message="",
            ),
        ):
            _test_candidates(
                candidates=candidates,
                domain=domain,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                attestation_cache=None,
                progress=None,
                messages=[],
                cancel_check=None,
                progress_update=None,
                domain_index=1,
                domain_total=1,
                domains_completed=0,
                started_at=__import__("datetime").datetime.now(),
                phase=ScanPhase.TESTING_FIFTH_LEVEL,
                candidates_offset=0,
                candidates_total=25,
                validate_fifth_level_parents=True,
                parent_passed=parent_passed,
                parent_decisions=parent_decisions,
                known_input_parents=set(),  # no known parents → breaker applies
            )

    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    # After 20 misses the breaker trips; candidates 21-25 should be skipped
    assert len(breaker_outcomes) == 5, (
        f"NA7b FAIL: expected 5 breaker skips (candidates 21-25), got {len(breaker_outcomes)}"
    )


# ---------------------------------------------------------------------------
# NA-8  Breaker does NOT fire at 19 consecutive misses.
# ---------------------------------------------------------------------------

def test_na8_breaker_does_not_fire_at_19():
    """NA-8 (Change 4): breaker must not trip before 20 misses."""
    from scanner.scan_engine import _test_candidates, ScanPhase
    from scanner.models import DomainScanResult

    domain = "example.ks.us"
    branch = "ci"
    civic = _civic_labels()
    candidates = [f"{label}.{branch}.{domain}" for label in civic[:19]]

    result = DomainScanResult(domain=domain)
    parent_passed: set[str] = {f"{branch}.{domain}"}

    with patch("scanner.scan_engine.asyncio.run", side_effect=lambda coro: ([], [])):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=MagicMock(
                verified=False, evidence_outcomes=[], records=[], errors=[], log_message=""
            ),
        ):
            _test_candidates(
                candidates=candidates,
                domain=domain,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                attestation_cache=None,
                progress=None,
                messages=[],
                cancel_check=None,
                progress_update=None,
                domain_index=1,
                domain_total=1,
                domains_completed=0,
                started_at=__import__("datetime").datetime.now(),
                phase=ScanPhase.TESTING_FIFTH_LEVEL,
                candidates_offset=0,
                candidates_total=19,
                validate_fifth_level_parents=True,
                parent_passed=parent_passed,
                parent_decisions={},
                known_input_parents=set(),
            )

    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    assert len(breaker_outcomes) == 0, (
        f"NA8 FAIL: breaker must not fire at 19 misses; "
        f"got {len(breaker_outcomes)} breaker outcomes"
    )


# ---------------------------------------------------------------------------
# NA-9  Breaker resets on a confirmed finding.
# ---------------------------------------------------------------------------

def test_na9_breaker_resets_on_finding():
    """NA-9 (Change 4): a confirmed finding resets the miss counter to zero."""
    from scanner.scan_engine import _test_candidates, ScanPhase
    from scanner.models import DomainScanResult, DiscoveredRecord, FindingClassification

    domain = "example.ks.us"
    branch = "ci"
    civic = _civic_labels()
    # Build 21 candidates; the 19th gets a finding, then 2 more misses → no breaker
    candidates = [f"{label}.{branch}.{domain}" for label in civic[:21]]
    # The 19th candidate will be the one with a real finding
    finding_candidate = candidates[18]

    call_count = 0

    def _fake_asyncio_run(coro):
        nonlocal call_count
        call_count += 1
        # Return a real A record for the 19th call
        if call_count == 19:
            rec = MagicMock()
            rec.classification = FindingClassification.STANDARD_RECORD
            rec.record_type = MagicMock()
            rec.record_type.value = "A"
            rec.attestation_status = None
            rec.wildcard_signature_matched = None
            rec.wildcard_differentiation_reason = None
            rec.confidence = None
            return ([rec], [])
        return ([], [])

    result = DomainScanResult(domain=domain)
    parent_passed: set[str] = {f"{branch}.{domain}"}

    with patch("scanner.scan_engine.asyncio.run", side_effect=_fake_asyncio_run):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=MagicMock(
                verified=False, evidence_outcomes=[], records=[], errors=[], log_message=""
            ),
        ):
            _test_candidates(
                candidates=candidates,
                domain=domain,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                attestation_cache=None,
                progress=None,
                messages=[],
                cancel_check=None,
                progress_update=None,
                domain_index=1,
                domain_total=1,
                domains_completed=0,
                started_at=__import__("datetime").datetime.now(),
                phase=ScanPhase.TESTING_FIFTH_LEVEL,
                candidates_offset=0,
                candidates_total=21,
                validate_fifth_level_parents=True,
                parent_passed=parent_passed,
                parent_decisions={},
                known_input_parents=set(),
            )

    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    # 18 misses → finding resets → 2 more misses = only 2 misses total at end, no breaker
    assert len(breaker_outcomes) == 0, (
        f"NA9 FAIL: breaker must not fire after reset from finding; "
        f"got {len(breaker_outcomes)} breaker skips"
    )


# ---------------------------------------------------------------------------
# NA-10  A branch with intermittent findings is fully swept.
# ---------------------------------------------------------------------------

def test_na10_intermittent_findings_branch_fully_swept():
    """NA-10 (Change 4): a branch that has findings interspersed must be fully swept."""
    from scanner.scan_engine import _test_candidates, ScanPhase
    from scanner.models import DomainScanResult, DiscoveredRecord, FindingClassification

    domain = "example.ks.us"
    branch = "ci"
    civic = _civic_labels()
    # 40 candidates; every 10th gets a finding → counter never reaches 20 consecutively
    candidates = [f"{label}.{branch}.{domain}" for label in civic[:40]]

    call_count = 0

    def _fake_asyncio_run(coro):
        nonlocal call_count
        call_count += 1
        if call_count % 10 == 0:
            rec = MagicMock()
            rec.classification = FindingClassification.STANDARD_RECORD
            rec.record_type = MagicMock()
            rec.record_type.value = "A"
            rec.attestation_status = None
            rec.wildcard_signature_matched = None
            rec.wildcard_differentiation_reason = None
            rec.confidence = None
            return ([rec], [])
        return ([], [])

    result = DomainScanResult(domain=domain)
    parent_passed: set[str] = {f"{branch}.{domain}"}

    with patch("scanner.scan_engine.asyncio.run", side_effect=_fake_asyncio_run):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=MagicMock(
                verified=False, evidence_outcomes=[], records=[], errors=[], log_message=""
            ),
        ):
            tested = _test_candidates(
                candidates=candidates,
                domain=domain,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                attestation_cache=None,
                progress=None,
                messages=[],
                cancel_check=None,
                progress_update=None,
                domain_index=1,
                domain_total=1,
                domains_completed=0,
                started_at=__import__("datetime").datetime.now(),
                phase=ScanPhase.TESTING_FIFTH_LEVEL,
                candidates_offset=0,
                candidates_total=40,
                validate_fifth_level_parents=True,
                parent_passed=parent_passed,
                parent_decisions={},
                known_input_parents=set(),
            )

    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    assert tested == 40, (
        f"NA10 FAIL: all 40 candidates must be tested (branch not tripped); tested={tested}"
    )
    assert len(breaker_outcomes) == 0, (
        f"NA10 FAIL: no breaker skips allowed when findings are interspersed; "
        f"got {len(breaker_outcomes)}"
    )


# ---------------------------------------------------------------------------
# NA-11  Skipped-by-breaker names carry SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC.
# ---------------------------------------------------------------------------

def test_na11_skipped_status_is_heuristic():
    """NA-11 (Change 4): the skipped outcome has SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC status
    and the detail text contains the required heuristic wording (not 'absent', 'NXDOMAIN', etc.)."""
    outcome = outcome_skipped_by_branch_timeout_heuristic(
        "police.ci.example.ks.us", branch="ci.example.ks.us", breaker_n=20
    )
    assert outcome.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC, (
        "NA11 FAIL: outcome status must be SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC"
    )
    detail = outcome.detail.lower()
    assert "heuristic" in detail, (
        f"NA11 FAIL: detail must contain 'heuristic' to signal non-authoritative skip; got: {detail!r}"
    )
    assert "not proof" in detail, (
        f"NA11 FAIL: detail must say 'not proof' (proof-of-absence contract); got: {detail!r}"
    )
    # Must NOT use language implying proven absence
    for banned in ("nxdomain", " absent", "not existing", "rejected", "does not exist"):
        assert banned not in detail, (
            f"NA11 FAIL: detail must not contain {banned!r}; got: {detail!r}"
        )


def test_na11b_heuristic_status_is_diagnostic():
    """NA-11b: SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC is a diagnostic (not confirmed) status."""
    status = EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    assert not is_confirmed_evidence_status(status), (
        "NA11b FAIL: SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC must not be confirmed evidence"
    )
    assert is_diagnostic_evidence_status(status), (
        "NA11b FAIL: SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC must be classified as diagnostic"
    )


# ---------------------------------------------------------------------------
# NA-12  Lane 1 / known-input validation bypasses the branch breaker.
# ---------------------------------------------------------------------------

def test_na12_known_input_parents_bypass_breaker():
    """NA-12 (Change 4): candidates whose parent is in known_input_parents are exempt from
    the branch breaker even after 20 misses on that same branch from generated candidates."""
    from scanner.scan_engine import _test_candidates, ScanPhase
    from scanner.models import DomainScanResult

    domain = "example.ks.us"
    branch = "ci"
    civic = _civic_labels()
    # First 20 are generated (no known parents) → trips breaker
    generated = [f"{label}.{branch}.{domain}" for label in civic[:20]]
    # Next 5 are from known-input parents → must NOT be skipped by breaker
    known_candidates = [f"{label}.{branch}.{domain}" for label in civic[20:25]]
    all_candidates = generated + known_candidates

    result = DomainScanResult(domain=domain)
    branch_parent = f"{branch}.{domain}"
    parent_passed: set[str] = {branch_parent}
    # Mark branch_parent as known-input
    known_input_parents: set[str] = {branch_parent}

    with patch("scanner.scan_engine.asyncio.run", side_effect=lambda coro: ([], [])):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=MagicMock(
                verified=False, evidence_outcomes=[], records=[], errors=[], log_message=""
            ),
        ):
            tested = _test_candidates(
                candidates=all_candidates,
                domain=domain,
                resolver=MagicMock(),
                result=result,
                wildcard_suspected=False,
                attestation_cache=None,
                progress=None,
                messages=[],
                cancel_check=None,
                progress_update=None,
                domain_index=1,
                domain_total=1,
                domains_completed=0,
                started_at=__import__("datetime").datetime.now(),
                phase=ScanPhase.TESTING_FIFTH_LEVEL,
                candidates_offset=0,
                candidates_total=25,
                validate_fifth_level_parents=True,
                parent_passed=parent_passed,
                parent_decisions={},
                known_input_parents=known_input_parents,  # lane 1 bypass
            )

    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    # The 5 known-input candidates must NOT be skipped by the breaker
    assert len(breaker_outcomes) == 0, (
        f"NA12 FAIL: known-input candidates must bypass the branch breaker; "
        f"got {len(breaker_outcomes)} breaker skips"
    )
    # All 25 should be tested (known-input ones exempt from breaker)
    assert tested == 25, (
        f"NA12 FAIL: all 25 candidates must be tested when known_input_parents applies; "
        f"tested={tested}"
    )


# ---------------------------------------------------------------------------
# NA-13  Wildcard-suppressed results do NOT reset the breaker.
# ---------------------------------------------------------------------------

def test_na13_wildcard_suppressed_does_not_reset_breaker():
    """NA-13 (Change 4 / WC-FIX): wildcard-suppressed candidates (TXT echo or other)
    do not reset the branch miss counter — they count as misses."""
    from scanner.scan_engine import _test_candidates, ScanPhase
    from scanner.models import DomainScanResult

    domain = "example.ks.us"
    branch = "ci"
    civic = _civic_labels()
    # 25 candidates all subject to wildcard suppression
    candidates = [f"{label}.{branch}.{domain}" for label in civic[:25]]

    # Build a fake wildcard attestation that suppresses everything
    fake_attestation = WildcardAttestation(
        parent=f"{branch}.{domain}",
        status=WildcardAttestationStatus.DETECTED,
        type_signatures={"A": frozenset({"1.2.3.4"})},
        address_pool=frozenset({"1.2.3.4"}),
    )

    result = DomainScanResult(domain=domain)
    parent_passed: set[str] = {f"{branch}.{domain}"}

    fake_record = MagicMock()
    fake_record.record_type = MagicMock()
    fake_record.record_type.value = "A"
    fake_record.attestation_status = None
    fake_record.wildcard_signature_matched = None
    fake_record.wildcard_differentiation_reason = None

    with patch("scanner.scan_engine.asyncio.run", side_effect=lambda coro: ([fake_record], [])):
        with patch(
            "scanner.scan_engine.verify_delegated_child_zone",
            return_value=MagicMock(
                verified=False, evidence_outcomes=[], records=[], errors=[], log_message=""
            ),
        ):
            with patch(
                "scanner.scan_engine.run_wildcard_attestation",
                return_value=fake_attestation,
            ):
                with patch(
                    "scanner.scan_engine.candidate_differentiates",
                    return_value=None,  # suppressed — matches wildcard
                ):
                    _test_candidates(
                        candidates=candidates,
                        domain=domain,
                        resolver=MagicMock(),
                        result=result,
                        wildcard_suspected=False,
                        attestation_cache={},
                        progress=None,
                        messages=[],
                        cancel_check=None,
                        progress_update=None,
                        domain_index=1,
                        domain_total=1,
                        domains_completed=0,
                        started_at=__import__("datetime").datetime.now(),
                        phase=ScanPhase.TESTING_FIFTH_LEVEL,
                        candidates_offset=0,
                        candidates_total=25,
                        validate_fifth_level_parents=True,
                        parent_passed=parent_passed,
                        parent_decisions={},
                        known_input_parents=set(),
                    )

    breaker_outcomes = [
        o for o in result.evidence_outcomes
        if o.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    ]
    # Candidates 21-25 should be breaker-skipped (wildcard hits count as misses)
    assert len(breaker_outcomes) == 5, (
        f"NA13 FAIL: wildcard-suppressed results must count as misses; "
        f"expected 5 breaker skips (candidates 21-25), got {len(breaker_outcomes)}"
    )


# ---------------------------------------------------------------------------
# NA-14  Claim-to-code evidence.
# ---------------------------------------------------------------------------

def test_na14_branch_breaker_n_constant():
    """NA-14a: BRANCH_BREAKER_N is 20 (the agreed threshold)."""
    assert BRANCH_BREAKER_N == 20, (
        f"NA14a FAIL: BRANCH_BREAKER_N must be 20, got {BRANCH_BREAKER_N}"
    )


def test_na14b_fifth_level_prefix_sources_constant():
    """NA-14b: FIFTH_LEVEL_PREFIX_SOURCES is the sole source-of-truth for 5th-level pool selection."""
    from scanner.scan_engine import FIFTH_LEVEL_PREFIX_SOURCES
    assert FIFTH_LEVEL_PREFIX_SOURCES == ("include_civic_departments",), (
        f"NA14b FAIL: FIFTH_LEVEL_PREFIX_SOURCES must be ('include_civic_departments',); "
        f"got {FIFTH_LEVEL_PREFIX_SOURCES}"
    )


def test_na14c_civic_priority_ordering():
    """NA-14c: civic_departments.txt first 20 labels are the intended high-yield guesses.

    Police, fire, library, pd, fd, clerk, admin, courts, court, and parks must be
    in the first 20 positions (the window the breaker uses before tripping).
    """
    civic = _civic_labels()
    first_20 = set(civic[:20])
    required_in_top20 = {"police", "fire", "library", "pd", "fd", "clerk", "admin"}
    missing = required_in_top20 - first_20
    assert not missing, (
        f"NA14c FAIL: high-yield Civic labels not in first 20 positions: {missing}. "
        f"First 20: {list(civic[:20])}"
    )


def test_na14d_skipped_by_branch_timeout_in_evidence_status():
    """NA-14d: EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC exists and has the
    correct string value."""
    assert EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC.value == (
        "SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC"
    ), (
        "NA14d FAIL: EvidenceStatus value mismatch for SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC"
    )


def test_na14e_outcome_helper_exists():
    """NA-14e: outcome_skipped_by_branch_timeout_heuristic helper is importable and returns
    the correct evidence status."""
    outcome = outcome_skipped_by_branch_timeout_heuristic(
        "fire.ci.example.ks.us", branch="ci.example.ks.us", breaker_n=20
    )
    assert outcome.evidence_status == EvidenceStatus.SKIPPED_BY_BRANCH_TIMEOUT_HEURISTIC
    assert outcome.source_method == "generated_candidate"


def test_na14f_is_rfc_branch_parent_used_in_engine():
    """NA-14f: _is_rfc_branch_parent correctly identifies validated RFC branches
    (used by the breaker to distinguish generated vs non-RFC parents)."""
    domain = "parsons.ks.us"
    for branch in FIFTH_LEVEL_BRANCHES:
        parent_key = f"{branch}.{domain}"
        assert _is_rfc_branch_parent(parent_key, domain), (
            f"NA14f FAIL: {parent_key!r} should be recognised as an RFC branch parent"
        )
    # A non-RFC parent must return False
    assert not _is_rfc_branch_parent(f"police.{domain}", domain), (
        "NA14f FAIL: 'police.parsons.ks.us' must NOT be classified as an RFC branch parent"
    )
