"""WL1a — RFC Branch Expansion regression tests.

Durable negative-action (NA) and acceptance-criteria (AC) tests for the
de-hardcoding of FIFTH_LEVEL_BRANCHES from ("ci","co") to the full
RFC 1480 locality subset.

WL1a rules:
  Rule 1  Branch set = ci, co, k12, cc, tec, pvt, lib  (7 branches).
  Rule 2  Excluded branches (state/dni/isa/nsn/fed/gen/mus) are absent.
  Rule 3  Light profile candidate set is identical to pre-WL1a (no expansion).
  Rule 4  Candidates attach under the provided locality, never a bare 2nd-level.
  Rule 5  Label source is the existing FIFTH_LEVEL_PREFIX_SOURCES pool (no new file).
  Rule 6  RFC gate (include_rfc_locality_baseline) still controls fifth_level_enabled.
  Rule 7  Evidence discipline is unchanged — new candidates flow through normal paths.
"""

from __future__ import annotations

import pathlib
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

from scanner.models import ScanOptions, ScanProfile
from scanner.scan_engine import (
    FIFTH_LEVEL_BRANCHES,
    FIFTH_LEVEL_KNOWN_PREFIXES,
    FIFTH_LEVEL_PREFIX_SOURCES,
    build_wordlist_plan,
    generate_broad_fifth_level_candidates,
    generate_known_child_fifth_level_candidates,
)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

WORDLISTS_DIR = pathlib.Path(__file__).parent.parent.parent / "wordlists"
BASE_DOMAIN = "indiana.pa.us"

# RFC 1480 locality branches that MUST be in FIFTH_LEVEL_BRANCHES
REQUIRED_BRANCHES = {"ci", "co", "k12", "cc", "tec", "pvt", "lib"}
# Branches that MUST NOT be in FIFTH_LEVEL_BRANCHES (non-geographic/archaic)
EXCLUDED_BRANCHES = {"state", "dni", "isa", "nsn", "fed", "gen", "mus"}


def _normal_plan(*, known_count: int = 0):
    opts = ScanOptions(scan_profile=ScanProfile.NORMAL)
    return build_wordlist_plan(opts, WORDLISTS_DIR, known_fourth_level_count=known_count)


def _light_plan(*, known_count: int = 0):
    opts = ScanOptions(scan_profile=ScanProfile.LIGHT)
    return build_wordlist_plan(opts, WORDLISTS_DIR, known_fourth_level_count=known_count)


# ---------------------------------------------------------------------------
# NA-1  All 7 required RFC branches are present in FIFTH_LEVEL_BRANCHES.
# ---------------------------------------------------------------------------

def test_na1_required_branches_present():
    """NA-1 (Rule 1): all 7 required branches must be in FIFTH_LEVEL_BRANCHES."""
    current = set(FIFTH_LEVEL_BRANCHES)
    missing = REQUIRED_BRANCHES - current
    assert not missing, (
        f"NA1 FAIL: required RFC branches missing from FIFTH_LEVEL_BRANCHES: {missing}"
    )


# ---------------------------------------------------------------------------
# NA-2  Excluded branches are absent from FIFTH_LEVEL_BRANCHES.
# ---------------------------------------------------------------------------

def test_na2_excluded_branches_absent():
    """NA-2 (Rule 2): non-geographic/archaic branches must NOT be in FIFTH_LEVEL_BRANCHES."""
    current = set(FIFTH_LEVEL_BRANCHES)
    leaked = EXCLUDED_BRANCHES & current
    assert not leaked, (
        f"NA2 FAIL: excluded branches present in FIFTH_LEVEL_BRANCHES: {leaked}"
    )


# ---------------------------------------------------------------------------
# NA-3  Light profile candidate set is identical to pre-WL1a: no branch
#       expansion, no broad 5th-level, total = 25 4th-level + known-5th only.
# ---------------------------------------------------------------------------

def test_na3_light_profile_unchanged():
    """NA-3 (Rule 3): Light profile must produce zero broad 5th-level candidates."""
    plan = _light_plan(known_count=0)
    assert not plan.fifth_level_enabled, (
        "NA3 FAIL: fifth_level_enabled must be False for Light profile"
    )
    broad = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)
    assert broad == [], (
        f"NA3 FAIL: Light profile must produce no broad 5th-level candidates, got {len(broad)}"
    )
    assert plan.total_unique_labels == 25, (
        f"NA3 FAIL: Light 4th-level label count should be 25, got {plan.total_unique_labels}"
    )
    # With one known parent, total = 25 + 10 known-prefixes = 35
    plan_with_known = _light_plan(known_count=1)
    assert plan_with_known.estimated_candidates_per_domain == 35, (
        f"NA3 FAIL: Light with 1 known parent should be 35 total, got {plan_with_known.estimated_candidates_per_domain}"
    )


# ---------------------------------------------------------------------------
# NA-4  Branch candidates attach under the provided locality, never a bare
#       2nd-level domain.
# ---------------------------------------------------------------------------

def test_na4_branch_attaches_under_locality_not_bare_tld():
    """NA-4 (Rule 4): generated candidates are <label>.<branch>.<locality>,
    not <label>.<branch>.<2nd-level>."""
    plan = _normal_plan()
    candidates = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)

    # Every candidate should end with .<branch>.indiana.pa.us
    for c in candidates:
        parts = c.rstrip(".").split(".")
        # Minimum: label.branch.indiana.pa.us = 5 labels
        assert len(parts) >= 5, (
            f"NA4 FAIL: candidate {c!r} too short to be <label>.<branch>.<locality>"
        )
        # The branch part is second-from-end of the locality prefix
        branch = parts[-4]  # label(0).branch(1).indiana(2).pa(3).us(4)
        assert branch in REQUIRED_BRANCHES, (
            f"NA4 FAIL: branch segment {branch!r} in {c!r} not a recognised RFC branch"
        )
        # Must end with the provided base domain
        assert c.endswith(f".{BASE_DOMAIN}") or c.endswith(f".{BASE_DOMAIN}."), (
            f"NA4 FAIL: candidate {c!r} does not end with the provided locality {BASE_DOMAIN!r}"
        )


# ---------------------------------------------------------------------------
# NA-5  FIFTH_LEVEL_KNOWN_PREFIXES and generate_known_child_fifth_level_candidates
#       are unchanged — the 10 hardcoded known-parent prefixes must not grow.
# ---------------------------------------------------------------------------

def test_na5_known_prefixes_unchanged():
    """NA-5 (Rule 5): FIFTH_LEVEL_KNOWN_PREFIXES still has exactly 10 entries,
    unchanged from pre-WL1a."""
    assert len(FIFTH_LEVEL_KNOWN_PREFIXES) == 10, (
        f"NA5 FAIL: FIFTH_LEVEL_KNOWN_PREFIXES should have 10 entries, has {len(FIFTH_LEVEL_KNOWN_PREFIXES)}"
    )
    required_known = {"www", "mail", "portal", "police", "fire", "library",
                      "clerk", "records", "gis", "admin"}
    assert set(FIFTH_LEVEL_KNOWN_PREFIXES) == required_known, (
        f"NA5 FAIL: FIFTH_LEVEL_KNOWN_PREFIXES mismatch: {set(FIFTH_LEVEL_KNOWN_PREFIXES)}"
    )


# ---------------------------------------------------------------------------
# NA-6  RFC gate controls fifth_level_enabled: removing rfc_locality_baseline
#       disables the broad 5th-level even with other lists on.
# ---------------------------------------------------------------------------

def test_na6_rfc_gate_still_controls_fifth_level():
    """NA-6 (Rule 6): fifth_level_enabled requires include_rfc_locality_baseline=True."""
    opts_no_rfc = ScanOptions(
        scan_profile=ScanProfile.DEEP,
        include_rfc_locality_baseline=False,
        include_dns_common=True,
        include_civic_departments=True,
    )
    plan = build_wordlist_plan(opts_no_rfc, WORDLISTS_DIR)
    assert not plan.fifth_level_enabled, (
        "NA6 FAIL: fifth_level_enabled should be False when include_rfc_locality_baseline=False"
    )
    broad = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)
    assert broad == [], (
        "NA6 FAIL: no broad 5th-level candidates when RFC gate is off"
    )


# ---------------------------------------------------------------------------
# AC-1  NORMAL generates <label>.<branch>.<locality> for all 7 branches.
#       Verified by checking that representative known real-world candidates
#       are produced (e.g. fcs.pvt.<loc>, portal.tec.<loc>, admin.k12.<loc>).
# ---------------------------------------------------------------------------

def test_ac1_all_7_branches_in_normal_candidates():
    """AC-1 (Rule 1): NORMAL produces broad 5th-level candidates for all 7 branches."""
    plan = _normal_plan()
    candidates = set(generate_broad_fifth_level_candidates(BASE_DOMAIN, plan))
    assert candidates, "AC1 FAIL: no broad 5th-level candidates generated in NORMAL"

    for branch in REQUIRED_BRANCHES:
        branch_candidates = [c for c in candidates if f".{branch}.{BASE_DOMAIN}" in c]
        assert branch_candidates, (
            f"AC1 FAIL: no candidates generated for branch {branch!r} under {BASE_DOMAIN!r}"
        )

    # Confirm specific real-world-shaped candidates are present
    # (label must come from the fifth_level_prefix_labels pool)
    new_branches = {"k12", "cc", "tec", "pvt", "lib"}  # were not in old ("ci","co") set
    for branch in new_branches:
        # At least one candidate must exist under this branch
        found = any(f".{branch}.{BASE_DOMAIN}" in c for c in candidates)
        assert found, (
            f"AC1 FAIL: new branch {branch!r} produced no candidates — expansion didn't fire"
        )


def test_ac1b_known_real_world_candidate_shapes():
    """AC-1b: confirm specific candidate shapes that the old code could not produce.

    WL-TRIM Change 1: 5th-level prefix pool is now Civic departments only.
    RFC/locality and Common DNS/web labels are no longer in the 5th-level pool.
    All verified candidate shapes must come from civic_departments.txt.
    """
    plan = _normal_plan()
    candidates = set(generate_broad_fifth_level_candidates(BASE_DOMAIN, plan))

    # admin.pvt.indiana.pa.us — Civic 'admin', pvt branch (was not in old ci/co set)
    assert "admin.pvt.indiana.pa.us" in candidates, (
        "AC1b FAIL: admin.pvt.indiana.pa.us should be generated (Civic admin + pvt branch)"
    )
    # police.tec.indiana.pa.us — Civic 'police', tec branch (was not in old ci/co set)
    assert "police.tec.indiana.pa.us" in candidates, (
        "AC1b FAIL: police.tec.indiana.pa.us should be generated (Civic police + tec branch)"
    )
    # fire.k12.indiana.pa.us — Civic 'fire', k12 branch (was not in old ci/co set)
    assert "fire.k12.indiana.pa.us" in candidates, (
        "AC1b FAIL: fire.k12.indiana.pa.us should be generated (Civic fire + k12 branch)"
    )
    # admin.ci.indiana.pa.us — Civic 'admin', ci branch (was in old set; must still be present)
    assert "admin.ci.indiana.pa.us" in candidates, (
        "AC1b FAIL: admin.ci.indiana.pa.us must still be generated"
    )
    # clerk.co.indiana.pa.us — Civic 'clerk', co branch (was in old set; must still be present)
    assert "clerk.co.indiana.pa.us" in candidates, (
        "AC1b FAIL: clerk.co.indiana.pa.us must still be generated"
    )
    # WL-TRIM: portal and www are no longer 5th-level prefixes (dns_common removed)
    assert "portal.tec.indiana.pa.us" not in candidates, (
        "AC1b FAIL: portal.tec.indiana.pa.us must NOT be generated (dns_common excluded from 5th)"
    )
    assert "www.k12.indiana.pa.us" not in candidates, (
        "AC1b FAIL: www.k12.indiana.pa.us must NOT be generated (dns_common excluded from 5th)"
    )


# ---------------------------------------------------------------------------
# AC-2  NORMAL candidate count math: 7 branches × prefix_count = broad-5th count.
# ---------------------------------------------------------------------------

def test_ac2_candidate_count_math():
    """AC-2: NORMAL broad-5th count = fifth_level_prefix_count × 7 branches.

    WL-TRIM Change 1: 5th-level prefix pool is now Civic departments only (90 labels).
    Previously it included dns_common + civic + public_services + schools_libraries = 138.
    New NORMAL broad-5th count = 90 × 7 = 630 (down from 966).
    """
    plan = _normal_plan()
    assert plan.fifth_level_enabled, "AC2 FAIL: fifth_level_enabled must be True for NORMAL"

    expected_broad = plan.fifth_level_prefix_count * len(FIFTH_LEVEL_BRANCHES)
    actual = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)
    assert len(actual) == expected_broad, (
        f"AC2 FAIL: expected {expected_broad} broad candidates "
        f"({plan.fifth_level_prefix_count} prefixes × {len(FIFTH_LEVEL_BRANCHES)} branches), "
        f"got {len(actual)}"
    )
    # WL-TRIM: Civic-only pool = 90 prefix labels, broad-5th = 630
    assert plan.fifth_level_prefix_count == 90, (
        f"AC2 FAIL: NORMAL 5th-level prefix-label count should be 90 (Civic only), "
        f"got {plan.fifth_level_prefix_count}"
    )
    assert expected_broad == 630, (
        f"AC2 FAIL: expected 630 broad-5th candidates (90×7), got {expected_broad}"
    )


# ---------------------------------------------------------------------------
# AC-3  Claim-to-code: the branch source constant is FIFTH_LEVEL_BRANCHES and
#       has exactly 7 elements matching the required set exactly.
# ---------------------------------------------------------------------------

def test_ac3_claim_to_code_branch_constant():
    """AC-3: FIFTH_LEVEL_BRANCHES has exactly 7 entries matching the required set."""
    assert len(FIFTH_LEVEL_BRANCHES) == 7, (
        f"AC3 FAIL: expected 7 branches, got {len(FIFTH_LEVEL_BRANCHES)}: {FIFTH_LEVEL_BRANCHES}"
    )
    assert set(FIFTH_LEVEL_BRANCHES) == REQUIRED_BRANCHES, (
        f"AC3 FAIL: branch set mismatch. "
        f"Expected {REQUIRED_BRANCHES}, got {set(FIFTH_LEVEL_BRANCHES)}"
    )


# ---------------------------------------------------------------------------
# AC-4  FIFTH_LEVEL_PREFIX_SOURCES unchanged: the 4 lists feeding the 5th-prefix
#       pool are the same as pre-WL1a (no new label file was added).
# ---------------------------------------------------------------------------

def test_ac4_prefix_sources_civic_only():
    """AC-4 (WL-TRIM Change 1): FIFTH_LEVEL_PREFIX_SOURCES must be Civic departments only.

    WL-TRIM narrowed the 5th-level prefix pool from 4 sources (dns_common,
    civic_departments, public_services, schools_libraries) to Civic departments only.
    RFC/locality labels are branch labels (4th-level), not leaf guesses.
    Common DNS/web labels are service-host guesses, mostly noise at 5th level.
    """
    expected = {"include_civic_departments"}
    assert set(FIFTH_LEVEL_PREFIX_SOURCES) == expected, (
        f"AC4 FAIL: FIFTH_LEVEL_PREFIX_SOURCES must be Civic-only after WL-TRIM. "
        f"Expected {expected}, got {set(FIFTH_LEVEL_PREFIX_SOURCES)}"
    )


# ---------------------------------------------------------------------------
# AC-5  Deep profile with all lists on: candidate count scales correctly with
#       7 branches (194 prefixes × 7 = 1358 broad, 221 4th, 10 known = 1589).
# ---------------------------------------------------------------------------

def test_ac5_deep_all_on_count():
    """AC-5: DEEP with all optional lists on produces correct candidate totals.

    WL-TRIM Changes 1 & 3:
    - 5th-level prefix pool is now Civic departments only (90 labels) regardless
      of which 4th-level sources are enabled.
    - delegated_manager_clues removed from WORDLIST_SOURCES; passing
      include_delegated_manager_clues=True no longer adds candidates.
    - DEEP broad-5th = 90 × 7 = 630 (down from 194×7=1358).
    """
    opts = ScanOptions(
        scan_profile=ScanProfile.DEEP,
        include_rfc_locality_baseline=True,
        include_dns_common=True,
        include_civic_departments=True,
        include_public_services=True,
        include_schools_libraries=True,
        include_delegated_manager_clues=True,  # no-op after WL-TRIM Change 3
    )
    plan = build_wordlist_plan(opts, WORDLISTS_DIR, known_fourth_level_count=1)
    assert plan.fifth_level_enabled, "AC5 FAIL: fifth_level_enabled should be True for DEEP+RFC"
    expected_broad = plan.fifth_level_prefix_count * 7
    broad = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)
    assert len(broad) == expected_broad, (
        f"AC5 FAIL: expected {expected_broad} broad candidates, got {len(broad)}"
    )
    # WL-TRIM: Civic-only 5th-level prefix pool = 90, broad-5th = 630
    assert plan.fifth_level_prefix_count == 90, (
        f"AC5 FAIL: DEEP 5th-level prefix count should be 90 (Civic only), "
        f"got {plan.fifth_level_prefix_count}"
    )
    assert expected_broad == 630, (
        f"AC5 FAIL: expected 630 broad candidates (90×7), got {expected_broad}"
    )


# ---------------------------------------------------------------------------
# AC-6  No duplicate candidates produced within a single branch or across
#       branches (dict.fromkeys dedup in generate_broad_fifth_level_candidates).
# ---------------------------------------------------------------------------

def test_ac6_no_duplicate_candidates():
    """AC-6: generate_broad_fifth_level_candidates produces no duplicates."""
    plan = _normal_plan()
    candidates = generate_broad_fifth_level_candidates(BASE_DOMAIN, plan)
    assert len(candidates) == len(set(candidates)), (
        "AC6 FAIL: duplicate candidates found in broad 5th-level generation"
    )
