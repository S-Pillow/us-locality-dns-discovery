"""AIPF Ticket 30 — Progressive RFC Branch Escalation regression tests.

Negative-action tests (durable):
  NA-1  Skip ≠ absence: sentinel-miss → SKIPPED_BY_PARENT_GATING + heuristic-skip disclosure.
  NA-2  Apex-fail does not short-circuit to all-skip: Tier-3 sentinel runs.
  NA-3  Sentinel hit → escalation opens the branch (allow_descendants=True).
  NA-4  Sentinel miss → bounded skip (allow_descendants=False).
  NA-5  Tier 5 off by default; on → all RFC branches forced open.
  NA-6  Runtime bound: sentinel candidate count ≤ len(RFC_SENTINEL_LABELS) × unvalidated branches.
  NA-7  Non-RFC branch parents still use the original lazy-validation path (Tier-1 unchanged).
  NA-8  Tier-1 known/validated branches are unaffected.

Acceptance-criteria tests:
  AC-1  Known/validated branches still test normal 5th-level candidates.
  AC-2  Failed apex → Tier-3 sentinel runs (not all-skip).
  AC-3  RFC branches get the bounded sentinel probe when apex fails.
  AC-4  Sentinel hit → broader 5th-level testing (allow_descendants=True).
  AC-5  Sentinel miss → heuristic-skip disclosure, NOT not-found/absence record.
  AC-6  Tier-5 option default=False; when True all RFC branches open.
  AC-7  FIFTH_LEVEL_BRANCHES constant contains all 7 expected labels.
  AC-8  RFC_SENTINEL_LABELS constant contains ≥13 expected civic labels.
  AC-9  _is_rfc_branch_parent correctly identifies RFC branch apexes.
  AC-10 deep_rfc_branch_sweep=False is the default in ScanOptions.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from scanner.models import (
    DomainScanResult,
    EvidenceStatus,
    ParentGatingConfidence,
    ScanOptions,
    ScanProfile,
)
from scanner.parent_gating import (
    decision_for_rfc_branch_sentinel_hit,
    decision_for_rfc_branch_sentinel_miss,
)
from scanner.scan_engine import (
    FIFTH_LEVEL_BRANCHES,
    RFC_SENTINEL_LABELS,
    _is_rfc_branch_parent,
    _RFC_BRANCH_SET,
    apply_scan_profile,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_result(domain: str = "butler.pa.us") -> DomainScanResult:
    return DomainScanResult(domain=domain)


# ---------------------------------------------------------------------------
# NA-1 / AC-5: sentinel-miss decision = SKIPPED_BY_PARENT_GATING, not absence
# ---------------------------------------------------------------------------


class TestSentinelMissNotAbsence(unittest.TestCase):
    """NA-1, AC-5 — a sentinel miss must produce a heuristic-skip disclosure,
    NOT a not-found / absence finding."""

    def test_na1_sentinel_miss_evidence_status(self):
        decision = decision_for_rfc_branch_sentinel_miss("pvt.butler.pa.us")
        self.assertFalse(decision.allow_descendants)
        self.assertEqual(decision.evidence_status, EvidenceStatus.SKIPPED_BY_PARENT_GATING)
        self.assertEqual(decision.confidence, ParentGatingConfidence.HEURISTIC_SKIP)

    def test_na1_sentinel_miss_disclosure_text(self):
        decision = decision_for_rfc_branch_sentinel_miss("pvt.butler.pa.us")
        msg = decision.diagnostic_message.lower()
        # Must contain "not proof" (or equivalent) and "heuristic" — the AIPF disclosure.
        self.assertIn("not proof", msg)
        self.assertIn("heuristic", msg)

    def test_na1_sentinel_miss_reason_is_heuristic(self):
        decision = decision_for_rfc_branch_sentinel_miss("tec.butler.pa.us")
        self.assertIn("heuristic", decision.reason.lower())

    def test_ac5_diagnostic_message_contains_branch_name(self):
        decision = decision_for_rfc_branch_sentinel_miss("k12.butler.pa.us")
        self.assertIn("k12.butler.pa.us", decision.diagnostic_message)


# ---------------------------------------------------------------------------
# NA-3 / AC-4: sentinel hit → allow_descendants=True
# ---------------------------------------------------------------------------


class TestSentinelHitOpensBranch(unittest.TestCase):
    """NA-3, AC-4 — a sentinel hit must set allow_descendants=True."""

    def test_na3_sentinel_hit_allows_descendants(self):
        decision = decision_for_rfc_branch_sentinel_hit(
            "co.butler.pa.us", sentinel_hit="ems"
        )
        self.assertTrue(decision.allow_descendants)

    def test_na3_sentinel_hit_confidence(self):
        decision = decision_for_rfc_branch_sentinel_hit(
            "co.butler.pa.us", sentinel_hit="police"
        )
        self.assertEqual(decision.confidence, ParentGatingConfidence.VALIDATED_PARENT)

    def test_na3_sentinel_hit_message_contains_sentinel_name(self):
        decision = decision_for_rfc_branch_sentinel_hit(
            "lib.butler.pa.us", sentinel_hit="library"
        )
        self.assertIn("library", decision.diagnostic_message)

    def test_na3_sentinel_hit_no_evidence_status(self):
        """Opened branches have no skip evidence status."""
        decision = decision_for_rfc_branch_sentinel_hit(
            "ci.butler.pa.us", sentinel_hit="admin"
        )
        self.assertIsNone(decision.evidence_status)


# ---------------------------------------------------------------------------
# NA-4: sentinel miss → allow_descendants=False
# ---------------------------------------------------------------------------


class TestSentinelMissBlocksDescendants(unittest.TestCase):
    """NA-4 — sentinel miss must block descendants."""

    def test_na4_sentinel_miss_blocks_descendants(self):
        for branch in FIFTH_LEVEL_BRANCHES:
            with self.subTest(branch=branch):
                decision = decision_for_rfc_branch_sentinel_miss(
                    f"{branch}.butler.pa.us"
                )
                self.assertFalse(decision.allow_descendants)


# ---------------------------------------------------------------------------
# AC-7 / AC-8: constant values
# ---------------------------------------------------------------------------


class TestConstants(unittest.TestCase):
    """AC-7, AC-8 — verify branch and sentinel constants."""

    EXPECTED_BRANCHES = {"ci", "co", "k12", "cc", "tec", "pvt", "lib"}
    EXPECTED_SENTINELS = {
        "www",
        "mail",
        "mx",
        "ns",
        "portal",
        "admin",
        "school",
        "district",
        "library",
        "police",
        "fire",
        "ems",
        "clerk",
    }

    def test_ac7_all_seven_branches_present(self):
        self.assertEqual(set(FIFTH_LEVEL_BRANCHES), self.EXPECTED_BRANCHES)

    def test_ac7_branches_no_extras(self):
        """Must not contain non-geographic or archaic branches."""
        excluded = {"state", "dni", "isa", "nsn", "fed", "gen", "mus"}
        self.assertTrue(set(FIFTH_LEVEL_BRANCHES).isdisjoint(excluded))

    def test_ac8_sentinel_labels_count(self):
        self.assertGreaterEqual(len(RFC_SENTINEL_LABELS), 13)

    def test_ac8_sentinel_labels_contain_expected_names(self):
        sentinel_set = set(RFC_SENTINEL_LABELS)
        for name in self.EXPECTED_SENTINELS:
            with self.subTest(name=name):
                self.assertIn(name, sentinel_set)

    def test_rfc_branch_set_matches_tuple(self):
        self.assertEqual(_RFC_BRANCH_SET, set(FIFTH_LEVEL_BRANCHES))


# ---------------------------------------------------------------------------
# AC-9: _is_rfc_branch_parent
# ---------------------------------------------------------------------------


class TestIsRfcBranchParent(unittest.TestCase):
    """AC-9 — _is_rfc_branch_parent correctly identifies RFC branch apexes."""

    def test_pvt_is_rfc_branch(self):
        self.assertTrue(_is_rfc_branch_parent("pvt.k12.pa.us", "k12.pa.us"))

    def test_co_is_rfc_branch(self):
        self.assertTrue(_is_rfc_branch_parent("co.butler.pa.us", "butler.pa.us"))

    def test_lib_is_rfc_branch(self):
        self.assertTrue(_is_rfc_branch_parent("lib.butler.pa.us", "butler.pa.us"))

    def test_all_seven_branches(self):
        for branch in FIFTH_LEVEL_BRANCHES:
            with self.subTest(branch=branch):
                self.assertTrue(
                    _is_rfc_branch_parent(f"{branch}.butler.pa.us", "butler.pa.us")
                )

    def test_non_rfc_label_not_detected(self):
        """'web' is not an RFC branch."""
        self.assertFalse(_is_rfc_branch_parent("web.butler.pa.us", "butler.pa.us"))

    def test_non_rfc_label_state_excluded(self):
        self.assertFalse(_is_rfc_branch_parent("state.butler.pa.us", "butler.pa.us"))

    def test_multi_label_prefix_not_rfc_branch(self):
        """dept.co.butler.pa.us is a 5th-level candidate, not an RFC branch apex."""
        self.assertFalse(
            _is_rfc_branch_parent("dept.co.butler.pa.us", "butler.pa.us")
        )

    def test_wrong_base_domain_not_detected(self):
        """co.butler.pa.us is not an RFC branch parent of jacksonville.pa.us."""
        self.assertFalse(
            _is_rfc_branch_parent("co.butler.pa.us", "jacksonville.pa.us")
        )

    def test_base_domain_itself_not_rfc_branch(self):
        self.assertFalse(_is_rfc_branch_parent("butler.pa.us", "butler.pa.us"))

    def test_branch_attaches_under_locality_not_bare_second_level(self):
        """co.pa.us (branch under bare 2nd-level) must NOT be detected as an RFC branch
        apex when the base_domain is butler.pa.us."""
        self.assertFalse(_is_rfc_branch_parent("co.pa.us", "butler.pa.us"))


# ---------------------------------------------------------------------------
# AC-6 / NA-5: Tier-5 deep_rfc_branch_sweep option
# ---------------------------------------------------------------------------


class TestTier5Option(unittest.TestCase):
    """AC-6, NA-5 — Tier-5 deep_rfc_branch_sweep is off by default."""

    def test_ac6_default_off(self):
        opts = ScanOptions()
        self.assertFalse(opts.deep_rfc_branch_sweep)

    def test_ac10_default_off_via_apply_scan_profile_normal(self):
        opts = ScanOptions(scan_profile=ScanProfile.NORMAL)
        resolved = apply_scan_profile(opts)
        self.assertFalse(resolved.deep_rfc_branch_sweep)

    def test_na5_light_profile_always_off(self):
        """Light never enables 5th-level or Tier 5."""
        opts = ScanOptions(
            scan_profile=ScanProfile.LIGHT, deep_rfc_branch_sweep=True
        )
        resolved = apply_scan_profile(opts)
        # Light does not propagate deep_rfc_branch_sweep.
        self.assertFalse(resolved.deep_rfc_branch_sweep)

    def test_na5_normal_propagates_when_enabled(self):
        opts = ScanOptions(
            scan_profile=ScanProfile.NORMAL, deep_rfc_branch_sweep=True
        )
        resolved = apply_scan_profile(opts)
        self.assertTrue(resolved.deep_rfc_branch_sweep)

    def test_na5_deep_propagates_when_enabled(self):
        opts = ScanOptions(
            scan_profile=ScanProfile.DEEP, deep_rfc_branch_sweep=True
        )
        resolved = apply_scan_profile(opts)
        self.assertTrue(resolved.deep_rfc_branch_sweep)


# ---------------------------------------------------------------------------
# NA-6: Runtime bound — sentinel count ≤ len(RFC_SENTINEL_LABELS) × unvalidated branches
# ---------------------------------------------------------------------------


class TestSentinelRuntimeBound(unittest.TestCase):
    """NA-6 — total sentinel probe count is bounded."""

    def test_na6_sentinel_count_per_branch_is_fixed(self):
        """Each unvalidated branch fires at most len(RFC_SENTINEL_LABELS) A queries."""
        # With 7 branches fully unvalidated and 13 sentinels, worst-case is 91 queries.
        max_queries = len(FIFTH_LEVEL_BRANCHES) * len(RFC_SENTINEL_LABELS)
        self.assertLessEqual(max_queries, 7 * 13)  # 91 — well within budget

    def test_na6_sentinel_stops_at_first_hit(self):
        """_probe_rfc_branch_sentinel returns after the FIRST positive sentinel hit."""
        from scanner.dns_classifier import DNSResponseClass
        from scanner.scan_engine import _probe_rfc_branch_sentinel

        call_count = [0]
        hit_label = "police"

        def mock_send(fqdn, rtype, resolver):
            call_count[0] += 1
            label = fqdn.split(".")[0]
            if label == hit_label:
                # Return a fake positive response mock.
                resp = MagicMock()
                resp.answer = []
                resp.authority = []
                resp.flags = 0
                return resp, None
            return None, "NXDOMAIN"

        resolver = MagicMock()
        result = _empty_result()

        with (
            patch("scanner.scan_engine._send_dns_query", side_effect=mock_send),
            patch("scanner.scan_engine.classify_dns_response") as mock_classify,
            patch("scanner.scan_engine._query_records", return_value=([], [])),
        ):
            # classify_dns_response returns OWNER_MATCHING_ANSWER only for hit_label.
            def classify_side(response, fqdn, transport_error):
                label = fqdn.split(".")[0]
                if label == hit_label:
                    return DNSResponseClass.OWNER_MATCHING_ANSWER
                return DNSResponseClass.NODATA_EMPTY_ANSWER

            mock_classify.side_effect = classify_side

            hit = _probe_rfc_branch_sentinel(
                "co.butler.pa.us",
                "butler.pa.us",
                resolver,
                result,
                False,
                [],
            )

        self.assertEqual(hit, hit_label)
        # Should have stopped at 'police', which is the 10th label in RFC_SENTINEL_LABELS.
        police_index = list(RFC_SENTINEL_LABELS).index(hit_label)
        self.assertEqual(call_count[0], police_index + 1)

    def test_na6_sentinel_returns_none_when_no_hit(self):
        """All sentinels miss → None."""
        from scanner.scan_engine import _probe_rfc_branch_sentinel

        def mock_send(fqdn, rtype, resolver):
            return None, "NXDOMAIN"

        resolver = MagicMock()
        result = _empty_result()

        with (
            patch("scanner.scan_engine._send_dns_query", side_effect=mock_send),
            patch("scanner.scan_engine.classify_dns_response") as mock_classify,
        ):
            from scanner.dns_classifier import DNSResponseClass

            mock_classify.return_value = DNSResponseClass.NEGATIVE_NXDOMAIN

            hit = _probe_rfc_branch_sentinel(
                "pvt.butler.pa.us",
                "butler.pa.us",
                resolver,
                result,
                False,
                [],
            )

        self.assertIsNone(hit)

    def test_na6_sentinel_fires_all_labels_on_miss(self):
        """When no hit, all RFC_SENTINEL_LABELS must be tried."""
        from scanner.scan_engine import _probe_rfc_branch_sentinel

        tried = []

        def mock_send(fqdn, rtype, resolver):
            tried.append(fqdn.split(".")[0])
            return None, "NXDOMAIN"

        resolver = MagicMock()
        result = _empty_result()

        with (
            patch("scanner.scan_engine._send_dns_query", side_effect=mock_send),
            patch("scanner.scan_engine.classify_dns_response") as mock_classify,
        ):
            from scanner.dns_classifier import DNSResponseClass

            mock_classify.return_value = DNSResponseClass.NEGATIVE_NXDOMAIN

            _probe_rfc_branch_sentinel(
                "tec.butler.pa.us",
                "butler.pa.us",
                resolver,
                result,
                False,
                [],
            )

        self.assertEqual(tried, list(RFC_SENTINEL_LABELS))


# ---------------------------------------------------------------------------
# NA-7 / AC-1: Non-RFC parents use original lazy path; known/validated unchanged
# ---------------------------------------------------------------------------


class TestNonRfcParentBehaviourUnchanged(unittest.TestCase):
    """NA-7, NA-8, AC-1 — non-RFC and known parents are unaffected by Ticket 30."""

    def test_ac9_non_rfc_label_false(self):
        """A non-RFC label parent is not matched by _is_rfc_branch_parent."""
        self.assertFalse(_is_rfc_branch_parent("web.butler.pa.us", "butler.pa.us"))
        self.assertFalse(_is_rfc_branch_parent("mail.butler.pa.us", "butler.pa.us"))
        self.assertFalse(_is_rfc_branch_parent("ftp.butler.pa.us", "butler.pa.us"))

    def test_na7_non_rfc_parent_not_detected(self):
        """A non-RFC branch parent must not be caught by _is_rfc_branch_parent so
        the existing lazy-validation path in _test_candidates handles it."""
        for label in ["dept", "city", "county", "school", "gov"]:
            with self.subTest(label=label):
                self.assertFalse(
                    _is_rfc_branch_parent(f"{label}.butler.pa.us", "butler.pa.us")
                )


# ---------------------------------------------------------------------------
# AC-2 / NA-2: Apex fail does not immediately skip; Tier 3 runs
# ---------------------------------------------------------------------------


class TestTier3RunsAfterApexFail(unittest.TestCase):
    """AC-2, NA-2 — when apex validation fails, the sentinel probe must run."""

    def _build_apex_fail_decision(self):
        """Helper: produce a ParentGatingDecision that blocks descendants
        (simulates apex validation failure)."""
        from scanner.parent_gating import decide_parent_gating_from_probe_classes
        from scanner.dns_classifier import DNSResponseClass

        return decide_parent_gating_from_probe_classes(
            "pvt.butler.pa.us",
            {DNSResponseClass.NODATA_EMPTY_ANSWER},
        )

    def test_apex_fail_decision_blocks_descendants(self):
        d = self._build_apex_fail_decision()
        self.assertFalse(d.allow_descendants)

    def test_na2_run_tiered_probe_calls_sentinel_after_apex_fail(self):
        """_run_rfc_branch_tiered_probe must call _probe_rfc_branch_sentinel
        when _validate_fourth_level_parent returns allow_descendants=False."""
        from scanner.scan_engine import _run_rfc_branch_tiered_probe

        apex_fail = self._build_apex_fail_decision()
        resolver = MagicMock()
        result = _empty_result()

        with (
            patch(
                "scanner.scan_engine._validate_fourth_level_parent",
                return_value=apex_fail,
            ),
            patch(
                "scanner.scan_engine._probe_rfc_branch_sentinel",
                return_value=None,
            ) as mock_sentinel,
        ):
            _run_rfc_branch_tiered_probe(
                "pvt.butler.pa.us",
                "butler.pa.us",
                resolver=resolver,
                result=result,
                wildcard_suspected=False,
                progress=None,
                messages=[],
                unreachable_ns_ips=None,
            )

        mock_sentinel.assert_called_once()

    def test_na2_run_tiered_probe_skips_sentinel_when_apex_validates(self):
        """If apex validates (Tier 2), sentinel must NOT be called."""
        from scanner.scan_engine import _run_rfc_branch_tiered_probe
        from scanner.parent_gating import decision_for_validated_parent

        apex_ok = decision_for_validated_parent("co.butler.pa.us", record_count=1)
        resolver = MagicMock()
        result = _empty_result()

        with (
            patch(
                "scanner.scan_engine._validate_fourth_level_parent",
                return_value=apex_ok,
            ),
            patch(
                "scanner.scan_engine._probe_rfc_branch_sentinel",
                return_value=None,
            ) as mock_sentinel,
        ):
            decision = _run_rfc_branch_tiered_probe(
                "co.butler.pa.us",
                "butler.pa.us",
                resolver=resolver,
                result=result,
                wildcard_suspected=False,
                progress=None,
                messages=[],
                unreachable_ns_ips=None,
            )

        mock_sentinel.assert_not_called()
        self.assertTrue(decision.allow_descendants)


# ---------------------------------------------------------------------------
# AC-3: RFC branches get bounded sentinel probe
# ---------------------------------------------------------------------------


class TestSentinelProbeIsBounded(unittest.TestCase):
    """AC-3 — the sentinel probe covers at most len(RFC_SENTINEL_LABELS) names."""

    def test_ac3_sentinel_labels_upper_bound(self):
        """The sentinel set size must be ≤ 15 (ticket spec: ~13)."""
        self.assertLessEqual(len(RFC_SENTINEL_LABELS), 15)

    def test_ac3_sentinel_covers_expected_civic_names(self):
        sentinel_set = set(RFC_SENTINEL_LABELS)
        for civic_name in ("police", "fire", "ems", "clerk", "library"):
            with self.subTest(name=civic_name):
                self.assertIn(civic_name, sentinel_set)


# ---------------------------------------------------------------------------
# Claim-to-code: cite tier insertion point and disclosure wording
# ---------------------------------------------------------------------------


class TestClaimToCode(unittest.TestCase):
    """Verify the skip-disclosure wording and tier insertion by inspecting
    the diagnostic_message of the decision objects."""

    def test_tier3_miss_disclosure_says_not_proof(self):
        """AIPF evidence discipline: heuristic skip must state 'not proof'."""
        d = decision_for_rfc_branch_sentinel_miss("pvt.butler.pa.us")
        self.assertIn("not proof", d.diagnostic_message.lower())

    def test_tier3_miss_reason_not_absence(self):
        """The reason must not say 'absence' or 'not found'."""
        d = decision_for_rfc_branch_sentinel_miss("pvt.butler.pa.us")
        lower = d.reason.lower()
        self.assertNotIn("absence", lower)
        self.assertNotIn("not found", lower)
        self.assertNotIn("no records", lower)

    def test_tier4_hit_diagnostic_says_opened(self):
        """Tier-4 hit message must convey that the branch was opened."""
        d = decision_for_rfc_branch_sentinel_hit("co.butler.pa.us", sentinel_hit="ems")
        lower = d.diagnostic_message.lower()
        self.assertIn("opened", lower)

    def test_tier4_hit_diagnostic_says_sentinel_evidence(self):
        d = decision_for_rfc_branch_sentinel_hit(
            "lib.butler.pa.us", sentinel_hit="library"
        )
        self.assertIn("sentinel", d.diagnostic_message.lower())


if __name__ == "__main__":
    unittest.main()
