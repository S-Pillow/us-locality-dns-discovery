"""AIPF Ticket T32 — NOERROR/NODATA Parent-Authority Classification.

Negative-action tests (durable):
  NA-1  NODATA-parent-authority → NOT delegation (not REFERRAL_DELEGATION).
  NA-2  NODATA-parent-authority → NOT absence (not NEGATIVE_NXDOMAIN).
  NA-3  Delegated apex (NS in authority/answer) → still REFERRAL_DELEGATION.
  NA-4  Genuine NXDOMAIN → still NEGATIVE_NXDOMAIN (no regression).
  NA-5  Skip wording for NODATA-parent ≠ wording for NXDOMAIN.
  NA-6  NODATA-parent class is a no-finding class.

Acceptance-criteria tests:
  AC-1  NOERROR + no-answer + ancestor-SOA-authority → NOERROR_NODATA_PARENT_AUTHORITY.
  AC-2  Distinct from NXDOMAIN, UNRELATED_AUTHORITY, and REFERRAL_DELEGATION.
  AC-3  Not a confirmed finding; not absence.
  AC-4  Skip wording: "no direct DNS records using tested methods" and
        "does not prove descendants do not exist."
  AC-5  pvt.k12.pa.us shape (parent SOA = k12.pa.us) classifies correctly.
  AC-6  Grandparent SOA (pa.us as ancestor of pvt.k12.pa.us) also classifies correctly.
  AC-7  UNRELATED_AUTHORITY not triggered by ancestor-zone SOA.
  AC-8  _is_ancestor helper works correctly.
  AC-9  EvidenceStatus.NODATA_PARENT_AUTHORITY exists and is distinct.
  AC-10 Parent gating produces correct wording for this class.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.name
import dns.rdataset
import dns.rrset


from scanner.dns_classifier import (
    DNSResponseClass,
    _is_ancestor,
    classify_dns_response,
    is_no_finding_class,
)
from scanner.models import EvidenceStatus, ParentGatingConfidence
from scanner.parent_gating import decide_parent_gating_from_probe_classes


# ---------------------------------------------------------------------------
# Helpers to build minimal dns.message.Message objects
# ---------------------------------------------------------------------------


_IN = dns.rdataclass.IN


def _build_noerror_with_authority_soa(qname: str, soa_owner: str) -> dns.message.Message:
    """Build a NOERROR response with no answer and a SOA in authority for soa_owner."""
    msg = dns.message.Message()
    msg.flags = dns.flags.QR | dns.flags.AA
    soa_rrset = dns.rrset.RRset(
        dns.name.from_text(soa_owner + "."),
        _IN,
        dns.rdatatype.SOA,
    )
    msg.authority.append(soa_rrset)
    return msg


def _build_noerror_with_authority_ns(qname: str, ns_owner: str) -> dns.message.Message:
    """Build a NOERROR response with no answer and NS in authority for ns_owner."""
    msg = dns.message.Message()
    msg.flags = dns.flags.QR | dns.flags.AA
    ns_rrset = dns.rrset.RRset(
        dns.name.from_text(ns_owner + "."),
        _IN,
        dns.rdatatype.NS,
    )
    msg.authority.append(ns_rrset)
    return msg


def _build_nxdomain_with_authority_soa(qname: str, soa_owner: str) -> dns.message.Message:
    """Build an NXDOMAIN response with SOA in authority."""
    msg = dns.message.Message()
    msg.flags = dns.flags.QR | dns.flags.AA
    msg.set_rcode(dns.rcode.NXDOMAIN)
    soa_rrset = dns.rrset.RRset(
        dns.name.from_text(soa_owner + "."),
        _IN,
        dns.rdatatype.SOA,
    )
    msg.authority.append(soa_rrset)
    return msg


def _build_noerror_with_own_ns(qname: str) -> dns.message.Message:
    """Build a NOERROR/REFERRAL with NS in authority for the queried name itself."""
    msg = dns.message.Message()
    msg.flags = dns.flags.QR
    ns_rrset = dns.rrset.RRset(
        dns.name.from_text(qname + "."),
        _IN,
        dns.rdatatype.NS,
    )
    msg.authority.append(ns_rrset)
    return msg


def _build_unrelated_soa(qname: str, unrelated_soa_owner: str) -> dns.message.Message:
    """Build a NOERROR with a truly unrelated SOA in authority."""
    msg = dns.message.Message()
    msg.flags = dns.flags.QR
    soa_rrset = dns.rrset.RRset(
        dns.name.from_text(unrelated_soa_owner + "."),
        _IN,
        dns.rdatatype.SOA,
    )
    msg.authority.append(soa_rrset)
    return msg


# ---------------------------------------------------------------------------
# AC-8: _is_ancestor helper
# ---------------------------------------------------------------------------


class TestIsAncestor(unittest.TestCase):
    """AC-8 — _is_ancestor helper correctness."""

    def test_immediate_parent(self):
        self.assertTrue(_is_ancestor("k12.pa.us", "pvt.k12.pa.us"))

    def test_grandparent(self):
        self.assertTrue(_is_ancestor("pa.us", "pvt.k12.pa.us"))

    def test_great_grandparent(self):
        self.assertTrue(_is_ancestor("us", "pvt.k12.pa.us"))

    def test_same_name_not_ancestor(self):
        self.assertFalse(_is_ancestor("pvt.k12.pa.us", "pvt.k12.pa.us"))

    def test_unrelated_not_ancestor(self):
        self.assertFalse(_is_ancestor("godaddy.com", "pvt.k12.pa.us"))

    def test_partial_match_not_ancestor(self):
        # "k12.pa.us" is not an ancestor of "notk12.pa.us"
        self.assertFalse(_is_ancestor("k12.pa.us", "notk12.pa.us"))

    def test_sibling_not_ancestor(self):
        # "ci.k12.pa.us" is not an ancestor of "pvt.k12.pa.us"
        self.assertFalse(_is_ancestor("ci.k12.pa.us", "pvt.k12.pa.us"))

    def test_empty_strings(self):
        self.assertFalse(_is_ancestor("", "pvt.k12.pa.us"))
        self.assertFalse(_is_ancestor("k12.pa.us", ""))


# ---------------------------------------------------------------------------
# AC-1 / AC-5: pvt.k12.pa.us-shape classification
# ---------------------------------------------------------------------------


class TestNodataParentAuthorityClassification(unittest.TestCase):
    """AC-1, AC-5 — NOERROR + no answer + ancestor SOA → NOERROR_NODATA_PARENT_AUTHORITY."""

    def test_ac1_parent_soa_in_authority(self):
        """pvt.k12.pa.us with k12.pa.us SOA in authority → NOERROR_NODATA_PARENT_AUTHORITY."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY)

    def test_ac5_pvt_k12_pa_us_shape(self):
        """The exact pvt.k12.pa.us / k12.pa.us SOA shape classifies correctly."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY)
        self.assertNotEqual(rc, DNSResponseClass.UNRELATED_AUTHORITY)

    def test_ac6_grandparent_soa(self):
        """Grandparent SOA (pa.us as ancestor of pvt.k12.pa.us) also classifies correctly."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY)

    def test_ancestor_soa_alone_classifies(self):
        """Ancestor SOA in authority (no NS) → NOERROR_NODATA_PARENT_AUTHORITY."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY)

    def test_ancestor_soa_with_ancestor_ns_falls_to_unrelated(self):
        """Ancestor SOA + ancestor NS in authority → UNRELATED_AUTHORITY.

        Ancestor-NS in authority indicates the parent zone is asserting its own
        delegation (not a delegation for the queried name).  Ancestor NS still
        sets has_unrelated=True to preserve existing delegation-verifier
        behavior; NOERROR_NODATA_PARENT_AUTHORITY only fires when authority has
        ancestor SOA with NO NS present.
        """
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        ns_rrset = dns.rrset.RRset(
            dns.name.from_text("k12.pa.us."),
            _IN,
            dns.rdatatype.NS,
        )
        msg.authority.append(ns_rrset)
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        # Ancestor NS sets has_unrelated=True → UNRELATED_AUTHORITY wins.
        self.assertEqual(rc, DNSResponseClass.UNRELATED_AUTHORITY)


# ---------------------------------------------------------------------------
# AC-2 / NA-1 / NA-2: Distinctness from other classes
# ---------------------------------------------------------------------------


class TestDistinctFromOtherClasses(unittest.TestCase):
    """AC-2 — NOERROR_NODATA_PARENT_AUTHORITY is distinct from NXDOMAIN, UNRELATED, REFERRAL."""

    def test_ac2_distinct_from_nxdomain(self):
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertNotEqual(rc, DNSResponseClass.NEGATIVE_NXDOMAIN)

    def test_ac2_distinct_from_unrelated_authority(self):
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertNotEqual(rc, DNSResponseClass.UNRELATED_AUTHORITY)

    def test_ac2_distinct_from_referral_delegation(self):
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertNotEqual(rc, DNSResponseClass.REFERRAL_DELEGATION)

    def test_na1_not_delegation(self):
        """NA-1: parent-authority NODATA → NOT delegation."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertNotEqual(rc, DNSResponseClass.REFERRAL_DELEGATION)

    def test_na2_not_absence(self):
        """NA-2: parent-authority NODATA → NOT absence (not NXDOMAIN)."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertNotEqual(rc, DNSResponseClass.NEGATIVE_NXDOMAIN)

    def test_ac7_unrelated_authority_not_triggered_by_ancestor(self):
        """NA-7 / AC-7: ancestor SOA must not route to UNRELATED_AUTHORITY."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertNotEqual(rc, DNSResponseClass.UNRELATED_AUTHORITY)


# ---------------------------------------------------------------------------
# NA-3 / NA-4: Regression — existing classes unaffected
# ---------------------------------------------------------------------------


class TestExistingClassesUnchanged(unittest.TestCase):
    """NA-3, NA-4 — delegation and NXDOMAIN classifications are not regressed."""

    def test_na3_delegated_apex_still_referral(self):
        """NA-3: own NS in authority → REFERRAL_DELEGATION (no regression)."""
        msg = _build_noerror_with_own_ns("pvt.k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.REFERRAL_DELEGATION)

    def test_na4_nxdomain_still_nxdomain(self):
        """NA-4: genuine NXDOMAIN → NEGATIVE_NXDOMAIN (no regression)."""
        msg = _build_nxdomain_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.NEGATIVE_NXDOMAIN)

    def test_truly_unrelated_soa_still_unrelated_authority(self):
        """Truly unrelated SOA (e.g. godaddy.com) → UNRELATED_AUTHORITY."""
        msg = _build_unrelated_soa("pvt.k12.pa.us", "godaddy.com")
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.UNRELATED_AUTHORITY)

    def test_ancestor_soa_plus_unrelated_soa_falls_to_unrelated(self):
        """When ancestor SOA AND truly unrelated SOA present, UNRELATED_AUTHORITY wins."""
        msg = _build_noerror_with_authority_soa("pvt.k12.pa.us", "k12.pa.us")
        # Add a truly unrelated SOA
        unrelated_rrset = dns.rrset.RRset(
            dns.name.from_text("godaddy.com."),
            _IN,
            dns.rdatatype.SOA,
        )
        msg.authority.append(unrelated_rrset)
        rc = classify_dns_response(msg, "pvt.k12.pa.us")
        self.assertEqual(rc, DNSResponseClass.UNRELATED_AUTHORITY)


# ---------------------------------------------------------------------------
# NA-6 / AC-3: No-finding class and non-confirmed
# ---------------------------------------------------------------------------


class TestNoFindingClass(unittest.TestCase):
    """NA-6, AC-3 — NOERROR_NODATA_PARENT_AUTHORITY produces no finding."""

    def test_na6_is_no_finding_class(self):
        """NA-6: NOERROR_NODATA_PARENT_AUTHORITY must be a no-finding class."""
        self.assertTrue(is_no_finding_class(DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY))

    def test_ac3_not_positive_class(self):
        """Not in the positive (finding) classes."""
        positive = {
            DNSResponseClass.OWNER_MATCHING_ANSWER,
            DNSResponseClass.CNAME_ALIAS,
            DNSResponseClass.REFERRAL_DELEGATION,
        }
        self.assertNotIn(DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY, positive)


# ---------------------------------------------------------------------------
# AC-9: EvidenceStatus.NODATA_PARENT_AUTHORITY exists and is distinct
# ---------------------------------------------------------------------------


class TestNodataParentAuthorityEvidenceStatus(unittest.TestCase):
    """AC-9 — NODATA_PARENT_AUTHORITY EvidenceStatus exists and is distinct."""

    def test_ac9_status_exists(self):
        self.assertEqual(
            EvidenceStatus.NODATA_PARENT_AUTHORITY.value, "NODATA_PARENT_AUTHORITY"
        )

    def test_ac9_distinct_from_ignored_unrelated(self):
        self.assertNotEqual(
            EvidenceStatus.NODATA_PARENT_AUTHORITY,
            EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
        )

    def test_ac9_distinct_from_skipped_by_gating(self):
        self.assertNotEqual(
            EvidenceStatus.NODATA_PARENT_AUTHORITY,
            EvidenceStatus.SKIPPED_BY_PARENT_GATING,
        )


# ---------------------------------------------------------------------------
# AC-10 / NA-5: Parent gating produces correct wording; ≠ NXDOMAIN wording
# ---------------------------------------------------------------------------


class TestParentGatingWording(unittest.TestCase):
    """AC-4, AC-10, NA-5 — parent gating decision wording for this class."""

    def _decide(self, classes: set[DNSResponseClass], saw_unrelated: bool = False):
        return decide_parent_gating_from_probe_classes(
            "pvt.k12.pa.us",
            classes,
            saw_unrelated_authority=saw_unrelated,
        )

    def test_ac10_nodata_parent_auth_produces_correct_decision(self):
        """Single NOERROR_NODATA_PARENT_AUTHORITY class → correct gating decision."""
        decision = self._decide({DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY})
        self.assertFalse(decision.allow_descendants)
        self.assertEqual(
            decision.evidence_status, EvidenceStatus.NODATA_PARENT_AUTHORITY
        )
        self.assertEqual(
            decision.response_class,
            DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY.value,
        )
        self.assertEqual(decision.confidence, ParentGatingConfidence.HEURISTIC_SKIP)

    def test_ac4_wording_contains_no_direct_records(self):
        """AC-4: skip wording must say 'no direct DNS records'."""
        decision = self._decide({DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY})
        self.assertIn("no direct", decision.diagnostic_message.lower())

    def test_ac4_wording_contains_does_not_prove(self):
        """AC-4: skip wording must say 'does not prove descendants do not exist'."""
        msg = decision = self._decide(
            {DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY}
        ).diagnostic_message.lower()
        self.assertIn("does not prove", msg)

    def test_na5_nodata_wording_differs_from_nxdomain_wording(self):
        """NA-5: NODATA wording ≠ NXDOMAIN wording — must be distinct messages."""
        nodata_decision = self._decide({DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY})
        nxdomain_decision = self._decide({DNSResponseClass.NEGATIVE_NXDOMAIN})
        self.assertNotEqual(
            nodata_decision.diagnostic_message, nxdomain_decision.diagnostic_message
        )

    def test_na5_nxdomain_wording_does_not_contain_no_direct_records(self):
        """NXDOMAIN wording must NOT say 'no direct DNS records' (NODATA wording)."""
        nxdomain_decision = self._decide({DNSResponseClass.NEGATIVE_NXDOMAIN})
        self.assertNotIn("no direct", nxdomain_decision.diagnostic_message.lower())

    def test_nodata_parent_not_treated_as_unrelated(self):
        """NODATA-parent-authority should NOT trigger the saw_unrelated_authority path."""
        decision = self._decide(
            {DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY},
            saw_unrelated=False,
        )
        self.assertNotEqual(
            decision.evidence_status, EvidenceStatus.IGNORED_UNRELATED_AUTHORITY
        )

    def test_positive_overrides_nodata_parent(self):
        """If both POSITIVE and NODATA-parent classes present, positive wins."""
        decision = self._decide(
            {
                DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY,
                DNSResponseClass.OWNER_MATCHING_ANSWER,
            }
        )
        self.assertTrue(decision.allow_descendants)

    def test_nodata_parent_plus_unrelated_falls_to_unrelated(self):
        """NODATA-parent + UNRELATED → UNRELATED_AUTHORITY takes priority."""
        decision = self._decide(
            {
                DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY,
                DNSResponseClass.UNRELATED_AUTHORITY,
            }
        )
        self.assertEqual(
            decision.evidence_status, EvidenceStatus.IGNORED_UNRELATED_AUTHORITY
        )


if __name__ == "__main__":
    unittest.main()
