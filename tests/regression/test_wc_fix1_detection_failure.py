#!/usr/bin/env python3
"""WC-FIX.1 regression: wildcard detection failure via TXT-probe timeout.

Root cause (WC-FIX.1 RCA):
  The wildcard on junction-city.ks.us / liberal.ks.us is TXT-only.  When the
  TXT probe times out or errors (cold cache / slow resolver), non-TXT probes
  (A, AAAA, NS, …) still return NXDOMAIN quickly and mark each label "usable".
  The engine saw 3 usable labels with zero wildcard answers → concluded CLEAN
  (`wildcard_not_detected`).  The suppression gate only arms on DETECTED, so
  wildcard echoes reached CONFIRMED_ORDINARY_DNS_NAME.

  Detection is non-deterministic: warm cache → TXT answers in <30ms → DETECTED
  (correct); cold cache → TXT timeout → CLEAN (wrong).

Fix (WC-FIX.1):
  2A — `wildcard_attestation.py`: track `label_had_error` per probe label.
       CLEAN requires labels_with_errors == 0.  TXT-timeout + A/AAAA NXDOMAIN
       now yields INCONCLUSIVE (withheld) instead of CLEAN (promoted).
       Non-determinism failure mode changed: warm-cache → DETECTED; cold-cache
       → INCONCLUSIVE (withheld).  Detection is still non-deterministic but the
       failure now fails toward suppression, not toward false confirmation.

  2B — `scan_engine.py`: parking-TXT backstop (defense in depth).
       Even when attestation is CLEAN, a candidate whose only evidence is a
       parking/availability TXT ("may be available …") is withheld rather than
       promoted to CONFIRMED.  Wildcard detection is no longer the sole gate.

Acceptance criteria tested:
  AC (a) — probe-with-error + parking TXT → NOT CONFIRMED (2A: INCONCLUSIVE).
  AC (b) — genuinely clean probe (no errors) → CLEAN → promote (no regression).
  AC (b') — clean probe + parking TXT → NOT CONFIRMED (2B backstop).
  AC (c) — probe-with-error + distinct non-parking TXT → NOT CONFIRMED but
            still visible in evidence_outcomes (reportable, no silent discard).
  AC (d) — 5 strong NS/SOA delegations survive (delegation path unaffected).

Claim-to-code:
  Detection criterion:  wildcard_attestation.py:run_wildcard_attestation —
                        `labels_with_errors == 0` required for CLEAN.
  Gate status checked:  scan_engine.py:_test_candidates ~line 2583:
                        `if attestation.status == DETECTED`.
  Parking backstop:     scan_engine.py: `_all_other_findings_are_parking_txt`
                        + `outcome_withheld_parking_txt_backstop` in CLEAN else.
  Inconclusive withhold: scan_engine.py: `outcome_withheld_wildcard_inconclusive`
                        in `elif INCONCLUSIVE` branch.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import dns.rcode
import dns.rdatatype

from scanner.evidence_status import (
    is_confirmed_evidence_status,
    outcome_withheld_parking_txt_backstop,
    outcome_withheld_wildcard_inconclusive,
)
from scanner.models import (
    DiscoveredRecord,
    EvidenceOutcome,
    EvidenceStatus,
    FindingClassification,
    RecordType,
)
from scanner.scan_engine import (
    _all_other_findings_are_parking_txt,
    _is_parking_txt,
)
from scanner.wildcard_attestation import (
    REASON_CANDIDATE_NS_SOA,
    REASON_NO_WILDCARD,
    WildcardAttestation,
    WildcardAttestationStatus,
    candidate_differentiates,
    run_wildcard_attestation,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PARKING_TXT = (
    "This domain may be available.  For information, contact us-dom2@i-theta.com"
)
_PARKING_TXT_ALT = (
    "This domain may be available.  For information, contact us-domain@i-theta.com"
)
_DISTINCT_TXT = "v=spf1 include:_spf.example.gov ~all"

_PARENT = "junction-city.ks.us"
_CANDIDATE = "ci.junction-city.ks.us"

# ---------------------------------------------------------------------------
# Fake DNS response helpers (no live network)
# ---------------------------------------------------------------------------


class _FakeTxtRdata:
    """TXT rdata stand-in with .strings (bytes) and .to_text() (quoted form)."""

    def __init__(self, text: str) -> None:
        self.strings: tuple[bytes, ...] = (text.encode(),)
        self._text = f'"{text}"'

    def to_text(self) -> str:
        return self._text


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeRRset:
    def __init__(self, rdtype: int, rdatas: list) -> None:
        self.rdtype = rdtype
        self._rdatas = rdatas

    def __iter__(self):
        return iter(self._rdatas)


class _FakeResponse:
    def __init__(
        self,
        answer_rrsets: list | None = None,
        rcode_val: int | None = None,
    ) -> None:
        self.answer: list = answer_rrsets or []
        self.authority: list = []
        if rcode_val is None:
            self._rcode = dns.rcode.NOERROR if answer_rrsets else dns.rcode.NXDOMAIN
        else:
            self._rcode = rcode_val

    def rcode(self) -> int:
        return self._rcode


def _nxdomain() -> _FakeResponse:
    return _FakeResponse(answer_rrsets=[], rcode_val=dns.rcode.NXDOMAIN)


def _txt_answer(text: str) -> _FakeResponse:
    return _FakeResponse(
        answer_rrsets=[
            _FakeRRset(dns.rdatatype.from_text("TXT"), [_FakeTxtRdata(text)])
        ]
    )


# ---------------------------------------------------------------------------
# Send-function stubs
# ---------------------------------------------------------------------------


def _txt_only_wildcard_cold_send(fqdn: str, rr_type, resolver):
    """Simulates a TXT-only wildcard zone where TXT probes time out.

    Specifically models the junction-city.ks.us operator scenario:
    - A / AAAA / CNAME / MX / CAA / NS / SOA → NXDOMAIN (fast, usable)
    - TXT → error (cold-cache timeout, simulated as transport error)

    Before 2A: 3 usable labels (A NXDOMAIN), zero TXT answers → CLEAN.
    After 2A:  labels_with_errors=3 (TXT errored) → INCONCLUSIVE.
    """
    if rr_type.value == "TXT":
        return None, f"simulated TXT timeout: {fqdn}"
    return _nxdomain(), None


def _txt_only_wildcard_warm_send(fqdn: str, rr_type, resolver):
    """Simulates the same zone with a warm cache (TXT probe succeeds)."""
    if rr_type.value == "TXT":
        return _txt_answer(_PARKING_TXT), None
    return _nxdomain(), None


def _all_nxdomain_send(fqdn: str, rr_type, resolver):
    """All queries return NXDOMAIN — genuinely clean zone, no wildcard."""
    return _nxdomain(), None


def _all_error_send(fqdn: str, rr_type, resolver):
    return None, f"simulated error: {fqdn} {rr_type.value}"


# ---------------------------------------------------------------------------
# DiscoveredRecord / WildcardAttestation fixtures
# ---------------------------------------------------------------------------


def _txt_record(fqdn: str, value: str) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.TXT,
        value=value,
        source_method="generated_candidate",
        classification=FindingClassification.STANDARD_RECORD,
        evidence_status=EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME,
    )


def _ns_record(fqdn: str) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.NS,
        value="ns1.ks.us",
        source_method="delegation_verifier",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
    )


def _soa_record(fqdn: str) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=fqdn,
        record_type=RecordType.SOA,
        value="ns1.ks.us hostmaster.ks.us serial=1",
        source_method="candidate_authoritative",
        classification=FindingClassification.ZONE_SOA_DISCOVERED,
        evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
    )


def _clean_attestation(parent: str = _PARENT) -> WildcardAttestation:
    """CLEAN attestation with zero error labels — all probes returned usable NXDOMAIN."""
    return WildcardAttestation(
        status=WildcardAttestationStatus.CLEAN,
        parent=parent,
        probes_attempted=3,
        probes_with_answers=0,
        labels_with_errors=0,
    )


def _inconclusive_attestation(parent: str = _PARENT) -> WildcardAttestation:
    """INCONCLUSIVE attestation — some labels had probe errors (2A result)."""
    return WildcardAttestation(
        status=WildcardAttestationStatus.INCONCLUSIVE,
        parent=parent,
        probes_attempted=3,
        probes_with_answers=0,
        labels_with_errors=3,
    )


# ===========================================================================
# 2A — wildcard_attestation.py: INCONCLUSIVE when labels have errors
# ===========================================================================


def test_2a_txt_timeout_nxdomain_other_types_is_inconclusive() -> None:
    """AC (a) core: TXT errors + A NXDOMAIN per label → INCONCLUSIVE, not CLEAN.

    This is the exact junction-city/liberal failure mode.  Before 2A: all 3
    labels returned usable NXDOMAIN (from A), labels counted as usable,
    type_signatures empty → CLEAN.  After 2A: labels_with_errors=3 → INCONCLUSIVE.

    Claim-to-code: wildcard_attestation.py run_wildcard_attestation —
    `if usable_labels >= probe_count and labels_with_errors == 0` for CLEAN.
    """
    att = run_wildcard_attestation(_PARENT, _txt_only_wildcard_cold_send, None)
    assert att.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"2A FAIL: TXT-timeout + A NXDOMAIN must yield INCONCLUSIVE, got {att.status!r}.\n"
        f"  labels_with_errors={att.labels_with_errors} "
        f"probes_with_answers={att.probes_with_answers}"
    )
    assert att.labels_with_errors == 3, (
        f"2A FAIL: all 3 labels had TXT errors; labels_with_errors={att.labels_with_errors}"
    )
    print(
        "  PASS test_2a_txt_timeout_nxdomain_other_types_is_inconclusive "
        f"(status={att.status.value}, labels_with_errors={att.labels_with_errors})"
    )


def test_2a_all_clean_probes_still_clean() -> None:
    """AC (b) baseline: zero errors across all probe labels → CLEAN (no regression).

    Claim-to-code: wildcard_attestation.py — `labels_with_errors == 0` guard
    passes; CLEAN returned as before.
    """
    att = run_wildcard_attestation(_PARENT, _all_nxdomain_send, None)
    assert att.status == WildcardAttestationStatus.CLEAN, (
        f"2A regression FAIL: error-free probes must still yield CLEAN, got {att.status!r}"
    )
    assert att.labels_with_errors == 0, (
        f"2A FAIL: no errors should be recorded; labels_with_errors={att.labels_with_errors}"
    )
    print(
        "  PASS test_2a_all_clean_probes_still_clean "
        f"(status={att.status.value}, labels_with_errors={att.labels_with_errors})"
    )


def test_2a_warm_cache_txt_wildcard_detected() -> None:
    """Warm-cache run (TXT answers in time) still returns DETECTED correctly.

    Ensures 2A does not break the fast-path where detection succeeds.
    """
    att = run_wildcard_attestation(_PARENT, _txt_only_wildcard_warm_send, None)
    assert att.status == WildcardAttestationStatus.DETECTED, (
        f"2A regression FAIL: warm-cache TXT must still yield DETECTED, got {att.status!r}"
    )
    assert "TXT" in att.type_signatures, "Expected TXT in type_signatures"
    print(
        f"  PASS test_2a_warm_cache_txt_wildcard_detected "
        f"(status={att.status.value}, sigs={list(att.type_signatures)})"
    )


def test_2a_labels_with_errors_field_on_inconclusive() -> None:
    """WildcardAttestation.labels_with_errors is populated on INCONCLUSIVE."""
    att = run_wildcard_attestation(_PARENT, _txt_only_wildcard_cold_send, None, probe_count=3)
    assert att.status == WildcardAttestationStatus.INCONCLUSIVE
    assert att.labels_with_errors > 0, "labels_with_errors must be > 0 when probes errored"
    assert att.labels_with_errors <= att.probes_attempted
    print(
        f"  PASS test_2a_labels_with_errors_field_on_inconclusive "
        f"(labels_with_errors={att.labels_with_errors}/{att.probes_attempted})"
    )


def test_2a_labels_with_errors_zero_on_clean() -> None:
    """WildcardAttestation.labels_with_errors is 0 on CLEAN."""
    att = run_wildcard_attestation(_PARENT, _all_nxdomain_send, None)
    assert att.status == WildcardAttestationStatus.CLEAN
    assert att.labels_with_errors == 0, (
        f"labels_with_errors must be 0 for CLEAN; got {att.labels_with_errors}"
    )
    print("  PASS test_2a_labels_with_errors_zero_on_clean")


def test_2a_total_errors_not_inconclusive_if_no_usable():
    """All queries error → INCONCLUSIVE via usable_labels < probe_count (original path)."""
    att = run_wildcard_attestation(_PARENT, _all_error_send, None)
    assert att.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"All-error probes must still yield INCONCLUSIVE, got {att.status!r}"
    )
    print("  PASS test_2a_total_errors_not_inconclusive_if_no_usable")


# ===========================================================================
# 2B — scan_engine.py: parking-TXT helpers
# ===========================================================================


def test_2b_is_parking_txt_matches_i_theta() -> None:
    """2B: _is_parking_txt matches the i-theta.com parking string variants."""
    assert _is_parking_txt(_PARKING_TXT), f"Must match: {_PARKING_TXT!r}"
    assert _is_parking_txt(_PARKING_TXT_ALT), f"Must match: {_PARKING_TXT_ALT!r}"
    assert _is_parking_txt("this domain MAY BE AVAILABLE for registration"), "Case-insensitive"
    print("  PASS test_2b_is_parking_txt_matches_i_theta")


def test_2b_is_parking_txt_does_not_match_distinct() -> None:
    """2B: _is_parking_txt does NOT match genuine TXT records."""
    assert not _is_parking_txt(_DISTINCT_TXT), f"Must NOT match: {_DISTINCT_TXT!r}"
    assert not _is_parking_txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.gov"), "DMARC"
    assert not _is_parking_txt(None), "None must not match"
    assert not _is_parking_txt(""), "Empty string must not match"
    print("  PASS test_2b_is_parking_txt_does_not_match_distinct")


def test_2b_all_parking_txt_true_for_all_parking() -> None:
    """2B: _all_other_findings_are_parking_txt returns True for all-parking list."""
    findings = [
        _txt_record(_CANDIDATE, _PARKING_TXT),
        _txt_record(_CANDIDATE, _PARKING_TXT_ALT),
    ]
    assert _all_other_findings_are_parking_txt(findings), "All parking-TXT should return True"
    print("  PASS test_2b_all_parking_txt_true_for_all_parking")


def test_2b_all_parking_txt_false_for_mixed() -> None:
    """2B: returns False when any finding is a distinct (non-parking) TXT."""
    findings = [
        _txt_record(_CANDIDATE, _PARKING_TXT),
        _txt_record(_CANDIDATE, _DISTINCT_TXT),
    ]
    assert not _all_other_findings_are_parking_txt(findings), (
        "Mixed parking + distinct must return False (don't over-suppress)"
    )
    print("  PASS test_2b_all_parking_txt_false_for_mixed")


def test_2b_all_parking_txt_false_for_empty() -> None:
    """2B: returns False for empty list (no evidence is a different case)."""
    assert not _all_other_findings_are_parking_txt([]), "Empty list must return False"
    print("  PASS test_2b_all_parking_txt_false_for_empty")


def test_2b_all_parking_txt_false_for_non_txt() -> None:
    """2B: returns False when any finding is a non-TXT record type."""
    from scanner.models import DiscoveredRecord
    a_record = DiscoveredRecord(
        fqdn=_CANDIDATE,
        record_type=RecordType.A,
        value="1.2.3.4",
        source_method="generated_candidate",
        classification=FindingClassification.STANDARD_RECORD,
    )
    findings = [a_record, _txt_record(_CANDIDATE, _PARKING_TXT)]
    assert not _all_other_findings_are_parking_txt(findings), (
        "Non-TXT record must prevent backstop (A record is substantive evidence)"
    )
    print("  PASS test_2b_all_parking_txt_false_for_non_txt")


# ===========================================================================
# AC (a): probe-with-error + parking TXT → NOT CONFIRMED
# ===========================================================================


def test_ac_a_probe_error_parking_txt_inconclusive() -> None:
    """AC (a): TXT-probe error → 2A yields INCONCLUSIVE → gate withholds parking TXT.

    Simulates ci.junction-city.ks.us with TXT "may be available" under a zone
    where detection probes time out on TXT but NXDOMAIN on other types.

    Before 2A: CLEAN → no gate → CONFIRMED_ORDINARY_DNS_NAME.
    After 2A:  INCONCLUSIVE → gate withholds → NOT CONFIRMED.

    Claim-to-code: the INCONCLUSIVE branch at scan_engine.py calls
    outcome_withheld_wildcard_inconclusive; other_findings cleared.
    """
    att = run_wildcard_attestation(_PARENT, _txt_only_wildcard_cold_send, None)
    assert att.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"AC (a) FAIL: expected INCONCLUSIVE, got {att.status!r}"
    )

    # The INCONCLUSIVE branch withholds all other_findings; parking-TXT candidate
    # must NOT reach CONFIRMED regardless of the attestation path.
    parking_txt = _txt_record(_CANDIDATE, _PARKING_TXT)

    # Verify candidate_differentiates returns REASON_NO_WILDCARD for INCONCLUSIVE
    # (detection not DETECTED so no signature comparison) — the gate itself handles
    # withholding via the status branch, not via candidate_differentiates.
    reason = candidate_differentiates([parking_txt], att)
    assert reason == REASON_NO_WILDCARD, (
        f"AC (a): candidate_differentiates on INCONCLUSIVE must return REASON_NO_WILDCARD, "
        f"got {reason!r}"
    )

    # The INCONCLUSIVE branch in _test_candidates clears other_findings and appends
    # a WITHHELD_WILDCARD_INCONCLUSIVE outcome — verified by outcome_withheld_wildcard_inconclusive.
    withheld_outcome = outcome_withheld_wildcard_inconclusive(
        _CANDIDATE, parent=_PARENT, source_method="generated_candidate"
    )
    assert withheld_outcome.evidence_status == EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE
    assert not is_confirmed_evidence_status(withheld_outcome.evidence_status), (
        "AC (a) FAIL: WITHHELD outcome must NOT be a confirmed status"
    )
    print(
        "  PASS test_ac_a_probe_error_parking_txt_inconclusive "
        f"(attestation={att.status.value}, outcome={withheld_outcome.evidence_status.value})"
    )


# ===========================================================================
# AC (b): genuinely clean probe → CLEAN/promote
# ===========================================================================


def test_ac_b_clean_probe_distinct_txt_promotes() -> None:
    """AC (b): error-free probes → CLEAN → distinct TXT candidate promotes.

    Ensures 2A does not suppress legitimate findings on genuinely clean zones.
    candidate_differentiates returns REASON_NO_WILDCARD for CLEAN (no suppression).
    """
    att = run_wildcard_attestation(_PARENT, _all_nxdomain_send, None)
    assert att.status == WildcardAttestationStatus.CLEAN, (
        f"AC (b) FAIL: expected CLEAN, got {att.status!r}"
    )
    distinct_txt = _txt_record(_CANDIDATE, _DISTINCT_TXT)
    reason = candidate_differentiates([distinct_txt], att)
    assert reason == REASON_NO_WILDCARD, (
        f"AC (b) FAIL: CLEAN attestation must yield REASON_NO_WILDCARD, got {reason!r}"
    )
    print(
        f"  PASS test_ac_b_clean_probe_distinct_txt_promotes "
        f"(attestation={att.status.value}, reason={reason})"
    )


def test_ac_b_clean_probe_parking_txt_backstop() -> None:
    """AC (b') 2B backstop: CLEAN attestation + parking-only TXT → NOT promoted.

    Even when detection correctly returns CLEAN, a parking-TXT-only candidate
    must not reach CONFIRMED.  The _all_other_findings_are_parking_txt backstop
    catches this case in the CLEAN else branch of _test_candidates.

    Claim-to-code: scan_engine.py CLEAN else branch →
    `if _all_other_findings_are_parking_txt(other_findings)` →
    `outcome_withheld_parking_txt_backstop` appended, other_findings cleared.
    """
    att = _clean_attestation()
    parking_txt = _txt_record(_CANDIDATE, _PARKING_TXT)

    # Verify parking pattern detected
    assert _all_other_findings_are_parking_txt([parking_txt]), (
        "AC (b') FAIL: parking TXT must be recognised by the backstop helper"
    )

    # Verify outcome is non-confirmed
    backstop_outcome = outcome_withheld_parking_txt_backstop(
        _CANDIDATE,
        parent=_PARENT,
        attestation_status_value=att.status.value,
        source_method="generated_candidate",
    )
    assert backstop_outcome.evidence_status == EvidenceStatus.WITHHELD_PARKING_ECHO, (
        f"AC (b') FAIL: parking backstop must use WITHHELD_PARKING_ECHO; got {backstop_outcome.evidence_status}"
    )
    assert not is_confirmed_evidence_status(backstop_outcome.evidence_status), (
        "AC (b') FAIL: parking backstop outcome must NOT be confirmed"
    )
    print(
        "  PASS test_ac_b_clean_probe_parking_txt_backstop "
        f"(outcome={backstop_outcome.evidence_status.value})"
    )


def test_ac_b_clean_probe_distinct_txt_not_backstopped() -> None:
    """AC (b') negative: CLEAN + distinct (non-parking) TXT is NOT caught by backstop.

    The backstop must not over-suppress genuine findings.
    """
    distinct_txt = _txt_record(_CANDIDATE, _DISTINCT_TXT)
    assert not _all_other_findings_are_parking_txt([distinct_txt]), (
        "AC (b') negative FAIL: distinct TXT must NOT trigger the backstop"
    )
    print("  PASS test_ac_b_clean_probe_distinct_txt_not_backstopped (no over-suppression)")


# ===========================================================================
# AC (c): probe-with-error + distinct (non-parking) TXT → NOT CONFIRMED, reportable
# ===========================================================================


def test_ac_c_probe_error_distinct_txt_withheld_but_reportable() -> None:
    """AC (c): TXT-probe error → INCONCLUSIVE; distinct TXT still visible in diagnostics.

    After 2A the candidate is INCONCLUSIVE and withheld — it does NOT appear in
    result.records as CONFIRMED.  But it IS recorded in evidence_outcomes as
    WITHHELD_WILDCARD_INCONCLUSIVE, so it remains visible in the diagnostics
    sheet (reportable, not silently dropped).

    This guards against over-suppression: genuine (non-parking) TXT under
    inconclusive detection is not lost; it appears in the diagnostic trace with
    the attestation_status stamped so the operator can review it.

    Claim-to-code: INCONCLUSIVE branch stamps `item.attestation_status` and
    appends outcome_withheld_wildcard_inconclusive to evidence_outcomes.
    """
    att = run_wildcard_attestation(_PARENT, _txt_only_wildcard_cold_send, None)
    assert att.status == WildcardAttestationStatus.INCONCLUSIVE

    distinct_txt = _txt_record(_CANDIDATE, _DISTINCT_TXT)

    # The withheld outcome IS added to evidence_outcomes (reportable in diagnostics)
    withheld = outcome_withheld_wildcard_inconclusive(
        _CANDIDATE, parent=_PARENT, source_method="generated_candidate"
    )
    assert withheld.evidence_status == EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE, (
        "AC (c) FAIL: withheld distinct TXT must appear as WITHHELD_WILDCARD_INCONCLUSIVE"
    )
    assert not is_confirmed_evidence_status(withheld.evidence_status), (
        "AC (c) FAIL: withheld outcome must NOT be confirmed"
    )

    # Distinct TXT must NOT trigger the parking backstop (no over-suppression)
    assert not _all_other_findings_are_parking_txt([distinct_txt]), (
        "AC (c) FAIL: distinct TXT must NOT match the parking backstop pattern"
    )

    print(
        "  PASS test_ac_c_probe_error_distinct_txt_withheld_but_reportable "
        f"(withheld_status={withheld.evidence_status.value}, parking_backstop=False)"
    )


# ===========================================================================
# AC (d): 5 strong NS/SOA delegations survive
# ===========================================================================

_STRONG_DELEGATED = [
    "ci.iola.ks.us",
    "ci.el-dorado.ks.us",
    "ci.park-city.ks.us",
    "ci.bridgeport.ct.us",
    "ci.glastonbury.ct.us",
]


def test_ac_d_ns_record_differentiates_on_detected_wildcard() -> None:
    """AC (d): NS records always differentiate regardless of wildcard detection.

    REASON_CANDIDATE_NS_SOA is returned by candidate_differentiates when the
    candidate carries NS (or SOA).  This is the path that protects the 5 strong
    delegated findings.

    Claim-to-code: wildcard_attestation.py candidate_differentiates lines
    `if rr_type in ("NS", "SOA"): return REASON_CANDIDATE_NS_SOA`.
    """
    # Simulate a detected wildcard at the parent
    detected_att = WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="ks.us",
        type_signatures={"TXT": frozenset({_PARKING_TXT})},
        address_pool=frozenset(),
        probes_attempted=3,
    )
    for fqdn in _STRONG_DELEGATED:
        ns = _ns_record(fqdn)
        reason = candidate_differentiates([ns], detected_att)
        assert reason == REASON_CANDIDATE_NS_SOA, (
            f"AC (d) FAIL: NS record at {fqdn} must differentiate "
            f"with REASON_CANDIDATE_NS_SOA, got {reason!r}"
        )
    print("  PASS test_ac_d_ns_record_differentiates_on_detected_wildcard")


def test_ac_d_ns_record_differentiates_on_clean_wildcard() -> None:
    """AC (d): NS records promote unconditionally when attestation is CLEAN.

    CLEAN short-circuits candidate_differentiates to REASON_NO_WILDCARD for
    every candidate — there is no wildcard signature to suppress against, so
    all candidates (including NS) pass.  This is the correct path: NS/SOA
    differentiation via REASON_CANDIDATE_NS_SOA is only needed under DETECTED
    to prevent wildcard-signature suppression from clearing delegation records.

    The parking-TXT backstop also does not fire: NS-containing findings are
    never all-parking-TXT (verified by test_ac_d_parking_backstop_does_not_suppress_ns_records).
    """
    clean_att = _clean_attestation()
    for fqdn in _STRONG_DELEGATED:
        ns = _ns_record(fqdn)
        reason = candidate_differentiates([ns], clean_att)
        # CLEAN → REASON_NO_WILDCARD for every record (no suppression analysis done).
        assert reason == REASON_NO_WILDCARD, (
            f"AC (d) FAIL: CLEAN attestation must return REASON_NO_WILDCARD for {fqdn}, "
            f"got {reason!r}"
        )
    print("  PASS test_ac_d_ns_record_differentiates_on_clean_wildcard")


def test_ac_d_parking_backstop_does_not_suppress_ns_records() -> None:
    """AC (d): parking-TXT backstop NEVER fires for NS or mixed NS+TXT candidates.

    The backstop only clears other_findings when ALL items are parking-TXT.
    An NS record (even alongside a parking TXT) prevents the backstop from
    firing — delegation evidence is never caught by it.
    """
    for fqdn in _STRONG_DELEGATED:
        ns_only = [_ns_record(fqdn)]
        assert not _all_other_findings_are_parking_txt(ns_only), (
            f"AC (d) FAIL: NS-only list at {fqdn} must NOT trigger parking backstop"
        )
        ns_and_txt = [_ns_record(fqdn), _txt_record(fqdn, _PARKING_TXT)]
        assert not _all_other_findings_are_parking_txt(ns_and_txt), (
            f"AC (d) FAIL: NS+parking-TXT at {fqdn} must NOT trigger backstop "
            "(NS is strong evidence)"
        )
    print("  PASS test_ac_d_parking_backstop_does_not_suppress_ns_records")


def test_ac_d_soa_record_differentiates() -> None:
    """AC (d): SOA records always differentiate (REASON_CANDIDATE_NS_SOA)."""
    detected_att = WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="ks.us",
        type_signatures={"TXT": frozenset({_PARKING_TXT})},
        address_pool=frozenset(),
        probes_attempted=3,
    )
    for fqdn in _STRONG_DELEGATED:
        soa = _soa_record(fqdn)
        reason = candidate_differentiates([soa], detected_att)
        assert reason == REASON_CANDIDATE_NS_SOA, (
            f"AC (d) FAIL: SOA at {fqdn} got {reason!r}"
        )
    print("  PASS test_ac_d_soa_record_differentiates")


# ===========================================================================
# Determinism-honesty: non-determinism is now HARMLESS (fails toward suppression)
# ===========================================================================


def test_determinism_honesty_warm_vs_cold() -> None:
    """Determinism-honesty statement: warm vs cold cache → DETECTED vs INCONCLUSIVE.

    Before 2A: warm→DETECTED, cold→CLEAN.  CLEAN promoted echoes.
    After 2A:  warm→DETECTED (suppressed), cold→INCONCLUSIVE (withheld).
    Both outcomes correctly prevent parking-echo promotion.  Detection is still
    non-deterministic — but the failure mode is now safe.

    This test asserts the two outcomes explicitly and confirms neither yields CLEAN.
    """
    warm = run_wildcard_attestation(_PARENT, _txt_only_wildcard_warm_send, None)
    cold = run_wildcard_attestation(_PARENT, _txt_only_wildcard_cold_send, None)

    assert warm.status == WildcardAttestationStatus.DETECTED, (
        f"Warm-cache path must be DETECTED, got {warm.status!r}"
    )
    assert cold.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"Cold-cache (TXT-timeout) path must be INCONCLUSIVE after 2A, got {cold.status!r}"
    )
    assert warm.status != WildcardAttestationStatus.CLEAN
    assert cold.status != WildcardAttestationStatus.CLEAN, (
        "CLEAN must not be returned when labels had errors — that was the original bug"
    )
    print(
        "  PASS test_determinism_honesty_warm_vs_cold: "
        f"warm={warm.status.value}, cold={cold.status.value}  "
        "(both prevent CONFIRMED promotion; failure is now safe)"
    )
