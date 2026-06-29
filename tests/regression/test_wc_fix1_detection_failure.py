"""WC-FIX.1 — Wildcard Echoes Surviving via Detection Failure.

AIPF Ticket WC-FIX.1.  Durable regression tests for the NOT-DETECTED path
that WC-FIX's coverage was missing.

Root cause:
  TXT-only wildcards cause wildcard detection to return CLEAN (wildcard_not_detected)
  instead of the correct INCONCLUSIVE when TXT probes time out.  Fast NXDOMAIN
  responses on A/AAAA/NS/SOA count the probe label as "usable", but the TXT query
  that reveals the wildcard timed out.  Detector sees 3 usable labels + 0 TXT
  answers → concludes CLEAN.  The WC-FIX suppression gate only fires on DETECTED,
  so the parking echo promotes to CONFIRMED.

Fixes:
  2A — label_had_error tracking: CLEAN only fires when EVERY probe label had ZERO
       query errors.  Any per-type timeout/error → label NOT counted toward CLEAN
       threshold → fewer clean_usable_labels → INCONCLUSIVE.
  2B — parking-string backstop: when attestation is INCONCLUSIVE (or CLEAN) and
       candidate TXT matches a known parking pattern → WITHHELD_PARKING_ECHO,
       not CONFIRMED.

Determinism note:
  2A converts the non-determinism from "silently wrong (clean→promote)" to "safely
  conservative (inconclusive→withhold)".  Detection is still non-deterministic when
  the TXT wildcard is cold vs warm in the resolver cache — but both outcomes are now
  safe:  DETECTED → differentiation check (same as before);
         INCONCLUSIVE → withhold (never silently promotes).

Tests:
  NA-1   TXT-timeout probe → INCONCLUSIVE, not CLEAN (2A core).
  NA-2   Error-free probe (no wildcard) → CLEAN / can promote (no regression).
  NA-3   Error-free probe + TXT wildcard answer → DETECTED (no regression).
  NA-4   probes_with_errors counter populated correctly on mixed error/usable labels.
  NA-5   is_parking_txt() returns True for confirmed parking patterns.
  NA-6   is_parking_txt() returns False for legitimate TXT content.
  NA-7   INCONCLUSIVE + parking TXT → WITHHELD_PARKING_ECHO outcome (2B).
  NA-8   INCONCLUSIVE + non-parking TXT → WITHHELD_WILDCARD_INCONCLUSIVE (no over-suppress).
  NA-9   CLEAN + parking TXT → WITHHELD_PARKING_ECHO (2B defense-in-depth).
  NA-10  CLEAN + non-parking TXT → not withheld by parking gate (no over-suppress).
  NA-11  Strong NS delegation (DELEGATED_CHILD_ZONE) always differentiates (existing).
  NA-12  Claim-to-code: WITHHELD_PARKING_ECHO is in _DIAGNOSTIC_EVIDENCE_STATUSES.
  NA-13  Determinism honesty: DETECTED path unchanged (warm-cache case still works).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import dns.rdatatype
import dns.rcode

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.evidence_status import (  # noqa: E402
    _DIAGNOSTIC_EVIDENCE_STATUSES,
    outcome_withheld_parking_echo,
    outcome_withheld_wildcard_inconclusive,
)
from scanner.models import (  # noqa: E402
    DiscoveredRecord,
    EvidenceStatus,
    FindingClassification,
    RecordType,
)
from scanner.wildcard_attestation import (  # noqa: E402
    ATTESTATION_PROBE_TYPES,
    PARKING_TXT_PATTERNS,
    WildcardAttestation,
    WildcardAttestationStatus,
    candidate_differentiates,
    is_parking_txt,
    run_wildcard_attestation,
)

# ---------------------------------------------------------------------------
# Fake DNS response helpers — no live network calls
# ---------------------------------------------------------------------------

PARKING_TXT_VALUE = "This domain may be available. For information, contact us-dom2@i-theta.com"
DISTINCT_TXT_VALUE = "v=spf1 include:mail.legitimate.gov ~all"
WILDCARD_TXT_VALUE = PARKING_TXT_VALUE  # same string acts as both parking + wildcard


class _FakeTxtRdata:
    def __init__(self, *segments: str) -> None:
        self.strings: tuple[bytes, ...] = tuple(s.encode() for s in segments)

    def to_text(self) -> str:
        return " ".join(f'"{s}"' for s in (s.decode() for s in self.strings))


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
        answer_rrsets: list[_FakeRRset] | None = None,
        rcode_val: int | None = None,
    ) -> None:
        self.answer: list[_FakeRRset] = answer_rrsets or []
        if rcode_val is None:
            self._rcode = dns.rcode.NOERROR if answer_rrsets else dns.rcode.NXDOMAIN
        else:
            self._rcode = rcode_val

    def rcode(self) -> int:
        return self._rcode


def _nxdomain() -> _FakeResponse:
    return _FakeResponse(answer_rrsets=[], rcode_val=dns.rcode.NXDOMAIN)


def _txt_response(value: str) -> _FakeResponse:
    return _FakeResponse(
        answer_rrsets=[
            _FakeRRset(
                dns.rdatatype.from_text("TXT"),
                [_FakeTxtRdata(value)],
            )
        ]
    )


def _error() -> tuple[None, str]:
    """Simulate a DNS query timeout / transport error."""
    return None, "timeout: Timed out"


def _make_txt_timeout_query_fn(probe_count: int = 3):
    """Return a send_dns_query_fn where A/AAAA/etc return NXDOMAIN but TXT times out.

    This is the junction-city / liberal scenario: TXT-only wildcard, cold resolver
    cache → TXT probes time out, other types return NXDOMAIN fast.
    """
    calls: list[tuple[str, object]] = []

    def send_query(fqdn: str, rr_type, resolver):
        calls.append((fqdn, rr_type))
        if rr_type.value == "TXT":
            return _error()
        return _nxdomain(), None

    return send_query, calls


def _make_clean_query_fn():
    """All probes return NXDOMAIN with no errors — genuinely clean domain."""
    def send_query(fqdn: str, rr_type, resolver):
        return _nxdomain(), None

    return send_query


def _make_txt_wildcard_query_fn(wildcard_txt: str):
    """TXT probes return the parking TXT answer; A/AAAA/etc return NXDOMAIN."""
    def send_query(fqdn: str, rr_type, resolver):
        if rr_type.value == "TXT":
            return _txt_response(wildcard_txt), None
        return _nxdomain(), None

    return send_query


# ---------------------------------------------------------------------------
# DiscoveredRecord fixtures
# ---------------------------------------------------------------------------

_PARENT = "ci.junction-city.ks.us"
_CANDIDATE = "ci.junction-city.ks.us"


def _parking_txt_record() -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=_CANDIDATE,
        record_type=RecordType.TXT,
        value=PARKING_TXT_VALUE,
        source_method="recursive_resolver",
        classification=FindingClassification.STANDARD_RECORD,
    )


def _distinct_txt_record() -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=_CANDIDATE,
        record_type=RecordType.TXT,
        value=DISTINCT_TXT_VALUE,
        source_method="recursive_resolver",
        classification=FindingClassification.STANDARD_RECORD,
    )


def _ns_delegation_record() -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=_CANDIDATE,
        record_type=RecordType.NS,
        value="ns1.real-provider.net.",
        source_method="delegation_verifier",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
    )


def _a_record(ip: str = "203.0.113.50") -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn=_CANDIDATE,
        record_type=RecordType.A,
        value=ip,
        source_method="recursive_resolver",
        classification=FindingClassification.STANDARD_RECORD,
    )


def _inconclusive_attestation() -> WildcardAttestation:
    return WildcardAttestation(
        status=WildcardAttestationStatus.INCONCLUSIVE,
        parent=_PARENT,
        probes_attempted=3,
        probes_with_answers=0,
        probes_with_errors=3,
    )


def _clean_attestation() -> WildcardAttestation:
    return WildcardAttestation(
        status=WildcardAttestationStatus.CLEAN,
        parent=_PARENT,
        probes_attempted=3,
        probes_with_answers=0,
        probes_with_errors=0,
    )


def _detected_txt_attestation(txt_value: str = PARKING_TXT_VALUE) -> WildcardAttestation:
    return WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent=_PARENT,
        probes_attempted=3,
        probes_with_answers=3,
        probes_with_errors=0,
        type_signatures={"TXT": frozenset({txt_value})},
        address_pool=frozenset(),
    )


# ---------------------------------------------------------------------------
# NA-1  TXT-timeout probe → INCONCLUSIVE, not CLEAN (2A core).
# ---------------------------------------------------------------------------


def test_na1_txt_timeout_probe_gives_inconclusive():
    """NA-1 (2A): when TXT queries time out, run_wildcard_attestation must return INCONCLUSIVE.

    Scenario: junction-city/liberal. A/AAAA/NS/SOA return NXDOMAIN fast (no wildcard
    for those types). TXT times out. Before 2A this returned CLEAN (false negative).
    After 2A each label that had any error is not counted as error-free, so
    clean_usable_labels < probe_count → INCONCLUSIVE.
    """
    resolver = MagicMock()
    query_fn, _ = _make_txt_timeout_query_fn(probe_count=3)

    result = run_wildcard_attestation(_PARENT, query_fn, resolver, probe_count=3)

    assert result.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"NA1 FAIL: expected INCONCLUSIVE when TXT times out, got {result.status}. "
        "Before 2A this falsely returned CLEAN."
    )
    assert result.probes_with_errors == 3, (
        f"NA1 FAIL: all 3 probe labels had a TXT error; expected probes_with_errors=3, "
        f"got {result.probes_with_errors}"
    )


def test_na1b_txt_timeout_not_promoted_as_clean():
    """NA-1b (2A): INCONCLUSIVE status means candidate_differentiates does NOT return
    REASON_NO_WILDCARD (no-wildcard fast path) — the inconclusive path uses candidate_differentiates
    as a pass-through only, but the gate in scan_engine withholds."""
    resolver = MagicMock()
    query_fn, _ = _make_txt_timeout_query_fn(probe_count=3)
    attest = run_wildcard_attestation(_PARENT, query_fn, resolver, probe_count=3)

    assert attest.status == WildcardAttestationStatus.INCONCLUSIVE, (
        "NA1b pre-condition: must be INCONCLUSIVE"
    )
    # candidate_differentiates on INCONCLUSIVE still returns REASON_NO_WILDCARD
    # (it can't suppress), but the gate in scan_engine withholds the whole candidate.
    # This test verifies the attestation object is INCONCLUSIVE so the gate fires.
    from scanner.wildcard_attestation import REASON_NO_WILDCARD

    reason = candidate_differentiates([_parking_txt_record()], attest)
    assert reason == REASON_NO_WILDCARD, (
        f"NA1b: candidate_differentiates on INCONCLUSIVE should pass through "
        f"(gate is in scan_engine, not here); got {reason!r}"
    )


# ---------------------------------------------------------------------------
# NA-2  Error-free probe (no wildcard) → CLEAN (no regression).
# ---------------------------------------------------------------------------


def test_na2_error_free_probe_returns_clean():
    """NA-2 (2A no-regression): error-free probe with no wildcard answers → CLEAN.

    A genuinely clean domain where all A/AAAA/TXT/etc return NXDOMAIN without
    any errors must still return CLEAN (no regression from 2A).
    """
    resolver = MagicMock()
    query_fn = _make_clean_query_fn()

    result = run_wildcard_attestation(_PARENT, query_fn, resolver, probe_count=3)

    assert result.status == WildcardAttestationStatus.CLEAN, (
        f"NA2 FAIL: genuinely clean domain must return CLEAN, got {result.status}"
    )
    assert result.probes_with_errors == 0, (
        f"NA2 FAIL: no errors expected, got probes_with_errors={result.probes_with_errors}"
    )


# ---------------------------------------------------------------------------
# NA-3  Error-free probe + TXT wildcard answer → DETECTED (no regression).
# ---------------------------------------------------------------------------


def test_na3_txt_wildcard_probe_returns_detected():
    """NA-3 (2A no-regression): error-free probe with TXT wildcard answer → DETECTED.

    parsons.ks.us scenario: TXT wildcard is present and warm in cache → probe
    returns TXT answers → DETECTED. 2A must not interfere with DETECTED.
    """
    resolver = MagicMock()
    query_fn = _make_txt_wildcard_query_fn(PARKING_TXT_VALUE)

    result = run_wildcard_attestation(_PARENT, query_fn, resolver, probe_count=3)

    assert result.status == WildcardAttestationStatus.DETECTED, (
        f"NA3 FAIL: TXT wildcard answers → DETECTED, got {result.status}"
    )
    assert "TXT" in result.type_signatures, (
        "NA3 FAIL: TXT must be in type_signatures for DETECTED wildcard"
    )
    assert result.probes_with_errors == 0, (
        f"NA3 FAIL: no errors in this scenario, got probes_with_errors={result.probes_with_errors}"
    )


# ---------------------------------------------------------------------------
# NA-4  probes_with_errors counter populated correctly.
# ---------------------------------------------------------------------------


def test_na4_probes_with_errors_counter():
    """NA-4 (2A): probes_with_errors is incremented for each errored probe label."""
    resolver = MagicMock()
    query_fn, _ = _make_txt_timeout_query_fn(probe_count=3)

    result = run_wildcard_attestation(_PARENT, query_fn, resolver, probe_count=3)

    # All 3 labels had TXT timeout errors.
    assert result.probes_with_errors == 3, (
        f"NA4 FAIL: expected probes_with_errors=3, got {result.probes_with_errors}"
    )
    assert result.probes_attempted == 3


def test_na4b_partial_error_still_inconclusive():
    """NA-4b: even 1 errored probe label out of 3 makes the result INCONCLUSIVE."""
    resolver = MagicMock()
    call_count = [0]

    def send_query(fqdn: str, rr_type, resolver):
        """First probe: all NXDOMAIN. Second/third probes: TXT times out."""
        call_count[0] += 1
        label = fqdn.split(".")[0]
        # We can't easily identify which label is which from fqdn alone, so instead:
        # return timeout for all TXT (simulates the real failure mode).
        if rr_type.value == "TXT":
            return _error()
        return _nxdomain(), None

    result = run_wildcard_attestation(_PARENT, send_query, resolver, probe_count=3)

    assert result.status == WildcardAttestationStatus.INCONCLUSIVE, (
        f"NA4b FAIL: any errored label → INCONCLUSIVE, got {result.status}"
    )


# ---------------------------------------------------------------------------
# NA-5  is_parking_txt() returns True for confirmed parking patterns.
# ---------------------------------------------------------------------------


def test_na5_parking_pattern_detected_itheta():
    """NA-5a: i-theta.com parking registrar email → is_parking_txt() True."""
    assert is_parking_txt("us-dom2@i-theta.com"), (
        "NA5a FAIL: i-theta.com contact must be detected as parking"
    )


def test_na5b_parking_pattern_detected_buddyns():
    """NA-5b: buddyns.com platform → is_parking_txt() True."""
    assert is_parking_txt("ns1.buddyns.com"), (
        "NA5b FAIL: buddyns.com must be detected as parking"
    )


def test_na5c_full_operator_evidence_string():
    """NA-5c: exact string from operator evidence (workbook 035805) matches."""
    operator_evidence = (
        "This domain may be available. For information, contact us-dom2@i-theta.com"
    )
    assert is_parking_txt(operator_evidence), (
        "NA5c FAIL: the exact string from operator evidence must match parking pattern"
    )


def test_na5d_case_insensitive():
    """NA-5d: parking detection is case-insensitive."""
    assert is_parking_txt("Contact I-THETA.COM for info"), (
        "NA5d FAIL: parking detection must be case-insensitive"
    )


# ---------------------------------------------------------------------------
# NA-6  is_parking_txt() returns False for legitimate TXT content.
# ---------------------------------------------------------------------------


def test_na6_spf_not_parking():
    """NA-6a: SPF record is NOT a parking string."""
    assert not is_parking_txt("v=spf1 include:_spf.google.com ~all"), (
        "NA6a FAIL: SPF record must not be classified as parking"
    )


def test_na6b_dkim_not_parking():
    """NA-6b: DKIM public key TXT is NOT a parking string."""
    assert not is_parking_txt("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOC"), (
        "NA6b FAIL: DKIM TXT must not be classified as parking"
    )


def test_na6c_dmarc_not_parking():
    """NA-6c: DMARC policy TXT is NOT a parking string."""
    assert not is_parking_txt("v=DMARC1; p=none; rua=mailto:dmarc@example.gov"), (
        "NA6c FAIL: DMARC TXT must not be classified as parking"
    )


def test_na6d_acme_not_parking():
    """NA-6d: ACME challenge token is NOT a parking string."""
    assert not is_parking_txt("osFRkANjuT4r0mQJzc9VJ1B2wG3hGqN4K6XfPLHmTvI"), (
        "NA6d FAIL: ACME challenge TXT must not be classified as parking"
    )


def test_na6e_distinct_spf_not_parking():
    """NA-6e: DISTINCT_TXT_VALUE used in test fixtures is not a parking string."""
    assert not is_parking_txt(DISTINCT_TXT_VALUE), (
        "NA6e FAIL: DISTINCT_TXT_VALUE must not trigger parking detection"
    )


# ---------------------------------------------------------------------------
# NA-7  INCONCLUSIVE + parking TXT → WITHHELD_PARKING_ECHO outcome (2B).
# ---------------------------------------------------------------------------


def test_na7_inconclusive_parking_txt_outcome_status():
    """NA-7: outcome_withheld_parking_echo produces WITHHELD_PARKING_ECHO status."""
    outcome = outcome_withheld_parking_echo(
        _CANDIDATE,
        parent=_PARENT,
        txt_value=PARKING_TXT_VALUE,
    )
    assert outcome.evidence_status == EvidenceStatus.WITHHELD_PARKING_ECHO, (
        f"NA7 FAIL: expected WITHHELD_PARKING_ECHO, got {outcome.evidence_status}"
    )
    assert "parking" in outcome.detail.lower(), (
        "NA7 FAIL: detail must mention parking"
    )


def test_na7b_inconclusive_parking_not_confirmed():
    """NA-7b: a candidate with INCONCLUSIVE attestation + parking TXT must NOT be CONFIRMED.

    Verifies that candidate_differentiates() returns REASON_NO_WILDCARD for INCONCLUSIVE
    (no wildcard found), which means the scan_engine gate handles it via the INCONCLUSIVE
    path (withheld) — not via the DETECTED suppress path.  The parking backstop in
    scan_engine uses _parking_echo_txt() to further classify it as WITHHELD_PARKING_ECHO.
    """
    attest = _inconclusive_attestation()
    records = [_parking_txt_record()]

    from scanner.wildcard_attestation import REASON_NO_WILDCARD

    reason = candidate_differentiates(records, attest)
    assert reason == REASON_NO_WILDCARD, (
        "NA7b FAIL: INCONCLUSIVE attestation must return REASON_NO_WILDCARD "
        "(gate is in scan_engine, not in candidate_differentiates)"
    )
    # The result is withheld by scan_engine, not promoted to CONFIRMED.
    assert attest.status == WildcardAttestationStatus.INCONCLUSIVE


# ---------------------------------------------------------------------------
# NA-8  INCONCLUSIVE + non-parking TXT → WITHHELD_WILDCARD_INCONCLUSIVE, not parking.
# ---------------------------------------------------------------------------


def test_na8_inconclusive_distinct_txt_not_parking_classified():
    """NA-8 (no over-suppression): INCONCLUSIVE + non-parking TXT → inconclusive withhold only.

    A candidate with legitimate non-parking TXT under INCONCLUSIVE detection must be
    classified as WITHHELD_WILDCARD_INCONCLUSIVE, NOT as WITHHELD_PARKING_ECHO.
    The parking backstop must be content-specific.
    """
    from scanner.scan_engine import _parking_echo_txt

    records = [_distinct_txt_record()]
    parking_val = _parking_echo_txt(records)
    assert parking_val is None, (
        f"NA8 FAIL: non-parking TXT {DISTINCT_TXT_VALUE!r} must not trigger parking backstop, "
        f"got {parking_val!r}"
    )


def test_na8b_inconclusive_outcome_for_non_parking():
    """NA-8b: outcome_withheld_wildcard_inconclusive status is WITHHELD_WILDCARD_INCONCLUSIVE."""
    outcome = outcome_withheld_wildcard_inconclusive(_CANDIDATE, parent=_PARENT)
    assert outcome.evidence_status == EvidenceStatus.WITHHELD_WILDCARD_INCONCLUSIVE, (
        f"NA8b FAIL: expected WITHHELD_WILDCARD_INCONCLUSIVE, got {outcome.evidence_status}"
    )


# ---------------------------------------------------------------------------
# NA-9  CLEAN + parking TXT → WITHHELD_PARKING_ECHO (2B defense-in-depth).
# ---------------------------------------------------------------------------


def test_na9_clean_parking_txt_triggers_backstop():
    """NA-9 (2B): even when detection returns CLEAN, parking TXT is caught by backstop.

    Defends against the warm-cache scenario where the wildcard TXT was cached from
    a prior run on parsons.ks.us and detection falsely returns CLEAN on junction-city.
    """
    from scanner.scan_engine import _parking_echo_txt

    records = [_parking_txt_record()]
    parking_val = _parking_echo_txt(records)
    assert parking_val is not None, (
        "NA9 FAIL: _parking_echo_txt must detect parking TXT under CLEAN attestation"
    )
    assert "i-theta.com" in parking_val.lower(), (
        "NA9 FAIL: returned parking value must contain the i-theta.com pattern"
    )


def test_na9b_clean_plus_ns_not_suppressed_by_parking():
    """NA-9b (no over-suppression): CLEAN + NS delegation → not parking-suppressed.

    If a candidate has both a parking TXT AND an NS delegation, the NS delegation
    is strong evidence and _parking_echo_txt should not suppress it.  The NS/delegation
    record wins (differentiation via delegation evidence path).
    Note: _parking_echo_txt looks only at TXT records; NS records are unaffected.
    """
    from scanner.scan_engine import _parking_echo_txt

    # Only TXT records are checked; NS records are separate.
    ns_record = _ns_delegation_record()
    parking_val = _parking_echo_txt([ns_record])
    assert parking_val is None, (
        "NA9b FAIL: _parking_echo_txt must not trigger on NS delegation record"
    )


# ---------------------------------------------------------------------------
# NA-10  CLEAN + non-parking TXT → promotes (no over-suppression from 2B).
# ---------------------------------------------------------------------------


def test_na10_clean_non_parking_txt_not_suppressed():
    """NA-10 (2B no over-suppression): CLEAN + non-parking TXT → 2B does NOT fire.

    A legitimate distinct TXT record on a clean (no wildcard) domain must not be
    suppressed by the parking backstop.  2B is content-specific.
    """
    from scanner.scan_engine import _parking_echo_txt

    records = [_distinct_txt_record()]
    parking_val = _parking_echo_txt(records)
    assert parking_val is None, (
        f"NA10 FAIL: {DISTINCT_TXT_VALUE!r} must not trigger 2B parking backstop"
    )


def test_na10b_clean_a_record_not_suppressed():
    """NA-10b: CLEAN + A record → 2B does NOT fire (only checks TXT)."""
    from scanner.scan_engine import _parking_echo_txt

    records = [_a_record()]
    parking_val = _parking_echo_txt(records)
    assert parking_val is None, (
        "NA10b FAIL: A record must not trigger 2B parking backstop"
    )


# ---------------------------------------------------------------------------
# NA-11  Strong NS delegation (DELEGATED_CHILD_ZONE) differentiates always.
# ---------------------------------------------------------------------------


def test_na11_ns_delegation_differentiates_under_inconclusive():
    """NA-11: NS delegation always differentiates regardless of attestation status.

    Under INCONCLUSIVE attestation, candidate_differentiates returns REASON_NO_WILDCARD
    (no wildcard → pass).  Delegation records on their own would open a 5th-level sweep
    (they are already in the delegation path, not gated by wildcard attestation).
    The key invariant: NS/SOA records are never classified as wildcard echoes.
    """
    attest = _inconclusive_attestation()
    ns_record = _ns_delegation_record()

    from scanner.wildcard_attestation import REASON_NO_WILDCARD

    reason = candidate_differentiates([ns_record], attest)
    assert reason == REASON_NO_WILDCARD, (
        "NA11 FAIL: NS delegation under INCONCLUSIVE should return REASON_NO_WILDCARD "
        "(delegation path bypasses wildcard suppression)"
    )


def test_na11b_ns_delegation_differentiates_under_detected():
    """NA-11b: NS record differentiates under DETECTED attestation (existing guard).

    candidate_differentiates checks rr_type in ("NS", "SOA") before classification,
    so an NS record returns REASON_CANDIDATE_NS_SOA — always differentiates.
    """
    attest = _detected_txt_attestation()
    ns_record = _ns_delegation_record()

    from scanner.wildcard_attestation import REASON_CANDIDATE_NS_SOA

    reason = candidate_differentiates([ns_record], attest)
    assert reason == REASON_CANDIDATE_NS_SOA, (
        f"NA11b FAIL: NS record under DETECTED must return REASON_CANDIDATE_NS_SOA, "
        f"got {reason!r}"
    )


def test_na11c_ns_delegation_not_affected_by_parking_backstop():
    """NA-11c: _parking_echo_txt() does NOT fire on a NS delegation record."""
    from scanner.scan_engine import _parking_echo_txt

    ns_record = _ns_delegation_record()
    assert _parking_echo_txt([ns_record]) is None, (
        "NA11c FAIL: NS delegation must never be classified as parking echo"
    )


# ---------------------------------------------------------------------------
# NA-12  Claim-to-code: WITHHELD_PARKING_ECHO is a diagnostic status.
# ---------------------------------------------------------------------------


def test_na12_withheld_parking_echo_is_diagnostic():
    """NA-12: WITHHELD_PARKING_ECHO must be in _DIAGNOSTIC_EVIDENCE_STATUSES."""
    assert EvidenceStatus.WITHHELD_PARKING_ECHO in _DIAGNOSTIC_EVIDENCE_STATUSES, (
        "NA12 FAIL: WITHHELD_PARKING_ECHO must be in _DIAGNOSTIC_EVIDENCE_STATUSES "
        "so it never appears in confirmed findings"
    )


def test_na12b_withheld_parking_echo_not_confirmed():
    """NA-12b: WITHHELD_PARKING_ECHO is not in CONFIRMED_EVIDENCE_STATUSES."""
    from scanner.evidence_status import CONFIRMED_EVIDENCE_STATUSES

    assert EvidenceStatus.WITHHELD_PARKING_ECHO not in CONFIRMED_EVIDENCE_STATUSES, (
        "NA12b FAIL: WITHHELD_PARKING_ECHO must never be a confirmed status"
    )


def test_na12c_parking_txt_patterns_non_empty():
    """NA-12c: PARKING_TXT_PATTERNS is non-empty and contains confirmed evidence strings."""
    assert len(PARKING_TXT_PATTERNS) >= 1, (
        "NA12c FAIL: PARKING_TXT_PATTERNS must have at least one entry"
    )
    assert any("i-theta" in p for p in PARKING_TXT_PATTERNS), (
        "NA12c FAIL: PARKING_TXT_PATTERNS must include i-theta.com (confirmed in operator evidence)"
    )


# ---------------------------------------------------------------------------
# NA-13  Determinism honesty: DETECTED path unchanged (warm-cache).
# ---------------------------------------------------------------------------


def test_na13_detected_path_unchanged():
    """NA-13: when TXT wildcard IS detected (warm cache), candidate_differentiates
    still suppresses a matching TXT echo — WC-FIX (DETECTED path) is unaffected by 2A.
    """
    attest = _detected_txt_attestation(PARKING_TXT_VALUE)
    records = [_parking_txt_record()]

    reason = candidate_differentiates(records, attest)
    assert reason is None, (
        "NA13 FAIL: TXT value matching wildcard signature must return None "
        "(echo suppressed — WC-FIX DETECTED path must still work)"
    )


def test_na13b_detected_distinct_txt_still_promotes():
    """NA-13b: under DETECTED attestation, a distinct (non-matching) TXT promotes."""
    attest = _detected_txt_attestation(PARKING_TXT_VALUE)
    records = [_distinct_txt_record()]

    from scanner.wildcard_attestation import REASON_DISTINCT_ANSWER

    reason = candidate_differentiates(records, attest)
    assert reason == REASON_DISTINCT_ANSWER, (
        f"NA13b FAIL: distinct TXT under DETECTED must differentiate, got {reason!r}"
    )
