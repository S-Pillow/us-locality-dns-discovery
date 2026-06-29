#!/usr/bin/env python3
"""R4d regression: TXT wildcard echo suppression (WC-FIX normalization fix).

Root cause (WC-RCA): _answer_values stored TXT via rdata.to_text() — quoted
master-file form, e.g. '"text"'.  scan_engine._format_rdata stored TXT via
decoded rdata.strings — unquoted form, e.g. 'text'.  The membership check
``candidate_value not in type_signatures["TXT"]`` always mismatched, so every
TXT echo returned REASON_DISTINCT_ANSWER and was promoted as a genuine finding
instead of being suppressed.

Fix (WC-FIX): _answer_values now uses _txt_rdata_value for TXT records, which
matches _format_rdata's decoded form exactly.

Tests in this file (all durable negative-action guards):

  AC-1  TXT echo (identical to wildcard catch-all) → suppressed, gate applied.
  AC-2  TXT genuinely distinct → promotes (REASON_DISTINCT_ANSWER), not suppressed.
  AC-3  _txt_rdata_value / _answer_values normalises TXT to unquoted decoded form.
  AC-4  Wildcard with TXT-only signature: candidate with SAME TXT → suppressed.
  AC-5  Wildcard with TXT-only signature: candidate with DIFFERENT TXT → promotes.
  AC-6  run_wildcard_attestation builds correct TXT signature via _answer_values.
  AC-7  A/AAAA/CNAME differentiation unchanged (regression guard for existing R4 paths).
  AC-8  NS/SOA on candidate always differentiates regardless of TXT wildcard (delegation guard).
  AC-9  candidate_differentiates returns None for multi-record candidate where all
        TXT values are in the wildcard signature.
  AC-10 candidate_differentiates returns REASON_DISTINCT_ANSWER when one TXT value
        in a multi-record batch is outside the wildcard signature.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import dns.rdatatype
import dns.rcode

from scanner.models import (
    DiscoveredRecord,
    FindingClassification,
    RecordType,
)
from scanner.wildcard_attestation import (
    REASON_CANDIDATE_NS_SOA,
    REASON_DISTINCT_ANSWER,
    REASON_DISTINCT_CNAME_TARGET,
    REASON_DISTINCT_RRTYPE,
    REASON_NO_WILDCARD,
    WildcardAttestation,
    WildcardAttestationStatus,
    _answer_values,
    _txt_rdata_value,
    candidate_differentiates,
    run_wildcard_attestation,
)

# ---------------------------------------------------------------------------
# Fake DNS response helpers — no live network calls
# ---------------------------------------------------------------------------


class _FakeTxtRdata:
    """Minimal TXT rdata stand-in with both .strings and .to_text().

    dnspython TXT rdata:
      .strings — tuple of bytes, one per TXT string segment
      .to_text() — DNS master-file quoted form, e.g. '"hello world"'

    This stub mimics both so that _txt_rdata_value and _answer_values work
    correctly in tests, and we can assert the normalisation difference.
    """

    def __init__(self, *segments: str) -> None:
        self.strings: tuple[bytes, ...] = tuple(s.encode() for s in segments)
        self._text: str = " ".join(f'"{s}"' for s in segments)

    def to_text(self) -> str:
        """DNS master-file quoted form — what dnspython returns."""
        return self._text


class _FakeRdata:
    """Generic rdata stand-in (A/AAAA/CNAME/MX/etc.): .to_text() only."""

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


def _txt_response(*segments: str) -> _FakeResponse:
    """Response with a single TXT record containing the given string segments."""
    return _FakeResponse(
        answer_rrsets=[
            _FakeRRset(
                dns.rdatatype.from_text("TXT"),
                [_FakeTxtRdata(*segments)],
            )
        ]
    )


def _a_response(ip: str) -> _FakeResponse:
    return _FakeResponse(
        answer_rrsets=[
            _FakeRRset(dns.rdatatype.from_text("A"), [_FakeRdata(ip)])
        ]
    )


def _nxdomain() -> _FakeResponse:
    return _FakeResponse(answer_rrsets=[], rcode_val=dns.rcode.NXDOMAIN)


# ---------------------------------------------------------------------------
# DiscoveredRecord fixtures
# ---------------------------------------------------------------------------

_CATCH_ALL_TXT = "This domain may be available. For information, contact us-domain@i-theta.com"
_DISTINCT_TXT = "v=spf1 include:legitimate.example.com ~all"


def _txt_record(value: str) -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn="candidate.example.ks.us",
        record_type=RecordType.TXT,
        value=value,
        source_method="recursive_resolver",
        classification=FindingClassification.STANDARD_RECORD,
    )


def _ns_record() -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn="candidate.example.ks.us",
        record_type=RecordType.NS,
        value="ns1.provider.net.",
        source_method="recursive_resolver",
        classification=FindingClassification.DELEGATED_CHILD_ZONE,
    )


def _a_record(ip: str = "1.2.3.4") -> DiscoveredRecord:
    return DiscoveredRecord(
        fqdn="candidate.example.ks.us",
        record_type=RecordType.A,
        value=ip,
        source_method="recursive_resolver",
        classification=FindingClassification.STANDARD_RECORD,
    )


def _txt_attestation(txt_value: str) -> WildcardAttestation:
    """Wildcard attestation whose TXT signature contains *txt_value* (normalised form)."""
    return WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="example.ks.us",
        probes_attempted=3,
        probes_with_answers=3,
        type_signatures={"TXT": frozenset({txt_value})},
        address_pool=frozenset(),
    )


def _a_txt_attestation(ip: str, txt_value: str) -> WildcardAttestation:
    """Wildcard attestation with both A and TXT signatures."""
    return WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="example.ks.us",
        probes_attempted=3,
        probes_with_answers=3,
        type_signatures={
            "A": frozenset({ip}),
            "TXT": frozenset({txt_value}),
        },
        address_pool=frozenset({ip}),
    )


# ---------------------------------------------------------------------------
# Wildcard send-fn stubs
# ---------------------------------------------------------------------------


def _txt_wildcard_send(fqdn, rr_type, resolver):
    """Wildcard that returns a catch-all TXT on every query."""
    if rr_type.value == "TXT":
        return _txt_response(_CATCH_ALL_TXT), None
    return _nxdomain(), None


def _a_wildcard_send(fqdn, rr_type, resolver):
    """Wildcard that returns only an A record (1.2.3.4)."""
    if rr_type.value == "A":
        return _a_response("1.2.3.4"), None
    return _nxdomain(), None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_txt_rdata_value_normalises_to_unquoted():
    """AC-3 / core fix: _txt_rdata_value returns the decoded form without quotes."""
    rdata = _FakeTxtRdata("This domain may be available.")
    result = _txt_rdata_value(rdata)
    # Must match _format_rdata TXT branch: no surrounding double-quotes.
    assert result == "This domain may be available.", repr(result)
    # Must NOT equal rdata.to_text() which has quotes.
    assert result != rdata.to_text(), "fix regression: still returning quoted form"


def test_txt_rdata_value_multi_segment():
    """_txt_rdata_value joins multiple TXT segments with a space (matching _format_rdata)."""
    rdata = _FakeTxtRdata("v=spf1", "include:example.com", "~all")
    result = _txt_rdata_value(rdata)
    assert result == "v=spf1 include:example.com ~all", repr(result)


def test_answer_values_txt_returns_unquoted_form():
    """AC-3: _answer_values for TXT returns the decoded unquoted form after the fix."""
    response = _txt_response(_CATCH_ALL_TXT)
    values = _answer_values(response, "TXT")
    assert _CATCH_ALL_TXT in values, f"unquoted form not found; got {values}"
    # Quoted form must NOT be present (that was the pre-fix bug).
    quoted = f'"{_CATCH_ALL_TXT}"'
    assert quoted not in values, f"quoted form still present after fix; got {values}"


def test_answer_values_a_unchanged():
    """_answer_values for A records is unaffected by the TXT fix."""
    response = _a_response("203.0.113.5")
    values = _answer_values(response, "A")
    assert "203.0.113.5" in values


def test_echo_suppressed_via_candidate_differentiates():
    """AC-1 / AC-4: candidate echoing the wildcard TXT is suppressed (returns None)."""
    attestation = _txt_attestation(_CATCH_ALL_TXT)
    candidate = [_txt_record(_CATCH_ALL_TXT)]
    result = candidate_differentiates(candidate, attestation)
    assert result is None, (
        f"Expected suppression (None) for TXT echo; got {result!r}. "
        "This means the normalization fix is not applied or not effective."
    )


def test_distinct_txt_promotes():
    """AC-2 / AC-5: candidate with genuinely distinct TXT promotes as REASON_DISTINCT_ANSWER."""
    attestation = _txt_attestation(_CATCH_ALL_TXT)
    candidate = [_txt_record(_DISTINCT_TXT)]
    result = candidate_differentiates(candidate, attestation)
    assert result == REASON_DISTINCT_ANSWER, (
        f"Expected REASON_DISTINCT_ANSWER for genuinely distinct TXT; got {result!r}"
    )


def test_run_wildcard_attestation_captures_txt_signature():
    """AC-6: run_wildcard_attestation builds TXT signature using normalised (unquoted) form."""
    attestation = run_wildcard_attestation(
        "example.ks.us",
        _txt_wildcard_send,
        resolver=None,
        probe_count=3,
    )
    assert attestation.status == WildcardAttestationStatus.DETECTED
    assert "TXT" in attestation.type_signatures, "TXT not in attestation signatures"
    sig = attestation.type_signatures["TXT"]
    assert _CATCH_ALL_TXT in sig, (
        f"Normalised TXT value not in signature.\n"
        f"  Expected: {_CATCH_ALL_TXT!r}\n"
        f"  Signature: {sig}"
    )
    # Quoted form must NOT be in the signature (that was the pre-fix bug).
    quoted = f'"{_CATCH_ALL_TXT}"'
    assert quoted not in sig, (
        f"Quoted TXT form still in signature after fix: {quoted!r}"
    )


def test_full_pipeline_txt_echo_suppressed():
    """AC-1 end-to-end: after run_wildcard_attestation, a TXT echo candidate is suppressed."""
    attestation = run_wildcard_attestation(
        "example.ks.us",
        _txt_wildcard_send,
        resolver=None,
        probe_count=3,
    )
    assert attestation.status == WildcardAttestationStatus.DETECTED
    # A candidate that echoes the same TXT must be suppressed.
    result = candidate_differentiates([_txt_record(_CATCH_ALL_TXT)], attestation)
    assert result is None, (
        f"Full pipeline: TXT echo not suppressed after attestation + differentiates. "
        f"Got {result!r}. This is the WC-RCA defect — the fix is not effective."
    )


def test_full_pipeline_distinct_txt_promotes():
    """AC-2 end-to-end: after attestation, genuinely distinct TXT still promotes."""
    attestation = run_wildcard_attestation(
        "example.ks.us",
        _txt_wildcard_send,
        resolver=None,
        probe_count=3,
    )
    result = candidate_differentiates([_txt_record(_DISTINCT_TXT)], attestation)
    assert result == REASON_DISTINCT_ANSWER, (
        f"Genuinely distinct TXT should promote; got {result!r}"
    )


def test_a_wildcard_cname_not_in_signature_still_distinct_rrtype():
    """AC-7 regression guard: A wildcard attestation, candidate with CNAME → distinct_rrtype.

    Verifies that the TXT normalization fix has zero effect on A/AAAA/CNAME paths.
    """
    attestation = WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="example.ks.us",
        probes_attempted=3,
        probes_with_answers=3,
        type_signatures={"A": frozenset({"1.2.3.4"})},
        address_pool=frozenset({"1.2.3.4"}),
    )
    from scanner.models import RecordType
    cname_record = DiscoveredRecord(
        fqdn="candidate.example.ks.us",
        record_type=RecordType.CNAME,
        value="other.example.com.",
        source_method="recursive_resolver",
        classification=FindingClassification.STANDARD_RECORD,
    )
    result = candidate_differentiates([cname_record], attestation)
    assert result == REASON_DISTINCT_RRTYPE, (
        f"Expected REASON_DISTINCT_RRTYPE for CNAME on A-wildcard; got {result!r}"
    )


def test_a_pool_containment_unchanged():
    """AC-7 regression guard: A address inside pool → suppressed (§6 pool containment)."""
    attestation = WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="example.ks.us",
        probes_attempted=3,
        probes_with_answers=3,
        type_signatures={"A": frozenset({"1.2.3.4"})},
        address_pool=frozenset({"1.2.3.4"}),
    )
    result = candidate_differentiates([_a_record("1.2.3.4")], attestation)
    assert result is None, f"A address in pool should suppress; got {result!r}"


def test_ns_differentiates_on_txt_wildcard():
    """AC-8 delegation guard: NS record on candidate always differentiates even under TXT wildcard."""
    attestation = _txt_attestation(_CATCH_ALL_TXT)
    result = candidate_differentiates([_ns_record()], attestation)
    assert result == REASON_CANDIDATE_NS_SOA, (
        f"NS on candidate should return REASON_CANDIDATE_NS_SOA; got {result!r}"
    )


def test_multi_record_all_echo_suppressed():
    """AC-9: candidate with multiple TXT records all matching wildcard → suppressed."""
    attestation = WildcardAttestation(
        status=WildcardAttestationStatus.DETECTED,
        parent="example.ks.us",
        probes_attempted=3,
        probes_with_answers=3,
        type_signatures={"TXT": frozenset({_CATCH_ALL_TXT, "v=spf1 ~all"})},
        address_pool=frozenset(),
    )
    records = [_txt_record(_CATCH_ALL_TXT), _txt_record("v=spf1 ~all")]
    result = candidate_differentiates(records, attestation)
    assert result is None, f"All TXT values in signature should suppress; got {result!r}"


def test_multi_record_one_distinct_promotes():
    """AC-10: candidate with one TXT value outside the wildcard signature → promotes."""
    attestation = _txt_attestation(_CATCH_ALL_TXT)
    records = [_txt_record(_CATCH_ALL_TXT), _txt_record(_DISTINCT_TXT)]
    result = candidate_differentiates(records, attestation)
    assert result == REASON_DISTINCT_ANSWER, (
        f"One distinct TXT should cause promotion; got {result!r}"
    )


def test_clean_attestation_no_wildcard():
    """CLEAN attestation returns REASON_NO_WILDCARD (no suppression analysis needed)."""
    clean = WildcardAttestation(
        status=WildcardAttestationStatus.CLEAN,
        parent="example.ks.us",
    )
    result = candidate_differentiates([_txt_record(_CATCH_ALL_TXT)], clean)
    assert result == REASON_NO_WILDCARD, (
        f"CLEAN attestation should return REASON_NO_WILDCARD; got {result!r}"
    )


def test_run_wildcard_attestation_txt_only_signature_no_a():
    """run_wildcard_attestation with TXT-only wildcard: no A in signature, TXT normalised."""
    attestation = run_wildcard_attestation(
        "example.ks.us",
        _txt_wildcard_send,
        resolver=None,
        probe_count=3,
    )
    assert "A" not in attestation.type_signatures, "A should not be in TXT-only wildcard signature"
    assert len(attestation.address_pool) == 0, "address_pool should be empty for TXT-only wildcard"


def main() -> None:
    print("=== R4d: TXT wildcard echo suppression ===")

    print("\n--- normalization unit tests ---")
    test_txt_rdata_value_normalises_to_unquoted()
    test_txt_rdata_value_multi_segment()
    test_answer_values_txt_returns_unquoted_form()
    test_answer_values_a_unchanged()

    print("\n--- candidate_differentiates TXT suppression ---")
    test_echo_suppressed_via_candidate_differentiates()
    test_distinct_txt_promotes()

    print("\n--- full pipeline (run_wildcard_attestation + candidate_differentiates) ---")
    test_run_wildcard_attestation_captures_txt_signature()
    test_full_pipeline_txt_echo_suppressed()
    test_full_pipeline_distinct_txt_promotes()
    test_run_wildcard_attestation_txt_only_signature_no_a()

    print("\n--- multi-record batch ---")
    test_multi_record_all_echo_suppressed()
    test_multi_record_one_distinct_promotes()

    print("\n--- regression guards: A/AAAA/CNAME/NS unchanged ---")
    test_a_wildcard_cname_not_in_signature_still_distinct_rrtype()
    test_a_pool_containment_unchanged()
    test_ns_differentiates_on_txt_wildcard()

    print("\n--- clean attestation ---")
    test_clean_attestation_no_wildcard()

    print("\n=== R4d: all assertions passed ===")


if __name__ == "__main__":
    main()
