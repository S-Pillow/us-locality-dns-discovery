"""DNS response classification firewall.

Every DNS response must be classified by classify_dns_response before any
finding creation code may inspect it.  Finding creation paths consult the
returned DNSResponseClass to decide whether and what kind of evidence is
permitted.

Classification priority (highest to lowest):
  transport error                 → TIMEOUT or MALFORMED_OR_UNUSABLE
  missing response object         → MALFORMED_OR_UNUSABLE
  rcode SERVFAIL                  → SERVFAIL
  rcode other than NOERROR/NXDOMAIN → MALFORMED_OR_UNUSABLE
  rcode NXDOMAIN                  → NEGATIVE_NXDOMAIN
  rcode NOERROR + owner-matching CNAME in answer → CNAME_ALIAS
  rcode NOERROR + owner-matching non-CNAME in answer → OWNER_MATCHING_ANSWER
  rcode NOERROR + no owner-matching answer
      authority has NS  owner == qname  → REFERRAL_DELEGATION
      authority has SOA owner == qname  → NODATA_EMPTY_ANSWER
      authority has NS/SOA for other name → UNRELATED_AUTHORITY
      empty authority                   → NODATA_EMPTY_ANSWER
"""

from __future__ import annotations

from enum import Enum

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype


class DNSResponseClass(str, Enum):
    """Classification labels for a single DNS response.

    Used to gate finding creation: only approved (classification, record-type)
    pairs may produce evidence records.
    """

    OWNER_MATCHING_ANSWER = "owner_matching_answer"
    """Answer section contains at least one RR whose owner equals the queried
    name (normalized).  Non-CNAME variant."""

    REFERRAL_DELEGATION = "referral_delegation"
    """Authority section contains NS records whose owner equals the queried
    name (a true in-bailiwick delegation referral)."""

    NEGATIVE_NXDOMAIN = "negative_nxdomain"
    """rcode NXDOMAIN — the queried name does not exist.  No finding."""

    NODATA_EMPTY_ANSWER = "nodata_empty_answer"
    """rcode NOERROR, no owner-matching answer, and either (a) authority SOA
    owner equals the queried name (zone exists, record type absent) or (b)
    authority section is empty.  No direct finding; owner-matching authority
    SOA may still be extracted for zone/apex evidence."""

    SERVFAIL = "servfail"
    """rcode SERVFAIL.  No finding."""

    TIMEOUT = "timeout"
    """Transport-level timeout before any response was received.  No finding."""

    UNRELATED_AUTHORITY = "unrelated_authority"
    """Authority section contains NS or SOA records whose owner does NOT match
    the queried name (e.g. .com registry payload, TLD SOA, parent-zone SOA).
    Diagnostic logging only; no finding."""

    CNAME_ALIAS = "cname_alias"
    """Answer section contains a CNAME whose owner equals the queried name.
    Proves the queried alias exists; does not automatically promote the CNAME
    target as in-scope."""

    MALFORMED_OR_UNUSABLE = "malformed_or_unusable"
    """Response is None, unparseable, or has an unexpected rcode.
    Fail-closed: no finding."""


def _norm_name(name: str) -> str:
    """Normalize a DNS name to lowercase without trailing dot."""
    return name.strip().lower().rstrip(".")


def classify_dns_response(
    response: dns.message.Message | None,
    qname: str,
    transport_error: str | None = None,
) -> DNSResponseClass:
    """Return the classification for *response* for the queried name *qname*.

    Args:
        response:        The raw :class:`dns.message.Message` returned by the
                         resolver, or ``None`` if none was received.
        qname:           The DNS name that was queried (not necessarily FQDN;
                         will be normalized internally).
        transport_error: The error string returned alongside ``response`` by
                         the low-level send function.  If non-empty, the
                         response is treated as absent regardless of its value.

    Returns:
        A :class:`DNSResponseClass` value.  Callers must treat any class not
        explicitly allowed by their evidence rules as producing no finding.
    """
    # --- Transport-level failures -----------------------------------------
    if transport_error is not None:
        if "timeout" in transport_error.lower():
            return DNSResponseClass.TIMEOUT
        return DNSResponseClass.MALFORMED_OR_UNUSABLE

    if response is None:
        return DNSResponseClass.MALFORMED_OR_UNUSABLE

    # --- Normalize the queried name ----------------------------------------
    nq = _norm_name(qname)

    # --- Decode rcode safely -----------------------------------------------
    try:
        rcode = response.rcode()
    except Exception:
        return DNSResponseClass.MALFORMED_OR_UNUSABLE

    if rcode == dns.rcode.SERVFAIL:
        return DNSResponseClass.SERVFAIL

    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return DNSResponseClass.MALFORMED_OR_UNUSABLE

    # --- NXDOMAIN: name does not exist ------------------------------------
    # Authority-section SOA in an NXDOMAIN is denial/caching context; it
    # must never create any finding for the queried candidate.
    if rcode == dns.rcode.NXDOMAIN:
        return DNSResponseClass.NEGATIVE_NXDOMAIN

    # --- NOERROR: scan answer section for owner-matching records -----------
    for rrset in response.answer:
        try:
            owner = _norm_name(rrset.name.to_text())
        except Exception:
            continue
        if owner == nq:
            if rrset.rdtype == dns.rdatatype.CNAME:
                return DNSResponseClass.CNAME_ALIAS
            return DNSResponseClass.OWNER_MATCHING_ANSWER

    # --- NOERROR, no owner-matching answer: inspect authority section ------
    # Walk every authority rrset and record whether we see owner-matching
    # NS/SOA or unrelated (different-owner) NS/SOA.  Owner-matching NS takes
    # highest priority because it signals a real delegation referral.
    has_own_ns: bool = False
    has_own_soa: bool = False
    has_unrelated: bool = False

    for rrset in response.authority:
        try:
            owner = _norm_name(rrset.name.to_text())
            rdtype = rrset.rdtype
        except Exception:
            has_unrelated = True
            continue

        if rdtype == dns.rdatatype.NS:
            if owner == nq:
                has_own_ns = True
            else:
                has_unrelated = True
        elif rdtype == dns.rdatatype.SOA:
            if owner == nq:
                has_own_soa = True
            else:
                # SOA from a different zone (TLD, parent, .com registry, etc.)
                has_unrelated = True
        else:
            # Other authority record types (NSEC, DS, …) from a different
            # owner are treated as unrelated; from the queried name they are
            # unexpected but not a security concern — leave unrelated flag
            # unchanged in the owner-match case.
            if owner != nq:
                has_unrelated = True

    # Priority: owner-matching NS > owner-matching SOA > unrelated > empty
    if has_own_ns:
        return DNSResponseClass.REFERRAL_DELEGATION
    if has_own_soa:
        return DNSResponseClass.NODATA_EMPTY_ANSWER
    if has_unrelated:
        return DNSResponseClass.UNRELATED_AUTHORITY

    # NOERROR with empty answer and empty authority — treat as NODATA
    return DNSResponseClass.NODATA_EMPTY_ANSWER


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

_NO_FINDING_CLASSES: frozenset[DNSResponseClass] = frozenset(
    {
        DNSResponseClass.NEGATIVE_NXDOMAIN,
        DNSResponseClass.SERVFAIL,
        DNSResponseClass.TIMEOUT,
        DNSResponseClass.UNRELATED_AUTHORITY,
        DNSResponseClass.MALFORMED_OR_UNUSABLE,
    }
)


def is_no_finding_class(rc: DNSResponseClass) -> bool:
    """Return True when *rc* must never produce a DNS finding."""
    return rc in _NO_FINDING_CLASSES
