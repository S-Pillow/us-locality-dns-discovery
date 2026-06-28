"""DNS response classification firewall.

Every DNS response must be classified by classify_dns_response before any
finding creation code may inspect it.  Finding creation paths consult the
returned DNSResponseClass to decide whether and what kind of evidence is
permitted.

Ten classifier values (DNSResponseClass):
  OWNER_MATCHING_ANSWER, REFERRAL_DELEGATION, NEGATIVE_NXDOMAIN,
  NODATA_EMPTY_ANSWER, NOERROR_NODATA_PARENT_AUTHORITY, SERVFAIL,
  TIMEOUT, UNRELATED_AUTHORITY, CNAME_ALIAS, MALFORMED_OR_UNUSABLE

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
      authority has SOA owned by an ANCESTOR of qname, no NS in authority
                                        → NOERROR_NODATA_PARENT_AUTHORITY (Ticket T32)
      authority has NS/SOA for other name (incl. ancestor NS) → UNRELATED_AUTHORITY
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
    authority section is empty.  No finding.  Fail-closed: must not call
    finding-creation code (_parse_dns_response)."""

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

    NOERROR_NODATA_PARENT_AUTHORITY = "noerror_nodata_parent_authority"
    """rcode NOERROR, no owner-matching answer, authority section contains a
    SOA record whose owner is an *ancestor* of the queried name (parent zone
    SOA), with no NS for the queried name.

    Semantic: the name exists within the parent zone but has no direct DNS
    record at the queried name and is not a delegated child zone.  This is
    the pre-delegation registry pattern — a name entered directly in the
    parent zone without its own NS.  (Ticket T32.)

    Evidence discipline (HARD):
    - NOT a delegated child zone.
    - NOT NXDOMAIN / absence.
    - NOT proof that descendants do not exist.
    - IS: "name in parent zone / no direct record / possible branch container."
    No finding.  Routing → context/diagnostic only."""

    MALFORMED_OR_UNUSABLE = "malformed_or_unusable"
    """Response is None, unparseable, or has an unexpected rcode.
    Fail-closed: no finding."""


def _norm_name(name: str) -> str:
    """Normalize a DNS name to lowercase without trailing dot."""
    return name.strip().lower().rstrip(".")


def _is_ancestor(ancestor_candidate: str, name: str) -> bool:
    """Return True when *ancestor_candidate* is a proper ancestor zone of *name*.

    ``_is_ancestor("k12.pa.us", "pvt.k12.pa.us")`` → True
    ``_is_ancestor("pa.us",     "pvt.k12.pa.us")`` → True
    ``_is_ancestor("pvt.k12.pa.us", "pvt.k12.pa.us")`` → False (same name)
    ``_is_ancestor("godaddy.com", "pvt.k12.pa.us")`` → False (unrelated)

    Used in Ticket T32 ancestor-SOA detection.
    """
    a = _norm_name(ancestor_candidate)
    n = _norm_name(name)
    if not a or not n or a == n:
        return False
    return n.endswith("." + a)


def _is_timeout_transport_error(transport_error: str) -> bool:
    """Return True when *transport_error* text indicates a DNS query timeout."""
    lowered = transport_error.lower()
    return (
        "timeout" in lowered
        or "timed out" in lowered
        or "timed-out" in lowered
    )


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
        if _is_timeout_transport_error(transport_error):
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
    # NS/SOA, ancestor-zone SOA, or truly unrelated NS/SOA.  Owner-matching
    # NS takes highest priority (real delegation referral).
    has_own_ns: bool = False       # NS for the queried name → REFERRAL_DELEGATION
    has_own_soa: bool = False      # SOA for the queried name → NODATA_EMPTY_ANSWER
    has_ancestor_soa: bool = False # SOA for an ancestor zone (no NS present) → NOERROR_NODATA_PARENT_AUTHORITY (T32)
    has_unrelated: bool = False    # Any NS not owned by qname, or SOA not owned by qname/ancestor

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
                # Any NS whose owner is not the queried name (whether ancestor or
                # unrelated zone) is treated as unrelated authority.  Ancestor-zone
                # NS appearing in authority means the parent zone is asserting its
                # own delegation — not a delegation for the queried name; existing
                # behavior preserved (UNRELATED_AUTHORITY path) so that delegation-
                # verifier code that relies on UNRELATED_AUTHORITY for parent-NS
                # responses is not regressed.
                has_unrelated = True
        elif rdtype == dns.rdatatype.SOA:
            if owner == nq:
                has_own_soa = True
            elif _is_ancestor(owner, nq):
                # Ancestor-zone SOA: the parent (or grandparent) authoritative
                # server is telling us this name is in-zone but has no direct
                # record.  Track separately from truly unrelated SOA (Ticket T32).
                has_ancestor_soa = True
            else:
                # SOA from a genuinely unrelated zone (TLD, cross-namespace, etc.)
                has_unrelated = True
        else:
            # Other authority record types (NSEC, DS, …).
            if owner != nq and not _is_ancestor(owner, nq):
                has_unrelated = True

    # Priority:
    #   own NS       → REFERRAL_DELEGATION
    #   own SOA      → NODATA_EMPTY_ANSWER (zone exists, record type absent)
    #   ancestor SOA → NOERROR_NODATA_PARENT_AUTHORITY (in-zone, not delegated)
    #                  *only when no truly unrelated authority is also present*
    #   unrelated    → UNRELATED_AUTHORITY
    #   empty        → NODATA_EMPTY_ANSWER
    if has_own_ns:
        return DNSResponseClass.REFERRAL_DELEGATION
    if has_own_soa:
        return DNSResponseClass.NODATA_EMPTY_ANSWER
    if has_ancestor_soa and not has_unrelated:
        return DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY
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
        DNSResponseClass.NODATA_EMPTY_ANSWER,
        DNSResponseClass.NOERROR_NODATA_PARENT_AUTHORITY,
        DNSResponseClass.SERVFAIL,
        DNSResponseClass.TIMEOUT,
        DNSResponseClass.UNRELATED_AUTHORITY,
        DNSResponseClass.MALFORMED_OR_UNUSABLE,
    }
)


def is_no_finding_class(rc: DNSResponseClass) -> bool:
    """Return True when *rc* must never produce a DNS finding."""
    return rc in _NO_FINDING_CLASSES
