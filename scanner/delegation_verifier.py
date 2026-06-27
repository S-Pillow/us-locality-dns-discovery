"""Delegation Verification Mode — gated promotion to delegated_child_zone.

A candidate may become a ``delegated_child_zone`` finding only after verification
through an allowed path:

1. **Parent-side authoritative** — parent-zone nameserver returns an NS RRset
   whose owner exactly equals the candidate name (answer or referral authority).
2. **Candidate-apex authoritative** — delegated child nameservers return
   owner-matching NS or SOA evidence at the candidate apex.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import dns.message
import dns.rdatatype

from scanner.dns_classifier import DNSResponseClass, classify_dns_response, is_no_finding_class
from scanner.evidence_status import outcome_ignored_unrelated_authority
from scanner.evidence_trace import build_promotion_trace, build_rejection_trace, promotion_traces_from_response
from scanner.models import (
    DiscoveredRecord,
    EvidenceOutcome,
    EvidenceStatus,
    FindingClassification,
    RecordType,
)

SendQueryFn = Callable[
    [str, RecordType, object],
    tuple[dns.message.Message | None, str | None],
]
ResolveNsIpsFn = Callable[[str], list[str]]
MakeResolverFn = Callable[[str | None], object]
GetParentNsHostsFn = Callable[[str], list[str]]


def _norm_name(name: str) -> str:
    return name.strip().lower().rstrip(".")


def _parent_domain(name: str) -> str | None:
    labels = _norm_name(name).split(".")
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])


def _format_ns(rdata) -> str:
    return rdata.target.to_text().rstrip(".")


def _format_soa(rdata) -> str:
    return (
        f"{rdata.mname} {rdata.rname} serial={rdata.serial} "
        f"refresh={rdata.refresh} retry={rdata.retry} expire={rdata.expire} minimum={rdata.minimum}"
    )


@dataclass
class DelegationVerificationResult:
    """Structured outcome of delegation verification for one candidate."""

    verified: bool
    method: str  # parent_authoritative_ns | candidate_apex_ns | candidate_apex_soa | none
    response_class: DNSResponseClass | None
    reason: str
    matched_owner: str | None
    source_path: str  # parent_authoritative | candidate_authoritative | unknown
    records: list[DiscoveredRecord] = field(default_factory=list)
    log_message: str = ""
    errors: list[str] = field(default_factory=list)
    evidence_outcomes: list[EvidenceOutcome] = field(default_factory=list)


def _collect_candidate_ns(
    response: dns.message.Message,
    candidate: str,
) -> list[tuple[str, str, int | None, str]]:
    """Return (owner, ns_target, ttl, section) for NS RRsets owned by *candidate*."""
    nq = _norm_name(candidate)
    found: list[tuple[str, str, int | None, str]] = []
    for section_name, section in (("answer", response.answer), ("authority", response.authority)):
        for rrset in section:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            owner = _norm_name(rrset.name.to_text())
            if owner != nq:
                continue
            for rdata in rrset:
                found.append((owner, _format_ns(rdata), rrset.ttl, section_name))
    return found


def _wrong_owner_hint(response: dns.message.Message, candidate: str) -> str | None:
    """Return the non-matching owner name from authority/answer, if present."""
    nq = _norm_name(candidate)
    for section in (response.authority, response.answer):
        for rrset in section:
            if rrset.rdtype not in (dns.rdatatype.NS, dns.rdatatype.SOA):
                continue
            owner = _norm_name(rrset.name.to_text())
            if owner == nq:
                continue
            return owner
    return None


def _delegation_log_not_verified(candidate: str, rc: DNSResponseClass) -> str:
    return f"Delegation not verified for {candidate}: {rc.name}"


def _delegation_log_ignored_signal(candidate: str, detail: str) -> str:
    return f"Ignored unverified delegation signal for {candidate}: {detail}"


def _delegation_log_verified(candidate: str, method: str) -> str:
    labels = {
        "parent_authoritative_ns": "parent-authoritative NS owner match",
        "candidate_apex_ns": "candidate-apex NS owner match",
        "candidate_apex_soa": "candidate-apex SOA owner match",
    }
    return f"Delegation verified for {candidate} via {labels.get(method, method)}"


def _records_from_parent_side_ns(
    candidate: str,
    ns_entries: list[tuple[str, str, int | None, str]],
    *,
    nameserver: str | None,
    source_method: str,
) -> list[DiscoveredRecord]:
    records: list[DiscoveredRecord] = []
    seen: set[tuple[str, str]] = set()
    for owner, target, ttl, section in ns_entries:
        key = (_norm_name(candidate), target)
        if key in seen:
            continue
        seen.add(key)
        trace = build_promotion_trace(
            qname=_norm_name(candidate),
            qtype="NS",
            response=None,
            section=section,
            rr_owner=_norm_name(candidate),
            rr_type="NS",
            rr_value=target,
            source_method=source_method,
            resolver_or_server=nameserver,
            response_class=DNSResponseClass.OWNER_MATCHING_ANSWER,
            evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
            finding_type=FindingClassification.DELEGATED_CHILD_ZONE,
            promotion_reason="Verified delegation via owner-matching NS",
        )
        records.append(
            DiscoveredRecord(
                fqdn=_norm_name(candidate),
                record_type=RecordType.NS,
                value=target,
                source_method=source_method,
                classification=FindingClassification.DELEGATED_CHILD_ZONE,
                confidence="high",
                nameserver=nameserver,
                ttl=ttl,
                evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
                evidence_trace=[trace],
            )
        )
    return records


def _record_from_apex_soa(
    candidate: str,
    response: dns.message.Message,
    *,
    nameserver: str | None,
    source_method: str,
) -> DiscoveredRecord | None:
    nq = _norm_name(candidate)
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.SOA:
            continue
        owner = _norm_name(rrset.name.to_text())
        if owner != nq:
            continue
        for rdata in rrset:
            soa_value = _format_soa(rdata)
            traces = promotion_traces_from_response(
                response,
                nq,
                RecordType.SOA,
                source_method=source_method,
                resolver_or_server=nameserver,
                classification=FindingClassification.ZONE_SOA_DISCOVERED,
                evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
                format_rdata=lambda _rt, rd: _format_soa(rd),
            )
            return DiscoveredRecord(
                fqdn=nq,
                record_type=RecordType.SOA,
                value=soa_value,
                source_method=source_method,
                classification=FindingClassification.ZONE_SOA_DISCOVERED,
                confidence="high",
                nameserver=nameserver,
                ttl=rrset.ttl,
                evidence_status=EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
                evidence_trace=traces,
            )
    return None


def _evaluate_parent_side_response(
    candidate: str,
    response: dns.message.Message | None,
    transport_error: str | None,
) -> tuple[bool, DNSResponseClass | None, str, list[tuple[str, str, int | None, str]]]:
    """Return (is_verified, response_class, reason_detail, candidate_ns_entries)."""
    rc = classify_dns_response(response, candidate, transport_error)

    if rc == DNSResponseClass.UNRELATED_AUTHORITY:
        hint = _wrong_owner_hint(response, candidate) if response else None
        detail = (
            f"authority NS owner {hint} does not match candidate"
            if hint
            else "unrelated authority data"
        )
        return False, rc, _delegation_log_ignored_signal(candidate, detail), []

    if is_no_finding_class(rc):
        return False, rc, _delegation_log_not_verified(candidate, rc), []

    if rc == DNSResponseClass.CNAME_ALIAS:
        return False, rc, _delegation_log_not_verified(candidate, rc), []

    if rc in (DNSResponseClass.OWNER_MATCHING_ANSWER, DNSResponseClass.REFERRAL_DELEGATION):
        ns_entries = _collect_candidate_ns(response, candidate) if response else []
        if ns_entries:
            return True, rc, "", ns_entries
        return False, rc, _delegation_log_not_verified(candidate, rc), []

    return False, rc, _delegation_log_not_verified(candidate, rc), []


def verify_delegated_child_zone(
    candidate: str,
    *,
    base_domain: str,
    send_query: SendQueryFn,
    resolve_ns_ips: ResolveNsIpsFn,
    make_resolver: MakeResolverFn,
    get_parent_ns_hosts: GetParentNsHostsFn | None = None,
    parent_ns_hosts: list[str] | None = None,
    delegation_child_ns_hosts: list[str] | None = None,
    source_method: str = "delegation_verification",
    log_sink: list[str] | None = None,
) -> DelegationVerificationResult:
    """Verify delegation for *candidate*; return structured result (fail-closed).

    Only parent-side or candidate-apex authoritative paths may produce
    ``delegated_child_zone`` or apex SOA findings.  Recursive resolver evidence
    is never sufficient by itself.
    """
    _ = base_domain  # reserved for future parent-context rules (Ticket 26)
    candidate_norm = _norm_name(candidate)
    parent = _parent_domain(candidate_norm)
    errors: list[str] = []
    evidence_outcomes: list[EvidenceOutcome] = []
    last_log = ""

    if not parent:
        msg = f"Delegation not verified for {candidate_norm}: no parent domain"
        if log_sink is not None:
            log_sink.append(msg)
        return DelegationVerificationResult(
            verified=False,
            method="none",
            response_class=None,
            reason="no parent domain",
            matched_owner=None,
            source_path="unknown",
            log_message=msg,
            evidence_outcomes=evidence_outcomes,
        )

    hosts = list(parent_ns_hosts or [])
    if not hosts and get_parent_ns_hosts is not None:
        try:
            hosts = list(get_parent_ns_hosts(parent))
        except Exception:
            hosts = []

    child_ns_targets: list[str] = []

    # --- Path 1: parent-side authoritative NS owner match -------------------
    for ns_host in hosts:
        for ns_ip in resolve_ns_ips(ns_host):
            resolver = make_resolver(ns_ip)
            response, transport_error = send_query(candidate_norm, RecordType.NS, resolver)
            if transport_error and "timeout" in transport_error.lower():
                errors.append(transport_error)

            verified, rc, reason, ns_entries = _evaluate_parent_side_response(
                candidate_norm, response, transport_error
            )
            if ns_entries:
                child_ns_targets.extend(target for _o, target, _t, _s in ns_entries)

            if verified:
                nameserver = f"{ns_host} ({ns_ip})"
                records = _records_from_parent_side_ns(
                    candidate_norm,
                    ns_entries,
                    nameserver=nameserver,
                    source_method=f"{source_method}/parent_authoritative",
                )
                log_msg = _delegation_log_verified(candidate_norm, "parent_authoritative_ns")
                if log_sink is not None:
                    log_sink.append(log_msg)
                return DelegationVerificationResult(
                    verified=True,
                    method="parent_authoritative_ns",
                    response_class=rc,
                    reason="",
                    matched_owner=candidate_norm,
                    source_path="parent_authoritative",
                    records=records,
                    log_message=log_msg,
                    errors=errors,
                    evidence_outcomes=evidence_outcomes,
                )

            if reason:
                last_log = reason
                if rc == DNSResponseClass.UNRELATED_AUTHORITY:
                    ignored_trace = build_rejection_trace(
                        qname=candidate_norm,
                        qtype=RecordType.NS.value,
                        response=response,
                        transport_error=transport_error,
                        response_class=rc,
                        source_method=source_method,
                        resolver_or_server=f"{ns_host} ({ns_ip})",
                        rejection_reason=reason,
                        evidence_status=EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
                    )
                    evidence_outcomes.append(
                        outcome_ignored_unrelated_authority(
                            candidate_norm,
                            source_method=source_method,
                            detail=reason,
                            evidence_trace=[ignored_trace],
                        )
                    )

    # --- Path 2: candidate-apex authoritative NS / SOA ----------------------
    child_ns_targets = list(dict.fromkeys(child_ns_targets + list(delegation_child_ns_hosts or [])))
    for child_host in child_ns_targets:
        for child_ip in resolve_ns_ips(child_host):
            resolver = make_resolver(child_ip)
            nameserver = f"{child_host} ({child_ip})"

            # NS at candidate apex
            ns_response, ns_error = send_query(candidate_norm, RecordType.NS, resolver)
            if ns_error and "timeout" in ns_error.lower():
                errors.append(ns_error)
            ns_verified, ns_rc, ns_reason, ns_entries = _evaluate_parent_side_response(
                candidate_norm, ns_response, ns_error
            )
            if ns_verified and ns_entries:
                records = _records_from_parent_side_ns(
                    candidate_norm,
                    ns_entries,
                    nameserver=nameserver,
                    source_method=f"{source_method}/candidate_authoritative",
                )
                log_msg = _delegation_log_verified(candidate_norm, "candidate_apex_ns")
                if log_sink is not None:
                    log_sink.append(log_msg)
                return DelegationVerificationResult(
                    verified=True,
                    method="candidate_apex_ns",
                    response_class=ns_rc,
                    reason="",
                    matched_owner=candidate_norm,
                    source_path="candidate_authoritative",
                    records=records,
                    log_message=log_msg,
                    errors=errors,
                    evidence_outcomes=evidence_outcomes,
                )
            if ns_reason:
                last_log = ns_reason
                if ns_rc == DNSResponseClass.UNRELATED_AUTHORITY:
                    ignored_trace = build_rejection_trace(
                        qname=candidate_norm,
                        qtype=RecordType.NS.value,
                        response=ns_response,
                        transport_error=ns_error,
                        response_class=ns_rc,
                        source_method=source_method,
                        resolver_or_server=nameserver,
                        rejection_reason=ns_reason,
                        evidence_status=EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
                    )
                    evidence_outcomes.append(
                        outcome_ignored_unrelated_authority(
                            candidate_norm,
                            source_method=source_method,
                            detail=ns_reason,
                            evidence_trace=[ignored_trace],
                        )
                    )

            # SOA at candidate apex (zone/apex evidence, not delegated_child_zone)
            soa_response, soa_error = send_query(candidate_norm, RecordType.SOA, resolver)
            if soa_error and "timeout" in soa_error.lower():
                errors.append(soa_error)
            soa_rc = classify_dns_response(soa_response, candidate_norm, soa_error)
            if soa_rc == DNSResponseClass.OWNER_MATCHING_ANSWER and soa_response is not None:
                soa_record = _record_from_apex_soa(
                    candidate_norm,
                    soa_response,
                    nameserver=nameserver,
                    source_method=f"{source_method}/candidate_authoritative",
                )
                if soa_record is not None:
                    log_msg = _delegation_log_verified(candidate_norm, "candidate_apex_soa")
                    if log_sink is not None:
                        log_sink.append(log_msg)
                    return DelegationVerificationResult(
                        verified=True,
                        method="candidate_apex_soa",
                        response_class=soa_rc,
                        reason="",
                        matched_owner=candidate_norm,
                        source_path="candidate_authoritative",
                        records=[soa_record],
                        log_message=log_msg,
                        errors=errors,
                        evidence_outcomes=evidence_outcomes,
                    )
            if is_no_finding_class(soa_rc):
                last_log = _delegation_log_not_verified(candidate_norm, soa_rc)
            elif soa_rc == DNSResponseClass.UNRELATED_AUTHORITY:
                hint = _wrong_owner_hint(soa_response, candidate_norm) if soa_response else None
                detail = (
                    f"authority SOA owner {hint} does not match candidate"
                    if hint
                    else "unrelated authority SOA"
                )
                last_log = _delegation_log_ignored_signal(candidate_norm, detail)
                ignored_trace = build_rejection_trace(
                    qname=candidate_norm,
                    qtype=RecordType.SOA.value,
                    response=soa_response,
                    transport_error=soa_error,
                    response_class=soa_rc,
                    source_method=source_method,
                    resolver_or_server=nameserver,
                    rejection_reason=last_log,
                    evidence_status=EvidenceStatus.IGNORED_UNRELATED_AUTHORITY,
                )
                evidence_outcomes.append(
                    outcome_ignored_unrelated_authority(
                        candidate_norm,
                        source_method=source_method,
                        detail=last_log,
                        evidence_trace=[ignored_trace],
                    )
                )

    if last_log:
        if log_sink is not None:
            log_sink.append(last_log)
        return DelegationVerificationResult(
            verified=False,
            method="none",
            response_class=None,
            reason=last_log,
            matched_owner=None,
            source_path="unknown",
            log_message=last_log,
            errors=errors,
            evidence_outcomes=evidence_outcomes,
        )

    msg = f"Delegation not verified for {candidate_norm}: no authoritative verification path"
    if log_sink is not None:
        log_sink.append(msg)
    return DelegationVerificationResult(
        verified=False,
        method="none",
        response_class=None,
        reason=msg,
        matched_owner=None,
        source_path="unknown",
        log_message=msg,
        errors=errors,
        evidence_outcomes=evidence_outcomes,
    )
