"""Raw evidence trace builders for DNS findings and diagnostics."""

from __future__ import annotations

import dns.flags
import dns.message
import dns.rdatatype
import dns.rcode

from scanner.dns_classifier import DNSResponseClass, classify_dns_response
from scanner.models import EvidenceStatus, EvidenceTrace, FindingClassification, RecordType


def normalize_trace_name(name: str) -> str:
    return name.strip().lower().rstrip(".")


def source_path_from_method(source_method: str) -> str:
    lowered = source_method.lower()
    if "parent_authoritative" in lowered:
        return "parent_authoritative"
    if "candidate_authoritative" in lowered:
        return "candidate_authoritative"
    if "delegation" in lowered:
        return "delegation_verifier"
    if lowered == "fifth_level_parent_validation":
        return "parent_gating"
    if lowered in {"recursive_resolver", "generated_candidate", "authoritative_nameserver"}:
        return "recursive"
    return "unknown"


def _rcode_text(
    response: dns.message.Message | None,
    transport_error: str | None,
) -> str | None:
    if transport_error and "timeout" in transport_error.lower():
        return "TIMEOUT"
    if response is None:
        return None
    try:
        return dns.rcode.to_text(response.rcode())
    except Exception:
        return None


def _resolver_label(
    resolver,
    nameserver: str | None,
) -> str | None:
    if nameserver:
        return nameserver
    try:
        servers = getattr(resolver, "nameservers", None)
        if servers:
            return str(servers[0])
    except Exception:
        pass
    return None


def _first_authority_rr(
    response: dns.message.Message,
    qname: str,
) -> tuple[str | None, str | None, str | None]:
    """Return (section, rr_owner, rr_type) for a diagnostic authority RR."""
    nq = normalize_trace_name(qname)
    for section_name, section in (("authority", response.authority), ("answer", response.answer)):
        for rrset in section:
            owner = normalize_trace_name(rrset.name.to_text())
            if owner == nq:
                continue
            try:
                rr_type = dns.rdatatype.to_text(rrset.rdtype)
            except Exception:
                rr_type = None
            return section_name, owner, rr_type
    return None, None, None


def trace_to_dict(trace: EvidenceTrace) -> dict[str, str | bool | None]:
    return {
        "qname": trace.qname,
        "normalized_qname": trace.normalized_qname,
        "qtype": trace.qtype,
        "rcode": trace.rcode,
        "section": trace.section,
        "rr_owner": trace.rr_owner,
        "normalized_rr_owner": trace.normalized_rr_owner,
        "rr_type": trace.rr_type,
        "rr_value": trace.rr_value,
        "resolver_or_server": trace.resolver_or_server,
        "authoritative_flag": trace.authoritative_flag,
        "source_path": trace.source_path,
        "response_class": trace.response_class,
        "evidence_status": trace.evidence_status,
        "finding_type": trace.finding_type,
        "promotion_reason": trace.promotion_reason,
        "rejection_reason": trace.rejection_reason,
    }


def traces_to_dicts(traces: list[EvidenceTrace]) -> list[dict[str, str | bool | None]]:
    return [trace_to_dict(item) for item in traces]


def build_promotion_trace(
    *,
    qname: str,
    qtype: str,
    response: dns.message.Message | None,
    section: str,
    rr_owner: str,
    rr_type: str,
    rr_value: str,
    source_method: str,
    resolver_or_server: str | None,
    response_class: DNSResponseClass,
    evidence_status: EvidenceStatus | None,
    finding_type: FindingClassification | None,
    promotion_reason: str,
) -> EvidenceTrace:
    authoritative = None
    if response is not None:
        authoritative = bool(response.flags & dns.flags.AA)
    return EvidenceTrace(
        qname=qname,
        normalized_qname=normalize_trace_name(qname),
        qtype=qtype,
        rcode=_rcode_text(response, None),
        section=section,
        rr_owner=rr_owner,
        normalized_rr_owner=normalize_trace_name(rr_owner),
        rr_type=rr_type,
        rr_value=rr_value,
        resolver_or_server=resolver_or_server,
        authoritative_flag=authoritative,
        source_path=source_path_from_method(source_method),
        response_class=response_class.value,
        evidence_status=evidence_status.value if evidence_status else None,
        finding_type=finding_type.value if finding_type else None,
        promotion_reason=promotion_reason,
        rejection_reason=None,
    )


def build_rejection_trace(
    *,
    qname: str,
    qtype: str,
    response: dns.message.Message | None,
    transport_error: str | None,
    response_class: DNSResponseClass,
    source_method: str,
    resolver_or_server: str | None,
    rejection_reason: str,
    evidence_status: EvidenceStatus | None = None,
    rr_owner: str | None = None,
    rr_type: str | None = None,
    rr_value: str | None = None,
    section: str | None = None,
) -> EvidenceTrace:
    authoritative = None
    if response is not None:
        authoritative = bool(response.flags & dns.flags.AA)
    if response is not None and response_class == DNSResponseClass.UNRELATED_AUTHORITY:
        hint_section, hint_owner, hint_type = _first_authority_rr(response, qname)
        section = section or hint_section or "authority"
        rr_owner = rr_owner or hint_owner
        rr_type = rr_type or hint_type
    if response_class in {
        DNSResponseClass.TIMEOUT,
        DNSResponseClass.MALFORMED_OR_UNUSABLE,
    }:
        section = section or "transport"
    if response_class == DNSResponseClass.NEGATIVE_NXDOMAIN:
        section = section or "none"
    if response_class == DNSResponseClass.NODATA_EMPTY_ANSWER:
        section = section or "authority"
    return EvidenceTrace(
        qname=qname,
        normalized_qname=normalize_trace_name(qname),
        qtype=qtype,
        rcode=_rcode_text(response, transport_error),
        section=section,
        rr_owner=rr_owner,
        normalized_rr_owner=normalize_trace_name(rr_owner) if rr_owner else None,
        rr_type=rr_type,
        rr_value=rr_value,
        resolver_or_server=resolver_or_server,
        authoritative_flag=authoritative,
        source_path=source_path_from_method(source_method),
        response_class=response_class.value,
        evidence_status=evidence_status.value if evidence_status else None,
        finding_type=None,
        promotion_reason=None,
        rejection_reason=rejection_reason,
    )


def promotion_traces_from_response(
    response: dns.message.Message,
    fqdn: str,
    record_type: RecordType,
    *,
    source_method: str,
    resolver_or_server: str | None,
    classification: FindingClassification,
    evidence_status: EvidenceStatus | None,
    format_rdata,
) -> list[EvidenceTrace]:
    """Build promotion traces for owner-matching answer RRs."""
    traces: list[EvidenceTrace] = []
    rc = classify_dns_response(response, fqdn, None)
    queried = normalize_trace_name(fqdn)
    qtype = record_type.value
    for rrset in response.answer:
        owner = normalize_trace_name(rrset.name.to_text())
        if owner != queried:
            continue
        try:
            parsed_type = RecordType(dns.rdatatype.to_text(rrset.rdtype))
        except ValueError:
            continue
        for rdata in rrset:
            value = format_rdata(parsed_type, rdata)
            item_class = classification
            if item_class == FindingClassification.DELEGATED_CHILD_ZONE:
                item_class = FindingClassification.STANDARD_RECORD
            status = evidence_status
            if status is None:
                if item_class == FindingClassification.DELEGATED_CHILD_ZONE:
                    status = EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE
                elif item_class == FindingClassification.STANDARD_RECORD:
                    status = EvidenceStatus.CONFIRMED_ORDINARY_DNS_NAME
            traces.append(
                build_promotion_trace(
                    qname=fqdn,
                    qtype=qtype,
                    response=response,
                    section="answer",
                    rr_owner=owner,
                    rr_type=parsed_type.value,
                    rr_value=value,
                    source_method=source_method,
                    resolver_or_server=resolver_or_server,
                    response_class=rc,
                    evidence_status=status,
                    finding_type=item_class,
                    promotion_reason=f"Owner-matching {parsed_type.value} in ANSWER section",
                )
            )
    if not traces and rc == DNSResponseClass.REFERRAL_DELEGATION:
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            owner = normalize_trace_name(rrset.name.to_text())
            if owner != queried:
                continue
            for rdata in rrset:
                target = rdata.target.to_text().rstrip(".")
                traces.append(
                    build_promotion_trace(
                        qname=fqdn,
                        qtype=qtype,
                        response=response,
                        section="authority",
                        rr_owner=owner,
                        rr_type="NS",
                        rr_value=target,
                        source_method=source_method,
                        resolver_or_server=resolver_or_server,
                        response_class=rc,
                        evidence_status=evidence_status or EvidenceStatus.CONFIRMED_DELEGATED_CHILD_ZONE,
                        finding_type=FindingClassification.DELEGATED_CHILD_ZONE,
                        promotion_reason="Owner-matching NS referral in AUTHORITY section",
                    )
                )
    return traces


def probe_traces_for_parent(
    parent: str,
    record_types: tuple[RecordType, ...],
    send_query,
    resolver,
    *,
    source_method: str,
    evidence_status: EvidenceStatus | None = None,
    rejection_reason: str | None = None,
) -> list[EvidenceTrace]:
    """Build diagnostic traces from parent probe queries."""
    traces: list[EvidenceTrace] = []
    resolver_label = _resolver_label(resolver, None)
    for record_type in record_types:
        response, transport_error = send_query(parent, record_type, resolver)
        rc = classify_dns_response(response, parent, transport_error)
        reason = rejection_reason or f"Parent probe classified as {rc.value}"
        traces.append(
            build_rejection_trace(
                qname=parent,
                qtype=record_type.value,
                response=response,
                transport_error=transport_error,
                response_class=rc,
                source_method=source_method,
                resolver_or_server=resolver_label,
                rejection_reason=reason,
                evidence_status=evidence_status,
            )
        )
    return traces
