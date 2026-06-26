"""CSV, JSON, and XLSX export for DNS discovery scan results."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from scanner.input_loader import known_child_domains_from_record, normalize_domain_name
from scanner.models import (
    DiscoveredRecord,
    DomainInputRecord,
    DomainScanResult,
    FindingClassification,
    ScanRunResult,
    ScanStatus,
)
from scanner.scan_engine import (
    CANDIDATE_STRONG_WARN_THRESHOLD,
    CANDIDATE_WARN_THRESHOLD,
    DNS_LIFETIME,
    DNS_TIMEOUT,
)

APP_NAME = ".US Locality DNS Discovery Tool"
APP_VERSION = None
OPERATOR_NOTE = (
    "This workbook is intended as discovery evidence for review. "
    "It is not an authoritative zone inventory."
)

REVIEW_PATH_NOTE = (
    "Recommended review path: open Evidence Review first, filter for strong/moderate "
    "evidence_support_level, manually verify selected rows with dig, and treat "
    "inconclusive/error rows as rerun candidates."
)

EVIDENCE_SUPPORT_ORDER = {
    "strong": 0,
    "moderate": 1,
    "limited": 2,
    "inconclusive": 3,
    "none": 4,
}

RECOMMENDED_REVIEW_ACTIONS = {
    "strong": "Strong example candidate — manually verify",
    "moderate": "Moderate example candidate — review DNS names",
    "limited": "Limited support — base zone or known-child evidence only",
    "inconclusive": "Rerun before conclusion",
    "none": "No action / no evidence found",
}

EVIDENCE_REVIEW_COLUMNS = [
    "base_domain",
    "delegated_manager",
    "zone",
    "evidence_support_level",
    "recommended_review_action",
    "known_child_domains_from_input",
    "dns_discovered_child_names_not_in_input",
    "delegated_child_zones_not_in_input",
    "base_zone_exists",
    "scan_status",
    "analysis_note",
    "manual_verification_hint",
    "limitation_note",
]

DISCOVERY_LIMITATION = (
    "DNS discovery results show only records found through the tested methods. "
    "No records discovered does not prove that no subdelegations or DNS records exist."
)

CONTEXT_LIMITATION = (
    "Results are based on selected input domains, selected wordlists, and tested DNS methods. "
    "Findings support that DNS activity can exist inside externally managed zones, "
    "but they do not provide a complete zone inventory. "
    "Known child-domain fields come from the input dataset and represent system-known information. "
    "DNS-discovered child names come from live DNS testing using selected wordlists and tested DNS methods. "
    "DNS-discovered names not present in the input may support the visibility-gap claim, "
    "but the scan does not provide complete zone enumeration."
)

PARTIAL_SCAN_NOTE = (
    "This scan was cancelled before all domains were completed. Results are partial."
)

SCAN_ERROR_NOTE = "Domain status is incomplete/error; rerun recommended."

SOA_FINDING_NOTE = (
    "SOA discovered; zone exists even though requested record type may have no direct answer."
)

CSV_COLUMNS = [
    "scan_timestamp",
    "base_domain",
    "tested_name",
    "record_type",
    "finding_type",
    "confidence",
    "source",
    "nameserver",
    "value",
    "ttl",
    "wildcard_suspected",
    "axfr_status",
    "error",
    "wordlist_sources",
    "notes",
]

SUMMARY_COLUMNS = [
    "scan_timestamp",
    "base_domain",
    "input_domain",
    "delegated_manager",
    "zone",
    "second_level_domain",
    "known_fourth_level_count",
    "known_fifth_level_count",
    "known_fourth_level_domains",
    "known_fifth_level_domains",
    "known_child_domains_from_input",
    "known_child_domains_from_input_count",
    "dns_discovered_child_names",
    "dns_discovered_child_names_count",
    "dns_discovered_child_names_already_known",
    "dns_discovered_child_names_already_known_count",
    "dns_discovered_child_names_not_in_input",
    "dns_discovered_child_names_not_in_input_count",
    "delegated_child_zones_not_in_input",
    "delegated_child_zones_not_in_input_count",
    "evidence_support_level",
    "recommended_review_action",
    "manual_verification_hint",
    "scan_status",
    "authoritative_nameservers",
    "axfr_status",
    "wildcard_suspected",
    "base_zone_exists",
    "base_records_found",
    "delegated_child_zones_found",
    "dns_names_with_records_found",
    "standard_records_found",
    "candidate_names_tested",
    "wordlist_sources",
    "evidence_summary",
    "analysis_note",
    "limitation_note",
]

ERRORS_WARNINGS_COLUMNS = [
    "scan_timestamp",
    "base_domain",
    "delegated_manager",
    "zone",
    "warning_type",
    "tested_name",
    "record_type",
    "nameserver",
    "message",
    "notes",
]

SCAN_STATUS_AXFR = "AXFR allowed"
SCAN_STATUS_DELEGATED_CHILD = "Possible delegated child zone discovered"
SCAN_STATUS_DNS_ACTIVITY_WITH_ERRORS = "DNS activity discovered with scan errors"
SCAN_STATUS_DNS_ACTIVITY = "DNS activity discovered"
SCAN_STATUS_BASE_ZONE_EXISTS = "Base domain zone exists"
SCAN_STATUS_BASE_ONLY = "Base domain records only"
SCAN_STATUS_INCOMPLETE = "Scan incomplete / error"
SCAN_STATUS_ERRORS_ONLY = "Scan errors only"
SCAN_STATUS_NO_RECORDS = "No records discovered using tested methods"

# Legacy alias used in a few internal references.
SCAN_STATUS_SUBDELEGATION = SCAN_STATUS_DELEGATED_CHILD

SUMMARY_STATUS_FILLS = {
    SCAN_STATUS_AXFR: PatternFill(fill_type="solid", fgColor="C6EFCE"),
    SCAN_STATUS_DELEGATED_CHILD: PatternFill(fill_type="solid", fgColor="BDD7EE"),
    SCAN_STATUS_DNS_ACTIVITY_WITH_ERRORS: PatternFill(fill_type="solid", fgColor="F4B084"),
    SCAN_STATUS_DNS_ACTIVITY: PatternFill(fill_type="solid", fgColor="FFE699"),
    SCAN_STATUS_BASE_ZONE_EXISTS: PatternFill(fill_type="solid", fgColor="D9E1F2"),
    SCAN_STATUS_BASE_ONLY: PatternFill(fill_type="solid", fgColor="EDEDED"),
    SCAN_STATUS_INCOMPLETE: PatternFill(fill_type="solid", fgColor="FFC7CE"),
    SCAN_STATUS_ERRORS_ONLY: PatternFill(fill_type="solid", fgColor="FFC7CE"),
    SCAN_STATUS_NO_RECORDS: PatternFill(fill_type="solid", fgColor="F8CBAD"),
}

ExportFormat = Literal["xlsx", "csv", "json", "all"]


@dataclass
class ExportOutcome:
    """Result of an export operation."""

    xlsx_path: Path | None = None
    csv_path: Path | None = None
    json_path: Path | None = None
    summary_csv_path: Path | None = None
    row_count: int = 0
    domain_count: int = 0


def _format_timestamp(value: datetime | None) -> str:
    if value is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _findings_report_stem(scan_timestamp: datetime | None) -> str:
    stamp = scan_timestamp or datetime.now()
    return f"us_locality_dns_discovery_{stamp.strftime('%Y%m%d_%H%M%S')}"


def _workbook_report_stem(scan_timestamp: datetime | None) -> str:
    stamp = scan_timestamp or datetime.now()
    return f"us_locality_dns_report_{stamp.strftime('%Y%m%d_%H%M%S')}"


def _export_notes(result: ScanRunResult) -> str:
    parts = [DISCOVERY_LIMITATION, CONTEXT_LIMITATION]
    if result.partial or result.cancelled:
        parts.append(PARTIAL_SCAN_NOTE)
    return " ".join(parts)


def _limitation_note(result: ScanRunResult) -> str:
    return _export_notes(result)


def _input_metadata_values(domain_result: DomainScanResult) -> dict[str, str]:
    record = domain_result.input_record
    if record is None:
        return {
            "input_domain": "",
            "delegated_manager": "",
            "zone": "",
            "second_level_domain": "",
            "known_fourth_level_count": "",
            "known_fifth_level_count": "",
            "known_fourth_level_domains": "",
            "known_fifth_level_domains": "",
        }

    return {
        "input_domain": record.original_domain,
        "delegated_manager": record.delegated_manager,
        "zone": record.zone,
        "second_level_domain": record.second_level_domain,
        "known_fourth_level_count": record.fourth_level_count,
        "known_fifth_level_count": record.fifth_level_count,
        "known_fourth_level_domains": "; ".join(record.known_fourth_level_domains),
        "known_fifth_level_domains": "; ".join(record.known_fifth_level_domains),
    }


def _is_child_name(fqdn: str, base_domain: str) -> bool:
    child = normalize_domain_name(fqdn)
    base = normalize_domain_name(base_domain)
    if child == base:
        return False
    return child.endswith(f".{base}")


def _join_domain_list(names: set[str]) -> str:
    return "; ".join(sorted(names))


def _collect_dns_discovered_children(
    domain_result: DomainScanResult,
) -> tuple[set[str], set[str], bool]:
    """
    Return DNS-discovered child names, delegated child zone names, and base-only flag.

    Child names come from standard_record, delegated_child_zone, zone_soa_discovered
    (below base), and axfr_success (below base).
    """
    base = domain_result.domain
    child_names: set[str] = set()
    delegated_children: set[str] = set()
    base_evidence = False

    for record in domain_result.records:
        classification = record.classification
        fqdn = normalize_domain_name(record.fqdn)

        if classification in {
            FindingClassification.QUERY_ERROR,
            FindingClassification.SCAN_ERROR,
            FindingClassification.AXFR_BLOCKED,
            FindingClassification.NO_RECORDS_DISCOVERED,
            FindingClassification.AUTHORITATIVE_NS,
        }:
            continue

        if classification in {
            FindingClassification.BASE_DOMAIN_RECORD,
            FindingClassification.BASE_ZONE_EXISTS,
        }:
            if fqdn == normalize_domain_name(base):
                base_evidence = True
            continue

        if classification == FindingClassification.ZONE_SOA_DISCOVERED:
            if _is_child_name(fqdn, base):
                child_names.add(fqdn)
            elif fqdn == normalize_domain_name(base):
                base_evidence = True
            continue

        if classification == FindingClassification.DELEGATED_CHILD_ZONE:
            if _is_child_name(fqdn, base):
                child_names.add(fqdn)
                delegated_children.add(fqdn)
            continue

        if classification == FindingClassification.STANDARD_RECORD:
            if _is_child_name(fqdn, base):
                child_names.add(fqdn)
            continue

        if classification == FindingClassification.AXFR_SUCCESS:
            if _is_child_name(fqdn, base):
                child_names.add(fqdn)
            elif fqdn == normalize_domain_name(base):
                base_evidence = True
            continue

    dns_discovered_base_only = base_evidence and not child_names
    return child_names, delegated_children, dns_discovered_base_only


def _compare_known_vs_discovered(
    domain_result: DomainScanResult,
) -> dict[str, str | int | bool]:
    known = known_child_domains_from_record(domain_result.input_record)
    discovered, delegated_discovered, dns_discovered_base_only = _collect_dns_discovered_children(
        domain_result
    )

    already_known = discovered & known
    not_in_input = discovered - known
    delegated_not_in_input = delegated_discovered - known

    return {
        "known_child_domains_from_input": _join_domain_list(known),
        "known_child_domains_from_input_count": len(known),
        "dns_discovered_child_names": _join_domain_list(discovered),
        "dns_discovered_child_names_count": len(discovered),
        "dns_discovered_child_names_already_known": _join_domain_list(already_known),
        "dns_discovered_child_names_already_known_count": len(already_known),
        "dns_discovered_child_names_not_in_input": _join_domain_list(not_in_input),
        "dns_discovered_child_names_not_in_input_count": len(not_in_input),
        "delegated_child_zones_not_in_input": _join_domain_list(delegated_not_in_input),
        "delegated_child_zones_not_in_input_count": len(delegated_not_in_input),
        "_dns_discovered_base_only": dns_discovered_base_only,
        "_known_set": known,
        "_discovered_set": discovered,
        "_delegated_not_in_input_set": delegated_not_in_input,
    }


def _axfr_child_names_not_in_input(domain_result: DomainScanResult, known: set[str]) -> set[str]:
    base = normalize_domain_name(domain_result.domain)
    not_in_input: set[str] = set()
    for record in domain_result.records:
        if record.classification != FindingClassification.AXFR_SUCCESS:
            continue
        fqdn = normalize_domain_name(record.fqdn)
        if fqdn != base and _is_child_name(fqdn, domain_result.domain) and fqdn not in known:
            not_in_input.add(fqdn)
    return not_in_input


def _evidence_support_level(
    domain_result: DomainScanResult,
    counts: dict[str, int],
    scan_status: str,
    comparison: dict[str, str | int | bool],
) -> str:
    if _domain_has_scan_error(domain_result):
        return "inconclusive"

    delegated_not_in_input = int(comparison["delegated_child_zones_not_in_input_count"])
    dns_not_in_input = int(comparison["dns_discovered_child_names_not_in_input_count"])
    known = comparison["_known_set"]
    axfr_children_not_in_input = _axfr_child_names_not_in_input(domain_result, known)  # type: ignore[arg-type]

    if delegated_not_in_input > 0 or axfr_children_not_in_input:
        return "strong"

    if dns_not_in_input > 0:
        return "moderate"

    discovered_count = int(comparison["dns_discovered_child_names_count"])
    already_known_count = int(comparison["dns_discovered_child_names_already_known_count"])
    has_base_zone = counts["base_zone_exists_flag"] > 0
    has_live_dns = (
        discovered_count > 0
        or counts["delegated_child_zones"] > 0
        or has_base_zone
        or counts["axfr_success"] > 0
    )

    if has_base_zone or (has_live_dns and discovered_count > 0 and discovered_count == already_known_count):
        return "limited"

    if scan_status == SCAN_STATUS_NO_RECORDS or not has_live_dns:
        return "none"

    return "limited"


def _analysis_note(
    domain_result: DomainScanResult,
    counts: dict[str, int],
    scan_status: str,
    comparison: dict[str, str | int | bool],
) -> str:
    if _domain_has_scan_error(domain_result):
        return "Scan incomplete/error; rerun before drawing conclusions."

    dns_not_in_input = int(comparison["dns_discovered_child_names_not_in_input_count"])
    discovered_count = int(comparison["dns_discovered_child_names_count"])
    already_known_count = int(comparison["dns_discovered_child_names_already_known_count"])
    known_count = int(comparison["known_child_domains_from_input_count"])
    dns_discovered_base_only = bool(comparison["_dns_discovered_base_only"])

    if dns_not_in_input > 0:
        return (
            "DNS-discovered child activity was found that was not listed in the "
            "input child-domain fields."
        )

    if discovered_count > 0 and discovered_count == already_known_count:
        return "DNS activity was found only on child domains already listed in the input."

    if known_count > 0 and discovered_count == 0:
        return (
            "Input lists known child domains, but this scan did not discover live "
            "DNS evidence for them."
        )

    if dns_discovered_base_only:
        return (
            "Only base-zone evidence was found; no child DNS names were discovered "
            "by tested methods."
        )

    if scan_status == SCAN_STATUS_NO_RECORDS:
        return "No records discovered using selected methods; this does not prove absence."

    if discovered_count > 0:
        return "DNS activity was found only on child domains already listed in the input."

    return "No records discovered using selected methods; this does not prove absence."


def _recommended_review_action(evidence_support_level: str) -> str:
    return RECOMMENDED_REVIEW_ACTIONS.get(
        evidence_support_level,
        "No action / no evidence found",
    )


def _parse_domain_list(value: str) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(";") if part.strip()]


def _manual_verification_hint(
    domain_result: DomainScanResult,
    counts: dict[str, int],
    scan_status: str,
    comparison: dict[str, str | int | bool],
    evidence_support_level: str,
) -> str:
    if evidence_support_level == "inconclusive" or _domain_has_scan_error(domain_result):
        return "Rerun domain before drawing conclusions."

    if evidence_support_level == "none":
        return "No manual verification target from this scan."

    base = domain_result.domain
    delegated_not_in = comparison.get("_delegated_not_in_input_set", set())
    dns_not_in = comparison.get("_discovered_set", set()) - comparison.get("_known_set", set())
    if isinstance(delegated_not_in, str):
        delegated_not_in = set(_parse_domain_list(str(comparison.get("delegated_child_zones_not_in_input", ""))))
    if not isinstance(dns_not_in, set):
        dns_not_in = set(
            _parse_domain_list(str(comparison.get("dns_discovered_child_names_not_in_input", "")))
        )

    if counts["axfr_success"] > 0 or scan_status == SCAN_STATUS_AXFR:
        return f"Review AXFR output if AXFR succeeded. Verify base zone with: dig SOA {base}; dig NS {base}"

    if evidence_support_level in {"strong", "moderate"} and delegated_not_in:
        child = sorted(delegated_not_in)[0]
        return f"Verify delegated child with: dig NS {child}"

    if evidence_support_level in {"strong", "moderate"} and dns_not_in:
        sample = sorted(dns_not_in)[:2]
        commands: list[str] = []
        for name in sample:
            commands.append(f"dig A {name}")
            commands.append(f"dig CNAME {name}")
        return f"Verify DNS activity with: {'; '.join(commands[:4])}"

    if evidence_support_level == "limited" or counts["base_zone_exists_flag"]:
        return f"Verify base zone with: dig SOA {base}; dig NS {base}"

    return "No manual verification target from this scan."


def _wordlist_sources_text(result: ScanRunResult) -> str:
    if result.wordlist_plan and result.wordlist_plan.source_counts:
        return "; ".join(result.wordlist_plan.source_counts.keys())
    return ""


def _map_confidence(value: str) -> str:
    mapping = {
        "normal": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(value, "unknown")


def _map_source(record: DiscoveredRecord) -> str:
    mapping = {
        "recursive_resolver": "recursive",
        "authoritative_nameserver": "authoritative",
        "axfr": "axfr",
        "wildcard_probe": "wildcard_probe",
        "generated_candidate": "generated_candidate",
    }
    return mapping.get(record.source_method, record.source_method)


def _domain_has_scan_error(domain_result: DomainScanResult) -> bool:
    if domain_result.scan_failed:
        return True
    if any(record.classification == FindingClassification.SCAN_ERROR for record in domain_result.records):
        return True
    return any(
        "unexpected error" in note.lower() or "interrupted" in note.lower()
        for note in domain_result.notes
    )


def _is_dns_activity_record(record: DiscoveredRecord) -> bool:
    if record.classification == FindingClassification.DELEGATED_CHILD_ZONE:
        return False
    if record.classification in {
        FindingClassification.BASE_ZONE_EXISTS,
        FindingClassification.ZONE_SOA_DISCOVERED,
        FindingClassification.STANDARD_RECORD,
    }:
        return True
    if record.classification == FindingClassification.BASE_DOMAIN_RECORD:
        return record.record_type is not None and record.record_type.value != "NS"
    return False


def _domain_summary_counts(domain_result: DomainScanResult) -> dict[str, int]:
    counts = {
        "total_findings": 0,
        "base_domain_records": 0,
        "authoritative_ns": 0,
        "base_zone_exists": 0,
        "delegated_child_zones": 0,
        "dns_names_with_records": 0,
        "standard_records": 0,
        "axfr_success": 0,
        "axfr_blocked": 0,
        "query_errors": 0,
        "scan_errors": 0,
        "candidates_tested": domain_result.candidates_tested,
    }
    dns_activity_names: set[str] = set()
    delegated_names: set[str] = set()
    base_has_zone = False

    for record in domain_result.records:
        counts["total_findings"] += 1
        key_map = {
            FindingClassification.BASE_DOMAIN_RECORD: "base_domain_records",
            FindingClassification.BASE_ZONE_EXISTS: "base_zone_exists",
            FindingClassification.AUTHORITATIVE_NS: "authoritative_ns",
            FindingClassification.DELEGATED_CHILD_ZONE: "delegated_child_zones",
            FindingClassification.STANDARD_RECORD: "standard_records",
            FindingClassification.AXFR_SUCCESS: "axfr_success",
            FindingClassification.AXFR_BLOCKED: "axfr_blocked",
            FindingClassification.QUERY_ERROR: "query_errors",
            FindingClassification.SCAN_ERROR: "scan_errors",
        }
        bucket = key_map.get(record.classification)
        if bucket:
            counts[bucket] += 1
        if record.classification == FindingClassification.ZONE_SOA_DISCOVERED:
            if record.fqdn == domain_result.domain:
                counts["base_zone_exists"] += 1

        if record.classification == FindingClassification.DELEGATED_CHILD_ZONE:
            delegated_names.add(record.fqdn)
        elif _is_dns_activity_record(record):
            dns_activity_names.add(record.fqdn)

        if record.classification == FindingClassification.BASE_ZONE_EXISTS and record.fqdn == domain_result.domain:
            base_has_zone = True
        if (
            record.record_type is not None
            and record.record_type.value == "SOA"
            and record.fqdn == domain_result.domain
            and record.classification
            in {
                FindingClassification.BASE_ZONE_EXISTS,
                FindingClassification.BASE_DOMAIN_RECORD,
                FindingClassification.ZONE_SOA_DISCOVERED,
            }
        ):
            base_has_zone = True

    counts["delegated_child_zones"] = len(delegated_names)
    counts["dns_names_with_records"] = len(dns_activity_names)
    counts["base_zone_exists_flag"] = 1 if base_has_zone else 0
    return counts


def _axfr_status_values(domain_result: DomainScanResult, axfr_enabled: bool) -> list[str]:
    if not axfr_enabled:
        return ["not_attempted"]

    statuses: list[str] = []
    if any(record.classification == FindingClassification.AXFR_SUCCESS for record in domain_result.records):
        statuses.append("success")

    for record in domain_result.records:
        if record.classification != FindingClassification.AXFR_BLOCKED:
            continue
        message = record.value.lower()
        if "timeout" in message:
            statuses.append("timeout")
        elif "refused" in message:
            statuses.append("refused")
        elif "blocked" in message or "transfererror" in message:
            statuses.append("blocked")
        else:
            statuses.append("failed")

    return statuses or ["not_attempted"]


def _domain_axfr_status(domain_result: DomainScanResult, axfr_enabled: bool) -> str:
    statuses = _axfr_status_values(domain_result, axfr_enabled)
    unique = list(dict.fromkeys(statuses))
    if len(unique) > 1:
        return "mixed"
    return unique[0]


def _authoritative_nameservers(domain_result: DomainScanResult) -> list[str]:
    names: list[str] = []
    for record in domain_result.records:
        if record.classification == FindingClassification.AUTHORITATIVE_NS and record.record_type:
            names.append(record.value.rstrip("."))

    if not names:
        for record in domain_result.records:
            if record.fqdn != domain_result.domain:
                continue
            if record.record_type is None or record.record_type.value != "SOA":
                continue
            if record.classification not in {
                FindingClassification.BASE_ZONE_EXISTS,
                FindingClassification.BASE_DOMAIN_RECORD,
                FindingClassification.ZONE_SOA_DISCOVERED,
            }:
                continue
            mname = record.value.split()[0].rstrip(".")
            if mname:
                names.append(f"{mname} (authoritative indicator from SOA)")

    return list(dict.fromkeys(names))


def _should_emit_no_records_row(domain_result: DomainScanResult, counts: dict[str, int]) -> bool:
    if _domain_has_scan_error(domain_result):
        return False
    if counts["base_zone_exists_flag"]:
        return False
    if counts["delegated_child_zones"] > 0 or counts["dns_names_with_records"] > 0:
        return False
    if counts["base_domain_records"] > 0 or counts["authoritative_ns"] > 0:
        return False
    if counts["axfr_success"] > 0:
        return False
    return True


def _include_record_in_export(record: DiscoveredRecord, base_domain: str) -> bool:
    if record.classification in {
        FindingClassification.QUERY_ERROR,
        FindingClassification.SCAN_ERROR,
    }:
        return record.fqdn == base_domain
    return True


def _record_type_text(record: DiscoveredRecord) -> str:
    if record.classification == FindingClassification.AXFR_SUCCESS and record.record_type is None:
        return "AXFR"
    if record.record_type is None:
        return ""
    return record.record_type.value


def _record_error(record: DiscoveredRecord) -> str:
    if record.classification in {
        FindingClassification.QUERY_ERROR,
        FindingClassification.SCAN_ERROR,
    }:
        return record.value
    return ""


def _finding_notes(record: DiscoveredRecord, base_notes: str) -> str:
    if record.classification in {
        FindingClassification.BASE_ZONE_EXISTS,
        FindingClassification.ZONE_SOA_DISCOVERED,
    }:
        return f"{SOA_FINDING_NOTE} {base_notes}".strip()
    if record.classification == FindingClassification.SCAN_ERROR:
        return f"{SCAN_ERROR_NOTE} {base_notes}".strip()
    return base_notes


def _record_value(record: DiscoveredRecord) -> str:
    if record.classification == FindingClassification.QUERY_ERROR:
        return ""
    if record.classification == FindingClassification.NO_RECORDS_DISCOVERED:
        return "No records discovered using tested methods"
    return record.value


def _base_has_discovered_records(domain_result: DomainScanResult) -> bool:
    for record in domain_result.records:
        if record.fqdn != domain_result.domain:
            continue
        if record.classification in {
            FindingClassification.BASE_DOMAIN_RECORD,
            FindingClassification.AUTHORITATIVE_NS,
            FindingClassification.BASE_ZONE_EXISTS,
            FindingClassification.ZONE_SOA_DISCOVERED,
        }:
            return True
    return False


def _determine_scan_status(domain_result: DomainScanResult, counts: dict[str, int]) -> str:
    has_error = _domain_has_scan_error(domain_result)
    has_delegated = counts["delegated_child_zones"] > 0
    has_dns = counts["dns_names_with_records"] > 0
    has_base_zone = bool(counts["base_zone_exists_flag"])
    has_base_records = counts["base_domain_records"] > 0 or counts["authoritative_ns"] > 0
    has_meaningful = (
        has_delegated
        or has_dns
        or has_base_zone
        or has_base_records
        or counts["axfr_success"] > 0
    )

    if counts["axfr_success"] > 0:
        return SCAN_STATUS_AXFR
    if has_delegated:
        return SCAN_STATUS_DELEGATED_CHILD
    if has_error and has_dns:
        return SCAN_STATUS_DNS_ACTIVITY_WITH_ERRORS
    if has_dns:
        return SCAN_STATUS_DNS_ACTIVITY
    if has_base_zone:
        return SCAN_STATUS_BASE_ZONE_EXISTS
    if has_base_records:
        return SCAN_STATUS_BASE_ONLY
    if has_error:
        if has_meaningful or domain_result.candidates_tested > 0:
            return SCAN_STATUS_INCOMPLETE
        return SCAN_STATUS_INCOMPLETE if domain_result.scan_failed else SCAN_STATUS_ERRORS_ONLY
    if counts["query_errors"] > 0 and counts["total_findings"] == counts["query_errors"]:
        return SCAN_STATUS_ERRORS_ONLY
    return SCAN_STATUS_NO_RECORDS


def _evidence_summary(domain_result: DomainScanResult, counts: dict[str, int]) -> str:
    parts: list[str] = []

    if _domain_has_scan_error(domain_result):
        parts.append("Scan incomplete due to error; rerun recommended.")

    if counts["axfr_success"] > 0:
        parts.append(f"AXFR succeeded with {counts['axfr_success']} record(s) discovered using tested methods")

    delegated = [
        record.fqdn
        for record in domain_result.records
        if record.classification == FindingClassification.DELEGATED_CHILD_ZONE
    ]
    if delegated:
        unique = list(dict.fromkeys(delegated))[:5]
        suffix = "..." if len(delegated) > 5 else ""
        sample = unique[0]
        if len(unique) == 1:
            parts.append(f"Delegated child zone discovered: {sample} has NS records.")
        else:
            parts.append(f"Delegated child zones discovered: {', '.join(unique)}{suffix}")

    dns_names = sorted(
        {
            record.fqdn
            for record in domain_result.records
            if _is_dns_activity_record(record) and not (
                record.fqdn == domain_result.domain
                and record.classification == FindingClassification.BASE_ZONE_EXISTS
            )
        }
    )
    if dns_names:
        examples = dns_names[:3]
        suffix = "..." if len(dns_names) > 3 else ""
        parts.append(
            f"DNS activity discovered: {', '.join(examples)}{suffix} has A/CNAME/MX/TXT/SOA or related records."
        )

    base_soa = [
        record
        for record in domain_result.records
        if record.fqdn == domain_result.domain
        and record.record_type is not None
        and record.record_type.value == "SOA"
    ]
    apex_a = [
        record
        for record in domain_result.records
        if record.fqdn == domain_result.domain
        and record.record_type is not None
        and record.record_type.value == "A"
    ]
    if base_soa and not apex_a:
        parts.append("SOA discovered for base zone; no apex A record found.")
    elif base_soa:
        parts.append("SOA discovered for base zone.")

    base_records = [
        record
        for record in domain_result.records
        if record.classification == FindingClassification.BASE_DOMAIN_RECORD
        and record.fqdn == domain_result.domain
        and record.record_type is not None
        and record.record_type.value != "SOA"
    ]
    if base_records:
        examples = list(
            dict.fromkeys(
                f"{item.record_type.value if item.record_type else 'record'}={item.value[:60]}"
                for item in base_records
            )
        )[:4]
        parts.append(f"Base domain records: {', '.join(examples)}")

    if domain_result.notes:
        for note in domain_result.notes:
            if "authoritative indicator from soa" in note.lower():
                parts.append(note)
            elif "No records discovered" in note and not parts:
                parts.append(note)

    if not parts:
        return "No records discovered using selected wordlists and tested methods."
    return "; ".join(dict.fromkeys(parts))


def build_findings_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Flatten scan results into findings row dictionaries."""
    return build_csv_rows(result)


def build_csv_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Flatten scan results into CSV row dictionaries."""
    rows: list[dict[str, str]] = []
    scan_timestamp = _format_timestamp(result.scan_timestamp)
    wordlist_sources = _wordlist_sources_text(result)
    axfr_enabled = result.input.options.attempt_axfr
    notes = _export_notes(result)

    for domain_result in result.domain_results:
        axfr_status = _domain_axfr_status(domain_result, axfr_enabled)
        wildcard = "true" if domain_result.wildcard_suspected else "false"
        counts = _domain_summary_counts(domain_result)

        if _should_emit_no_records_row(domain_result, counts):
            rows.append(
                {
                    "scan_timestamp": scan_timestamp,
                    "base_domain": domain_result.domain,
                    "tested_name": domain_result.domain,
                    "record_type": "",
                    "finding_type": FindingClassification.NO_RECORDS_DISCOVERED.value,
                    "confidence": "unknown",
                    "source": "recursive",
                    "nameserver": "",
                    "value": "No records discovered using tested methods",
                    "ttl": "",
                    "wildcard_suspected": wildcard,
                    "axfr_status": axfr_status,
                    "error": "",
                    "wordlist_sources": wordlist_sources,
                    "notes": notes,
                }
            )

        for record in domain_result.records:
            if not _include_record_in_export(record, domain_result.domain):
                continue

            rows.append(
                {
                    "scan_timestamp": scan_timestamp,
                    "base_domain": domain_result.domain,
                    "tested_name": record.fqdn,
                    "record_type": _record_type_text(record),
                    "finding_type": record.classification.value,
                    "confidence": _map_confidence(record.confidence),
                    "source": _map_source(record),
                    "nameserver": record.nameserver or "",
                    "value": _record_value(record),
                    "ttl": "" if record.ttl is None else str(record.ttl),
                    "wildcard_suspected": wildcard,
                    "axfr_status": axfr_status,
                    "error": _record_error(record),
                    "wordlist_sources": wordlist_sources,
                    "notes": _finding_notes(record, notes),
                }
            )

    return rows


def build_summary_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Build one summary row per base domain."""
    rows: list[dict[str, str]] = []
    scan_timestamp = _format_timestamp(result.scan_timestamp)
    wordlist_sources = _wordlist_sources_text(result)
    axfr_enabled = result.input.options.attempt_axfr

    for domain_result in result.domain_results:
        counts = _domain_summary_counts(domain_result)
        metadata = _input_metadata_values(domain_result)
        comparison = _compare_known_vs_discovered(domain_result)
        scan_status = _determine_scan_status(domain_result, counts)
        comparison_export = {
            key: str(value)
            for key, value in comparison.items()
            if not key.startswith("_")
        }
        evidence_level = _evidence_support_level(
            domain_result, counts, scan_status, comparison
        )
        rows.append(
            {
                "scan_timestamp": scan_timestamp,
                "base_domain": domain_result.domain,
                **metadata,
                **comparison_export,
                "evidence_support_level": evidence_level,
                "recommended_review_action": _recommended_review_action(evidence_level),
                "manual_verification_hint": _manual_verification_hint(
                    domain_result,
                    counts,
                    scan_status,
                    comparison,
                    evidence_level,
                ),
                "scan_status": scan_status,
                "authoritative_nameservers": "; ".join(_authoritative_nameservers(domain_result)),
                "axfr_status": _domain_axfr_status(domain_result, axfr_enabled),
                "wildcard_suspected": "true" if domain_result.wildcard_suspected else "false",
                "base_zone_exists": "true" if counts["base_zone_exists_flag"] else "false",
                "base_records_found": str(counts["base_domain_records"] + counts["authoritative_ns"]),
                "delegated_child_zones_found": str(counts["delegated_child_zones"]),
                "dns_names_with_records_found": str(counts["dns_names_with_records"]),
                "standard_records_found": str(counts["standard_records"]),
                "candidate_names_tested": str(counts["candidates_tested"]),
                "wordlist_sources": wordlist_sources,
                "evidence_summary": _evidence_summary(domain_result, counts),
                "analysis_note": _analysis_note(domain_result, counts, scan_status, comparison),
                "limitation_note": _limitation_note(result),
            }
        )

    return rows


def build_evidence_review_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Build coworker-ready evidence review rows sorted by support level."""
    summary_rows = build_summary_rows(result)
    review_rows = [
        {column: row.get(column, "") for column in EVIDENCE_REVIEW_COLUMNS}
        for row in summary_rows
    ]
    review_rows.sort(
        key=lambda row: EVIDENCE_SUPPORT_ORDER.get(row.get("evidence_support_level", "none"), 99)
    )
    return review_rows


def build_settings_rows(result: ScanRunResult) -> list[tuple[str, str]]:
    """Build key/value rows for the Scan Settings sheet."""
    plan = result.wordlist_plan
    options = result.input.options
    label_counts = plan.source_counts if plan else {}

    load_info = result.input_load_info
    rows: list[tuple[str, str]] = [
        ("app_name", APP_NAME),
        ("scan_timestamp", _format_timestamp(result.scan_timestamp)),
        ("input_file_type", load_info.input_file_type if load_info else ""),
        ("metadata_columns_detected", ", ".join(load_info.metadata_columns_detected) if load_info else ""),
        ("domains_loaded", str(load_info.domains_loaded if load_info else len(result.domain_inputs))),
        ("duplicate_domains_removed", str(load_info.duplicate_domains_removed if load_info else 0)),
        (
            "input_metadata_preserved",
            str(load_info.input_metadata_preserved).lower() if load_info else "false",
        ),
        ("domains_scanned", str(len(result.domain_results))),
        ("domains_planned", str(result.domains_total or len(result.domains_planned))),
        ("scan_completed", str(result.scan_status == ScanStatus.COMPLETED).lower()),
        ("scan_cancelled", str(result.cancelled).lower()),
        ("partial_results", str(result.partial).lower()),
        ("elapsed_seconds", "" if result.elapsed_seconds is None else f"{result.elapsed_seconds:.1f}"),
        ("selected_wordlist_sources", _wordlist_sources_text(result)),
        ("label_count_by_source", json.dumps(label_counts)),
        ("total_unique_labels", str(plan.total_unique_labels if plan else 0)),
        ("estimated_candidates_per_domain", str(plan.estimated_candidates_per_domain if plan else 0)),
        ("axfr_enabled", str(options.attempt_axfr).lower()),
        ("authoritative_query_enabled", str(options.query_authoritative_ns).lower()),
        ("custom_wordlist_used", str(options.include_custom_wordlist).lower()),
        ("dns_timeout", str(DNS_TIMEOUT)),
        ("dns_lifetime", str(DNS_LIFETIME)),
        ("discovery_limitation", DISCOVERY_LIMITATION),
        ("context_limitation", CONTEXT_LIMITATION),
        ("partial_scan_note", PARTIAL_SCAN_NOTE if result.partial or result.cancelled else ""),
        ("operator_note", OPERATOR_NOTE),
        ("review_path_note", REVIEW_PATH_NOTE),
    ]
    return rows


def _warning_context(domain_result: DomainScanResult | None) -> dict[str, str]:
    if domain_result is None:
        return {"delegated_manager": "", "zone": ""}
    meta = _input_metadata_values(domain_result)
    return {
        "delegated_manager": meta["delegated_manager"],
        "zone": meta["zone"],
    }


def build_errors_warning_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Build domain-level warnings and errors for export."""
    rows: list[dict[str, str]] = []
    scan_timestamp = _format_timestamp(result.scan_timestamp)
    axfr_enabled = result.input.options.attempt_axfr
    plan = result.wordlist_plan

    if result.partial or result.cancelled:
        rows.append(
            {
                "scan_timestamp": scan_timestamp,
                "base_domain": "",
                "delegated_manager": "",
                "zone": "",
                "warning_type": "scan_cancelled",
                "tested_name": "",
                "record_type": "",
                "nameserver": "",
                "message": PARTIAL_SCAN_NOTE,
                "notes": _export_notes(result),
            }
        )

    if plan and plan.estimated_candidates_per_domain > CANDIDATE_STRONG_WARN_THRESHOLD:
        rows.append(
            {
                "scan_timestamp": scan_timestamp,
                "base_domain": "",
                "delegated_manager": "",
                "zone": "",
                "warning_type": "large_candidate_count",
                "tested_name": "",
                "record_type": "",
                "nameserver": "",
                "message": (
                    f"WARNING: estimated {plan.estimated_candidates_per_domain} candidates per domain "
                    "is very large — scan time and noise may increase significantly."
                ),
                "notes": DISCOVERY_LIMITATION,
            }
        )
    elif plan and plan.estimated_candidates_per_domain > CANDIDATE_WARN_THRESHOLD:
        rows.append(
            {
                "scan_timestamp": scan_timestamp,
                "base_domain": "",
                "delegated_manager": "",
                "zone": "",
                "warning_type": "large_candidate_count",
                "tested_name": "",
                "record_type": "",
                "nameserver": "",
                "message": (
                    f"Warning: estimated {plan.estimated_candidates_per_domain} candidates per domain "
                    "may increase scan time and noise."
                ),
                "notes": DISCOVERY_LIMITATION,
            }
        )

    for domain_result in result.domain_results:
        context = _warning_context(domain_result)
        if domain_result.wildcard_suspected:
            rows.append(
                {
                    "scan_timestamp": scan_timestamp,
                    "base_domain": domain_result.domain,
                    **context,
                    "warning_type": "wildcard_suspected",
                    "tested_name": domain_result.domain,
                    "record_type": "",
                    "nameserver": "",
                    "message": "Wildcard suspected using tested methods; some candidate results marked lower confidence.",
                    "notes": DISCOVERY_LIMITATION,
                }
            )

        for record in domain_result.records:
            if record.classification == FindingClassification.AXFR_BLOCKED:
                message = record.value
                warning_type = "axfr_blocked"
                lower = message.lower()
                if "timeout" in lower:
                    warning_type = "axfr_timeout"
                elif "refused" in lower:
                    warning_type = "axfr_refused"
                elif "failed" in lower:
                    warning_type = "axfr_failed"
                rows.append(
                    {
                        "scan_timestamp": scan_timestamp,
                        "base_domain": domain_result.domain,
                        **context,
                        "warning_type": warning_type,
                        "tested_name": domain_result.domain,
                        "record_type": "AXFR",
                        "nameserver": record.nameserver or "",
                        "message": message,
                        "notes": DISCOVERY_LIMITATION,
                    }
                )

            if record.classification == FindingClassification.QUERY_ERROR and record.fqdn == domain_result.domain:
                rows.append(
                    {
                        "scan_timestamp": scan_timestamp,
                        "base_domain": domain_result.domain,
                        **context,
                        "warning_type": "query_error",
                        "tested_name": record.fqdn,
                        "record_type": _record_type_text(record),
                        "nameserver": record.nameserver or "",
                        "message": record.value,
                        "notes": DISCOVERY_LIMITATION,
                    }
                )

            if record.classification == FindingClassification.SCAN_ERROR and record.fqdn == domain_result.domain:
                rows.append(
                    {
                        "scan_timestamp": scan_timestamp,
                        "base_domain": domain_result.domain,
                        **context,
                        "warning_type": "scan_error",
                        "tested_name": record.fqdn,
                        "record_type": "",
                        "nameserver": "",
                        "message": record.value,
                        "notes": SCAN_ERROR_NOTE,
                    }
                )

        for note in domain_result.notes:
            if "unexpected error" in note.lower() or "interrupted" in note.lower():
                if any(
                    row.get("base_domain") == domain_result.domain
                    and row.get("warning_type") == "scan_error"
                    for row in rows
                ):
                    continue
                rows.append(
                    {
                        "scan_timestamp": scan_timestamp,
                        "base_domain": domain_result.domain,
                        **context,
                        "warning_type": "scan_error",
                        "tested_name": domain_result.domain,
                        "record_type": "",
                        "nameserver": "",
                        "message": note,
                        "notes": SCAN_ERROR_NOTE,
                    }
                )

    return rows


def _finding_to_dict(
    record: DiscoveredRecord,
    base_domain: str,
    include_errors: bool,
) -> dict | None:
    if record.classification in {
        FindingClassification.QUERY_ERROR,
        FindingClassification.SCAN_ERROR,
    }:
        if not include_errors or record.fqdn != base_domain:
            return None
        return {
            "tested_name": record.fqdn,
            "record_type": None,
            "finding_type": record.classification.value,
            "confidence": _map_confidence(record.confidence),
            "source": _map_source(record),
            "nameserver": record.nameserver,
            "value": None,
            "ttl": record.ttl,
            "error": record.value,
        }

    return {
        "tested_name": record.fqdn,
        "record_type": _record_type_text(record) or None,
        "finding_type": record.classification.value,
        "confidence": _map_confidence(record.confidence),
        "source": _map_source(record),
        "nameserver": record.nameserver,
        "value": _record_value(record) or record.value,
        "ttl": record.ttl,
        "error": None,
    }


def build_json_document(result: ScanRunResult) -> dict:
    """Build the JSON export document."""
    plan = result.wordlist_plan
    metadata = {
        "scan_timestamp": _format_timestamp(result.scan_timestamp),
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "selected_wordlist_sources": plan.source_counts if plan else {},
        "total_unique_labels": plan.total_unique_labels if plan else 0,
        "estimated_candidates_per_domain": plan.estimated_candidates_per_domain if plan else 0,
        "axfr_enabled": result.input.options.attempt_axfr,
        "authoritative_query_enabled": result.input.options.query_authoritative_ns,
        "scan_completed": result.scan_status == ScanStatus.COMPLETED,
        "scan_cancelled": result.cancelled,
        "partial_results": result.partial,
        "elapsed_seconds": result.elapsed_seconds,
        "discovery_limitation": DISCOVERY_LIMITATION,
        "context_limitation": CONTEXT_LIMITATION,
        "partial_scan_note": PARTIAL_SCAN_NOTE if result.partial or result.cancelled else "",
    }
    if result.input_load_info:
        metadata["input_file_type"] = result.input_load_info.input_file_type
        metadata["metadata_columns_detected"] = result.input_load_info.metadata_columns_detected
        metadata["domains_loaded"] = result.input_load_info.domains_loaded
        metadata["duplicate_domains_removed"] = result.input_load_info.duplicate_domains_removed
        metadata["input_metadata_preserved"] = result.input_load_info.input_metadata_preserved

    domains: list[dict] = []
    axfr_enabled = result.input.options.attempt_axfr

    for domain_result in result.domain_results:
        findings: list[dict] = []
        errors: list[str] = []
        counts = _domain_summary_counts(domain_result)

        if _should_emit_no_records_row(domain_result, counts):
            findings.append(
                {
                    "tested_name": domain_result.domain,
                    "record_type": None,
                    "finding_type": FindingClassification.NO_RECORDS_DISCOVERED.value,
                    "confidence": "unknown",
                    "source": "recursive",
                    "nameserver": None,
                    "value": "No records discovered using tested methods",
                    "ttl": None,
                    "error": None,
                }
            )

        for record in domain_result.records:
            if record.classification in {
                FindingClassification.QUERY_ERROR,
                FindingClassification.SCAN_ERROR,
            }:
                if record.fqdn == domain_result.domain:
                    errors.append(record.value)
                continue
            item = _finding_to_dict(record, domain_result.domain, include_errors=False)
            if item:
                findings.append(item)

        comparison = _compare_known_vs_discovered(domain_result)
        scan_status = _determine_scan_status(domain_result, counts)
        comparison_export = {
            key: value
            for key, value in comparison.items()
            if not key.startswith("_")
        }
        evidence_level = _evidence_support_level(
            domain_result, counts, scan_status, comparison
        )

        domains.append(
            {
                "base_domain": domain_result.domain,
                "input_domain": domain_result.input_record.original_domain if domain_result.input_record else None,
                "delegated_manager": _input_metadata_values(domain_result)["delegated_manager"] or None,
                "zone": _input_metadata_values(domain_result)["zone"] or None,
                "known_vs_dns_comparison": comparison_export,
                "evidence_support_level": evidence_level,
                "recommended_review_action": _recommended_review_action(evidence_level),
                "manual_verification_hint": _manual_verification_hint(
                    domain_result,
                    counts,
                    scan_status,
                    comparison,
                    evidence_level,
                ),
                "analysis_note": _analysis_note(domain_result, counts, scan_status, comparison),
                "wildcard_suspected": domain_result.wildcard_suspected,
                "scan_failed": domain_result.scan_failed,
                "authoritative_nameservers": _authoritative_nameservers(domain_result),
                "axfr_status": _domain_axfr_status(domain_result, axfr_enabled),
                "scan_status": _determine_scan_status(domain_result, counts),
                "findings": findings,
                "summary_counts": counts,
                "errors": errors,
                "notes": domain_result.notes + [DISCOVERY_LIMITATION],
            }
        )

    return {
        "scan_metadata": metadata,
        "domains": domains,
    }


def _write_table_sheet(
    worksheet: Worksheet,
    headers: list[str],
    rows: list[dict[str, str]] | list[tuple[str, str]],
    wrap_columns: set[str] | None = None,
    status_column: str | None = None,
    status_fill_map: dict[str, PatternFill] | None = None,
) -> None:
    wrap_columns = wrap_columns or set()
    header_font = Font(bold=True)
    wrap_alignment = Alignment(wrap_text=True, vertical="top")

    if rows and isinstance(rows[0], tuple):
        worksheet.append(["Setting", "Value"])
        for row in rows:
            worksheet.append(list(row))
        headers = ["Setting", "Value"]
    else:
        worksheet.append(headers)
        for row in rows:
            worksheet.append([row.get(column, "") for column in headers])

    for cell in worksheet[1]:
        cell.font = header_font

    worksheet.freeze_panes = "A2"
    worksheet.auto_filter.ref = worksheet.dimensions

    for index, header in enumerate(headers, start=1):
        column_letter = get_column_letter(index)
        max_length = len(header)
        for row_cells in worksheet.iter_rows(min_row=2, min_col=index, max_col=index):
            for cell in row_cells:
                value = "" if cell.value is None else str(cell.value)
                max_length = max(max_length, min(len(value), 80))
                if header in wrap_columns:
                    cell.alignment = wrap_alignment
        worksheet.column_dimensions[column_letter].width = min(max(max_length + 2, 12), 60)

    if status_column and status_fill_map and status_column in headers:
        status_index = headers.index(status_column) + 1
        for row_index in range(2, worksheet.max_row + 1):
            cell = worksheet.cell(row=row_index, column=status_index)
            fill = status_fill_map.get(str(cell.value))
            if fill:
                for col in range(1, len(headers) + 1):
                    worksheet.cell(row=row_index, column=col).fill = fill


def export_xlsx_report(result: ScanRunResult, output_dir: Path) -> Path:
    """Write the operator-facing XLSX workbook."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{_workbook_report_stem(result.scan_timestamp)}.xlsx"

    workbook = Workbook()
    summary_sheet = workbook.active
    summary_sheet.title = "Summary"

    summary_rows = build_summary_rows(result)
    _write_table_sheet(
        summary_sheet,
        SUMMARY_COLUMNS,
        summary_rows,
        wrap_columns={
            "evidence_summary",
            "analysis_note",
            "limitation_note",
            "manual_verification_hint",
            "authoritative_nameservers",
            "wordlist_sources",
            "known_fourth_level_domains",
            "known_fifth_level_domains",
            "known_child_domains_from_input",
            "dns_discovered_child_names",
            "dns_discovered_child_names_already_known",
            "dns_discovered_child_names_not_in_input",
            "delegated_child_zones_not_in_input",
        },
        status_column="scan_status",
        status_fill_map=SUMMARY_STATUS_FILLS,
    )

    review_sheet = workbook.create_sheet("Evidence Review")
    review_rows = build_evidence_review_rows(result)
    _write_table_sheet(
        review_sheet,
        EVIDENCE_REVIEW_COLUMNS,
        review_rows,
        wrap_columns={
            "known_child_domains_from_input",
            "dns_discovered_child_names_not_in_input",
            "delegated_child_zones_not_in_input",
            "analysis_note",
            "manual_verification_hint",
            "limitation_note",
        },
    )

    findings_sheet = workbook.create_sheet("Findings")
    findings_rows = build_findings_rows(result)
    _write_table_sheet(
        findings_sheet,
        CSV_COLUMNS,
        findings_rows,
        wrap_columns={"value", "notes", "error", "nameserver"},
    )

    settings_sheet = workbook.create_sheet("Scan Settings")
    _write_table_sheet(
        settings_sheet,
        [],
        build_settings_rows(result),
        wrap_columns={"Value"},
    )

    warnings_sheet = workbook.create_sheet("Errors Warnings")
    warning_rows = build_errors_warning_rows(result)
    if not warning_rows:
        warning_rows = [
            {
                "scan_timestamp": _format_timestamp(result.scan_timestamp),
                "base_domain": "",
                "warning_type": "none",
                "tested_name": "",
                "record_type": "",
                "nameserver": "",
                "message": "No domain-level warnings or errors recorded for this scan.",
                "notes": DISCOVERY_LIMITATION,
            }
        ]
    _write_table_sheet(
        warnings_sheet,
        ERRORS_WARNINGS_COLUMNS,
        warning_rows,
        wrap_columns={"message", "notes"},
    )

    workbook.save(path)
    return path


def export_csv(result: ScanRunResult, output_dir: Path) -> tuple[Path, int]:
    """Write findings CSV report and return path plus row count."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{_findings_report_stem(result.scan_timestamp)}.csv"
    rows = build_csv_rows(result)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    return path, len(rows)


def export_summary_csv(result: ScanRunResult, output_dir: Path) -> Path:
    """Write summary CSV report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{_findings_report_stem(result.scan_timestamp)}_summary.csv"
    rows = build_summary_rows(result)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    return path


def export_json(result: ScanRunResult, output_dir: Path) -> Path:
    """Write JSON report and return path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{_findings_report_stem(result.scan_timestamp)}.json"
    document = build_json_document(result)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")

    return path


def export_results(
    result: ScanRunResult,
    output_dir: Path,
    export_format: ExportFormat,
) -> ExportOutcome:
    """Export scan results to XLSX, CSV, JSON, or all formats."""
    findings_rows = build_findings_rows(result)
    outcome = ExportOutcome(
        domain_count=len(result.domain_results),
        row_count=len(findings_rows),
    )

    if export_format in {"xlsx", "all"}:
        outcome.xlsx_path = export_xlsx_report(result, output_dir)

    if export_format in {"csv", "all"}:
        outcome.csv_path, _ = export_csv(result, output_dir)

    if export_format in {"json", "all"}:
        outcome.json_path = export_json(result, output_dir)

    if export_format == "all":
        outcome.summary_csv_path = export_summary_csv(result, output_dir)

    return outcome
