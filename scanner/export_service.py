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

from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    FindingClassification,
    ScanRunResult,
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

DISCOVERY_LIMITATION = (
    "DNS discovery results show only records found through the tested methods. "
    "No records discovered does not prove that no subdelegations or DNS records exist."
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
    "scan_status",
    "authoritative_nameservers",
    "axfr_status",
    "wildcard_suspected",
    "base_records_found",
    "possible_subdelegations_found",
    "standard_records_found",
    "candidate_names_tested",
    "wordlist_sources",
    "evidence_summary",
    "limitation_note",
]

ERRORS_WARNINGS_COLUMNS = [
    "scan_timestamp",
    "base_domain",
    "warning_type",
    "tested_name",
    "record_type",
    "nameserver",
    "message",
    "notes",
]

SCAN_STATUS_AXFR = "AXFR allowed"
SCAN_STATUS_SUBDELEGATION = "Possible subdelegation discovered"
SCAN_STATUS_DNS_ACTIVITY = "DNS activity discovered"
SCAN_STATUS_BASE_ONLY = "Base domain records only"
SCAN_STATUS_NO_RECORDS = "No records discovered using tested methods"
SCAN_STATUS_ERRORS_ONLY = "Scan errors only"

SUMMARY_STATUS_FILLS = {
    SCAN_STATUS_AXFR: PatternFill(fill_type="solid", fgColor="C6EFCE"),
    SCAN_STATUS_SUBDELEGATION: PatternFill(fill_type="solid", fgColor="BDD7EE"),
    SCAN_STATUS_DNS_ACTIVITY: PatternFill(fill_type="solid", fgColor="FFE699"),
    SCAN_STATUS_BASE_ONLY: PatternFill(fill_type="solid", fgColor="EDEDED"),
    SCAN_STATUS_NO_RECORDS: PatternFill(fill_type="solid", fgColor="F8CBAD"),
    SCAN_STATUS_ERRORS_ONLY: PatternFill(fill_type="solid", fgColor="FFC7CE"),
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


def _domain_summary_counts(domain_result: DomainScanResult) -> dict[str, int]:
    counts = {
        "total_findings": 0,
        "base_domain_records": 0,
        "authoritative_ns": 0,
        "possible_subdelegations": 0,
        "standard_records": 0,
        "axfr_success": 0,
        "axfr_blocked": 0,
        "query_errors": 0,
        "candidates_tested": domain_result.candidates_tested,
    }
    for record in domain_result.records:
        counts["total_findings"] += 1
        key_map = {
            FindingClassification.BASE_DOMAIN_RECORD: "base_domain_records",
            FindingClassification.AUTHORITATIVE_NS: "authoritative_ns",
            FindingClassification.POSSIBLE_SUBDELEGATION: "possible_subdelegations",
            FindingClassification.STANDARD_RECORD: "standard_records",
            FindingClassification.AXFR_SUCCESS: "axfr_success",
            FindingClassification.AXFR_BLOCKED: "axfr_blocked",
            FindingClassification.QUERY_ERROR: "query_errors",
        }
        bucket = key_map.get(record.classification)
        if bucket:
            counts[bucket] += 1
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
    return list(dict.fromkeys(names))


def _include_record_in_export(record: DiscoveredRecord, base_domain: str) -> bool:
    if record.classification == FindingClassification.QUERY_ERROR:
        return record.fqdn == base_domain
    return True


def _record_type_text(record: DiscoveredRecord) -> str:
    if record.classification == FindingClassification.AXFR_SUCCESS and record.record_type is None:
        return "AXFR"
    if record.record_type is None:
        return ""
    return record.record_type.value


def _record_error(record: DiscoveredRecord) -> str:
    if record.classification == FindingClassification.QUERY_ERROR:
        return record.value
    return ""


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
        }:
            return True
    return False


def _determine_scan_status(domain_result: DomainScanResult, counts: dict[str, int]) -> str:
    if counts["axfr_success"] > 0:
        return SCAN_STATUS_AXFR
    if counts["possible_subdelegations"] > 0:
        return SCAN_STATUS_SUBDELEGATION
    if counts["standard_records"] > 0:
        return SCAN_STATUS_DNS_ACTIVITY
    if counts["base_domain_records"] > 0 or counts["authoritative_ns"] > 0:
        return SCAN_STATUS_BASE_ONLY
    if counts["query_errors"] > 0 and counts["total_findings"] == counts["query_errors"]:
        return SCAN_STATUS_ERRORS_ONLY
    return SCAN_STATUS_NO_RECORDS


def _evidence_summary(domain_result: DomainScanResult, counts: dict[str, int]) -> str:
    parts: list[str] = []

    if counts["axfr_success"] > 0:
        parts.append(f"AXFR succeeded with {counts['axfr_success']} record(s) discovered using tested methods")

    subdelegations = [
        record.fqdn
        for record in domain_result.records
        if record.classification == FindingClassification.POSSIBLE_SUBDELEGATION
    ]
    if subdelegations:
        unique = list(dict.fromkeys(subdelegations))[:5]
        suffix = "..." if len(subdelegations) > 5 else ""
        parts.append(f"Possible subdelegation at {', '.join(unique)}{suffix}")

    standard = [
        record
        for record in domain_result.records
        if record.classification == FindingClassification.STANDARD_RECORD
    ]
    if standard:
        examples = list(dict.fromkeys(f"{item.fqdn} {item.record_type.value if item.record_type else ''}".strip() for item in standard))[:3]
        parts.append(f"Candidate DNS activity: {', '.join(examples)}")

    base_records = [
        record
        for record in domain_result.records
        if record.classification == FindingClassification.BASE_DOMAIN_RECORD and record.fqdn == domain_result.domain
    ]
    if base_records:
        examples = list(dict.fromkeys(
            f"{item.record_type.value if item.record_type else 'record'}={item.value[:60]}"
            for item in base_records
        ))[:4]
        parts.append(f"Base domain records: {', '.join(examples)}")

    if domain_result.notes:
        parts.extend(note for note in domain_result.notes if "No records discovered" in note)

    if not parts:
        return "No records discovered using tested methods"
    return "; ".join(parts)


def build_findings_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Flatten scan results into findings row dictionaries."""
    return build_csv_rows(result)


def build_csv_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Flatten scan results into CSV row dictionaries."""
    rows: list[dict[str, str]] = []
    scan_timestamp = _format_timestamp(result.scan_timestamp)
    wordlist_sources = _wordlist_sources_text(result)
    axfr_enabled = result.input.options.attempt_axfr
    notes = DISCOVERY_LIMITATION

    for domain_result in result.domain_results:
        axfr_status = _domain_axfr_status(domain_result, axfr_enabled)
        wildcard = "true" if domain_result.wildcard_suspected else "false"

        if not _base_has_discovered_records(domain_result):
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
                    "notes": notes,
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
        rows.append(
            {
                "scan_timestamp": scan_timestamp,
                "base_domain": domain_result.domain,
                "scan_status": _determine_scan_status(domain_result, counts),
                "authoritative_nameservers": "; ".join(_authoritative_nameservers(domain_result)),
                "axfr_status": _domain_axfr_status(domain_result, axfr_enabled),
                "wildcard_suspected": "true" if domain_result.wildcard_suspected else "false",
                "base_records_found": str(counts["base_domain_records"] + counts["authoritative_ns"]),
                "possible_subdelegations_found": str(counts["possible_subdelegations"]),
                "standard_records_found": str(counts["standard_records"]),
                "candidate_names_tested": str(counts["candidates_tested"]),
                "wordlist_sources": wordlist_sources,
                "evidence_summary": _evidence_summary(domain_result, counts),
                "limitation_note": DISCOVERY_LIMITATION,
            }
        )

    return rows


def build_settings_rows(result: ScanRunResult) -> list[tuple[str, str]]:
    """Build key/value rows for the Scan Settings sheet."""
    plan = result.wordlist_plan
    options = result.input.options
    label_counts = plan.source_counts if plan else {}

    rows: list[tuple[str, str]] = [
        ("app_name", APP_NAME),
        ("scan_timestamp", _format_timestamp(result.scan_timestamp)),
        ("domains_scanned", str(len(result.domain_results))),
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
        ("operator_note", OPERATOR_NOTE),
    ]
    return rows


def build_errors_warning_rows(result: ScanRunResult) -> list[dict[str, str]]:
    """Build domain-level warnings and errors for export."""
    rows: list[dict[str, str]] = []
    scan_timestamp = _format_timestamp(result.scan_timestamp)
    axfr_enabled = result.input.options.attempt_axfr
    plan = result.wordlist_plan

    if plan and plan.estimated_candidates_per_domain > CANDIDATE_STRONG_WARN_THRESHOLD:
        rows.append(
            {
                "scan_timestamp": scan_timestamp,
                "base_domain": "",
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
        if domain_result.wildcard_suspected:
            rows.append(
                {
                    "scan_timestamp": scan_timestamp,
                    "base_domain": domain_result.domain,
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
                        "warning_type": "query_error",
                        "tested_name": record.fqdn,
                        "record_type": _record_type_text(record),
                        "nameserver": record.nameserver or "",
                        "message": record.value,
                        "notes": DISCOVERY_LIMITATION,
                    }
                )

        for note in domain_result.notes:
            if "unexpected error" in note.lower() or "interrupted" in note.lower():
                rows.append(
                    {
                        "scan_timestamp": scan_timestamp,
                        "base_domain": domain_result.domain,
                        "warning_type": "scan_error",
                        "tested_name": domain_result.domain,
                        "record_type": "",
                        "nameserver": "",
                        "message": note,
                        "notes": DISCOVERY_LIMITATION,
                    }
                )

    return rows


def _finding_to_dict(
    record: DiscoveredRecord,
    base_domain: str,
    include_errors: bool,
) -> dict | None:
    if record.classification == FindingClassification.QUERY_ERROR:
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
        "discovery_limitation": DISCOVERY_LIMITATION,
    }

    domains: list[dict] = []
    axfr_enabled = result.input.options.attempt_axfr

    for domain_result in result.domain_results:
        findings: list[dict] = []
        errors: list[str] = []

        if not _base_has_discovered_records(domain_result):
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
            if record.classification == FindingClassification.QUERY_ERROR:
                if record.fqdn == domain_result.domain:
                    errors.append(record.value)
                continue
            item = _finding_to_dict(record, domain_result.domain, include_errors=False)
            if item:
                findings.append(item)

        domains.append(
            {
                "base_domain": domain_result.domain,
                "wildcard_suspected": domain_result.wildcard_suspected,
                "authoritative_nameservers": _authoritative_nameservers(domain_result),
                "axfr_status": _domain_axfr_status(domain_result, axfr_enabled),
                "findings": findings,
                "summary_counts": _domain_summary_counts(domain_result),
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
        wrap_columns={"evidence_summary", "limitation_note", "authoritative_nameservers", "wordlist_sources"},
        status_column="scan_status",
        status_fill_map=SUMMARY_STATUS_FILLS,
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
