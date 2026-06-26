"""CSV and JSON export for DNS discovery scan results."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from scanner.models import (
    DiscoveredRecord,
    DomainScanResult,
    FindingClassification,
    ScanRunResult,
)

APP_NAME = ".US Locality DNS Discovery Tool"
APP_VERSION = None

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

ExportFormat = Literal["csv", "json", "both"]


@dataclass
class ExportOutcome:
    """Result of an export operation."""

    csv_path: Path | None = None
    json_path: Path | None = None
    row_count: int = 0
    domain_count: int = 0


def _format_timestamp(value: datetime | None) -> str:
    if value is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _report_stem(scan_timestamp: datetime | None) -> str:
    stamp = scan_timestamp or datetime.now()
    return f"us_locality_dns_discovery_{stamp.strftime('%Y%m%d_%H%M%S')}"


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


def _domain_axfr_status(domain_result: DomainScanResult, axfr_enabled: bool) -> str:
    if not axfr_enabled:
        return "not_attempted"

    successes = [
        record
        for record in domain_result.records
        if record.classification == FindingClassification.AXFR_SUCCESS
    ]
    if successes:
        return "success"

    blocked = [
        record
        for record in domain_result.records
        if record.classification == FindingClassification.AXFR_BLOCKED
    ]
    if not blocked:
        return "not_attempted"

    message = " ".join(record.value.lower() for record in blocked)
    if "timeout" in message:
        return "timeout"
    if "refused" in message:
        return "refused"
    if "blocked" in message or "transfererror" in message:
        return "blocked"
    return "failed"


def _authoritative_nameservers(domain_result: DomainScanResult) -> list[str]:
    names: list[str] = []
    for record in domain_result.records:
        if record.classification == FindingClassification.AUTHORITATIVE_NS and record.record_type:
            names.append(record.value.rstrip("."))
    return list(dict.fromkeys(names))


def _include_record_in_csv(record: DiscoveredRecord, base_domain: str) -> bool:
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
            if not _include_record_in_csv(record, domain_result.domain):
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


def export_csv(result: ScanRunResult, output_dir: Path) -> tuple[Path, int]:
    """Write CSV report and return path plus row count."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = _report_stem(result.scan_timestamp)
    path = output_dir / f"{stem}.csv"
    rows = build_csv_rows(result)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    return path, len(rows)


def export_json(result: ScanRunResult, output_dir: Path) -> Path:
    """Write JSON report and return path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = _report_stem(result.scan_timestamp)
    path = output_dir / f"{stem}.json"
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
    """Export scan results to CSV, JSON, or both."""
    rows = build_csv_rows(result)
    outcome = ExportOutcome(
        domain_count=len(result.domain_results),
        row_count=len(rows),
    )

    if export_format in {"csv", "both"}:
        outcome.csv_path, _ = export_csv(result, output_dir)

    if export_format in {"json", "both"}:
        outcome.json_path = export_json(result, output_dir)

    return outcome
