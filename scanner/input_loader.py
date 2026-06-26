"""Domain list input parsing for TXT, simple CSV, and enriched CSV files."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

from scanner.models import DomainInputRecord

DOMAIN_COLUMN_KEYS = frozenset(
    {
        "third level domain",
        "domain",
        "domain name",
    }
)

KNOWN_METADATA_KEYS: dict[str, str] = {
    "third level domain": "third_level_domain",
    "second level domain": "second_level_domain",
    "zone": "zone",
    "companyname": "companyname",
    "company name": "companyname",
    "delegated manager": "delegated_manager",
    "fourth level domains": "fourth_level_domains",
    "fifth level domains": "fifth_level_domains",
    "fourth level count": "fourth_level_count",
    "fifth level count": "fifth_level_count",
}

RECOGNIZED_METADATA_FIELDS = frozenset(KNOWN_METADATA_KEYS.values())


@dataclass
class DomainLoadResult:
    """Outcome of loading a domain input file."""

    domains: list[DomainInputRecord] = field(default_factory=list)
    input_file_type: str = "txt"
    metadata_columns_detected: list[str] = field(default_factory=list)
    domains_loaded: int = 0
    duplicate_domains_removed: int = 0
    input_metadata_preserved: bool = False
    error: str | None = None


def normalize_header(header: str) -> str:
    """Normalize a CSV header for case-insensitive, space/underscore matching."""
    return " ".join(header.strip().lower().replace("_", " ").split())


def _display_name(name: str) -> str:
    return name.strip().lower().rstrip(".")


def _looks_like_domain(value: str) -> bool:
    value = value.strip().lower()
    if not value or value.startswith("#"):
        return False
    return "." in value and " " not in value


def _split_domain_list(value: str) -> list[str]:
    if not value or not str(value).strip():
        return []
    text = str(value).strip()
    parts = re.split(r"[;\n]+", text)
    return [part.strip() for part in parts if part.strip()]


def _parse_count(value: str) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def _build_input_record(
    *,
    domain_value: str,
    row_number: int | None,
    row_values: dict[str, str],
) -> DomainInputRecord | None:
    original_domain = domain_value.strip()
    normalized = _display_name(original_domain)
    if not normalized:
        return None

    metadata: dict[str, str] = {}
    for key, value in row_values.items():
        if value is None:
            continue
        text = str(value).strip()
        if text:
            metadata[key] = text

    delegated_manager = metadata.get("delegated_manager") or metadata.get("companyname") or ""
    fourth_raw = metadata.get("fourth_level_domains", "")
    fifth_raw = metadata.get("fifth_level_domains", "")

    return DomainInputRecord(
        domain=normalized,
        original_domain=original_domain,
        source_row_number=row_number,
        metadata=metadata,
        second_level_domain=metadata.get("second_level_domain", ""),
        zone=metadata.get("zone", ""),
        delegated_manager=delegated_manager,
        known_fourth_level_domains=_split_domain_list(fourth_raw),
        known_fifth_level_domains=_split_domain_list(fifth_raw),
        fourth_level_count=_parse_count(metadata.get("fourth_level_count", "")),
        fifth_level_count=_parse_count(metadata.get("fifth_level_count", "")),
    )


def _dedupe_domains(records: list[DomainInputRecord]) -> tuple[list[DomainInputRecord], int]:
    seen: set[str] = set()
    deduped: list[DomainInputRecord] = []
    removed = 0
    for record in records:
        if record.domain in seen:
            removed += 1
            continue
        seen.add(record.domain)
        deduped.append(record)
    return deduped, removed


def _load_txt(path: Path) -> DomainLoadResult:
    records: list[DomainInputRecord] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        cell = line.strip()
        if not cell or cell.startswith("#"):
            continue
        record = _build_input_record(
            domain_value=cell,
            row_number=line_number,
            row_values={},
        )
        if record:
            records.append(record)

    domains, removed = _dedupe_domains(records)
    return DomainLoadResult(
        domains=domains,
        input_file_type="txt",
        domains_loaded=len(domains),
        duplicate_domains_removed=removed,
        input_metadata_preserved=False,
    )


def _map_headers(raw_headers: list[str]) -> tuple[str | None, dict[str, str], list[str]]:
    """Return domain field name, header->metadata field map, and detected metadata columns."""
    normalized_headers = [normalize_header(header) for header in raw_headers]
    domain_field: str | None = None
    header_map: dict[str, str] = {}
    metadata_detected: list[str] = []

    for raw_header, normalized in zip(raw_headers, normalized_headers, strict=False):
        if normalized in DOMAIN_COLUMN_KEYS and domain_field is None:
            mapped = KNOWN_METADATA_KEYS.get(normalized, "third_level_domain")
            domain_field = mapped
            header_map[raw_header] = mapped
            if mapped in RECOGNIZED_METADATA_FIELDS:
                metadata_detected.append(mapped)
            continue
        mapped = KNOWN_METADATA_KEYS.get(normalized)
        if mapped:
            header_map[raw_header] = mapped
            if mapped not in metadata_detected:
                metadata_detected.append(mapped)

    return domain_field, header_map, metadata_detected


def _first_row_looks_like_header(first_row: list[str]) -> bool:
    if not first_row:
        return False
    normalized = [normalize_header(cell) for cell in first_row]
    if any(cell in DOMAIN_COLUMN_KEYS for cell in normalized):
        return True
    if any(cell in KNOWN_METADATA_KEYS for cell in normalized):
        return True
    return not _looks_like_domain(first_row[0])


def _load_csv(path: Path) -> DomainLoadResult:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = [row for row in reader if any(cell.strip() for cell in row)]

    if not rows:
        return DomainLoadResult(error="No data rows found in CSV input file.")

    if _first_row_looks_like_header(rows[0]):
        raw_headers = rows[0]
        data_rows = rows[1:]
        domain_field, header_map, metadata_detected = _map_headers(raw_headers)
        if not domain_field:
            return DomainLoadResult(
                error=(
                    "Could not find a domain column in CSV headers. "
                    "Expected one of: third_level_domain, domain, domain_name, "
                    "Domain Name, Third Level Domain."
                )
            )

        records: list[DomainInputRecord] = []
        for row_index, row in enumerate(data_rows, start=2):
            if not any(cell.strip() for cell in row):
                continue
            row_values: dict[str, str] = {}
            for column_index, raw_header in enumerate(raw_headers):
                if column_index >= len(row):
                    continue
                mapped = header_map.get(raw_header)
                if not mapped:
                    continue
                row_values[mapped] = row[column_index].strip()

            domain_value = row_values.get(domain_field, "")
            if not domain_value:
                first_cell = row[0].strip() if row else ""
                if domain_field == "third_level_domain" and first_cell:
                    domain_value = first_cell
            record = _build_input_record(
                domain_value=domain_value,
                row_number=row_index,
                row_values=row_values,
            )
            if record:
                records.append(record)

        domains, removed = _dedupe_domains(records)
        return DomainLoadResult(
            domains=domains,
            input_file_type="enriched_csv",
            metadata_columns_detected=metadata_detected,
            domains_loaded=len(domains),
            duplicate_domains_removed=removed,
            input_metadata_preserved=bool(metadata_detected),
        )

    records = []
    for row_index, row in enumerate(rows, start=1):
        if not row:
            continue
        cell = row[0].strip()
        if not cell or cell.startswith("#"):
            continue
        record = _build_input_record(
            domain_value=cell,
            row_number=row_index,
            row_values={},
        )
        if record:
            records.append(record)

    domains, removed = _dedupe_domains(records)
    return DomainLoadResult(
        domains=domains,
        input_file_type="simple_csv",
        domains_loaded=len(domains),
        duplicate_domains_removed=removed,
        input_metadata_preserved=False,
    )


def load_domain_inputs(path: Path) -> DomainLoadResult:
    """Load domain input records from a TXT or CSV file."""
    if path.suffix.lower() == ".txt":
        try:
            return _load_txt(path)
        except OSError as exc:
            return DomainLoadResult(error=f"Failed to read domain file: {exc}")

    if path.suffix.lower() == ".csv":
        try:
            return _load_csv(path)
        except OSError as exc:
            return DomainLoadResult(error=f"Failed to read domain file: {exc}")

    return DomainLoadResult(error=f"Domain file must be .txt or .csv (got {path.suffix})")


def load_domains(path: Path) -> list[str]:
    """Load normalized domain names from a TXT or CSV file."""
    result = load_domain_inputs(path)
    if result.error:
        raise ValueError(result.error)
    return [record.domain for record in result.domains]
