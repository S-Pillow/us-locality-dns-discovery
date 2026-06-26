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
        "domain_name",
    }
)

KNOWN_METADATA_KEYS: dict[str, str] = {
    "third level domain": "third_level_domain",
    "domain": "domain",
    "domain name": "domain",
    "domain_name": "domain",
    "locality label": "locality_label",
    "second level domain": "second_level_domain",
    "zone": "zone",
    "companyname": "companyname",
    "company name": "companyname",
    "delegated manager": "delegated_manager",
    "fourth level domains": "fourth_level_domains",
    "fifth level domains": "fifth_level_domains",
    "known fourth level domains": "known_fourth_level_domains",
    "known fifth level domains": "known_fifth_level_domains",
    "fourth level count": "fourth_level_count",
    "fifth level count": "fifth_level_count",
    "sample reason": "sample_reason",
    "notes": "notes",
}

RECOGNIZED_METADATA_FIELDS = frozenset(KNOWN_METADATA_KEYS.values()) | {
    "third_level_domain",
    "fourth_level_domains",
    "fifth_level_domains",
}

NULL_LIKE_VALUES = frozenset(
    {
        "null",
        "none",
        "n/a",
        "na",
        "*",
        "",
    }
)

KNOWN_CHILD_FIELD_KEYS = (
    "known_fourth_level_domains",
    "known_fifth_level_domains",
    "fourth_level_domains",
    "fifth_level_domains",
)

PREFERRED_ENRICHED_FIELDS = frozenset(
    {
        "domain",
        "delegated_manager",
        "known_fourth_level_domains",
        "known_fifth_level_domains",
        "fourth_level_count",
        "fifth_level_count",
    }
)

RECOMMENDED_INPUT_COLUMNS_CSV = (
    "domain,delegated_manager,known_fourth_level_domains,"
    "known_fifth_level_domains,fourth_level_count,fifth_level_count"
)

PREFERRED_INPUT_FORMAT_NOTE = (
    "Recommended input CSV columns: domain, delegated_manager, "
    "known_fourth_level_domains, known_fifth_level_domains, "
    "fourth_level_count, fifth_level_count. The tool compares known domains "
    "from the input against child DNS names discovered from live DNS. "
    "Extra spreadsheet columns (zone, locality_label, notes, etc.) are not required."
)


@dataclass
class DomainLoadResult:
    """Outcome of loading a domain input file."""

    domains: list[DomainInputRecord] = field(default_factory=list)
    input_file_type: str = "txt"
    metadata_columns_detected: list[str] = field(default_factory=list)
    domains_loaded: int = 0
    duplicate_domains_removed: int = 0
    input_metadata_preserved: bool = False
    selected_domain_column: str = ""
    sample_domains_preview: list[str] = field(default_factory=list)
    input_warnings: list[str] = field(default_factory=list)
    preferred_input_format_detected: bool = False
    error: str | None = None


def detect_preferred_input_format(
    metadata_columns_detected: list[str],
    domain_field: str | None,
) -> bool:
    """Return True when the simplified six-column enriched CSV format is detected."""
    fields = set(metadata_columns_detected)
    if domain_field:
        fields.add(domain_field)
    if "domain" not in fields:
        return False
    return PREFERRED_ENRICHED_FIELDS.issubset(fields)


def normalize_header(header: str) -> str:
    """Normalize a CSV header for case-insensitive, space/underscore matching."""
    return " ".join(header.strip().lower().replace("_", " ").split())


def normalize_domain_name(name: str) -> str:
    """Normalize a domain name for comparison (lowercase, trim, no trailing dot)."""
    return name.strip().lower().rstrip(".")


def is_null_like(value: str) -> bool:
    """Return True when a spreadsheet cell should be ignored as a known domain."""
    return normalize_domain_name(value) in NULL_LIKE_VALUES or not str(value).strip()


def _display_name(name: str) -> str:
    return normalize_domain_name(name)


def _looks_like_domain(value: str) -> bool:
    value = value.strip().lower()
    if not value or value.startswith("#") or is_null_like(value):
        return False
    return "." in value and " " not in value


def _looks_like_us_fqdn(value: str) -> bool:
    normalized = normalize_domain_name(value)
    return _looks_like_domain(normalized) and normalized.endswith(".us")


def _looks_like_label_only(value: str) -> bool:
    normalized = normalize_domain_name(value)
    if not normalized or is_null_like(normalized):
        return False
    return "." not in normalized


def split_domain_list(value: str) -> list[str]:
    """Split a delimited domain list and return normalized unique names."""
    if not value or not str(value).strip():
        return []
    text = str(value).strip()
    parts = re.split(r"[;\n,|]+", text)
    seen: set[str] = set()
    domains: list[str] = []
    for part in parts:
        if is_null_like(part):
            continue
        normalized = normalize_domain_name(part)
        if normalized and normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
    return domains


def known_child_domains_from_record(record: DomainInputRecord | None) -> set[str]:
    """Return normalized known 4th/5th-level domains from input metadata."""
    if record is None:
        return set()
    known: set[str] = set()
    for raw in record.known_fourth_level_domains + record.known_fifth_level_domains:
        if is_null_like(raw):
            continue
        normalized = normalize_domain_name(raw)
        if normalized:
            known.add(normalized)
    return known


def _split_domain_list(value: str) -> list[str]:
    return split_domain_list(value)


def _parse_count(value: str) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _merge_known_child_fields(row_values: dict[str, str]) -> tuple[str, str]:
    fourth_parts: list[str] = []
    fifth_parts: list[str] = []
    for key in ("known_fourth_level_domains", "fourth_level_domains"):
        if row_values.get(key):
            fourth_parts.append(row_values[key])
    for key in ("known_fifth_level_domains", "fifth_level_domains"):
        if row_values.get(key):
            fifth_parts.append(row_values[key])
    fourth_raw = ";".join(fourth_parts)
    fifth_raw = ";".join(fifth_parts)
    return fourth_raw, fifth_raw


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
    if _looks_like_label_only(original_domain):
        return None

    metadata: dict[str, str] = {}
    for key, value in row_values.items():
        if value is None:
            continue
        text = str(value).strip()
        if text and not is_null_like(text):
            metadata[key] = text

    delegated_manager = metadata.get("delegated_manager") or metadata.get("companyname") or ""
    fourth_raw, fifth_raw = _merge_known_child_fields(metadata)

    return DomainInputRecord(
        domain=normalized,
        original_domain=original_domain,
        source_row_number=row_number,
        metadata=metadata,
        second_level_domain=metadata.get("second_level_domain", ""),
        zone=metadata.get("zone", ""),
        delegated_manager=delegated_manager,
        locality_label=metadata.get("locality_label", ""),
        known_fourth_level_domains=_split_domain_list(fourth_raw),
        known_fifth_level_domains=_split_domain_list(fifth_raw),
        fourth_level_count=_parse_count(metadata.get("fourth_level_count", "")),
        fifth_level_count=_parse_count(metadata.get("fifth_level_count", "")),
        sample_reason=metadata.get("sample_reason", ""),
        notes=metadata.get("notes", ""),
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


def _collect_input_warnings(records: list[DomainInputRecord]) -> list[str]:
    warnings: list[str] = []
    if not records:
        return warnings

    non_us = [record.domain for record in records if not record.domain.endswith(".us")]
    if non_us:
        warnings.append(
            f"WARNING: {len(non_us)} domain value(s) do not end in .us "
            f"(examples: {', '.join(non_us[:3])})."
        )

    label_like = [
        record.original_domain
        for record in records
        if _looks_like_label_only(record.original_domain)
    ]
    if label_like:
        warnings.append(
            f"WARNING: skipped {len(label_like)} row(s) with label-like values instead of FQDNs "
            f"(examples: {', '.join(label_like[:3])})."
        )
    return warnings


def _score_domain_column(rows: list[list[str]], column_index: int) -> int:
    score = 0
    for row in rows[:50]:
        if column_index >= len(row):
            continue
        value = row[column_index].strip()
        if _looks_like_us_fqdn(value):
            score += 3
        elif _looks_like_domain(value):
            score += 2
        elif _looks_like_label_only(value):
            score -= 2
    return score


def _select_domain_column(
    raw_headers: list[str],
    data_rows: list[list[str]],
) -> tuple[str | None, dict[str, str], list[str], list[str]]:
    """Pick domain column, map headers, detect metadata, and return warnings."""
    normalized_headers = [normalize_header(header) for header in raw_headers]
    warnings: list[str] = []
    domain_candidates: list[tuple[int, str, str]] = []

    for index, (raw_header, normalized) in enumerate(zip(raw_headers, normalized_headers, strict=False)):
        if normalized in DOMAIN_COLUMN_KEYS:
            mapped = KNOWN_METADATA_KEYS.get(normalized, "domain")
            domain_candidates.append((index, raw_header, mapped))

    duplicate_domain_headers = [raw for _, raw, _ in domain_candidates]
    if len(duplicate_domain_headers) > 1:
        warnings.append(
            "WARNING: duplicate domain-like headers detected: "
            + ", ".join(duplicate_domain_headers)
            + ". The column with the most .us FQDN-like values will be used."
        )

    selected_index: int | None = None
    selected_raw: str | None = None
    selected_mapped: str | None = None
    if domain_candidates:
        best = max(domain_candidates, key=lambda item: _score_domain_column(data_rows, item[0]))
        selected_index, selected_raw, selected_mapped = best

    header_map: dict[str, str] = {}
    metadata_detected: list[str] = []
    for raw_header, normalized in zip(raw_headers, normalized_headers, strict=False):
        mapped = KNOWN_METADATA_KEYS.get(normalized)
        if mapped:
            header_map[raw_header] = mapped
            if mapped in RECOGNIZED_METADATA_FIELDS and mapped not in metadata_detected:
                metadata_detected.append(mapped)

    if selected_mapped and selected_raw:
        header_map[selected_raw] = selected_mapped
        if selected_mapped not in metadata_detected:
            metadata_detected.insert(0, selected_mapped)

    return selected_mapped, header_map, metadata_detected, warnings


def _load_txt(path: Path) -> DomainLoadResult:
    records: list[DomainInputRecord] = []
    skipped_labels: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        cell = line.strip()
        if not cell or cell.startswith("#"):
            continue
        if _looks_like_label_only(cell):
            skipped_labels.append(cell)
            continue
        record = _build_input_record(
            domain_value=cell,
            row_number=line_number,
            row_values={},
        )
        if record:
            records.append(record)

    domains, removed = _dedupe_domains(records)
    warnings = _collect_input_warnings(domains)
    if skipped_labels:
        warnings.append(
            f"WARNING: skipped {len(skipped_labels)} label-like line(s) without a full domain "
            f"(examples: {', '.join(skipped_labels[:3])})."
        )
    return DomainLoadResult(
        domains=domains,
        input_file_type="txt",
        domains_loaded=len(domains),
        duplicate_domains_removed=removed,
        input_metadata_preserved=False,
        selected_domain_column="(line text)",
        sample_domains_preview=[record.domain for record in domains[:5]],
        input_warnings=warnings,
    )


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
        domain_field, header_map, metadata_detected, header_warnings = _select_domain_column(
            raw_headers,
            data_rows,
        )
        if not domain_field:
            return DomainLoadResult(
                error=(
                    "Could not find a domain column in CSV headers. "
                    "Expected one of: domain, third_level_domain, domain_name, Domain Name."
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
                if first_cell and _looks_like_domain(first_cell):
                    domain_value = first_cell
            record = _build_input_record(
                domain_value=domain_value,
                row_number=row_index,
                row_values=row_values,
            )
            if record:
                records.append(record)

        domains, removed = _dedupe_domains(records)
        warnings = header_warnings + _collect_input_warnings(domains)
        selected_column = next(
            (raw for raw, mapped in header_map.items() if mapped == domain_field),
            domain_field,
        )
        preferred = detect_preferred_input_format(metadata_detected, domain_field)
        return DomainLoadResult(
            domains=domains,
            input_file_type="enriched_csv",
            metadata_columns_detected=metadata_detected,
            domains_loaded=len(domains),
            duplicate_domains_removed=removed,
            input_metadata_preserved=bool(metadata_detected),
            selected_domain_column=selected_column,
            sample_domains_preview=[record.domain for record in domains[:5]],
            input_warnings=warnings,
            preferred_input_format_detected=preferred,
        )

    records = []
    for row_index, row in enumerate(rows, start=1):
        if not row:
            continue
        cell = row[0].strip()
        if not cell or cell.startswith("#") or _looks_like_label_only(cell):
            continue
        record = _build_input_record(
            domain_value=cell,
            row_number=row_index,
            row_values={},
        )
        if record:
            records.append(record)

    domains, removed = _dedupe_domains(records)
    warnings = _collect_input_warnings(domains)
    return DomainLoadResult(
        domains=domains,
        input_file_type="simple_csv",
        domains_loaded=len(domains),
        duplicate_domains_removed=removed,
        input_metadata_preserved=False,
        selected_domain_column="(first column)",
        sample_domains_preview=[record.domain for record in domains[:5]],
        input_warnings=warnings,
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
