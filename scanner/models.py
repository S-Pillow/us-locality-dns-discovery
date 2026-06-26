"""Data structures for scan inputs and results (future scan engine)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class RecordType(str, Enum):
    """Standard DNS record types the tool may discover."""

    NS = "NS"
    SOA = "SOA"
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    CNAME = "CNAME"
    CAA = "CAA"


@dataclass
class ScanOptions:
    """User-selected scan configuration."""

    use_builtin_wordlist: bool = True
    include_rfc1480_patterns: bool = True
    include_civic_labels: bool = True
    include_dns_common_labels: bool = True
    attempt_axfr: bool = False
    query_authoritative_ns: bool = True
    custom_wordlist_path: Optional[Path] = None


@dataclass
class ScanInput:
    """Validated input for a future scan run."""

    domain_file_path: Path
    options: ScanOptions
    output_dir: Path


@dataclass
class DiscoveredRecord:
    """A single DNS record found through tested discovery methods."""

    fqdn: str
    record_type: RecordType
    value: str
    source_method: str


@dataclass
class DomainScanResult:
    """Discovery results for one 3rd-level locality domain."""

    domain: str
    records: list[DiscoveredRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanRunResult:
    """Aggregate outcome of a scan run."""

    input: ScanInput
    domain_results: list[DomainScanResult] = field(default_factory=list)
    status_messages: list[str] = field(default_factory=list)
