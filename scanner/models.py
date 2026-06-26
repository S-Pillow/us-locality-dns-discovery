"""Data structures for scan inputs and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

ProgressCallback = Callable[[str], None]


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


class FindingClassification(str, Enum):
    """How a discovery finding should be interpreted in reports."""

    BASE_DOMAIN_RECORD = "base_domain_record"
    AUTHORITATIVE_NS = "authoritative_ns"
    POSSIBLE_SUBDELEGATION = "possible_subdelegation"
    STANDARD_RECORD = "standard_record"
    AXFR_SUCCESS = "axfr_success"
    AXFR_BLOCKED = "axfr_blocked"
    QUERY_ERROR = "query_error"
    NO_RECORDS_DISCOVERED = "no_records_discovered"


@dataclass
class ScanOptions:
    """User-selected scan configuration."""

    include_rfc_locality_baseline: bool = True
    include_dns_common: bool = True
    include_civic_departments: bool = True
    include_public_services: bool = False
    include_schools_libraries: bool = False
    include_delegated_manager_clues: bool = False
    include_custom_wordlist: bool = False
    custom_wordlist_path: Optional[Path] = None
    attempt_axfr: bool = False
    query_authoritative_ns: bool = True


@dataclass
class WordlistPlan:
    """Resolved wordlist selections used for a scan run."""

    source_counts: dict[str, int] = field(default_factory=dict)
    total_unique_labels: int = 0
    estimated_candidates_per_domain: int = 0
    fifth_level_enabled: bool = False
    fifth_level_prefix_count: int = 0
    unique_labels: list[str] = field(default_factory=list)
    fifth_level_prefix_labels: list[str] = field(default_factory=list)


@dataclass
class ScanInput:
    """Validated input for a scan run."""

    domain_file_path: Path
    options: ScanOptions
    output_dir: Path
    wordlists_dir: Path


@dataclass
class DiscoveredRecord:
    """A single DNS record or discovery finding from tested methods."""

    fqdn: str
    record_type: Optional[RecordType]
    value: str
    source_method: str
    classification: FindingClassification
    confidence: str = "normal"
    nameserver: Optional[str] = None


@dataclass
class DomainScanResult:
    """Discovery results for one base domain."""

    domain: str
    records: list[DiscoveredRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    wildcard_suspected: bool = False
    candidates_tested: int = 0


@dataclass
class ScanRunResult:
    """Aggregate outcome of a scan run."""

    input: ScanInput
    domain_results: list[DomainScanResult] = field(default_factory=list)
    status_messages: list[str] = field(default_factory=list)
    wordlist_plan: Optional[WordlistPlan] = None
