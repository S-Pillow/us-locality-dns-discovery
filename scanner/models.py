"""Data structures for scan inputs and results."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

ProgressCallback = Callable[[str], None]


class ScanStatus(str, Enum):
    """Overall scan run status."""

    COMPLETED = "completed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanProfile(str, Enum):
    """Operator scan profile controlling candidate breadth and defaults."""

    LIGHT = "light_evidence"
    NORMAL = "normal_evidence"
    DEEP = "deep_targeted"


class ScanPhase(str, Enum):
    """Human-readable scan progress phase for the GUI."""

    PREPARING_INPUT = "Preparing input"
    LOADING_WORDLISTS = "Loading wordlists"
    DISCOVERING_AUTH_NS = "Discovering authoritative nameservers"
    CHECKING_BASE = "Checking base SOA/NS"
    ATTEMPTING_AXFR = "Attempting AXFR"
    TESTING_FOURTH_LEVEL = "Testing 4th-level candidate names"
    TESTING_FIFTH_LEVEL = "Testing 5th-level candidate names"
    BUILDING_RESULTS = "Building results"
    COMPLETE = "Complete"
    CANCELLED = "Cancelled"
    ERROR = "Error"


class CancellationToken:
    """Thread-safe scan cancellation flag."""

    def __init__(self) -> None:
        self._cancelled = False
        self._lock = threading.Lock()

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def reset(self) -> None:
        with self._lock:
            self._cancelled = False


@dataclass
class ScanProgressUpdate:
    """Structured scan progress for GUI display."""

    domain_index: int
    domain_total: int
    current_domain: str
    candidates_tested: int
    candidates_total: int
    domains_completed: int
    elapsed_seconds: float
    phase: str = ""
    message: str = ""
    candidates_started: bool = False
    progress_indeterminate: bool = True


ScanProgressCallback = Callable[[ScanProgressUpdate], None]
CancelCheck = Callable[[], bool]


@dataclass
class PreflightSummary:
    """Pre-scan estimate shown to the operator."""

    domain_count: int
    wordlist_sources: dict[str, int]
    total_unique_labels: int
    estimated_candidates_per_domain: int
    estimated_total_candidates: int
    axfr_enabled: bool
    auth_ns_enabled: bool
    warning_level: str
    scan_profile: str = ScanProfile.NORMAL.value
    input_file_type: str = "txt"
    metadata_columns_detected: list[str] = field(default_factory=list)
    duplicate_domains_removed: int = 0
    selected_domain_column: str = ""
    sample_domains_preview: list[str] = field(default_factory=list)
    input_warnings: list[str] = field(default_factory=list)
    preferred_input_format_detected: bool = False


@dataclass
class DomainInputRecord:
    """One domain from an input file, with optional spreadsheet metadata."""

    domain: str
    original_domain: str
    source_row_number: int | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    second_level_domain: str = ""
    zone: str = ""
    delegated_manager: str = ""
    locality_label: str = ""
    known_fourth_level_domains: list[str] = field(default_factory=list)
    known_fifth_level_domains: list[str] = field(default_factory=list)
    fourth_level_count: str = ""
    fifth_level_count: str = ""
    sample_reason: str = ""
    notes: str = ""


@dataclass
class DomainLoadInfo:
    """Metadata about how the domain input file was parsed."""

    input_file_type: str = "txt"
    metadata_columns_detected: list[str] = field(default_factory=list)
    domains_loaded: int = 0
    duplicate_domains_removed: int = 0
    input_metadata_preserved: bool = False
    selected_domain_column: str = ""
    sample_domains_preview: list[str] = field(default_factory=list)
    input_warnings: list[str] = field(default_factory=list)
    preferred_input_format_detected: bool = False


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


class EvidenceStatus(str, Enum):
    """Structured evidence outcome for tested names and DNS findings.

    Confirmed statuses require an approved evidence path.  Diagnostic statuses
    (skipped, inconclusive, ignored, candidate-only) must not be treated as
    discovered domains in reports.
    """

    CANDIDATE_TESTED = "CANDIDATE_TESTED"
    CONFIRMED_ORDINARY_DNS_NAME = "CONFIRMED_ORDINARY_DNS_NAME"
    CONFIRMED_DELEGATED_CHILD_ZONE = "CONFIRMED_DELEGATED_CHILD_ZONE"
    KNOWN_DOMAIN_VALIDATED = "KNOWN_DOMAIN_VALIDATED"
    SKIPPED_BY_PARENT_GATING = "SKIPPED_BY_PARENT_GATING"
    INCONCLUSIVE_DNS_FAILURE = "INCONCLUSIVE_DNS_FAILURE"
    IGNORED_UNRELATED_AUTHORITY = "IGNORED_UNRELATED_AUTHORITY"
    NOT_RECORDED = "NOT_RECORDED"
    # Wildcard attestation outcomes (R4a)
    SUPPRESSED_WILDCARD_MATCH = "SUPPRESSED_WILDCARD_MATCH"
    """Candidate response matches the parent's wildcard signature; suppressed to diagnostic."""
    WITHHELD_WILDCARD_INCONCLUSIVE = "WITHHELD_WILDCARD_INCONCLUSIVE"
    """Wildcard attestation at parent was inconclusive; promotion withheld in Light mode."""


@dataclass
class EvidenceTrace:
    """Structured raw DNS evidence explaining a finding or diagnostic outcome."""

    qname: str
    normalized_qname: str
    qtype: str
    rcode: str | None = None
    section: str | None = None
    rr_owner: str | None = None
    normalized_rr_owner: str | None = None
    rr_type: str | None = None
    rr_value: str | None = None
    resolver_or_server: str | None = None
    authoritative_flag: bool | None = None
    source_path: str = "unknown"
    response_class: str | None = None
    evidence_status: str | None = None
    finding_type: str | None = None
    promotion_reason: str | None = None
    rejection_reason: str | None = None


@dataclass
class EvidenceOutcome:
    """Non-finding or diagnostic evidence status for a tested name."""

    fqdn: str
    evidence_status: EvidenceStatus
    source_method: str
    detail: str = ""
    evidence_trace: list[EvidenceTrace] = field(default_factory=list)
    # Per-parent wildcard attestation status attached at testing time (R4a).
    attestation_status: str | None = None
    # §8 match-detail fields — populated at suppression time for
    # SUPPRESSED_WILDCARD_MATCH outcomes only (R4c).
    matched_rrtype: str | None = None
    """Comma-separated RR type(s) whose values matched the wildcard signature."""
    matched_values: list[str] | None = None
    """Normalized rdata values that matched the wildcard signature."""


class ParentGatingConfidence(str, Enum):
    """How confidently a parent-gating decision was reached."""

    CONFIDENT_NEGATIVE = "confident_negative"
    VALIDATED_PARENT = "validated_parent"
    KNOWN_PARENT = "known_parent"
    HEURISTIC_SKIP = "heuristic_skip"
    INCONCLUSIVE = "inconclusive"
    IGNORED_AUTHORITY = "ignored_authority"


@dataclass
class ParentGatingDecision:
    """Structured outcome for fifth-level parent gating."""

    allow_descendants: bool
    parent_name: str
    reason: str
    evidence_status: EvidenceStatus | None
    response_class: str | None
    confidence: ParentGatingConfidence
    diagnostic_message: str
    evidence_trace: list[EvidenceTrace] = field(default_factory=list)


class FindingClassification(str, Enum):
    """How a discovery finding should be interpreted in reports."""

    BASE_DOMAIN_RECORD = "base_domain_record"
    BASE_ZONE_EXISTS = "base_zone_exists"
    ZONE_SOA_DISCOVERED = "zone_soa_discovered"
    AUTHORITATIVE_NS = "authoritative_ns"
    DELEGATED_CHILD_ZONE = "delegated_child_zone"
    STANDARD_RECORD = "standard_record"
    AXFR_SUCCESS = "axfr_success"
    AXFR_BLOCKED = "axfr_blocked"
    QUERY_ERROR = "query_error"
    SCAN_ERROR = "scan_error"
    NO_RECORDS_DISCOVERED = "no_records_discovered"


@dataclass
class ScanOptions:
    """User-selected scan configuration."""

    scan_profile: ScanProfile = ScanProfile.LIGHT
    include_light_evidence: bool = False
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
    known_fifth_level_candidates: int = 0
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
    ttl: Optional[int] = None
    evidence_status: EvidenceStatus | None = None
    evidence_trace: list[EvidenceTrace] = field(default_factory=list)
    # Per-parent wildcard attestation fields (R4a).  R4b surfaces these in exports.
    attestation_status: str | None = None
    wildcard_signature_matched: bool | None = None
    """False when the candidate differentiated from the wildcard; None when no
    wildcard was detected or the field has not been evaluated."""
    wildcard_differentiation_reason: str | None = None
    """Named differentiation reason (distinct_rrtype | distinct_answer |
    distinct_cname_target | candidate_ns_soa | verified_delegation) when the
    candidate promoted despite a DETECTED wildcard at its enumeration parent."""


@dataclass
class DomainScanResult:
    """Discovery results for one base domain."""

    domain: str
    records: list[DiscoveredRecord] = field(default_factory=list)
    evidence_outcomes: list[EvidenceOutcome] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    wildcard_suspected: bool = False
    candidates_tested: int = 0
    fourth_level_candidates_tested: int = 0
    fifth_level_candidates_tested: int = 0
    scan_failed: bool = False
    input_record: DomainInputRecord | None = None


@dataclass
class ScanRunResult:
    """Aggregate outcome of a scan run."""

    input: ScanInput
    domain_results: list[DomainScanResult] = field(default_factory=list)
    status_messages: list[str] = field(default_factory=list)
    wordlist_plan: Optional[WordlistPlan] = None
    scan_timestamp: Optional[datetime] = None
    scan_status: ScanStatus = ScanStatus.COMPLETED
    partial: bool = False
    cancelled: bool = False
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    elapsed_seconds: Optional[float] = None
    domains_total: int = 0
    domains_planned: list[str] = field(default_factory=list)
    domain_inputs: list[DomainInputRecord] = field(default_factory=list)
    input_load_info: DomainLoadInfo | None = None
