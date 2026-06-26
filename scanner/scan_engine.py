"""Placeholder scan engine — DNS discovery logic will be added in a future ticket."""

from __future__ import annotations

from pathlib import Path

from scanner.models import ScanInput, ScanRunResult


def validate_domain_file(path: Path) -> tuple[bool, str]:
    """Validate that the domain input file exists and has an accepted extension."""
    if not path.exists():
        return False, f"Domain file not found: {path}"
    if not path.is_file():
        return False, f"Domain path is not a file: {path}"
    if path.suffix.lower() not in {".txt", ".csv"}:
        return False, f"Domain file must be .txt or .csv (got {path.suffix})"
    return True, f"Domain file OK: {path}"


def validate_wordlist_file(path: Path) -> tuple[bool, str]:
    """Validate an optional custom wordlist file."""
    if not path.exists():
        return False, f"Wordlist file not found: {path}"
    if not path.is_file():
        return False, f"Wordlist path is not a file: {path}"
    if path.suffix.lower() not in {".txt", ".csv"}:
        return False, f"Wordlist file must be .txt or .csv (got {path.suffix})"
    return True, f"Custom wordlist OK: {path}"


def run_scan(scan_input: ScanInput) -> ScanRunResult:
    """
    Placeholder scan entry point.

    This ticket does not perform live DNS lookups, AXFR, or external network calls.
    """
    result = ScanRunResult(input=scan_input)
    result.status_messages.append("Scan engine not implemented in this ticket.")
    result.status_messages.append(
        "Future versions will report discovery-based results only; "
        "absence of discovered records is not proof that no records exist."
    )
    return result
