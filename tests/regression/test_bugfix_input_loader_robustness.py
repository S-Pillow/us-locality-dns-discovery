"""AIPF Ticket 2 bug-fix regression: input loader must not crash on unreadable files.

Defect: load_domain_inputs() only caught OSError, so a non-UTF-8 file
(UnicodeDecodeError) or a CSV containing a NUL byte (csv.Error) raised an
uncaught exception that would crash the GUI scan/preflight thread instead of
returning a DomainLoadResult(error=...).  AIPF 15.3 requires a graceful
recovery path for bad input files.
"""
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.input_loader import load_domain_inputs


def _tmp(name: str, data: bytes) -> Path:
    p = Path(tempfile.mkdtemp()) / name
    p.write_bytes(data)
    return p


def test_bad_utf8_csv_returns_error_not_exception():
    p = _tmp("bad_encoding.csv", b"domain\nstate.wv.us\n\xff\xfe garbage \x80\x81\n")
    result = load_domain_inputs(p)  # must not raise
    assert result.error, "expected a graceful error message, got none"
    assert not result.domains


def test_nul_byte_csv_does_not_crash_or_leak():
    # Platform note: Python's csv module raises "line contains NUL" on some
    # platforms (Linux) but tolerates NUL bytes on others (Windows).  The
    # cross-platform contract is: load_domain_inputs must never raise, and a
    # corrupt NUL line must never leak into the parsed domains.
    p = _tmp("nul.csv", b"domain\nstate.wv.us\n\x00\x00\n")
    result = load_domain_inputs(p)  # must not raise
    domains = [r.domain for r in result.domains]
    assert "\x00" not in "".join(domains), "NUL bytes leaked into a parsed domain"
    if result.error is None:
        # Tolerated path: the good row still loads, the junk line is dropped.
        assert domains == ["state.wv.us"]
    else:
        # Raised-and-caught path: a graceful error is surfaced instead.
        assert "NUL" in result.error or "corrupt" in result.error.lower()


def test_bad_utf8_txt_returns_error_not_exception():
    p = _tmp("bad.txt", b"state.wv.us\n\xff\xfe\x80\n")
    result = load_domain_inputs(p)  # must not raise
    assert result.error, "expected a graceful error message, got none"


def test_valid_csv_still_loads():
    p = _tmp("good.csv", b"domain\nstate.wv.us\nauburn.in.us\n")
    result = load_domain_inputs(p)
    assert result.error is None
    assert [r.domain for r in result.domains] == ["state.wv.us", "auburn.in.us"]


if __name__ == "__main__":
    test_bad_utf8_csv_returns_error_not_exception()
    test_nul_byte_csv_does_not_crash_or_leak()
    test_bad_utf8_txt_returns_error_not_exception()
    test_valid_csv_still_loads()
    print("ALL PASS")
