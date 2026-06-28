"""AIPF Ticket T31 — Registry-Known Input Completeness & DNS/Portal Comparison.

Negative-action tests (durable):
  NA-1  Registry-known + DNS-not-live → dns_not_confirmed, not counted as gap.
  NA-2  Lane-2 guessed name → never tagged registry_known_validation source.
  NA-3  Registry-present + DNS-live + portal-present → VALIDATION_ONLY, NOT STRONG_GAP.
  NA-4  Report wording factual; does not assert concealment.
  NA-5  No registry_known_names in input → registry_matrix empty.
  NA-6  Portal-present but DNS not live → REGISTRY_PORTAL_MATCH, not gap.

Acceptance-criteria tests:
  AC-1  Registry-known names ingest as first-class input, distinct from portal/system-known.
  AC-2  Each registry-known name gets a live DNS validation result (dns_confirmed / dns_not_confirmed).
  AC-3  Each name is compared to portal/system-known input columns (portal_present / portal_missing).
  AC-4  Evidence matrix is built per domain with correct cell classification.
  AC-5  STRONG_GAP: registry-known + DNS-live + portal-missing correctly classified.
  AC-6  Guessed (Lane 2) names never tagged registry_known_validation.
  AC-7  Evidence-honest wording (factual, not asserting concealment).
  AC-8  MatrixCell enum covers all four cells in the ticket's matrix.
  AC-9  input_loader parses registry_known_names from CSV column.
  AC-10 Existing scan results reused without re-querying for registry-known names.
"""

from __future__ import annotations

import io
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.models import (
    DomainInputRecord,
    DomainScanResult,
    FindingClassification,
    MatrixCell,
    PortalStatus,
    RegistryDNSStatus,
    RegistryKnownEntry,
    ScanOptions,
    ScanProfile,
)
from scanner.scan_engine import (
    REGISTRY_KNOWN_VALIDATION_SOURCE,
    _portal_known_names,
    _validate_registry_known_names,
)
from scanner.input_loader import _build_input_record, split_domain_list
from scanner.export_service import (
    REGISTRY_MATRIX_COLUMNS,
    build_registry_matrix_rows,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_input(
    domain: str,
    registry: list[str] | None = None,
    portal_4th: list[str] | None = None,
    portal_5th: list[str] | None = None,
) -> DomainInputRecord:
    return DomainInputRecord(
        domain=domain,
        original_domain=domain,
        registry_known_names=registry or [],
        known_fourth_level_domains=portal_4th or [],
        known_fifth_level_domains=portal_5th or [],
    )


def _empty_result(domain: str = "k12.pa.us", input_record=None) -> DomainScanResult:
    return DomainScanResult(domain=domain, input_record=input_record)


# ---------------------------------------------------------------------------
# AC-1 / AC-9: Input loader parses registry_known_names
# ---------------------------------------------------------------------------


class TestInputLoaderParsesRegistryKnownNames(unittest.TestCase):
    """AC-1, AC-9 — registry_known_names ingests as first-class, distinct from portal."""

    def test_ac1_registry_parsed_from_csv_row(self):
        record = _build_input_record(
            domain_value="k12.pa.us",
            row_number=2,
            row_values={
                "registry_known_names": "pvt.k12.pa.us;fcs.pvt.k12.pa.us",
                "known_fourth_level_domains": "co.butler.pa.us",
            },
        )
        self.assertIsNotNone(record)
        self.assertIn("pvt.k12.pa.us", record.registry_known_names)
        self.assertIn("fcs.pvt.k12.pa.us", record.registry_known_names)

    def test_ac1_registry_distinct_from_portal(self):
        record = _build_input_record(
            domain_value="k12.pa.us",
            row_number=2,
            row_values={
                "registry_known_names": "pvt.k12.pa.us",
                "known_fourth_level_domains": "ci.k12.pa.us",
            },
        )
        self.assertIsNotNone(record)
        # Registry-known must not bleed into portal columns and vice versa.
        self.assertIn("pvt.k12.pa.us", record.registry_known_names)
        self.assertNotIn("pvt.k12.pa.us", record.known_fourth_level_domains)
        self.assertIn("ci.k12.pa.us", record.known_fourth_level_domains)
        self.assertNotIn("ci.k12.pa.us", record.registry_known_names)

    def test_ac1_empty_registry_when_not_provided(self):
        record = _build_input_record(
            domain_value="k12.pa.us",
            row_number=2,
            row_values={"known_fourth_level_domains": "co.k12.pa.us"},
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.registry_known_names, [])

    def test_ac9_semicolon_delimited_registry_names(self):
        record = _build_input_record(
            domain_value="k12.pa.us",
            row_number=2,
            row_values={
                "registry_known_names": "pvt.k12.pa.us;tec.k12.pa.us;fcs.pvt.k12.pa.us"
            },
        )
        self.assertIsNotNone(record)
        self.assertEqual(len(record.registry_known_names), 3)

    def test_ac1_default_registry_known_names_empty(self):
        record = DomainInputRecord(domain="k12.pa.us", original_domain="k12.pa.us")
        self.assertEqual(record.registry_known_names, [])


# ---------------------------------------------------------------------------
# AC-8: MatrixCell enum covers all four cells
# ---------------------------------------------------------------------------


class TestMatrixCellEnum(unittest.TestCase):
    """AC-8 — MatrixCell must cover exactly the four cells in the ticket matrix."""

    def test_ac8_all_four_cells_present(self):
        expected = {
            MatrixCell.STRONG_GAP,
            MatrixCell.VALIDATION_ONLY,
            MatrixCell.REGISTRY_ONLY,
            MatrixCell.REGISTRY_PORTAL_MATCH,
        }
        self.assertEqual(set(MatrixCell), expected)

    def test_ac8_strong_gap_value(self):
        self.assertEqual(MatrixCell.STRONG_GAP.value, "strong_gap")

    def test_ac8_validation_only_value(self):
        self.assertEqual(MatrixCell.VALIDATION_ONLY.value, "validation_only")


# ---------------------------------------------------------------------------
# _portal_known_names helper
# ---------------------------------------------------------------------------


class TestPortalKnownNames(unittest.TestCase):
    def test_portal_includes_fourth_and_fifth(self):
        rec = _make_input(
            "k12.pa.us",
            portal_4th=["pvt.k12.pa.us"],
            portal_5th=["fcs.pvt.k12.pa.us"],
        )
        known = _portal_known_names(rec)
        self.assertIn("pvt.k12.pa.us", known)
        self.assertIn("fcs.pvt.k12.pa.us", known)

    def test_portal_empty_when_no_input(self):
        self.assertEqual(_portal_known_names(None), frozenset())

    def test_portal_does_not_include_registry_only(self):
        rec = _make_input(
            "k12.pa.us",
            registry=["secret.pvt.k12.pa.us"],
            portal_4th=["pvt.k12.pa.us"],
        )
        known = _portal_known_names(rec)
        self.assertNotIn("secret.pvt.k12.pa.us", known)
        self.assertIn("pvt.k12.pa.us", known)


# ---------------------------------------------------------------------------
# NA-5: No registry_known_names → registry_matrix stays empty
# ---------------------------------------------------------------------------


class TestNoRegistryInputProducesNoMatrix(unittest.TestCase):
    """NA-5 — when no registry_known_names, registry_matrix must stay empty."""

    def test_na5_empty_matrix_when_no_registry_names(self):
        ir = _make_input("k12.pa.us", registry=None, portal_4th=["pvt.k12.pa.us"])
        result = _empty_result("k12.pa.us", ir)
        resolver = MagicMock()
        _validate_registry_known_names(ir, "k12.pa.us", resolver, result, False, None, [])
        self.assertEqual(result.registry_matrix, [])

    def test_na5_empty_matrix_when_input_record_is_none(self):
        result = _empty_result("k12.pa.us", None)
        resolver = MagicMock()
        _validate_registry_known_names(None, "k12.pa.us", resolver, result, False, None, [])
        self.assertEqual(result.registry_matrix, [])


# ---------------------------------------------------------------------------
# AC-2 / AC-3 / AC-4 / AC-5: Evidence matrix classification via mock DNS
# ---------------------------------------------------------------------------


def _pos_dns_response():
    """Return a mock DNS response that will produce at least one finding."""
    resp = MagicMock()
    resp.answer = []
    resp.authority = []
    resp.flags = 0
    return resp, None


def _neg_dns_response():
    return None, "NXDOMAIN"


class TestMatrixClassification(unittest.TestCase):
    """AC-2, AC-3, AC-4, AC-5 — validate all four matrix cells."""

    def _run_validate(
        self,
        domain: str,
        registry_names: list[str],
        portal_names: list[str],
        dns_answers: dict[str, bool],  # fqdn → True means positive
    ) -> list[RegistryKnownEntry]:
        ir = _make_input(domain, registry=registry_names, portal_4th=portal_names)
        result = _empty_result(domain, ir)
        resolver = MagicMock()

        from scanner.models import DiscoveredRecord, RecordType
        from scanner.dns_classifier import DNSResponseClass

        def mock_query_records(fqdn, record_types, resolver, **kwargs):
            if dns_answers.get(fqdn.lower().rstrip(".")):
                rec = DiscoveredRecord(
                    fqdn=fqdn,
                    record_type=RecordType.A,
                    value="1.2.3.4",
                    source_method=kwargs.get("source_method", "test"),
                    classification=FindingClassification.STANDARD_RECORD,
                )
                return [rec], []
            return [], []

        with patch("scanner.scan_engine._query_records", side_effect=mock_query_records):
            _validate_registry_known_names(ir, domain, resolver, result, False, None, [])

        return result.registry_matrix

    def test_ac5_strong_gap_when_dns_live_portal_missing(self):
        """Registry-known + DNS-live + portal-missing → STRONG_GAP."""
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["fcs.pvt.k12.pa.us"],
            portal_names=[],  # portal doesn't know it
            dns_answers={"fcs.pvt.k12.pa.us": True},
        )
        self.assertEqual(len(matrix), 1)
        entry = matrix[0]
        self.assertEqual(entry.matrix_cell, MatrixCell.STRONG_GAP)
        self.assertEqual(entry.dns_status, RegistryDNSStatus.DNS_CONFIRMED)
        self.assertEqual(entry.portal_status, PortalStatus.PORTAL_MISSING)

    def test_na3_validation_only_when_dns_live_portal_present(self):
        """Registry-known + DNS-live + portal-present → VALIDATION_ONLY, NOT STRONG_GAP."""
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=["pvt.k12.pa.us"],  # portal also knows it
            dns_answers={"pvt.k12.pa.us": True},
        )
        self.assertEqual(len(matrix), 1)
        entry = matrix[0]
        self.assertEqual(entry.matrix_cell, MatrixCell.VALIDATION_ONLY)
        self.assertNotEqual(entry.matrix_cell, MatrixCell.STRONG_GAP)

    def test_na1_registry_only_when_dns_dead_portal_missing(self):
        """Registry-known + DNS-not-live + portal-missing → REGISTRY_ONLY, not gap."""
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=[],
            dns_answers={"pvt.k12.pa.us": False},
        )
        self.assertEqual(len(matrix), 1)
        entry = matrix[0]
        self.assertEqual(entry.matrix_cell, MatrixCell.REGISTRY_ONLY)
        self.assertEqual(entry.dns_status, RegistryDNSStatus.DNS_NOT_CONFIRMED)
        self.assertNotEqual(entry.matrix_cell, MatrixCell.STRONG_GAP)

    def test_na6_registry_portal_match_when_dns_dead_portal_present(self):
        """Registry-known + DNS-not-live + portal-present → REGISTRY_PORTAL_MATCH."""
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=["pvt.k12.pa.us"],
            dns_answers={"pvt.k12.pa.us": False},
        )
        self.assertEqual(len(matrix), 1)
        entry = matrix[0]
        self.assertEqual(entry.matrix_cell, MatrixCell.REGISTRY_PORTAL_MATCH)

    def test_ac4_multiple_names_correct_matrix(self):
        """Multiple registry-known names each get correct matrix cell."""
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us", "tec.k12.pa.us"],
            portal_names=["tec.k12.pa.us"],  # tec is portal-present, pvt is not
            dns_answers={"pvt.k12.pa.us": True, "tec.k12.pa.us": True},
        )
        self.assertEqual(len(matrix), 2)
        cells = {e.fqdn: e.matrix_cell for e in matrix}
        self.assertEqual(cells["pvt.k12.pa.us"], MatrixCell.STRONG_GAP)
        self.assertEqual(cells["tec.k12.pa.us"], MatrixCell.VALIDATION_ONLY)

    def test_ac2_dns_confirmed_when_records_found(self):
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=[],
            dns_answers={"pvt.k12.pa.us": True},
        )
        self.assertEqual(matrix[0].dns_status, RegistryDNSStatus.DNS_CONFIRMED)

    def test_ac2_dns_not_confirmed_when_no_records(self):
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=[],
            dns_answers={"pvt.k12.pa.us": False},
        )
        self.assertEqual(matrix[0].dns_status, RegistryDNSStatus.DNS_NOT_CONFIRMED)

    def test_ac3_portal_present_correct(self):
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=["pvt.k12.pa.us"],
            dns_answers={"pvt.k12.pa.us": False},
        )
        self.assertEqual(matrix[0].portal_status, PortalStatus.PORTAL_PRESENT)

    def test_ac3_portal_missing_correct(self):
        matrix = self._run_validate(
            "k12.pa.us",
            registry_names=["pvt.k12.pa.us"],
            portal_names=[],
            dns_answers={"pvt.k12.pa.us": False},
        )
        self.assertEqual(matrix[0].portal_status, PortalStatus.PORTAL_MISSING)


# ---------------------------------------------------------------------------
# NA-2 / AC-6: Lane-2 guessed names never tagged registry_known_validation
# ---------------------------------------------------------------------------


class TestLane1Lane2Separation(unittest.TestCase):
    """NA-2, AC-6 — registry-known and guessed names stay in separate lanes."""

    def test_na2_guessed_candidate_not_registry_source(self):
        """A record discovered by wordlist candidate testing has a different source_method."""
        from scanner.models import DiscoveredRecord, RecordType

        result = _empty_result("k12.pa.us")
        # Simulate a record from wordlist candidate testing.
        record = DiscoveredRecord(
            fqdn="mail.k12.pa.us",
            record_type=RecordType.A,
            value="1.2.3.4",
            source_method="generated_candidate",  # Lane 2
            classification=FindingClassification.STANDARD_RECORD,
        )
        result.records.append(record)
        self.assertNotEqual(record.source_method, REGISTRY_KNOWN_VALIDATION_SOURCE)

    def test_ac6_registry_validation_source_tag(self):
        """Records from registry validation carry REGISTRY_KNOWN_VALIDATION_SOURCE."""
        self.assertEqual(REGISTRY_KNOWN_VALIDATION_SOURCE, "registry_known_validation")

    def test_ac6_registry_source_distinct_from_candidate(self):
        self.assertNotEqual(REGISTRY_KNOWN_VALIDATION_SOURCE, "generated_candidate")


# ---------------------------------------------------------------------------
# AC-10: Reuse existing scan results without re-querying
# ---------------------------------------------------------------------------


class TestExistingScanResultsReused(unittest.TestCase):
    """AC-10 — if the candidate scan already found a registry-known name, reuse it."""

    def test_ac10_no_second_query_when_already_found(self):
        from scanner.models import DiscoveredRecord, RecordType

        ir = _make_input("k12.pa.us", registry=["pvt.k12.pa.us"], portal_4th=[])
        result = _empty_result("k12.pa.us", ir)
        # Pre-populate result with an existing record for pvt.k12.pa.us.
        existing = DiscoveredRecord(
            fqdn="pvt.k12.pa.us",
            record_type=RecordType.A,
            value="10.0.0.1",
            source_method="generated_candidate",
            classification=FindingClassification.STANDARD_RECORD,
        )
        result.records.append(existing)
        resolver = MagicMock()

        with patch("scanner.scan_engine._query_records") as mock_qr:
            _validate_registry_known_names(ir, "k12.pa.us", resolver, result, False, None, [])

        # _query_records must NOT be called since the name was already found.
        mock_qr.assert_not_called()

    def test_ac10_reused_result_is_dns_confirmed(self):
        from scanner.models import DiscoveredRecord, RecordType

        ir = _make_input("k12.pa.us", registry=["pvt.k12.pa.us"], portal_4th=[])
        result = _empty_result("k12.pa.us", ir)
        result.records.append(
            DiscoveredRecord(
                fqdn="pvt.k12.pa.us",
                record_type=RecordType.A,
                value="10.0.0.1",
                source_method="generated_candidate",
                classification=FindingClassification.STANDARD_RECORD,
            )
        )
        resolver = MagicMock()

        with patch("scanner.scan_engine._query_records", return_value=([], [])):
            _validate_registry_known_names(ir, "k12.pa.us", resolver, result, False, None, [])

        # Even without a new query, the existing record makes dns_status = confirmed.
        self.assertEqual(len(result.registry_matrix), 1)
        self.assertEqual(result.registry_matrix[0].dns_status, RegistryDNSStatus.DNS_CONFIRMED)


# ---------------------------------------------------------------------------
# build_registry_matrix_rows / export
# ---------------------------------------------------------------------------


class TestBuildRegistryMatrixRows(unittest.TestCase):
    """AC-4 export — build_registry_matrix_rows produces correct row structure."""

    def _make_scan_result(self, entries: list[RegistryKnownEntry]) -> MagicMock:
        """Mock a ScanRunResult with a single domain containing the given matrix entries."""
        from scanner.models import ScanInput, ScanOptions, ScanProfile, DomainLoadInfo
        from pathlib import Path
        import datetime

        domain_result = DomainScanResult(domain="k12.pa.us", registry_matrix=entries)
        run_result = MagicMock()
        run_result.domain_results = [domain_result]
        run_result.scan_timestamp = datetime.datetime(2026, 6, 27, 12, 0, 0)
        return run_result

    def test_columns_present(self):
        entry = RegistryKnownEntry(
            fqdn="fcs.pvt.k12.pa.us",
            dns_status=RegistryDNSStatus.DNS_CONFIRMED,
            portal_status=PortalStatus.PORTAL_MISSING,
            matrix_cell=MatrixCell.STRONG_GAP,
            dns_record_types=["A"],
            dns_detail="24.0.0.1 (A)",
        )
        run_result = self._make_scan_result([entry])
        rows = build_registry_matrix_rows(run_result)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        for col in REGISTRY_MATRIX_COLUMNS:
            self.assertIn(col, row, f"Missing column: {col}")

    def test_strong_gap_is_strong_gap_yes(self):
        entry = RegistryKnownEntry(
            fqdn="fcs.pvt.k12.pa.us",
            dns_status=RegistryDNSStatus.DNS_CONFIRMED,
            portal_status=PortalStatus.PORTAL_MISSING,
            matrix_cell=MatrixCell.STRONG_GAP,
        )
        rows = build_registry_matrix_rows(self._make_scan_result([entry]))
        self.assertEqual(rows[0]["is_strong_gap"], "yes")

    def test_validation_only_is_strong_gap_no(self):
        entry = RegistryKnownEntry(
            fqdn="pvt.k12.pa.us",
            dns_status=RegistryDNSStatus.DNS_CONFIRMED,
            portal_status=PortalStatus.PORTAL_PRESENT,
            matrix_cell=MatrixCell.VALIDATION_ONLY,
        )
        rows = build_registry_matrix_rows(self._make_scan_result([entry]))
        self.assertEqual(rows[0]["is_strong_gap"], "no")

    def test_strong_gap_sorted_first(self):
        """STRONG_GAP entries appear first in the exported rows."""
        entries = [
            RegistryKnownEntry(
                fqdn="b.pvt.k12.pa.us",
                dns_status=RegistryDNSStatus.DNS_CONFIRMED,
                portal_status=PortalStatus.PORTAL_PRESENT,
                matrix_cell=MatrixCell.VALIDATION_ONLY,
            ),
            RegistryKnownEntry(
                fqdn="a.pvt.k12.pa.us",
                dns_status=RegistryDNSStatus.DNS_CONFIRMED,
                portal_status=PortalStatus.PORTAL_MISSING,
                matrix_cell=MatrixCell.STRONG_GAP,
            ),
        ]
        rows = build_registry_matrix_rows(self._make_scan_result(entries))
        self.assertEqual(rows[0]["matrix_cell"], "strong_gap")
        self.assertEqual(rows[1]["matrix_cell"], "validation_only")

    def test_empty_when_no_registry_matrix(self):
        domain_result = DomainScanResult(domain="k12.pa.us")  # no registry_matrix
        run_result = MagicMock()
        run_result.domain_results = [domain_result]
        run_result.scan_timestamp = None
        rows = build_registry_matrix_rows(run_result)
        self.assertEqual(rows, [])


# ---------------------------------------------------------------------------
# NA-4 / AC-7: Evidence-honest wording
# ---------------------------------------------------------------------------


class TestEvidenceHonestWording(unittest.TestCase):
    """NA-4, AC-7 — wording must be factual, not assert concealment."""

    def test_ac7_registry_matrix_cell_note_does_not_assert_concealment(self):
        from scanner.export_service import REGISTRY_MATRIX_CELL_NOTE
        lower = REGISTRY_MATRIX_CELL_NOTE.lower()
        forbidden = ["hiding", "concealing", "fraud", "deliberate", "intentional", "lied"]
        for word in forbidden:
            with self.subTest(word=word):
                self.assertNotIn(word, lower)

    def test_ac7_strong_gap_framing_factual(self):
        from scanner.export_service import REGISTRY_MATRIX_CELL_NOTE
        # Must contain factual framing language.
        lower = REGISTRY_MATRIX_CELL_NOTE.lower()
        self.assertIn("registry", lower)
        self.assertIn("portal", lower)
        self.assertIn("factually", lower)

    def test_na4_strong_gap_log_message_factual(self):
        """The STRONG_GAP log message must state facts without asserting concealment."""
        ir = _make_input("k12.pa.us", registry=["fcs.pvt.k12.pa.us"], portal_4th=[])
        result = _empty_result("k12.pa.us", ir)
        resolver = MagicMock()
        messages: list[str] = []

        from scanner.models import DiscoveredRecord, RecordType

        def mock_qr(fqdn, *args, **kwargs):
            rec = DiscoveredRecord(
                fqdn=fqdn,
                record_type=RecordType.A,
                value="1.2.3.4",
                source_method=REGISTRY_KNOWN_VALIDATION_SOURCE,
                classification=FindingClassification.STANDARD_RECORD,
            )
            return [rec], []

        with patch("scanner.scan_engine._query_records", side_effect=mock_qr):
            _validate_registry_known_names(
                ir, "k12.pa.us", resolver, result, False, None, messages
            )

        strong_gap_msgs = [m for m in messages if "STRONG GAP" in m]
        self.assertTrue(strong_gap_msgs, "Expected at least one STRONG GAP log line")
        for msg in strong_gap_msgs:
            lower = msg.lower()
            self.assertNotIn("hiding", lower)
            self.assertNotIn("concealing", lower)
            # Must use factual language.
            self.assertIn("registry-known", lower)
            self.assertIn("dns-live", lower)
            self.assertIn("portal", lower)


if __name__ == "__main__":
    unittest.main()
