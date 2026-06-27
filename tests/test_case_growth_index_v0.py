from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - exercised only when optional test dep is absent
    jsonschema = None

from hoxline.case_growth.collector import BOUNDARY, ROW_FIELDS, build_case_growth_index
from hoxline.case_growth.render import render_case_growth_markdown
from hoxline.cli import main


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "case_growth" / "org"
SAMPLE_JSON = ROOT / "examples" / "case-growth" / "sample-case-growth-index.json"
SCHEMA = ROOT / "schemas" / "case-growth-index-v0.schema.json"


def row_by_id(index: dict[str, object], case_id: str) -> dict[str, object]:
    cases = index["cases"]
    assert isinstance(cases, list)
    for row in cases:
        assert isinstance(row, dict)
        if row["case_id"] == case_id:
            return row
    raise AssertionError(f"missing row {case_id}")


def derived_summary(rows: list[dict[str, object]]) -> dict[str, int]:
    return {
        "cases_total": len(rows),
        "source_packages_count": sum(1 for row in rows if row["source_status"] == "SOURCE_EXISTS"),
        "controlled_validations_count": sum(1 for row in rows if row["validation_status"] == "CONTROLLED_TEST_VALIDATED"),
        "runtime_candidate_lanes_count": sum(
            1
            for row in rows
            if row["runtime_candidate_status"] in {"PRIVATE_RUNTIME_CANDIDATE", "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"}
        ),
        "private_runtime_evidence_captured_count": sum(
            1 for row in rows if row["runtime_candidate_status"] == "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"
        ),
        "scheduled_collector_lanes_count": sum(
            1 for row in rows if row["scheduled_collector_status"] == "SCHEDULED_COLLECTOR_LANE_PRESENT_GATED"
        ),
        "proof_records_count": sum(1 for row in rows if row["proof_record_status"] == "PROOF_RECORD_EXISTS"),
        "proofcards_count": sum(1 for row in rows if row["proofcard_status"] == "PROOFCARD_EXISTS"),
        "claim_authority_cases_count": sum(1 for row in rows if row["claim_authority_status"] != "NOT_INDEXED"),
        "metrics_available_count": sum(1 for row in rows if row["metrics_available"]),
        "public_safe_cases_count": sum(1 for row in rows if row["public_safe_status"] == "PUBLIC_SAFE"),
        "closed_cases_count": sum(1 for row in rows if row["case_state"] == "CLOSED"),
        "blocked_claims_count": sum(int(row["blocked_claim_count"]) for row in rows),
        "cases_with_next_gate_count": sum(1 for row in rows if not str(row["next_gate"]).startswith("UNKNOWN_WITH_REASON")),
        "cases_missing_proof_record_count": sum(1 for row in rows if row["proof_record_status"] != "PROOF_RECORD_EXISTS"),
        "cases_missing_proofcard_count": sum(1 for row in rows if row["proofcard_status"] != "PROOFCARD_EXISTS"),
        "cases_not_public_safe_count": sum(1 for row in rows if row["public_safe_status"] != "PUBLIC_SAFE"),
        "unknown_state_count": sum(1 for row in rows if row["case_state"] == "UNKNOWN_WITH_REASON"),
    }


class CaseGrowthIndexV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_case_growth_index(FIXTURE_ROOT, generated_at="2026-06-27T00:00:00Z")
        self.rows = self.index["cases"]
        assert isinstance(self.rows, list)

    def test_fixture_repo_root_loads(self) -> None:
        self.assertEqual(self.index["schema_version"], "case-growth-index-v0")
        self.assertGreaterEqual(self.index["summary"]["cases_total"], 1)

    def test_cli_prints_json(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["case-growth", "index", "--repo-root", str(FIXTURE_ROOT), "--format", "json"])
        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], "case-growth-index-v0")

    def test_cli_prints_markdown(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["case-growth", "index", "--repo-root", str(FIXTURE_ROOT), "--format", "markdown"])
        self.assertEqual(status, 0)
        self.assertIn("| case_id | source | validation | runtime_candidate |", stdout.getvalue())

    def test_schema_validates_sample_json(self) -> None:
        sample = json.loads(SAMPLE_JSON.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        if jsonschema is not None:
            jsonschema.validate(sample, schema)
        else:
            for field in schema["required"]:
                self.assertIn(field, sample)

    def test_rows_include_every_required_field(self) -> None:
        for row in self.rows:
            for field in ROW_FIELDS:
                self.assertIn(field, row)

    def test_summary_counts_are_numeric(self) -> None:
        for value in self.index["summary"].values():
            self.assertIsInstance(value, int)

    def test_summary_counts_match_row_derived_counts(self) -> None:
        self.assertEqual(self.index["summary"], derived_summary(self.rows))

    def test_blocked_claims_count_is_sum_of_rows(self) -> None:
        self.assertEqual(
            self.index["summary"]["blocked_claims_count"],
            sum(int(row["blocked_claim_count"]) for row in self.rows),
        )

    def test_public_safe_count_only_counts_explicit_public_safe(self) -> None:
        self.assertEqual(self.index["summary"]["public_safe_cases_count"], 0)
        self.assertTrue(all(row["public_safe_status"] != "PUBLIC_SAFE" for row in self.rows))

    def test_closed_count_only_counts_explicit_closed(self) -> None:
        self.assertEqual(self.index["summary"]["closed_cases_count"], 0)
        self.assertTrue(all(row["case_state"] != "CLOSED" for row in self.rows))

    def test_website_evidence_never_creates_proof_status(self) -> None:
        website_only = row_by_id(self.index, "HO-DET-999")
        self.assertEqual(website_only["source_status"], "NOT_FOUND")
        self.assertEqual(website_only["proof_record_status"], "NOT_PROVEN")
        self.assertEqual(website_only["proofcard_status"], "NOT_PROVEN")

    def test_metrics_available_for_hox_gauntlet_fixture(self) -> None:
        gauntlet = row_by_id(self.index, "HOX-GAUNTLET-001")
        self.assertTrue(gauntlet["metrics_available"])
        self.assertTrue(gauntlet["metrics_refs"])

    def test_not_public_safe_and_not_proven_states_are_preserved(self) -> None:
        controlled = row_by_id(self.index, "HO-DET-900")
        self.assertEqual(controlled["public_safe_status"], "NOT_PUBLIC_SAFE")
        self.assertEqual(controlled["signal_status"], "NOT_PROVEN")

    def test_missing_evidence_gets_explicit_unknown_or_not_found(self) -> None:
        source_only = row_by_id(self.index, "HO-DET-901")
        self.assertEqual(source_only["validation_status"], "NOT_FOUND")
        self.assertEqual(source_only["proof_record_status"], "NOT_PROVEN")

    def test_boundary_booleans_are_all_false(self) -> None:
        self.assertEqual(self.index["boundary"], BOUNDARY)
        self.assertTrue(all(value is False for value in self.index["boundary"].values()))

    def test_output_contains_at_least_one_case_row(self) -> None:
        self.assertGreater(len(self.rows), 0)

    def test_generated_markdown_includes_table_headers(self) -> None:
        markdown = render_case_growth_markdown(self.index)
        self.assertIn("| Metric | Count |", markdown)
        self.assertIn("| case_id | source | validation | runtime_candidate |", markdown)

    def test_current_sample_json_has_summary_cases_boundary(self) -> None:
        sample = json.loads(SAMPLE_JSON.read_text(encoding="utf-8"))
        self.assertIn("summary", sample)
        self.assertIn("cases", sample)
        self.assertIn("boundary", sample)

    def test_anti_vague_output_has_numeric_counts_and_evidence_refs(self) -> None:
        self.assertGreater(self.index["summary"]["cases_total"], 0)
        self.assertTrue(any(row["source_evidence_refs"] or row["validation_evidence_refs"] for row in self.rows))
        self.assertTrue(any(isinstance(value, int) for value in self.index["summary"].values()))
        self.assertTrue(all("next_gate" in row for row in self.rows))

    def test_anti_overclaim_flags_are_not_true_anywhere(self) -> None:
        self.assertTrue(all(value is False for value in self.index["boundary"].values()))
        for row in self.rows:
            self.assertNotEqual(row["public_safe_status"], "PUBLIC_SAFE")
            self.assertNotEqual(row["signal_status"], "SIGNAL_OBSERVED_PUBLIC")
            self.assertNotEqual(row["case_state"], "CLOSED")

    def test_invalid_repo_root_exits_nonzero(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["case-growth", "index", "--repo-root", str(ROOT / "missing"), "--format", "json"])
        self.assertNotEqual(status, 0)
        self.assertIn("error:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
