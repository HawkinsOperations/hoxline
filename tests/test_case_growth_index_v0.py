from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - exercised only when optional test dep is absent
    jsonschema = None

from hoxline.case_growth.collector import (
    BOUNDARY,
    ROW_FIELDS,
    _reproducibility_hash,
    build_case_growth_index,
    diff_case_growth_snapshot,
    verify_case_growth_snapshot,
)
from hoxline.case_growth.discovery import REPO_NAMES
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


def pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 2)


def derived_health(summary: dict[str, int]) -> dict[str, float]:
    cases_total = summary["cases_total"]
    source_packages = summary["source_packages_count"]
    return {
        "validation_coverage_percent": pct(summary["controlled_validations_count"], source_packages),
        "proof_record_coverage_percent": pct(summary["proof_records_count"], cases_total),
        "proofcard_coverage_percent": pct(summary["proofcards_count"], cases_total),
        "scheduled_collector_coverage_percent": pct(summary["scheduled_collector_lanes_count"], cases_total),
        "runtime_candidate_coverage_percent": pct(summary["runtime_candidate_lanes_count"], cases_total),
        "metrics_coverage_percent": pct(summary["metrics_available_count"], cases_total),
        "public_safe_percent": pct(summary["public_safe_cases_count"], cases_total),
        "closed_case_percent": pct(summary["closed_cases_count"], cases_total),
        "blocked_claim_density": ratio(summary["blocked_claims_count"], cases_total),
        "next_gate_coverage_percent": pct(summary["cases_with_next_gate_count"], cases_total),
        "missing_proof_record_percent": pct(summary["cases_missing_proof_record_count"], cases_total),
        "missing_proofcard_percent": pct(summary["cases_missing_proofcard_count"], cases_total),
        "not_public_safe_percent": pct(summary["cases_not_public_safe_count"], cases_total),
    }


class CaseGrowthIndexV0Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = build_case_growth_index(FIXTURE_ROOT, generated_at="2026-06-27T00:00:00Z")
        cls.rows = cls.index["cases"]
        assert isinstance(cls.rows, list)

    def test_fixture_repo_root_loads(self) -> None:
        self.assertEqual(self.index["schema_version"], "case-growth-index-v1")
        self.assertGreaterEqual(self.index["summary"]["cases_total"], 1)

    def test_cli_prints_json(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["case-growth", "index", "--repo-root", str(FIXTURE_ROOT), "--format", "json"])
        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], "case-growth-index-v1")

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

    def test_case_growth_health_metrics_are_derived_from_summary(self) -> None:
        health = self.index["case_growth_health"]
        for key, expected in derived_health(self.index["summary"]).items():
            self.assertEqual(health[key], expected)
        self.assertIn(
            health["recommended_next_build"],
            {
                "proof_record_backfill",
                "proofcard_backfill",
                "public_safe_candidate_review_packet",
                "runtime_signal_review_gate",
                "case_closure_contract",
                "external_reviewer_demo_packet",
                "hygiene_cleanup_only",
            },
        )

    def test_public_safe_blocked_health_when_no_cases_are_public_safe(self) -> None:
        health = self.index["case_growth_health"]
        self.assertEqual(health["overall_health_status"], "PUBLIC_SAFE_BLOCKED")
        self.assertTrue(any("public_safe blocked" in item for item in health["top_bottlenecks"]))

    def test_repo_slot_accuracy_present_github_fixture(self) -> None:
        accuracy = self.index["repo_slot_accuracy"]
        self.assertEqual(accuracy["expected_repo_slots"], 7)
        self.assertEqual(accuracy["present_local_repos"], 7)
        self.assertEqual(accuracy["missing_local_repos"], [])
        self.assertTrue(accuracy["github_org_root_exists"])
        self.assertIn("seven expected repo slots evaluated", accuracy["wording"])

    def test_repo_slot_accuracy_missing_github_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir) / "org"
            shutil.copytree(FIXTURE_ROOT, temp_root)
            shutil.rmtree(temp_root / ".github")
            index = build_case_growth_index(temp_root, generated_at="2026-06-27T00:00:00Z")
        accuracy = index["repo_slot_accuracy"]
        self.assertEqual(accuracy["expected_repo_slots"], 7)
        self.assertEqual(accuracy["present_local_repos"], 6)
        self.assertEqual(accuracy["missing_local_repos"], [".github"])
        self.assertFalse(accuracy["github_org_root_exists"])
        self.assertIn("missing local repo slots: .github", accuracy["wording"])

    def test_hoxline_internal_fixture_org_does_not_create_live_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir) / "org"
            shutil.copytree(FIXTURE_ROOT, temp_root)
            leak_path = temp_root / "hoxline" / "tests" / "fixtures" / "case_growth" / "org" / "README.md"
            leak_path.parent.mkdir(parents=True)
            leak_path.write_text("Fixture-only HO-DET-777 must not become a live case.\n", encoding="utf-8")
            generated_path = temp_root / "hoxline" / "examples" / "case-growth" / "current-case-growth-index.md"
            generated_path.parent.mkdir(parents=True)
            generated_path.write_text("Generated-only HO-DET-778 must not become a live case.\n", encoding="utf-8")
            doc_path = temp_root / "hoxline" / "docs" / "case-growth" / "HOXLINE_CASE_GROWTH_INDEX_V0.md"
            doc_path.parent.mkdir(parents=True)
            doc_path.write_text("Documentation-only HO-DET-779 must not become a live case.\n", encoding="utf-8")
            index = build_case_growth_index(temp_root, generated_at="2026-06-27T00:00:00Z")
        case_ids = {row["case_id"] for row in index["cases"]}
        self.assertNotIn("HO-DET-777", case_ids)
        self.assertNotIn("HO-DET-778", case_ids)
        self.assertNotIn("HO-DET-779", case_ids)

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
        self.assertIn("## Source Revisions", markdown)
        self.assertIn("## Convergence Findings", markdown)
        self.assertIn("## Case Growth Health", markdown)
        self.assertIn("| Health metric | Value |", markdown)
        self.assertIn("| Top bottleneck |", markdown)
        self.assertIn("| case_id | source | validation | runtime_candidate |", markdown)

    def test_current_sample_json_has_summary_cases_boundary(self) -> None:
        sample = json.loads(SAMPLE_JSON.read_text(encoding="utf-8"))
        self.assertIn("summary", sample)
        self.assertIn("case_growth_health", sample)
        self.assertIn("repo_slot_accuracy", sample)
        self.assertIn("cases", sample)
        self.assertIn("boundary", sample)

    def test_v1_source_revisions_are_exactly_seven_and_sanitized(self) -> None:
        revisions = self.index["source_revisions"]
        self.assertEqual(len(revisions), 7)
        self.assertEqual({item["repository"] for item in revisions}, set(REPO_NAMES))
        serialized = json.dumps(self.index)
        self.assertNotIn("C:\\\\Raylee\\\\", serialized)
        self.assertNotIn("C:/Raylee/", serialized)
        for item in revisions:
            self.assertIn("authority_role", item)
            self.assertIn("source_commit_sha", item)
            self.assertIn("source_file_sha256", item)
            self.assertIn("source_freshness_state", item)
            self.assertIn("next_legal_action", item)

    def test_reproducibility_hash_ignores_only_generated_at(self) -> None:
        first = build_case_growth_index(FIXTURE_ROOT, generated_at="2026-06-27T00:00:00Z")
        second = build_case_growth_index(FIXTURE_ROOT, generated_at="2030-01-01T00:00:00Z")
        self.assertEqual(first["reproducibility_sha256"], second["reproducibility_sha256"])

    def test_verify_rejects_absolute_path_duplicate_and_promotion(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["repo_root"] = r"C:\Raylee\Repo\HawkinsOperations"
        hostile["cases"].append(json.loads(json.dumps(hostile["cases"][0])))
        hostile["cases"][0]["public_safe_status"] = "PUBLIC_SAFE"
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("absolute local path" in error for error in errors))
        self.assertTrue(any("duplicate case ID" in error for error in errors))
        self.assertTrue(any("unauthorized public-safe status" in error for error in errors))

    def test_verify_rejects_forged_counts_and_historical_current_conflict(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["summary"]["proof_records_count"] += 99
        hostile["historical_snapshot"] = True
        hostile["current_authority"] = True
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertIn("snapshot cannot be both historical_snapshot=true and current_authority=true", errors)
        self.assertTrue(any("summary counts disagree" in error for error in errors))

    def test_diff_classifies_explicit_historical_changes_as_context(self) -> None:
        historical = json.loads(json.dumps(self.index))
        historical["historical_snapshot"] = True
        historical["current_authority"] = False
        historical["summary"]["proof_records_count"] = -1
        report = diff_case_growth_snapshot(FIXTURE_ROOT, historical)
        change = next(item for item in report["changes"] if item["field"] == "summary.proof_records_count")
        self.assertEqual(change["classification"], "EXPECTED_HISTORICAL_CONTEXT")

    def test_cli_verify_fails_closed_on_hostile_snapshot(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["repo_root"] = r"C:\Users\operator\snapshot.json"
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot = Path(temp_dir) / "hostile.json"
            snapshot.write_text(json.dumps(hostile), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "case-growth",
                        "verify",
                        "--repo-root",
                        str(FIXTURE_ROOT),
                        "--snapshot",
                        str(snapshot),
                        "--format",
                        "json",
                    ]
                )
        self.assertEqual(status, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertTrue(any("absolute local path" in error for error in payload["errors"]))

    def test_cli_diff_emits_reviewer_readable_json(self) -> None:
        historical = json.loads(json.dumps(self.index))
        historical["historical_snapshot"] = True
        historical["current_authority"] = False
        historical["summary"]["proof_records_count"] = -1
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot = Path(temp_dir) / "historical.json"
            snapshot.write_text(json.dumps(historical), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "case-growth",
                        "diff",
                        "--repo-root",
                        str(FIXTURE_ROOT),
                        "--snapshot",
                        str(snapshot),
                        "--format",
                        "json",
                    ]
                )
        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], "case-growth-diff-v1")
        self.assertTrue(payload["changes"])

    def test_verify_requires_exact_unique_seven_repository_set(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["source_revisions"][-1] = json.loads(json.dumps(hostile["source_revisions"][0]))
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("repository names must be unique" in error for error in errors))
        self.assertTrue(any("exact seven-repository set" in error for error in errors))

    def test_verify_rejects_forged_runtime_and_claim_authority_fields(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["cases"][0]["runtime_candidate_status"] = "RUNTIME_ACTIVE"
        hostile["cases"][0]["claim_authority_status"] = "ANALYST_APPROVED"
        hostile["cases"][0]["next_gate"] = "final authorization and case closure"
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("unauthorized runtime_candidate_status" in error for error in errors))
        self.assertTrue(any("unauthorized claim_authority_status" in error for error in errors))
        self.assertTrue(any("final authorization wording" in error for error in errors))
        self.assertTrue(any("case closure wording" in error for error in errors))

    def test_historical_snapshot_sha_must_resolve_in_stated_repository(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["historical_snapshot"] = True
        hostile["current_authority"] = False
        hostile["source_revisions"][0]["source_commit_sha"] = "f" * 40
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("not a reachable commit" in error for error in errors))

    def test_historical_snapshot_fingerprint_must_match_stated_commit_blob(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["historical_snapshot"] = True
        hostile["current_authority"] = False
        hostile["source_revisions"][0]["source_commit_sha"] = "a" * 40
        hostile["source_revisions"][0]["source_file_sha256"] = "0" * 64
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        with (
            mock.patch("hoxline.case_growth.collector.git_commit_exists", return_value=True),
            mock.patch("hoxline.case_growth.collector.git_blob_sha256", return_value="b" * 64),
        ):
            errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("does not match the authoritative blob at the stated commit" in error for error in errors))

    def test_current_snapshot_rejects_worktree_modified_freshness(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["source_revisions"][0]["source_freshness_state"] = "WORKTREE_MODIFIED"
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("source_freshness_state must be one of" in error for error in errors))

    def test_current_hoxline_snapshot_requires_self_reference_and_immediate_parent(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hoxline_revision = next(
            revision for revision in hostile["source_revisions"] if revision["repository"] == "hoxline"
        )
        hoxline_revision["self_referential"] = False
        hoxline_revision["revision_scope"] = "authoritative_source_at_commit"
        hoxline_revision["source_commit_sha"] = "a" * 40
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("self_referential must be true" in error for error in errors))
        self.assertTrue(any("revision_scope must be authoritative_sources_excluding_snapshot" in error for error in errors))
        self.assertTrue(any("must cite the immediate parent engine commit" in error for error in errors))

    def test_verify_rejects_drive_unc_and_posix_absolute_paths(self) -> None:
        for leaked_path in (r"D:\private\evidence.json", r"\\private-host\share\evidence.json", "/home/reviewer/evidence.json"):
            with self.subTest(leaked_path=leaked_path):
                hostile = json.loads(json.dumps(self.index))
                hostile["cases"][0]["source_evidence_refs"] = [leaked_path]
                hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
                errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
                self.assertTrue(any("absolute local path" in error for error in errors))

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
