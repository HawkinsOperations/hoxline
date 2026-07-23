from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
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
    _content_normalized_cases,
    _reproducibility_hash,
    build_case_growth_index,
    diff_case_growth_snapshot,
    verify_selected_source_checkout,
    verify_case_growth_snapshot,
)
from hoxline.case_growth.discovery import REPO_NAMES
from hoxline.case_growth.render import render_case_growth_markdown
from hoxline.cli import main


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "case_growth" / "org"
SAMPLE_JSON = ROOT / "examples" / "case-growth" / "sample-case-growth-index.json"
SCHEMA = ROOT / "schemas" / "case-growth-index-v0.schema.json"


def _git(repo: Path, *args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _write_source_selection_manifest(
    org_root: Path,
    selected_repository: str,
    revision: str,
    reviewed_tree: str,
) -> None:
    entries: list[dict[str, object]] = [
        {
            "repository": ".github",
            "canonical_repository": "HawkinsOperations/.github",
            "revision_source": "github_event_sha",
            "tree_source": "github_event_tree",
        }
    ]
    for repository in REPO_NAMES:
        if repository == ".github":
            continue
        entries.append(
            {
                "repository": repository,
                "canonical_repository": f"HawkinsOperations/{repository}",
                "revision": revision if repository == selected_repository else "0" * 40,
                "authority_content_revision": (
                    revision if repository == selected_repository else "0" * 40
                ),
                "reviewed_tree_sha": reviewed_tree if repository == selected_repository else "0" * 40,
            }
        )
    manifest = {
        "schema": "hawkinsoperations-convergence-source-manifest-v1",
        "manifest_id": "TEST_EXACT_SEVEN_SOURCE_SELECTION",
        "repositories": entries,
        "constraints": {
            "exact_repository_count": 7,
            "read_only": True,
            "default_branch_fallback": False,
            "require_detached_exact_revision": True,
            "record_checked_revisions": True,
            "consumer_outputs_are_not_authority": True,
            "proof_ceiling": "CONTROLLED_REPO_CONVERGENCE_AND_LOCAL_FIXTURE_REVIEW_ONLY",
        },
    }
    manifest_path = org_root / ".github" / "governance" / "CONVERGENCE_SOURCE_MANIFEST.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    command_center = org_root / ".github"
    _git(command_center, "init")
    _git(command_center, "config", "user.name", "Hoxline Test")
    _git(command_center, "config", "user.email", "hoxline-test@example.invalid")
    _git(command_center, "remote", "add", "origin", "https://github.com/HawkinsOperations/.github.git")
    _git(command_center, "add", "governance/CONVERGENCE_SOURCE_MANIFEST.json")
    _git(command_center, "commit", "-m", "source selection")


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

    def test_cli_writes_content_bound_json_markdown_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pair_base = Path(temp_dir) / "case-growth"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "case-growth",
                        "index",
                        "--repo-root",
                        str(FIXTURE_ROOT),
                        "--format",
                        "json",
                        "--paired-output-base",
                        str(pair_base),
                    ]
                )
            self.assertEqual(status, 0)
            payload = json.loads(pair_base.with_suffix(".json").read_text(encoding="utf-8"))
            self.assertEqual(
                pair_base.with_suffix(".md").read_text(encoding="utf-8"),
                render_case_growth_markdown(payload),
            )
            pair_base.with_suffix(".md").write_text("tampered\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                verify_status = main(
                    [
                        "case-growth",
                        "verify",
                        "--repo-root",
                        str(FIXTURE_ROOT),
                        "--snapshot",
                        str(pair_base.with_suffix(".json")),
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(verify_status, 1)
            self.assertIn("not the exact render", stdout.getvalue())

    def test_schema_validates_sample_json(self) -> None:
        sample = self.index
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
        case_ids = {row["case_id"] for row in self.rows}
        self.assertNotIn("HO-DET-999", case_ids)

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

    def test_diff_classifies_head_rewrite_with_same_content_as_observation_only(self) -> None:
        snapshot = json.loads(json.dumps(self.index))
        hoxline_revision = next(item for item in snapshot["source_revisions"] if item["repository"] == "hoxline")
        hoxline_revision["source_commit_sha"] = "a" * 40
        hoxline_revision["source_observed_head_sha"] = "a" * 40
        hoxline_revision["current_observed_head_sha"] = "a" * 40
        report = diff_case_growth_snapshot(FIXTURE_ROOT, snapshot)
        change = next(
            item
            for item in report["changes"]
            if item["source_owner"] == "hoxline" and item["field"] == "source_commit_sha"
        )
        self.assertEqual(change["classification"], "OBSERVATION_ONLY_CONTENT_CURRENT")
        self.assertTrue(report["next_legal_action"].startswith("none;"))

    def test_case_content_normalization_ignores_only_rewritten_commit_clock(self) -> None:
        before = json.loads(json.dumps(self.rows))
        after = json.loads(json.dumps(self.rows))
        after[0]["last_updated"] = "2035-01-02T03:04:05+00:00"
        self.assertEqual(_content_normalized_cases(before), _content_normalized_cases(after))

        after[0]["source_status"] = "FORGED_SOURCE_STATUS"
        self.assertNotEqual(_content_normalized_cases(before), _content_normalized_cases(after))

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

    def test_missing_authorization_metric_token_is_bounded_context(self) -> None:
        bounded = json.loads(json.dumps(self.index))
        bounded["cases"][0]["notes"] = ["missing_human_final_authorization"]
        bounded["reproducibility_sha256"] = _reproducibility_hash(bounded)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, bounded)
        self.assertFalse(any("final authorization wording" in error for error in errors))

    def test_unavailable_observed_sha_does_not_replace_content_authority(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["source_revisions"][0]["source_commit_sha"] = "f" * 40
        hostile["source_revisions"][0]["source_observed_head_sha"] = "f" * 40
        hostile["source_revisions"][0]["current_observed_head_sha"] = "f" * 40
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertFalse(any("authoritative Git blob disagrees" in error for error in errors))

    def test_selected_source_checkout_accepts_exact_detached_and_content_equivalent_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            org_root = Path(temp_dir)
            repository = "hawkinsoperations-detections"
            repo = org_root / repository
            repo.mkdir()
            _git(repo, "init")
            _git(repo, "config", "user.name", "Hoxline Test")
            _git(repo, "config", "user.email", "hoxline-test@example.invalid")
            (repo / "authority.yml").write_text("authority: detection\n", encoding="utf-8")
            _git(repo, "add", "authority.yml")
            _git(repo, "commit", "-m", "authority")
            (repo / "review.txt").write_text("reviewed selection\n", encoding="utf-8")
            _git(repo, "add", "review.txt")
            _git(repo, "commit", "-m", "reviewed selection")
            selected = _git(repo, "rev-parse", "HEAD")
            reviewed_tree = _git(repo, "rev-parse", "HEAD^{tree}")
            _write_source_selection_manifest(org_root, repository, selected, reviewed_tree)

            _git(repo, "checkout", "--detach", selected)
            self.assertEqual(verify_selected_source_checkout(org_root, repository), [])

            selection_path = org_root / ".github" / "governance" / "CONVERGENCE_SOURCE_MANIFEST.json"
            selection_text = selection_path.read_text(encoding="utf-8")
            selection_path.write_text(selection_text + "\n", encoding="utf-8")
            self.assertTrue(
                any(
                    "must be tracked and clean" in error
                    for error in verify_selected_source_checkout(org_root, repository)
                )
            )
            selection_path.write_text(selection_text, encoding="utf-8")

            (repo / "post-selection.txt").write_text("merge descendant observation\n", encoding="utf-8")
            _git(repo, "add", "post-selection.txt")
            _git(repo, "commit", "-m", "merge descendant")
            self.assertEqual(verify_selected_source_checkout(org_root, repository), [])

            rewritten = _git(repo, "commit-tree", reviewed_tree, input_text="rewritten identity\n")
            _git(repo, "checkout", "--detach", rewritten)
            self.assertEqual(verify_selected_source_checkout(org_root, repository), [])

    def test_dynamic_command_center_selection_requires_exact_detached_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            org_root = Path(temp_dir)
            repository = "hawkinsoperations-detections"
            repo = org_root / repository
            repo.mkdir()
            _git(repo, "init")
            _git(repo, "config", "user.name", "Hoxline Test")
            _git(repo, "config", "user.email", "hoxline-test@example.invalid")
            (repo / "authority.yml").write_text("authority: detection\n", encoding="utf-8")
            _git(repo, "add", "authority.yml")
            _git(repo, "commit", "-m", "authority")
            selected = _git(repo, "rev-parse", "HEAD")
            reviewed_tree = _git(repo, "rev-parse", "HEAD^{tree}")
            _write_source_selection_manifest(org_root, repository, selected, reviewed_tree)

            command_center = org_root / ".github"
            command_head = _git(command_center, "rev-parse", "HEAD")
            with mock.patch.dict(
                "os.environ",
                {"HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA": ""},
            ):
                self.assertEqual(
                    verify_selected_source_checkout(org_root, ".github"),
                    [],
                )

            _git(command_center, "checkout", "--detach", command_head)
            with mock.patch.dict(
                "os.environ",
                {"HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA": ""},
            ):
                errors = verify_selected_source_checkout(org_root, ".github")
            self.assertTrue(any("requires HAWKINS_COMMAND_CENTER" in error for error in errors))

            with mock.patch.dict(
                "os.environ",
                {"HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA": command_head},
            ):
                self.assertEqual(
                    verify_selected_source_checkout(org_root, ".github"),
                    [],
                )

            with mock.patch.dict(
                "os.environ",
                {"HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA": "f" * 40},
            ):
                errors = verify_selected_source_checkout(org_root, ".github")
            self.assertTrue(any("differs from the immutable workflow observation" in error for error in errors))

    def test_selected_source_checkout_rejects_older_same_authority_blob_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            org_root = Path(temp_dir)
            repository = "hawkinsoperations-detections"
            repo = org_root / repository
            repo.mkdir()
            _git(repo, "init")
            _git(repo, "config", "user.name", "Hoxline Test")
            _git(repo, "config", "user.email", "hoxline-test@example.invalid")
            (repo / "authority.yml").write_text("authority: detection\n", encoding="utf-8")
            _git(repo, "add", "authority.yml")
            _git(repo, "commit", "-m", "authority")
            older = _git(repo, "rev-parse", "HEAD")
            authority_blob = _git(repo, "rev-parse", "HEAD:authority.yml")
            (repo / "review.txt").write_text("reviewed selection\n", encoding="utf-8")
            _git(repo, "add", "review.txt")
            _git(repo, "commit", "-m", "reviewed selection")
            selected = _git(repo, "rev-parse", "HEAD")
            reviewed_tree = _git(repo, "rev-parse", "HEAD^{tree}")
            self.assertEqual(_git(repo, "rev-parse", "HEAD:authority.yml"), authority_blob)
            _write_source_selection_manifest(org_root, repository, selected, reviewed_tree)

            _git(repo, "checkout", "--detach", older)
            errors = verify_selected_source_checkout(org_root, repository)
            self.assertTrue(any("behind the explicit selected revision" in error for error in errors))

    def test_current_snapshot_rejects_forged_content_identity(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["source_revisions"][0]["authoritative_git_blob_sha"] = "a" * 40
        hostile["source_revisions"][0]["authoritative_content_fingerprint"] = "0" * 64
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("authoritative Git blob disagrees" in error for error in errors))
        self.assertTrue(any("semantic fingerprint disagrees" in error for error in errors))

    def test_current_snapshot_rejects_worktree_modified_freshness(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hostile["current_authority"] = True
        hostile["snapshot_state"]["current_authority"] = True
        hostile["source_revisions"][0]["source_freshness_state"] = "WORKTREE_MODIFIED"
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("source_freshness_state must be one of" in error for error in errors))

    def test_generated_consumers_cannot_become_self_referential_authority(self) -> None:
        hostile = json.loads(json.dumps(self.index))
        hoxline_revision = next(
            revision for revision in hostile["source_revisions"] if revision["repository"] == "hoxline"
        )
        hoxline_revision["self_referential"] = True
        hoxline_revision["revision_scope"] = "authoritative_source_at_commit"
        hostile["reproducibility_sha256"] = _reproducibility_hash(hostile)
        errors, _ = verify_case_growth_snapshot(FIXTURE_ROOT, hostile)
        self.assertTrue(any("generated consumers must not be self-referential authority" in error for error in errors))
        self.assertTrue(any("revision_scope must be content_addressed_authority" in error for error in errors))

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
