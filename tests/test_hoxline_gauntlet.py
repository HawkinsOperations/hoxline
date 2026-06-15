from __future__ import annotations

import json
from pathlib import Path

from hoxline.cli import main
from hoxline.gauntlet import CANONICAL_LOOP, REQUIRED_BLOCKED_CLAIMS, build_full_loop_run, render_markdown


ROOT = Path(__file__).resolve().parents[1]


def test_full_loop_run_has_required_fields_and_order() -> None:
    report = build_full_loop_run("HO-DET-001", repo_root=ROOT)

    required = {
        "run_id",
        "artifact_id",
        "product",
        "proof_ceiling",
        "public_safe",
        "human_review_required",
        "loop_stages",
        "allowed_claims",
        "blocked_claims",
        "missing_evidence",
        "authority_sources",
        "reviewer_summary",
        "non_claims",
    }

    assert required <= set(report)
    assert [stage["stage"] for stage in report["loop_stages"]] == CANONICAL_LOOP
    assert report["product"] == "Hoxline by HawkinsOperations"
    assert report["proof_ceiling"] == "CONTROLLED_TEST_VALIDATED"
    assert report["public_safe"] is False
    assert report["human_review_required"] is True


def test_full_loop_stage_statuses_preserve_boundaries() -> None:
    report = build_full_loop_run("HO-DET-001", repo_root=ROOT)
    statuses = {stage["stage"]: stage["status"] for stage in report["loop_stages"]}

    assert statuses["AI-assisted security work"] == "REFERENCE_ONLY"
    assert statuses["Artifact Intake"] == "PASS"
    assert statuses["Evidence Graph"] == "PASS"
    assert statuses["Telemetry Contract Check"] == "PASS"
    assert statuses["Controlled Validation"] == "PASS"
    assert statuses["Runtime Candidate Ledger"] == "BLOCKED"
    assert statuses["Signal Observation"] == "MISSING_EVIDENCE"
    assert statuses["Human Review Gate"] == "HUMAN_REVIEW_REQUIRED"
    assert statuses["ProofCard"] == "PASS"
    assert statuses["Claim Authority"] == "PASS"
    assert statuses["Safe Claim / Blocked Claim"] == "PASS"


def test_required_blocked_claims_and_missing_evidence_are_present() -> None:
    report = build_full_loop_run("HO-DET-001", repo_root=ROOT)
    blocked = {item["claim"] for item in report["blocked_claims"]}

    assert set(REQUIRED_BLOCKED_CLAIMS) <= blocked
    assert "runtime_evidence" in report["missing_evidence"]
    assert "signal_observation_evidence" in report["missing_evidence"]
    assert "public_safe_authorization" in report["missing_evidence"]
    assert "human_review_gate_complete" in report["missing_evidence"]
    assert "legal_review_record" in report["missing_evidence"]
    assert "business_evidence_record" in report["missing_evidence"]


def test_cli_json_and_markdown_outputs(capsys) -> None:
    json_status = main(["gauntlet", "run", "--artifact", "HO-DET-001", "--format", "json"])
    json_output = capsys.readouterr()
    assert json_status == 0
    assert json.loads(json_output.out)["artifact_id"] == "HO-DET-001"

    markdown_status = main(["gauntlet", "run", "--artifact", "HO-DET-001", "--format", "markdown"])
    markdown_output = capsys.readouterr()
    assert markdown_status == 0
    assert "# Hoxline Gauntlet Full-Loop Run v0" in markdown_output.out
    assert "Runtime Candidate Ledger" in markdown_output.out


def test_markdown_keeps_case_closed_out_of_scannable_boundary_text() -> None:
    report = build_full_loop_run("HO-DET-001", repo_root=ROOT)
    markdown = render_markdown(report)

    assert "case-closure wording" in markdown
    assert "case closed" not in markdown.lower()
