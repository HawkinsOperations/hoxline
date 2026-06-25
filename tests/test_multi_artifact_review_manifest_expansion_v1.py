from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from hoxline.cli import main
from hoxline.review_engine import verify_batch_run


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "examples" / "review" / "multi-artifact-review-index-v1.json"
HOSTILE_BATCH_DIR = ROOT / "examples" / "review" / "hostile-batch"
MANIFESTS = {
    "HO-DET-009": ROOT / "examples" / "review" / "ho-det-009-artifact-manifest-v1.json",
    "HO-DET-010": ROOT / "examples" / "review" / "ho-det-010-artifact-manifest-v1.json",
    "HO-DET-011": ROOT / "examples" / "review" / "ho-det-011-artifact-manifest-v1.json",
    "HO-DET-012": ROOT / "examples" / "review" / "ho-det-012-artifact-manifest-v1.json",
}


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_single_artifact_manifests_pass(tmp_path) -> None:
    for artifact_id, manifest in MANIFESTS.items():
        output_dir = tmp_path / artifact_id
        assert main(["review", "run", "--artifact", str(manifest), "--output", str(output_dir), "--force"]) == 0
        assert main(["review", "verify", "--run", str(output_dir / "machine-state.json")]) == 0
        state = _json(output_dir / "machine-state.json")
        assert state["artifact_id"] == artifact_id
        assert state["final_status"] == "PASS"
        assert state["public_safe_status"] == "NOT_PUBLIC_SAFE"
        assert state["human_review_required"] is True
        assert state["ai_disposition_authority"] is False
        assert state["endpoint_mutation"] is False
        assert state["wazuh_mutation"] is False
        assert state["runtime_proof"] is False
        assert state["public_proof_promoted"] is False
        assert state["lifetime_ledger_changed"] is False


def test_batch_run_creates_aggregate_outputs_and_verifies(tmp_path, capsys) -> None:
    output_dir = tmp_path / "batch"

    status = main(["review", "batch", "run", "--index", str(INDEX), "--output", str(output_dir), "--force"])

    output = capsys.readouterr()
    assert status == 0
    assert "Hoxline Review Engine v1 batch" in output.out
    for name in ["input-index.json", "batch-machine-state.json", "batch-summary.md", "batch-reviewer-pack.md", "batch-run-summary.json"]:
        assert (output_dir / name).is_file(), name
    assert main(["review", "batch", "verify", "--run", str(output_dir / "batch-machine-state.json")]) == 0
    assert verify_batch_run(output_dir / "batch-machine-state.json") == []


def test_batch_machine_state_contains_all_artifacts_and_boundaries(tmp_path) -> None:
    output_dir = tmp_path / "batch"
    assert main(["review", "batch", "run", "--index", str(INDEX), "--output", str(output_dir), "--force"]) == 0

    state = _json(output_dir / "batch-machine-state.json")
    artifacts = {item["artifact_id"]: item for item in state["artifacts"]}
    assert set(artifacts) == {"HO-DET-009", "HO-DET-010", "HO-DET-011", "HO-DET-012"}
    assert state["final_status"] == "PASS"
    assert state["expected_pass_artifacts"] == ["HO-DET-009", "HO-DET-010", "HO-DET-011", "HO-DET-012"]
    assert state["expected_blocked_artifacts"] == []
    assert state["public_safe_status"] == "NOT_PUBLIC_SAFE"
    assert state["human_review_required"] is True
    assert state["ai_disposition_authority"] is False
    assert state["endpoint_mutation"] is False
    assert state["wazuh_mutation"] is False
    assert state["runtime_proof"] is False
    assert state["public_proof_promoted"] is False
    assert state["lifetime_ledger_changed"] is False
    for artifact_id, artifact in artifacts.items():
        assert Path(artifact["machine_state"]).is_file(), artifact_id
        assert Path(artifact["reviewer_pack"]).is_file(), artifact_id
        assert artifact["final_status"] == "PASS"


def test_aggregate_reviewer_pack_explains_pass_and_block_sections(tmp_path) -> None:
    output_dir = tmp_path / "batch"
    assert main(["review", "batch", "run", "--index", str(INDEX), "--output", str(output_dir), "--force"]) == 0

    pack = (output_dir / "batch-reviewer-pack.md").read_text(encoding="utf-8")
    for artifact_id in MANIFESTS:
        assert artifact_id in pack
    assert "## What Passed" in pack
    assert "## What Blocked" in pack
    assert "## What This Proves" in pack
    assert "## What This Does Not Prove" in pack


def test_hostile_batch_indexes_fail_closed(tmp_path) -> None:
    hostile_files = sorted(HOSTILE_BATCH_DIR.glob("*.json"))
    assert hostile_files
    for index in hostile_files:
        output_dir = tmp_path / index.stem
        status = main(["review", "batch", "run", "--index", str(index), "--output", str(output_dir), "--force"])
        assert status == 1, index.name
        state = _json(output_dir / "batch-machine-state.json")
        assert state["final_status"] == "BLOCKED", index.name
        assert state["block_reason"], index.name
        verify_status = main(["review", "batch", "verify", "--run", str(output_dir / "batch-machine-state.json")])
        if index.name in {"unexpected-blocked-pass-index.json", "unexpected-pass-index.json"}:
            assert verify_status == 1
        else:
            assert verify_status == 0


def test_expected_pass_artifact_blocking_causes_nonzero(tmp_path) -> None:
    index = _json(INDEX)
    hostile_manifest = ROOT / "examples" / "review" / "hostile" / "missing-telemetry-contract.json"
    index["artifacts"] = [{"artifact_id": "HO-DET-010", "manifest_path": str(hostile_manifest)}]
    index["expected_pass_artifacts"] = ["HO-DET-010"]
    index["expected_blocked_artifacts"] = []
    temp_index = tmp_path / "expected-pass-blocks.json"
    temp_index.write_text(json.dumps(index, indent=2), encoding="utf-8")

    output_dir = tmp_path / "batch"
    assert main(["review", "batch", "run", "--index", str(temp_index), "--output", str(output_dir), "--force"]) == 1
    state = _json(output_dir / "batch-machine-state.json")
    assert state["final_status"] == "BLOCKED"
    assert "expected PASS artifacts" in state["block_reason"]


def test_existing_single_review_demo_and_summarize_still_work(tmp_path) -> None:
    review_dir = tmp_path / "single"
    assert main(["review", "run", "--artifact", str(MANIFESTS["HO-DET-010"]), "--output", str(review_dir), "--force"]) == 0
    assert main(["review", "verify", "--run", str(review_dir / "machine-state.json")]) == 0
    assert main(["review", "summarize", "--run", str(review_dir / "machine-state.json")]) == 0

    demo_dir = tmp_path / "demo"
    assert main(["demo", "quickstart", "--output", str(demo_dir), "--force"]) == 0
    assert main(["demo", "verify", "--input", str(demo_dir / "run-summary.json")]) == 0


def test_batch_command_works_from_repo_root(tmp_path) -> None:
    output_dir = tmp_path / "repo-root-batch"
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "hoxline",
            "review",
            "batch",
            "run",
            "--index",
            "examples/review/multi-artifact-review-index-v1.json",
            "--output",
            str(output_dir),
            "--force",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (output_dir / "batch-machine-state.json").is_file()


def test_batch_generated_outputs_remain_ignored() -> None:
    result = subprocess.run(
        ["git", "check-ignore", "-q", ".hoxline/batch-runs/self-test/batch-machine-state.json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
