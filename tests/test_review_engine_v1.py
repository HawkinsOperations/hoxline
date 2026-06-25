from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from hoxline.cli import main
from hoxline.review_engine import EXPECTED_PASS_OUTPUTS, STAGE_REGISTRY, verify_review_run


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "review" / "ho-det-010-artifact-manifest-v1.json"
HOSTILE_DIR = ROOT / "examples" / "review" / "hostile"


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_valid_ho_det_010_manifest_run_passes(tmp_path, capsys) -> None:
    output_dir = tmp_path / "review-run"

    status = main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"])

    output = capsys.readouterr()
    assert status == 0
    assert "Hoxline Review Engine v1" in output.out
    assert (output_dir / "machine-state.json").is_file()
    assert verify_review_run(output_dir / "machine-state.json") == []


def test_review_verify_passes_valid_machine_state(tmp_path, capsys) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    status = main(["review", "verify", "--run", str(output_dir / "machine-state.json")])

    output = capsys.readouterr()
    assert status == 0
    assert "PASS" in output.out


def test_all_expected_pass_outputs_exist(tmp_path) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    for name in EXPECTED_PASS_OUTPUTS:
        assert (output_dir / name).is_file(), name


def test_machine_state_stage_order_and_boundaries(tmp_path) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    state = _json(output_dir / "machine-state.json")
    assert [stage["stage_name"] for stage in state["stages"]] == STAGE_REGISTRY
    assert state["final_status"] == "PASS"
    assert all(stage["status"] == "PASS" for stage in state["stages"])
    assert state["public_safe_status"] == "NOT_PUBLIC_SAFE"
    assert state["human_review_required"] is True
    assert state["ai_disposition_authority"] is False
    assert state["endpoint_mutation"] is False
    assert state["wazuh_mutation"] is False
    assert state["runtime_proof"] is False
    assert state["public_proof_promoted"] is False
    assert state["lifetime_ledger_changed"] is False


def test_ho_det_010_event_and_rule_metadata_represented(tmp_path) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    telemetry = _json(output_dir / "telemetry-contract-check.json")
    manifest = _json(output_dir / "artifact-manifest.json")
    assert telemetry["required_source"] == "Windows Security EventChannel"
    assert telemetry["event_ids"] == [4720, 4725, 4726, 4732, 4733, 4738]
    assert telemetry["wazuh_rule_family"] == [910101, 910102, 910103]
    assert manifest["telemetry_contract"]["wazuh_rule_ids"] == [910101, 910102, 910103]


def test_synthetic_signal_only_and_blocked_claims_enforced(tmp_path) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    signal = _json(output_dir / "synthetic-signal.json")
    state = _json(output_dir / "machine-state.json")
    blocked = {item["claim"] for item in state["blocked_claims"]}
    assert signal["source"] == "safe bundled fixture"
    assert signal["detection_fired"] is True
    assert signal["endpoint_mutation"] is False
    for claim in {
        "production ready",
        "public-safe runtime proof",
        "SOCaaS deployed",
        "customer deployed",
        "autonomous SOC",
        "AI-approved disposition",
        "analyst-approved disposition",
        "final authorization",
        "case closure",
    }:
        assert claim in blocked


def test_reviewer_pack_has_required_sections(tmp_path) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    text = (output_dir / "reviewer-pack.md").read_text(encoding="utf-8")
    assert "## What This Proves" in text
    assert "## What This Does Not Prove" in text
    assert "## Stage Table" in text
    assert "## Final Claim Boundary" in text


def test_review_summarize_works(tmp_path, capsys) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    status = main(["review", "summarize", "--run", str(output_dir / "machine-state.json")])

    output = capsys.readouterr()
    assert status == 0
    assert "Hoxline Review Engine Summary" in output.out
    assert "Final status: `PASS`" in output.out


def test_invalid_manifest_path_exits_nonzero(tmp_path, capsys) -> None:
    missing = tmp_path / "missing.json"

    status = main(["review", "run", "--artifact", str(missing), "--output", str(tmp_path / "run")])

    output = capsys.readouterr()
    assert status == 2
    assert "FAIL" in output.err


def test_hostile_manifests_block(tmp_path) -> None:
    hostile_files = sorted(HOSTILE_DIR.glob("*.json"))
    assert hostile_files
    for manifest in hostile_files:
        output_dir = tmp_path / manifest.stem
        status = main(["review", "run", "--artifact", str(manifest), "--output", str(output_dir), "--force"])
        assert status == 1, manifest.name
        state = _json(output_dir / "machine-state.json")
        assert state["final_status"] == "BLOCKED", manifest.name
        assert state["block_reason"], manifest.name
        assert main(["review", "verify", "--run", str(output_dir / "machine-state.json")]) == 0



def test_blocked_outputs_do_not_echo_private_or_raw_field_names(tmp_path) -> None:
    hostile_files = [
        HOSTILE_DIR / "raw-alert-like-field-attempt.json",
        HOSTILE_DIR / "private-evidence-field-attempt.json",
        HOSTILE_DIR / "private-execution-id-field-attempt.json",
    ]
    for manifest in hostile_files:
        output_dir = tmp_path / manifest.stem
        assert main(["review", "run", "--artifact", str(manifest), "--output", str(output_dir), "--force"]) == 1
        combined = "\n".join(path.read_text(encoding="utf-8") for path in output_dir.glob("*.*"))
        assert "raw_alert" not in combined
        assert "private_execution_id" not in combined
        assert "private_evidence\"" not in combined
        assert "prohibited private/raw" in combined
def test_hostile_manifest_names_cover_required_block_classes() -> None:
    names = {path.name for path in HOSTILE_DIR.glob("*.json")}
    assert "missing-telemetry-contract.json" in names
    assert "missing-fixture-path.json" in names
    assert "unsafe-public-safe-status.json" in names
    assert "requested-production-claim.json" in names
    assert "requested-socaas-claim.json" in names
    assert "requested-customer-claim.json" in names
    assert "requested-autonomous-soc-claim.json" in names
    assert "requested-ai-approved-claim.json" in names
    assert "requested-analyst-approved-claim.json" in names
    assert "requested-final-authorization-claim.json" in names
    assert "requested-case-closure-claim.json" in names
    assert "private-evidence-field-attempt.json" in names
    assert "raw-alert-like-field-attempt.json" in names
    assert "private-execution-id-field-attempt.json" in names


def test_existing_demo_quickstart_and_verify_still_work(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0
    assert main(["demo", "verify", "--input", str(output_dir / "run-summary.json")]) == 0


def test_review_command_works_from_repo_root(tmp_path) -> None:
    output_dir = tmp_path / "repo-root-review-run"

    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "hoxline",
            "review",
            "run",
            "--artifact",
            "examples/review/ho-det-010-artifact-manifest-v1.json",
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
    assert (output_dir / "machine-state.json").is_file()


def test_local_generated_outputs_remain_ignored() -> None:
    result = subprocess.run(
        ["git", "check-ignore", "-q", ".hoxline/runs/self-test/machine-state.json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
