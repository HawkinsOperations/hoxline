from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from hoxline.cli import main
from hoxline.demo import EXPECTED_OUTPUTS, PRODUCT_LOOP, verify_demo_run_dir


ROOT = Path(__file__).resolve().parents[1]


def test_one_command_demo_generates_expected_outputs(tmp_path, capsys) -> None:
    output_dir = tmp_path / "demo-run"

    status = main(["demo", "quickstart", "--output", str(output_dir), "--force"])

    output = capsys.readouterr()
    assert status == 0
    assert "Artifact intake created" in output.out
    assert "Reviewer pack written" in output.out
    for name in EXPECTED_OUTPUTS:
        assert (output_dir / name).is_file()
    assert verify_demo_run_dir(output_dir) == []


def test_demo_run_summary_preserves_required_boundaries(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    summary = _json(output_dir / "run-summary.json")
    assert summary["product_loop"] == PRODUCT_LOOP
    assert summary["public_safe_status"] == "NOT_PUBLIC_SAFE"
    assert summary["human_review_required"] is True
    assert summary["ai_disposition_authority"] is False
    assert summary["endpoint_mutation"] is False
    assert summary["runtime_rerun"] is False
    assert summary["wazuh_mutation"] is False
    assert summary["private_evidence_committed"] is False
    assert summary["public_proof_promoted"] is False
    assert summary["lifetime_ledger_changed"] is False


def test_ho_det_010_telemetry_contract_is_represented(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    telemetry = _json(output_dir / "telemetry-contract-check.json")
    assert telemetry["required_source"] == "Windows Security EventChannel"
    assert telemetry["event_ids"] == [4720, 4725, 4726, 4732, 4733, 4738]
    assert telemetry["wazuh_rule_family"] == [910101, 910102, 910103]
    assert telemetry["result"] == "pass"
    assert telemetry["scope"] == "pass for fixture only"


def test_detection_fires_only_from_safe_fixture(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    signal = _json(output_dir / "synthetic-signal.json")
    validation = _json(output_dir / "validation-result.json")
    assert signal["source"] == "safe bundled fixture"
    assert signal["detection_fired"] is True
    assert signal["endpoint_mutation"] is False
    assert signal["backend_mutation"] is False
    assert validation["positive_cases"] == 1
    assert validation["negative_cases"] == 1
    assert validation["false_positive_negative_cases"] == 0


def test_proofcard_and_claim_authority_boundaries(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    proofcard = _json(output_dir / "proofcard.json")
    decision = _json(output_dir / "claim-authority.json")
    assert proofcard["public_safe_status"] == "NOT_PUBLIC_SAFE"
    assert proofcard["human_review_required"] is True
    assert proofcard["ai_disposition_authority"] is False
    assert proofcard["runtime_active"] is False
    assert proofcard["signal_observed"] is False
    blocked = {item["claim"] for item in decision["blocked_claims"]}
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


def test_reviewer_pack_has_required_reader_sections(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    text = (output_dir / "reviewer-pack.md").read_text(encoding="utf-8")
    assert "## What This Proves" in text
    assert "## What This Does Not Prove" in text
    assert "Evidence decides what can be claimed. AI does not." in text


def test_demo_outputs_do_not_emit_private_or_raw_terms(tmp_path) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    combined = "\n".join((output_dir / name).read_text(encoding="utf-8") for name in EXPECTED_OUTPUTS)
    forbidden = [
        "VM108",
        "VM9000",
        "ho-wazuh-01",
        "ho-wazuh-02",
        "raw Wazuh",
        "raw alert",
        "endpoint log",
        "generated password",
        "private packet",
        "private payload",
        "execution id",
        "command line",
    ]
    for term in forbidden:
        assert term.lower() not in combined.lower()


def test_demo_exits_nonzero_on_invalid_fixture(tmp_path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"artifact_id": "HO-DET-010"}) + "\n", encoding="utf-8")

    status = main(["demo", "quickstart", "--fixture", str(invalid), "--output", str(tmp_path / "run")])

    output = capsys.readouterr()
    assert status == 2
    assert "FAIL" in output.err


def test_demo_verify_cli_passes_generated_run(tmp_path, capsys) -> None:
    output_dir = tmp_path / "demo-run"
    assert main(["demo", "quickstart", "--output", str(output_dir), "--force"]) == 0

    status = main(["demo", "verify", "--input", str(output_dir / "run-summary.json")])

    output = capsys.readouterr()
    assert status == 0
    assert "PASS" in output.out


def test_demo_command_works_from_repo_root(tmp_path) -> None:
    output_dir = tmp_path / "repo-root-run"

    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "hoxline",
            "demo",
            "quickstart",
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
    assert (output_dir / "run-summary.json").is_file()


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
