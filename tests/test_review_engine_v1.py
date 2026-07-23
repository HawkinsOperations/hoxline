from __future__ import annotations

import json
import base64
from copy import deepcopy
import hashlib
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

import pytest

from hoxline.cli import main
from hoxline.review_engine import (
    EXPECTED_PASS_OUTPUTS,
    STAGE_REGISTRY,
    ReviewBlocked,
    _validate_generated_output_security,
    _validate_no_private_markers,
    _validate_recursive_boundaries,
    verify_review_run,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "review" / "ho-det-010-artifact-manifest-v1.json"
HOSTILE_DIR = ROOT / "examples" / "review" / "hostile"


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _integrity(value: dict[str, object], field: str = "state_integrity_digest") -> str:
    return hashlib.sha256(
        json.dumps(
            {key: item for key, item in value.items() if key != field},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


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
    assert telemetry["event_ids"] == [4732, 4733]
    assert telemetry["wazuh_rule_family"] == [910101, 910102, 910103]
    assert manifest["telemetry_contract"]["wazuh_rule_ids"] == [910101, 910102, 910103]


def test_controlled_test_signal_only_and_blocked_claims_enforced(tmp_path) -> None:
    output_dir = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output_dir), "--force"]) == 0

    signal = _json(output_dir / "controlled-test-signal.json")
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
        assert "input rejected by strict-structure boundary" in combined
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


def test_duplicate_and_unknown_manifest_fields_fail_closed(tmp_path) -> None:
    text = MANIFEST.read_text(encoding="utf-8")
    duplicate = text.replace(
        '"ai_disposition_authority": false,',
        '"ai_disposition_authority": false, "AI_Disposition_Authority": true,',
        1,
    )
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(duplicate, encoding="utf-8")
    duplicate_out = tmp_path / "duplicate-run"
    assert main(["review", "run", "--artifact", str(duplicate_path), "--output", str(duplicate_out), "--force"]) == 1
    assert _json(duplicate_out / "machine-state.json")["final_status"] == "BLOCKED"

    unknown = _json(MANIFEST)
    unknown["extension"] = {"harmless": True}
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
    unknown_out = tmp_path / "unknown-run"
    assert main(["review", "run", "--artifact", str(unknown_path), "--output", str(unknown_out), "--force"]) == 1
    assert _json(unknown_out / "machine-state.json")["block_reason"] == "input rejected by strict-structure boundary"


def test_nested_and_encoded_authority_laundering_fails_closed(tmp_path) -> None:
    def encoded(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    encoded_claims = [
        "public_safe_approved",
        "analyst%2Dapproved%20disposition",
        "final%2520authorization",
        base64.urlsafe_b64encode(b"case closure").decode("ascii"),
        encoded(b"case closure!"),
        encoded(b"final authorization!"),
        encoded(encoded(b"AI-approved disposition").encode("ascii")),
        encoded(b"private execution ID"),
        encoded(b"C:\\private\\fixture.json"),
        '{"nested":{"ai_approved":true}}',
    ]
    for index, claim in enumerate(encoded_claims):
        manifest = _json(MANIFEST)
        manifest["field_mapping"] = {"nested": claim}
        path = tmp_path / f"encoded-{index}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        output = tmp_path / f"encoded-{index}"
        assert main(["review", "run", "--artifact", str(path), "--output", str(output), "--force"]) == 1
        state = _json(output / "machine-state.json")
        assert state["block_reason"] in {
            "input rejected by claim-authority boundary",
            "input rejected by private-data boundary",
            "input rejected by path-containment boundary",
        }
        combined = "\n".join(item.read_text(encoding="utf-8") for item in output.glob("*.json"))
        assert claim not in combined

    manifest = _json(MANIFEST)
    manifest["field_mapping"] = {"nested_authority": {"approvedByAnalyst": True}}
    path = tmp_path / "nested-authority.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "nested-authority"
    assert main(["review", "run", "--artifact", str(path), "--output", str(output), "--force"]) == 1

    canonical = encoded(b"case closure!")
    noncanonical = canonical[:-1] + chr(ord(canonical[-1]) + 1)
    for index, hostile_value in enumerate((noncanonical, "eyJaaaaaa")):
        manifest = _json(MANIFEST)
        manifest["field_mapping"] = {"encoded": hostile_value}
        path = tmp_path / f"invalid-base64-{index}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        output = tmp_path / f"invalid-base64-{index}"
        assert main(["review", "run", "--artifact", str(path), "--output", str(output), "--force"]) == 1


def test_nfkc_security_keys_and_normalized_collisions_fail_closed(tmp_path) -> None:
    attacks = [
        {"ｐｕｂｌｉｃ＿ｓａｆｅ": True},
        {"ａｉ＿ｄｉｓｐｏｓｉｔｉｏｎ＿ａｕｔｈｏｒｉｔｙ": True},
        {"public_ｓａｆｅ": True},
        {"public_safe": False, "ｐｕｂｌｉｃ＿ｓａｆｅ": True},
    ]
    for index, attack in enumerate(attacks):
        manifest = _json(MANIFEST)
        manifest["field_mapping"] = attack
        path = tmp_path / f"nfkc-{index}.json"
        path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        output = tmp_path / f"nfkc-{index}"
        assert main(["review", "run", "--artifact", str(path), "--output", str(output), "--force"]) == 1
        assert _json(output / "machine-state.json")["final_status"] == "BLOCKED"


def test_generic_negation_cannot_launder_an_adjacent_positive_claim() -> None:
    attacks = [
        "pending documentation, production is live",
        "unsupported note \u2014 customer environment deployed",
        "future issue: signal was observed",
        "missing receipt while production is live",
        "no proof currently, customer environment deployed",
        "not approved / production is live",
    ]
    for attack in attacks:
        with pytest.raises(ReviewBlocked):
            _validate_generated_output_security({"note": attack}, "hostile generated output")

    for bounded in (
        "This does not prove production readiness, customer deployment, or signal-observed proof.",
        "Production readiness is unsupported.",
        "Claims block customer deployment.",
    ):
        _validate_generated_output_security({"note": bounded}, "bounded generated output")

    with pytest.raises(ReviewBlocked):
        _validate_generated_output_security(
            {"extra": "not_public_safe; production is live"},
            "hostile generated output",
        )


def test_compositional_promotion_keys_and_embedded_structures_fail_closed() -> None:
    keys = [
        "production_live",
        "customer_deployment",
        "socaas_deployment",
        "runtime_status",
        "signal_status",
        "approval_status",
        "closure_status",
        "case_status",
        "public_safe_runtime",
        "final_authorized",
        "%70roduction_live",
        "production_live_flag",
        "customer_deployment_enabled",
        "runtime_status_value",
        "signal_observed_state",
        "public_safe_runtime_flag",
        "final_authorized_flag",
        "case_closed_value",
        "ai_approval_state",
        "ai_disposition_enabled",
        "analyst_authority_state",
        "analyst_approval_value",
        "approved_by_analyst_flag",
    ]
    for key in keys:
        payload = {"metadata": {key: True}}
        encoded_json = json.dumps(payload, separators=(",", ":"))
        variants = [
            payload,
            encoded_json,
            quote(encoded_json, safe=""),
            base64.urlsafe_b64encode(encoded_json.encode("utf-8")).decode("ascii").rstrip("="),
        ]
        for variant in variants:
            with pytest.raises(ReviewBlocked):
                _validate_recursive_boundaries({"extension": variant}, "hostile input")
            with pytest.raises(ReviewBlocked):
                _validate_generated_output_security({"extension": variant}, "hostile output")

    _validate_recursive_boundaries(
        {"metadata": {"production_live": False, "case_status": "BLOCKED"}},
        "bounded input",
    )
    _validate_generated_output_security(
        {"metadata": {"production_live": False, "case_status": "BLOCKED"}},
        "bounded output",
    )


def test_private_marker_keys_fail_closed_through_recursive_encodings() -> None:
    keys = [
        "raw_wazuh",
        "private_evidence",
        "%72aw_wazuh",
        "%2572aw_wazuh",
        "%70rivate_evidence",
        "%2570rivate_evidence",
    ]
    for key in keys:
        payload = {"metadata": {key: "hostile marker"}}
        encoded_json = json.dumps(payload, separators=(",", ":"))
        variants = [
            payload,
            encoded_json,
            quote(encoded_json, safe=""),
            quote(quote(encoded_json, safe=""), safe=""),
            base64.urlsafe_b64encode(encoded_json.encode("utf-8")).decode("ascii").rstrip("="),
        ]
        for variant in variants:
            with pytest.raises(ReviewBlocked):
                _validate_no_private_markers({"extension": variant}, "hostile private input")

    for value in (
        "raw_wazuh",
        "private_evidence",
        "endpoint_log",
        "generated_password",
        "private_payload",
        "raw-alert",
    ):
        for variant in (
            value,
            quote(value, safe=""),
            base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("="),
        ):
            with pytest.raises(ReviewBlocked):
                _validate_no_private_markers({"note": variant}, "hostile private value")


def test_encoded_mixed_and_drive_relative_paths_fail_closed(tmp_path) -> None:
    attacks = [
        r"C:relative\fixture.json",
        r"C:\private\fixture.json",
        r"\\host\share\fixture.json",
        "/tmp/fixture.json",
        r"examples/review\../private.json",
        "examples/review/%2e%2e/private.json",
        "examples/review/%252e%252e/private.json",
        "file:///C:/private/fixture.json",
    ]
    for index, attack in enumerate(attacks):
        manifest = _json(MANIFEST)
        manifest["fixture_paths"]["positive"] = attack
        path = tmp_path / f"path-{index}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        output = tmp_path / f"path-{index}"
        assert main(["review", "run", "--artifact", str(path), "--output", str(output), "--force"]) == 1
        state = _json(output / "machine-state.json")
        assert state["block_reason"] == "input rejected by path-containment boundary"
        assert attack not in json.dumps(state)


def test_single_replay_binds_every_output_and_machine_state_field(tmp_path) -> None:
    output = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output), "--force"]) == 0
    state_path = output / "machine-state.json"
    baseline = _json(state_path)

    for field, value in {
        "final_status": "BLOCKED",
        "public_safe_status": "PUBLIC_SAFE",
        "human_review_required": False,
        "ai_disposition_authority": True,
        "next_gate": "case closure",
        "source_manifest_digest": "0" * 64,
    }.items():
        hostile = deepcopy(baseline)
        hostile[field] = value
        state_path.write_text(json.dumps(hostile), encoding="utf-8")
        assert verify_review_run(state_path), field
    state_path.write_text(json.dumps(baseline), encoding="utf-8")

    for name in baseline["output_digests"]:
        path = output / name
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        assert any("digest mismatch" in error for error in verify_review_run(state_path)), name
        path.write_bytes(original)
    assert verify_review_run(state_path) == []


def test_single_replay_rejects_rehashed_output_and_guardrail_laundering(tmp_path) -> None:
    output = tmp_path / "review-run"
    assert main(["review", "run", "--artifact", str(MANIFEST), "--output", str(output), "--force"]) == 0
    state_path = output / "machine-state.json"
    baseline = _json(state_path)

    for name in baseline["output_digests"]:
        path = output / name
        original = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            hostile = json.loads(original)
            hostile["replay_extension"] = {"approvedByAnalyst": True}
            path.write_text(json.dumps(hostile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            path.write_text(original + "\nproduction ready\n", encoding="utf-8")
        state = deepcopy(baseline)
        state["output_digests"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        state["state_integrity_digest"] = _integrity(state)
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert verify_review_run(state_path), name
        path.write_text(original, encoding="utf-8")
        state_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for mutator in (
        lambda state: state["outputs"].update({"proofcard_markdown": "proofcard.json"}),
        lambda state: state["stages"][0].update({"proof_boundary": "production ready"}),
        lambda state: state["blocked_claims"][0].update({"safer_wording": "production ready"}),
        lambda state: state.update({"proof_boundary": "production ready"}),
        lambda state: state.update({"replay_extension": "bounded-looking extra field"}),
        lambda state: state.update({"created_at": "2099-01-01T00:00:00Z"}),
    ):
        hostile_state = deepcopy(baseline)
        mutator(hostile_state)
        hostile_state["state_integrity_digest"] = _integrity(hostile_state)
        state_path.write_text(json.dumps(hostile_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert verify_review_run(state_path)

    state_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_review_run(state_path) == []


def test_blocked_replay_rejects_rehashed_output_and_role_laundering(tmp_path) -> None:
    manifest = _json(MANIFEST)
    manifest["requested_claims"] = {"nested": {"approvedByAnalyst": True}}
    manifest_path = tmp_path / "blocked-input.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "blocked-run"
    assert main(["review", "run", "--artifact", str(manifest_path), "--output", str(output), "--force"]) == 1
    state_path = output / "machine-state.json"
    baseline = _json(state_path)
    assert baseline["final_status"] == "BLOCKED"
    assert verify_review_run(state_path) == []

    for name in baseline["output_digests"]:
        path = output / name
        original = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            hostile = json.loads(original)
            hostile["replay_extension"] = {"publicSafe": True}
            path.write_text(json.dumps(hostile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            path.write_text(original + "\nfinal authorization\n", encoding="utf-8")
        state = deepcopy(baseline)
        state["output_digests"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        state["state_integrity_digest"] = _integrity(state)
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert verify_review_run(state_path), name
        path.write_text(original, encoding="utf-8")
        state_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    hostile_state = deepcopy(baseline)
    hostile_state["outputs"]["blocked_review"] = "run-summary.json"
    hostile_state["state_integrity_digest"] = _integrity(hostile_state)
    state_path.write_text(json.dumps(hostile_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_review_run(state_path)

    hostile_state = deepcopy(baseline)
    hostile_state["replay_extension"] = "bounded-looking extra field"
    hostile_state["state_integrity_digest"] = _integrity(hostile_state)
    state_path.write_text(json.dumps(hostile_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_review_run(state_path)

    hostile_state = deepcopy(baseline)
    hostile_state["created_at"] = "2099-01-01T00:00:00Z"
    hostile_state["state_integrity_digest"] = _integrity(hostile_state)
    state_path.write_text(json.dumps(hostile_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_review_run(state_path)

    state_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_review_run(state_path) == []
