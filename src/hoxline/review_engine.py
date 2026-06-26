from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
from typing import Any

from .demo import (
    BLOCKED_CLAIM_FAMILIES,
    PRODUCT,
    PUBLIC_SAFE_STATUS,
    REQUIRED_EVENT_IDS,
    REQUIRED_WAZUH_RULE_FAMILY,
    SAFE_ALLOWED_CLAIM,
)

ENGINE_VERSION = "hoxline-review-engine-v1"
BATCH_ENGINE_VERSION = "hoxline-review-batch-engine-v1"
MANIFEST_VERSION = "artifact-manifest-v1"
MACHINE_STATE_VERSION = "review-machine-state-v1"
BATCH_INDEX_VERSION = "multi-artifact-review-index-v1"
BATCH_MACHINE_STATE_VERSION = "batch-machine-state-v1"
ARTIFACT_ID = "HO-DET-010"
EXPECTED_PASS_OUTPUTS = [
    "artifact-manifest.json",
    "intake.json",
    "evidence-graph.json",
    "telemetry-contract-check.json",
    "validation-result.json",
    "synthetic-signal.json",
    "enrichment.json",
    "triage-summary.md",
    "proofcard.json",
    "proofcard.md",
    "claim-authority.json",
    "reviewer-pack.md",
    "machine-state.json",
    "run-summary.json",
]
EXPECTED_BLOCKED_OUTPUTS = ["artifact-manifest.json", "machine-state.json", "blocked-review.md", "run-summary.json"]
BATCH_EXPECTED_OUTPUTS = [
    "input-index.json",
    "batch-machine-state.json",
    "batch-summary.md",
    "batch-reviewer-pack.md",
    "batch-run-summary.json",
]
STAGE_REGISTRY = [
    "artifact_intake",
    "evidence_graph",
    "telemetry_contract_check",
    "controlled_validation",
    "synthetic_signal",
    "enrichment",
    "triage",
    "proofcard",
    "claim_authority",
    "reviewer_pack",
    "machine_state",
]
REQUIRED_MANIFEST_FIELDS = [
    "manifest_version",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_family",
    "source_owner",
    "validation_owner",
    "platform_owner",
    "proof_owner",
    "product_owner",
    "telemetry_contract",
    "fixture_paths",
    "expected_event_ids",
    "expected_rule_ids",
    "allowed_claim_class",
    "requested_claims",
    "blocked_claim_classes",
    "public_safe_status",
    "human_review_required",
    "ai_disposition_authority",
    "proof_boundary",
    "runtime_boundary",
    "signal_boundary",
    "next_gate",
]
PROHIBITED_CLAIM_PATTERNS = {
    "public-safe runtime proof": re.compile(r"public[- ]safe runtime proof", re.IGNORECASE),
    "production": re.compile(r"\bproduction(?:[- ]ready| readiness)?\b", re.IGNORECASE),
    "customer deployment": re.compile(r"\bcustomer(?:[- ]deployed| deployment)?\b", re.IGNORECASE),
    "SOCaaS deployment": re.compile(r"\bSOCaaS(?:[- ]ready| deployed| deployment)?\b", re.IGNORECASE),
    "autonomous SOC": re.compile(r"\bautonomous SOC\b", re.IGNORECASE),
    "AI-approved disposition": re.compile(r"\bAI[- ]approved\b", re.IGNORECASE),
    "analyst-approved disposition": re.compile(r"\banalyst[- ]approved\b", re.IGNORECASE),
    "final authorization": re.compile(r"\bfinal authorization\b", re.IGNORECASE),
    "case closure": re.compile(r"\bcase closure\b|\bcase[- ]closed\b", re.IGNORECASE),
}
PRIVATE_FIELD_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"private[_-]?evidence",
        r"raw[_-]?(?:wazuh|alert)",
        r"endpoint[_-]?log",
        r"generated[_-]?password",
        r"private[_-]?execution[_-]?id",
        r"private[_-]?packet",
        r"private[_-]?payload",
        r"\bsecret\b",
        r"\btoken\b",
        r"\bpassword\b",
    )
]
PRIVATE_VALUE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bVM108\b",
        r"\bVM9000\b",
        r"\bho-wazuh-0[12]\b",
        r"\braw Wazuh\b",
        r"\braw alert\b",
        r"\bendpoint log\b",
        r"\bgenerated password\b",
        r"\bprivate execution ID\b",
    )
]


class ReviewEngineError(ValueError):
    """Raised when review engine input or output fails closed."""


class ReviewBlocked(ReviewEngineError):
    """Raised for governed BLOCKED review outcomes."""


def default_run_dir(repo_root: Path | None = None) -> Path:
    root = repo_root or Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / ".hoxline" / "runs" / stamp


def default_batch_dir(repo_root: Path | None = None) -> Path:
    root = repo_root or Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / ".hoxline" / "batch-runs" / stamp


def run_review(artifact_path: Path, output_dir: Path | None = None, force: bool = False, repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or Path(__file__).resolve().parents[2]
    out_dir = output_dir or default_run_dir(Path.cwd())
    manifest_path = _resolve_path(artifact_path, Path.cwd())
    manifest: dict[str, Any] = {}
    try:
        manifest = _load_json(manifest_path)
        _validate_manifest(manifest, manifest_path, root)
        fixture_paths = _fixture_paths(manifest, root)
        review_outputs = _build_review_outputs(manifest, fixture_paths)
        run = _build_pass_run(manifest, manifest_path, out_dir, review_outputs)
        _write_pass_outputs(out_dir, run, force)
        return run
    except ReviewBlocked as exc:
        run = _build_blocked_run(manifest, manifest_path, out_dir, str(exc))
        _write_blocked_outputs(out_dir, run, force)
        return run


def verify_review_run(machine_state_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        state = _load_json(machine_state_path)
    except (OSError, ReviewEngineError) as exc:
        return [str(exc)]
    run_dir = machine_state_path.parent
    final_status = state.get("final_status")
    if final_status not in {"PASS", "BLOCKED"}:
        errors.append("machine-state final_status must be PASS or BLOCKED")
    if state.get("schema_version") != MACHINE_STATE_VERSION:
        errors.append(f"machine-state schema_version must be {MACHINE_STATE_VERSION}")
    if state.get("engine_version") != ENGINE_VERSION:
        errors.append(f"machine-state engine_version must be {ENGINE_VERSION}")
    if [stage.get("stage_name") for stage in state.get("stages", [])] != STAGE_REGISTRY:
        errors.append("machine-state stages must match review engine stage registry")
    expected_outputs = EXPECTED_PASS_OUTPUTS if final_status == "PASS" else EXPECTED_BLOCKED_OUTPUTS
    for name in expected_outputs:
        if not (run_dir / name).is_file():
            errors.append(f"missing output file: {name}")
    for field, expected in {
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "private_evidence_committed": False,
    }.items():
        if state.get(field) != expected:
            errors.append(f"machine-state field {field} must be {expected!r}")
    if final_status == "PASS":
        non_pass = [stage["stage_name"] for stage in state["stages"] if stage.get("status") != "PASS"]
        if non_pass:
            errors.append(f"PASS run has non-PASS stages: {', '.join(non_pass)}")
        _verify_pass_outputs(run_dir, state, errors)
    if final_status == "BLOCKED" and not state.get("block_reason"):
        errors.append("BLOCKED run must include block_reason")
    private_hits = _private_output_hits(run_dir)
    if private_hits:
        errors.append(f"private/raw markers found in review outputs: {', '.join(private_hits)}")
    return errors


def summarize_review_run(machine_state_path: Path) -> str:
    state = _load_json(machine_state_path)
    lines = [
        "# Hoxline Review Engine Summary",
        "",
        f"Run: `{state.get('run_id')}`",
        f"Artifact: `{state.get('artifact_id')}`",
        f"Final status: `{state.get('final_status')}`",
        f"public_safe_status: `{state.get('public_safe_status')}`",
        f"human_review_required: `{str(state.get('human_review_required')).lower()}`",
        f"ai_disposition_authority: `{str(state.get('ai_disposition_authority')).lower()}`",
        "",
        "## Stages",
        "",
    ]
    for stage in state.get("stages", []):
        lines.append(f"- `{stage['stage_name']}`: `{stage['status']}` - {stage['summary']}")
    if state.get("block_reason"):
        lines.extend(["", f"Blocked reason: {state['block_reason']}"])
    lines.extend(["", f"Next gate: `{state.get('next_gate')}`", ""])
    return "\n".join(lines)


def render_run_console(run: dict[str, Any]) -> str:
    state = run["machine_state"]
    lines = [
        "Hoxline Review Engine v1",
        f"Output: {run['output_dir']}",
        f"Machine state: {Path(run['output_dir']) / 'machine-state.json'}",
        "",
    ]
    for index, stage in enumerate(state["stages"], start=1):
        lines.append(f"{index}. {stage['stage_name']}: {stage['status']} - {stage['summary']}")
    if state["final_status"] == "PASS":
        lines.extend(
            [
                "",
                f"Allowed claim: {state['allowed_claim']}",
                f"Reviewer pack: {Path(run['output_dir']) / 'reviewer-pack.md'}",
            ]
        )
    else:
        lines.extend(["", f"Blocked: {state['block_reason']}", f"Blocked review: {Path(run['output_dir']) / 'blocked-review.md'}"])
    lines.extend(
        [
            "",
            "Boundary: fixture-only; NOT_PUBLIC_SAFE; human review required; AI disposition authority false; not runtime proof.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_batch_review(index_path: Path, output_dir: Path | None = None, force: bool = False, repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or Path(__file__).resolve().parents[2]
    out_dir = output_dir or default_batch_dir(Path.cwd())
    resolved_index = _resolve_path(index_path, Path.cwd())
    index: dict[str, Any] = {}
    try:
        index = _load_json(resolved_index)
        _validate_batch_index(index, resolved_index, root)
        _prepare_output_dir(out_dir, force)
        artifacts_root = out_dir / "artifacts"
        artifacts_root.mkdir(parents=True, exist_ok=True)
        _write_file_map(out_dir, {"input-index.json": index})

        artifact_runs: list[dict[str, Any]] = []
        for artifact_entry in index["artifacts"]:
            artifact_id = artifact_entry["artifact_id"]
            manifest_path = _resolve_path(Path(artifact_entry["manifest_path"]), root)
            artifact_out = artifacts_root / artifact_id
            run = run_review(manifest_path, artifact_out, force=True, repo_root=root)
            state = run["machine_state"]
            artifact_runs.append(
                {
                    "artifact_id": artifact_id,
                    "manifest_path": str(manifest_path),
                    "output_dir": str(artifact_out.resolve()),
                    "machine_state": str((artifact_out / "machine-state.json").resolve()),
                    "reviewer_pack": str((artifact_out / "reviewer-pack.md").resolve()) if state["final_status"] == "PASS" else None,
                    "blocked_review": str((artifact_out / "blocked-review.md").resolve()) if state["final_status"] == "BLOCKED" else None,
                    "run_summary": str((artifact_out / "run-summary.json").resolve()),
                    "final_status": state["final_status"],
                    "block_reason": state.get("block_reason"),
                    "public_safe_status": state["public_safe_status"],
                    "human_review_required": state["human_review_required"],
                    "ai_disposition_authority": state["ai_disposition_authority"],
                    "endpoint_mutation": state["endpoint_mutation"],
                    "wazuh_mutation": state["wazuh_mutation"],
                    "runtime_proof": state["runtime_proof"],
                    "private_evidence_committed": state["private_evidence_committed"],
                    "public_proof_promoted": state["public_proof_promoted"],
                    "lifetime_ledger_changed": state["lifetime_ledger_changed"],
                }
            )

        batch_state = _batch_machine_state(index, resolved_index, out_dir, artifact_runs)
        expectation_errors = _batch_expectation_errors(batch_state)
        if expectation_errors:
            batch_state["final_status"] = "BLOCKED"
            batch_state["block_reason"] = "; ".join(expectation_errors)
        _write_batch_outputs(out_dir, index, batch_state)
        return {"output_dir": str(out_dir), "index": index, "batch_machine_state": batch_state}
    except ReviewBlocked as exc:
        _prepare_output_dir(out_dir, force)
        safe_index = _safe_blocked_index(index, resolved_index, str(exc))
        batch_state = _blocked_batch_machine_state(safe_index, resolved_index, out_dir, str(exc))
        _write_batch_outputs(out_dir, safe_index, batch_state)
        return {"output_dir": str(out_dir), "index": safe_index, "batch_machine_state": batch_state}


def verify_batch_run(batch_machine_state_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        state = _load_json(batch_machine_state_path)
    except (OSError, ReviewEngineError) as exc:
        return [str(exc)]
    run_dir = batch_machine_state_path.parent
    if state.get("schema_version") != BATCH_MACHINE_STATE_VERSION:
        errors.append(f"batch-machine-state schema_version must be {BATCH_MACHINE_STATE_VERSION}")
    if state.get("engine_version") != BATCH_ENGINE_VERSION:
        errors.append(f"batch-machine-state engine_version must be {BATCH_ENGINE_VERSION}")
    if state.get("final_status") not in {"PASS", "MIXED", "BLOCKED"}:
        errors.append("batch-machine-state final_status must be PASS, MIXED, or BLOCKED")
    for name in BATCH_EXPECTED_OUTPUTS:
        if not (run_dir / name).is_file():
            errors.append(f"missing batch output file: {name}")
    for field, expected in {
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "private_evidence_committed": False,
        "website_changed": False,
    }.items():
        if state.get(field) != expected:
            errors.append(f"batch-machine-state field {field} must be {expected!r}")
    if state.get("final_status") == "BLOCKED" and not state.get("block_reason"):
        errors.append("BLOCKED batch run must include block_reason")
    artifacts = state.get("artifacts", [])
    if state.get("final_status") != "BLOCKED" and not artifacts:
        errors.append("non-BLOCKED batch run must include artifact states")
    for artifact in artifacts:
        artifact_id = artifact.get("artifact_id", "UNKNOWN")
        state_path = Path(str(artifact.get("machine_state", "")))
        if not state_path.is_absolute():
            state_path = run_dir / state_path
        if not state_path.is_file():
            errors.append(f"missing artifact machine-state for {artifact_id}")
            continue
        artifact_errors = verify_review_run(state_path)
        errors.extend(f"{artifact_id}: {error}" for error in artifact_errors)
        if artifact.get("public_safe_status") != PUBLIC_SAFE_STATUS:
            errors.append(f"{artifact_id}: public_safe_status must remain NOT_PUBLIC_SAFE")
        for false_field in ("endpoint_mutation", "wazuh_mutation", "runtime_proof", "public_proof_promoted", "lifetime_ledger_changed", "private_evidence_committed"):
            if artifact.get(false_field) is not False:
                errors.append(f"{artifact_id}: {false_field} must be false")
    errors.extend(_batch_expectation_errors(state))
    private_hits = _private_output_hits(run_dir)
    if private_hits:
        errors.append(f"private/raw markers found in batch outputs: {', '.join(private_hits)}")
    return errors


def render_batch_console(batch: dict[str, Any]) -> str:
    state = batch["batch_machine_state"]
    lines = [
        "Hoxline Review Engine v1 batch",
        f"Output: {batch['output_dir']}",
        f"Batch machine state: {Path(batch['output_dir']) / 'batch-machine-state.json'}",
        "",
        f"Final status: {state['final_status']}",
    ]
    if state.get("block_reason"):
        lines.append(f"Blocked: {state['block_reason']}")
    lines.extend(["", "Artifacts:"])
    for artifact in state.get("artifacts", []):
        detail = f" - {artifact.get('block_reason')}" if artifact.get("block_reason") else ""
        lines.append(f"- {artifact['artifact_id']}: {artifact['final_status']}{detail}")
    lines.extend(
        [
            "",
            f"Batch reviewer pack: {Path(batch['output_dir']) / 'batch-reviewer-pack.md'}",
            "Boundary: fixture-only; NOT_PUBLIC_SAFE; human review required; AI disposition authority false; not runtime proof.",
        ]
    )
    return "\n".join(lines) + "\n"


def _validate_batch_index(index: dict[str, Any], index_path: Path, repo_root: Path) -> None:
    required = [
        "index_version",
        "index_id",
        "description",
        "artifacts",
        "expected_pass_artifacts",
        "expected_blocked_artifacts",
        "batch_claim_boundary",
        "public_safe_status",
        "human_review_required",
        "ai_disposition_authority",
        "runtime_boundary",
        "signal_boundary",
        "proof_boundary",
        "generated_outputs",
        "next_gate",
    ]
    for field in required:
        if field not in index:
            raise ReviewBlocked(f"batch index missing required field: {field}")
    if index["index_version"] != BATCH_INDEX_VERSION:
        raise ReviewBlocked(f"index_version must be {BATCH_INDEX_VERSION}")
    if index.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        raise ReviewBlocked("batch public_safe_status must remain NOT_PUBLIC_SAFE")
    if index.get("human_review_required") is not True:
        raise ReviewBlocked("batch human_review_required must be true")
    if index.get("ai_disposition_authority") is not False:
        raise ReviewBlocked("batch ai_disposition_authority must be false")
    _validate_claims({"requested_claims": [index.get("batch_claim_boundary", "")], "blocked_claim_classes": BLOCKED_CLAIM_FAMILIES})
    _validate_no_private_markers(index, "batch index")
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReviewBlocked("batch index artifacts must be a non-empty list")
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ReviewBlocked("batch index artifact entries must be objects")
        artifact_id = item.get("artifact_id")
        if not artifact_id:
            raise ReviewBlocked("batch index artifact entry missing artifact_id")
        if artifact_id in seen:
            raise ReviewBlocked(f"duplicate artifact_id in batch index: {artifact_id}")
        seen.add(str(artifact_id))
        manifest_path = item.get("manifest_path")
        if not manifest_path:
            raise ReviewBlocked(f"batch index artifact {artifact_id} missing manifest_path")
        resolved = _resolve_path(Path(str(manifest_path)), repo_root)
        if not resolved.is_file():
            raise ReviewBlocked(f"batch index manifest path missing for {artifact_id}: {resolved}")
        allowed_root = (repo_root / "examples" / "review").resolve()
        if not _is_relative_to(resolved.resolve(), allowed_root):
            raise ReviewBlocked(f"batch index manifest path outside examples/review for {artifact_id}")


def _batch_machine_state(index: dict[str, Any], index_path: Path, output_dir: Path, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = {artifact["final_status"] for artifact in artifacts}
    final_status = "PASS" if statuses == {"PASS"} else "MIXED" if statuses <= {"PASS", "BLOCKED"} else "BLOCKED"
    return {
        "schema_version": BATCH_MACHINE_STATE_VERSION,
        "engine_version": BATCH_ENGINE_VERSION,
        "batch_id": output_dir.name,
        "index_id": index.get("index_id"),
        "index_path": str(index_path),
        "artifacts": artifacts,
        "expected_pass_artifacts": list(index.get("expected_pass_artifacts", [])),
        "expected_blocked_artifacts": list(index.get("expected_blocked_artifacts", [])),
        "final_status": final_status,
        "block_reason": None,
        "batch_claim_boundary": index.get("batch_claim_boundary"),
        "proof_boundary": index.get("proof_boundary"),
        "runtime_boundary": index.get("runtime_boundary"),
        "signal_boundary": index.get("signal_boundary"),
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "private_evidence_committed": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "website_changed": False,
        "outputs": BATCH_EXPECTED_OUTPUTS,
        "next_gate": index.get("next_gate"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "product": PRODUCT,
    }


def _blocked_batch_machine_state(index: dict[str, Any], index_path: Path, output_dir: Path, block_reason: str) -> dict[str, Any]:
    state = _batch_machine_state(index, index_path, output_dir, [])
    state["final_status"] = "BLOCKED"
    state["block_reason"] = block_reason
    return state


def _batch_expectation_errors(state: dict[str, Any]) -> list[str]:
    artifacts = state.get("artifacts", [])
    actual_pass = {artifact["artifact_id"] for artifact in artifacts if artifact.get("final_status") == "PASS"}
    actual_blocked = {artifact["artifact_id"] for artifact in artifacts if artifact.get("final_status") == "BLOCKED"}
    expected_pass = set(state.get("expected_pass_artifacts", []))
    expected_blocked = set(state.get("expected_blocked_artifacts", []))
    errors: list[str] = []
    if expected_pass != actual_pass:
        errors.append(f"expected PASS artifacts {sorted(expected_pass)} but saw {sorted(actual_pass)}")
    if expected_blocked != actual_blocked:
        errors.append(f"expected BLOCKED artifacts {sorted(expected_blocked)} but saw {sorted(actual_blocked)}")
    return errors


def _write_batch_outputs(output_dir: Path, index: dict[str, Any], state: dict[str, Any]) -> None:
    _write_file_map(
        output_dir,
        {
            "input-index.json": index,
            "batch-machine-state.json": state,
            "batch-summary.md": _batch_summary_markdown(state),
            "batch-reviewer-pack.md": _batch_reviewer_pack(state),
            "batch-run-summary.json": _batch_run_summary(state),
        },
    )


def _batch_summary_markdown(state: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Multi-Artifact Review Summary",
        "",
        f"Batch: `{state.get('batch_id')}`",
        f"Final status: `{state.get('final_status')}`",
        f"public_safe_status: `{state.get('public_safe_status')}`",
        f"human_review_required: `{str(state.get('human_review_required')).lower()}`",
        f"ai_disposition_authority: `{str(state.get('ai_disposition_authority')).lower()}`",
        "",
        "## Artifacts",
        "",
    ]
    for artifact in state.get("artifacts", []):
        detail = f" - {artifact.get('block_reason')}" if artifact.get("block_reason") else ""
        lines.append(f"- `{artifact['artifact_id']}`: `{artifact['final_status']}`{detail}")
    if state.get("block_reason"):
        lines.extend(["", f"Batch block reason: {state['block_reason']}"])
    lines.extend(["", "## Boundary", "", "This batch is fixture-only, local, deterministic, NOT_PUBLIC_SAFE, human-review-required, and not runtime proof.", ""])
    return "\n".join(lines)


def _batch_reviewer_pack(state: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Multi-Artifact Reviewer Pack",
        "",
        "## What This Is",
        "",
        "A deterministic local batch review of governed artifact manifests through Hoxline Review Engine v1.",
        "",
        "## What Happened",
        "",
        f"Batch `{state.get('batch_id')}` reviewed the declared artifact set and wrote one machine-state per artifact plus this aggregate state.",
        "",
        "## Artifact Results",
        "",
        "| Artifact | Status | Reviewer Output |",
        "|---|---|---|",
    ]
    for artifact in state.get("artifacts", []):
        output = artifact.get("reviewer_pack") or artifact.get("blocked_review") or "none"
        lines.append(f"| `{artifact['artifact_id']}` | `{artifact['final_status']}` | `{output}` |")
    lines.extend(
        [
            "",
            "## What Passed",
            "",
        ]
    )
    passed = [artifact["artifact_id"] for artifact in state.get("artifacts", []) if artifact.get("final_status") == "PASS"]
    lines.extend(f"- `{artifact_id}`" for artifact_id in passed)
    if not passed:
        lines.append("- none")
    lines.extend(["", "## What Blocked", ""])
    blocked = [artifact for artifact in state.get("artifacts", []) if artifact.get("final_status") == "BLOCKED"]
    lines.extend(f"- `{artifact['artifact_id']}`: {artifact.get('block_reason')}" for artifact in blocked)
    if not blocked:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## What This Proves",
            "",
            "- Hoxline can run the Review Engine across a declared artifact manifest set.",
            "- The batch machine-state records per-artifact PASS and BLOCKED outcomes and verifies expectations.",
            "- Unsupported claims block fail-closed at the artifact and batch layers.",
            "",
            "## What This Does Not Prove",
            "",
            "- It does not prove live runtime behavior or public signal observation.",
            "- It does not prove public-safe status, production readiness, deployment, approval, authorization, or case closure.",
            "- It does not touch endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, ledgers, or website proof state.",
            "",
            "## Final Claim Boundary",
            "",
            f"- public_safe_status: `{state['public_safe_status']}`",
            f"- human_review_required: `{str(state['human_review_required']).lower()}`",
            f"- ai_disposition_authority: `{str(state['ai_disposition_authority']).lower()}`",
            f"- next_gate: `{state.get('next_gate')}`",
            "",
        ]
    )
    return "\n".join(lines)


def _batch_run_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "batch-run-summary-v1",
        "engine_version": BATCH_ENGINE_VERSION,
        "batch_id": state["batch_id"],
        "index_id": state.get("index_id"),
        "final_status": state["final_status"],
        "block_reason": state.get("block_reason"),
        "artifacts": state.get("artifacts", []),
        "outputs": BATCH_EXPECTED_OUTPUTS,
        "public_safe_status": state["public_safe_status"],
        "human_review_required": state["human_review_required"],
        "ai_disposition_authority": state["ai_disposition_authority"],
        "endpoint_mutation": state["endpoint_mutation"],
        "runtime_proof": state["runtime_proof"],
        "wazuh_mutation": state["wazuh_mutation"],
        "private_evidence_committed": state["private_evidence_committed"],
        "public_proof_promoted": state["public_proof_promoted"],
        "lifetime_ledger_changed": state["lifetime_ledger_changed"],
        "website_changed": state["website_changed"],
    }


def _safe_blocked_index(index: dict[str, Any], index_path: Path, block_reason: str) -> dict[str, Any]:
    return {
        "schema_version": "blocked-batch-index-v1",
        "index_path": str(index_path),
        "index_id": index.get("index_id", "UNKNOWN") if index else "UNKNOWN",
        "final_status": "BLOCKED",
        "block_reason": block_reason,
        "redaction": "Original hostile batch index content is not copied into blocked outputs.",
        "expected_pass_artifacts": [],
        "expected_blocked_artifacts": [],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "runtime_boundary": "runtime prohibited",
        "signal_boundary": "synthetic fixture signal only",
        "proof_boundary": "not public proof",
        "next_gate": "index_fix_required",
    }


def _build_pass_run(manifest: dict[str, Any], manifest_path: Path, output_dir: Path, review_outputs: dict[str, Any]) -> dict[str, Any]:
    run_id = output_dir.name
    output_refs = {
        "artifact_manifest": "artifact-manifest.json",
        "artifact_intake": "intake.json",
        "evidence_graph": "evidence-graph.json",
        "telemetry_contract_check": "telemetry-contract-check.json",
        "controlled_validation": "validation-result.json",
        "synthetic_signal": "synthetic-signal.json",
        "enrichment": "enrichment.json",
        "triage": "triage-summary.md",
        "proofcard": "proofcard.json",
        "claim_authority": "claim-authority.json",
        "reviewer_pack": "reviewer-pack.md",
        "machine_state": "machine-state.json",
        "run_summary": "run-summary.json",
    }
    state = _machine_state(
        manifest=manifest,
        manifest_path=manifest_path,
        run_id=run_id,
        final_status="PASS",
        stages=_pass_stages(output_refs),
        outputs=output_refs,
    )
    reviewer_pack = _reviewer_pack(manifest, state)
    summary = _run_summary(manifest, state, EXPECTED_PASS_OUTPUTS)
    return {
        "output_dir": str(output_dir),
        "manifest": manifest,
        "review_outputs": review_outputs,
        "reviewer_pack": reviewer_pack,
        "machine_state": state,
        "run_summary": summary,
    }


def _build_blocked_run(manifest: dict[str, Any], manifest_path: Path, output_dir: Path, block_reason: str) -> dict[str, Any]:
    run_id = output_dir.name
    output_refs = {
        "artifact_manifest": "artifact-manifest.json",
        "machine_state": "machine-state.json",
        "blocked_review": "blocked-review.md",
        "run_summary": "run-summary.json",
    }
    state = _machine_state(
        manifest=manifest,
        manifest_path=manifest_path,
        run_id=run_id,
        final_status="BLOCKED",
        stages=_blocked_stages(block_reason, output_refs),
        outputs=output_refs,
        block_reason=block_reason,
    )
    return {
        "output_dir": str(output_dir),
        "manifest": _safe_blocked_manifest(manifest, manifest_path, block_reason),
        "blocked_review": _blocked_review(state),
        "machine_state": state,
        "run_summary": _run_summary(manifest, state, EXPECTED_BLOCKED_OUTPUTS),
    }



def _safe_blocked_manifest(manifest: dict[str, Any], manifest_path: Path, block_reason: str) -> dict[str, Any]:
    return {
        "schema_version": "blocked-artifact-manifest-v1",
        "manifest_path": str(manifest_path),
        "artifact_id": manifest.get("artifact_id", "UNKNOWN") if manifest else "UNKNOWN",
        "final_status": "BLOCKED",
        "block_reason": block_reason,
        "redaction": "Original hostile manifest content is not copied into blocked outputs.",
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,

    }

def _write_pass_outputs(output_dir: Path, run: dict[str, Any], force: bool) -> None:
    _prepare_output_dir(output_dir, force)
    outputs = run["review_outputs"]
    file_map: dict[str, Any] = {
        "artifact-manifest.json": run["manifest"],
        "intake.json": outputs["intake"],
        "evidence-graph.json": outputs["evidence_graph"],
        "telemetry-contract-check.json": outputs["telemetry_contract_check"],
        "validation-result.json": outputs["validation_result"],
        "synthetic-signal.json": outputs["synthetic_signal"],
        "enrichment.json": outputs["enrichment"],
        "triage-summary.md": outputs["triage_summary"],
        "proofcard.json": outputs["proofcard"],
        "proofcard.md": outputs["proofcard_markdown"],
        "claim-authority.json": outputs["claim_authority"],
        "reviewer-pack.md": run["reviewer_pack"],
        "machine-state.json": run["machine_state"],
        "run-summary.json": run["run_summary"],
    }
    _write_file_map(output_dir, file_map)


def _write_blocked_outputs(output_dir: Path, run: dict[str, Any], force: bool) -> None:
    _prepare_output_dir(output_dir, force)
    _write_file_map(
        output_dir,
        {
            "artifact-manifest.json": run["manifest"],
            "machine-state.json": run["machine_state"],
            "blocked-review.md": run["blocked_review"],
            "run-summary.json": run["run_summary"],
        },
    )


def _node(node_id: str, node_type: str, owner: str, status: str) -> dict[str, str]:
    return {"id": node_id, "type": node_type, "owner": owner, "status": status}


def _build_review_outputs(manifest: dict[str, Any], fixture_paths: dict[str, Path]) -> dict[str, Any]:
    positive_fixture = _load_json(fixture_paths["positive"])
    negative_fixture = _load_json(fixture_paths["negative"])
    _validate_review_fixture(positive_fixture, manifest, True)
    _validate_review_fixture(negative_fixture, manifest, False)

    intake = _artifact_intake(manifest)
    telemetry = _telemetry_contract_check(manifest, positive_fixture)
    validation = _controlled_validation(manifest, positive_fixture, negative_fixture, telemetry)
    signal = _synthetic_signal(manifest, positive_fixture, validation)
    enrichment = _enrichment(manifest, positive_fixture)
    triage = _triage(manifest, signal, enrichment, validation)
    proofcard = _proofcard(manifest, intake, telemetry, validation, signal, enrichment, triage)
    claim_authority = _claim_authority(manifest, proofcard)
    evidence_graph = _evidence_graph(manifest, intake, telemetry, validation, signal, proofcard, claim_authority)
    return {
        "intake": intake,
        "evidence_graph": evidence_graph,
        "telemetry_contract_check": telemetry,
        "validation_result": validation,
        "synthetic_signal": signal,
        "enrichment": enrichment,
        "triage_summary": _triage_markdown(manifest, triage),
        "proofcard": proofcard,
        "proofcard_markdown": _proofcard_markdown(proofcard),
        "claim_authority": claim_authority,
    }


def _artifact_intake(manifest: dict[str, Any]) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "artifact-intake-v1",
        "intake_id": f"intake-{artifact_id.lower()}-review-v1",
        "artifact_id": artifact_id,
        "artifact_type": manifest["artifact_type"],
        "source_owner": manifest["source_owner"],
        "source_label": manifest["artifact_name"],
        "ai_assisted": True,
        "initial_claim_ceiling": manifest["allowed_claim_class"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "notes": [
            "Fixture is synthetic and local-only.",
            "No users, groups, endpoints, Wazuh systems, or private infrastructure are touched.",
        ],
    }


def _telemetry_contract_check(manifest: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    contract = manifest["telemetry_contract"]
    observed_event_ids = sorted({int(event["event_id"]) for event in fixture["events"]})
    return {
        "schema_version": "telemetry-contract-check-v0",
        "artifact_id": manifest["artifact_id"],
        "required_source": contract["source"],
        "event_ids": list(manifest["expected_event_ids"]),
        "fixture_event_ids": observed_event_ids,
        "wazuh_rule_family": list(manifest["expected_rule_ids"]),
        "required_fields": list(contract.get("required_fields", ["event_id", "channel", "action", "actor"])),
        "missing_required_fields": [],
        "result": "pass",
        "scope": "pass for fixture only",
        "network_required": False,
        "endpoint_mutation": False,
    }


def _controlled_validation(
    manifest: dict[str, Any],
    fixture: dict[str, Any],
    negative_fixture: dict[str, Any],
    telemetry: dict[str, Any],
) -> dict[str, Any]:
    positive_match = _fixture_matches_manifest(fixture, manifest)
    negative_match = _fixture_matches_manifest(negative_fixture, manifest)
    result = "pass" if positive_match and not negative_match and telemetry["result"] == "pass" else "fail"
    return {
        "schema_version": "validation-result-v0",
        "artifact_id": manifest["artifact_id"],
        "fixture_mode": "safe-fixture",
        "fixture_ids": [fixture["fixture_id"], negative_fixture["fixture_id"]],
        "positive_cases": 1,
        "negative_cases": 1,
        "matched_positive_cases": 1 if positive_match else 0,
        "false_positive_negative_cases": 1 if negative_match else 0,
        "result": result,
        "endpoint_mutation": False,
        "runtime_rerun": False,
        "wazuh_mutation": False,
        "explanation": "Validation evaluates bundled synthetic fixture records only.",
    }


def _synthetic_signal(manifest: dict[str, Any], fixture: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "synthetic-signal-v0",
        "artifact_id": artifact_id,
        "signal_id": f"synthetic-signal-{artifact_id.lower()}-review-v1",
        "source": "safe bundled fixture",
        "detection_fired": validation["result"] == "pass" and _fixture_matches_manifest(fixture, manifest),
        "simulation_only": True,
        "endpoint_mutation": False,
        "backend_mutation": False,
        "explanation": "The signal is derived from fixture fields and does not create operating-system events.",
    }


def _enrichment(manifest: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    event_mapping = {str(event_id): f"fixture event metadata for {manifest['artifact_id']}" for event_id in manifest["expected_event_ids"]}
    return {
        "schema_version": "enrichment-v0",
        "artifact_id": manifest["artifact_id"],
        "attack_mapping": list(manifest.get("attack_mapping", [{"technique_id": "T0000", "technique": "synthetic fixture review", "scope": "review mapping only"}])),
        "event_id_mapping": event_mapping,
        "source_mapping": {
            "channel": manifest["telemetry_contract"]["source"],
            "fixture_host": fixture["host"],
            "fixture_scope": "synthetic demo host",
        },
        "field_mapping": dict(manifest.get("field_mapping", {"event_id": "event identifier", "action": "review action", "actor": "synthetic actor label"})),
        "confidence": manifest.get("confidence", "bounded-demo-high"),
        "severity": manifest.get("severity", "medium"),
    }


def _triage(manifest: dict[str, Any], signal: dict[str, Any], enrichment: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "triage-summary-v0",
        "artifact_id": artifact_id,
        "what_happened": manifest.get("triage_what_happened", f"A synthetic fixture represented the {artifact_id} review pattern."),
        "why_it_matters": manifest.get("triage_why_it_matters", "The pattern can matter during security review when backed by appropriate evidence."),
        "evidence_exists": [
            "artifact intake record",
            "evidence graph",
            "telemetry contract check",
            "positive and negative synthetic fixtures",
            "fixture-derived synthetic signal",
            "enrichment mapping",
            "ProofCard",
            "Claim Authority decision",
        ],
        "missing_evidence": ["public-safe runtime proof", "public signal proof", "human review gate completion", "final authorization record"],
        "next_gate": manifest["next_gate"],
        "detection_fired": signal["detection_fired"],
        "validation_result": validation["result"],
        "attack_mapping": enrichment["attack_mapping"],
    }


def _proofcard(
    manifest: dict[str, Any],
    intake: dict[str, Any],
    telemetry: dict[str, Any],
    validation: dict[str, Any],
    signal: dict[str, Any],
    enrichment: dict[str, Any],
    triage: dict[str, Any],
) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "proofcard-v1",
        "proofcard_id": f"proofcard-{artifact_id.lower()}-review-v1",
        "detection_id": artifact_id,
        "artifact_id": intake["artifact_id"],
        "proof_owner": "hoxline-review-fixture",
        "proof_ceiling": manifest["allowed_claim_class"],
        "proof_ceiling_meaning": "LOCAL_FIXTURE_REVIEW_ONLY",
        "review_lane": "REVIEW_ENGINE_V1",
        "review_version": "v1",
        "owner_split": {
            "source_truth": manifest["source_owner"],
            "behavior_truth": "bundled synthetic fixture",
            "platform_runtime_truth": "not asserted",
            "proof_authority": "not asserted by review engine",
            "rendering": "local generated files only",
        },
        "telemetry_contract": telemetry,
        "controlled_validation": validation,
        "synthetic_signal": signal,
        "enrichment": enrichment,
        "triage": triage,
        "allowed_claims": _allowed_claims_for(manifest),
        "blocked_claims": _blocked_claims(),
        "missing_evidence": triage["missing_evidence"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "runtime_active": False,
        "signal_observed": False,
        "next_gate": manifest["next_gate"],
    }


def _claim_authority(manifest: dict[str, Any], proofcard: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "claim-authority-v1",
        "decision_id": f"claim-authority-{manifest['artifact_id'].lower()}-review-v1",
        "artifact_id": manifest["artifact_id"],
        "proof_ceiling": proofcard["proof_ceiling"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "allowed_claims": list(proofcard["allowed_claims"]),
        "blocked_claims": _blocked_claims(),
        "safer_wording": [
            "Use fixture-only review wording.",
            "Say the review shows deterministic local engine behavior; do not say it proves live runtime or public-safe status.",
        ],
    }


def _evidence_graph(
    manifest: dict[str, Any],
    intake: dict[str, Any],
    telemetry: dict[str, Any],
    validation: dict[str, Any],
    signal: dict[str, Any],
    proofcard: dict[str, Any],
    claim_authority: dict[str, Any],
) -> dict[str, Any]:
    nodes = [
        _node("artifact-intake", "artifact_intake", intake["source_owner"], "PASS"),
        _node("telemetry-contract-check", "telemetry_contract_check", "hoxline-review-fixture", telemetry["result"].upper()),
        _node("controlled-validation", "controlled_validation", "hoxline-review-fixture", validation["result"].upper()),
        _node("synthetic-signal", "synthetic_signal", "hoxline-review-fixture", "PASS"),
        _node("proofcard", "proofcard", proofcard["proof_owner"], "PASS"),
        _node("claim-authority", "claim_authority", "hoxline", "PASS"),
    ]
    return {
        "schema_version": "evidence-graph-v1",
        "graph_id": f"evidence-graph-{manifest['artifact_id'].lower()}-review-v1",
        "detection_id": manifest["artifact_id"],
        "artifact_id": manifest["artifact_id"],
        "nodes": nodes,
        "edges": [
            {"from": "artifact-intake", "to": "telemetry-contract-check", "relationship": "declares assumptions"},
            {"from": "telemetry-contract-check", "to": "controlled-validation", "relationship": "bounds fixture validation"},
            {"from": "controlled-validation", "to": "synthetic-signal", "relationship": "creates fixture-only signal"},
            {"from": "synthetic-signal", "to": "proofcard", "relationship": "summarized by"},
            {"from": "proofcard", "to": "claim-authority", "relationship": "constrains claims"},
        ],
        "missing_evidence": proofcard["missing_evidence"],
    }


def _triage_markdown(manifest: dict[str, Any], triage: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Review Engine Triage Summary",
        "",
        f"Artifact: `{manifest['artifact_id']}`",
        "",
        f"What happened: {triage['what_happened']}",
        "",
        f"Why it matters: {triage['why_it_matters']}",
        "",
        "Evidence exists:",
    ]
    lines.extend(f"- {item}" for item in triage["evidence_exists"])
    lines.extend(["", "Missing evidence:"])
    lines.extend(f"- {item}" for item in triage["missing_evidence"])
    lines.extend(["", f"Next gate: `{triage['next_gate']}`", ""])
    return "\n".join(lines)


def _proofcard_markdown(proofcard: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Review Engine ProofCard",
        "",
        f"Artifact: `{proofcard['artifact_id']}`",
        "",
        f"Proof ceiling: `{proofcard['proof_ceiling']}`",
        "",
        f"public_safe_status: `{proofcard['public_safe_status']}`",
        "",
        f"human_review_required: `{str(proofcard['human_review_required']).lower()}`",
        "",
        f"ai_disposition_authority: `{str(proofcard['ai_disposition_authority']).lower()}`",
        "",
        "## Allowed Claim",
        "",
    ]
    lines.extend(f"- {claim}" for claim in proofcard["allowed_claims"])
    lines.extend(["", "## Blocked Claims", ""])
    lines.extend(f"- `{item['claim']}`: {item['safer_wording']}" for item in proofcard["blocked_claims"])
    lines.extend(["", "## Missing Evidence", ""])
    lines.extend(f"- `{item}`" for item in proofcard["missing_evidence"])
    lines.append("")
    return "\n".join(lines)


def _validate_review_fixture(fixture: dict[str, Any], manifest: dict[str, Any], expected_detection: bool) -> None:
    expected = {
        "schema_version": "hoxline-demo-fixture-v0",
        "artifact_id": manifest["artifact_id"],
        "fixture_kind": "synthetic-demo-only",
        "safe_fixture": True,
        "endpoint_mutation": False,
        "runtime_required": False,
        "network_required": False,
    }
    for field, value in expected.items():
        if fixture.get(field) != value:
            raise ReviewBlocked(f"fixture field {field} must be {value!r}")
    if fixture.get("expected_detection") is not expected_detection:
        raise ReviewBlocked(f"fixture expected_detection must be {expected_detection!r}")
    events = fixture.get("events")
    if not isinstance(events, list) or not events:
        raise ReviewBlocked("fixture events must be a non-empty list")
    for event in events:
        if not isinstance(event, dict):
            raise ReviewBlocked("fixture events must be objects")
        for field in ("event_id", "channel", "action", "actor"):
            if field not in event:
                raise ReviewBlocked(f"fixture event missing field: {field}")
    if expected_detection and not _fixture_matches_manifest(fixture, manifest):
        raise ReviewBlocked("positive fixture does not match manifest detection")
    if not expected_detection and _fixture_matches_manifest(fixture, manifest):
        raise ReviewBlocked("negative fixture unexpectedly matches manifest detection")


def _fixture_matches_manifest(fixture: dict[str, Any], manifest: dict[str, Any]) -> bool:
    if fixture.get("expected_detection") is not True:
        return False
    expected_ids = {int(event_id) for event_id in manifest.get("expected_event_ids", [])}
    for event in fixture.get("events", []):
        if not isinstance(event, dict):
            continue
        if int(event.get("event_id", 0)) in expected_ids and event.get("channel") in {"Windows Security", "Windows System", "TaskScheduler Operational"}:
            return True
    return False


def _allowed_claims_for(manifest: dict[str, Any]) -> list[str]:
    requested = manifest.get("requested_claims", [])
    if requested:
        return [str(requested[0])]
    if manifest.get("artifact_id") == ARTIFACT_ID:
        return [SAFE_ALLOWED_CLAIM]
    return [f"{manifest.get('artifact_id', 'artifact')} has a deterministic local fixture review through Hoxline Review Engine v1 without claiming live runtime proof."]


def _validate_manifest(manifest: dict[str, Any], manifest_path: Path, repo_root: Path) -> None:
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            raise ReviewBlocked(f"manifest missing required field: {field}")
    if manifest["manifest_version"] != MANIFEST_VERSION:
        raise ReviewBlocked(f"manifest_version must be {MANIFEST_VERSION}")
    if manifest["artifact_id"] != ARTIFACT_ID and manifest.get("artifact_family") != "synthetic-review-only":
        raise ReviewBlocked("unknown artifact requires explicit synthetic-review-only artifact_family")
    if manifest.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        raise ReviewBlocked("public_safe_status must remain NOT_PUBLIC_SAFE")
    if manifest.get("human_review_required") is not True:
        raise ReviewBlocked("human_review_required must be true")
    if manifest.get("ai_disposition_authority") is not False:
        raise ReviewBlocked("ai_disposition_authority must be false")
    _validate_manifest_flags(manifest)
    _validate_telemetry_contract(manifest)
    _validate_claims(manifest)
    _validate_no_private_markers(manifest, "manifest")
    paths = _fixture_paths(manifest, repo_root)
    for label, path in paths.items():
        if not path.is_file():
            raise ReviewBlocked(f"{label} fixture path missing: {path}")
        _validate_fixture_path(path, repo_root)
        fixture = _load_json(path)
        _validate_no_private_markers(fixture, f"{label} fixture")


def _validate_manifest_flags(manifest: dict[str, Any]) -> None:
    flag_checks = {
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "lifetime_ledger_changed": False,
        "public_proof_promoted": False,
        "runtime_proof": False,
    }
    for field, expected in flag_checks.items():
        if field in manifest and manifest[field] is not expected:
            raise ReviewBlocked(f"{field} must be {str(expected).lower()}")


def _validate_telemetry_contract(manifest: dict[str, Any]) -> None:
    contract = manifest.get("telemetry_contract")
    if not isinstance(contract, dict):
        raise ReviewBlocked("telemetry_contract must be an object")
    if contract.get("source") != "Windows Security EventChannel":
        raise ReviewBlocked("telemetry_contract.source must be Windows Security EventChannel")
    event_ids = contract.get("event_ids")
    expected_event_ids = manifest.get("expected_event_ids")
    if not isinstance(event_ids, list) or not event_ids:
        raise ReviewBlocked("telemetry_contract.event_ids must be a non-empty list")
    if sorted(event_ids) != sorted(expected_event_ids or []):
        raise ReviewBlocked("telemetry_contract.event_ids must match expected_event_ids")
    rule_ids = contract.get("wazuh_rule_ids")
    expected_rule_ids = manifest.get("expected_rule_ids")
    if not isinstance(rule_ids, list) or not rule_ids:
        raise ReviewBlocked("telemetry_contract.wazuh_rule_ids must be a non-empty list")
    if sorted(rule_ids) != sorted(expected_rule_ids or []):
        raise ReviewBlocked("telemetry_contract.wazuh_rule_ids must match expected_rule_ids")


def _validate_claims(manifest: dict[str, Any]) -> None:
    requested_claims = manifest.get("requested_claims")
    if not isinstance(requested_claims, list):
        raise ReviewBlocked("requested_claims must be a list")
    requested_text = "\n".join(str(item) for item in requested_claims)
    for label, pattern in PROHIBITED_CLAIM_PATTERNS.items():
        if pattern.search(requested_text):
            raise ReviewBlocked(f"requested claim is unsupported and blocked: {label}")
    blocked = set(manifest.get("blocked_claim_classes", []))
    missing = [claim for claim in BLOCKED_CLAIM_FAMILIES if claim not in blocked]
    if missing:
        raise ReviewBlocked(f"manifest must list blocked claim classes: {', '.join(missing)}")


def _fixture_paths(manifest: dict[str, Any], repo_root: Path) -> dict[str, Path]:
    raw = manifest.get("fixture_paths")
    if not isinstance(raw, dict):
        raise ReviewBlocked("fixture_paths must be an object")
    try:
        return {
            "positive": _resolve_path(Path(str(raw["positive"])), repo_root),
            "negative": _resolve_path(Path(str(raw["negative"])), repo_root),
        }
    except KeyError as exc:
        raise ReviewBlocked(f"fixture_paths missing key: {exc.args[0]}") from exc


def _validate_fixture_path(path: Path, repo_root: Path) -> None:
    resolved = path.resolve()
    allowed_roots = [(repo_root / "examples" / "demo").resolve(), (repo_root / "examples" / "review").resolve()]
    if not any(_is_relative_to(resolved, allowed) for allowed in allowed_roots):
        raise ReviewBlocked(f"fixture path outside allowed example roots: {path}")


def _validate_no_private_markers(value: Any, label: str, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            full = f"{path}.{key}" if path else str(key)
            for pattern in PRIVATE_FIELD_PATTERNS:
                if pattern.search(str(key)):
                    raise ReviewBlocked(f"{label} contains prohibited private/raw field marker")
            _validate_no_private_markers(item, label, full)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_no_private_markers(item, label, f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in PRIVATE_VALUE_PATTERNS:
            if pattern.search(value):
                raise ReviewBlocked(f"{label} contains prohibited private/raw value marker")


def _machine_state(
    manifest: dict[str, Any],
    manifest_path: Path,
    run_id: str,
    final_status: str,
    stages: list[dict[str, Any]],
    outputs: dict[str, str],
    block_reason: str | None = None,
) -> dict[str, Any]:
    requested_claims = manifest.get("requested_claims", []) if manifest else []
    return {
        "schema_version": MACHINE_STATE_VERSION,
        "engine_version": ENGINE_VERSION,
        "run_id": run_id,
        "artifact_id": manifest.get("artifact_id", "UNKNOWN") if manifest else "UNKNOWN",
        "manifest_path": str(manifest_path),
        "stages": stages,
        "outputs": outputs,
        "final_status": final_status,
        "block_reason": block_reason,
        "allowed_claim": _allowed_claims_for(manifest)[0] if final_status == "PASS" and manifest else None,
        "requested_claims": requested_claims,
        "blocked_claims": _blocked_claims(),
        "proof_boundary": manifest.get("proof_boundary", "fixture-only; not public proof") if manifest else "manifest blocked before proof boundary established",
        "runtime_boundary": manifest.get("runtime_boundary", "runtime prohibited") if manifest else "runtime prohibited",
        "signal_boundary": manifest.get("signal_boundary", "synthetic fixture signal only") if manifest else "synthetic fixture signal only",
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "private_evidence_committed": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "next_gate": manifest.get("next_gate", "human_review_gate") if manifest else "manifest_fix_required",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "product": PRODUCT,
    }


def _stage(stage_name: str, status: str, output_ref: str | None, summary: str, failure_mode: str | None = None) -> dict[str, Any]:
    return {
        "stage_name": stage_name,
        "status": status,
        "input_refs": ["artifact-manifest.json"],
        "output_ref": output_ref,
        "proof_boundary": "fixture-only; NOT_PUBLIC_SAFE; not runtime proof",
        "failure_mode": failure_mode,
        "claim_boundary": "unsupported public, runtime, production, customer, SOCaaS, autonomous, approval, authorization, and case-closure claims block",
        "summary": summary,
    }


def _pass_stages(outputs: dict[str, str]) -> list[dict[str, Any]]:
    summaries = {
        "artifact_intake": "manifest accepted and intake created",
        "evidence_graph": "evidence graph linked local fixture review nodes",
        "telemetry_contract_check": "Windows Security EventChannel event and rule metadata checked",
        "controlled_validation": "positive and negative bundled fixtures validated",
        "synthetic_signal": "safe fixture signal simulated without endpoint mutation",
        "enrichment": "ATT&CK, event, source, and field mapping attached",
        "triage": "reviewer-readable triage summary generated",
        "proofcard": "ProofCard rendered under fixture-only ceiling",
        "claim_authority": "Claim Authority allowed bounded claim and blocked stronger claims",
        "reviewer_pack": "reviewer pack generated",
        "machine_state": "replayable machine-state generated",
    }
    return [_stage(name, "PASS", outputs.get(name), summaries[name]) for name in STAGE_REGISTRY]


def _blocked_stages(block_reason: str, outputs: dict[str, str]) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = []
    blocked_seen = False
    for name in STAGE_REGISTRY:
        if name == "artifact_intake":
            stages.append(_stage(name, "BLOCKED", outputs.get("blocked_review"), block_reason, block_reason))
            blocked_seen = True
        else:
            stages.append(_stage(name, "SKIPPED" if blocked_seen else "BLOCKED", None, "skipped after fail-closed gate", block_reason))
    return stages


def _reviewer_pack(manifest: dict[str, Any], state: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Review Engine v1 Reviewer Pack",
        "",
        "## What This Is",
        "",
        "A deterministic local review of an artifact manifest through the Hoxline ProofOps machine.",
        "",
        "## What Happened",
        "",
        f"Artifact `{state['artifact_id']}` ran through artifact intake, evidence graph, telemetry contract check, controlled validation, synthetic signal, enrichment, triage, ProofCard, Claim Authority, reviewer pack, and machine-state stages.",
        "",
        "## Stage Table",
        "",
        "| Stage | Status | Summary |",
        "|---|---|---|",
    ]
    lines.extend(f"| `{stage['stage_name']}` | `{stage['status']}` | {stage['summary']} |" for stage in state["stages"])
    lines.extend(
        [
            "",
            "## What Hoxline Allowed",
            "",
            f"- {state['allowed_claim']}",
            "",
            "## What Hoxline Blocked",
            "",
        ]
    )
    lines.extend(f"- `{item['claim']}`: {item['safer_wording']}" for item in state["blocked_claims"])
    lines.extend(
        [
            "",
            "## What This Proves",
            "",
            "- The artifact manifest can be reviewed by deterministic local Hoxline stages.",
            "- The engine can generate replayable machine-state and reviewer artifacts from public-safe synthetic fixtures.",
            "- Claim Authority blocks unsupported public, runtime, production, customer, SOCaaS, autonomous, approval, authorization, and case-closure claims.",
            "",
            "## What This Does Not Prove",
            "",
            "- It does not prove live runtime behavior.",
            "- It does not prove public signal observation.",
            "- It does not prove public-safe status, production readiness, deployment, approval, authorization, or case closure.",
            "- It does not touch endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, ledgers, or website proof state.",
            "",
            "## Output Files",
            "",
        ]
    )
    lines.extend(f"- `{name}`" for name in EXPECTED_PASS_OUTPUTS)
    lines.extend(
        [
            "",
            "## Final Claim Boundary",
            "",
            f"- public_safe_status: `{state['public_safe_status']}`",
            f"- human_review_required: `{str(state['human_review_required']).lower()}`",
            f"- ai_disposition_authority: `{str(state['ai_disposition_authority']).lower()}`",
            f"- next_gate: `{state['next_gate']}`",
            "",
        ]
    )
    return "\n".join(lines)


def _blocked_review(state: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Hoxline Review Engine v1 Blocked Review",
            "",
            f"Artifact: `{state.get('artifact_id')}`",
            f"Final status: `{state['final_status']}`",
            f"Block reason: {state['block_reason']}",
            "",
            "## Boundary",
            "",
            "- Fail-closed gate blocked the review before stronger claims could be emitted.",
            "- public_safe_status remains `NOT_PUBLIC_SAFE`.",
            "- human_review_required remains `true`.",
            "- ai_disposition_authority remains `false`.",
            "- runtime proof, public proof promotion, endpoint mutation, Wazuh mutation, and ledger changes remain false.",
            "",
        ]
    )


def _run_summary(manifest: dict[str, Any], state: dict[str, Any], outputs: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "review-run-summary-v1",
        "engine_version": ENGINE_VERSION,
        "run_id": state["run_id"],
        "artifact_id": state["artifact_id"],
        "manifest_version": manifest.get("manifest_version") if manifest else None,
        "final_status": state["final_status"],
        "block_reason": state.get("block_reason"),
        "outputs": outputs,
        "public_safe_status": state["public_safe_status"],
        "human_review_required": state["human_review_required"],
        "ai_disposition_authority": state["ai_disposition_authority"],
        "endpoint_mutation": state["endpoint_mutation"],
        "runtime_proof": state["runtime_proof"],
        "wazuh_mutation": state["wazuh_mutation"],
        "private_evidence_committed": state["private_evidence_committed"],
        "public_proof_promoted": state["public_proof_promoted"],
        "lifetime_ledger_changed": state["lifetime_ledger_changed"],
    }


def _verify_pass_outputs(run_dir: Path, state: dict[str, Any], errors: list[str]) -> None:
    manifest = _load_json(run_dir / "artifact-manifest.json")
    telemetry = _load_json(run_dir / "telemetry-contract-check.json")
    validation = _load_json(run_dir / "validation-result.json")
    signal = _load_json(run_dir / "synthetic-signal.json")
    proofcard = _load_json(run_dir / "proofcard.json")
    claim_authority = _load_json(run_dir / "claim-authority.json")
    reviewer_pack = (run_dir / "reviewer-pack.md").read_text(encoding="utf-8")
    if telemetry.get("required_source") != "Windows Security EventChannel":
        errors.append("telemetry contract must use Windows Security EventChannel")
    if sorted(telemetry.get("event_ids", [])) != sorted(manifest.get("expected_event_ids", [])):
        errors.append("telemetry contract event IDs must match artifact manifest")
    if sorted(telemetry.get("wazuh_rule_family", [])) != sorted(manifest.get("expected_rule_ids", [])):
        errors.append("telemetry contract Wazuh rule metadata must match artifact manifest")
    if validation.get("result") != "pass" or validation.get("endpoint_mutation") is not False:
        errors.append("controlled validation must pass without endpoint mutation")
    if signal.get("source") != "safe bundled fixture" or signal.get("detection_fired") is not True:
        errors.append("synthetic signal must fire only from safe bundled fixture")
    if proofcard.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        errors.append("ProofCard must preserve NOT_PUBLIC_SAFE")
    blocked = {item.get("claim") for item in claim_authority.get("blocked_claims", [])}
    missing = [claim for claim in BLOCKED_CLAIM_FAMILIES if claim not in blocked]
    if missing:
        errors.append(f"blocked claims missing: {', '.join(missing)}")
    for heading in ("## What This Proves", "## What This Does Not Prove"):
        if heading not in reviewer_pack:
            errors.append(f"reviewer pack missing heading: {heading}")


def _blocked_claims() -> list[dict[str, str]]:
    return [
        {
            "claim": claim,
            "status": "BLOCKED",
            "safer_wording": {
                "production ready": "production readiness is not asserted",
                "public-safe runtime proof": "public-safe runtime proof is not asserted",
                "SOCaaS deployed": "SOCaaS deployment is not asserted",
                "customer deployed": "customer deployment is not asserted",
                "autonomous SOC": "autonomous SOC operation is not asserted",
                "AI-approved disposition": "AI-approved disposition is not asserted",
                "analyst-approved disposition": "analyst-approved disposition is not asserted",
                "final authorization": "final authorization is not asserted",
                "case closure": "case closure is not asserted",
                "website rendering as proof": "website rendering is not proof",
                "green CI as approval": "green CI is not approval",
            }[claim],
        }
        for claim in BLOCKED_CLAIM_FAMILIES
    ]


def _prepare_output_dir(output_dir: Path, force: bool) -> None:
    if output_dir.exists():
        if not force:
            raise ReviewEngineError(f"output directory already exists: {output_dir}")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)


def _write_file_map(output_dir: Path, file_map: dict[str, Any]) -> None:
    for name, value in file_map.items():
        path = output_dir / name
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _private_output_hits(run_dir: Path) -> list[str]:
    hits: list[str] = []
    for path in run_dir.iterdir():
        if not path.is_file() or path.suffix not in {".json", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in PRIVATE_VALUE_PATTERNS:
            if pattern.search(text):
                hits.append(f"{path.name}:{pattern.pattern}")
    return hits


def _resolve_path(path: Path, base: Path) -> Path:
    if path.is_absolute():
        return path
    return (base / path).resolve()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ReviewEngineError(f"input must be a JSON object: {path}")
    return deepcopy(data)
