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
    build_demo_run,
)

ENGINE_VERSION = "hoxline-review-engine-v1"
MANIFEST_VERSION = "artifact-manifest-v1"
MACHINE_STATE_VERSION = "review-machine-state-v1"
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


def run_review(artifact_path: Path, output_dir: Path | None = None, force: bool = False, repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or Path(__file__).resolve().parents[2]
    out_dir = output_dir or default_run_dir(Path.cwd())
    manifest_path = _resolve_path(artifact_path, Path.cwd())
    manifest: dict[str, Any] = {}
    try:
        manifest = _load_json(manifest_path)
        _validate_manifest(manifest, manifest_path, root)
        fixture_paths = _fixture_paths(manifest, root)
        demo_run = build_demo_run(root, fixture_paths["positive"], fixture_paths["negative"])
        run = _build_pass_run(manifest, manifest_path, out_dir, demo_run)
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


def _build_pass_run(manifest: dict[str, Any], manifest_path: Path, output_dir: Path, demo_run: dict[str, Any]) -> dict[str, Any]:
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
        "demo_run": demo_run,
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
    demo = run["demo_run"]
    file_map: dict[str, Any] = {
        "artifact-manifest.json": run["manifest"],
        "intake.json": demo["intake"],
        "evidence-graph.json": demo["evidence_graph"],
        "telemetry-contract-check.json": demo["telemetry_contract_check"],
        "validation-result.json": demo["validation_result"],
        "synthetic-signal.json": demo["synthetic_signal"],
        "enrichment.json": demo["enrichment"],
        "triage-summary.md": demo["triage_summary"],
        "proofcard.json": demo["proofcard"],
        "proofcard.md": demo["proofcard_markdown"],
        "claim-authority.json": demo["claim_authority"],
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
    if sorted(contract.get("event_ids", [])) != REQUIRED_EVENT_IDS:
        raise ReviewBlocked("telemetry_contract.event_ids must include HO-DET-010 required event IDs")
    if sorted(contract.get("wazuh_rule_ids", [])) != REQUIRED_WAZUH_RULE_FAMILY:
        raise ReviewBlocked("telemetry_contract.wazuh_rule_ids must include required rule metadata")
    if sorted(manifest.get("expected_event_ids", [])) != REQUIRED_EVENT_IDS:
        raise ReviewBlocked("expected_event_ids must include HO-DET-010 required event IDs")
    if sorted(manifest.get("expected_rule_ids", [])) != REQUIRED_WAZUH_RULE_FAMILY:
        raise ReviewBlocked("expected_rule_ids must include required rule metadata")


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
        "allowed_claim": SAFE_ALLOWED_CLAIM if final_status == "PASS" else None,
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
    telemetry = _load_json(run_dir / "telemetry-contract-check.json")
    validation = _load_json(run_dir / "validation-result.json")
    signal = _load_json(run_dir / "synthetic-signal.json")
    proofcard = _load_json(run_dir / "proofcard.json")
    claim_authority = _load_json(run_dir / "claim-authority.json")
    reviewer_pack = (run_dir / "reviewer-pack.md").read_text(encoding="utf-8")
    if telemetry.get("required_source") != "Windows Security EventChannel":
        errors.append("telemetry contract must use Windows Security EventChannel")
    if telemetry.get("event_ids") != REQUIRED_EVENT_IDS:
        errors.append("telemetry contract missing HO-DET-010 event IDs")
    if telemetry.get("wazuh_rule_family") != REQUIRED_WAZUH_RULE_FAMILY:
        errors.append("telemetry contract missing Wazuh rule metadata")
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
