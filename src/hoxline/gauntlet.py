from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


CANONICAL_LOOP = [
    "AI-assisted security work",
    "Artifact Intake",
    "Evidence Graph",
    "Telemetry Contract Check",
    "Controlled Validation",
    "Runtime Candidate Ledger",
    "Signal Observation",
    "Human Review Gate",
    "ProofCard",
    "Claim Authority",
    "Safe Claim / Blocked Claim",
]

VALID_STAGE_STATUSES = {
    "PASS",
    "BLOCKED",
    "MISSING_EVIDENCE",
    "HUMAN_REVIEW_REQUIRED",
    "NOT_PUBLIC_SAFE",
    "REFERENCE_ONLY",
}

SAFE_CLAIM = (
    "HO-DET-001 has controlled validation evidence from controlled positive "
    "and negative process-creation fixtures and remains under review."
)

REQUIRED_BLOCKED_CLAIMS = [
    "runtime-active",
    "runtime proven",
    "signal observed",
    "public-safe proof",
    "production-ready",
    "SOCaaS-ready",
    "SOCaaS deployed",
    "customer deployed",
    "AI approved",
    "analyst approved",
    "final human authorization",
    "case closed",
    "public runtime proof",
    "public signal proof",
    "revenue",
    "legal availability",
    "product-market fit",
]

ADDITIONAL_BLOCKED_CLAIMS = {
    "public-safe proof": {
        "reason": "Requires separate public wording, privacy, evidence-link, and approval review.",
        "required_evidence": ["public_safe_authorization"],
        "safer_wording": "public release status is not asserted",
    },
    "revenue": {
        "reason": "Business outcome evidence is outside this controlled-validation run.",
        "required_evidence": ["business_evidence_record", "human_review_gate_complete"],
        "safer_wording": "business outcome evidence is not asserted",
    },
    "legal availability": {
        "reason": "Legal availability requires separate legal review and authorization.",
        "required_evidence": ["legal_review_record", "public_safe_authorization"],
        "safer_wording": "legal availability is not asserted",
    },
    "product-market fit": {
        "reason": "Market-fit evidence is outside this controlled-validation run.",
        "required_evidence": ["business_evidence_record", "human_review_gate_complete"],
        "safer_wording": "market-fit evidence is not asserted",
    },
}

BLOCKED_MARKDOWN_LABELS = {
    "case closed": "case-closure wording",
    "final human authorization": "final authorization or final human authorization",
}


class GauntletError(ValueError):
    """Raised when a gauntlet run cannot be built from local artifacts."""


def build_full_loop_run(artifact_id: str, repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or Path(__file__).resolve().parents[2]
    if artifact_id != "HO-DET-001":
        raise GauntletError(f"unsupported artifact: {artifact_id}")

    proofcard = _load_json(root / "examples" / "gauntlet" / "ho-det-001-proofcard-v0.json")
    evidence_graph = _load_json(root / "examples" / "gauntlet" / "ho-det-001-evidence-graph-v0.json")
    promotion_state = _load_json(root / "examples" / "gauntlet" / "ho-det-001-promotion-state-v0.json")
    demo_manifest = _load_json(root / "examples" / "demo" / "ho-det-001-controlled-demo-manifest.json")

    _validate_artifact_ids(artifact_id, proofcard, evidence_graph, promotion_state, demo_manifest)

    blocked_claims = _blocked_claims(proofcard)
    missing_evidence = _missing_evidence(proofcard, demo_manifest, blocked_claims)
    public_safe = bool(proofcard.get("public_safe"))
    human_review_required = bool(proofcard.get("human_review_required"))

    report: dict[str, Any] = {
        "run_id": "ho-det-001-full-loop-run-v0",
        "artifact_id": artifact_id,
        "product": "Hoxline by HawkinsOperations",
        "proof_ceiling": proofcard["proof_ceiling"],
        "public_safe": public_safe,
        "human_review_required": human_review_required,
        "loop_stages": _loop_stages(proofcard, evidence_graph, promotion_state, demo_manifest),
        "allowed_claims": list(proofcard.get("allowed_claims") or [SAFE_CLAIM]),
        "blocked_claims": blocked_claims,
        "missing_evidence": missing_evidence,
        "authority_sources": list(proofcard["authority_sources"]),
        "reviewer_summary": _reviewer_summary(proofcard, public_safe, human_review_required),
        "non_claims": _non_claims(proofcard, demo_manifest),
    }
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Gauntlet Full-Loop Run v0",
        "",
        f"Run ID: `{report['run_id']}`",
        "",
        f"Artifact: `{report['artifact_id']}`",
        "",
        f"Product: {report['product']}",
        "",
        f"Proof ceiling: `{report['proof_ceiling']}`",
        "",
        f"public_safe value: `{str(report['public_safe']).lower()}`",
        "",
        f"Human review required: `{str(report['human_review_required']).lower()}`",
        "",
        "## Canonical Loop Coverage",
        "",
        "| Stage | Status | Reviewer note |",
        "|---|---|---|",
    ]

    for stage in report["loop_stages"]:
        lines.append(f"| {stage['stage']} | `{stage['status']}` | {stage['reviewer_note']} |")

    lines.extend(
        [
            "",
            "## Allowed Claim",
            "",
        ]
    )
    for claim in report["allowed_claims"]:
        lines.append(f"- {claim}")

    lines.extend(
        [
            "",
            "## Blocked Claim Boundaries",
            "",
            "The runner records blocked claim families as boundaries. It does not promote them.",
            "",
        ]
    )
    for claim in report["blocked_claims"]:
        label = BLOCKED_MARKDOWN_LABELS.get(claim["claim"], claim["claim"])
        lines.append(f"- This run does not claim {label}. Safer wording: {claim['safer_wording']}.")

    lines.extend(
        [
            "",
            "## Missing Evidence",
            "",
        ]
    )
    for item in report["missing_evidence"]:
        lines.append(f"- `{item}`")

    lines.extend(
        [
            "",
            "## Authority Sources",
            "",
        ]
    )
    for source in report["authority_sources"]:
        lines.append(f"- `{source}`")

    lines.extend(
        [
            "",
            "## Non-Claims",
            "",
        ]
    )
    for non_claim in report["non_claims"]:
        label = BLOCKED_MARKDOWN_LABELS.get(non_claim, non_claim)
        lines.append(f"- This run does not claim {label}.")

    lines.extend(
        [
            "",
            "## Reviewer Summary",
            "",
            report["reviewer_summary"],
            "",
        ]
    )
    return "\n".join(lines)


def verify_full_loop_run_file(input_path: Path, schema_path: Path) -> list[str]:
    schema = _load_json(schema_path)
    report = _load_json(input_path)
    return verify_full_loop_run(report, schema)


def verify_full_loop_run(report: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    _validate_schema_identity(schema, errors)
    _validate_required_output_fields(report, schema, errors)
    _validate_fixed_invariants(report, errors)
    _validate_loop_contract(report, errors)
    _validate_claim_boundary_contract(report, errors)
    return errors


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GauntletError(f"required artifact not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise GauntletError(f"required artifact is not a JSON object: {path}")
    return data


def _validate_schema_identity(schema: dict[str, Any], errors: list[str]) -> None:
    if schema.get("title") != "Hoxline Gauntlet Full-Loop Run v0":
        errors.append("schema title must be Hoxline Gauntlet Full-Loop Run v0")
    if schema.get("$id") != "https://hawkinsoperations.dev/hoxline/schemas/gauntlet-full-loop-run-v0.schema.json":
        errors.append("schema id must identify gauntlet-full-loop-run-v0")


def _validate_required_output_fields(report: dict[str, Any], schema: dict[str, Any], errors: list[str]) -> None:
    required = schema.get("required")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        errors.append("schema required field list is missing or invalid")
        return

    for field in required:
        if field not in report:
            errors.append(f"missing required field: {field}")
    for field in report:
        if field not in required:
            errors.append(f"unexpected field: {field}")

    expected_types = {
        "run_id": str,
        "artifact_id": str,
        "product": str,
        "proof_ceiling": str,
        "public_safe": bool,
        "human_review_required": bool,
        "loop_stages": list,
        "allowed_claims": list,
        "blocked_claims": list,
        "missing_evidence": list,
        "authority_sources": list,
        "reviewer_summary": str,
        "non_claims": list,
    }
    for field, expected_type in expected_types.items():
        if field in report and not isinstance(report[field], expected_type):
            errors.append(f"field {field} must be {expected_type.__name__}")

    for field in ("allowed_claims", "missing_evidence", "authority_sources", "non_claims"):
        value = report.get(field)
        if isinstance(value, list) and not all(isinstance(item, str) and item for item in value):
            errors.append(f"field {field} must contain non-empty strings")


def _validate_fixed_invariants(report: dict[str, Any], errors: list[str]) -> None:
    fixed_values = {
        "artifact_id": "HO-DET-001",
        "product": "Hoxline by HawkinsOperations",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "public_safe": False,
        "human_review_required": True,
    }
    for field, expected in fixed_values.items():
        if report.get(field) != expected:
            errors.append(f"field {field} must be {expected!r}")


def _validate_loop_contract(report: dict[str, Any], errors: list[str]) -> None:
    stages = report.get("loop_stages")
    if not isinstance(stages, list):
        errors.append("loop_stages must be a list")
        return
    if len(stages) != len(CANONICAL_LOOP):
        errors.append("loop_stages must contain exactly 11 stages")
        return

    observed_order: list[str] = []
    stage_by_name: dict[str, dict[str, Any]] = {}
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            errors.append(f"loop_stages[{index}] must be an object")
            continue
        _validate_exact_keys(stage, {"stage", "status", "reviewer_note", "authority_refs", "missing_evidence"}, f"loop_stages[{index}]", errors)
        name = stage.get("stage")
        status = stage.get("status")
        observed_order.append(name if isinstance(name, str) else "")
        if isinstance(name, str):
            stage_by_name[name] = stage
        if status not in VALID_STAGE_STATUSES:
            errors.append(f"loop stage {name or index} has invalid status: {status}")
        for field in ("reviewer_note",):
            if not isinstance(stage.get(field), str) or not stage.get(field):
                errors.append(f"loop stage {name or index} field {field} must be a non-empty string")
        for field in ("authority_refs", "missing_evidence"):
            value = stage.get(field)
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                errors.append(f"loop stage {name or index} field {field} must be a string list")

    if observed_order != CANONICAL_LOOP:
        errors.append("loop_stages order must match the canonical Hoxline loop")

    _validate_stage_not_pass_without_evidence(stage_by_name, "Runtime Candidate Ledger", "runtime_evidence", errors)
    _validate_stage_not_pass_without_evidence(stage_by_name, "Signal Observation", "signal_observation_evidence", errors)


def _validate_stage_not_pass_without_evidence(
    stage_by_name: dict[str, dict[str, Any]],
    stage_name: str,
    missing_evidence_id: str,
    errors: list[str],
) -> None:
    stage = stage_by_name.get(stage_name)
    if not stage:
        return
    if stage.get("status") != "PASS":
        return
    authority_refs = stage.get("authority_refs")
    if not isinstance(authority_refs, list) or not authority_refs:
        errors.append(f"{stage_name} cannot be PASS without authority_refs evidence")
    missing_evidence = stage.get("missing_evidence")
    if isinstance(missing_evidence, list) and missing_evidence_id in missing_evidence:
        errors.append(f"{stage_name} cannot be PASS while {missing_evidence_id} remains missing")


def _validate_claim_boundary_contract(report: dict[str, Any], errors: list[str]) -> None:
    allowed_claims = report.get("allowed_claims")
    if isinstance(allowed_claims, list) and SAFE_CLAIM not in allowed_claims:
        errors.append("allowed_claims must contain the controlled-validation safe claim")

    blocked_claims = report.get("blocked_claims")
    if not isinstance(blocked_claims, list):
        errors.append("blocked_claims must be a list")
        return

    observed: set[str] = set()
    for index, item in enumerate(blocked_claims):
        if not isinstance(item, dict):
            errors.append(f"blocked_claims[{index}] must be an object")
            continue
        _validate_exact_keys(item, {"claim", "status", "reason", "required_evidence", "safer_wording"}, f"blocked_claims[{index}]", errors)
        claim = item.get("claim")
        if isinstance(claim, str):
            observed.add(claim)
        if item.get("status") != "BLOCKED":
            errors.append(f"blocked claim {claim or index} must have status BLOCKED")
        for field in ("reason", "safer_wording"):
            if not isinstance(item.get(field), str) or not item.get(field):
                errors.append(f"blocked claim {claim or index} field {field} must be a non-empty string")
        required_evidence = item.get("required_evidence")
        if not isinstance(required_evidence, list) or not all(isinstance(value, str) for value in required_evidence):
            errors.append(f"blocked claim {claim or index} required_evidence must be a string list")

    missing = [claim for claim in REQUIRED_BLOCKED_CLAIMS if claim not in observed]
    if missing:
        errors.append(f"blocked_claims missing required families: {', '.join(missing)}")


def _validate_exact_keys(item: dict[str, Any], allowed_keys: set[str], label: str, errors: list[str]) -> None:
    missing = sorted(allowed_keys - set(item))
    unexpected = sorted(set(item) - allowed_keys)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if unexpected:
        errors.append(f"{label} unexpected fields: {', '.join(unexpected)}")


def _validate_artifact_ids(artifact_id: str, *records: dict[str, Any]) -> None:
    for record in records:
        if record.get("artifact_id") != artifact_id:
            raise GauntletError(f"artifact mismatch: expected {artifact_id}, found {record.get('artifact_id')}")


def _loop_stages(
    proofcard: dict[str, Any],
    evidence_graph: dict[str, Any],
    promotion_state: dict[str, Any],
    demo_manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    graph_nodes = {node.get("type"): node for node in evidence_graph.get("nodes", []) if isinstance(node, dict)}
    runtime = promotion_state.get("runtime", {})
    signal = promotion_state.get("signal", {})
    human_review = promotion_state.get("human_review_gate", {})
    proofcard_state = promotion_state.get("proofcard", {})
    gates = promotion_state.get("gates", {})

    stages = [
        _stage(
            "AI-assisted security work",
            "REFERENCE_ONLY",
            "Artifact is treated as referenced AI-assisted security work; AI is not authority.",
            [demo_manifest["demo_id"]],
        ),
        _stage(
            "Artifact Intake",
            "PASS" if gates.get("artifact_intake") == "accepted" else "BLOCKED",
            "Artifact intake is accepted for this controlled run.",
            [demo_manifest["demo_id"]],
        ),
        _stage(
            "Evidence Graph",
            "PASS" if evidence_graph.get("graph_id") else "MISSING_EVIDENCE",
            "Evidence graph example links the artifact through the loop.",
            [evidence_graph.get("graph_id", "missing")],
        ),
        _stage(
            "Telemetry Contract Check",
            "PASS" if gates.get("telemetry_contract_check") == "passed" else "REFERENCE_ONLY",
            "Telemetry contract support is referenced from source-truth artifacts.",
            [graph_nodes.get("telemetry_contract_check", {}).get("id", "missing")],
        ),
        _stage(
            "Controlled Validation",
            "PASS" if gates.get("controlled_validation") == "passed" else "BLOCKED",
            "Controlled validation is limited to controlled positive and negative process-creation fixtures.",
            proofcard.get("authority_sources", []),
        ),
        _stage(
            "Runtime Candidate Ledger",
            "PASS" if runtime.get("observed") and runtime.get("evidence_refs") else "BLOCKED",
            "Runtime evidence is missing; this run does not claim runtime-active status.",
            runtime.get("evidence_refs", []),
            ["runtime_evidence"] if not runtime.get("evidence_refs") else [],
        ),
        _stage(
            "Signal Observation",
            "PASS" if signal.get("observed") and signal.get("evidence_refs") else "MISSING_EVIDENCE",
            "Signal evidence is missing; this run does not claim signal observed status.",
            signal.get("evidence_refs", []),
            ["signal_observation_evidence"] if not signal.get("evidence_refs") else [],
        ),
        _stage(
            "Human Review Gate",
            "HUMAN_REVIEW_REQUIRED",
            "Human review remains required; no final authorization claim is made.",
            human_review.get("review_refs", []),
            ["human_review_gate_complete"],
        ),
        _stage(
            "ProofCard",
            "PASS" if proofcard_state.get("proofcard_id") else "MISSING_EVIDENCE",
            "ProofCard v0 exists as a reviewer bridge, not proof authority.",
            proofcard_state.get("evidence_refs", []),
        ),
        _stage(
            "Claim Authority",
            "PASS",
            "Claim Authority preserves allowed wording and blocked wording boundaries.",
            ["examples/policies/default-claim-authority-policy.yml"],
        ),
        _stage(
            "Safe Claim / Blocked Claim",
            "PASS" if proofcard.get("allowed_claims") and proofcard.get("blocked_claims") else "BLOCKED",
            "Safe and blocked outputs are present under the controlled-validation proof ceiling.",
            ["examples/gauntlet/ho-det-001-proofcard-v0.json"],
        ),
    ]

    observed_loop = promotion_state.get("loop", [])
    if observed_loop and observed_loop != CANONICAL_LOOP:
        raise GauntletError("promotion-state loop order does not match the canonical loop")
    if [stage["stage"] for stage in stages] != CANONICAL_LOOP:
        raise GauntletError("runner loop order does not match the canonical loop")
    return stages


def _stage(
    name: str,
    status: str,
    reviewer_note: str,
    authority_refs: list[str],
    missing_evidence: list[str] | None = None,
) -> dict[str, Any]:
    if status not in VALID_STAGE_STATUSES:
        raise GauntletError(f"invalid stage status for {name}: {status}")
    return {
        "stage": name,
        "status": status,
        "reviewer_note": reviewer_note,
        "authority_refs": [ref for ref in authority_refs if ref],
        "missing_evidence": missing_evidence or [],
    }


def _blocked_claims(proofcard: dict[str, Any]) -> list[dict[str, Any]]:
    by_claim: dict[str, dict[str, Any]] = {}
    for item in proofcard.get("blocked_claims", []):
        claim = item.get("claim")
        if not isinstance(claim, str):
            continue
        by_claim[claim] = {
            "claim": claim,
            "status": "BLOCKED",
            "reason": item.get("reason", "Requires evidence outside this controlled-validation run."),
            "required_evidence": list(item.get("required_evidence", [])),
            "safer_wording": _safer_wording(claim, proofcard),
        }

    for claim in REQUIRED_BLOCKED_CLAIMS:
        if claim in by_claim:
            continue
        extra = ADDITIONAL_BLOCKED_CLAIMS.get(
            claim,
            {
                "reason": "Requires evidence outside this controlled-validation run.",
                "required_evidence": ["human_review_gate_complete"],
                "safer_wording": "claim is not asserted",
            },
        )
        by_claim[claim] = {
            "claim": claim,
            "status": "BLOCKED",
            "reason": extra["reason"],
            "required_evidence": list(extra["required_evidence"]),
            "safer_wording": extra["safer_wording"],
        }

    ordered = [deepcopy(by_claim[claim]) for claim in REQUIRED_BLOCKED_CLAIMS]
    for claim, item in sorted(by_claim.items()):
        if claim not in REQUIRED_BLOCKED_CLAIMS:
            ordered.append(deepcopy(item))
    return ordered


def _safer_wording(claim: str, proofcard: dict[str, Any]) -> str:
    for suggestion in proofcard.get("safer_suggestions", []):
        if suggestion.get("blocked_claim") == claim:
            return suggestion.get("suggestion", "claim is not asserted")
    if claim in ADDITIONAL_BLOCKED_CLAIMS:
        return ADDITIONAL_BLOCKED_CLAIMS[claim]["safer_wording"]
    return "claim is not asserted"


def _missing_evidence(
    proofcard: dict[str, Any],
    demo_manifest: dict[str, Any],
    blocked_claims: list[dict[str, Any]],
) -> list[str]:
    evidence = set(proofcard.get("required_evidence", []))
    evidence.update(demo_manifest.get("required_next_evidence", []))
    for claim in blocked_claims:
        evidence.update(claim.get("required_evidence", []))
    return sorted(evidence)


def _non_claims(proofcard: dict[str, Any], demo_manifest: dict[str, Any]) -> list[str]:
    values = list(proofcard.get("non_claims", []))
    for item in demo_manifest.get("non_claims", []):
        if item not in values:
            values.append(item)
    return values


def _reviewer_summary(proofcard: dict[str, Any], public_safe: bool, human_review_required: bool) -> str:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return (
        f"Generated {timestamp}. HO-DET-001 remains bounded to "
        f"{proofcard['proof_ceiling']} with public_safe={str(public_safe).lower()} "
        f"and human_review_required={str(human_review_required).lower()}. "
        "The only allowed claim is controlled-validation wording. Runtime, signal, "
        "public release, service, business, legal, approval, and case-disposition "
        "claims remain blocked until their required evidence and review records exist."
    )
