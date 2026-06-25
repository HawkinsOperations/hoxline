from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
from typing import Any

PRODUCT = "Hoxline by HawkinsOperations"
DOCTRINE = "AI is not the authority. Evidence is."
SCHEMA_VERSION = "hoxline-demo-run-v0"
DEMO_ID = "hoxline-one-command-reviewer-demo-v0"
ARTIFACT_ID = "HO-DET-010"
ARTIFACT_TYPE = "synthetic-local-admin-membership-change-detection"
PROOF_CEILING = "CONTROLLED_FIXTURE_VALIDATED"
PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
SAFE_ALLOWED_CLAIM = (
    "HO-DET-010 has a deterministic local fixture demonstration showing how Hoxline carries "
    "an AI-assisted detection artifact through intake, validation, ProofCard, and Claim Authority "
    "without claiming live runtime proof."
)
TALK_TRACK = (
    "In this demo, an AI-assisted detection artifact enters Hoxline. Hoxline captures it, "
    "links evidence, checks telemetry assumptions, validates a safe fixture, simulates a "
    "detection signal, enriches the finding, triages it, renders a ProofCard, and blocks "
    "unsupported public claims. Evidence decides what can be claimed. AI does not."
)
PRODUCT_LOOP = [
    "Artifact Intake",
    "Evidence Graph",
    "Telemetry Contract Check",
    "Controlled Validation",
    "Runtime Candidate / Signal Simulation",
    "Enrichment",
    "Triage",
    "ProofCard",
    "Claim Authority",
    "Safe Claim / Blocked Claim",
    "Reviewer Pack",
]
EXPECTED_OUTPUTS = [
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
    "run-summary.json",
]
REQUIRED_EVENT_IDS = [4720, 4725, 4726, 4732, 4733, 4738]
REQUIRED_WAZUH_RULE_FAMILY = [910101, 910102, 910103]
BLOCKED_CLAIM_FAMILIES = [
    "production ready",
    "public-safe runtime proof",
    "SOCaaS deployed",
    "customer deployed",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
    "final authorization",
    "case closure",
    "website rendering as proof",
    "green CI as approval",
]
PRIVATE_TERM_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bVM108\b",
        r"\bVM9000\b",
        r"\bho-wazuh-0[12]\b",
        r"\braw[_ -]?wazuh\b",
        r"\braw[_ -]?alert\b",
        r"\bendpoint log\b",
        r"\bgenerated password\b",
        r"\bprivate packet\b",
        r"\bprivate payload\b",
        r"\bexecution id\b",
        r"\bcommand line\b",
    )
]


class DemoError(ValueError):
    """Raised when a one-command demo cannot be built or verified safely."""


def default_output_dir(repo_root: Path | None = None) -> Path:
    root = repo_root or Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / ".hoxline" / "demo-runs" / stamp


def build_demo_run(
    repo_root: Path | None = None,
    fixture_path: Path | None = None,
    negative_fixture_path: Path | None = None,
) -> dict[str, Any]:
    root = repo_root or Path(__file__).resolve().parents[2]
    fixture = _load_json(fixture_path or root / "examples" / "demo" / "ho-det-010-safe-fixture.json")
    negative_fixture = _load_json(
        negative_fixture_path or root / "examples" / "demo" / "ho-det-010-safe-negative-fixture.json"
    )
    _validate_fixture(fixture, expected_detection=True)
    _validate_fixture(negative_fixture, expected_detection=False)

    intake = _artifact_intake()
    telemetry = _telemetry_contract_check(fixture)
    validation = _controlled_validation(fixture, negative_fixture, telemetry)
    signal = _synthetic_signal(fixture, validation)
    enrichment = _enrichment(fixture)
    triage = _triage(signal, enrichment, validation)
    proofcard = _proofcard(intake, telemetry, validation, signal, enrichment, triage)
    claim_authority = _claim_authority(proofcard)
    evidence_graph = _evidence_graph(intake, telemetry, validation, signal, proofcard, claim_authority)
    return {
        "intake": intake,
        "evidence_graph": evidence_graph,
        "telemetry_contract_check": telemetry,
        "validation_result": validation,
        "synthetic_signal": signal,
        "enrichment": enrichment,
        "triage_summary": _triage_markdown(triage),
        "proofcard": proofcard,
        "proofcard_markdown": _proofcard_markdown(proofcard),
        "claim_authority": claim_authority,
        "reviewer_pack": _reviewer_pack(proofcard, claim_authority, triage),
        "run_summary": _run_summary(
            intake, evidence_graph, telemetry, validation, signal, enrichment, triage, proofcard, claim_authority
        ),
    }


def write_demo_run(output_dir: Path, run: dict[str, Any], force: bool = False) -> Path:
    if output_dir.exists():
        if not force:
            raise DemoError(f"output directory already exists: {output_dir}")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    file_map = {
        "intake.json": run["intake"],
        "evidence-graph.json": run["evidence_graph"],
        "telemetry-contract-check.json": run["telemetry_contract_check"],
        "validation-result.json": run["validation_result"],
        "synthetic-signal.json": run["synthetic_signal"],
        "enrichment.json": run["enrichment"],
        "triage-summary.md": run["triage_summary"],
        "proofcard.json": run["proofcard"],
        "proofcard.md": run["proofcard_markdown"],
        "claim-authority.json": run["claim_authority"],
        "reviewer-pack.md": run["reviewer_pack"],
        "run-summary.json": run["run_summary"],
    }
    for name, value in file_map.items():
        path = output_dir / name
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_dir


def verify_demo_run_dir(input_path: Path) -> list[str]:
    run_dir = input_path.parent if input_path.name == "run-summary.json" else input_path
    errors: list[str] = []
    for name in EXPECTED_OUTPUTS:
        if not (run_dir / name).is_file():
            errors.append(f"missing output file: {name}")
    if errors:
        return errors
    try:
        summary = _load_json(run_dir / "run-summary.json")
        proofcard = _load_json(run_dir / "proofcard.json")
        claim_authority = _load_json(run_dir / "claim-authority.json")
        telemetry = _load_json(run_dir / "telemetry-contract-check.json")
        validation = _load_json(run_dir / "validation-result.json")
        signal = _load_json(run_dir / "synthetic-signal.json")
        reviewer_pack = (run_dir / "reviewer-pack.md").read_text(encoding="utf-8")
    except (OSError, DemoError) as exc:
        return [str(exc)]
    expected = {
        "schema_version": SCHEMA_VERSION,
        "demo_id": DEMO_ID,
        "artifact_id": ARTIFACT_ID,
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "runtime_rerun": False,
        "wazuh_mutation": False,
        "private_evidence_committed": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
    }
    for field, value in expected.items():
        if summary.get(field) != value:
            errors.append(f"run-summary field {field} must be {value!r}")
    if summary.get("product_loop") != PRODUCT_LOOP:
        errors.append("run-summary product_loop must match demo loop")
    if sorted(summary.get("outputs", [])) != sorted(EXPECTED_OUTPUTS):
        errors.append("run-summary outputs must list every expected output")
    if telemetry.get("event_ids") != REQUIRED_EVENT_IDS:
        errors.append("telemetry contract must list HO-DET-010 event IDs")
    if telemetry.get("wazuh_rule_family") != REQUIRED_WAZUH_RULE_FAMILY:
        errors.append("telemetry contract must list HO-DET-010 Wazuh rule family")
    if validation.get("result") != "pass" or validation.get("endpoint_mutation") is not False:
        errors.append("validation must pass without endpoint mutation")
    if signal.get("detection_fired") is not True or signal.get("source") != "safe bundled fixture":
        errors.append("synthetic signal must fire from safe bundled fixture only")
    if proofcard.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        errors.append("ProofCard must keep public_safe_status NOT_PUBLIC_SAFE")
    if proofcard.get("human_review_required") is not True:
        errors.append("ProofCard must keep human_review_required true")
    if proofcard.get("ai_disposition_authority") is not False:
        errors.append("ProofCard must keep ai_disposition_authority false")
    if not claim_authority.get("allowed_claims"):
        errors.append("Claim Authority must emit at least one allowed demo claim")
    blocked = {item.get("claim") for item in claim_authority.get("blocked_claims", []) if isinstance(item, dict)}
    missing = [claim for claim in BLOCKED_CLAIM_FAMILIES if claim not in blocked]
    if missing:
        errors.append(f"Claim Authority missing blocked claim families: {', '.join(missing)}")
    for heading in ("## What This Proves", "## What This Does Not Prove"):
        if heading not in reviewer_pack:
            errors.append(f"reviewer pack missing heading: {heading}")
    private_hits = _private_term_hits(run_dir)
    if private_hits:
        errors.append(f"private/raw term emitted in demo outputs: {', '.join(private_hits)}")
    return errors


def render_quickstart_console(output_dir: Path, run: dict[str, Any]) -> str:
    lines = [
        "Hoxline one-command reviewer demo v0",
        f"Output: {output_dir}",
        "",
        "1. Artifact intake created.",
        "2. Evidence graph linked.",
        "3. Telemetry contract checked.",
        "4. Controlled validation passed using bundled fixture.",
        "5. Safe synthetic signal/detection event fired.",
        "6. Enrichment attached ATT&CK / source / field mapping.",
        "7. Triage summary generated.",
        "8. ProofCard rendered.",
        "9. Claim Authority emitted allowed claim.",
        "10. Unsupported public claims blocked.",
        "11. Reviewer pack written.",
        "",
        f"Allowed demo claim: {run['claim_authority']['allowed_claims'][0]}",
        "Boundary: fixture-only; no endpoint mutation; no runtime proof; NOT_PUBLIC_SAFE; human review required.",
        f"Open next: {output_dir / 'reviewer-pack.md'}",
    ]
    return "\n".join(lines) + "\n"


def _artifact_intake() -> dict[str, Any]:
    return {
        "schema_version": "artifact-intake-v1",
        "intake_id": "intake-ho-det-010-demo-v0",
        "artifact_id": ARTIFACT_ID,
        "artifact_type": ARTIFACT_TYPE,
        "source_owner": "hawkinsoperations-detections",
        "source_label": "synthetic demo fixture for local Administrators membership change logic",
        "ai_assisted": True,
        "initial_claim_ceiling": PROOF_CEILING,
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "notes": [
            "Fixture is synthetic and local-only.",
            "No users, groups, endpoints, Wazuh systems, or private infrastructure are touched.",
        ],
    }


def _telemetry_contract_check(fixture: dict[str, Any]) -> dict[str, Any]:
    observed_event_ids = sorted({int(event["event_id"]) for event in fixture["events"]})
    return {
        "schema_version": "telemetry-contract-check-v0",
        "artifact_id": ARTIFACT_ID,
        "required_source": "Windows Security EventChannel",
        "event_ids": REQUIRED_EVENT_IDS,
        "fixture_event_ids": observed_event_ids,
        "wazuh_rule_family": REQUIRED_WAZUH_RULE_FAMILY,
        "required_fields": ["event_id", "channel", "target_account", "group_name", "action", "actor"],
        "missing_required_fields": [],
        "result": "pass",
        "scope": "pass for fixture only",
        "network_required": False,
        "endpoint_mutation": False,
    }


def _controlled_validation(fixture: dict[str, Any], negative_fixture: dict[str, Any], telemetry: dict[str, Any]) -> dict[str, Any]:
    positive_match = _fixture_matches_detection(fixture)
    negative_match = _fixture_matches_detection(negative_fixture)
    result = "pass" if positive_match and not negative_match and telemetry["result"] == "pass" else "fail"
    return {
        "schema_version": "validation-result-v0",
        "artifact_id": ARTIFACT_ID,
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


def _synthetic_signal(fixture: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "synthetic-signal-v0",
        "artifact_id": ARTIFACT_ID,
        "signal_id": "synthetic-signal-ho-det-010-demo-v0",
        "source": "safe bundled fixture",
        "detection_fired": validation["result"] == "pass" and _fixture_matches_detection(fixture),
        "simulation_only": True,
        "endpoint_mutation": False,
        "backend_mutation": False,
        "explanation": "The signal is derived from fixture fields and does not create operating-system events.",
    }


def _enrichment(fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "enrichment-v0",
        "artifact_id": ARTIFACT_ID,
        "attack_mapping": [{"technique_id": "T1098", "technique": "Account Manipulation", "scope": "demo mapping only"}],
        "event_id_mapping": {
            "4720": "user account created",
            "4725": "user account disabled",
            "4726": "user account deleted",
            "4732": "member added to local group",
            "4733": "member removed from local group",
            "4738": "user account changed",
        },
        "source_mapping": {"channel": "Windows Security EventChannel", "fixture_host": fixture["host"], "fixture_scope": "synthetic demo host"},
        "field_mapping": {"event_id": "event identifier", "target_account": "account under review", "group_name": "local group name", "action": "membership or account action", "actor": "synthetic actor label"},
        "confidence": "bounded-demo-high",
        "severity": "medium",
    }


def _triage(signal: dict[str, Any], enrichment: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "triage-summary-v0",
        "artifact_id": ARTIFACT_ID,
        "what_happened": "A synthetic fixture represented a local Administrators membership change pattern.",
        "why_it_matters": "Unexpected local administrator membership changes can indicate account or privilege manipulation.",
        "evidence_exists": ["artifact intake record", "evidence graph", "telemetry contract check", "positive and negative synthetic fixtures", "fixture-derived synthetic signal", "enrichment mapping", "ProofCard", "Claim Authority decision"],
        "missing_evidence": ["public-safe runtime proof", "public signal proof", "human review gate completion", "final authorization record"],
        "next_gate": "human_review_gate",
        "detection_fired": signal["detection_fired"],
        "validation_result": validation["result"],
        "attack_mapping": enrichment["attack_mapping"],
    }


def _proofcard(intake: dict[str, Any], telemetry: dict[str, Any], validation: dict[str, Any], signal: dict[str, Any], enrichment: dict[str, Any], triage: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "proofcard-v1",
        "proofcard_id": "proofcard-ho-det-010-demo-v0",
        "detection_id": ARTIFACT_ID,
        "artifact_id": intake["artifact_id"],
        "proof_owner": "hoxline-demo-fixture",
        "proof_ceiling": PROOF_CEILING,
        "proof_ceiling_meaning": "LOCAL_FIXTURE_DEMONSTRATION_ONLY",
        "review_lane": "ONE_COMMAND_REVIEWER_DEMO_V0",
        "review_version": "v0",
        "owner_split": {"source_truth": "hawkinsoperations-detections", "behavior_truth": "bundled synthetic fixture", "platform_runtime_truth": "not asserted", "proof_authority": "not asserted by demo", "rendering": "local generated files only"},
        "telemetry_contract": telemetry,
        "controlled_validation": validation,
        "synthetic_signal": signal,
        "enrichment": enrichment,
        "triage": triage,
        "allowed_claims": [SAFE_ALLOWED_CLAIM],
        "blocked_claims": _blocked_claims(),
        "missing_evidence": triage["missing_evidence"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "runtime_active": False,
        "signal_observed": False,
        "next_gate": "human_review_gate",
    }


def _claim_authority(proofcard: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "claim-authority-v1",
        "decision_id": "claim-authority-ho-det-010-demo-v0",
        "artifact_id": ARTIFACT_ID,
        "proof_ceiling": proofcard["proof_ceiling"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "allowed_claims": list(proofcard["allowed_claims"]),
        "blocked_claims": _blocked_claims(),
        "safer_wording": ["Use fixture-only reviewer demo wording.", "Say the demo shows the governed loop locally; do not say it proves live runtime or public-safe status."],
    }


def _evidence_graph(intake: dict[str, Any], telemetry: dict[str, Any], validation: dict[str, Any], signal: dict[str, Any], proofcard: dict[str, Any], claim_authority: dict[str, Any]) -> dict[str, Any]:
    nodes = [
        _node("artifact-intake", "artifact_intake", intake["source_owner"], "PASS"),
        _node("telemetry-contract-check", "telemetry_contract_check", "hoxline-demo-fixture", telemetry["result"].upper()),
        _node("controlled-validation", "controlled_validation", "hoxline-demo-fixture", validation["result"].upper()),
        _node("synthetic-signal", "synthetic_signal", "hoxline-demo-fixture", "PASS"),
        _node("proofcard", "proofcard", proofcard["proof_owner"], "PASS"),
        _node("claim-authority", "claim_authority", "hoxline", "PASS"),
    ]
    return {
        "schema_version": "evidence-graph-v1",
        "graph_id": "evidence-graph-ho-det-010-demo-v0",
        "detection_id": ARTIFACT_ID,
        "artifact_id": ARTIFACT_ID,
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


def _run_summary(intake: dict[str, Any], evidence_graph: dict[str, Any], telemetry: dict[str, Any], validation: dict[str, Any], signal: dict[str, Any], enrichment: dict[str, Any], triage: dict[str, Any], proofcard: dict[str, Any], claim_authority: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "demo_id": DEMO_ID,
        "artifact_id": ARTIFACT_ID,
        "artifact_type": ARTIFACT_TYPE,
        "product": PRODUCT,
        "doctrine": DOCTRINE,
        "product_loop": PRODUCT_LOOP,
        "outputs": EXPECTED_OUTPUTS,
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "runtime_rerun": False,
        "wazuh_mutation": False,
        "private_evidence_committed": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "website_rendering_is_proof": False,
        "stage_results": {"intake": intake["intake_id"], "evidence_graph": evidence_graph["graph_id"], "telemetry_contract_check": telemetry["result"], "controlled_validation": validation["result"], "synthetic_signal": signal["detection_fired"], "enrichment": enrichment["confidence"], "triage": triage["next_gate"], "proofcard": proofcard["proofcard_id"], "claim_authority": claim_authority["decision_id"]},
    }


def _reviewer_pack(proofcard: dict[str, Any], claim_authority: dict[str, Any], triage: dict[str, Any]) -> str:
    lines = [
        "# Hoxline One-Command Reviewer Demo v0", "", f"Product: {PRODUCT}", "", f"Doctrine: {DOCTRINE}", "", f"Artifact: `{ARTIFACT_ID}`", "", "## 30-Second Talk Track", "", TALK_TRACK, "",
        "## What This Proves", "", "- A reviewer can run Hoxline locally against bundled synthetic fixtures.", "- Hoxline can produce intake, graph, telemetry, validation, signal simulation, enrichment, triage, ProofCard, Claim Authority, and reviewer-pack outputs.", "- Claim Authority allows only bounded demo wording and blocks stronger public claims.", "",
        "## What This Does Not Prove", "", "- It does not prove live runtime behavior.", "- It does not prove public signal observation.", "- It does not prove public-safe status, production readiness, deployment, approval, authorization, or case closure.", "- It does not touch endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, or ledgers.", "",
        "## Triage", "", f"- What happened: {triage['what_happened']}", f"- Why it matters: {triage['why_it_matters']}", f"- Next gate: `{triage['next_gate']}`", "", "## Allowed Claim", "", f"- {claim_authority['allowed_claims'][0]}", "", "## Blocked Claims", "",
    ]
    for item in claim_authority["blocked_claims"]:
        lines.append(f"- `{item['claim']}`: {item['safer_wording']}")
    lines.extend(["", "## Proof Boundary", "", f"- proof_ceiling: `{proofcard['proof_ceiling']}`", f"- public_safe_status: `{proofcard['public_safe_status']}`", f"- human_review_required: `{str(proofcard['human_review_required']).lower()}`", f"- ai_disposition_authority: `{str(proofcard['ai_disposition_authority']).lower()}`", "", "## Stage Outputs", ""])
    for name in EXPECTED_OUTPUTS:
        lines.append(f"- `{name}`")
    return "\n".join(lines) + "\n"


def _triage_markdown(triage: dict[str, Any]) -> str:
    lines = ["# Hoxline Demo Triage Summary", "", f"Artifact: `{ARTIFACT_ID}`", "", f"What happened: {triage['what_happened']}", "", f"Why it matters: {triage['why_it_matters']}", "", "Evidence exists:"]
    lines.extend(f"- {item}" for item in triage["evidence_exists"])
    lines.extend(["", "Missing evidence:"])
    lines.extend(f"- {item}" for item in triage["missing_evidence"])
    lines.extend(["", f"Next gate: `{triage['next_gate']}`", ""])
    return "\n".join(lines)


def _proofcard_markdown(proofcard: dict[str, Any]) -> str:
    lines = ["# Hoxline Demo ProofCard", "", f"Artifact: `{proofcard['artifact_id']}`", "", f"Proof ceiling: `{proofcard['proof_ceiling']}`", "", f"public_safe_status: `{proofcard['public_safe_status']}`", "", f"human_review_required: `{str(proofcard['human_review_required']).lower()}`", "", f"ai_disposition_authority: `{str(proofcard['ai_disposition_authority']).lower()}`", "", "## Allowed Claim", ""]
    lines.extend(f"- {claim}" for claim in proofcard["allowed_claims"])
    lines.extend(["", "## Blocked Claims", ""])
    lines.extend(f"- `{item['claim']}`: {item['safer_wording']}" for item in proofcard["blocked_claims"])
    lines.extend(["", "## Missing Evidence", ""])
    lines.extend(f"- `{item}`" for item in proofcard["missing_evidence"])
    lines.append("")
    return "\n".join(lines)


def _blocked_claims() -> list[dict[str, Any]]:
    return [{"claim": claim, "status": "BLOCKED", "reason": "Requires evidence or authority outside this local fixture demo.", "required_evidence": _required_evidence_for_claim(claim), "safer_wording": _safer_wording_for_claim(claim)} for claim in BLOCKED_CLAIM_FAMILIES]


def _required_evidence_for_claim(claim: str) -> list[str]:
    mapping = {
        "production ready": ["runtime_evidence", "deployment_evidence", "human_review_gate_complete"],
        "public-safe runtime proof": ["runtime_evidence", "public_safe_authorization"],
        "SOCaaS deployed": ["service_deployment_evidence", "public_safe_authorization"],
        "customer deployed": ["customer_deployment_evidence", "public_safe_authorization"],
        "autonomous SOC": ["human_review_gate_complete", "disposition_authority_record"],
        "AI-approved disposition": ["human_review_gate_complete"],
        "analyst-approved disposition": ["analyst_review_record"],
        "final authorization": ["final_authorization_record"],
        "case closure": ["case_closure_record"],
        "website rendering as proof": ["proof_authority_record"],
        "green CI as approval": ["human_review_gate_complete"],
    }
    return mapping[claim]


def _safer_wording_for_claim(claim: str) -> str:
    return {
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
    }[claim]


def _node(node_id: str, node_type: str, owner: str, status: str) -> dict[str, str]:
    return {"id": node_id, "type": node_type, "owner": owner, "status": status}


def _validate_fixture(fixture: dict[str, Any], expected_detection: bool) -> None:
    expected = {"schema_version": "hoxline-demo-fixture-v0", "artifact_id": ARTIFACT_ID, "fixture_kind": "synthetic-demo-only", "safe_fixture": True, "endpoint_mutation": False, "runtime_required": False, "network_required": False}
    for field, value in expected.items():
        if fixture.get(field) != value:
            raise DemoError(f"fixture field {field} must be {value!r}")
    if fixture.get("expected_detection") is not expected_detection:
        raise DemoError(f"fixture expected_detection must be {expected_detection!r}")
    events = fixture.get("events")
    if not isinstance(events, list) or not events:
        raise DemoError("fixture events must be a non-empty list")
    for event in events:
        if not isinstance(event, dict):
            raise DemoError("fixture events must be objects")
        for field in ("event_id", "channel", "target_account", "group_name", "action", "actor"):
            if field not in event:
                raise DemoError(f"fixture event missing field: {field}")
    if expected_detection and not _fixture_matches_detection(fixture):
        raise DemoError("positive fixture does not match demo detection")
    if not expected_detection and _fixture_matches_detection(fixture):
        raise DemoError("negative fixture unexpectedly matches demo detection")


def _fixture_matches_detection(fixture: dict[str, Any]) -> bool:
    for event in fixture.get("events", []):
        if not isinstance(event, dict):
            continue
        if int(event.get("event_id", 0)) == 4732 and event.get("channel") == "Windows Security" and event.get("group_name") == "Administrators" and event.get("action") == "member_added":
            return True
    return False


def _private_term_hits(run_dir: Path) -> list[str]:
    hits: list[str] = []
    for name in EXPECTED_OUTPUTS:
        text = (run_dir / name).read_text(encoding="utf-8")
        for pattern in PRIVATE_TERM_PATTERNS:
            if pattern.search(text):
                hits.append(f"{name}:{pattern.pattern}")
    return hits


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise DemoError(f"input must be a JSON object: {path}")
    return deepcopy(data)
