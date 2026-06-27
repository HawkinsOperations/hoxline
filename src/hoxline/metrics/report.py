from __future__ import annotations

from datetime import timezone, datetime
import json
from pathlib import Path
from typing import Any

from .evaluator import evaluate_detection_fixture, load_synthetic_events, telemetry_coverage


PROOF_CEILING = "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY"
REQUIRED_PROOFCARD_SECTIONS = (
    "schema_version",
    "proofcard_id",
    "artifact_id",
    "title",
    "proof_ceiling",
    "what_exists",
    "what_was_tested",
    "validation_result",
    "failed_or_blocked",
    "required_telemetry",
    "runtime_state",
    "signal_state",
    "human_review_state",
    "allowed_claims",
    "blocked_claims",
    "public_safe",
)


def build_work_impact_report(
    *,
    events_path: str | Path,
    artifact_path: str | Path,
    proofcard_path: str | Path,
    claim_output_path: str | Path,
    generated_at: str | None = None,
) -> dict[str, Any]:
    artifact = _load_json_object(artifact_path)
    proofcard = _load_json_object(proofcard_path)
    claim_output = _load_json_object(claim_output_path)
    events_fixture = load_synthetic_events(events_path)
    events = events_fixture["events"]
    if not isinstance(events, list):
        raise ValueError("synthetic event fixture must include an events list")

    _require(artifact, "artifact_id", "HOX-GAUNTLET-001")
    _require(artifact, "proof_ceiling", PROOF_CEILING)
    _require(proofcard, "artifact_id", "HOX-GAUNTLET-001")
    _require(proofcard, "proof_ceiling", PROOF_CEILING)
    _require(claim_output, "artifact_id", "HOX-GAUNTLET-001")
    _require(claim_output, "proof_ceiling", PROOF_CEILING)

    detection = evaluate_detection_fixture(events_path)
    required_fields = _required_telemetry_fields(artifact)
    telemetry = telemetry_coverage([event for event in events if isinstance(event, dict)], required_fields)
    claim_metrics = _claim_authority_metrics(claim_output)
    proofcard_metrics = _proofcard_metrics(proofcard)
    evidence_gaps = _evidence_gaps(proofcard)

    report: dict[str, Any] = {
        "schema_version": "work-impact-metrics-v0",
        "artifact_id": "HOX-GAUNTLET-001",
        "metrics_generated_at": generated_at or _default_generated_at(),
        "proof_ceiling": PROOF_CEILING,
        "dataset": {
            "events_total": detection.events_total,
            "expected_positive": detection.expected_positive,
            "expected_negative": detection.expected_negative,
        },
        "detection_quality": {
            "true_positive": detection.true_positive,
            "true_negative": detection.true_negative,
            "false_positive": detection.false_positive,
            "false_negative": detection.false_negative,
            "precision": detection.precision,
            "recall": detection.recall,
            "f1": detection.f1,
            "false_positive_rate": detection.false_positive_rate,
        },
        "telemetry_coverage": telemetry,
        "claim_authority": claim_metrics,
        "proofcard": proofcard_metrics,
        "evidence_gaps": evidence_gaps,
        "work_impact": {
            "files_evaluated_count": 4,
            "numeric_metrics_emitted_count": 0,
            "deterministic_checks_count": detection.events_total
            + claim_metrics["claims_scanned"]
            + proofcard_metrics["required_sections_count"],
            "validation_commands_count": 9,
            "measurable_output": True,
        },
        "boundary": {
            "runtime_proof_claimed": False,
            "signal_proof_claimed": False,
            "customer_deployment_claimed": False,
            "production_readiness_claimed": False,
            "ai_approval_claimed": False,
            "analyst_approval_claimed": False,
            "final_authorization_claimed": False,
        },
    }
    report["work_impact"]["numeric_metrics_emitted_count"] = _count_numeric_metrics(report)
    return report


def _claim_authority_metrics(claim_output: dict[str, Any]) -> dict[str, int | float]:
    safe_release = _mapping(claim_output, "safe_release_note")
    bad_release = _mapping(claim_output, "bad_release_note")
    blocked_claims = bad_release.get("blocked_claims")
    if not isinstance(blocked_claims, list):
        raise ValueError("claim output bad_release_note.blocked_claims must be a list")
    claims_allowed = 1 if safe_release.get("allowed") is True else 0
    claims_blocked = len(blocked_claims)
    claims_scanned = claims_allowed + claims_blocked
    return {
        "claims_scanned": claims_scanned,
        "claims_allowed": claims_allowed,
        "claims_blocked": claims_blocked,
        "block_rate_percent": _percent(claims_blocked, claims_scanned),
    }


def _proofcard_metrics(proofcard: dict[str, Any]) -> dict[str, int | float]:
    present = [section for section in REQUIRED_PROOFCARD_SECTIONS if section in proofcard]
    required_count = len(REQUIRED_PROOFCARD_SECTIONS)
    present_count = len(present)
    return {
        "required_sections_count": required_count,
        "present_sections_count": present_count,
        "completeness_percent": _percent(present_count, required_count),
    }


def _evidence_gaps(proofcard: dict[str, Any]) -> dict[str, bool]:
    runtime_state = _mapping(proofcard, "runtime_state")
    signal_state = _mapping(proofcard, "signal_state")
    human_review_state = _mapping(proofcard, "human_review_state")
    return {
        "missing_runtime_evidence": runtime_state.get("observed") is not True,
        "missing_signal_evidence": signal_state.get("observed") is not True,
        "missing_customer_deployment_evidence": True,
        "missing_human_final_authorization": human_review_state.get("final_authorization") is not True,
        "missing_public_runtime_authorization": proofcard.get("public_safe") is not True,
    }


def _required_telemetry_fields(artifact: dict[str, Any]) -> list[str]:
    detection_artifact = _mapping(artifact, "detection_artifact")
    required_fields = detection_artifact.get("required_fields")
    if not isinstance(required_fields, list) or not all(isinstance(field, str) for field in required_fields):
        raise ValueError("artifact detection_artifact.required_fields must be a list of strings")
    return required_fields


def _load_json_object(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value


def _require(data: dict[str, Any], key: str, expected: str) -> None:
    if data.get(key) != expected:
        raise ValueError(f"{key} must be {expected}")


def _percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def _count_numeric_metrics(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return 1
    if isinstance(value, dict):
        return sum(_count_numeric_metrics(item) for item in value.values())
    if isinstance(value, list):
        return sum(_count_numeric_metrics(item) for item in value)
    return 0


def _default_generated_at() -> str:
    return datetime(2026, 6, 27, 0, 0, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
