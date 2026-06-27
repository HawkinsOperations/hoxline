from __future__ import annotations

import json
from pathlib import Path


REQUIRED_FIELDS = {
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
}


def load_proofcard(path: str | Path) -> dict[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("ProofCard must be a JSON object")
    validate_proofcard(data)
    return data


def validate_proofcard(data: dict[str, object]) -> None:
    missing = REQUIRED_FIELDS - set(data)
    if missing:
        raise ValueError(f"ProofCard missing required fields: {', '.join(sorted(missing))}")
    if data["schema_version"] != "proofcard-v0":
        raise ValueError("ProofCard schema_version must be proofcard-v0")
    if data["artifact_id"] != "HOX-GAUNTLET-001":
        raise ValueError("ProofCard artifact_id must be HOX-GAUNTLET-001")
    if data["proof_ceiling"] != "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY":
        raise ValueError("ProofCard proof ceiling is outside the gauntlet v0 demo boundary")
    if data["public_safe"] is not False:
        raise ValueError("ProofCard public_safe must remain false")
    if _mapping(data, "runtime_state").get("observed") is not False:
        raise ValueError("ProofCard runtime state must remain unobserved")
    if _mapping(data, "signal_state").get("observed") is not False:
        raise ValueError("ProofCard signal state must remain unobserved")
    if _mapping(data, "human_review_state").get("final_authorization") is not False:
        raise ValueError("ProofCard must not assert final authorization")


def _mapping(data: dict[str, object], key: str) -> dict[str, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value
