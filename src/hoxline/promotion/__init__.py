from __future__ import annotations

import json
from pathlib import Path


CANONICAL_LOOP = (
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
)


def load_promotion_state(path: str | Path) -> dict[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("promotion state must be a JSON object")
    validate_promotion_state(data)
    return data


def validate_promotion_state(data: dict[str, object]) -> None:
    _require(data, "schema_version", "promotion-state-v0")
    _require(data, "artifact_id", "HOX-GAUNTLET-001")
    if tuple(data.get("loop", ())) != CANONICAL_LOOP:
        raise ValueError("promotion state loop must contain all 11 Hoxline stages in order")
    if data.get("proof_ceiling") != "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY":
        raise ValueError("promotion state proof ceiling is outside the gauntlet v0 demo boundary")
    runtime = _mapping(data, "runtime")
    signal = _mapping(data, "signal")
    review = _mapping(data, "human_review_gate")
    if runtime.get("observed") is not False:
        raise ValueError("runtime state must remain unobserved for this public demo")
    if signal.get("observed") is not False:
        raise ValueError("signal state must remain unobserved for this public demo")
    if review.get("status") != "pending":
        raise ValueError("human review gate must remain pending for this public demo")


def _require(data: dict[str, object], key: str, expected: str) -> None:
    if data.get(key) != expected:
        raise ValueError(f"{key} must be {expected}")


def _mapping(data: dict[str, object], key: str) -> dict[str, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value
