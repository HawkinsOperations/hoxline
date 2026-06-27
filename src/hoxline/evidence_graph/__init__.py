from __future__ import annotations

import json
from pathlib import Path


REQUIRED_NODE_TYPES = {
    "artifact",
    "artifact_intake",
    "telemetry_contract_check",
    "controlled_validation",
    "runtime_candidate",
    "signal_observation",
    "human_review_gate",
    "proofcard",
    "claim_decision",
}


def load_evidence_graph(path: str | Path) -> dict[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("evidence graph must be a JSON object")
    validate_evidence_graph(data)
    return data


def validate_evidence_graph(data: dict[str, object]) -> None:
    if data.get("schema_version") != "evidence-graph-v0":
        raise ValueError("evidence graph schema_version must be evidence-graph-v0")
    if data.get("artifact_id") != "HOX-GAUNTLET-001":
        raise ValueError("evidence graph artifact_id must be HOX-GAUNTLET-001")
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("evidence graph nodes must be a list")
    node_types = {node.get("type") for node in nodes if isinstance(node, dict)}
    missing = REQUIRED_NODE_TYPES - node_types
    if missing:
        raise ValueError(f"evidence graph missing node types: {', '.join(sorted(missing))}")
    runtime = _mapping(data, "runtime")
    signal = _mapping(data, "signal")
    if runtime.get("observed") is not False:
        raise ValueError("runtime evidence must not be promoted in the public demo")
    if signal.get("observed") is not False:
        raise ValueError("signal evidence must not be promoted in the public demo")


def _mapping(data: dict[str, object], key: str) -> dict[str, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value
