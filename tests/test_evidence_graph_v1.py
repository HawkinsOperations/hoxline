from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "examples" / "gauntlet" / "ho-det-001-evidence-graph-v1.json"
SCHEMA = ROOT / "schemas" / "evidence-graph-v1.schema.json"


def test_evidence_graph_v1_schema_and_required_nodes() -> None:
    schema = _json(SCHEMA)
    graph = _json(GRAPH)
    required_types = {
        "artifact_intake",
        "evidence_graph",
        "telemetry_contract_check",
        "controlled_validation",
        "runtime_candidate_ledger",
        "signal_observation",
        "human_review_gate",
        "proofcard",
        "claim_authority",
        "safe_blocked_claim",
    }

    for field in schema["required"]:
        assert field in graph
    assert {node["type"] for node in graph["nodes"]} == required_types
    assert graph["website_boundary"]["mode"] == "rendering-only"
    assert graph["public_safe"] is False
    assert "runtime_evidence" in graph["missing_evidence"]


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
