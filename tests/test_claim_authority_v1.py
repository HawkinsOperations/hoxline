from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from hoxline.gauntlet import SAFE_CLAIM, decide_claim_authority_v1


ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "examples" / "gauntlet" / "ho-det-001-gauntlet-run-v1.json"


def test_controlled_validation_claim_is_allowed() -> None:
    decision = decide_claim_authority_v1(_run())

    assert decision["allowed_claims"] == [SAFE_CLAIM]
    assert decision["proof_ceiling"] == "CONTROLLED_TEST_VALIDATED"
    assert decision["public_safe"] is False
    assert decision["next_gate"] == "human_review_gate"


@pytest.mark.parametrize(
    ("claim", "missing"),
    [
        ("runtime proven", "runtime_evidence"),
        ("signal observed", "signal_observation_evidence"),
        ("production ready", "deployment_evidence"),
        ("customer deployed", "customer_deployment_evidence"),
        ("SOCaaS deployed", "service_deployment_evidence"),
        ("public-safe runtime proof", "public_safe_authorization"),
        ("AI approved", "human_review_gate_complete"),
        ("analyst approved", "analyst_review_record"),
        ("final authorization", "final_authorization_record"),
        ("case closure", "case_closure_record"),
    ],
)
def test_structured_evidence_blocks_unsupported_claims(claim: str, missing: str) -> None:
    blocked = {item["claim"]: item for item in decide_claim_authority_v1(_run())["blocked_claims"]}

    assert blocked[claim]["status"] == "BLOCKED"
    assert missing in blocked[claim]["missing_evidence"]


def test_telemetry_contract_missing_field_removes_allowed_claim() -> None:
    run = _run()
    run["telemetry_contract_check"]["missing_required_fields"] = ["process.command_line"]

    decision = decide_claim_authority_v1(run)

    assert decision["allowed_claims"] == []
    assert "controlled-validation claim is not allowed" in decision["safer_wording"]


def test_public_safe_true_without_authorization_still_blocks_public_safe_runtime_proof() -> None:
    run = _run()
    run["public_safe"] = True

    blocked = {item["claim"]: item for item in decide_claim_authority_v1(run)["blocked_claims"]}

    assert "public_safe_authorization" in blocked["public-safe runtime proof"]["missing_evidence"]


def _run() -> dict[str, object]:
    with RUN.open("r", encoding="utf-8") as handle:
        return deepcopy(json.load(handle))
