from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hoxline.claim_authority import scan_release_note
from hoxline.cli import main
from hoxline.evidence_graph import REQUIRED_NODE_TYPES, load_evidence_graph
from hoxline.promotion import CANONICAL_LOOP, load_promotion_state
from hoxline.proofcard import REQUIRED_FIELDS, load_proofcard


ARTIFACT = ROOT / "examples" / "gauntlet" / "sample-artifact.json"
EVIDENCE_GRAPH = ROOT / "examples" / "gauntlet" / "sample-evidence-graph.json"
PROMOTION_STATE = ROOT / "examples" / "gauntlet" / "sample-promotion-state.json"
PROOFCARD = ROOT / "examples" / "gauntlet" / "sample-proofcard.json"
CLAIM_OUTPUT = ROOT / "examples" / "gauntlet" / "sample-claim-authority-output.json"
BAD_RELEASE_NOTE = ROOT / "examples" / "gauntlet" / "bad-release-note.md"
SAFE_RELEASE_NOTE = ROOT / "examples" / "gauntlet" / "safe-release-note.md"
POLICY = ROOT / "examples" / "policies" / "default-claim-authority-policy.yml"


class HoxlineGauntletV0Test(unittest.TestCase):
    def test_sample_artifact_is_synthetic_splunk_soc_detection_artifact(self) -> None:
        artifact = _load_json(ARTIFACT)

        self.assertEqual(artifact["artifact_id"], "HOX-GAUNTLET-001")
        self.assertTrue(artifact["ai_assisted"])
        self.assertEqual(artifact["detection_artifact"]["platform"], "Splunk")
        self.assertEqual(artifact["proof_ceiling"], "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY")
        self.assertTrue(artifact["public_safety"]["synthetic_only"])
        self.assertFalse(artifact["public_safety"]["contains_malware_code"])
        self.assertFalse(artifact["public_safety"]["contains_exploit_instructions"])

    def test_gauntlet_sample_contains_all_11_stages(self) -> None:
        promotion_state = load_promotion_state(PROMOTION_STATE)

        self.assertEqual(tuple(promotion_state["loop"]), CANONICAL_LOOP)
        self.assertEqual(len(promotion_state["loop"]), 11)

    def test_evidence_graph_contains_required_nodes_and_unpromoted_runtime_signal(self) -> None:
        graph = load_evidence_graph(EVIDENCE_GRAPH)
        node_types = {node["type"] for node in graph["nodes"]}

        self.assertTrue(REQUIRED_NODE_TYPES <= node_types)
        self.assertFalse(graph["runtime"]["observed"])
        self.assertFalse(graph["signal"]["observed"])

    def test_promotion_state_records_runtime_signal_and_review_boundaries(self) -> None:
        state = load_promotion_state(PROMOTION_STATE)

        self.assertEqual(state["runtime"]["state"], "NOT_PROMOTED")
        self.assertEqual(state["signal"]["state"], "NOT_OBSERVED")
        self.assertEqual(state["human_review_gate"]["status"], "pending")
        self.assertFalse(state["claim_authority"]["public_safe"])

    def test_proofcard_contains_required_fields_and_boundaries(self) -> None:
        proofcard = load_proofcard(PROOFCARD)

        self.assertTrue(REQUIRED_FIELDS <= set(proofcard))
        self.assertFalse(proofcard["runtime_state"]["observed"])
        self.assertFalse(proofcard["signal_state"]["observed"])
        self.assertFalse(proofcard["human_review_state"]["final_authorization"])

    def test_bad_release_note_blocks_unsupported_claims(self) -> None:
        report = scan_release_note(BAD_RELEASE_NOTE, POLICY)
        blocked = {claim.claim_id for claim in report.blocked_claims}

        self.assertFalse(report.allowed)
        self.assertIn("production_ready", blocked)
        self.assertIn("runtime_truth", blocked)
        self.assertIn("signal_truth", blocked)
        self.assertIn("service_deployment", blocked)
        self.assertIn("final_authority", blocked)

    def test_safe_release_note_passes(self) -> None:
        report = scan_release_note(SAFE_RELEASE_NOTE, POLICY)

        self.assertTrue(report.allowed)
        self.assertEqual(report.blocked_claims, ())

    def test_runtime_signal_production_and_customer_claims_remain_blocked_without_evidence(self) -> None:
        report = scan_release_note(BAD_RELEASE_NOTE, POLICY)
        phrases = {claim.phrase for claim in report.blocked_claims}

        self.assertIn("production ready", phrases)
        self.assertIn("runtime proof", phrases)
        self.assertIn("signal observation confirmed", phrases)
        self.assertIn("customer deployed service", phrases)

    def test_claim_authority_output_matches_safe_and_blocked_decision(self) -> None:
        output = _load_json(CLAIM_OUTPUT)

        self.assertEqual(output["artifact_id"], "HOX-GAUNTLET-001")
        self.assertTrue(output["safe_release_note"]["allowed"])
        self.assertFalse(output["bad_release_note"]["allowed"])
        self.assertEqual(output["decision"], "SAFE_CLAIM_ALLOWED_STRONGER_CLAIMS_BLOCKED")

    def test_cli_accepts_gauntlet_v0_artifact_path(self) -> None:
        status = main(["gauntlet", "run", "--artifact", str(ARTIFACT), "--format", "json"])

        self.assertEqual(status, 0)


def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return data


if __name__ == "__main__":
    unittest.main()
