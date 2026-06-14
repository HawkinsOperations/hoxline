from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
for module_name in tuple(sys.modules):
    if module_name == "claimfirewall" or module_name.startswith("claimfirewall."):
        del sys.modules[module_name]

from claimfirewall.claim_authority import evaluate_text, load_claim_authority_policy


POLICY = ROOT / "examples" / "policies" / "default-claim-authority-policy.yml"
PROOFCARD = ROOT / "examples" / "gauntlet" / "ho-det-001-proofcard-v0.json"
EVIDENCE_GRAPH = ROOT / "examples" / "gauntlet" / "ho-det-001-evidence-graph-v0.json"
PROMOTION_STATE = ROOT / "examples" / "gauntlet" / "ho-det-001-promotion-state-v0.json"


class HoDet001BridgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_claim_authority_policy(POLICY)
        with PROOFCARD.open("r", encoding="utf-8") as handle:
            self.report = json.load(handle)

    def test_bridge_output_loads_and_has_required_fields(self) -> None:
        required_fields = {
            "artifact_id",
            "artifact_name",
            "evidence_state",
            "proof_ceiling",
            "public_safe",
            "allowed",
            "allowed_claims",
            "blocked_claims",
            "safer_suggestions",
            "required_evidence",
            "authority_sources",
            "non_claims",
            "human_review_required",
        }

        self.assertLessEqual(required_fields, set(self.report))
        self.assertEqual(self.report["artifact_id"], "HO-DET-001")
        self.assertEqual(self.report["evidence_state"], "CONTROLLED_TEST_VALIDATED")
        self.assertEqual(self.report["proof_ceiling"], "CONTROLLED_TEST_VALIDATED")
        self.assertFalse(self.report["public_safe"])
        self.assertTrue(self.report["human_review_required"])

    def test_gauntlet_examples_load(self) -> None:
        for path in (EVIDENCE_GRAPH, PROMOTION_STATE):
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["artifact_id"], "HO-DET-001")
            self.assertFalse(data["claim_authority"]["public_safe"])

    def test_safe_controlled_validation_claim_allowed(self) -> None:
        claim = (
            "HO-DET-001 has controlled validation evidence from controlled positive "
            "and negative process-creation fixtures and remains under review."
        )

        report = evaluate_text(claim, self.policy, evidence_states=["controlled_test_validated"])

        self.assertTrue(report.allowed)
        self.assertEqual(report.blocked_claims, ())
        self.assertFalse(report.public_safe)

    def test_required_blocked_claim_families_are_blocked(self) -> None:
        blocked_claims = {
            "runtime claim": "HO-DET-001 is runtime-active.",
            "runtime proven claim": "HO-DET-001 is runtime proven.",
            "signal claim": "HO-DET-001 has signal observed evidence.",
            "public-safe claim": "HO-DET-001 is public-safe.",
            "production claim": "HO-DET-001 is production-ready.",
            "SOCaaS claim": "HO-DET-001 is SOCaaS-ready.",
            "customer claim": "HO-DET-001 is customer deployed.",
            "AI-approved claim": "AI approved the disposition.",
            "analyst-approved claim": "The analyst approved the disposition.",
            "final authorization claim": "HO-DET-001 has final human authorization.",
            "case-closure claim": "The case closed.",
            "live Splunk claim": "Live Splunk fired for HO-DET-001.",
            "Cribl claim": "Cribl routed live telemetry for HO-DET-001.",
            "Wazuh claim": "Wazuh routed live telemetry for HO-DET-001.",
            "AWS-live claim": "HO-DET-001 is AWS-live.",
            "autonomous SOC claim": "HO-DET-001 runs an autonomous SOC.",
            "public runtime proof claim": "HO-DET-001 has public runtime proof.",
            "public signal proof claim": "HO-DET-001 has public signal proof.",
        }

        for label, text in blocked_claims.items():
            with self.subTest(label=label):
                report = evaluate_text(text, self.policy)
                self.assertFalse(report.allowed)
                self.assertTrue(report.blocked_claims)

    def test_authority_sources_are_references_only(self) -> None:
        authority_sources = self.report["authority_sources"]

        self.assertTrue(authority_sources)
        self.assertTrue(all(isinstance(source, str) for source in authority_sources))
        self.assertTrue(all(source.startswith("hawkinsoperations-") for source in authority_sources))
        self.assertFalse(any(source.startswith("C:") or source.startswith("/") for source in authority_sources))

    def test_report_contains_expected_blocked_claim_names(self) -> None:
        blocked = {entry["claim"] for entry in self.report["blocked_claims"]}

        for claim in (
            "runtime-active",
            "signal observed",
            "public-safe",
            "production-ready",
            "SOCaaS-ready",
            "customer deployed",
            "AI approved",
            "analyst approved",
            "final human authorization",
            "case closed",
        ):
            self.assertIn(claim, blocked)


if __name__ == "__main__":
    unittest.main()
