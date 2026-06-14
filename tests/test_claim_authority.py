from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
for module_name in tuple(sys.modules):
    if module_name == "claimfirewall" or module_name.startswith("claimfirewall."):
        del sys.modules[module_name]

from claimfirewall.claim_authority import evaluate_text, load_claim_authority_policy, scan_paths

POLICY = ROOT / "examples" / "policies" / "default-claim-authority-policy.yml"
BAD_RELEASE_NOTE = ROOT / "examples" / "gauntlet" / "bad-release-note.md"
SAFE_RELEASE_NOTE = ROOT / "examples" / "gauntlet" / "safe-release-note.md"


class ClaimAuthorityDecisionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_claim_authority_policy(POLICY)

    def test_unsafe_production_claim_blocked_without_runtime_or_signal_proof(self) -> None:
        report = evaluate_text("This artifact is production ready.", self.policy)

        self.assertFalse(report.allowed)
        self.assertEqual(report.proof_ceiling, "CLAIM_AUTHORITY_V0_ONLY")
        self.assertIn("runtime_signal_observed", report.required_evidence)
        self.assertIn("human_review_gate_complete", report.required_evidence)

    def test_controlled_validation_wording_allowed(self) -> None:
        report = evaluate_text("This artifact is a controlled-validation candidate.", self.policy)

        self.assertTrue(report.allowed)
        self.assertEqual(report.blocked_claims, ())

    def test_safer_wording_is_suggested(self) -> None:
        report = evaluate_text("The release has runtime proof.", self.policy)

        self.assertFalse(report.allowed)
        self.assertTrue(report.safer_suggestions)
        self.assertEqual(report.safer_suggestions[0].suggestion, "controlled-validation evidence recorded")

    def test_public_safe_defaults_false(self) -> None:
        report = evaluate_text("This artifact is a controlled-validation candidate.", self.policy)

        self.assertFalse(report.public_safe)

    def test_bad_release_note_blocks_and_safe_release_note_allows(self) -> None:
        bad = scan_paths([BAD_RELEASE_NOTE], self.policy)
        safe = scan_paths([SAFE_RELEASE_NOTE], self.policy)

        self.assertFalse(bad.allowed)
        self.assertTrue(safe.allowed)


if __name__ == "__main__":
    unittest.main()
