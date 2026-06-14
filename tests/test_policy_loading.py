from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
for module_name in tuple(sys.modules):
    if module_name == "claimfirewall" or module_name.startswith("claimfirewall."):
        del sys.modules[module_name]

from claimfirewall.claim_authority import load_claim_authority_policy

POLICY = ROOT / "examples" / "policies" / "default-claim-authority-policy.yml"


class ClaimAuthorityPolicyLoadingTest(unittest.TestCase):
    def test_policy_loads(self) -> None:
        policy = load_claim_authority_policy(POLICY)

        self.assertEqual(policy.version, 0)
        self.assertEqual(policy.proof_ceiling, "CLAIM_AUTHORITY_V0_ONLY")
        self.assertGreaterEqual(len(policy.blocked_claims), 5)
        self.assertFalse(policy.public_safe)


if __name__ == "__main__":
    unittest.main()
