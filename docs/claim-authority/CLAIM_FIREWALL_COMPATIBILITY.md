# Claim Firewall Compatibility

Claim Firewall remains the first internal Claim Authority enforcement capability inside Hoxline.

It is not the product, not Product 001, not the front-door repo, and not an eighth repository. The user-facing module name for this depth work is Claim Authority. The existing `claimfirewall` CLI and legacy blocked-claim policy behavior remain available for compatibility.

## Compatibility Contract

The existing command continues to work:

```bash
claimfirewall scan examples/pass.md --policy policy/blocked_claims.yml
```

When the policy file is a Claim Authority v0 policy, the same command returns Claim Authority decisions:

```bash
claimfirewall scan examples/gauntlet/bad-release-note.md --policy examples/policies/default-claim-authority-policy.yml --format json
```

Legacy findings retain their legacy fields. Claim Authority reports include `allowed`, `blocked_claims`, `safer_suggestions`, `required_evidence`, `proof_ceiling`, and `public_safe`.

## Non-Claims

The compatibility layer does not claim runtime proof, does not claim signal proof, does not claim public-safe proof, does not claim production readiness, does not claim customer deployment, does not claim SOCaaS availability, does not claim autonomous SOC operation, does not claim AI-approved disposition, does not claim analyst-approved disposition, does not claim final authorization, and does not claim case closure.
