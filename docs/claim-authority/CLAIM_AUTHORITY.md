# Hoxline Claim Authority v0

Claim Authority maps evidence state to allowed and blocked wording.

Doctrine: AI is not the authority. Evidence is.

Claim Authority v0 is a policy-based wording evaluator. It can load a policy pack, scan Markdown or text artifacts, block unsupported claim wording, and suggest safer wording. It does not prove runtime state, signal state, public release safety, deployment, service availability, approval, final authorization, or case closure.

Proof ceiling: `CLAIM_AUTHORITY_V0_ONLY / TOOL_FUNCTION_ONLY`.

## Core Loop Placement

AI-assisted security work -> Artifact Intake -> Evidence Graph -> Telemetry Contract Check -> Controlled Validation -> Runtime Candidate Ledger -> Signal Observation -> Human Review Gate -> ProofCard -> Claim Authority -> Safe Claim / Blocked Claim

## Behavior

The default policy can define:

* blocked terms or phrases
* safer replacements
* evidence states required for stronger wording
* proof ceiling labels
* `public_safe`, defaulting to `false`

The evaluator returns:

* `allowed`
* `blocked_claims`
* `safer_suggestions`
* `required_evidence`
* `proof_ceiling`
* `public_safe`

## Examples

Bad release note:

```text
Hoxline Claim Authority has reviewed this artifact and it is production ready.
The release has runtime proof, signal observation confirmed, and public release safe status.
```

That wording is blocked unless the configured evidence states support it. Claim Authority v0 still does not turn those states into public proof.

Safe release note:

```text
Hoxline Claim Authority evaluated this artifact as a controlled-validation candidate.
It does not claim production status, does not claim runtime status, does not claim signal status, and does not claim public-safe status.
```

This wording stays within the tool ceiling and does not claim public-safe proof.

## JSON Output

Use the existing CLI with a Claim Authority policy:

```bash
claimfirewall scan examples/gauntlet/bad-release-note.md --policy examples/policies/default-claim-authority-policy.yml --format json
```

The JSON report includes the blocked wording, missing evidence states, safer suggestions, proof ceiling, and `public_safe`.

## SARIF Output

SARIF output is planned. It is not included in v0 because the JSON report covers the current scope without adding a second reporting contract.
