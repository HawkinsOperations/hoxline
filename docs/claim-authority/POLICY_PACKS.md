# Claim Authority Policy Packs

Policy packs define how Hoxline Claim Authority v0 maps evidence state to allowed and blocked wording.

The default example lives at:

```text
examples/policies/default-claim-authority-policy.yml
```

The schema lives at:

```text
schemas/claim-authority-policy-v0.schema.json
```

## Required Fields

Policy packs include:

* `kind: claim-authority-policy`
* `version: 0`
* `proof_ceiling`
* `public_safe`
* `proof_ceiling_labels`
* `evidence_states`
* `blocked_claims`

`public_safe` defaults to `false` in the loader if omitted, but policy packs should set it explicitly to `false` for review clarity.

## Blocked Claim Rules

Each blocked claim rule includes:

* `id`
* `phrase`
* `pattern`
* `reason`
* `safer_replacement`
* `required_evidence`
* `proof_ceiling`
* `allowed_replacements`
* `allowed_context_patterns`

If text matches a blocked pattern and the required evidence states are missing, Claim Authority returns `allowed: false`, the missing evidence, and safer wording suggestions.

## Evidence States

Evidence states describe wording ceilings such as controlled validation. They do not create proof authority by themselves.

Claim Authority v0 does not claim runtime proof, does not claim signal proof, and does not claim public-safe status. It only maps configured evidence state to configured wording decisions.

## SARIF

SARIF output is planned and intentionally left out of v0. JSON is the supported report format for this policy depth.
