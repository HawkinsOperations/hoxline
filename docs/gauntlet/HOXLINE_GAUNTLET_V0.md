# Hoxline Gauntlet v0

This gauntlet shows one artifact moving through the full Hoxline loop without asserting proof beyond the sample records.

AevumGuard was a prior working name. Hoxline is the current product name.

This sample is not the default reviewer/demo path. Use `docs/gauntlet/HO_DET_001_GAUNTLET_RUN.md` for the default HO-DET-001 Gauntlet.

Proof ceiling: PRODUCT_SPINE_ONLY.

## Loop

AI-assisted security work
→ Artifact Intake
→ Evidence Graph
→ Telemetry Contract Check
→ Controlled Validation
→ Runtime Candidate Ledger
→ Signal Observation
→ Human Review Gate
→ ProofCard
→ Claim Authority
→ Safe Claim / Blocked Claim

## Sample Artifact

Artifact: `artifact-ai-security-work-v0`

Purpose: demonstrate how Hoxline records an AI-assisted security artifact through the control plane.

The sample artifact has:

* No runtime observation.
* No signal observation.
* No external safety status.
* No final authorization claim.

## Gauntlet Walkthrough

| Step | Stage | Sample state | Result |
| --- | --- | --- | --- |
| 1 | AI-assisted security work | Work is marked `ai_assisted=true`. | Intake required. |
| 2 | Artifact Intake | Artifact identity, source, scope, and proposed claim are recorded. | Evidence graph node created. |
| 3 | Evidence Graph | Artifact, contract check, validation, runtime candidate, signal observation, review, ProofCard, and claim decision nodes are linked. | Traceable state exists. |
| 4 | Telemetry Contract Check | Status is `not_checked`. | Promotion cannot claim telemetry support. |
| 5 | Controlled Validation | Status is `not_started`. | Promotion cannot claim validation support. |
| 6 | Runtime Candidate Ledger | Candidate exists with `observed=false`. | Candidate is recorded without observation. |
| 7 | Signal Observation | Signal status is `observed=false`. | Claim cannot rely on signal observation. |
| 8 | Human Review Gate | Status is `pending`. | Claim Authority cannot treat review as complete. |
| 9 | ProofCard | Status is `draft`. | ProofCard is not final authority. |
| 10 | Claim Authority | Disposition is `blocked_claim`. | Unsupported wording is blocked. |
| 11 | Safe Claim / Blocked Claim | Final sample disposition is blocked. | No safe claim is emitted. |

## Required Files

* `examples/gauntlet/sample-artifact.json`
* `examples/gauntlet/sample-promotion-state.json`
* `examples/gauntlet/sample-evidence-graph.json`

The sample JSON files keep `runtime.observed=false`, `signal.observed=false`, and `claim_authority.public_safe=false` because no exact proof is included in this product-spine sample.
