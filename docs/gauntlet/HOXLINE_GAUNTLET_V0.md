# Hoxline Gauntlet v0: Splunk ProofOps Lab

This gauntlet is a controlled product demo artifact for Hoxline. It shows how an AI-assisted security draft moves from source-controlled artifact to evidence-bound claim decision.

Artifact ID: `HOX-GAUNTLET-001`

Scenario: an AI assistant drafts a synthetic Splunk/SOC detection-review artifact and release note for a browser-cache / ClickFix-style payload extraction detection idea. The fixture is sanitized, contains no malware code, contains no exploit instructions, and does not depend on live telemetry.

Proof ceiling: `CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY`.

Safe claim:

> This artifact demonstrates Hoxline's controlled validation and claim-boundary workflow for an AI-assisted security draft.

This artifact does not claim production readiness, runtime proof, signal observation, customer deployment, AI approval, analyst approval, enterprise SOC deployment, or public runtime proof.

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

## Three-Minute Reviewer Path

1. Read this page for the boundary and stage map.
2. Open `examples/gauntlet/sample-artifact.json` for the synthetic detection artifact and telemetry contract.
3. Compare `examples/gauntlet/bad-release-note.md` with `examples/gauntlet/safe-release-note.md`.
4. Open `examples/gauntlet/sample-evidence-graph.json`, `examples/gauntlet/sample-promotion-state.json`, `examples/gauntlet/sample-proofcard.json`, and `examples/gauntlet/sample-claim-authority-output.json`.
5. Open `docs/gauntlet/HOXLINE_GAUNTLET_METRICS_V0.md` for the numeric Work Impact Metrics v0 output.
6. Run `python -B -m unittest discover -s tests` to verify the sample remains deterministic.

## Truth Boundaries

* Source truth: the artifact exists in source control.
* Validation truth: deterministic controlled checks passed under the stated fixture scope.
* Runtime truth: not proven.
* Signal truth: not observed.
* Evidence truth: each claim must match the evidence graph and ProofCard.
* External proof publication: not authorized by this artifact.
* Rendering truth: website or GitHub display is not proof.

## Sample Artifact

Artifact: `HOX-GAUNTLET-001`

Purpose: demonstrate how Hoxline governs an AI-assisted Splunk/SOC detection draft through the control plane.

The sample artifact has:

* A synthetic Splunk-style detection review object.
* A telemetry contract describing required fields and fixture-only scope.
* Controlled validation with deterministic positive and negative fixture expectations.
* Runtime candidate state recorded as `NOT_PROMOTED`.
* Signal observation state recorded as `NOT_OBSERVED`.
* Human Review Gate state recorded as `PENDING`.
* One ProofCard and one Claim Authority output.

## Gauntlet Walkthrough

| Step | Stage | Sample state | Result |
| --- | --- | --- | --- |
| 1 | AI-assisted security work | Work is marked `ai_assisted=true`. | Intake required. |
| 2 | Artifact Intake | Artifact identity, source-control path, scope, and proposed claims are recorded. | Evidence graph node created. |
| 3 | Evidence Graph | Artifact, telemetry contract, validation, runtime candidate, signal observation, review, ProofCard, and claim decision nodes are linked. | Traceable state exists. |
| 4 | Telemetry Contract Check | Status is `PASSED_SYNTHETIC_CONTRACT`. | Required synthetic fields are declared. |
| 5 | Controlled Validation | Status is `PASSED_CONTROLLED_FIXTURES`. | Fixture-only validation supports the safe claim. |
| 6 | Runtime Candidate Ledger | Candidate state is `NOT_PROMOTED`. | Runtime proof remains unavailable. |
| 7 | Signal Observation | Signal state is `NOT_OBSERVED`. | Signal proof remains unavailable. |
| 8 | Human Review Gate | Status is `PENDING`. | No approval or final authorization is claimed. |
| 9 | ProofCard | Status is `READY_FOR_REVIEW`. | Reviewer can see tested scope and blockers. |
| 10 | Claim Authority | Bad note is blocked; safe note passes. | Unsupported wording is constrained. |
| 11 | Safe Claim / Blocked Claim | One safe claim is allowed and stronger claims are blocked. | Public wording remains evidence-bound. |

## Required Files

* `examples/gauntlet/sample-artifact.json`
* `examples/gauntlet/sample-promotion-state.json`
* `examples/gauntlet/sample-evidence-graph.json`
* `examples/gauntlet/sample-proofcard.json`
* `examples/gauntlet/sample-claim-authority-output.json`
* `examples/gauntlet/synthetic-events.json`
* `examples/gauntlet/expected-detection-results.json`
* `examples/gauntlet/sample-work-impact-metrics.json`
* `examples/gauntlet/bad-release-note.md`
* `examples/gauntlet/safe-release-note.md`

The sample JSON files keep runtime observation, signal observation, external proof publication, deployment, customer, and final human authorization states unset because no exact release evidence is included in this controlled product demo.

## Work Impact Metrics

`HOX-GAUNTLET-001` now emits numeric Work Impact Metrics v0 for the controlled fixture: 12 synthetic events, 4 expected positives, 8 expected negatives, 4 true positives, 8 true negatives, 0 false positives, 0 false negatives, 1.0 precision, 1.0 recall, 1.0 F1, 0.0 false-positive rate, 100.0% telemetry coverage, 7 claims scanned, 1 claim allowed, 6 claims blocked, and 100.0% ProofCard completeness.

Run:

```powershell
python -B -m hoxline.cli gauntlet metrics --events examples/gauntlet/synthetic-events.json --artifact examples/gauntlet/sample-artifact.json --proofcard examples/gauntlet/sample-proofcard.json --claim-output examples/gauntlet/sample-claim-authority-output.json --format json
```
