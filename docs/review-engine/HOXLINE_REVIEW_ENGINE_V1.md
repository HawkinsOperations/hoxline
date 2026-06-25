# Hoxline Review Engine v1

Status: REVIEW_ENGINE_V1 / LOCAL_FIXTURE_MACHINE / NO_PROOF_PROMOTION

## Purpose

Hoxline Review Engine v1 turns a fixed demo into a reusable deterministic ProofOps machine. It accepts an artifact manifest, runs local fixture-based review stages, enforces fail-closed gates, writes reviewer artifacts, and emits replayable `machine-state.json` for verification.

## Exact Commands

Run from the Hoxline repo root:

```powershell
python -B -m hoxline review run --artifact examples/review/ho-det-010-artifact-manifest-v1.json
```

Verify a run:

```powershell
python -B -m hoxline review verify --run .hoxline/runs/<run-id>/machine-state.json
```

Summarize a run:

```powershell
python -B -m hoxline review summarize --run .hoxline/runs/<run-id>/machine-state.json
```

Run the governed multi-artifact review set:

```powershell
python -B -m hoxline review batch run --index examples/review/multi-artifact-review-index-v1.json
```

Verify a batch run:

```powershell
python -B -m hoxline review batch verify --run .hoxline/batch-runs/<batch-id>/batch-machine-state.json
```

## Artifact Manifest Schema

The manifest schema is `schemas/artifact-manifest-v1.schema.json`. A manifest must define ownership, telemetry assumptions, fixture paths, requested claims, blocked claim classes, and boundaries. The HO-DET-010 example is `examples/review/ho-det-010-artifact-manifest-v1.json`.

Required fields include `manifest_version`, `artifact_id`, `artifact_name`, `artifact_type`, `artifact_family`, source/validation/platform/proof/product owners, `telemetry_contract`, `fixture_paths`, `expected_event_ids`, `expected_rule_ids`, `allowed_claim_class`, `requested_claims`, `blocked_claim_classes`, `public_safe_status`, `human_review_required`, `ai_disposition_authority`, `proof_boundary`, `runtime_boundary`, `signal_boundary`, and `next_gate`.

## Stage Registry

1. `artifact_intake`
2. `evidence_graph`
3. `telemetry_contract_check`
4. `controlled_validation`
5. `synthetic_signal`
6. `enrichment`
7. `triage`
8. `proofcard`
9. `claim_authority`
10. `reviewer_pack`
11. `machine_state`

Each stage records status, input refs, output ref, proof boundary, failure mode, claim boundary, and summary.

## Fail-Closed Gates

The engine blocks if required fields are missing, telemetry source/event IDs/rule IDs are missing, fixture paths are missing or outside allowed example roots, fixtures are invalid, public-safe status is anything other than `NOT_PUBLIC_SAFE`, human review is not required, AI disposition authority is enabled, endpoint/Wazuh/runtime/ledger/public-proof flags are true, private evidence-like fields appear, raw alert-like fields appear, or requested claims include public-safe runtime proof, production, customer deployment, SOCaaS deployment, autonomous SOC, AI-approved disposition, analyst-approved disposition, final authorization, or case closure.

No proof-boundary violation is warning-only. Violations produce `final_status=BLOCKED` and a nonzero run exit.

## Machine-State Contract

`machine-state.json` uses `schemas/review-machine-state-v1.schema.json` and includes run ID, artifact ID, manifest path, stage records, outputs, final status, block reason when blocked, allowed claim, requested claims, blocked claims, proof/runtime/signal boundaries, `public_safe_status`, `human_review_required`, `ai_disposition_authority`, endpoint/Wazuh/private/public-proof/ledger flags, next gate, creation timestamp, and engine version.

## Generated Outputs

PASS runs write `artifact-manifest.json`, `intake.json`, `evidence-graph.json`, `telemetry-contract-check.json`, `validation-result.json`, `synthetic-signal.json`, `enrichment.json`, `triage-summary.md`, `proofcard.json`, `proofcard.md`, `claim-authority.json`, `reviewer-pack.md`, `machine-state.json`, and `run-summary.json`.

BLOCKED runs write sanitized `artifact-manifest.json`, `machine-state.json`, `blocked-review.md`, and `run-summary.json` when safe.

## Replay Verification

`review verify` independently checks the machine state, required stage registry, output refs, final status, claim boundary flags, blocked claim enforcement, and private/raw marker absence.

## Hostile Fixture Behavior

Synthetic hostile manifests under `examples/review/hostile/` intentionally request unsafe claims, omit telemetry, point to missing fixtures, or include private/raw-like fields. They are expected to block. They are not evidence and are not runtime material.

## Clean-Room Expectation

A reviewer should be able to clone Hoxline, run the exact review command, inspect `.hoxline/runs/<run-id>/reviewer-pack.md`, and verify `.hoxline/runs/<run-id>/machine-state.json` without private infrastructure.

## Difference From Demo Quickstart

`python -B -m hoxline demo quickstart` is the fastest fixed walkthrough. `python -B -m hoxline review run --artifact ...` is the reusable manifest-driven engine path for future detections.

Both are deterministic, local, fixture-based, `NOT_PUBLIC_SAFE`, human-review-required, and not runtime proof.

## Multi-Artifact Index

`examples/review/multi-artifact-review-index-v1.json` declares the governed review set for HO-DET-009, HO-DET-010, HO-DET-011, and HO-DET-012. The schema is `schemas/multi-artifact-review-index-v1.schema.json`.

The index records artifact manifest paths, expected PASS artifacts, expected BLOCKED artifacts, batch boundaries, generated outputs, and the next gate. Batch run output is written under `.hoxline/batch-runs/<batch-id>/`. Each artifact gets its own subdirectory under `artifacts/<artifact-id>/` with the same machine-state and reviewer-pack contract as a single-artifact run.

## Batch Machine-State Contract

`batch-machine-state.json` records the index ID, index path, artifact result table, expected outcome sets, final status, batch claim boundary, proof/runtime/signal boundaries, generated outputs, and the same governance flags used by single-artifact machine state. It must keep `public_safe_status=NOT_PUBLIC_SAFE`, `human_review_required=true`, `ai_disposition_authority=false`, endpoint mutation false, Wazuh mutation false, runtime proof false, public proof promotion false, ledger change false, and website change false.

## Expected PASS/BLOCKED Semantics

A batch exits zero only when actual artifact outcomes match `expected_pass_artifacts` and `expected_blocked_artifacts`. A PASS artifact that blocks, or a BLOCKED artifact that passes, makes the batch `BLOCKED` and exits nonzero. This prevents unsupported artifacts from being treated as success.

## Hostile Batch Behavior

Synthetic hostile indexes under `examples/review/hostile-batch/` cover duplicate artifact IDs, missing manifests, expectation mismatches, unsafe batch status, private-marker attempts, and production wording. They are expected to block fail-closed.

## Adding The Next Artifact Safely

Add a manifest only when source-controlled metadata exists or when the manifest is explicitly synthetic and fixture-only. Add positive and negative synthetic fixtures under `examples/review/fixtures/`, list every blocked claim class, keep all governance flags bounded, add the artifact to the index, and add a hostile case for the most likely unsafe claim. If the artifact cannot satisfy telemetry or fixture gates, list it as expected BLOCKED instead of pretending it is review-passable.

## Future Detection Plug-In Path

To add a future detection, create a synthetic fixture manifest with telemetry assumptions, allowed example fixture paths, expected event/rule metadata, requested bounded claim wording, blocked claim classes, and explicit proof/runtime/signal boundaries. The engine should block until every required field and gate is satisfied.

## What It Proves

It proves Hoxline can deterministically review a public sanitized synthetic artifact manifest through machine-checkable stages, generate reviewer artifacts, emit replayable machine state, and block unsupported claims.

## What It Does Not Prove

It does not prove live runtime behavior, public signal observation, public-safe status, production readiness, SOCaaS deployment, customer deployment, autonomous SOC operation, AI approval, analyst approval, final authorization, case closure, or website proof authority.

## Proof Boundary

- public_safe_status: `NOT_PUBLIC_SAFE`
- human_review_required: `true`
- ai_disposition_authority: `false`
- endpoint_mutation: `false`
- wazuh_mutation: `false`
- runtime_proof: `false`
- public_proof_promoted: `false`
- lifetime_ledger_changed: `false`

## Local Operator Shortcut

Raylee can run the local launcher from anywhere on the machine:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Raylee\Scripts\hoxline-review.ps1
powershell -ExecutionPolicy Bypass -File C:\Raylee\Scripts\hoxline-review.ps1 -VerifyLatest
```

## 30-Second Talk Track

“Hoxline Review Engine v1 takes an artifact manifest, runs deterministic local review stages, checks telemetry and validation assumptions, simulates only safe fixture signals, enriches and triages the result, renders a ProofCard, applies Claim Authority, blocks unsupported claims, and writes a replayable machine-state file. Evidence decides what can be claimed. AI does not.”

## 3-Minute Deep Review Path

1. Read `examples/review/ho-det-010-artifact-manifest-v1.json`.
2. Run the review command.
3. Open `reviewer-pack.md`.
4. Inspect `machine-state.json`.
5. Run `review verify`.
6. Run one hostile manifest and confirm it blocks.

## Troubleshooting

If Python cannot import Hoxline, run from the repo root or install editable mode once with `python -m pip install -e ".[test]"`. If a run blocks, read `blocked-review.md` and `machine-state.json` for the fail-closed reason. If an output directory exists, rerun with `--force` or choose a new `--output` path.

