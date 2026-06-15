# Hoxline Gauntlet Full-Loop Runner v0

Status: REVIEWER_READABLE_RUNNER_V0

Product surface: Hoxline by HawkinsOperations

Proof ceiling: CONTROLLED_TEST_VALIDATED

public_safe value: false

Human review required: true

## Purpose

The Hoxline Gauntlet full-loop runner consumes the local HO-DET-001 controlled demo, ProofCard, evidence graph, and promotion state examples. It emits a reviewer-readable result for every canonical Hoxline stage.

Hoxline is the ProofOps control plane for AI-assisted security work. AI is not the authority. Evidence is. The runner controls claim wording boundaries; it is not proof authority.

## CLI Usage

Installed package form:

```powershell
python -B -m hoxline gauntlet run --artifact HO-DET-001 --format json
python -B -m hoxline gauntlet run --artifact HO-DET-001 --format markdown
```

Local checkout form:

```powershell
$env:PYTHONPATH='src'; python -B -m hoxline gauntlet run --artifact HO-DET-001 --format json
$env:PYTHONPATH='src'; python -B -m hoxline gauntlet run --artifact HO-DET-001 --format markdown
```

Optional output files:

```powershell
$env:PYTHONPATH='src'; python -B -m hoxline gauntlet run --artifact HO-DET-001 --format json --output examples/gauntlet/ho-det-001-full-loop-run-v0.json
$env:PYTHONPATH='src'; python -B -m hoxline gauntlet run --artifact HO-DET-001 --format markdown --output examples/gauntlet/ho-det-001-full-loop-run-v0.md
```

## Inputs

- `examples/demo/ho-det-001-controlled-demo-manifest.json`
- `examples/gauntlet/ho-det-001-proofcard-v0.json`
- `examples/gauntlet/ho-det-001-evidence-graph-v0.json`
- `examples/gauntlet/ho-det-001-promotion-state-v0.json`

## Outputs

- `examples/gauntlet/ho-det-001-full-loop-run-v0.json`
- `examples/gauntlet/ho-det-001-full-loop-run-v0.md`

## Output Contract

The JSON output is governed by `schemas/gauntlet-full-loop-run-v0.schema.json`.

Verify the checked-in example before future ingestion work:

```powershell
$env:PYTHONPATH='src'; python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-full-loop-run-v0.json
```

The verifier loads the schema, checks the JSON shape, and enforces the Hoxline v0 invariants that matter for reviewer safety.

## Invariants Enforced

- `artifact_id` is `HO-DET-001`.
- `product` is `Hoxline by HawkinsOperations`.
- `proof_ceiling` is `CONTROLLED_TEST_VALIDATED`.
- `public_safe` is `false`.
- `human_review_required` is `true`.
- The canonical loop contains exactly 11 stages in order.
- Stage status values are limited to `PASS`, `BLOCKED`, `MISSING_EVIDENCE`, `HUMAN_REVIEW_REQUIRED`, `NOT_PUBLIC_SAFE`, and `REFERENCE_ONLY`.
- Runtime Candidate Ledger cannot be `PASS` without runtime evidence references.
- Signal Observation cannot be `PASS` without signal evidence references.
- `allowed_claims` contains the controlled-validation safe claim.
- `blocked_claims` contains the required blocked claim families.

## Boundary

The runner allows only the controlled-validation claim already present in the HO-DET-001 ProofCard. It does not claim runtime-active status, runtime proven status, signal observed status, public-safe proof, production-ready status, SOCaaS-ready status, SOCaaS deployed status, customer deployed status, AI approved status, analyst approved status, final authorization or final human authorization, case-closure status, public runtime proof, public signal proof, revenue, legal availability, or product-market fit.

Runtime and signal stages remain blocked or missing evidence unless preserved evidence is added in the source artifacts. public_safe remains false. human_review_required remains true.

## Non-Claims

The output contract does not create proof authority. It does not claim runtime evidence, signal evidence, public-safe proof, production status, SOCaaS readiness or deployment, customer deployment, AI approval, analyst approval, final authorization, revenue, legal availability, product-market fit, or case closure.
