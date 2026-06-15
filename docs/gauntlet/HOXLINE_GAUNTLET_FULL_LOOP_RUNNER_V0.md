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

## Boundary

The runner allows only the controlled-validation claim already present in the HO-DET-001 ProofCard. It does not claim runtime-active status, runtime proven status, signal observed status, public-safe proof, production-ready status, SOCaaS-ready status, SOCaaS deployed status, customer deployed status, AI approved status, analyst approved status, final authorization or final human authorization, case-closure status, public runtime proof, public signal proof, revenue, legal availability, or product-market fit.

Runtime and signal stages remain blocked or missing evidence unless preserved evidence is added in the source artifacts. public_safe remains false. human_review_required remains true.
