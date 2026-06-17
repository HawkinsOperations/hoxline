# Hoxline Gauntlet v1

Hoxline Gauntlet v1 is a laptop-runnable product-engine loop for one bounded artifact: `HO-DET-001`.

It covers:

AI-assisted security work -> Artifact Intake -> Evidence Graph -> Telemetry Contract Check -> Controlled Validation -> Runtime Candidate Ledger -> Signal Observation -> Human Review Gate -> ProofCard -> Claim Authority -> Safe Claim / Blocked Claim.

## Reviewer Commands

```powershell
python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json --schema schemas/gauntlet-run-v1.schema.json
python -B -m hoxline gauntlet summarize --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json
python -B -m hoxline claim-authority decide --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json
python -B -m hoxline proofcard render --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json
```

No server is required. No runtime collector is required.

## Source Routes

Downstream reviewers can use `examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json` as the machine-readable route index for the v1 examples, schemas, reviewer docs, and CLI commands.

## What It Proves

The command proves that the local Gauntlet v1 record preserves the product-loop shape, owner split, proof ceiling, missing evidence list, blocked claims, and next gate.

Allowed claim:

> HO-DET-001 has controlled validation evidence under stated scope and remains bounded by its proof ceiling.

## What It Does Not Prove

It does not claim runtime truth, signal truth, public-safe status, customer deployment, SOCaaS deployment, production readiness, AI-approved disposition, analyst-approved disposition, final authorization, or case closure.

## Authority Split

* Source owner: `hawkinsoperations-detections`
* Validation owner: `hawkinsoperations-validation`
* Platform owner: `hawkinsoperations-platform`
* Proof owner: `hawkinsoperations-proof`
* Website owner: `hawkinsoperations-website`

The website boundary is rendering-only. The website may display approved records; it cannot authorize claims or create proof.

Proof ceiling: `CONTROLLED_TEST_VALIDATED`.

Public release safety is not asserted.
