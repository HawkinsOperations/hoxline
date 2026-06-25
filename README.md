# Hoxline by HawkinsOperations

Hoxline is ProofOps control for the AI security era.

Hoxline by HawkinsOperations is the product name for the current product/front-door repo.

Current repo: HawkinsOperations/hoxline. Product name: Hoxline by HawkinsOperations.

AevumGuard was a prior working name. Hoxline is the current product name.

Hoxline governs how AI-assisted security work becomes tested, reviewed, blocked, or safe to claim.

Doctrine: AI is not the authority. Evidence is.

## 30-Second Reviewer Demo

Run the deterministic local reviewer demo from a fresh clone:

```powershell
python -B -m hoxline demo quickstart
```

For an explicit repeatable output path:

```powershell
python -B -m hoxline demo quickstart --output .hoxline/demo-runs/self-test --force
python -B -m hoxline demo verify --input .hoxline/demo-runs/self-test/run-summary.json
```

The command writes `.hoxline/demo-runs/<timestamp-or-demo-id>/` with `intake.json`, `evidence-graph.json`, `telemetry-contract-check.json`, `validation-result.json`, `synthetic-signal.json`, `enrichment.json`, `triage-summary.md`, `proofcard.json`, `proofcard.md`, `claim-authority.json`, `reviewer-pack.md`, and `run-summary.json`.

What it proves: Hoxline can carry a synthetic HO-DET-010 fixture through intake, evidence graph, telemetry contract check, controlled validation, fixture-only signal simulation, enrichment, triage, ProofCard, Claim Authority, blocked claims, and reviewer packaging.

What it does not prove: live runtime behavior, public signal observation, public-safe status, production readiness, SOCaaS deployment, customer deployment, autonomous SOC operation, AI approval, analyst approval, final authorization, or case closure. The demo does not touch endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, ledgers, or website proof state.

See `docs/demo/HOXLINE_ONE_COMMAND_REVIEWER_DEMO_V0.md` for the design contract and 30-second talk track.
## Product Spine

Hoxline governs the product loop:

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

The product spine in this repository defines the boundary, module map, doctrine, gauntlet, schemas, and examples for that loop. It does not create runtime proof, signal proof, final authorization, or external claims.

## Default Reviewer/Demo Path

The default reviewer and demo path is the HO-DET-001 Gauntlet:

1. `docs/gauntlet/HO_DET_001_GAUNTLET_RUN.md`
2. `examples/gauntlet/ho-det-001-full-loop-run-v0.json`
3. `examples/gauntlet/ho-det-001-full-loop-run-v0.md`
4. `examples/gauntlet/ho-det-001-proofcard-v0.json`
5. `docs/proofcards/HO-DET-001_PROOFCARD_V0.md`

This path shows one artifact, the full Hoxline loop, one ProofCard reference, one safe claim, blocked stronger claims, the missing evidence list, proof ceiling, runtime boundary, signal boundary, and human review boundary.

Safe claim:

> HO-DET-001 has controlled validation evidence and remains under governed public-safe candidate review.

This path does not claim production ready, runtime proven, signal observed, customer deployed, SOCaaS deployed, public-safe runtime proof, AI approved, analyst approved, final authorization, or case closure.

## HO-DET-001 Public-Safe Candidate Review v1

Hoxline models the merged platform/proof candidate-review state for HO-DET-001 as a bounded product loop state only:

* `review_lane`: `PUBLIC_SAFE_CANDIDATE_REVIEW_V1`
* `privacy_review`, `stale_review`, `evidence_linkage_review`, `wording_approval`: `PENDING`
* `public_safe_status`: `NOT_PUBLIC_SAFE`
* `runtime_active`: `false`
* `signal_observed`: `false`
* `human_review_required`: `true`
* `proof_ceiling`: `CONTROLLED_TEST_VALIDATED`
* `proof_ceiling_meaning`: `CONTROLLED_VALIDATION_ONLY`

References are carried from `hawkinsoperations-platform#64` and `hawkinsoperations-proof#82`. They remain references only; Hoxline does not own platform ledger truth, proof authority, runtime truth, signal truth, website rendering authority, or final authorization. Hoxline does not claim public-safe approval.


## Private Runtime Candidate Lane

Hoxline also supports private runtime candidate review for artifacts whose source, telemetry contract, validation, private signal, packet verification, and scheduled collector inclusion have been established internally but are not public-safe proof.

HO-DET-010 is the current bounded example: it has private VM108-scoped runtime signal evidence, a verified private packet, and standing private collector inclusion. It remains `NOT_PUBLIC_SAFE`; human review is required; AI has no disposition authority; no public proof, ledger append, website proof promotion, production, customer, SOCaaS, fleet, analyst-approved, AI-approved, or case-closure claim is made.
## Claim Firewall

Claim Firewall is the first Claim Authority enforcement capability inside Hoxline.

Claim Firewall is not the product, not the front-door repo, not the platform, and not an eighth repo. It is an internal capability that helps Claim Authority block or constrain claims when evidence is missing, stale, incompatible, or insufficient.

Existing Claim Firewall behavior remains in the `claimfirewall` CLI, GitHub Action contract, policy loader, scanner, and tests. The product spine repositions that behavior inside Hoxline; it does not replace the implementation.

## Repository Set

The HawkinsOperations system is exactly seven repositories:

Exactly seven repos. No eighth repo.

* .github
* hawkinsoperations-detections
* hawkinsoperations-validation
* hawkinsoperations-platform
* hawkinsoperations-proof
* hawkinsoperations-website
* hoxline

No eighth repository is part of this product spine. Hoxline modules are internal product modules, not separate repositories.

## Current Contents

* `PRODUCT_BOUNDARY.md` defines what Hoxline owns and does not own.
* `docs/gauntlet/HO_DET_001_GAUNTLET_RUN.md` is the default HO-DET-001 reviewer/demo path.
* `docs/reviewer/HOXLINE_PUBLIC_REVIEWER_PACKET_V0.md` explains the public reviewer packet and its boundaries.
* `docs/product/HOXLINE_BLUEPRINT.md` defines the Hoxline product-spine blueprint.
* `docs/product/MODULE_MAP.md` maps every loop stage to an internal module responsibility.
* `docs/product/SEVEN_REPO_SYSTEM_MAP.md` preserves the seven-repo system boundary.
* `docs/product/PROOFOPS_DOCTRINE.md` states the evidence-first doctrine.
* `docs/gauntlet/HOXLINE_GAUNTLET_V0.md` remains a non-default sample path.
* `schemas/` contains v0 JSON shapes for promotion state and evidence graph records.
* `examples/gauntlet/` contains sample JSON records with runtime observation, signal observation, and public safety status unset.
* `examples/reviewer/hoxline-public-reviewer-packet-v0.json` contains the sanitized reviewer current-state packet.

Proof ceiling: PRODUCT_SPINE_ONLY.
