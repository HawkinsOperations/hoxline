# Product Boundary

Hoxline is ProofOps control for the AI security era.

Hoxline by HawkinsOperations is the product name for the current product/front-door repo.

Current repo: HawkinsOperations/hoxline. Product name: Hoxline by HawkinsOperations.

AevumGuard was a prior working name. Hoxline is the current product name.

Hoxline governs how AI-assisted security work becomes tested, reviewed, blocked, or safe to claim.

Doctrine: AI is not the authority. Evidence is.

## Owns

Hoxline owns the control-plane product boundary for this loop:

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

Hoxline owns:

* Artifact intake rules for AI-assisted security work.
* Evidence graph structure and evidence sufficiency tracking.
* Promotion state records for movement through the loop.
* Telemetry contract check status as a gate, not as telemetry ownership.
* Controlled validation state as a gate, not as validation implementation ownership.
* Runtime candidate ledger structure.
* Signal observation status as evidence state.
* Human Review Gate status.
* ProofCard readiness state and references.
* Claim Authority decisions.
* Claim Firewall as the first Claim Authority enforcement capability.

## Does Not Own

Hoxline does not own:

* Detection engineering repositories or rule libraries.
* Validation runners, harnesses, or external validation infrastructure.
* Platform runtime systems.
* Public website implementation.
* Organization-level GitHub administration.
* Raw runtime exports, private evidence, credentials, or secrets.
* Separate side-product repositories for internal modules.

## Claim Firewall Boundary

Claim Firewall is the first Claim Authority enforcement capability inside Hoxline. It is not the product.

Claim Firewall can block, constrain, or require edits to a claim when the evidence graph, promotion state, ProofCard, or review gate does not support the claim. It does not replace the product spine or authorize claims by itself.

## Default Demo Boundary

The default reviewer/demo path is the HO-DET-001 Gauntlet at `docs/gauntlet/HO_DET_001_GAUNTLET_RUN.md`.

It is bounded to one artifact, the full Hoxline loop, one ProofCard reference, one safe claim, blocked stronger claims, a missing evidence list, proof ceiling, runtime boundary, signal boundary, and human review boundary.

Safe claim:

> HO-DET-001 has controlled validation evidence and remains under governed public-safe candidate review.

The Gauntlet does not claim production ready, runtime proven, signal observed, customer deployed, SOCaaS deployed, public-safe runtime proof, AI approved, analyst approved, final authorization, or case closure unless exact evidence exists and is approved.

## Candidate Review Boundary

HO-DET-001 Public-Safe Candidate Review v1 is represented in Hoxline as controlled-validation modeling only.

* Platform reference: `hawkinsoperations-platform#64`, merge commit `c49a95e2b9f2e6b5fa118c03dfc68f8827981c82`.
* Proof reference: `hawkinsoperations-proof#82`, merge commit `68798e43855e34a15df06d9a2bc9d6ac71d6746d`.
* Review lane: `PUBLIC_SAFE_CANDIDATE_REVIEW_V1`.
* Review gates: privacy review, stale review, evidence-linkage review, and wording approval remain `PENDING`.
* Runtime is not promoted. Signal is not promoted. Hoxline does not claim public-safe approval.
* Human review is required before any stronger public claim.

Rendering, GitHub display, and green CI are not proof or approval.

## Seven-Repo Rule

Exactly seven repos. No eighth repo.

## Proof Ceiling

This repository content is PRODUCT_SPINE_ONLY. It defines product structure and sample records. It does not establish runtime proof, signal proof, external safety status, final authorization, or deployment status.
