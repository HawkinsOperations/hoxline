# Hoxline

Hoxline is a proof-bound claim control system for AI-assisted security work.

Hoxline by HawkinsOperations is the product name for the current product/front-door repo.

Current repository path: HawkinsOperations/aevumguard. Product name: Hoxline by HawkinsOperations. Repository rename is not yet approved.

Hoxline governs how AI-assisted security work becomes tested, reviewed, blocked, or safe to claim.

Doctrine: AI is not the authority. Evidence is.

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
* aevumguard

No eighth repository is part of this product spine. Hoxline modules are internal product modules, not separate repositories.

## Current Contents

* `PRODUCT_BOUNDARY.md` defines what Hoxline owns and does not own.
* `docs/product/AEVUMGUARD_BLUEPRINT.md` describes the v0 product spine.
* `docs/product/MODULE_MAP.md` maps every loop stage to an internal module responsibility.
* `docs/product/SEVEN_REPO_SYSTEM_MAP.md` preserves the seven-repo system boundary.
* `docs/product/PROOFOPS_DOCTRINE.md` states the evidence-first doctrine.
* `docs/gauntlet/AEVUMGUARD_GAUNTLET_V0.md` walks one artifact through the full loop.
* `schemas/` contains v0 JSON shapes for promotion state and evidence graph records.
* `examples/gauntlet/` contains sample JSON records with runtime observation, signal observation, and public safety status unset.

Proof ceiling: PRODUCT_SPINE_ONLY.
