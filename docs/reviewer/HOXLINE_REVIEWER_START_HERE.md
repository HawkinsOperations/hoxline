# Hoxline Reviewer Start Here

Status: REVIEWER_START_HERE / POST_MERGE_GUIDE / NO_PROOF_PROMOTION

Proof ceiling: CONTROLLED_TEST_VALIDATED

public_safe: false

human_review_required: true

## 30-Second Path

From a clone of Hoxline, run:

```powershell
python -B -m hoxline demo quickstart
```

The demo is deterministic, local, and fixture-based. It writes a reviewer pack under `.hoxline/demo-runs/`, keeps `public_safe_status=NOT_PUBLIC_SAFE`, keeps `human_review_required=true`, keeps `ai_disposition_authority=false`, and does not claim live runtime proof or public proof promotion.
## Inspect First

Start with these files:

1. `docs/gauntlet/HO_DET_001_GAUNTLET_RUN.md`
2. `examples/gauntlet/ho-det-001-full-loop-run-v0.json`
3. `examples/gauntlet/ho-det-001-full-loop-run-v0.md`
4. `examples/gauntlet/ho-det-001-proofcard-v0.json`
5. `docs/proofcards/HO-DET-001_PROOFCARD_V0.md`
6. `docs/reviewer/HOXLINE_PUBLIC_REVIEWER_PACKET_V0.md`
7. `examples/reviewer/hoxline-public-reviewer-packet-v0.json`
8. `examples/reviewer/hoxline-public-reviewer-packet-v0.md`
9. `docs/demo/HOXLINE_CONTROLLED_DEMO_V0.md`
10. `docs/demo/HO_DET_001_WALKTHROUGH.md`
11. `docs/demo/CLAIM_DECISION_TABLE.md`
12. `docs/releases/HOXLINE_PR7_PR8_PR63_RELEASE_PACKET.md`
13. `docs/strategy/README.md`
14. Website route: `/hoxline/`

## Hoxline Product Loop

Hoxline controls what AI-assisted security work is allowed to become.

The current loop is:

1. AI-assisted security work
2. Artifact Intake
3. Evidence Graph
4. Telemetry Contract Check
5. Controlled Validation
6. Runtime Candidate Ledger
7. Signal Observation
8. Human Review Gate
9. ProofCard
10. Claim Authority
11. Safe Claim / Blocked Claim

One artifact, one loop, one ProofCard, one safe claim, one blocked claim.

Default safe claim:

> HO-DET-001 has controlled validation evidence under stated scope and remains bounded by its proof ceiling.

The default Gauntlet output shows blocked stronger claims, the missing evidence list, proof ceiling, runtime boundary, signal boundary, and human review boundary.

## HO-DET-001 Bridge Artifacts

- Controlled demo overview: `docs/demo/HOXLINE_CONTROLLED_DEMO_V0.md`
- Controlled demo walkthrough: `docs/demo/HO_DET_001_WALKTHROUGH.md`
- Claim decision table: `docs/demo/CLAIM_DECISION_TABLE.md`
- Controlled demo manifest: `examples/demo/ho-det-001-controlled-demo-manifest.json`
- Claim decision summary: `examples/demo/ho-det-001-claim-decision-summary.json`
- ProofCard bridge: `docs/proofcards/HO-DET-001_PROOFCARD_V0.md`
- Gauntlet run: `docs/gauntlet/HO_DET_001_GAUNTLET_RUN.md`
- Reviewer report JSON: `examples/gauntlet/ho-det-001-proofcard-v0.json`
- Evidence graph example: `examples/gauntlet/ho-det-001-evidence-graph-v0.json`
- Promotion-state example: `examples/gauntlet/ho-det-001-promotion-state-v0.json`
- Claim Authority policy: `examples/policies/default-claim-authority-policy.yml`
- Bridge tests: `tests/test_ho_det_001_bridge.py`

## Strategy Draft Locations

- `docs/strategy/README.md`
- `docs/strategy/Hoxline_ProofOps_Case_Study_DRAFT.md`
- `docs/strategy/Hoxline_Business_Model_DRAFT.md`
- `docs/strategy/Hoxline_Go_To_Market_Narrative_DRAFT.md`
- `docs/strategy/Hoxline_Public_Proof_Hardening_DRAFT.md`

These docs are DRAFT / STRATEGY_ONLY / HYPOTHESIS_ONLY.


## Private Runtime Candidate Review

Hoxline now distinguishes the public HO-DET-001 controlled-validation reviewer path from private runtime candidate review.

Private runtime candidate review is not public proof. It is a governed internal lane where a reviewer can inspect bounded metadata showing how an artifact moved through source, telemetry contract, controlled validation, private runtime observation, sanitized packet verification, scheduled collector inclusion, claim ceiling, blocked claims, and next review gate.

Current private scheduled collector scope:

- HO-DET-009
- HO-DET-010
- HO-DET-011
- HO-DET-012

HO-DET-010 may be described internally as having private VM108-scoped runtime signal evidence, a verified private packet, and standing private collector inclusion. It remains `NOT_PUBLIC_SAFE`, `human_review_required=true`, and `ai_disposition_authority=false` pending governed review.

Do not copy private packet contents, raw Wazuh alerts, endpoint logs, command lines, generated credentials, private payloads, execution identifiers, or private telemetry into public documentation.
## Website Route

The website route is `/hoxline/`.

Website rendering is not proof. The website route does not create proof authority. The route presents the controlled-validation bridge for reviewer orientation only.

## Authority Boundaries

- Hoxline is the product/front-door name.
- Hoxline by HawkinsOperations is the public form.
- Claim Firewall is an internal Hoxline Claim Authority capability.
- Hoxline is not proof authority.
- `hawkinsoperations-proof` remains proof authority.
- `hawkinsoperations-detections` remains source truth.
- `hawkinsoperations-validation` remains behavior truth.
- `hawkinsoperations-platform` remains contracts, schemas, ledgers, and promotion authority.
- `hawkinsoperations-website` remains rendering only.

Controlled validation proves controlled validation only.

Codex is labor. Evidence is authority. Raylee approves promotion.

## What Is Not Claimed

This reviewer guide does not claim runtime-active status, runtime proven status, signal observed status, public-safe proof, production-ready status, SOCaaS readiness, SOCaaS deployment, customer deployed status, live Splunk fired status, Cribl routed live telemetry, Wazuh routed live telemetry, AWS-live status, autonomous SOC operation, AI approved disposition, analyst approved disposition, final human authorization, public runtime proof, public signal proof, enterprise purchase intent, customer traction, revenue, legal availability, trademark clearance, LLC formation, or case closure.

## What Must Not Be Promoted Yet

Do not promote runtime-active status.

Do not promote signal observed status.

This guide does not claim public-safe proof.

This guide does not claim production-ready status.

Do not promote SOCaaS readiness or SOCaaS deployment.

Do not promote customer deployed status.

Do not promote AI approval, analyst approval, final human authorization, or case closure.

## Next Safe Work Item

Hoxline public reviewer packet v0 / controlled demo packaging.

Keep that work bounded to reviewer packaging and controlled demo language. It does not claim public-safe status and should not promote runtime, signal, production, SOCaaS, customer, or legal claims.
