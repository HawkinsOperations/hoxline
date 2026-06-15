# HO-DET-001 Controlled Demo Walkthrough

Status: REVIEWER_WALKTHROUGH / CONTROLLED_VALIDATION_ONLY / NO_PROOF_PROMOTION

Proof ceiling: CONTROLLED_TEST_VALIDATED

public_safe: false

human_review_required: true

## Walkthrough Goal

This walkthrough shows how one HO-DET-001 controlled-validation artifact moves through the Hoxline reviewer loop. It is a demo package for inspection. It does not create proof authority and does not promote stronger claims.

## Chain

AI-assisted security work
-> Artifact Intake
-> Evidence Graph
-> Telemetry Contract Check
-> Controlled Validation
-> Runtime Candidate Ledger
-> Signal Observation
-> Human Review Gate
-> ProofCard
-> Claim Authority
-> Safe Claim / Blocked Claim

## Step 1: Artifact Intake

The artifact is HO-DET-001, Suspicious PowerShell EncodedCommand Execution. Hoxline treats the artifact as reviewer input and references source-truth paths instead of copying authority records.

Inspect:

- `docs/proofcards/HO-DET-001_PROOFCARD_V0.md`
- `examples/gauntlet/ho-det-001-proofcard-v0.json`

## Step 2: Evidence Graph

The evidence graph connects the artifact to the telemetry contract, controlled validation, runtime candidate, signal observation, human review gate, ProofCard, and claim decision.

Inspect:

- `examples/gauntlet/ho-det-001-evidence-graph-v0.json`

The graph keeps runtime and signal observation fields false or empty where no authority evidence exists.

## Step 3: Telemetry Contract Check

HO-DET-001 references Windows process creation telemetry, with Sysmon Event ID 1 where available. The demo does not create telemetry evidence and does not edit the detection source.

Inspect:

- `examples/gauntlet/ho-det-001-promotion-state-v0.json`

## Step 4: Controlled Validation

Controlled validation is the highest supported state in this demo package:

- evidence_state: CONTROLLED_TEST_VALIDATED
- proof_ceiling: CONTROLLED_TEST_VALIDATED
- controlled cases: 14
- positives: 7
- negatives: 7
- matched positives: 7
- missed positives: 0
- false-positive negatives: 0

Controlled validation proves controlled validation only.

## Step 5: Runtime Candidate Ledger

The runtime candidate stage is represented as a gate, not as achieved runtime evidence. This walkthrough does not claim runtime-active status or runtime proven status.

## Step 6: Signal Observation

The signal observation stage is represented as a gate, not as achieved signal evidence. This walkthrough does not claim signal observed status.

## Step 7: Human Review Gate

The human review gate remains required. human_review_required remains true because this demo does not claim final authorization and does not claim analyst approval.

## Step 8: ProofCard

The ProofCard is a reviewer bridge. It summarizes the controlled-validation ceiling and the claim decision. Hoxline is not proof authority, and the ProofCard does not become proof authority.

Inspect:

- `docs/proofcards/HO-DET-001_PROOFCARD_V0.md`

## Step 9: Claim Authority

Claim Firewall is an internal Hoxline Claim Authority capability. It allows the controlled-validation claim and blocks stronger claim families.

Inspect:

- `examples/policies/default-claim-authority-policy.yml`
- `examples/demo/ho-det-001-claim-decision-summary.json`

## Step 10: Safe Claim / Blocked Claim

Safe claim:

HO-DET-001 has controlled validation evidence from controlled positive and negative process-creation fixtures and remains under review.

Blocked claim boundary:

This walkthrough does not claim runtime-active status, runtime proven status, signal observed status, public-safe proof, production-ready status, SOCaaS-ready status, SOCaaS deployed status, customer deployed status, live Splunk fired status, Cribl routed live telemetry, Wazuh routed live telemetry, AWS-live status, autonomous SOC operation, AI approved disposition, analyst approved disposition, final authorization or final human authorization, case closure status, public runtime proof, public signal proof, enterprise purchase intent, customer traction, revenue, legal availability, trademark clearance, LLC formation, or product-market fit.

## Promotion Evidence Needed

Before stronger claims are considered, reviewers need evidence outside this demo package:

- Runtime evidence tied to the artifact.
- Preserved signal observation evidence.
- Public release authorization.
- Completed human review gate.
- Analyst review record for analyst approval.
- This walkthrough does not claim final authorization; required next evidence is `final_authorization_record`.
- This walkthrough does not claim case closure; required next evidence is `case_closure_record`.
- Legal and business review records for legal availability, trademark clearance, formation, revenue, traction, or market-fit language.
