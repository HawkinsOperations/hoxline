# Hoxline ProofOps Case Study

Status: DRAFT / STRATEGY_ONLY / HYPOTHESIS_ONLY

Proof ceiling: CONTROLLED_TEST_VALIDATED

public_safe: false

human_review_required: true

## Problem

AI-assisted security work can produce confident summaries faster than evidence can be checked. That creates a governance problem: a draft detection, triage note, or release summary can sound stronger than its authority sources allow.

Hoxline frames that gap as a ProofOps problem. The product question is not whether AI can write security output. The product question is whether every claim can be bounded to source truth, behavior truth, proof authority, and human review.

## Product

Hoxline by HawkinsOperations is a control plane for moving AI-assisted security work from draft output to evidence-bound claims.

The current demo surface is the HO-DET-001 ProofCard v0 / Gauntlet controlled-validation bridge. The bridge does three things:

1. References authority sources by path.
2. Emits a reviewer-readable claim decision.
3. Blocks stronger claims until the required evidence and review gates exist.

Claim Firewall is the internal Claim Authority capability that evaluates wording. It is not the product identity.

## First Demo

HO-DET-001 is the controlled-validation example:

| Field | Value |
|---|---|
| artifact_id | HO-DET-001 |
| ATT&CK | T1059.001 |
| telemetry family | Windows process creation / Sysmon Event ID 1 where available |
| controlled cases | 14 total |
| positives | 7 |
| negatives | 7 |
| matched positives | 7 |
| missed positives | 0 |
| false-positive negatives | 0 |
| evidence_state | CONTROLLED_TEST_VALIDATED |
| proof_ceiling | CONTROLLED_TEST_VALIDATED |
| public_safe | false |
| human_review_required | true |

Allowed demo wording:

> HO-DET-001 has controlled validation evidence from controlled positive and negative process-creation fixtures and remains under review.

## What Hoxline Shows

Hoxline shows that a security artifact can have useful controlled-validation evidence while still refusing stronger claims.

The bridge does not claim runtime-active status.
The bridge does not claim signal observed status.
The bridge does not claim public-safe status.
The bridge does not claim production-ready status.
The bridge does not claim SOCaaS readiness.
The bridge does not claim customer deployed status.
The bridge does not claim AI approval, analyst approval, final human authorization, or case closure.

## Reviewer Takeaway

The case study is not a public proof promotion. It is a bounded demonstration of claim control: safe wording can pass, unsafe promotion language is blocked, and authority remains in the designated HawkinsOperations repositories.
