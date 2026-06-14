# HO-DET-001 Hoxline ProofCard v0

Status: REVIEWER_BRIDGE_DRAFT

Product surface: Hoxline by HawkinsOperations

Proof ceiling: CONTROLLED_TEST_VALIDATED

public_safe value: false

Human review required: true

## Purpose

This Hoxline ProofCard v0 is a reviewer bridge for HO-DET-001. It maps authority-repo evidence paths into a controlled-validation claim decision without changing proof authority, source truth, validation truth, platform ledgers, website rendering, or public claim ceilings.

Hoxline is not proof authority. Claim Firewall is an internal Hoxline Claim Authority capability. Proof authority remains in `hawkinsoperations-proof`.

## Artifact

| Field | Value |
|---|---|
| artifact_id | HO-DET-001 |
| artifact_name | Suspicious PowerShell EncodedCommand Execution |
| ATT&CK | T1059.001 PowerShell |
| telemetry family | Windows process creation / Sysmon Event ID 1 where available |
| evidence_state | CONTROLLED_TEST_VALIDATED |
| proof_ceiling | CONTROLLED_TEST_VALIDATED |
| public_safe | false |
| human_review_required | true |

## Controlled Validation Facts

| Fact | Value |
|---|---|
| controlled cases | 14 total |
| positives | 7 |
| negatives | 7 |
| matched positives | 7 |
| missed positives | 0 |
| false-positive negatives | 0 |

## Authority Sources

Authority sources are path references only. This Hoxline file does not copy or replace proof authority.

| Authority plane | Path reference |
|---|---|
| proof authority | `hawkinsoperations-proof/proof/records/HO-DET-001.md` |
| proof card authority route | `hawkinsoperations-proof/proof/cards/HO-DET-001.md` |
| source truth | `hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml` |
| source status | `hawkinsoperations-detections/detections/successor/ho-det-001/status.yml` |
| validation truth | `hawkinsoperations-validation/reports/ho-det-001/validation-result.json` |
| validation cases | `hawkinsoperations-validation/validation/successor/ho-det-001/validation-cases.json` |
| platform guardrail | `hawkinsoperations-platform/contracts/examples/ho-det-001-runtime-contract.sample.json` |

## Allowed Claim

HO-DET-001 has controlled validation evidence from controlled positive and negative process-creation fixtures and remains under review.

## Claim Decision

The bridge allows the controlled-validation wording above. It keeps `public_safe` false and `human_review_required` true.

The bridge does not claim runtime-active status.
The bridge does not claim runtime proven status.
The bridge does not claim signal observed status.
The bridge does not claim public-safe status.
The bridge does not claim production-ready status.
The bridge does not claim SOCaaS readiness or SOCaaS deployment.
The bridge does not claim customer deployed status.
The bridge does not claim live Splunk fired status.
The bridge does not claim Cribl routed live telemetry.
The bridge does not claim Wazuh routed live telemetry.
The bridge does not claim AWS-live status.
The bridge does not claim autonomous SOC operation.
The bridge does not claim AI approved disposition.
The bridge does not claim analyst approved disposition.
The bridge does not claim final human authorization.
The bridge does not claim case closed status.
The bridge does not claim public runtime proof.
The bridge does not claim public signal proof.

## Reviewer JSON

The reviewer-readable bridge report is in `examples/gauntlet/ho-det-001-proofcard-v0.json`.

The controlled-validation evidence graph is in `examples/gauntlet/ho-det-001-evidence-graph-v0.json`.

The promotion-state guardrail example is in `examples/gauntlet/ho-det-001-promotion-state-v0.json`.

## Non-Claims

This ProofCard bridge does not claim public-safe proof, customer deployment, autonomous SOC operation, AI-approved disposition, analyst-approved disposition, final human authorization, public runtime proof, public signal proof, enterprise purchase intent, legal availability, trademark clearance, LLC formation, or case closure; it also does not create proof authority, runtime truth, signal truth, production readiness, or SOCaaS availability.
