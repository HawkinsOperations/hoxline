# HO-DET-001 Gauntlet Controlled-Validation Run

Status: REVIEWER_BRIDGE_DRAFT

Product surface: Hoxline by HawkinsOperations

Proof ceiling: CONTROLLED_TEST_VALIDATED

public_safe value: false

Human review required: true

## Scope

This Gauntlet run records the Hoxline-side bridge for HO-DET-001. It evaluates reviewer wording against the controlled-validation ceiling and preserves authority boundaries.

Hoxline is not proof authority. Claim Firewall is an internal Hoxline Claim Authority capability. The proof record in `hawkinsoperations-proof` remains the authority source for proof status.

## Input Facts

| Field | Value |
|---|---|
| artifact_id | HO-DET-001 |
| artifact_name | Suspicious PowerShell EncodedCommand Execution |
| ATT&CK | T1059.001 |
| telemetry family | Windows process creation / Sysmon Event ID 1 where available |
| evidence_state | CONTROLLED_TEST_VALIDATED |
| proof_ceiling | CONTROLLED_TEST_VALIDATED |
| controlled cases | 14 |
| positive cases | 7 |
| negative cases | 7 |
| matched positives | 7 |
| missed positives | 0 |
| false-positive negatives | 0 |

## Authority References

- `hawkinsoperations-proof/proof/records/HO-DET-001.md`
- `hawkinsoperations-proof/proof/cards/HO-DET-001.md`
- `hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml`
- `hawkinsoperations-detections/detections/successor/ho-det-001/status.yml`
- `hawkinsoperations-validation/reports/ho-det-001/validation-result.json`
- `hawkinsoperations-validation/validation/successor/ho-det-001/validation-cases.json`
- `hawkinsoperations-platform/contracts/examples/ho-det-001-runtime-contract.sample.json`

## Allowed Claim Test

Input:

> HO-DET-001 has controlled validation evidence from controlled positive and negative process-creation fixtures and remains under review.

Decision: allowed

Reason: the wording is bounded to controlled validation evidence and keeps the artifact under review.

## Blocked Claim Tests

Each blocked family requires additional evidence and human review before promotion.

| Claim family | Decision |
|---|---|
| runtime-active | blocked |
| runtime proven | blocked |
| signal observed | blocked |
| does not claim public-safe | blocked |
| does not claim production-ready | blocked |
| SOCaaS-ready | blocked |
| SOCaaS deployed | blocked |
| customer deployed | blocked |
| live Splunk fired | blocked |
| Cribl routed live telemetry | blocked |
| Wazuh routed live telemetry | blocked |
| AWS-live | blocked |
| does not claim autonomous SOC | blocked |
| AI approved | blocked |
| analyst approved | blocked |
| case closed | blocked |
| final human authorization | blocked |
| public runtime proof | blocked |
| public signal proof | blocked |

## Output

- `examples/gauntlet/ho-det-001-proofcard-v0.json`
- `examples/gauntlet/ho-det-001-evidence-graph-v0.json`
- `examples/gauntlet/ho-det-001-promotion-state-v0.json`

## Boundary

This Gauntlet run does not claim runtime-active status.
This Gauntlet run does not claim signal observed status.
This Gauntlet run does not claim public-safe status.
This Gauntlet run does not claim production-ready status.
This Gauntlet run does not claim autonomous SOC operation, SOCaaS availability, SOCaaS deployment, customer deployment, AI approval, analyst approval, final human authorization, public runtime proof, public signal proof, or case closure.
