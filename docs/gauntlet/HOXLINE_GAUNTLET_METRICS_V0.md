# Hoxline Gauntlet Metrics v0

This page describes the Work Impact Metrics v0 output for `HOX-GAUNTLET-001`.

Proof ceiling: `CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY`.

## What Is Measured

The metrics engine evaluates the controlled synthetic event fixture for the browser-cache / script-interpreter detection-review scenario. It emits numeric JSON for:

* synthetic event volume
* expected positive and negative counts
* true positive, true negative, false positive, and false negative counts
* precision, recall, F1, and false-positive rate
* telemetry field coverage
* Claim Authority allowed and blocked counts
* ProofCard section completeness
* evidence gaps that remain open
* explicit false proof-boundary flags

## Sample Metric Table

| Metric | Value | Meaning |
| --- | ---: | --- |
| events_total | 12 | synthetic events evaluated |
| expected_positive | 4 | events expected to match the controlled review rule |
| expected_negative | 8 | events expected not to match the controlled review rule |
| true_positive | 4 | expected positive events matched |
| true_negative | 8 | expected negative events did not match |
| false_positive | 0 | benign events incorrectly matched |
| false_negative | 0 | expected matches missed |
| precision | 1.0 | controlled fixture precision |
| recall | 1.0 | controlled fixture recall |
| f1 | 1.0 | controlled fixture F1 |
| false_positive_rate | 0.0 | controlled fixture false-positive rate |
| claims_scanned | 7 | one allowed claim plus six blocked claims evaluated |
| claims_allowed | 1 | controlled safe claim allowed |
| claims_blocked | 6 | unsupported claims blocked |
| telemetry_coverage | 100.0% | required fields present in fixture |
| proofcard_completeness | 100.0% | required sections present |
| numeric_metrics_emitted_count | 26 | numeric fields emitted in the report |
| measurable_output | true | numeric report emitted |

## Screenshot-Ready Metric Block

```text
HOX-GAUNTLET-001 Work Impact Metrics v0
events_total: 12
true_positive: 4
true_negative: 8
false_positive: 0
false_negative: 0
precision: 1.0
recall: 1.0
f1: 1.0
false_positive_rate: 0.0
telemetry_coverage_percent: 100.0
claims_scanned: 7
claims_allowed: 1
claims_blocked: 6
proofcard_completeness_percent: 100.0
proof_ceiling: CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY
```

## What The Numbers Prove

The numbers prove that Hoxline can run a deterministic controlled-fixture evaluation for this one synthetic detection-review artifact and emit measurable JSON. They also show that the fixture has all required telemetry fields, that Claim Authority blocks unsupported wording in the bad release note, and that the ProofCard has all required sections.

## What The Numbers Do Not Prove

This artifact does not prove runtime evidence, signal evidence, customer deployment, production readiness, AI approval, analyst approval, final authorization, or public runtime authorization. A perfect score on this controlled fixture is only controlled fixture perfect.

## How To Run

```powershell
python -B -m hoxline.cli gauntlet metrics `
  --events examples/gauntlet/synthetic-events.json `
  --artifact examples/gauntlet/sample-artifact.json `
  --proofcard examples/gauntlet/sample-proofcard.json `
  --claim-output examples/gauntlet/sample-claim-authority-output.json `
  --format json
```

To write the report:

```powershell
python -B -m hoxline.cli gauntlet metrics `
  --events examples/gauntlet/synthetic-events.json `
  --artifact examples/gauntlet/sample-artifact.json `
  --proofcard examples/gauntlet/sample-proofcard.json `
  --claim-output examples/gauntlet/sample-claim-authority-output.json `
  --format json `
  --output examples/gauntlet/sample-work-impact-metrics.json
```

The checked-in sample report is `examples/gauntlet/sample-work-impact-metrics.json`.
