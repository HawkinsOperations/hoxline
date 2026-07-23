# Hoxline Case Growth Index v1

Generated: `2026-07-23T00:11:42Z`
Proof ceiling: `CASE_GROWTH_INDEX_CONTROLLED_REPO_AGGREGATION_ONLY`
Repo-slot accuracy: `seven expected repo slots evaluated; seven present local repos scanned`
Historical snapshot: `false`
Current authority: `true`
Reproducibility SHA-256: `85b30834147614510b1a1a42f7c5652821adeae05e487811e5d2c52ea41d990b`

## Summary

| Metric | Count |
| --- | ---: |
| `cases_total` | 27 |
| `source_packages_count` | 14 |
| `controlled_validations_count` | 12 |
| `runtime_candidate_lanes_count` | 5 |
| `private_runtime_evidence_captured_count` | 1 |
| `scheduled_collector_lanes_count` | 4 |
| `proof_records_count` | 11 |
| `proofcards_count` | 12 |
| `claim_authority_cases_count` | 26 |
| `metrics_available_count` | 1 |
| `public_safe_cases_count` | 0 |
| `closed_cases_count` | 0 |
| `blocked_claims_count` | 295 |
| `cases_with_next_gate_count` | 26 |
| `cases_missing_proof_record_count` | 16 |
| `cases_missing_proofcard_count` | 15 |
| `cases_not_public_safe_count` | 27 |
| `unknown_state_count` | 1 |

## Source Revisions

| Repository | Authority role | Source path | Source revision | Source freshness | Snapshot freshness |
| --- | --- | --- | --- | --- | --- |
| `.github` | `org command-center routing` | `scripts/verify-command-center-invariants.py` | `b051aa3981e52a56b45a3078fcbf32ac34a99f92` | `CURRENT` | `CURRENT` |
| `hawkinsoperations-detections` | `detection source truth` | `detections/DETECTION_PROMOTION_MATRIX.yml` | `c2790ab007279faff6130a60dc68818343c255ee` | `CURRENT` | `CURRENT` |
| `hawkinsoperations-validation` | `controlled validation truth` | `validation/VALIDATION_REGISTRY.yml` | `a3a2f6938412f3012bea1bc447bb084d82ed1936` | `CURRENT` | `CURRENT` |
| `hawkinsoperations-platform` | `platform contract truth` | `contracts/public-status-source-contract-v1.json` | `7ed8f08c9c3e4bc07797961ba84292ec96978da6` | `CURRENT` | `CURRENT` |
| `hawkinsoperations-proof` | `proof and claim-boundary truth` | `proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml` | `042a918ad4a8473cd5abcfd575072fc094639682` | `CURRENT` | `CURRENT` |
| `hawkinsoperations-website` | `rendering-only public status` | `public/data/public-status.json` | `771c90515d687eb0ce86fd438d664a9234912f67` | `CURRENT` | `CURRENT` |
| `hoxline` | `case-growth and fixture-review product truth` | `src/hoxline/case_growth/collector.py` | `4c96f52f28a3f0af767a94529cff165fc2042ca2` | `CURRENT_SELF_REFERENTIAL` | `CURRENT` |

## Convergence Findings

- No missing, dangling, contradictory, or stale source-owned state detected.

Next legal action: none; current source-controlled inputs converge

## Case Growth Health

| Health metric | Value |
| --- | ---: |
| `validation_coverage_percent` | 85.71 |
| `proof_record_coverage_percent` | 40.74 |
| `proofcard_coverage_percent` | 44.44 |
| `scheduled_collector_coverage_percent` | 14.81 |
| `runtime_candidate_coverage_percent` | 18.52 |
| `metrics_coverage_percent` | 3.7 |
| `public_safe_percent` | 0.0 |
| `closed_case_percent` | 0.0 |
| `blocked_claim_density` | 10.93 |
| `next_gate_coverage_percent` | 96.3 |
| `missing_proof_record_percent` | 59.26 |
| `missing_proofcard_percent` | 55.56 |
| `not_public_safe_percent` | 100.0 |

| Assessment | Value |
| --- | --- |
| `overall_health_status` | `PUBLIC_SAFE_BLOCKED` |
| `strongest_lane` | `controlled_validation` |
| `weakest_lane` | `public_safe` |
| `recommended_next_build` | `proof_record_backfill` |

| Top bottleneck |
| --- |
| `public_safe blocked for all indexed cases` |
| `proof records missing for most indexed cases` |
| `ProofCards missing for most indexed cases` |
| `case-level metrics available for only a small share of indexed cases` |

The health section is derived from numeric index counts only. It does not promote runtime, signal, customer, production, approval, or public_safe runtime proof.

## Cases

| case_id | source | validation | runtime_candidate | scheduled | proof | proofcard | metrics | public_safe | case_state | next_gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `AWS-DET-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `separate proof scope before any live-cloud or public route approval` |
| `HO-DET-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `proof-record-specific human review before any public-safe, runtime, or signal promotion` |
| `HO-DET-002` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-003` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-004` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-005` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-006` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-007` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-008` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-009` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `separate runtime receipt and proof review before any runtime, signal, public-safe, production, or approval wording` |
| `HO-DET-010` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any separately approved private runtime gate` |
| `HO-DET-011` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_EVIDENCE_CAPTURED` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `proof-card or public reviewer route only after separate human-approved proof scope` |
| `HO-DET-012` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `blocked until separate runtime or signal evidence review supports any runtime, routed-telemetry, public-safe, production, autonomous SOC, or disposition-authority promotion` |
| `HO-DET-013` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any separately approved private runtime gate` |
| `HO-DET-014` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-015` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-016` | `VALIDATION_PLANNED` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-DET-999` | `NOT_FOUND` | `NOT_FOUND` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `UNKNOWN_WITH_REASON` | `UNKNOWN_WITH_REASON: no next gate indexed` |
| `HO-NDR-001` | `EXTERNAL_BOUNDARY_CONTRACT` | `VALIDATION_CONTRACT_ENFORCED` | `NOT_PROVEN` | `NOT_INDEXED` | `NOT_PROVEN` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `captured cross-source corroboration evidence under separate proof scope` |
| `HO-NDR-002` | `VALIDATION_PLANNED` | `NOT_FOUND` | `LISTED_ONLY` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `create source package under separate source-authoring approval` |
| `HO-PIPE-001` | `SOURCE_EXISTS` | `VALIDATION_CONTRACT_ENFORCED` | `TELEMETRY_CONTRACT_ONLY` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `proof and runtime remain separate; any traffic, delivery, signal, route-proof, public-safe, or production wording requires separate approval` |
| `HOD-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `preserve hero baseline while successor HO-DET-001 remains the current reviewed source package` |
| `HOX-GAUNTLET-001` | `SOURCE_EXISTS` | `CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | true | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `human review before runtime, signal, customer, production, public wording, or final human gate promotion` |
| `ID-DET-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any separately approved identity runtime gate` |
| `ID-DET-002` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any separately approved identity runtime gate` |
| `ID-DET-003` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any separately approved identity runtime gate` |
| `ID-DET-004` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any separately approved identity runtime gate` |

## Boundary

| Boundary flag | Value |
| --- | --- |
| `runtime_public_proof_claimed` | `false` |
| `signal_public_proof_claimed` | `false` |
| `customer_deployment_claimed` | `false` |
| `production_readiness_claimed` | `false` |
| `public_safe_runtime_proof_claimed` | `false` |
| `ai_approval_claimed` | `false` |
| `analyst_approval_claimed` | `false` |
| `final_authorization_claimed` | `false` |
| `website_rendering_treated_as_proof` | `false` |
| `green_ci_treated_as_approval` | `false` |

## Data Quality Notes

- platform lifetime ledger manifest reports closed_case_count=0
- HOD-001 has controlled validation but no proof record
