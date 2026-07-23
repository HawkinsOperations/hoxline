# Hoxline Case Growth Index v1

Generated: `2026-07-23T22:10:35Z`
Proof ceiling: `CASE_GROWTH_INDEX_CONTROLLED_REPO_AGGREGATION_ONLY`
Repo-slot accuracy: `seven expected repo slots evaluated; seven present local repos scanned`
Historical snapshot: `false`
Current authority: `true`
Source manifest digest: `ad6f20c070aee750d8d45ba8682822ae2dcf6d5e6730f411c4721cc5ec86e093`
Reproducibility SHA-256: `3d436b4687568d8e8fd34c84a0ddced7e8f5201f75f1483dd092eab53faae2c4`

## Summary

| Metric | Count |
| --- | ---: |
| `cases_total` | 26 |
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
| `cases_missing_proof_record_count` | 15 |
| `cases_missing_proofcard_count` | 14 |
| `cases_not_public_safe_count` | 26 |
| `unknown_state_count` | 0 |

## Source Revisions

| Repository | Authority role | Authority path | Observed head | Git blob | Semantic fingerprint | Source freshness |
| --- | --- | --- | --- | --- | --- | --- |
| `.github` | `org command-center routing` | `governance/COMMAND_CENTER_INVARIANTS.json` | `6e6763a81d6af09c2e4588462b56117ce82c2f88` | `623e3f9e813b0599618a7df41dee1c9a40fb7a18` | `45cfa989c3f742b546f7f8a497632b43c928029bcaa09e80e04c7c894dba660c` | `CURRENT` |
| `hawkinsoperations-detections` | `detection source truth` | `detections/DETECTION_PROMOTION_MATRIX.yml` | `c2790ab007279faff6130a60dc68818343c255ee` | `e1d040134f139d2598c527c3584e1859e9c9553d` | `7ca1a5d76ed11de08832dbd074d120295d71d5935be3f10ed3d874d0198bf3e3` | `CURRENT` |
| `hawkinsoperations-validation` | `controlled validation truth` | `validation/VALIDATION_REGISTRY.yml` | `ebf52f7c6c9b78de767272cc56fccdc584f5c4e0` | `6fac3ac3d048c3ef687faaf5ebef1b04e846aad1` | `de88ff4a621256cae51ec597a2cbb73f172d16c9d6e5109bcc42ff9a3b461cc3` | `CURRENT` |
| `hawkinsoperations-platform` | `platform contract truth` | `contracts/public-status-source-contract-v1.json` | `651a43a4dfe0776605d5bd7b85ef4f8381c42b64` | `577dd64c65324f45248ce36e4550cba04b9ff056` | `8381676118717c267039bb783a4540544a82e20c3e5df943bfc3eeae05cc5d95` | `CURRENT` |
| `hawkinsoperations-proof` | `proof and claim-boundary truth` | `proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml` | `042a918ad4a8473cd5abcfd575072fc094639682` | `623b93e6e5ac141684978ff4dcdc6ed1dec55678` | `68e5de4749bfe34a6677331f6116fab82987c88e999ae14eaf706e9b33536170` | `CURRENT` |
| `hawkinsoperations-website` | `rendering-only public status contract` | `schemas/public-status-v0.schema.json` | `5856f8e69527b5e61c3953b88a2ad4c088268655` | `1f10e8c0948635eda720905c1f1e7476ef63bf3c` | `5d04c8fbce269352e341798f28afdc29720fd2ea97b80d63884cfdb32e893a11` | `CURRENT` |
| `hoxline` | `case-growth and fixture-review product truth` | `src/hoxline/case_growth/collector.py` | `d2ce9d977e832e327b4bdbfef55f04a4fd7c35e7` | `1eed4c1d3433667670a130278ca8a804e00c5243` | `8eee6ebefd06667c8d4c4814a03fa1b159215d6189a136b9fe74d9bd8702c324` | `CURRENT` |

## Convergence Findings

- No missing, dangling, contradictory, or stale source-owned state detected.

Next legal action: none; current source-controlled inputs converge

## Case Growth Health

| Health metric | Value |
| --- | ---: |
| `validation_coverage_percent` | 85.71 |
| `proof_record_coverage_percent` | 42.31 |
| `proofcard_coverage_percent` | 46.15 |
| `scheduled_collector_coverage_percent` | 15.38 |
| `runtime_candidate_coverage_percent` | 19.23 |
| `metrics_coverage_percent` | 3.85 |
| `public_safe_percent` | 0.0 |
| `closed_case_percent` | 0.0 |
| `blocked_claim_density` | 11.35 |
| `next_gate_coverage_percent` | 100.0 |
| `missing_proof_record_percent` | 57.69 |
| `missing_proofcard_percent` | 53.85 |
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
