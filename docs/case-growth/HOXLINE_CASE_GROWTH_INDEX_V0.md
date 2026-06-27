# Hoxline Case Growth Index v0

Proof ceiling: `CASE_GROWTH_INDEX_CONTROLLED_REPO_AGGREGATION_ONLY`

The Case Growth Index measures whether the HawkinsOperations / Hoxline seven-repo system is growing reviewable cases, not just producing control-language artifacts. It reads repo-visible source, validation, platform, proof, product metrics, website route, and org route surfaces, then emits numeric JSON and Markdown rows.

It is a repo aggregation product spine. It does not claim runtime proof, signal proof, customer deployment proof, production readiness proof, public-safe runtime proof, autonomous SOC operation, SOCaaS deployment, AI approval, analyst approval, final authorization, or product-market fit proof.

## CLI

```powershell
python -B -m hoxline.cli case-growth index --repo-root C:\Raylee\Repo\HawkinsOperations --format json
python -B -m hoxline.cli case-growth index --repo-root C:\Raylee\Repo\HawkinsOperations --format markdown
python -B -m hoxline.cli case-growth index --repo-root C:\Raylee\Repo\HawkinsOperations --format json --output examples/case-growth/current-case-growth-index.json
python -B -m hoxline.cli case-growth index --repo-root C:\Raylee\Repo\HawkinsOperations --format markdown --output examples/case-growth/current-case-growth-index.md
```

The command prints to stdout unless `--output` is provided. It exits nonzero when the repo root is invalid.

## Required Output Fields

Each row includes `case_id`, `detection_id`, `case_kind`, source, validation, runtime-candidate, scheduled-collector, signal, proof-record, ProofCard, Claim Authority, blocked-claim, `public_safe`, case-state, metrics, last-updated, next-gate, evidence-confidence, and notes fields.

The summary includes numeric counts for total cases, source packages, controlled validations, runtime-candidate lanes, private runtime evidence captured, scheduled collector lanes, proof records, ProofCards, Claim Authority cases, metrics availability, `public_safe` cases, closed cases, blocked claims, missing proof records, missing ProofCards, `NOT_PUBLIC_SAFE` cases, next-gate cases, and unknown-state cases.

## Current Summary

Generated from `examples/case-growth/current-case-growth-index.json`.

| Metric | Count |
| --- | ---: |
| `cases_total` | 27 |
| `source_packages_count` | 14 |
| `controlled_validations_count` | 12 |
| `runtime_candidate_lanes_count` | 5 |
| `private_runtime_evidence_captured_count` | 1 |
| `scheduled_collector_lanes_count` | 4 |
| `proof_records_count` | 4 |
| `proofcards_count` | 4 |
| `claim_authority_cases_count` | 26 |
| `metrics_available_count` | 1 |
| `public_safe_cases_count` | 0 |
| `closed_cases_count` | 0 |
| `blocked_claims_count` | 243 |
| `cases_with_next_gate_count` | 26 |
| `cases_missing_proof_record_count` | 23 |
| `cases_missing_proofcard_count` | 23 |
| `cases_not_public_safe_count` | 27 |
| `unknown_state_count` | 1 |

## Case Table

| case_id | source | validation | runtime_candidate | scheduled | proof | proofcard | metrics | public_safe | case_state | next_gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `AWS-DET-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `separate proof scope before any live-cloud or public route approval` |
| `HO-DET-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `NOT_INDEXED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `proof-record-specific human review before any public wording, runtime, or signal promotion` |
| `HO-DET-009` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `platform fixture support and separately approved runtime receipt only after cleanup gates pass` |
| `HO-DET-010` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `reviewer validates source and controlled-test validation before any private runtime gate` |
| `HO-DET-011` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_EVIDENCE_CAPTURED` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `PROOF_RECORD_EXISTS` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `proof-card or public reviewer route only after separate human-approved proof scope` |
| `HO-DET-012` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `PRIVATE_RUNTIME_CANDIDATE` | `SCHEDULED_COLLECTOR_LANE_PRESENT_GATED` | `PROOF_RECORD_EXISTS` | `PROOFCARD_EXISTS` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `blocked until separate runtime or signal evidence review supports any runtime, routed-telemetry, public wording, production, autonomous SOC, or disposition-authority promotion` |
| `HOX-GAUNTLET-001` | `SOURCE_EXISTS` | `CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY` | `NOT_INDEXED` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | true | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `human review before runtime, signal, customer, production, public wording, or final human gate promotion` |
| `ID-DET-001` | `SOURCE_EXISTS` | `CONTROLLED_TEST_VALIDATED` | `NOT_PROVEN` | `NOT_INDEXED` | `NOT_PROVEN` | `NOT_PROVEN` | false | `NOT_PUBLIC_SAFE` | `BLOCKED_WAITING_NEXT_GATE` | `proof record creation under separate proof scope` |

The full table is generated in `examples/case-growth/current-case-growth-index.md`.

## What The Numbers Prove

The numbers prove repo-visible case growth by lane: source packages, controlled validations, private runtime-candidate lanes, scheduled collector lanes, proof records, ProofCards, Claim Authority blocked-claim coverage, metrics availability, `public_safe` status, closed-case status, and next gates.

## What The Numbers Do Not Prove

The index does not claim runtime-active public proof, signal-observed public proof, customer deployment, production readiness, autonomous SOC, SOCaaS deployment, public-safe runtime proof, AI approval, analyst approval, final human authorization, case closure without explicit closed evidence, product-market fit, or customer adoption.

Website rendering and org route presence are route surfaces only. They never override proof status.

## Screenshot-Ready View

Use `examples/case-growth/current-case-growth-index.md` for screenshot-ready tables. The first screen should show the summary counts and the first case rows with `public_safe_cases_count: 0` and `closed_cases_count: 0` visible.

## Next Gates

The generated rows carry per-case `next_gate` values. Current recurring gates are proof-record creation for validated cases without proof records, ProofCard creation for proof-record cases missing ProofCards, runtime/signal review before public wording, and human review before any `public_safe` or closed-case promotion.

## Public Safety Caveats

`public_safe_cases_count` is `0`. `cases_not_public_safe_count` is `27`. The index does not claim public-safe status unless a row has explicit `PUBLIC_SAFE` evidence from authority surfaces. No website-rendered page, green CI state, route, fixture, private candidate, or metrics artifact can promote `public_safe` status.
