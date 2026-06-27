# Case Growth Source Map v0

Proof ceiling: `CASE_GROWTH_INDEX_CONTROLLED_REPO_AGGREGATION_ONLY`

This map defines what each repo can contribute to the Hoxline Case Growth Index v0 and what it cannot prove.

| Repo | Source role | Files and patterns inspected | Can prove | Cannot prove |
| --- | --- | --- | --- | --- |
| `.github` | Organization route/reviewer defaults | `.github/README.md`, workflow and org-default text when present | Org front-door or reviewer route availability | Does not prove detection proof, runtime truth, signal truth, public-safe status, or case closure |
| `hawkinsoperations-detections` | Source package authority | `detections/DETECTION_PROMOTION_MATRIX.yml`, `detections/**/rule.yml`, `status.yml`, `event-mapping.yml`, SPL/XML/source files | Source package status, required source file refs, detection-side blocked claims, source-side next gate | Does not prove controlled validation truth, runtime proof, signal proof, proof ceiling, or public-safe approval |
| `hawkinsoperations-validation` | Controlled validation authority | `validation/VALIDATION_REGISTRY.yml`, `reports/**/validation-result.json`, `reports/**/validation-result.md`, validator and parity scripts, activity ledger | Controlled validation status and validation evidence refs | Does not claim runtime-active public proof, signal-observed public proof, public-safe status, or final authorization |
| `hawkinsoperations-platform` | Platform runtime-candidate and collector contract authority | `contracts/examples/runtime-collector-eligibility-v0.sample.json`, `.github/workflows/hoxline-schedule-gated-collection.yml`, `contracts/lifetime-case-ledger-v1-state-manifest.json`, runtime/receipt contract examples | Private runtime-candidate lanes, scheduled collector lane presence, gated collector scope, ledger count caveats | Does not claim public runtime proof, public signal proof, production readiness, public-safe runtime proof, or case closure unless explicit closed evidence exists |
| `hawkinsoperations-proof` | Proof boundary authority | `proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml`, `proof/records/**`, `proof/cards/**`, claim ceilings and blocked-claim lists | Proof records, ProofCards, proof ceilings, `public_safe` status when explicit, blocked claims, next gates | Does not prove website rendering proof, green CI approval, customer adoption, or production readiness |
| `hawkinsoperations-website` | Presentation route surface | `app/**`, `components/**`, `src/data/**`, `public/data/**`, route/rendering mentions | Route/rendering availability and public presentation mentions | Does not prove any proof status, public-safe status, runtime truth, signal truth, approval, or closure |
| `hoxline` | Product metrics and Hoxline Gauntlet authority | `examples/gauntlet/sample-work-impact-metrics.json`, Hoxline Gauntlet docs, metrics engine, CLI | Product-demo metrics availability, Gauntlet/product case rows, metrics refs | Does not prove runtime proof, signal proof, customer deployment, production readiness, or final authorization |

## Truth Boundary

Data source priority is:

1. Proof repo proof status index for proof ceiling, `public_safe` status, proof records, ProofCards, blocked claims, and next gates.
2. Detections repo for source status and source package evidence.
3. Validation repo for controlled validation status and validation evidence.
4. Platform repo for runtime-candidate status, scheduled collector status, private candidate lanes, and receipt intake gates.
5. Hoxline repo for product metrics availability and Gauntlet/product case metrics.
6. Website repo for route availability only.
7. `.github` repo for org front-door and reviewer route availability only.

Website and org route surfaces never override proof status.

## Known Gaps

Current local generation found 27 cases and 982 scanned source-controlled files. Known gaps are represented directly in the output:

* `cases_missing_proof_record_count`: 23
* `cases_missing_proofcard_count`: 23
* `public_safe_cases_count`: 0
* `closed_cases_count`: 0
* `cases_not_public_safe_count`: 27
* `unknown_state_count`: 1

The index preserves missing and unknown states as `NOT_FOUND`, `NOT_INDEXED`, `NOT_PROVEN`, `NOT_PUBLIC_SAFE`, or `UNKNOWN_WITH_REASON`. It does not invent successful statuses to make rows look complete.

## Safety Notes

The aggregator reads source-controlled public release-safe files from the configured repo roots. It does not read private runtime logs, raw endpoint logs, raw Wazuh alerts, secrets, tokens, credentials, customer data, or private evidence payloads.
