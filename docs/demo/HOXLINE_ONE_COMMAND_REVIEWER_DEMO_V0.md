# Hoxline One-Command Reviewer Demo v0

Status: REVIEWER_DEMO / LOCAL_FIXTURE_ONLY / NO_PROOF_PROMOTION

Proof ceiling: CONTROLLED_FIXTURE_VALIDATED

public_safe_status: NOT_PUBLIC_SAFE

human_review_required: true

ai_disposition_authority: false

## Purpose

This demo lets a reviewer clone Hoxline, run one command, and see the governed ProofOps loop in about 30 seconds. It uses a bundled synthetic HO-DET-010 fixture for a local Administrators membership-change pattern. It does not create users, change groups, touch endpoints, connect to Wazuh, publish private evidence, or claim live runtime proof.

## Command

```powershell
python -B -m hoxline demo quickstart
```

For repeatable local validation:

```powershell
python -B -m hoxline demo quickstart --output .hoxline/demo-runs/self-test --force
python -B -m hoxline demo verify --input .hoxline/demo-runs/self-test/run-summary.json
```

Expected runtime under normal machine conditions: under 5 seconds after Python dependencies are available.

## Expected Output Files

The command writes `.hoxline/demo-runs/<timestamp-or-demo-id>/` with:

- `intake.json`
- `evidence-graph.json`
- `telemetry-contract-check.json`
- `validation-result.json`
- `synthetic-signal.json`
- `enrichment.json`
- `triage-summary.md`
- `proofcard.json`
- `proofcard.md`
- `claim-authority.json`
- `reviewer-pack.md`
- `run-summary.json`

`.hoxline/` is ignored by git.

## Product Loop Stages

1. Artifact Intake
2. Evidence Graph
3. Telemetry Contract Check
4. Controlled Validation
5. Runtime Candidate / Signal Simulation
6. Enrichment
7. Triage
8. ProofCard
9. Claim Authority
10. Safe Claim / Blocked Claim
11. Reviewer Pack

## Supported Artifact

The demo supports `HO-DET-010` with a synthetic local Administrators membership-change fixture:

- positive fixture: `examples/demo/ho-det-010-safe-fixture.json`
- negative fixture: `examples/demo/ho-det-010-safe-negative-fixture.json`

The telemetry contract represents Windows Security EventChannel assumptions for event IDs `4720`, `4725`, `4726`, `4732`, `4733`, and `4738`, plus Wazuh rule family `910101`, `910102`, and `910103`. The result is pass for fixture only.

## What It Proves

- Hoxline can generate the reviewer path locally from synthetic fixtures approved for public demo use.
- The demo produces structured records for intake, graph linkage, telemetry assumptions, validation, signal simulation, enrichment, triage, ProofCard, Claim Authority, and reviewer packaging.
- Claim Authority allows bounded demo wording and blocks unsupported public claims.

## What It Does Not Prove

- It does not prove live runtime behavior.
- It does not prove public signal observation.
- It does not prove approval for public release status.
- It does not prove production readiness, service deployment, customer rollout, autonomous operation, AI disposition approval, analyst disposition approval, final authorization, or case closure.
- It does not mutate endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, ledgers, or website proof state.

## Claim Ceiling

Allowed demo wording:

> HO-DET-010 has a deterministic local fixture demonstration showing how Hoxline carries an AI-assisted detection artifact through intake, validation, ProofCard, and Claim Authority without claiming live runtime proof.

Blocked claim families include production readiness, public runtime-proof wording, service deployment, customer rollout, autonomous operation, AI disposition approval, analyst disposition approval, final authorization, case closure, website rendering as proof, and green CI as approval.

## 30-Second Reviewer Script

In this demo, an AI-assisted detection artifact enters Hoxline. Hoxline captures it, links evidence, checks telemetry assumptions, validates a safe fixture, simulates a detection signal, enriches the finding, triages it, renders a ProofCard, and blocks unsupported public claims. Evidence decides what can be claimed. AI does not.

## Troubleshooting

- If the command cannot import `hoxline`, run it from the repository root or install the project with `python -m pip install -e ".[test]"`.
- If the output directory already exists, pass `--force` or choose a new `--output` directory.
- If verification fails, inspect `run-summary.json`, `proofcard.json`, `claim-authority.json`, and `reviewer-pack.md` first.
