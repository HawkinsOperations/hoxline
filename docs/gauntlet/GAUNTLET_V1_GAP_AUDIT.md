# Hoxline Gauntlet v1 Gap Audit

Date: 2026-06-17

## Existing Coverage

* Artifact intake: present in v0 loop output as a stage, but not as a standalone v1 intake record.
* Evidence graph: v0 schema and HO-DET-001 example exist.
* Telemetry contract: represented in v0 loop/evidence graph, but not as a standalone contract schema/example.
* Controlled validation: represented in v0 loop, ProofCard, and demo manifest references.
* Runtime candidate ledger: represented as blocked/unobserved v0 state.
* Signal observation: represented as missing-evidence v0 state.
* Human review gate: represented as required/pending v0 state.
* ProofCard: v0 example exists; v0 schema file is empty.
* Claim Authority: text-policy Claim Firewall exists; structured evidence-state decision logic is shallow.
* Safe/blocked claim output: v0 output includes allowed and blocked claims.
* CLI verifier: v0 `python -B -m hoxline gauntlet verify` exists.
* Tests: v0 gauntlet and Claim Authority tests exist.

## Highest-Impact v1 Work

Add Gauntlet v1 records and schemas for the full product loop, harden Claim Authority against structured evidence state, add reviewer CLI commands for verify/summarize/decide/render, and add tests that prove allowed controlled-validation wording while blocking stronger runtime, signal, production, customer, service, public-release, approval, authorization, and disposition wording.
