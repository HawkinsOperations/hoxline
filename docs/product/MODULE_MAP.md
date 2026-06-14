# Module Map

Hoxline is organized around the exact product loop:

AI-assisted security work
→ Artifact Intake
→ Evidence Graph
→ Telemetry Contract Check
→ Controlled Validation
→ Runtime Candidate Ledger
→ Signal Observation
→ Human Review Gate
→ ProofCard
→ Claim Authority
→ Safe Claim / Blocked Claim

## Loop Stage Responsibilities

| Stage | Hoxline responsibility | Primary record |
| --- | --- | --- |
| AI-assisted security work | Identify the submitted work as AI-assisted and require evidence-based promotion. | Artifact record |
| Artifact Intake | Record artifact identity, source, scope, declared claims, and intake status. | Artifact record |
| Evidence Graph | Link artifacts, contracts, validation records, runtime candidates, observations, reviews, ProofCards, and claim decisions. | Evidence graph |
| Telemetry Contract Check | Track whether required telemetry contracts are present, missing, incompatible, or not checked. | Promotion state |
| Controlled Validation | Track whether validation is not started, running, passed, failed, or blocked. | Promotion state |
| Runtime Candidate Ledger | Track candidate runtime records without asserting observation. | Promotion state and evidence graph |
| Signal Observation | Track signal observation status and supporting references. | Promotion state and evidence graph |
| Human Review Gate | Track whether human review is pending, requested changes, approved to continue, or blocked. | Promotion state |
| ProofCard | Track whether a ProofCard exists and what evidence it references. | ProofCard reference |
| Claim Authority | Decide whether claim wording is allowed, constrained, or blocked. | Claim decision |
| Safe Claim / Blocked Claim | Emit the final claim disposition for the loop instance. | Claim decision |

## Internal Modules

* `artifact_intake`: normalizes submitted AI-assisted work.
* `evidence_graph`: stores evidence nodes and edges.
* `promotion`: records loop stage, gate status, and blocking reasons.
* `proofcard`: summarizes evidence state for review.
* `claim_authority`: applies claim rules and emits claim decisions.
* `claim_firewall`: first Claim Authority enforcement capability, implemented as part of `claim_authority`.

Internal modules are not separate repositories.

## Guardrails

No module can override evidence requirements. AI output, generated summaries, draft wording, or suggested claim language are inputs to be checked, not authority.
