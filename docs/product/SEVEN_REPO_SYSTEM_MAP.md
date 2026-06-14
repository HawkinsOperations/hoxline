# Seven-Repo System Map

The HawkinsOperations product system contains exactly seven repositories:

* .github
* hawkinsoperations-detections
* hawkinsoperations-validation
* hawkinsoperations-platform
* hawkinsoperations-proof
* hawkinsoperations-website
* hoxline

No eighth repository is introduced or implied by Hoxline.

Local/package/schema references to `aevumguard` remain compatibility naming until a separate migration is approved. They do not define the current product/front-door identity.

## Repository Roles

| Repository | Role |
| --- | --- |
| `.github` | Organization profile and shared GitHub configuration. |
| `hawkinsoperations-detections` | Detection work and detection artifacts. |
| `hawkinsoperations-validation` | Validation contracts, test harnesses, and validation evidence structures. |
| `hawkinsoperations-platform` | Platform contracts and runtime-adjacent platform structures. |
| `hawkinsoperations-proof` | Proof records, proof documentation, and evidence-facing artifacts. |
| `hawkinsoperations-website` | Public-facing website implementation and presentation surfaces. |
| `hoxline` | Hoxline ProofOps control plane for AI-assisted security work. |

## Hoxline Placement

Hoxline governs the loop:

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

It coordinates state and claim authority across the system without creating side-product repositories. Claim Firewall remains an internal Hoxline capability.
