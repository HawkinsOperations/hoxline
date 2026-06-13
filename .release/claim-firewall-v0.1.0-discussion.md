# AevumGuard v0.1.0: Claim Authority enforcement

ProofOps control for the AI security era.

AevumGuard is the ProofOps control plane for AI-assisted security work.

AevumGuard governs how AI-assisted security work becomes tested, reviewed, blocked, or safe to claim.

Claim Firewall is AevumGuard's first Claim Authority module. It is the wording enforcement edge for configured security claims and proof ceiling enforcement. It is not proof authority, and it is not the product identity.

Current repo reference: `HawkinsOperations/claim-firewall`
Future repo target: `HawkinsOperations/aevumguard`
Proof ceiling: `TOOL_FUNCTION_ONLY`

## What it does

AevumGuard's Claim Firewall module scans security docs, PR text, README files, YAML files, and public-facing Markdown for unsupported security claims.

It reports:

* file path
* line number
* matched claim
* reason
* suggested ceiling

It exits non-zero when configured blocked wording is found.

## Who it is for

AevumGuard Claim Authority enforcement is built for:

* detection engineers
* SOC automation builders
* security content maintainers
* open-source security reviewers
* teams using AI-assisted security documentation
* anyone who needs public security wording to stay behind the evidence boundary

## Why this exists

AI-assisted security work makes it easier to generate detection docs, PR text, case notes, README updates, and public summaries quickly.

That speed creates a predictable failure mode:

> Security claims can publish faster than evidence can authorize them.

AevumGuard uses Claim Firewall to catch that failure mode before unsupported wording becomes public truth.

## Example policy areas

AevumGuard's Claim Firewall module can flag configured wording around:

* maturity claims
* runtime proof
* public release safety
* signal observation
* automated operations claims
* AI approval language
* analyst approval language
* customer rollout evidence
* service availability
* coverage breadth

It can also suppress safe negative-context wording when policy allows it.

## How it fits HawkinsOperations

Claim Firewall is the first Claim Authority enforcement capability inside AevumGuard.

It is not the full product identity.

AevumGuard's planned module map is:

* Artifact Intake
* Evidence Graph
* Telemetry Contract Engine
* Validation Ledger
* Promotion Gate
* ProofCard Generator
* AI Work Output Register
* Claim Authority / Claim Firewall

Claim Firewall supports claim hygiene and claim blocking, but it does not approve claims.

Compatibility note: Existing Claim Firewall behavior remains available as AevumGuard's first Claim Authority enforcement capability. Repository rename may require updating GitHub Action references after the GitHub repo settings rename.

## What it does not prove

AevumGuard's Claim Firewall module does not prove:

* detection behavior
* runtime telemetry
* signal observation
* production deployment
* public release safety
* customer rollout
* service availability
* AI approval
* analyst approval
* final human authorization

The tool checks wording policy. Evidence and review still decide truth.

## Release validation

Before release, the release-candidate gate passed:

* 16 tests passed
* passing example exited 0
* failing example exited 1 with expected blocked-wording findings
* README and claim-boundary docs scanned clean
* repository scan passed with expected exclusions
* JSON output was valid
* stale old-name references were removed
* generated caches and install metadata were cleaned
* GitHub CI passed on main

## Why this matters

A detection rule existing is not proof that it works.

A passing test is not proof of operational coverage.

A rendered website is not proof authority.

An AI-generated summary is not a security disposition.

AevumGuard includes Claim Firewall because security claims should compile before they ship.
