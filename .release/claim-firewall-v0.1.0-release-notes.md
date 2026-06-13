# AevumGuard v0.1.0: Claim Authority wording enforcement

ProofOps control for the AI security era.

AevumGuard is the ProofOps control plane for AI-assisted security work.

AevumGuard governs how AI-assisted security work becomes tested, reviewed, blocked, or safe to claim.

Claim Firewall is AevumGuard's first Claim Authority module. It is the wording enforcement edge for configured security claims and proof ceiling enforcement. It is not proof authority, and it is not the product identity.

The v0.1.0 behavior scans security docs, PR text, README files, YAML files, and public-facing Markdown for unsupported security claims before they ship.

## What this release includes

* Python CLI: `claimfirewall`
* Composite GitHub Action
* Configurable blocked-claims policy
* Text and JSON output
* File and directory scanning
* Repeated `--exclude` support
* Safe-context suppression with `allowed_context_patterns`
* Tests for unsafe claims, safe negative-context wording, CLI behavior, JSON output, directory scanning, and action contract behavior

## Install locally

```powershell
python -m pip install -e ".[test]"
```

## CLI examples

Passing example:

```powershell
python -m claimfirewall scan examples/pass.md --policy policy/blocked_claims.yml
```

Failing example:

```powershell
python -m claimfirewall scan examples/fail.md --policy policy/blocked_claims.yml
```

Console script:

```powershell
claimfirewall scan examples/pass.md --policy policy/blocked_claims.yml
```

JSON output:

```powershell
python -m claimfirewall scan examples/fail.md --policy policy/blocked_claims.yml --format json
```

## GitHub Action example

```yaml
name: AevumGuard Claim Authority

on:
  pull_request:
  push:

jobs:
  claim-authority:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HawkinsOperations/claim-firewall@v0.1.0
        with:
          paths: "."
          format: "text"
          exclude: "examples/fail.md policy/blocked_claims.yml"
```

Compatibility note: Existing Claim Firewall behavior remains available as AevumGuard's first Claim Authority enforcement capability. Repository rename may require updating GitHub Action references after the GitHub repo settings rename.

## Example blocked areas

AevumGuard's Claim Firewall module can flag configured wording around:

* maturity claims
* runtime proof claims
* public release safety claims
* signal observation claims
* autonomous operations claims
* AI approval wording
* analyst approval wording
* deployment evidence claims
* service availability claims
* broad coverage claims

Policy exceptions can suppress safe negative-context wording when the text clearly stays below the claim ceiling.

## Validation status

Before release, the local release-candidate gate passed:

* `python -m pytest`: 16 passed
* Passing example scan: exit 0
* Failing example scan: exit 1 with expected blocked-claim findings
* README and claim-boundary scan: exit 0
* Repository scan with expected exclusions: exit 0
* JSON output scan: valid JSON with findings
* Console script pass scan: exit 0
* Old-name search: no stale naming references

## Proof boundary

AevumGuard's Claim Firewall module checks wording against configured policy only.

It does not prove detection behavior, runtime telemetry, signal observation, production deployment, public-safe status, SOCaaS availability, AI approval, analyst approval, or final human authorization.

It does not prove customer deployment evidence.

## Proof ceiling

`TOOL_FUNCTION_ONLY`

This release proves only that AevumGuard includes a tested Claim Firewall utility for scanning configured wording-policy violations.

It does not create HawkinsOperations proof authority, runtime proof, signal proof, production proof, SOCaaS availability, AI approval authority, analyst approval authority, or final human authorization.

It does not prove public release safety approval or customer deployment evidence.
