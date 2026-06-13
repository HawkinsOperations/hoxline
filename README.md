# AevumGuard

ProofOps control for the AI security era.

AevumGuard is the ProofOps control plane for AI-assisted security work.

AevumGuard governs how AI-assisted security work becomes tested, reviewed, blocked, or safe to claim.

Claim Firewall is AevumGuard's first Claim Authority module. It is the wording enforcement edge for configured security claims, providing proof ceiling enforcement before unsupported wording ships. It is not proof authority, and it is not the product identity.

The current `claimfirewall` CLI and GitHub Action scan Markdown, YAML, and text files for configured security wording that should not ship without separate evidence or authorization. They report the file path, line number, matched claim, reason, and suggested ceiling, then exit non-zero when findings are present.

## Module map

- Artifact Intake
- Evidence Graph
- Telemetry Contract Engine
- Validation Ledger
- Promotion Gate
- ProofCard Generator
- AI Work Output Register
- Claim Authority / Claim Firewall

## 30-second use

Install locally:

```powershell
python -m pip install -e .
```

Run passing and failing examples:

```powershell
python -m claimfirewall scan examples/pass.md --policy policy/blocked_claims.yml
python -m claimfirewall scan examples/fail.md --policy policy/blocked_claims.yml
claimfirewall scan examples/pass.md --policy policy/blocked_claims.yml
python -m claimfirewall.cli scan examples/pass.md --policy policy/blocked_claims.yml
```

Use JSON output and excludes:

```powershell
python -m claimfirewall scan . --policy policy/blocked_claims.yml --exclude examples/fail.md --exclude policy/blocked_claims.yml --format json
```

## GitHub Action

```yaml
- uses: HawkinsOperations/claim-firewall@v0.1.0
  with:
    paths: "README.md docs"
    format: "text"
```

If `policy` is not provided, the action uses the bundled policy from the action package. Callers can pass `policy`, `exclude`, and `format` inputs.

Compatibility note: Existing Claim Firewall behavior remains available as AevumGuard's first Claim Authority enforcement capability. Repository rename may require updating GitHub Action references after the GitHub repo settings rename.

## Policy Snippet

```yaml
version: 1
blocked_claims:
  - claim: production-ready
    pattern: '\bproduction-ready\b'
    reason: 'Claims production maturity that this tool does not establish.'
    suggested_ceiling: 'TOOL_FUNCTION_ONLY'
    allowed_context_patterns:
      - '\bdoes not prove\b.*\bproduction\b'
      - '\bdoes not claim\b.*\bproduction\b'
      - '\bnot production-ready\b'
```

`allowed_context_patterns` suppress a finding only when the same line matches the blocked claim and an allowed context pattern for that same claim.

## Proof Boundary

AevumGuard's Claim Firewall module checks wording against configured policy only. It enforces claim ceilings; it does not authorize truth.

It does not prove detection behavior, runtime telemetry, signal observation, production deployment, public-safe status, customer deployment, SOCaaS availability, AI approval, analyst approval, or final human authorization.

Explicit non-claims:

- no runtime proof claim
- no signal observation claim
- no production deployment claim
- no public-safe approval claim
- no SOCaaS availability claim
- no customer deployment claim
- no AI approval claim
- no analyst approval claim

Proof ceiling after local validation: `TOOL_FUNCTION_ONLY`.

This rename and repositioning does not create runtime truth, signal truth, production readiness, SOCaaS availability, or case closure. It does not claim customer deployment, autonomous SOC capability, AI-approved disposition, or analyst-approved disposition.
