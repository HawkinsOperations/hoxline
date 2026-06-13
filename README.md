# Claim Firewall

Claim Firewall is a local CLI and GitHub Action that scans Markdown, YAML, and text files for configured security wording that should not ship without separate evidence or authorization. It reports the file path, line number, matched claim, reason, and suggested ceiling, then exits non-zero when findings are present.

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

Claim Firewall checks wording against configured policy only. It does not prove detection behavior, runtime telemetry, signal observation, production deployment, public-safe status, customer deployment, SOCaaS availability, AI approval, analyst approval, or final human authorization.

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
