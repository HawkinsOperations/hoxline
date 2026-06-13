from __future__ import annotations

from pathlib import Path

from claimfirewall.policy import load_policy
from claimfirewall.scanner import scan_paths


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy" / "blocked_claims.yml"


def test_policy_loads_at_least_ten_blocked_claims() -> None:
    policy = load_policy(POLICY)

    assert len(policy) >= 10


def test_passing_example_has_no_findings() -> None:
    policy = load_policy(POLICY)

    findings = scan_paths([ROOT / "examples" / "pass.md"], policy)

    assert findings == []


def test_readme_and_claim_boundary_have_no_findings() -> None:
    policy = load_policy(POLICY)

    findings = scan_paths([ROOT / "README.md", ROOT / "CLAIM_BOUNDARY.md"], policy)

    assert findings == []


def test_failing_example_reports_blocked_claims() -> None:
    policy = load_policy(POLICY)

    findings = scan_paths([ROOT / "examples" / "fail.md"], policy)

    matched = {finding.matched_claim for finding in findings}
    assert "production-ready" in matched
    assert "runtime-proven" in matched
    assert "public-safe" in matched
    assert "fleet-wide coverage" in matched
    assert all(finding.line_number > 0 for finding in findings)


def test_directory_scan_and_exclude() -> None:
    policy = load_policy(POLICY)

    findings = scan_paths([ROOT], policy, exclude_patterns=["examples/fail.md", "policy/blocked_claims.yml"])

    assert findings == []
