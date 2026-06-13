from __future__ import annotations

from pathlib import Path

from claimfirewall.policy import load_policy
from claimfirewall.scanner import scan_paths


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy" / "blocked_claims.yml"


def test_safe_negative_context_examples_pass(tmp_path: Path) -> None:
    sample = tmp_path / "safe.md"
    sample.write_text(
        "\n".join(
            [
                "Claim Firewall does not prove production deployment.",
                "This repository does not claim public-safe status.",
                "No autonomous SOC claim is made.",
                "AI-approved disposition is blocked wording, not an authority this tool grants.",
                "This tool is not runtime-proven by itself.",
            ]
        ),
        encoding="utf-8",
    )

    findings = scan_paths([sample], load_policy(POLICY))

    assert findings == []


def test_unsafe_context_examples_fail(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe.md"
    sample.write_text(
        "\n".join(
            [
                "This is production-ready.",
                "This is runtime-proven.",
                "This output is public-safe.",
                "This is an autonomous SOC.",
                "This provides AI-approved disposition.",
                "This provides analyst-approved disposition.",
                "This proves customer deployment.",
                "SOCaaS available now.",
                "Fleet-wide coverage is provided.",
            ]
        ),
        encoding="utf-8",
    )

    findings = scan_paths([sample], load_policy(POLICY))
    matched = {finding.matched_claim for finding in findings}

    assert matched == {
        "production-ready",
        "runtime-proven",
        "public-safe",
        "autonomous SOC",
        "AI-approved disposition",
        "analyst-approved disposition",
        "customer deployment",
        "SOCaaS available",
        "fleet-wide coverage",
    }
