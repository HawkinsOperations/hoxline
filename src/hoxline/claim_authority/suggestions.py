from __future__ import annotations

from claimfirewall.claim_authority.evaluator import ClaimAuthorityReport


def safer_suggestions(report: ClaimAuthorityReport) -> list[str]:
    return [suggestion.suggestion for suggestion in report.safer_suggestions]
