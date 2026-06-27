from __future__ import annotations

from pathlib import Path

from claimfirewall.claim_authority import ClaimAuthorityReport, evaluate_text, scan_paths

from .policy import load_policy


def evaluate_release_note(text: str, policy_path: str | Path) -> ClaimAuthorityReport:
    return evaluate_text(text, load_policy(policy_path))


def scan_release_note(path: str | Path, policy_path: str | Path) -> ClaimAuthorityReport:
    return scan_paths([Path(path)], load_policy(policy_path))
