from __future__ import annotations

from pathlib import Path

from claimfirewall.policy import load_policy
from claimfirewall.scanner import scan_paths


ROOT = Path(__file__).resolve().parents[1]


def test_action_uses_action_path_and_console_script() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")

    assert "${{ github.action_path }}" in action
    assert "claimfirewall scan" in action
    assert "python -m claimfirewall.cli" not in action


def test_no_old_naming_appears_in_repo_files() -> None:
    forbidden = ["claim" + "lint", "Claim" + "lint", "CLAIM" + "LINT"]
    skipped_dirs = {".pytest_cache", "__pycache__", ".git", ".venv"}

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped_dirs or part.endswith(".egg-info") for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not any(token in text for token in forbidden), path


def test_docs_scan_cleanly() -> None:
    policy = load_policy(ROOT / "policy" / "blocked_claims.yml")

    findings = scan_paths([ROOT / "README.md", ROOT / "CLAIM_BOUNDARY.md"], policy)

    assert findings == []
