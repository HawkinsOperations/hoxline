from __future__ import annotations

from pathlib import Path
import re

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


def test_ci_uses_immutable_sibling_revisions_and_all_required_trust_checks() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    refs = re.findall(r"^\s+ref:\s+([0-9a-f]{40})\s*$", workflow, flags=re.MULTILINE)
    reviewed_refs = {
        "b93fb586fccf80dd40c714281086fe2a940506a7",
        "48de1240a8437432f35aee77654b568704627a68",
        "5840c517bbacf845acdbbcca10c5c09953dbb595",
        "bc489b6c1549288909a6d19cd96f3fa731059ce9",
        "79d4bff2dccb24c2b29a68f4a3be7a1e916414b4",
        "0c16f2a97ae73910633daf6193a51918f26d1798",
    }
    assert len(refs) == 6
    assert set(refs) == reviewed_refs
    assert (
        "HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA: "
        "b93fb586fccf80dd40c714281086fe2a940506a7"
    ) in workflow
    assert "ref: main" not in workflow
    assert "ref: feature/" not in workflow
    assert "persist-credentials: false" in workflow
    assert "permissions:\n  contents: read" in workflow
    for required in (
        "python -B -m unittest discover -s tests",
        "python -B -m pytest",
        "case-growth index",
        "case-growth verify",
        "case-growth diff",
        "review batch run",
        "review batch verify",
        "git diff --check",
    ):
        assert required in workflow
