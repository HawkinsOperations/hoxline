from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml


CASE_ID_PATTERN = re.compile(
    r"\b(?:HO-DET-\d{3}|ID-DET-\d{3}|AWS-DET-\d{3}|HO-NDR-\d{3}|HOX-GAUNTLET-\d{3}|HO-PIPE-\d{3}|HOD-\d{3})\b"
)

REPO_NAMES = (
    ".github",
    "hawkinsoperations-detections",
    "hawkinsoperations-validation",
    "hawkinsoperations-platform",
    "hawkinsoperations-proof",
    "hawkinsoperations-website",
    "hoxline",
)


def resolve_repo_paths(repo_root: Path) -> dict[str, Path | None]:
    root = repo_root.resolve()
    paths: dict[str, Path | None] = {}
    github_candidates = (
        root / ".github",
        root / "HawkinsOperations.github",
        root.parent / "HawkinsOperations.github",
    )
    paths[".github"] = next((path for path in github_candidates if path.exists()), None)
    for name in REPO_NAMES:
        if name == ".github":
            continue
        path = root / name
        paths[name] = path if path.exists() else None
    return paths


def git_lines(repo_path: Path, args: list[str]) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    return [line for line in result.stdout.splitlines() if line]


def repo_branch(repo_path: Path) -> str:
    lines = git_lines(repo_path, ["branch", "--show-current"])
    return lines[0] if lines else "UNKNOWN_WITH_REASON: no git branch available"


def repo_dirty(repo_path: Path) -> bool:
    return bool(git_lines(repo_path, ["status", "--short"]))


def tracked_files(repo_path: Path) -> list[Path]:
    files = git_lines(repo_path, ["ls-files"])
    if files:
        return [repo_path / file_name for file_name in files]
    return [
        path
        for path in repo_path.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
        and path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".avif", ".zip", ".sqlite"}
    ]


def repo_relative(repo_name: str, repo_path: Path, path: Path) -> str:
    try:
        rel = path.resolve().relative_to(repo_path.resolve()).as_posix()
    except ValueError:
        rel = path.as_posix()
    return f"{repo_name}/{rel}"


def load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if path.suffix.lower() in {".yml", ".yaml"}:
        return yaml.safe_load(text)
    raise ValueError(f"unsupported structured file: {path}")


def discover_case_ids(repo_paths: dict[str, Path | None]) -> tuple[set[str], int]:
    ids: set[str] = set()
    scanned = 0
    for repo_path in repo_paths.values():
        if repo_path is None:
            continue
        for path in tracked_files(repo_path):
            scanned += 1
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".avif", ".zip", ".sqlite"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            ids.update(CASE_ID_PATTERN.findall(text))
    return ids, scanned


def last_git_update(repo_path: Path, repo_relative_path: str) -> str | None:
    lines = git_lines(repo_path, ["log", "-1", "--format=%cI", "--", repo_relative_path])
    return lines[0] if lines else None
