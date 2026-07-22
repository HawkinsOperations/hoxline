from __future__ import annotations

import json
import hashlib
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


def repo_dirty_paths(repo_path: Path) -> list[str]:
    return [line[3:].strip().replace("\\", "/") for line in git_lines(repo_path, ["status", "--short"]) if len(line) > 3]


def repo_head_sha(repo_path: Path) -> str:
    lines = git_lines(repo_path, ["rev-parse", "HEAD"])
    return lines[0] if lines and re.fullmatch(r"[0-9a-f]{40}", lines[0]) else "UNKNOWN"


def repo_parent_sha(repo_path: Path) -> str:
    lines = git_lines(repo_path, ["rev-parse", "HEAD^"])
    return lines[0] if lines and re.fullmatch(r"[0-9a-f]{40}", lines[0]) else "UNKNOWN"


def git_commit_exists(repo_path: Path, sha: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return False
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", f"{sha}^{{commit}}"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0


def git_blob_sha256(repo_path: Path, sha: str, repo_relative_path: str) -> str | None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return None
    normalized_path = repo_relative_path.replace("\\", "/").lstrip("/")
    if not normalized_path or ".." in Path(normalized_path).parts:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "show", f"{sha}:{normalized_path}"],
            check=False,
            capture_output=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


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


def case_growth_files(repo_name: str, repo_path: Path) -> list[Path]:
    return [path for path in tracked_files(repo_path) if not _excluded_case_growth_file(repo_name, repo_path, path)]


def _excluded_case_growth_file(repo_name: str, repo_path: Path, path: Path) -> bool:
    if repo_name != "hoxline":
        return False
    try:
        rel_parts = path.resolve().relative_to(repo_path.resolve()).parts
    except ValueError:
        return False
    if rel_parts[:1] == ("tests",):
        return True
    if rel_parts[:2] in {("docs", "case-growth"), ("examples", "case-growth")}:
        return True
    return False


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
    for repo_name, repo_path in repo_paths.items():
        if repo_path is None:
            continue
        for path in case_growth_files(repo_name, repo_path):
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
