from __future__ import annotations

import json
import hashlib
import os
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

CASE_AUTHORITY_COLLECTIONS = (
    ("hawkinsoperations-detections", "detections/DETECTION_PROMOTION_MATRIX.yml", "entries"),
    ("hawkinsoperations-validation", "validation/VALIDATION_REGISTRY.yml", "packages"),
    ("hawkinsoperations-proof", "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml", "entries"),
)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def sanitized_git_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.casefold().startswith("git_")
    }
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    pairs = loader.construct_pairs(node, deep=deep)
    result: dict[Any, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = str(key).casefold()
        if normalized in seen:
            raise ValueError("structured authority source contains a duplicate key")
        seen.add(normalized)
        result[key] = value
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = key.casefold()
        if normalized in seen:
            raise ValueError("structured authority source contains a duplicate key")
        seen.add(normalized)
        result[key] = value
    return result


def resolve_repo_paths(repo_root: Path) -> dict[str, Path | None]:
    root = repo_root.resolve()
    paths: dict[str, Path | None] = {}
    paths[".github"] = root / ".github" if (root / ".github").is_dir() else None
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
            env=sanitized_git_env(),
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    return [line for line in result.stdout.splitlines() if line]


def repo_branch(repo_path: Path) -> str:
    lines = git_lines(repo_path, ["branch", "--show-current"])
    return lines[0] if lines else "UNKNOWN_WITH_REASON: no git branch available"


def _is_volatile_generated_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    return (
        "/__pycache__/" in f"/{normalized}"
        or normalized.endswith(".pyc")
        or normalized.startswith(".hoxline/")
    )


def repo_dirty(repo_path: Path) -> bool:
    return bool(repo_dirty_paths(repo_path))


def repo_dirty_paths(repo_path: Path) -> list[str]:
    paths = [line[3:].strip().replace("\\", "/") for line in git_lines(repo_path, ["status", "--short"]) if len(line) > 3]
    return [path for path in paths if not _is_volatile_generated_path(path)]


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
            env=sanitized_git_env(),
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
            env=sanitized_git_env(),
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def git_blob_identity(repo_path: Path, sha: str, repo_relative_path: str) -> tuple[str, bytes] | None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return None
    normalized_path = repo_relative_path.replace("\\", "/").lstrip("/")
    if (
        not normalized_path
        or normalized_path.startswith("/")
        or "\\" in normalized_path
        or any(part in {"", ".", ".."} for part in normalized_path.split("/"))
    ):
        return None
    blob = git_lines(repo_path, ["rev-parse", f"{sha}:{normalized_path}"])
    if len(blob) != 1 or not re.fullmatch(r"[0-9a-f]{40}", blob[0]):
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "blob", blob[0]],
            check=False,
            capture_output=True,
            env=sanitized_git_env(),
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return blob[0], result.stdout


def semantic_fingerprint(repo_relative_path: str, raw: bytes) -> str:
    suffix = Path(repo_relative_path).suffix.casefold()
    if suffix == ".json":
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    elif suffix in {".yml", ".yaml"}:
        value = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    else:
        canonical = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(canonical).hexdigest()


def repo_origin(repo_path: Path) -> str:
    # Inspect only the value physically stored in this repository. `git remote
    # get-url` applies ambient url.*.insteadOf rewriting and can conceal a
    # non-canonical stored owner.
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "config",
                "--local",
                "--null",
                "--get-all",
                "remote.origin.url",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=sanitized_git_env(),
        )
    except (OSError, subprocess.CalledProcessError):
        return "UNKNOWN"
    values = result.stdout.split("\0")
    if values and values[-1] == "":
        values.pop()
    stripped = [value.strip() for value in values]
    return stripped[0] if len(stripped) == 1 and stripped[0] else "UNKNOWN"


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
        return json.loads(text, object_pairs_hook=_unique_json_object)
    if path.suffix.lower() in {".yml", ".yaml"}:
        return yaml.load(text, Loader=_UniqueKeyLoader)
    raise ValueError(f"unsupported structured file: {path}")


def discover_case_ids(repo_paths: dict[str, Path | None]) -> tuple[set[str], int]:
    ids: set[str] = set()
    scanned = 0
    for repo_name, relative_path, collection_name in CASE_AUTHORITY_COLLECTIONS:
        repo_path = repo_paths.get(repo_name)
        if repo_path is None:
            continue
        path = repo_path / relative_path
        if not path.is_file():
            continue
        scanned += 1
        data = load_structured(path)
        if not isinstance(data, dict) or not isinstance(data.get(collection_name), list):
            continue
        for entry in data[collection_name]:
            if not isinstance(entry, dict):
                continue
            case_id = entry.get("detection_id")
            if isinstance(case_id, str) and CASE_ID_PATTERN.fullmatch(case_id):
                ids.add(case_id)
    return ids, scanned


def last_git_update(repo_path: Path, repo_relative_path: str) -> str | None:
    lines = git_lines(repo_path, ["log", "-1", "--format=%cI", "--", repo_relative_path])
    return lines[0] if lines else None
