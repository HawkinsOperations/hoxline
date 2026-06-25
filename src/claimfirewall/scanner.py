from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable

from .policy import BlockedClaim


SUPPORTED_EXTENSIONS = {".md", ".markdown", ".txt", ".yaml", ".yml"}
DEFAULT_EXCLUDES = (".git/**", ".venv/**", ".hoxline/**", "**/__pycache__/**", ".pytest_cache/**", "*.egg-info/**", "**/*.egg-info/**")
SAFE_CANDIDATE_REVIEW_CONTEXTS = (
    "public-safe candidate review",
    "public-safe candidate-review",
    "PUBLIC_SAFE_CANDIDATE_REVIEW_V1",
    "NOT_PUBLIC_SAFE",
)


@dataclass(frozen=True)
class Finding:
    file_path: Path
    line_number: int
    matched_claim: str
    reason: str
    suggested_ceiling: str

    def to_dict(self) -> dict[str, object]:
        return {
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "matched_claim": self.matched_claim,
            "reason": self.reason,
            "suggested_ceiling": self.suggested_ceiling,
        }


def scan_paths(
    paths: Iterable[str | Path],
    policy: list[BlockedClaim],
    exclude_patterns: Iterable[str] = (),
) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_scan_files(paths, exclude_patterns):
        findings.extend(scan_file(path, policy))
    return findings


def scan_file(path: str | Path, policy: list[BlockedClaim]) -> list[Finding]:
    file_path = Path(path)
    findings: list[Finding] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            for blocked in policy:
                if blocked.pattern.search(line) and not blocked.is_allowed_context(line) and not _is_candidate_review_context(line):
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line_number=line_number,
                            matched_claim=blocked.claim,
                            reason=blocked.reason,
                            suggested_ceiling=blocked.suggested_ceiling,
                        )
                    )
    return findings


def _is_candidate_review_context(line: str) -> bool:
    lowered = line.lower()
    return any(context.lower() in lowered for context in SAFE_CANDIDATE_REVIEW_CONTEXTS)


def _iter_scan_files(paths: Iterable[str | Path], exclude_patterns: Iterable[str]) -> Iterable[Path]:
    excludes = tuple(DEFAULT_EXCLUDES) + tuple(exclude_patterns)
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file():
            if _is_supported(path) and not _is_excluded(path, excludes):
                yield path
            continue

        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and _is_supported(child) and not _is_excluded(child, excludes):
                    yield child
            continue

        raise FileNotFoundError(f"Scan path not found: {path}")


def _is_supported(path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def _is_excluded(path: Path, exclude_patterns: Iterable[str]) -> bool:
    normalized = path.as_posix()
    try:
        relative = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        relative = normalized
    name = path.name
    parts = set(path.parts)
    if ".git" in parts or ".venv" in parts or ".hoxline" in parts or "__pycache__" in parts or ".pytest_cache" in parts:
        return True
    if any(part.endswith(".egg-info") for part in path.parts):
        return True
    return any(
        fnmatch(normalized, pattern.replace("\\", "/"))
        or fnmatch(relative, pattern.replace("\\", "/"))
        or fnmatch(name, pattern)
        for pattern in exclude_patterns
    )
