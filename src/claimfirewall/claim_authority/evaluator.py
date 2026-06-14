from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable

from .policy import ClaimAuthorityPolicy, ClaimRule


SUPPORTED_EXTENSIONS = {".md", ".markdown", ".txt", ".yaml", ".yml"}
DEFAULT_EXCLUDES = (".git/**", ".venv/**", "**/__pycache__/**", ".pytest_cache/**", "*.egg-info/**", "**/*.egg-info/**")


@dataclass(frozen=True)
class SaferSuggestion:
    blocked_claim: str
    suggestion: str
    allowed_replacements: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "blocked_claim": self.blocked_claim,
            "suggestion": self.suggestion,
            "allowed_replacements": list(self.allowed_replacements),
        }


@dataclass(frozen=True)
class BlockedClaimDecision:
    claim_id: str
    phrase: str
    reason: str
    required_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    proof_ceiling: str
    safer_replacement: str
    file_path: str | None = None
    line_number: int | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "claim_id": self.claim_id,
            "phrase": self.phrase,
            "reason": self.reason,
            "required_evidence": list(self.required_evidence),
            "missing_evidence": list(self.missing_evidence),
            "proof_ceiling": self.proof_ceiling,
            "safer_replacement": self.safer_replacement,
        }
        if self.file_path is not None:
            data["file_path"] = self.file_path
        if self.line_number is not None:
            data["line_number"] = self.line_number
        return data


@dataclass(frozen=True)
class ClaimAuthorityReport:
    allowed: bool
    blocked_claims: tuple[BlockedClaimDecision, ...]
    safer_suggestions: tuple[SaferSuggestion, ...]
    required_evidence: tuple[str, ...]
    proof_ceiling: str
    public_safe: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "blocked_claims": [claim.to_dict() for claim in self.blocked_claims],
            "safer_suggestions": [suggestion.to_dict() for suggestion in self.safer_suggestions],
            "required_evidence": list(self.required_evidence),
            "proof_ceiling": self.proof_ceiling,
            "public_safe": self.public_safe,
        }


def evaluate_text(
    text: str,
    policy: ClaimAuthorityPolicy,
    evidence_states: Iterable[str] = (),
    file_path: str | None = None,
    line_number: int | None = None,
) -> ClaimAuthorityReport:
    present_evidence = set(evidence_states)
    blocked: list[BlockedClaimDecision] = []

    for rule in policy.blocked_claims:
        if not rule.pattern.search(text) or rule.is_allowed_context(text):
            continue
        missing = tuple(state for state in rule.required_evidence if state not in present_evidence)
        if missing:
            blocked.append(_blocked_decision(rule, missing, file_path, line_number))

    return _report_from_blocked(policy, blocked)


def scan_paths(
    paths: Iterable[str | Path],
    policy: ClaimAuthorityPolicy,
    evidence_states: Iterable[str] = (),
    exclude_patterns: Iterable[str] = (),
) -> ClaimAuthorityReport:
    blocked: list[BlockedClaimDecision] = []
    for path in _iter_scan_files(paths, exclude_patterns):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                report = evaluate_text(
                    line,
                    policy,
                    evidence_states=evidence_states,
                    file_path=str(path),
                    line_number=line_number,
                )
                blocked.extend(report.blocked_claims)
    return _report_from_blocked(policy, blocked)


def _blocked_decision(
    rule: ClaimRule,
    missing_evidence: tuple[str, ...],
    file_path: str | None,
    line_number: int | None,
) -> BlockedClaimDecision:
    return BlockedClaimDecision(
        claim_id=rule.id,
        phrase=rule.phrase,
        reason=rule.reason,
        required_evidence=rule.required_evidence,
        missing_evidence=missing_evidence,
        proof_ceiling=rule.proof_ceiling,
        safer_replacement=rule.safer_replacement,
        file_path=file_path,
        line_number=line_number,
    )


def _report_from_blocked(policy: ClaimAuthorityPolicy, blocked: list[BlockedClaimDecision]) -> ClaimAuthorityReport:
    required_evidence = tuple(sorted({state for claim in blocked for state in claim.missing_evidence}))
    suggestions = tuple(
        SaferSuggestion(
            blocked_claim=claim.phrase,
            suggestion=claim.safer_replacement,
            allowed_replacements=_allowed_replacements(policy, claim.claim_id),
        )
        for claim in blocked
    )
    return ClaimAuthorityReport(
        allowed=not blocked,
        blocked_claims=tuple(blocked),
        safer_suggestions=suggestions,
        required_evidence=required_evidence,
        proof_ceiling=policy.proof_ceiling,
        public_safe=policy.public_safe,
    )


def _allowed_replacements(policy: ClaimAuthorityPolicy, claim_id: str) -> tuple[str, ...]:
    for rule in policy.blocked_claims:
        if rule.id == claim_id:
            return rule.allowed_replacements
    return ()


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
    if ".git" in parts or ".venv" in parts or "__pycache__" in parts or ".pytest_cache" in parts:
        return True
    if any(part.endswith(".egg-info") for part in path.parts):
        return True
    return any(
        fnmatch(normalized, pattern.replace("\\", "/"))
        or fnmatch(relative, pattern.replace("\\", "/"))
        or fnmatch(name, pattern)
        for pattern in exclude_patterns
    )
