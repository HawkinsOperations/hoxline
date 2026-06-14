from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


@dataclass(frozen=True)
class ClaimRule:
    id: str
    phrase: str
    pattern: re.Pattern[str]
    reason: str
    safer_replacement: str
    required_evidence: tuple[str, ...]
    proof_ceiling: str
    allowed_replacements: tuple[str, ...]
    allowed_context_patterns: tuple[re.Pattern[str], ...]

    def is_allowed_context(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self.allowed_context_patterns)


@dataclass(frozen=True)
class EvidenceStateRule:
    id: str
    label: str
    allowed_phrases: tuple[str, ...]
    proof_ceiling: str
    public_safe: bool = False


@dataclass(frozen=True)
class ClaimAuthorityPolicy:
    version: int
    name: str
    proof_ceiling: str
    public_safe: bool
    blocked_claims: tuple[ClaimRule, ...]
    evidence_states: tuple[EvidenceStateRule, ...]
    proof_ceiling_labels: tuple[str, ...]


def load_claim_authority_policy(policy_path: str | Path) -> ClaimAuthorityPolicy:
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"Claim Authority policy must be a mapping: {path}")
    if data.get("kind") != "claim-authority-policy":
        raise ValueError(f"Not a Claim Authority policy: {path}")

    version = _required_int(data, "version", path)
    name = _required_str(data, "name", path)
    proof_ceiling = _required_str(data, "proof_ceiling", path)
    public_safe = bool(data.get("public_safe", False))

    proof_ceiling_labels = tuple(_required_str_list(data, "proof_ceiling_labels", path))
    if proof_ceiling not in proof_ceiling_labels:
        raise ValueError(f"Policy proof_ceiling must be listed in proof_ceiling_labels: {path}")

    blocked_claims = tuple(_load_claim_rules(data.get("blocked_claims"), path))
    evidence_states = tuple(_load_evidence_states(data.get("evidence_states", []), path))
    if not blocked_claims:
        raise ValueError(f"Claim Authority policy has no blocked_claims entries: {path}")

    return ClaimAuthorityPolicy(
        version=version,
        name=name,
        proof_ceiling=proof_ceiling,
        public_safe=public_safe,
        blocked_claims=blocked_claims,
        evidence_states=evidence_states,
        proof_ceiling_labels=proof_ceiling_labels,
    )


def _load_claim_rules(raw_rules: object, path: Path) -> list[ClaimRule]:
    if not isinstance(raw_rules, list):
        raise ValueError(f"Policy blocked_claims must be a list: {path}")

    rules: list[ClaimRule] = []
    for index, item in enumerate(raw_rules, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Policy blocked_claims entry {index} must be a mapping")
        rule_id = _required_str(item, "id", path, index)
        phrase = _required_str(item, "phrase", path, index)
        pattern = _required_str(item, "pattern", path, index)
        reason = _required_str(item, "reason", path, index)
        safer_replacement = _required_str(item, "safer_replacement", path, index)
        required_evidence = tuple(_required_str_list(item, "required_evidence", path, index))
        proof_ceiling = _required_str(item, "proof_ceiling", path, index)
        allowed_replacements = tuple(_optional_str_list(item, "allowed_replacements", path, index))
        context_patterns = tuple(
            re.compile(context_pattern, re.IGNORECASE)
            for context_pattern in _optional_str_list(item, "allowed_context_patterns", path, index)
        )
        rules.append(
            ClaimRule(
                id=rule_id,
                phrase=phrase,
                pattern=re.compile(pattern, re.IGNORECASE),
                reason=reason,
                safer_replacement=safer_replacement,
                required_evidence=required_evidence,
                proof_ceiling=proof_ceiling,
                allowed_replacements=allowed_replacements,
                allowed_context_patterns=context_patterns,
            )
        )
    return rules


def _load_evidence_states(raw_states: object, path: Path) -> list[EvidenceStateRule]:
    if not isinstance(raw_states, list):
        raise ValueError(f"Policy evidence_states must be a list: {path}")

    states: list[EvidenceStateRule] = []
    for index, item in enumerate(raw_states, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Policy evidence_states entry {index} must be a mapping")
        states.append(
            EvidenceStateRule(
                id=_required_str(item, "id", path, index),
                label=_required_str(item, "label", path, index),
                allowed_phrases=tuple(_optional_str_list(item, "allowed_phrases", path, index)),
                proof_ceiling=_required_str(item, "proof_ceiling", path, index),
                public_safe=bool(item.get("public_safe", False)),
            )
        )
    return states


def _required_int(data: dict[str, object], key: str, path: Path) -> int:
    value = data.get(key)
    if not isinstance(value, int):
        raise ValueError(f"Policy key {key} must be an integer: {path}")
    return value


def _required_str(data: dict[str, object], key: str, path: Path, index: int | None = None) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        location = f" entry {index}" if index is not None else ""
        raise ValueError(f"Policy{location} key {key} must be a non-empty string: {path}")
    return value


def _required_str_list(data: dict[str, object], key: str, path: Path, index: int | None = None) -> list[str]:
    values = _list_value(data, key, path, index)
    if not values:
        location = f" entry {index}" if index is not None else ""
        raise ValueError(f"Policy{location} key {key} must not be empty: {path}")
    return values


def _optional_str_list(data: dict[str, object], key: str, path: Path, index: int | None = None) -> list[str]:
    if key not in data:
        return []
    return _list_value(data, key, path, index)


def _list_value(data: dict[str, object], key: str, path: Path, index: int | None) -> list[str]:
    value = data.get(key)
    location = f" entry {index}" if index is not None else ""
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"Policy{location} key {key} must be a list of non-empty strings: {path}")
    return value
