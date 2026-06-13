from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


@dataclass(frozen=True)
class BlockedClaim:
    claim: str
    pattern: re.Pattern[str]
    reason: str
    suggested_ceiling: str
    allowed_context_patterns: tuple[re.Pattern[str], ...] = ()

    def is_allowed_context(self, line: str) -> bool:
        return any(pattern.search(line) for pattern in self.allowed_context_patterns)


def load_policy(policy_path: str | Path) -> list[BlockedClaim]:
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"Policy must be a mapping: {path}")

    claims = data.get("blocked_claims", [])
    if not isinstance(claims, list):
        raise ValueError(f"Policy blocked_claims must be a list: {path}")
    if not claims:
        raise ValueError(f"Policy has no blocked_claims entries: {path}")

    blocked: list[BlockedClaim] = []
    for index, item in enumerate(claims, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Policy entry {index} must be a mapping")
        try:
            claim = item["claim"]
            pattern = item["pattern"]
            reason = item["reason"]
            suggested_ceiling = item["suggested_ceiling"]
        except KeyError as exc:
            raise ValueError(f"Policy entry {index} missing required key: {exc.args[0]}") from exc

        blocked.append(
            BlockedClaim(
                claim=claim,
                pattern=re.compile(pattern, re.IGNORECASE),
                reason=reason,
                suggested_ceiling=suggested_ceiling,
                allowed_context_patterns=tuple(
                    re.compile(context_pattern, re.IGNORECASE)
                    for context_pattern in item.get("allowed_context_patterns", [])
                ),
            )
        )

    return blocked
