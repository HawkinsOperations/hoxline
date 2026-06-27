from __future__ import annotations

from pathlib import Path

from claimfirewall.claim_authority import ClaimAuthorityPolicy, load_claim_authority_policy


def load_policy(path: str | Path) -> ClaimAuthorityPolicy:
    return load_claim_authority_policy(path)
