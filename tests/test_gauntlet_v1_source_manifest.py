from __future__ import annotations

import json
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "gauntlet" / "ho-det-001-gauntlet-v1-source-manifest.json"


def test_gauntlet_v1_source_manifest_routes_are_stable() -> None:
    manifest = _json(MANIFEST)

    assert manifest["manifest_id"] == "ho-det-001-gauntlet-v1-source-manifest"
    assert manifest["schema_version"] == "gauntlet-v1-source-manifest"
    assert manifest["detection_id"] == "HO-DET-001"
    assert manifest["artifact_id"] == "HO-DET-001"
    assert manifest["proof_ceiling"] == "CONTROLLED_TEST_VALIDATED"
    assert manifest["public_safe"] is False
    assert manifest["public_safe_status"] == "blocked"
    assert manifest["human_review_required"] is True
    assert manifest["authority_split"]["website_boundary"] == "rendering-only"

    required_blocked = {
        "runtime proven",
        "signal observed",
        "production ready",
        "customer deployed",
        "SOCaaS deployed",
        "public-safe runtime proof",
        "AI approved",
        "analyst approved",
        "final authorization",
        "case closure",
    }
    assert required_blocked <= set(manifest["blocked_claims"])

    commands = manifest["reviewer_commands"]
    assert any("gauntlet verify" in command and "gauntlet-run-v1" in command for command in commands)
    assert any("gauntlet summarize" in command for command in commands)
    assert any("claim-authority decide" in command for command in commands)
    assert any("proofcard render" in command for command in commands)

    for route in _manifest_routes(manifest["canonical_v1_paths"]):
        assert not _is_absolute_or_local(route)
        assert (ROOT / route).is_file(), route

    for value in _all_strings(manifest):
        assert not value.startswith("C:/")
        assert not value.startswith("C:\\")
        assert not value.startswith("file:")


def _manifest_routes(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        routes: list[str] = []
        for child in value.values():
            routes.extend(_manifest_routes(child))
        return routes
    return []


def _is_absolute_or_local(route: str) -> bool:
    return (
        route.startswith("/")
        or "\\" in route
        or ":" in PurePosixPath(route).parts[0]
        or route.startswith("C:")
        or route.startswith("file:")
    )


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        strings: list[str] = []
        for child in value:
            strings.extend(_all_strings(child))
        return strings
    if isinstance(value, dict):
        strings = []
        for child in value.values():
            strings.extend(_all_strings(child))
        return strings
    return []


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
