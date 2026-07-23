from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from .case_growth.collector import verify_selected_source_checkout
from .demo import (
    BLOCKED_CLAIM_FAMILIES,
    PRODUCT,
    PUBLIC_SAFE_STATUS,
    REQUIRED_EVENT_IDS,
    REQUIRED_WAZUH_RULE_FAMILY,
    SAFE_ALLOWED_CLAIM,
)

ENGINE_VERSION = "hoxline-review-engine-v1"
BATCH_ENGINE_VERSION = "hoxline-review-batch-engine-v1"
MANIFEST_VERSION = "artifact-manifest-v1"
MACHINE_STATE_VERSION = "review-machine-state-v1"
BATCH_INDEX_VERSION = "multi-artifact-review-index-v1"
BATCH_MACHINE_STATE_VERSION = "batch-machine-state-v1"
ARTIFACT_ID = "HO-DET-010"
ARTIFACT_ID_PATTERN = re.compile(r"^(?:HO-DET|HO-NDR|ID-DET|AWS-DET)-\d{3}$")
EXPECTED_PASS_OUTPUTS = [
    "artifact-manifest.json",
    "intake.json",
    "evidence-graph.json",
    "telemetry-contract-check.json",
    "validation-result.json",
    "synthetic-signal.json",
    "enrichment.json",
    "triage-summary.md",
    "proofcard.json",
    "proofcard.md",
    "claim-authority.json",
    "reviewer-pack.md",
    "machine-state.json",
    "run-summary.json",
]
EXPECTED_BLOCKED_OUTPUTS = ["artifact-manifest.json", "machine-state.json", "blocked-review.md", "run-summary.json"]
BATCH_EXPECTED_OUTPUTS = [
    "input-index.json",
    "batch-machine-state.json",
    "batch-summary.md",
    "batch-reviewer-pack.md",
    "batch-run-summary.json",
]
STAGE_REGISTRY = [
    "artifact_intake",
    "evidence_graph",
    "telemetry_contract_check",
    "controlled_validation",
    "synthetic_signal",
    "enrichment",
    "triage",
    "proofcard",
    "claim_authority",
    "reviewer_pack",
    "machine_state",
]
REQUIRED_MANIFEST_FIELDS = [
    "manifest_version",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_family",
    "source_owner",
    "validation_owner",
    "platform_owner",
    "proof_owner",
    "product_owner",
    "telemetry_contract",
    "fixture_paths",
    "expected_event_ids",
    "expected_rule_ids",
    "allowed_claim_class",
    "requested_claims",
    "blocked_claim_classes",
    "public_safe_status",
    "human_review_required",
    "ai_disposition_authority",
    "proof_boundary",
    "runtime_boundary",
    "signal_boundary",
    "next_gate",
]
PROHIBITED_CLAIM_PATTERNS = {
    "public-safe runtime proof": re.compile(r"public[- ]safe runtime proof", re.IGNORECASE),
    "public-safe promotion": re.compile(
        r"\bpublic[-_ ]safe(?:[-_ ](?:approved|promotion|promoted|proof|status|true))\b",
        re.IGNORECASE,
    ),
    "runtime promotion": re.compile(r"\bruntime[-_ ]active\b", re.IGNORECASE),
    "signal promotion": re.compile(r"\bsignal[-_ ]observed\b|\bsignal[-_ ]proof\b", re.IGNORECASE),
    "production": re.compile(r"\bproduction(?:[- ]ready| readiness)?\b", re.IGNORECASE),
    "customer deployment": re.compile(r"\bcustomer(?:[- ]deployed| deployment)?\b", re.IGNORECASE),
    "SOCaaS deployment": re.compile(r"\bSOCaaS(?:[- ]ready| deployed| deployment)?\b", re.IGNORECASE),
    "autonomous SOC": re.compile(r"\bautonomous SOC\b", re.IGNORECASE),
    "AI-approved disposition": re.compile(r"\bAI[-_ ]approved\b", re.IGNORECASE),
    "analyst-approved disposition": re.compile(r"\banalyst[-_ ]approved\b", re.IGNORECASE),
    "final authorization": re.compile(r"\bfinal[-_ ]authorization\b", re.IGNORECASE),
    "case closure": re.compile(r"\bcase[-_ ]closure\b|\bcase[-_ ]closed\b", re.IGNORECASE),
    "live cloud claim": re.compile(r"\blive (?:AWS|cloud)(?: runtime| proof| signal)?\b", re.IGNORECASE),
    "live identity runtime claim": re.compile(r"\blive (?:IdP|identity)(?: runtime| proof| signal)?\b", re.IGNORECASE),
    "live Security Onion proof": re.compile(r"\blive Security Onion(?: proof| signal| runtime)?\b", re.IGNORECASE),
}
PRIVATE_FIELD_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"private[_-]?evidence",
        r"raw[_-]?(?:wazuh|alert)",
        r"endpoint[_-]?log",
        r"generated[_-]?password",
        r"private[_-]?execution[_-]?id",
        r"private[_-]?packet",
        r"private[_-]?payload",
        r"\bsecret\b",
        r"\btoken\b",
        r"\bpassword\b",
    )
]
PRIVATE_VALUE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bVM108\b",
        r"\bVM9000\b",
        r"\bho-wazuh-0[12]\b",
        r"\braw Wazuh\b",
        r"\braw alert\b",
        r"\bendpoint log\b",
        r"\bgenerated password\b",
        r"\bprivate execution ID\b",
    )
]
ABSOLUTE_LOCAL_PATH = re.compile(
    r"(?i)(?:[A-Z]:[\\/]|(?<![\\/:])\\{2,}[^\\/\s]+[\\/]"
    r"|(?<![\\/:])//[^/\s]+/|(?<![A-Za-z0-9_./:-])/(?!/)[^\s\"'<>]+)"
)
CANONICAL_ORIGINS = {
    "hawkinsoperations-detections": "https://github.com/HawkinsOperations/hawkinsoperations-detections",
    "hawkinsoperations-validation": "https://github.com/HawkinsOperations/hawkinsoperations-validation",
}
MANIFEST_ALLOWED_FIELDS = set(REQUIRED_MANIFEST_FIELDS) | {
    "additional_telemetry_sources",
    "attack_mapping",
    "confidence",
    "detection_family",
    "endpoint_mutation",
    "expected_block_reason",
    "expected_event_keys",
    "expected_review_outcome",
    "field_mapping",
    "lifetime_ledger_changed",
    "public_proof_promoted",
    "runtime_proof",
    "severity",
    "triage_what_happened",
    "triage_why_it_matters",
    "wazuh_mutation",
}
TELEMETRY_CONTRACT_ALLOWED_FIELDS = {
    "event_ids",
    "event_key_field",
    "event_keys",
    "required_fields",
    "scope",
    "source",
    "source_control_note",
    "wazuh_rule_ids",
}
BATCH_INDEX_ALLOWED_FIELDS = {
    "index_version",
    "index_id",
    "description",
    "artifacts",
    "expected_pass_artifacts",
    "expected_blocked_artifacts",
    "batch_claim_boundary",
    "public_safe_status",
    "human_review_required",
    "ai_disposition_authority",
    "runtime_boundary",
    "signal_boundary",
    "proof_boundary",
    "generated_outputs",
    "next_gate",
}
FIXTURE_ALLOWED_FIELDS = {
    "artifact_id",
    "endpoint_mutation",
    "description",
    "events",
    "expected_detection",
    "fixture_id",
    "fixture_kind",
    "host",
    "network_required",
    "runtime_required",
    "safe_fixture",
    "schema_version",
}
SECURITY_FALSE_FIELDS = {
    "ai_disposition_authority",
    "analyst_disposition_authority",
    "analyst_approval",
    "case_closed",
    "case_closure",
    "endpoint_mutation",
    "final_authorization",
    "lifetime_ledger_changed",
    "private_evidence_committed",
    "public_proof_promoted",
    "public_safe",
    "runtime_active",
    "runtime_proof",
    "signal_observed",
    "wazuh_mutation",
}
SECURITY_FALSE_KEY_TOKENS = {
    re.sub(r"[^a-z0-9]", "", value.casefold()) for value in SECURITY_FALSE_FIELDS
} | {
    "aiapproved",
    "aiapproval",
    "analystapproved",
    "approvedbyanalyst",
    "caseclosureapproved",
    "finalapproved",
    "publicsafeapproved",
}
SECURITY_FIXED_FIELDS: dict[str, Any] = {
    "public_safe_status": PUBLIC_SAFE_STATUS,
    "human_review_required": True,
    "ai_disposition_authority": False,
}
REVIEW_OUTPUT_SECURITY_FIELDS: dict[str, Any] = {
    **SECURITY_FIXED_FIELDS,
    "endpoint_mutation": False,
    "wazuh_mutation": False,
    "runtime_proof": False,
    "public_proof_promoted": False,
    "lifetime_ledger_changed": False,
    "private_evidence_committed": False,
}
_AUTHORITY_BINDING_CACHE: dict[tuple[str, ...], dict[str, Any]] = {}


class ReviewEngineError(ValueError):
    """Raised when review engine input or output fails closed."""


class ReviewBlocked(ReviewEngineError):
    """Raised for governed BLOCKED review outcomes."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects exact and case-folded duplicate keys."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    pairs = loader.construct_pairs(node, deep=deep)
    result: dict[Any, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = str(key).casefold()
        if normalized in seen:
            raise ReviewBlocked("structured input contains a duplicate key")
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
            raise ReviewBlocked("structured input contains a duplicate key")
        seen.add(normalized)
        result[key] = value
    return result


def _require_exact_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ReviewBlocked(f"{label} contains unsupported fields")


def _normalize_security_key(value: Any) -> str:
    decoded = _decoded_text_variants(str(value))[-1]
    return re.sub(r"[^a-z0-9]", "", decoded.casefold())


def _decoded_text_variants(value: str) -> list[str]:
    variants = [value]
    current = value
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    compact = value.strip()
    if len(compact) >= 8 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            padded = compact + "=" * ((4 - len(compact) % 4) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            decoded = decoded_bytes.decode("utf-8")
            if decoded and decoded not in variants and all(char.isprintable() or char.isspace() for char in decoded):
                variants.append(decoded)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    return variants


def _string_has_unsafe_claim(value: str) -> bool:
    for candidate in _decoded_text_variants(value):
        if any(pattern.search(candidate) for pattern in PROHIBITED_CLAIM_PATTERNS.values()):
            return True
        stripped = candidate.strip()
        if stripped.startswith(("{", "[")):
            try:
                nested = json.loads(stripped, object_pairs_hook=_unique_json_object)
            except (json.JSONDecodeError, ReviewEngineError):
                continue
            try:
                _validate_recursive_boundaries(nested, "encoded structured value")
            except ReviewBlocked:
                return True
    return False


def _validate_recursive_boundaries(value: Any, label: str, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            normalized_key = _normalize_security_key(key)
            if normalized_key in SECURITY_FALSE_KEY_TOKENS and item not in (False, None, 0, "", [], {}):
                raise ReviewBlocked(f"{label} contains prohibited authority promotion")
            for canonical, expected in SECURITY_FIXED_FIELDS.items():
                if normalized_key == _normalize_security_key(canonical) and item != expected:
                    raise ReviewBlocked(f"{label} violates a fixed authority boundary")
            _validate_recursive_boundaries(item, label, key_path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_recursive_boundaries(item, label, f"{path}[{index}]")
        return
    if isinstance(value, str):
        _validate_declared_string(value, label)
        if _string_has_unsafe_claim(value):
            raise ReviewBlocked(f"{label} contains an unsupported claim")


def _validate_declared_string(value: str, label: str) -> None:
    for candidate in _decoded_text_variants(value):
        if "\x00" in candidate or any(ord(char) < 32 and char not in "\t\r\n" for char in candidate):
            raise ReviewBlocked(f"{label} contains an unsafe encoded value")
        if _looks_like_local_or_escaping_path(candidate):
            raise ReviewBlocked(f"{label} contains a prohibited local or escaping path")


def _looks_like_local_or_escaping_path(value: str) -> bool:
    candidate = value.strip()
    if not candidate:
        return False
    if re.match(r"(?i)^file:", candidate):
        return True
    parsed = urlsplit(candidate)
    if parsed.scheme and len(parsed.scheme) > 1 and parsed.scheme.casefold() != "https":
        return True
    if re.match(r"(?i)^[a-z]:", candidate):
        return True
    if candidate.startswith(("\\\\", "//", "/", "\\")):
        return True
    normalized = candidate.replace("\\", "/")
    if "\\" in candidate and "/" in candidate:
        return True
    segments = normalized.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return True
    return False


def _normalize_repo_relative_path(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ReviewBlocked(f"{label} must be a non-empty repository-relative path")
    variants = _decoded_text_variants(raw)
    if len(variants) > 1:
        raise ReviewBlocked(f"{label} must not use encoded path characters")
    value = variants[0]
    if _looks_like_local_or_escaping_path(value) or "\\" in value:
        raise ReviewBlocked(f"{label} must be a contained POSIX repository-relative path")
    pure = PurePosixPath(value)
    normalized = pure.as_posix()
    if normalized != value or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ReviewBlocked(f"{label} is not canonical")
    if PureWindowsPath(value).is_absolute() or PureWindowsPath(value).drive:
        raise ReviewBlocked(f"{label} must not be a Windows path")
    return normalized


def _contained_file(base: Path, raw: Any, label: str, allowed_root: Path | None = None) -> Path:
    normalized = _normalize_repo_relative_path(raw, label)
    candidate = (base / normalized).resolve()
    root = (allowed_root or base).resolve()
    if not _is_relative_to(candidate, root):
        raise ReviewBlocked(f"{label} escapes its allowed root")
    if candidate.is_symlink():
        raise ReviewBlocked(f"{label} must not be a symbolic link")
    return candidate


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReviewBlocked("authority repository Git identity could not be verified")
    return result.stdout.strip()


def _canonical_origin(value: str) -> str:
    normalized = value.strip().removesuffix(".git").replace("git@github.com:", "https://github.com/")
    return normalized.casefold()


def _authority_file_identity(repo: Path, relative_path: str) -> dict[str, str]:
    path = _contained_file(repo, relative_path, "authority path")
    if not path.is_file():
        raise ReviewBlocked("authority path is missing")
    tracked = _git(repo, "ls-files", "--error-unmatch", "--", relative_path)
    if tracked.replace("\\", "/") != relative_path:
        raise ReviewBlocked("authority path is not tracked at its canonical name")
    blob = _git(repo, "rev-parse", f"HEAD:{relative_path}")
    current_blob = _git(repo, "hash-object", "--", relative_path)
    if blob != current_blob:
        raise ReviewBlocked("authority source is dirty")
    return {
        "repository": repo.name,
        "path": relative_path,
        "git_blob_sha": blob,
        "sha256": _sha256_file(path),
    }


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _state_integrity_digest(state: dict[str, Any], field: str) -> str:
    payload = {key: value for key, value in state.items() if key != field}
    return _semantic_digest(payload)


def _sanitize_block_reason(reason: str) -> str:
    lowered = reason.casefold()
    if "private" in lowered or "raw" in lowered:
        return "input rejected by private-data boundary"
    if "path" in lowered or "absolute" in lowered or "escape" in lowered or "symbolic" in lowered:
        return "input rejected by path-containment boundary"
    if any(
        marker in lowered
        for marker in (
            "claim",
            "authority",
            "approval",
            "authorization",
            "closure",
            "customer",
            "production",
            "public_safe",
            "public-safe",
            "runtime",
            "signal",
        )
    ):
        return "input rejected by claim-authority boundary"
    if "duplicate" in lowered or "unsupported field" in lowered or "structured" in lowered:
        return "input rejected by strict-structure boundary"
    return re.sub(r"(?i)(?:[A-Z]:[\\/]|\\\\|/home/|/users/)\S*", "[redacted]", reason)[:240]


def default_run_dir(repo_root: Path | None = None) -> Path:
    root = repo_root or Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / ".hoxline" / "runs" / stamp


def default_batch_dir(repo_root: Path | None = None) -> Path:
    root = repo_root or Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / ".hoxline" / "batch-runs" / stamp


def _review_repo_root(input_path: Path, explicit_root: Path | None = None) -> Path:
    if explicit_root is not None:
        return explicit_root.resolve()
    resolved = input_path.resolve()
    for candidate in (resolved.parent, *resolved.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "examples" / "review").is_dir():
            return candidate
    return Path.cwd().resolve()


def _load_yaml_object(path: Path) -> dict[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, ReviewEngineError) as exc:
        raise ReviewBlocked("authority YAML could not be parsed strictly") from exc
    if not isinstance(value, dict):
        raise ReviewBlocked("authority YAML must contain an object")
    return value


def _single_entry(items: Any, key: str, expected: str, label: str) -> dict[str, Any]:
    if not isinstance(items, list):
        raise ReviewBlocked(f"{label} inventory must be a list")
    matches = [item for item in items if isinstance(item, dict) and item.get(key) == expected]
    if len(matches) != 1:
        raise ReviewBlocked(f"{label} must contain exactly one matching identity")
    return matches[0]


def _case_lists(value: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases = value.get("cases")
    if isinstance(cases, dict):
        positive = cases.get("positive")
        negative = cases.get("negative")
    else:
        positive = value.get("positive")
        negative = value.get("negative")
    if not isinstance(positive, list) or not isinstance(negative, list) or not positive or not negative:
        raise ReviewBlocked("validation-owned fixture contract must include positive and negative cases")
    if not all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in [*positive, *negative]):
        raise ReviewBlocked("validation-owned fixture cases require explicit identifiers")
    ids = [str(item["id"]).casefold() for item in [*positive, *negative]]
    if len(ids) != len(set(ids)):
        raise ReviewBlocked("validation-owned fixture case identifiers must be unique")
    return positive, negative


def _owned_authority_binding(manifest: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    artifact_id = str(manifest["artifact_id"])
    if artifact_id.startswith("HO-NDR-"):
        raise ReviewBlocked("boundary-contract artifact has no owned controlled-validation PASS authority")
    org_root = repo_root.parent.resolve()
    detection_repo = (org_root / "hawkinsoperations-detections").resolve()
    validation_repo = (org_root / "hawkinsoperations-validation").resolve()
    for repo_name, repo in (
        ("hawkinsoperations-detections", detection_repo),
        ("hawkinsoperations-validation", validation_repo),
    ):
        if repo.parent != org_root or not (repo / ".git").exists():
            raise ReviewBlocked("required authority repository is missing")
        origin = _canonical_origin(_git(repo, "remote", "get-url", "origin"))
        if origin != _canonical_origin(CANONICAL_ORIGINS[repo_name]):
            raise ReviewBlocked("authority repository origin is not canonical")
        selection_errors = verify_selected_source_checkout(org_root, repo_name)
        if selection_errors:
            raise ReviewBlocked(f"authority repository selection is invalid: {selection_errors[0]}")
    cache_key = (
        artifact_id,
        str(detection_repo),
        _git(detection_repo, "rev-parse", "HEAD"),
        _git(detection_repo, "status", "--porcelain", "--untracked-files=no"),
        str(validation_repo),
        _git(validation_repo, "rev-parse", "HEAD"),
        _git(validation_repo, "status", "--porcelain", "--untracked-files=no"),
        _semantic_digest(
            {
                "expected_event_ids": manifest.get("expected_event_ids", []),
                "expected_event_keys": manifest.get("expected_event_keys", []),
                "expected_rule_ids": manifest.get("expected_rule_ids", []),
            }
        ),
    )
    if cache_key in _AUTHORITY_BINDING_CACHE:
        return deepcopy(_AUTHORITY_BINDING_CACHE[cache_key])

    matrix_path = "detections/DETECTION_PROMOTION_MATRIX.yml"
    registry_path = "validation/VALIDATION_REGISTRY.yml"
    matrix = _load_yaml_object(detection_repo / matrix_path)
    registry = _load_yaml_object(validation_repo / registry_path)
    source_entry = _single_entry(matrix.get("entries"), "detection_id", artifact_id, "detection matrix")
    validation_entry = _single_entry(registry.get("packages"), "detection_id", artifact_id, "validation registry")

    if source_entry.get("source_status") != "SOURCE_EXISTS":
        raise ReviewBlocked("source-owned package is not SOURCE_EXISTS")
    if source_entry.get("validation_expected_owner") != "hawkinsoperations-validation":
        raise ReviewBlocked("source-owned validation handoff owner is invalid")
    if source_entry.get("runtime_active") is not False or source_entry.get("signal_observed") is not False:
        raise ReviewBlocked("source-owned entry exceeds the allowed runtime or signal boundary")
    if source_entry.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        raise ReviewBlocked("source-owned entry exceeds the public-safe boundary")

    package_path = _normalize_repo_relative_path(source_entry.get("package_path"), "source package path")
    package = (detection_repo / package_path).resolve()
    if not _is_relative_to(package, detection_repo) or not package.is_dir():
        raise ReviewBlocked("source-owned package path is missing or outside its repository")
    required_files = source_entry.get("required_files")
    if not isinstance(required_files, list) or not required_files or not all(isinstance(item, str) for item in required_files):
        raise ReviewBlocked("source-owned entry must declare required package files")
    normalized_required: list[str] = []
    for item in required_files:
        relative = _normalize_repo_relative_path(f"{package_path}/{item}", "source required file")
        if relative.casefold() in {path.casefold() for path in normalized_required}:
            raise ReviewBlocked("source required files contain a normalized duplicate")
        normalized_required.append(relative)
        if not (detection_repo / relative).is_file():
            raise ReviewBlocked("source required file is missing")
    if f"{package_path}/rule.yml" not in normalized_required or f"{package_path}/status.yml" not in normalized_required:
        raise ReviewBlocked("source package must include rule.yml and status.yml")
    source_rule = _load_yaml_object(detection_repo / package_path / "rule.yml")
    source_status = _load_yaml_object(detection_repo / package_path / "status.yml")
    if source_rule.get("detection_id") != artifact_id or source_status.get("detection_id") != artifact_id:
        raise ReviewBlocked("source package identity disagrees with the artifact identity")

    exact_validation = {
        "validation_owner": "hawkinsoperations-validation",
        "source_owner": "hawkinsoperations-detections",
        "expected_result": "PASS",
        "actual_result": "PASS",
        "human_review_required": True,
        "ai_disposition_authority": False,
        "validation_kind": "controlled_validation",
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "runtime_status": False,
        "signal_status": False,
        "source_dependency_required": True,
        "ci_source_dependency_mode": "required",
    }
    for key, expected in exact_validation.items():
        if validation_entry.get(key) != expected:
            raise ReviewBlocked("validation-owned registry entry is not eligible for fixture PASS")
    expected_source_reference = f"hawkinsoperations-detections/{package_path}"
    if validation_entry.get("source_reference") != expected_source_reference:
        raise ReviewBlocked("validation-owned source handoff disagrees with the source package")

    validation_paths: list[str] = []
    for key in (
        "fixture_file",
        "report_json",
        "report_markdown",
        "validator_script",
        "parity_script",
        "claim_boundary_script",
    ):
        relative = _normalize_repo_relative_path(validation_entry.get(key), f"validation {key}")
        if relative.casefold() in {path.casefold() for path in validation_paths}:
            raise ReviewBlocked("validation registry paths contain a normalized duplicate")
        validation_paths.append(relative)
        if not (validation_repo / relative).is_file():
            raise ReviewBlocked("validation-owned required file is missing")

    validation_fixture = _load_json(validation_repo / str(validation_entry["fixture_file"]))
    validation_report = _load_json(validation_repo / str(validation_entry["report_json"]))
    for value, label in ((validation_fixture, "validation fixture"), (validation_report, "validation report")):
        if value.get("detection_id") != artifact_id:
            raise ReviewBlocked(f"{label} identity disagrees with the artifact identity")
    positive, negative = _case_lists(validation_fixture)
    report_status = str(validation_report.get("status") or validation_report.get("result") or "").casefold()
    if report_status != "pass":
        raise ReviewBlocked("validation-owned report does not record PASS")
    expected_positive = validation_entry.get("expected_positive_count")
    expected_negative = validation_entry.get("expected_negative_count")
    if expected_positive != len(positive) or expected_negative != len(negative):
        raise ReviewBlocked("validation-owned registry case counts disagree with its fixture")

    searchable_source = "\n".join((detection_repo / path).read_text(encoding="utf-8") for path in normalized_required)
    searchable_validation = json.dumps(validation_fixture, sort_keys=True)
    for event_id in manifest.get("expected_event_ids", []):
        if not re.search(rf"(?<!\d){re.escape(str(event_id))}(?!\d)", searchable_source + searchable_validation):
            raise ReviewBlocked("manifest event identity is not supported by owned source and validation data")
    for rule_id in manifest.get("expected_rule_ids", []):
        if not re.search(rf"(?<!\d){re.escape(str(rule_id))}(?!\d)", searchable_source):
            raise ReviewBlocked("manifest rule identity is not supported by owned source data")
    for event_key in manifest.get("expected_event_keys", []):
        if str(event_key) not in searchable_source and str(event_key) not in searchable_validation:
            raise ReviewBlocked("manifest behavior identity is not supported by owned source and validation data")

    identities = [
        _authority_file_identity(detection_repo, matrix_path),
        *(_authority_file_identity(detection_repo, path) for path in normalized_required),
        _authority_file_identity(validation_repo, registry_path),
        *(_authority_file_identity(validation_repo, path) for path in validation_paths),
    ]
    identities.sort(key=lambda item: (item["repository"], item["path"]))
    manifest_digest = _semantic_digest(identities)
    binding = {
        "artifact_id": artifact_id,
        "source_owner": "hawkinsoperations-detections",
        "source_package_path": package_path,
        "source_rule_blob_sha": next(
            item["git_blob_sha"] for item in identities if item["repository"] == detection_repo.name and item["path"] == f"{package_path}/rule.yml"
        ),
        "validation_owner": "hawkinsoperations-validation",
        "validation_fixture_path": validation_entry["fixture_file"],
        "validation_report_path": validation_entry["report_json"],
        "validation_report_identity": validation_entry["report_identity"],
        "validation_parity_identity": validation_entry["parity_identity"],
        "positive_case_ids": [item["id"] for item in positive],
        "negative_case_ids": [item["id"] for item in negative],
        "proof_ceiling": validation_entry.get("proof_ceiling"),
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "authority_files": identities,
        "source_manifest_digest": manifest_digest,
    }
    _AUTHORITY_BINDING_CACHE[cache_key] = deepcopy(binding)
    return binding


def run_review(artifact_path: Path, output_dir: Path | None = None, force: bool = False, repo_root: Path | None = None) -> dict[str, Any]:
    out_dir = output_dir or default_run_dir(Path.cwd())
    manifest_path = _resolve_path(artifact_path, Path.cwd())
    root = _review_repo_root(manifest_path, repo_root)
    manifest: dict[str, Any] = {}
    try:
        manifest = _load_json(manifest_path)
        _validate_manifest(manifest, manifest_path, root)
        fixture_paths = _fixture_paths(manifest, root)
        authority_binding = _owned_authority_binding(manifest, root)
        review_outputs = _build_review_outputs(manifest, fixture_paths, authority_binding)
        run = _build_pass_run(manifest, manifest_path, out_dir, review_outputs, fixture_paths, authority_binding)
        _write_pass_outputs(out_dir, run, force)
        return run
    except ReviewBlocked as exc:
        run = _build_blocked_run(manifest, manifest_path, out_dir, _sanitize_block_reason(str(exc)))
        _write_blocked_outputs(out_dir, run, force)
        return run


def verify_review_run(machine_state_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        state = _load_json(machine_state_path)
    except (OSError, ReviewEngineError) as exc:
        return [str(exc)]
    run_dir = machine_state_path.parent
    if machine_state_path.is_symlink() or not _is_relative_to(machine_state_path.resolve(), run_dir.resolve()):
        return ["machine-state path escapes its run root"]
    final_status = state.get("final_status")
    if final_status not in {"PASS", "BLOCKED"}:
        errors.append("machine-state final_status must be PASS or BLOCKED")
    if state.get("schema_version") != MACHINE_STATE_VERSION:
        errors.append(f"machine-state schema_version must be {MACHINE_STATE_VERSION}")
    if state.get("engine_version") != ENGINE_VERSION:
        errors.append(f"machine-state engine_version must be {ENGINE_VERSION}")
    if [stage.get("stage_name") for stage in state.get("stages", [])] != STAGE_REGISTRY:
        errors.append("machine-state stages must match review engine stage registry")
    expected_outputs = EXPECTED_PASS_OUTPUTS if final_status == "PASS" else EXPECTED_BLOCKED_OUTPUTS
    output_refs = state.get("outputs")
    if not isinstance(output_refs, dict) or set(output_refs.values()) != set(expected_outputs) - {"proofcard.md"}:
        errors.append("machine-state output references must exactly match the engine contract")
    declared_output_names = set(state.get("output_digests", {}))
    expected_digest_names = set(expected_outputs) - {"machine-state.json"}
    if declared_output_names != expected_digest_names:
        errors.append("machine-state output digest inventory must exactly match generated outputs")
    for name in expected_outputs:
        path = (run_dir / name).resolve()
        if not _is_relative_to(path, run_dir.resolve()) or path.is_symlink():
            errors.append(f"output path is not contained: {name}")
        elif not path.is_file():
            errors.append(f"missing output file: {name}")
    for name, expected_digest in state.get("output_digests", {}).items():
        try:
            normalized = _normalize_repo_relative_path(name, "machine-state output path")
        except ReviewBlocked as exc:
            errors.append(str(exc))
            continue
        path = (run_dir / normalized).resolve()
        if not _is_relative_to(path, run_dir.resolve()) or path.is_symlink() or not path.is_file():
            errors.append(f"bound output is missing or escapes the run root: {name}")
        elif expected_digest != _sha256_file(path):
            errors.append(f"output digest mismatch: {name}")
    if state.get("state_integrity_digest") != _state_integrity_digest(state, "state_integrity_digest"):
        errors.append("machine-state integrity digest mismatch")
    for field, expected in {
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "private_evidence_committed": False,
    }.items():
        if state.get(field) != expected:
            errors.append(f"machine-state field {field} must be {expected!r}")
    try:
        scan_state = {
            key: value
            for key, value in state.items()
            if key not in {"blocked_claims", "stages", "proof_boundary", "runtime_boundary", "signal_boundary"}
        }
        _validate_recursive_boundaries(scan_state, "machine-state")
        _validate_no_private_markers(state, "machine-state")
    except ReviewBlocked as exc:
        errors.append(_sanitize_block_reason(str(exc)))
    if final_status == "PASS":
        non_pass = [stage["stage_name"] for stage in state["stages"] if stage.get("status") != "PASS"]
        if non_pass:
            errors.append(f"PASS run has non-PASS stages: {', '.join(non_pass)}")
        _verify_pass_outputs(run_dir, state, errors)
        try:
            manifest = _load_json(run_dir / "artifact-manifest.json")
            _validate_manifest(manifest, run_dir / "artifact-manifest.json", Path(__file__).resolve().parents[2])
            fixture_paths = _fixture_paths(manifest, Path(__file__).resolve().parents[2])
            authority = _owned_authority_binding(manifest, Path(__file__).resolve().parents[2])
            expected_inputs = {
                "manifest": _semantic_digest(manifest),
                "positive_fixture": _sha256_file(fixture_paths["positive"]),
                "negative_fixture": _sha256_file(fixture_paths["negative"]),
                "source_manifest": authority["source_manifest_digest"],
            }
            if state.get("input_digests") != expected_inputs:
                errors.append("machine-state input digest contract does not match current owned inputs")
            if state.get("source_manifest_digest") != authority["source_manifest_digest"]:
                errors.append("machine-state source manifest digest mismatch")
            if state.get("authority_binding") != authority:
                errors.append("machine-state authority binding does not match current owned sources")
        except (OSError, ReviewEngineError) as exc:
            errors.append(f"owned input replay failed closed: {_sanitize_block_reason(str(exc))}")
    if final_status == "BLOCKED" and not state.get("block_reason"):
        errors.append("BLOCKED run must include block_reason")
    private_hits = _private_output_hits(run_dir)
    if private_hits:
        errors.append(f"private/raw markers found in review outputs: {', '.join(private_hits)}")
    return errors


def summarize_review_run(machine_state_path: Path) -> str:
    state = _load_json(machine_state_path)
    lines = [
        "# Hoxline Review Engine Summary",
        "",
        f"Run: `{state.get('run_id')}`",
        f"Artifact: `{state.get('artifact_id')}`",
        f"Final status: `{state.get('final_status')}`",
        f"public_safe_status: `{state.get('public_safe_status')}`",
        f"human_review_required: `{str(state.get('human_review_required')).lower()}`",
        f"ai_disposition_authority: `{str(state.get('ai_disposition_authority')).lower()}`",
        "",
        "## Stages",
        "",
    ]
    for stage in state.get("stages", []):
        lines.append(f"- `{stage['stage_name']}`: `{stage['status']}` - {stage['summary']}")
    if state.get("block_reason"):
        lines.extend(["", f"Blocked reason: {state['block_reason']}"])
    lines.extend(["", f"Next gate: `{state.get('next_gate')}`", ""])
    return "\n".join(lines)


def render_run_console(run: dict[str, Any]) -> str:
    state = run["machine_state"]
    lines = [
        "Hoxline Review Engine v1",
        f"Output: {run['output_dir']}",
        f"Machine state: {Path(run['output_dir']) / 'machine-state.json'}",
        "",
    ]
    for index, stage in enumerate(state["stages"], start=1):
        lines.append(f"{index}. {stage['stage_name']}: {stage['status']} - {stage['summary']}")
    if state["final_status"] == "PASS":
        lines.extend(
            [
                "",
                f"Allowed claim: {state['allowed_claim']}",
                f"Reviewer pack: {Path(run['output_dir']) / 'reviewer-pack.md'}",
            ]
        )
    else:
        lines.extend(["", f"Blocked: {state['block_reason']}", f"Blocked review: {Path(run['output_dir']) / 'blocked-review.md'}"])
    lines.extend(
        [
            "",
            "Boundary: fixture-only; NOT_PUBLIC_SAFE; human review required; AI disposition authority false; not runtime proof.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_batch_review(index_path: Path, output_dir: Path | None = None, force: bool = False, repo_root: Path | None = None) -> dict[str, Any]:
    out_dir = output_dir or default_batch_dir(Path.cwd())
    resolved_index = _resolve_path(index_path, Path.cwd())
    root = _review_repo_root(resolved_index, repo_root)
    index: dict[str, Any] = {}
    try:
        index = _load_json(resolved_index)
        _validate_batch_index(index, resolved_index, root)
        _prepare_output_dir(out_dir, force)
        artifacts_root = out_dir / "artifacts"
        artifacts_root.mkdir(parents=True, exist_ok=True)
        _write_file_map(out_dir, {"input-index.json": index})

        artifact_runs: list[dict[str, Any]] = []
        for artifact_entry in index["artifacts"]:
            artifact_id = artifact_entry["artifact_id"]
            manifest_path = _resolve_path(Path(artifact_entry["manifest_path"]), root)
            artifact_out = (artifacts_root / artifact_id).resolve()
            if not _is_relative_to(artifact_out, artifacts_root.resolve()):
                raise ReviewBlocked(f"artifact output path escapes batch root: {artifact_id}")
            run = run_review(manifest_path, artifact_out, force=True, repo_root=root)
            state = run["machine_state"]
            artifact_runs.append(
                {
                    "artifact_id": artifact_id,
                    "manifest_path": _display_path(manifest_path),
                    "output_dir": f"artifacts/{artifact_id}",
                    "machine_state": f"artifacts/{artifact_id}/machine-state.json",
                    "machine_state_sha256": _sha256_file(artifact_out / "machine-state.json"),
                    "manifest_sha256": state.get("input_digests", {}).get("manifest"),
                    "source_manifest_digest": state.get("source_manifest_digest"),
                    "state_integrity_digest": state.get("state_integrity_digest"),
                    "output_digests": state.get("output_digests", {}),
                    "reviewer_pack": f"artifacts/{artifact_id}/reviewer-pack.md" if state["final_status"] == "PASS" else None,
                    "blocked_review": f"artifacts/{artifact_id}/blocked-review.md" if state["final_status"] == "BLOCKED" else None,
                    "run_summary": f"artifacts/{artifact_id}/run-summary.json",
                    "final_status": state["final_status"],
                    "block_reason": state.get("block_reason"),
                    "public_safe_status": state["public_safe_status"],
                    "human_review_required": state["human_review_required"],
                    "ai_disposition_authority": state["ai_disposition_authority"],
                    "endpoint_mutation": state["endpoint_mutation"],
                    "wazuh_mutation": state["wazuh_mutation"],
                    "runtime_proof": state["runtime_proof"],
                    "private_evidence_committed": state["private_evidence_committed"],
                    "public_proof_promoted": state["public_proof_promoted"],
                    "lifetime_ledger_changed": state["lifetime_ledger_changed"],
                    "next_gate": state["next_gate"],
                }
            )

        batch_state = _batch_machine_state(index, resolved_index, out_dir, artifact_runs)
        expectation_errors = _batch_expectation_errors(batch_state)
        if expectation_errors:
            batch_state["final_status"] = "BLOCKED"
            batch_state["block_reason"] = "; ".join(expectation_errors)
        _write_batch_outputs(out_dir, index, batch_state)
        return {"output_dir": str(out_dir), "index": index, "batch_machine_state": batch_state}
    except ReviewBlocked as exc:
        _prepare_output_dir(out_dir, force)
        safe_reason = _sanitize_block_reason(str(exc))
        safe_index = _safe_blocked_index(index, resolved_index, safe_reason)
        batch_state = _blocked_batch_machine_state(safe_index, resolved_index, out_dir, safe_reason)
        _write_batch_outputs(out_dir, safe_index, batch_state)
        return {"output_dir": str(out_dir), "index": safe_index, "batch_machine_state": batch_state}


def verify_batch_run(batch_machine_state_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        state = _load_json(batch_machine_state_path)
    except (OSError, ReviewEngineError) as exc:
        return [str(exc)]
    run_dir = batch_machine_state_path.parent
    if batch_machine_state_path.is_symlink() or not _is_relative_to(batch_machine_state_path.resolve(), run_dir.resolve()):
        return ["batch-machine-state path escapes its run root"]
    if state.get("schema_version") != BATCH_MACHINE_STATE_VERSION:
        errors.append(f"batch-machine-state schema_version must be {BATCH_MACHINE_STATE_VERSION}")
    if state.get("engine_version") != BATCH_ENGINE_VERSION:
        errors.append(f"batch-machine-state engine_version must be {BATCH_ENGINE_VERSION}")
    if state.get("final_status") not in {"PASS", "MIXED", "BLOCKED"}:
        errors.append("batch-machine-state final_status must be PASS, MIXED, or BLOCKED")
    for name in BATCH_EXPECTED_OUTPUTS:
        path = (run_dir / name).resolve()
        if not _is_relative_to(path, run_dir.resolve()) or path.is_symlink():
            errors.append(f"batch output path is not contained: {name}")
        elif not path.is_file():
            errors.append(f"missing batch output file: {name}")
    expected_digest_names = set(BATCH_EXPECTED_OUTPUTS) - {"batch-machine-state.json"}
    if set(state.get("output_digests", {})) != expected_digest_names:
        errors.append("batch output digest inventory must exactly match generated outputs")
    for name, expected_digest in state.get("output_digests", {}).items():
        try:
            normalized = _normalize_repo_relative_path(name, "batch output path")
        except ReviewBlocked as exc:
            errors.append(str(exc))
            continue
        path = (run_dir / normalized).resolve()
        if not _is_relative_to(path, run_dir.resolve()) or path.is_symlink() or not path.is_file():
            errors.append(f"bound batch output is missing or escapes the run root: {name}")
        elif expected_digest != _sha256_file(path):
            errors.append(f"batch output digest mismatch: {name}")
    if state.get("batch_state_integrity_digest") != _state_integrity_digest(state, "batch_state_integrity_digest"):
        errors.append("batch-machine-state integrity digest mismatch")
    for field, expected in {
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "private_evidence_committed": False,
        "website_changed": False,
    }.items():
        if state.get(field) != expected:
            errors.append(f"batch-machine-state field {field} must be {expected!r}")
    if state.get("final_status") == "BLOCKED" and not state.get("block_reason"):
        errors.append("BLOCKED batch run must include block_reason")
    artifacts = state.get("artifacts", [])
    if state.get("final_status") != "BLOCKED" and not artifacts:
        errors.append("non-BLOCKED batch run must include artifact states")
    artifact_ids: set[str] = set()
    source_digests: list[str] = []
    for artifact in artifacts:
        artifact_id = artifact.get("artifact_id", "UNKNOWN")
        if artifact_id in artifact_ids:
            errors.append(f"duplicate aggregate artifact identity: {artifact_id}")
        artifact_ids.add(str(artifact_id))
        try:
            state_relative = _normalize_repo_relative_path(artifact.get("machine_state"), "artifact machine-state path")
        except ReviewBlocked as exc:
            errors.append(f"{artifact_id}: {exc}")
            continue
        state_path = (run_dir / state_relative).resolve()
        if not _is_relative_to(state_path, (run_dir / "artifacts").resolve()) or state_path.is_symlink():
            errors.append(f"{artifact_id}: child machine-state escapes artifacts root")
            continue
        if not state_path.is_file():
            errors.append(f"missing artifact machine-state for {artifact_id}")
            continue
        if artifact.get("machine_state_sha256") != _sha256_file(state_path):
            errors.append(f"{artifact_id}: machine-state hash mismatch")
        artifact_errors = verify_review_run(state_path)
        errors.extend(f"{artifact_id}: {error}" for error in artifact_errors)
        child_state = _load_json(state_path)
        if child_state.get("artifact_id") != artifact_id:
            errors.append(f"{artifact_id}: aggregate artifact_id does not match child machine-state artifact_id")
        for key in (
            "final_status",
            "block_reason",
            "public_safe_status",
            "human_review_required",
            "ai_disposition_authority",
            "endpoint_mutation",
            "wazuh_mutation",
            "runtime_proof",
            "private_evidence_committed",
            "public_proof_promoted",
            "lifetime_ledger_changed",
            "next_gate",
            "source_manifest_digest",
            "state_integrity_digest",
            "output_digests",
        ):
            if artifact.get(key) != child_state.get(key):
                errors.append(f"{artifact_id}: aggregate {key} does not match child machine-state")
        if artifact.get("manifest_sha256") != child_state.get("input_digests", {}).get("manifest"):
            errors.append(f"{artifact_id}: aggregate manifest digest does not match child machine-state")
        if child_state.get("source_manifest_digest"):
            source_digests.append(str(child_state["source_manifest_digest"]))
        if artifact.get("public_safe_status") != PUBLIC_SAFE_STATUS:
            errors.append(f"{artifact_id}: public_safe_status must remain NOT_PUBLIC_SAFE")
        for false_field in ("endpoint_mutation", "wazuh_mutation", "runtime_proof", "public_proof_promoted", "lifetime_ledger_changed", "private_evidence_committed"):
            if artifact.get(false_field) is not False:
                errors.append(f"{artifact_id}: {false_field} must be false")
    errors.extend(_batch_expectation_errors(state))
    expected_aggregate = _semantic_digest(sorted(source_digests)) if source_digests else None
    if state.get("source_manifest_digest") != expected_aggregate:
        errors.append("batch source manifest digest does not match child authority bindings")
    input_index = run_dir / "input-index.json"
    if input_index.is_file() and state.get("input_index_sha256") != _sha256_file(input_index):
        errors.append("batch input-index digest mismatch")
    if state.get("final_status") != "BLOCKED":
        try:
            index = _load_json(input_index)
            _validate_batch_index(index, input_index, Path(__file__).resolve().parents[2])
            if state.get("index_id") != index.get("index_id"):
                errors.append("batch index identity mismatch")
            if state.get("expected_pass_artifacts") != index.get("expected_pass_artifacts"):
                errors.append("batch expected PASS list does not match input index")
            if state.get("expected_blocked_artifacts") != index.get("expected_blocked_artifacts"):
                errors.append("batch expected BLOCKED list does not match input index")
        except (OSError, ReviewEngineError) as exc:
            errors.append(f"batch input-index replay failed closed: {_sanitize_block_reason(str(exc))}")
    private_hits = _private_output_hits(run_dir)
    if private_hits:
        errors.append(f"private/raw markers found in batch outputs: {', '.join(private_hits)}")
    return errors


def render_batch_console(batch: dict[str, Any]) -> str:
    state = batch["batch_machine_state"]
    lines = [
        "Hoxline Review Engine v1 batch",
        f"Output: {batch['output_dir']}",
        f"Batch machine state: {Path(batch['output_dir']) / 'batch-machine-state.json'}",
        "",
        f"Final status: {state['final_status']}",
    ]
    if state.get("block_reason"):
        lines.append(f"Blocked: {state['block_reason']}")
    lines.extend(["", "Artifacts:"])
    for artifact in state.get("artifacts", []):
        detail = f" - {artifact.get('block_reason')}" if artifact.get("block_reason") else ""
        lines.append(f"- {artifact['artifact_id']}: {artifact['final_status']}{detail}")
    lines.extend(
        [
            "",
            f"Batch reviewer pack: {Path(batch['output_dir']) / 'batch-reviewer-pack.md'}",
            "Boundary: fixture-only; NOT_PUBLIC_SAFE; human review required; AI disposition authority false; not runtime proof.",
        ]
    )
    return "\n".join(lines) + "\n"


def _validate_batch_index(index: dict[str, Any], index_path: Path, repo_root: Path) -> None:
    required = [
        "index_version",
        "index_id",
        "description",
        "artifacts",
        "expected_pass_artifacts",
        "expected_blocked_artifacts",
        "batch_claim_boundary",
        "public_safe_status",
        "human_review_required",
        "ai_disposition_authority",
        "runtime_boundary",
        "signal_boundary",
        "proof_boundary",
        "generated_outputs",
        "next_gate",
    ]
    for field in required:
        if field not in index:
            raise ReviewBlocked(f"batch index missing required field: {field}")
    _require_exact_keys(index, BATCH_INDEX_ALLOWED_FIELDS, "batch index")
    if index["index_version"] != BATCH_INDEX_VERSION:
        raise ReviewBlocked(f"index_version must be {BATCH_INDEX_VERSION}")
    if index.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        raise ReviewBlocked("batch public_safe_status must remain NOT_PUBLIC_SAFE")
    if index.get("human_review_required") is not True:
        raise ReviewBlocked("batch human_review_required must be true")
    if index.get("ai_disposition_authority") is not False:
        raise ReviewBlocked("batch ai_disposition_authority must be false")
    _validate_claims({"requested_claims": [index.get("batch_claim_boundary", "")], "blocked_claim_classes": BLOCKED_CLAIM_FAMILIES})
    _validate_recursive_boundaries(index, "batch index")
    _validate_no_private_markers(index, "batch index")
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReviewBlocked("batch index artifacts must be a non-empty list")
    seen: set[str] = set()
    normalized_manifest_paths: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ReviewBlocked("batch index artifact entries must be objects")
        _require_exact_keys(item, {"artifact_id", "manifest_path"}, "batch artifact entry")
        artifact_id = item.get("artifact_id")
        if not artifact_id:
            raise ReviewBlocked("batch index artifact entry missing artifact_id")
        if not ARTIFACT_ID_PATTERN.fullmatch(str(artifact_id)):
            raise ReviewBlocked(f"batch index artifact_id has invalid format: {artifact_id}")
        if artifact_id in seen:
            raise ReviewBlocked(f"duplicate artifact_id in batch index: {artifact_id}")
        seen.add(str(artifact_id))
        manifest_path = item.get("manifest_path")
        if not manifest_path:
            raise ReviewBlocked(f"batch index artifact {artifact_id} missing manifest_path")
        canonical_manifest_path = _normalize_repo_relative_path(manifest_path, "batch manifest path")
        if canonical_manifest_path.casefold() in normalized_manifest_paths:
            raise ReviewBlocked("batch index contains a duplicate normalized manifest path")
        normalized_manifest_paths.add(canonical_manifest_path.casefold())
        resolved = _contained_file(
            repo_root,
            canonical_manifest_path,
            "batch manifest path",
            repo_root / "examples" / "review",
        )
        if not resolved.is_file():
            raise ReviewBlocked("batch index manifest path is missing")
        allowed_root = (repo_root / "examples" / "review").resolve()
        if not _is_relative_to(resolved.resolve(), allowed_root):
            raise ReviewBlocked(f"batch index manifest path outside examples/review for {artifact_id}")
        manifest = _load_json(resolved)
        if manifest.get("artifact_id") != artifact_id:
            raise ReviewBlocked(
                f"batch index artifact_id {artifact_id} does not match manifest artifact_id {manifest.get('artifact_id')}"
            )
    expected_pass = index.get("expected_pass_artifacts")
    expected_blocked = index.get("expected_blocked_artifacts")
    if not isinstance(expected_pass, list) or not isinstance(expected_blocked, list):
        raise ReviewBlocked("batch expectations must be arrays")
    if not all(isinstance(item, str) and ARTIFACT_ID_PATTERN.fullmatch(item) for item in [*expected_pass, *expected_blocked]):
        raise ReviewBlocked("batch expectation identities are malformed")
    if len({item.casefold() for item in expected_pass}) != len(expected_pass) or len(
        {item.casefold() for item in expected_blocked}
    ) != len(expected_blocked):
        raise ReviewBlocked("batch expectations contain duplicate normalized identities")
    if set(expected_pass) & set(expected_blocked):
        raise ReviewBlocked("batch PASS and BLOCKED expectations must be disjoint")
    if set(expected_pass) | set(expected_blocked) != seen:
        raise ReviewBlocked("batch expectations must classify every declared artifact exactly once")
    expected_generated = [name for name in BATCH_EXPECTED_OUTPUTS if name != "input-index.json"]
    if index.get("generated_outputs") != expected_generated:
        raise ReviewBlocked("batch generated_outputs must match the engine output contract")


def _batch_machine_state(index: dict[str, Any], index_path: Path, output_dir: Path, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = {artifact["final_status"] for artifact in artifacts}
    final_status = "PASS" if statuses == {"PASS"} else "MIXED" if statuses <= {"PASS", "BLOCKED"} else "BLOCKED"
    return {
        "schema_version": BATCH_MACHINE_STATE_VERSION,
        "engine_version": BATCH_ENGINE_VERSION,
        "batch_id": output_dir.name,
        "index_id": index.get("index_id"),
        "index_path": _display_path(index_path),
        "artifacts": artifacts,
        "expected_pass_artifacts": list(index.get("expected_pass_artifacts", [])),
        "expected_blocked_artifacts": list(index.get("expected_blocked_artifacts", [])),
        "final_status": final_status,
        "actual_pass_artifacts": sorted(
            artifact["artifact_id"] for artifact in artifacts if artifact.get("final_status") == "PASS"
        ),
        "actual_blocked_artifacts": sorted(
            artifact["artifact_id"] for artifact in artifacts if artifact.get("final_status") == "BLOCKED"
        ),
        "block_reason": None,
        "batch_claim_boundary": index.get("batch_claim_boundary"),
        "proof_boundary": index.get("proof_boundary"),
        "runtime_boundary": index.get("runtime_boundary"),
        "signal_boundary": index.get("signal_boundary"),
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "private_evidence_committed": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "website_changed": False,
        "outputs": BATCH_EXPECTED_OUTPUTS,
        "next_gate": index.get("next_gate"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "product": PRODUCT,
        "source_manifest_digest": _semantic_digest(
            sorted(
                str(artifact["source_manifest_digest"])
                for artifact in artifacts
                if artifact.get("source_manifest_digest")
            )
        )
        if artifacts
        else None,
    }


def _blocked_batch_machine_state(index: dict[str, Any], index_path: Path, output_dir: Path, block_reason: str) -> dict[str, Any]:
    state = _batch_machine_state(index, index_path, output_dir, [])
    state["batch_id"] = "blocked-batch-run"
    state["final_status"] = "BLOCKED"
    state["block_reason"] = block_reason
    return state


def _batch_expectation_errors(state: dict[str, Any]) -> list[str]:
    artifacts = state.get("artifacts", [])
    actual_pass = {artifact["artifact_id"] for artifact in artifacts if artifact.get("final_status") == "PASS"}
    actual_blocked = {artifact["artifact_id"] for artifact in artifacts if artifact.get("final_status") == "BLOCKED"}
    expected_pass = set(state.get("expected_pass_artifacts", []))
    expected_blocked = set(state.get("expected_blocked_artifacts", []))
    errors: list[str] = []
    if expected_pass != actual_pass:
        errors.append(f"expected PASS artifacts {sorted(expected_pass)} but saw {sorted(actual_pass)}")
    if expected_blocked != actual_blocked:
        errors.append(f"expected BLOCKED artifacts {sorted(expected_blocked)} but saw {sorted(actual_blocked)}")
    if state.get("actual_pass_artifacts") != sorted(actual_pass):
        errors.append("recorded actual PASS artifacts do not match child states")
    if state.get("actual_blocked_artifacts") != sorted(actual_blocked):
        errors.append("recorded actual BLOCKED artifacts do not match child states")
    expected_status = "PASS" if actual_pass and not actual_blocked else "MIXED" if actual_pass and actual_blocked else "BLOCKED"
    if not errors and state.get("final_status") != expected_status:
        errors.append(f"aggregate final status must be {expected_status}")
    return errors


def _write_batch_outputs(output_dir: Path, index: dict[str, Any], state: dict[str, Any]) -> None:
    file_map = {
        "input-index.json": index,
        "batch-summary.md": _batch_summary_markdown(state),
        "batch-reviewer-pack.md": _batch_reviewer_pack(state),
        "batch-run-summary.json": _batch_run_summary(state),
    }
    _write_file_map(output_dir, file_map)
    state["input_index_sha256"] = _sha256_file(output_dir / "input-index.json")
    state["output_digests"] = {name: _sha256_file(output_dir / name) for name in sorted(file_map)}
    state["batch_state_integrity_digest"] = _state_integrity_digest(state, "batch_state_integrity_digest")
    _write_file_map(output_dir, {"batch-machine-state.json": state})


def _batch_summary_markdown(state: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Multi-Artifact Review Summary",
        "",
        f"Batch: `{state.get('batch_id')}`",
        f"Final status: `{state.get('final_status')}`",
        f"public_safe_status: `{state.get('public_safe_status')}`",
        f"human_review_required: `{str(state.get('human_review_required')).lower()}`",
        f"ai_disposition_authority: `{str(state.get('ai_disposition_authority')).lower()}`",
        "",
        "## Artifacts",
        "",
    ]
    for artifact in state.get("artifacts", []):
        detail = f" - {artifact.get('block_reason')}" if artifact.get("block_reason") else ""
        lines.append(f"- `{artifact['artifact_id']}`: `{artifact['final_status']}`{detail}")
    if state.get("block_reason"):
        lines.extend(["", f"Batch block reason: {state['block_reason']}"])
    lines.extend(["", "## Boundary", "", "This batch is fixture-only, local, deterministic, NOT_PUBLIC_SAFE, human-review-required, and not runtime proof.", ""])
    return "\n".join(lines)


def _batch_reviewer_pack(state: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Multi-Artifact Reviewer Pack",
        "",
        "## What This Is",
        "",
        "A deterministic local batch review of governed artifact manifests through Hoxline Review Engine v1.",
        "",
        "## What Happened",
        "",
        f"Batch `{state.get('batch_id')}` reviewed the declared artifact set and wrote one machine-state per artifact plus this aggregate state.",
        "",
        "## Artifact Results",
        "",
        "| Artifact | Status | Reviewer Output |",
        "|---|---|---|",
    ]
    for artifact in state.get("artifacts", []):
        output = artifact.get("reviewer_pack") or artifact.get("blocked_review") or "none"
        lines.append(f"| `{artifact['artifact_id']}` | `{artifact['final_status']}` | `{output}` |")
    lines.extend(
        [
            "",
            "## What Passed",
            "",
        ]
    )
    passed = [artifact["artifact_id"] for artifact in state.get("artifacts", []) if artifact.get("final_status") == "PASS"]
    lines.extend(f"- `{artifact_id}`" for artifact_id in passed)
    if not passed:
        lines.append("- none")
    lines.extend(["", "## What Blocked", ""])
    blocked = [artifact for artifact in state.get("artifacts", []) if artifact.get("final_status") == "BLOCKED"]
    lines.extend(f"- `{artifact['artifact_id']}`: {artifact.get('block_reason')}" for artifact in blocked)
    if not blocked:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## What This Proves",
            "",
            "- Hoxline can run the Review Engine across a declared artifact manifest set.",
            "- The batch machine-state records per-artifact PASS and BLOCKED outcomes and verifies expectations.",
            "- Unsupported claims block fail-closed at the artifact and batch layers.",
            "",
            "## What This Does Not Prove",
            "",
            "- It does not prove live runtime behavior or public signal observation.",
            "- It does not prove public-safe status, production readiness, deployment, approval, authorization, or case closure.",
            "- It does not touch endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, ledgers, or website proof state.",
            "",
            "## Final Claim Boundary",
            "",
            f"- public_safe_status: `{state['public_safe_status']}`",
            f"- human_review_required: `{str(state['human_review_required']).lower()}`",
            f"- ai_disposition_authority: `{str(state['ai_disposition_authority']).lower()}`",
            f"- next_gate: `{state.get('next_gate')}`",
            "",
        ]
    )
    return "\n".join(lines)


def _batch_run_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "batch-run-summary-v1",
        "engine_version": BATCH_ENGINE_VERSION,
        "batch_id": state["batch_id"],
        "index_id": state.get("index_id"),
        "final_status": state["final_status"],
        "block_reason": state.get("block_reason"),
        "artifacts": state.get("artifacts", []),
        "outputs": BATCH_EXPECTED_OUTPUTS,
        "public_safe_status": state["public_safe_status"],
        "human_review_required": state["human_review_required"],
        "ai_disposition_authority": state["ai_disposition_authority"],
        "endpoint_mutation": state["endpoint_mutation"],
        "runtime_proof": state["runtime_proof"],
        "wazuh_mutation": state["wazuh_mutation"],
        "private_evidence_committed": state["private_evidence_committed"],
        "public_proof_promoted": state["public_proof_promoted"],
        "lifetime_ledger_changed": state["lifetime_ledger_changed"],
        "website_changed": state["website_changed"],
    }


def _safe_blocked_index(index: dict[str, Any], index_path: Path, block_reason: str) -> dict[str, Any]:
    index_id = index.get("index_id") if index else None
    safe_index_id = index_id if isinstance(index_id, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,96}", index_id) else "UNKNOWN"
    return {
        "schema_version": "blocked-batch-index-v1",
        "index_path": "blocked-input-index.json",
        "index_id": safe_index_id,
        "final_status": "BLOCKED",
        "block_reason": block_reason,
        "redaction": "Original hostile batch index content is not copied into blocked outputs.",
        "expected_pass_artifacts": [],
        "expected_blocked_artifacts": [],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "runtime_boundary": "runtime prohibited",
        "signal_boundary": "synthetic fixture signal only",
        "proof_boundary": "not public proof",
        "next_gate": "index_fix_required",
    }


def _build_pass_run(
    manifest: dict[str, Any],
    manifest_path: Path,
    output_dir: Path,
    review_outputs: dict[str, Any],
    fixture_paths: dict[str, Path],
    authority_binding: dict[str, Any],
) -> dict[str, Any]:
    run_id = output_dir.name
    output_refs = {
        "artifact_manifest": "artifact-manifest.json",
        "artifact_intake": "intake.json",
        "evidence_graph": "evidence-graph.json",
        "telemetry_contract_check": "telemetry-contract-check.json",
        "controlled_validation": "validation-result.json",
        "synthetic_signal": "synthetic-signal.json",
        "enrichment": "enrichment.json",
        "triage": "triage-summary.md",
        "proofcard": "proofcard.json",
        "claim_authority": "claim-authority.json",
        "reviewer_pack": "reviewer-pack.md",
        "machine_state": "machine-state.json",
        "run_summary": "run-summary.json",
    }
    state = _machine_state(
        manifest=manifest,
        manifest_path=manifest_path,
        run_id=run_id,
        final_status="PASS",
        stages=_pass_stages(output_refs),
        outputs=output_refs,
    )
    state["source_manifest_digest"] = authority_binding["source_manifest_digest"]
    state["authority_binding"] = authority_binding
    state["input_digests"] = {
        "manifest": _semantic_digest(manifest),
        "positive_fixture": _sha256_file(fixture_paths["positive"]),
        "negative_fixture": _sha256_file(fixture_paths["negative"]),
        "source_manifest": authority_binding["source_manifest_digest"],
    }
    reviewer_pack = _reviewer_pack(manifest, state)
    summary = _run_summary(manifest, state, EXPECTED_PASS_OUTPUTS)
    return {
        "output_dir": str(output_dir),
        "manifest": manifest,
        "review_outputs": review_outputs,
        "reviewer_pack": reviewer_pack,
        "machine_state": state,
        "run_summary": summary,
    }


def _build_blocked_run(manifest: dict[str, Any], manifest_path: Path, output_dir: Path, block_reason: str) -> dict[str, Any]:
    run_id = "blocked-review-run"
    output_refs = {
        "artifact_manifest": "artifact-manifest.json",
        "machine_state": "machine-state.json",
        "blocked_review": "blocked-review.md",
        "run_summary": "run-summary.json",
    }
    safe_manifest = _safe_blocked_manifest(manifest, manifest_path, block_reason)
    state = _machine_state(
        manifest=safe_manifest,
        manifest_path=Path("blocked-input.json"),
        run_id=run_id,
        final_status="BLOCKED",
        stages=_blocked_stages(block_reason, output_refs),
        outputs=output_refs,
        block_reason=block_reason,
    )
    return {
        "output_dir": str(output_dir),
        "manifest": safe_manifest,
        "blocked_review": _blocked_review(state),
        "machine_state": state,
        "run_summary": _run_summary(manifest, state, EXPECTED_BLOCKED_OUTPUTS),
    }



def _safe_blocked_manifest(manifest: dict[str, Any], manifest_path: Path, block_reason: str) -> dict[str, Any]:
    artifact_id = manifest.get("artifact_id") if manifest else None
    safe_artifact_id = artifact_id if isinstance(artifact_id, str) and ARTIFACT_ID_PATTERN.fullmatch(artifact_id) else "UNKNOWN"
    return {
        "schema_version": "blocked-artifact-manifest-v1",
        "manifest_path": "blocked-input.json",
        "artifact_id": safe_artifact_id,
        "final_status": "BLOCKED",
        "block_reason": block_reason,
        "redaction": "Original hostile manifest content is not copied into blocked outputs.",
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,

    }

def _write_pass_outputs(output_dir: Path, run: dict[str, Any], force: bool) -> None:
    _prepare_output_dir(output_dir, force)
    outputs = run["review_outputs"]
    file_map: dict[str, Any] = {
        "artifact-manifest.json": run["manifest"],
        "intake.json": outputs["intake"],
        "evidence-graph.json": outputs["evidence_graph"],
        "telemetry-contract-check.json": outputs["telemetry_contract_check"],
        "validation-result.json": outputs["validation_result"],
        "synthetic-signal.json": outputs["synthetic_signal"],
        "enrichment.json": outputs["enrichment"],
        "triage-summary.md": outputs["triage_summary"],
        "proofcard.json": outputs["proofcard"],
        "proofcard.md": outputs["proofcard_markdown"],
        "claim-authority.json": outputs["claim_authority"],
        "reviewer-pack.md": run["reviewer_pack"],
    }
    _write_file_map(output_dir, file_map)
    state = run["machine_state"]
    state["output_digests"] = {
        name: _sha256_file(output_dir / name)
        for name in sorted(file_map)
    }
    summary = _run_summary(run["manifest"], state, EXPECTED_PASS_OUTPUTS)
    _write_file_map(output_dir, {"run-summary.json": summary})
    state["output_digests"]["run-summary.json"] = _sha256_file(output_dir / "run-summary.json")
    state["state_integrity_digest"] = _state_integrity_digest(state, "state_integrity_digest")
    _write_file_map(output_dir, {"machine-state.json": state})
    run["run_summary"] = summary


def _write_blocked_outputs(output_dir: Path, run: dict[str, Any], force: bool) -> None:
    _prepare_output_dir(output_dir, force)
    file_map = {
        "artifact-manifest.json": run["manifest"],
        "blocked-review.md": run["blocked_review"],
    }
    _write_file_map(output_dir, file_map)
    state = run["machine_state"]
    state["output_digests"] = {name: _sha256_file(output_dir / name) for name in sorted(file_map)}
    summary = _run_summary(run["manifest"], state, EXPECTED_BLOCKED_OUTPUTS)
    _write_file_map(output_dir, {"run-summary.json": summary})
    state["output_digests"]["run-summary.json"] = _sha256_file(output_dir / "run-summary.json")
    state["state_integrity_digest"] = _state_integrity_digest(state, "state_integrity_digest")
    _write_file_map(output_dir, {"machine-state.json": state})
    run["run_summary"] = summary


def _node(node_id: str, node_type: str, owner: str, status: str) -> dict[str, str]:
    return {"id": node_id, "type": node_type, "owner": owner, "status": status}


def _build_review_outputs(
    manifest: dict[str, Any],
    fixture_paths: dict[str, Path],
    authority_binding: dict[str, Any],
) -> dict[str, Any]:
    positive_fixture = _load_json(fixture_paths["positive"])
    negative_fixture = _load_json(fixture_paths["negative"])
    _validate_review_fixture(positive_fixture, manifest, True)
    _validate_review_fixture(negative_fixture, manifest, False)

    intake = _artifact_intake(manifest)
    telemetry = _telemetry_contract_check(manifest, positive_fixture)
    validation = _controlled_validation(manifest, positive_fixture, negative_fixture, telemetry, authority_binding)
    signal = _synthetic_signal(manifest, positive_fixture, validation)
    enrichment = _enrichment(manifest, positive_fixture)
    triage = _triage(manifest, signal, enrichment, validation)
    proofcard = _proofcard(manifest, intake, telemetry, validation, signal, enrichment, triage)
    claim_authority = _claim_authority(manifest, proofcard)
    evidence_graph = _evidence_graph(manifest, intake, telemetry, validation, signal, proofcard, claim_authority)
    return {
        "intake": intake,
        "evidence_graph": evidence_graph,
        "telemetry_contract_check": telemetry,
        "validation_result": validation,
        "synthetic_signal": signal,
        "enrichment": enrichment,
        "triage_summary": _triage_markdown(manifest, triage),
        "proofcard": proofcard,
        "proofcard_markdown": _proofcard_markdown(proofcard),
        "claim_authority": claim_authority,
    }


def _artifact_intake(manifest: dict[str, Any]) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "artifact-intake-v1",
        "intake_id": f"intake-{artifact_id.lower()}-review-v1",
        "artifact_id": artifact_id,
        "artifact_type": manifest["artifact_type"],
        "source_owner": manifest["source_owner"],
        "source_label": manifest["artifact_name"],
        "ai_assisted": True,
        "initial_claim_ceiling": manifest["allowed_claim_class"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "notes": [
            "Fixture is synthetic and local-only.",
            "No users, groups, endpoints, Wazuh systems, or private infrastructure are touched.",
        ],
    }


def _telemetry_contract_check(manifest: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    contract = manifest["telemetry_contract"]
    observed_event_ids = sorted({int(event["event_id"]) for event in fixture["events"] if "event_id" in event})
    event_key_field = str(contract.get("event_key_field") or "event_key")
    observed_event_keys = sorted({str(event[event_key_field]) for event in fixture["events"] if event_key_field in event})
    return {
        "schema_version": "telemetry-contract-check-v0",
        "artifact_id": manifest["artifact_id"],
        "required_source": contract["source"],
        "event_ids": list(manifest["expected_event_ids"]),
        "fixture_event_ids": observed_event_ids,
        "event_keys": list(manifest.get("expected_event_keys", [])),
        "fixture_event_keys": observed_event_keys,
        "wazuh_rule_family": list(manifest["expected_rule_ids"]),
        "required_fields": list(contract.get("required_fields", [_manifest_event_selector(manifest), "channel", "action", "actor"])),
        "missing_required_fields": [],
        "result": "pass",
        "scope": "pass for fixture only",
        "network_required": False,
        "endpoint_mutation": False,
    }


def _controlled_validation(
    manifest: dict[str, Any],
    fixture: dict[str, Any],
    negative_fixture: dict[str, Any],
    telemetry: dict[str, Any],
    authority_binding: dict[str, Any],
) -> dict[str, Any]:
    positive_match = _fixture_matches_manifest(fixture, manifest)
    negative_match = _fixture_matches_manifest(negative_fixture, manifest)
    result = "pass" if positive_match and not negative_match and telemetry["result"] == "pass" else "fail"
    return {
        "schema_version": "validation-result-v0",
        "artifact_id": manifest["artifact_id"],
        "fixture_mode": "safe-fixture",
        "fixture_ids": [fixture["fixture_id"], negative_fixture["fixture_id"]],
        "positive_cases": 1,
        "negative_cases": 1,
        "matched_positive_cases": 1 if positive_match else 0,
        "false_positive_negative_cases": 1 if negative_match else 0,
        "result": result,
        "owned_authority_binding": authority_binding,
        "source_manifest_digest": authority_binding["source_manifest_digest"],
        "endpoint_mutation": False,
        "runtime_rerun": False,
        "wazuh_mutation": False,
        "explanation": "Validation evaluates bundled synthetic fixture records only.",
    }


def _synthetic_signal(manifest: dict[str, Any], fixture: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "synthetic-signal-v0",
        "artifact_id": artifact_id,
        "signal_id": f"synthetic-signal-{artifact_id.lower()}-review-v1",
        "source": "safe bundled fixture",
        "detection_fired": validation["result"] == "pass" and _fixture_matches_manifest(fixture, manifest),
        "simulation_only": True,
        "endpoint_mutation": False,
        "backend_mutation": False,
        "explanation": "The signal is derived from fixture fields and does not create operating-system events.",
    }


def _enrichment(manifest: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    selectors = [str(event_id) for event_id in manifest["expected_event_ids"]] + [str(key) for key in manifest.get("expected_event_keys", [])]
    event_mapping = {selector: f"fixture event metadata for {manifest['artifact_id']}" for selector in selectors}
    return {
        "schema_version": "enrichment-v0",
        "artifact_id": manifest["artifact_id"],
        "attack_mapping": list(manifest.get("attack_mapping", [{"technique_id": "T0000", "technique": "synthetic fixture review", "scope": "review mapping only"}])),
        "event_id_mapping": event_mapping,
        "source_mapping": {
            "channel": manifest["telemetry_contract"]["source"],
            "fixture_host": fixture["host"],
            "fixture_scope": "synthetic demo host",
        },
        "field_mapping": dict(manifest.get("field_mapping", {"event_id": "event identifier", "action": "review action", "actor": "synthetic actor label"})),
        "confidence": manifest.get("confidence", "bounded-demo-high"),
        "severity": manifest.get("severity", "medium"),
    }


def _triage(manifest: dict[str, Any], signal: dict[str, Any], enrichment: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "triage-summary-v0",
        "artifact_id": artifact_id,
        "what_happened": manifest.get("triage_what_happened", f"A synthetic fixture represented the {artifact_id} review pattern."),
        "why_it_matters": manifest.get("triage_why_it_matters", "The pattern can matter during security review when backed by appropriate evidence."),
        "evidence_exists": [
            "artifact intake record",
            "evidence graph",
            "telemetry contract check",
            "positive and negative synthetic fixtures",
            "fixture-derived synthetic signal",
            "enrichment mapping",
            "ProofCard",
            "Claim Authority decision",
        ],
        "missing_evidence": ["public-safe runtime proof", "public signal proof", "human review gate completion", "final authorization record"],
        "next_gate": manifest["next_gate"],
        "detection_fired": signal["detection_fired"],
        "validation_result": validation["result"],
        "attack_mapping": enrichment["attack_mapping"],
    }


def _proofcard(
    manifest: dict[str, Any],
    intake: dict[str, Any],
    telemetry: dict[str, Any],
    validation: dict[str, Any],
    signal: dict[str, Any],
    enrichment: dict[str, Any],
    triage: dict[str, Any],
) -> dict[str, Any]:
    artifact_id = manifest["artifact_id"]
    return {
        "schema_version": "proofcard-v1",
        "proofcard_id": f"proofcard-{artifact_id.lower()}-review-v1",
        "detection_id": artifact_id,
        "artifact_id": intake["artifact_id"],
        "proof_owner": "hoxline-review-fixture",
        "proof_ceiling": manifest["allowed_claim_class"],
        "proof_ceiling_meaning": "LOCAL_FIXTURE_REVIEW_ONLY",
        "review_lane": "REVIEW_ENGINE_V1",
        "review_version": "v1",
        "owner_split": {
            "source_truth": manifest["source_owner"],
            "behavior_truth": "bundled synthetic fixture",
            "platform_runtime_truth": "not asserted",
            "proof_authority": "not asserted by review engine",
            "rendering": "local generated files only",
        },
        "telemetry_contract": telemetry,
        "controlled_validation": validation,
        "synthetic_signal": signal,
        "enrichment": enrichment,
        "triage": triage,
        "allowed_claims": _allowed_claims_for(manifest),
        "blocked_claims": _blocked_claims(),
        "missing_evidence": triage["missing_evidence"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "runtime_active": False,
        "signal_observed": False,
        "next_gate": manifest["next_gate"],
    }


def _claim_authority(manifest: dict[str, Any], proofcard: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "claim-authority-v1",
        "decision_id": f"claim-authority-{manifest['artifact_id'].lower()}-review-v1",
        "artifact_id": manifest["artifact_id"],
        "proof_ceiling": proofcard["proof_ceiling"],
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "allowed_claims": list(proofcard["allowed_claims"]),
        "blocked_claims": _blocked_claims(),
        "safer_wording": [
            "Use fixture-only review wording.",
            "Say the review shows deterministic local engine behavior; do not say it proves live runtime or public-safe status.",
        ],
    }


def _evidence_graph(
    manifest: dict[str, Any],
    intake: dict[str, Any],
    telemetry: dict[str, Any],
    validation: dict[str, Any],
    signal: dict[str, Any],
    proofcard: dict[str, Any],
    claim_authority: dict[str, Any],
) -> dict[str, Any]:
    nodes = [
        _node("artifact-intake", "artifact_intake", intake["source_owner"], "PASS"),
        _node("telemetry-contract-check", "telemetry_contract_check", "hoxline-review-fixture", telemetry["result"].upper()),
        _node("controlled-validation", "controlled_validation", "hoxline-review-fixture", validation["result"].upper()),
        _node("synthetic-signal", "synthetic_signal", "hoxline-review-fixture", "PASS"),
        _node("proofcard", "proofcard", proofcard["proof_owner"], "PASS"),
        _node("claim-authority", "claim_authority", "hoxline", "PASS"),
    ]
    return {
        "schema_version": "evidence-graph-v1",
        "graph_id": f"evidence-graph-{manifest['artifact_id'].lower()}-review-v1",
        "detection_id": manifest["artifact_id"],
        "artifact_id": manifest["artifact_id"],
        "nodes": nodes,
        "edges": [
            {"from": "artifact-intake", "to": "telemetry-contract-check", "relationship": "declares assumptions"},
            {"from": "telemetry-contract-check", "to": "controlled-validation", "relationship": "bounds fixture validation"},
            {"from": "controlled-validation", "to": "synthetic-signal", "relationship": "creates fixture-only signal"},
            {"from": "synthetic-signal", "to": "proofcard", "relationship": "summarized by"},
            {"from": "proofcard", "to": "claim-authority", "relationship": "constrains claims"},
        ],
        "missing_evidence": proofcard["missing_evidence"],
    }


def _triage_markdown(manifest: dict[str, Any], triage: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Review Engine Triage Summary",
        "",
        f"Artifact: `{manifest['artifact_id']}`",
        "",
        f"What happened: {triage['what_happened']}",
        "",
        f"Why it matters: {triage['why_it_matters']}",
        "",
        "Evidence exists:",
    ]
    lines.extend(f"- {item}" for item in triage["evidence_exists"])
    lines.extend(["", "Missing evidence:"])
    lines.extend(f"- {item}" for item in triage["missing_evidence"])
    lines.extend(["", f"Next gate: `{triage['next_gate']}`", ""])
    return "\n".join(lines)


def _proofcard_markdown(proofcard: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Review Engine ProofCard",
        "",
        f"Artifact: `{proofcard['artifact_id']}`",
        "",
        f"Proof ceiling: `{proofcard['proof_ceiling']}`",
        "",
        f"public_safe_status: `{proofcard['public_safe_status']}`",
        "",
        f"human_review_required: `{str(proofcard['human_review_required']).lower()}`",
        "",
        f"ai_disposition_authority: `{str(proofcard['ai_disposition_authority']).lower()}`",
        "",
        "## Allowed Claim",
        "",
    ]
    lines.extend(f"- {claim}" for claim in proofcard["allowed_claims"])
    lines.extend(["", "## Blocked Claims", ""])
    lines.extend(f"- `{item['claim']}`: {item['safer_wording']}" for item in proofcard["blocked_claims"])
    lines.extend(["", "## Missing Evidence", ""])
    lines.extend(f"- `{item}`" for item in proofcard["missing_evidence"])
    lines.append("")
    return "\n".join(lines)


def _validate_review_fixture(fixture: dict[str, Any], manifest: dict[str, Any], expected_detection: bool) -> None:
    expected = {
        "schema_version": "hoxline-demo-fixture-v0",
        "artifact_id": manifest["artifact_id"],
        "fixture_kind": "synthetic-demo-only",
        "safe_fixture": True,
        "endpoint_mutation": False,
        "runtime_required": False,
        "network_required": False,
    }
    for field, value in expected.items():
        if fixture.get(field) != value:
            raise ReviewBlocked(f"fixture field {field} must be {value!r}")
    if fixture.get("expected_detection") is not expected_detection:
        raise ReviewBlocked(f"fixture expected_detection must be {expected_detection!r}")
    events = fixture.get("events")
    if not isinstance(events, list) or not events:
        raise ReviewBlocked("fixture events must be a non-empty list")
    for event in events:
        if not isinstance(event, dict):
            raise ReviewBlocked("fixture events must be objects")
        required_fields = manifest.get("telemetry_contract", {}).get(
            "required_fields", [_manifest_event_selector(manifest), "channel", "action", "actor"]
        )
        for field in required_fields:
            if field not in event:
                raise ReviewBlocked(f"fixture event missing field: {field}")
    if expected_detection and not _fixture_matches_manifest(fixture, manifest):
        raise ReviewBlocked("positive fixture does not match manifest detection")
    if not expected_detection and _fixture_matches_manifest(fixture, manifest):
        raise ReviewBlocked("negative fixture unexpectedly matches manifest detection")


def _fixture_matches_manifest(fixture: dict[str, Any], manifest: dict[str, Any]) -> bool:
    if fixture.get("expected_detection") is not True:
        return False
    expected_ids = {int(event_id) for event_id in manifest.get("expected_event_ids", [])}
    expected_keys = {str(value) for value in manifest.get("expected_event_keys", [])}
    event_key_field = _manifest_event_selector(manifest)
    for event in fixture.get("events", []):
        if not isinstance(event, dict):
            continue
        event_id = event.get("event_id")
        if event_id is not None and expected_ids and int(event_id) in expected_ids:
            return True
        if expected_keys and str(event.get(event_key_field, "")) in expected_keys:
            return True
    return False


def _manifest_event_selector(manifest: dict[str, Any]) -> str:
    contract = manifest.get("telemetry_contract") if isinstance(manifest.get("telemetry_contract"), dict) else {}
    return "event_id" if manifest.get("expected_event_ids") else str(contract.get("event_key_field") or "event_key")


def _allowed_claims_for(manifest: dict[str, Any]) -> list[str]:
    requested = manifest.get("requested_claims", [])
    if requested:
        return [str(requested[0])]
    if manifest.get("artifact_id") == ARTIFACT_ID:
        return [SAFE_ALLOWED_CLAIM]
    return [f"{manifest.get('artifact_id', 'artifact')} has a deterministic local fixture review through Hoxline Review Engine v1 without claiming live runtime proof."]


def _validate_manifest(manifest: dict[str, Any], manifest_path: Path, repo_root: Path) -> None:
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            raise ReviewBlocked(f"manifest missing required field: {field}")
    _require_exact_keys(manifest, MANIFEST_ALLOWED_FIELDS, "artifact manifest")
    if manifest["manifest_version"] != MANIFEST_VERSION:
        raise ReviewBlocked(f"manifest_version must be {MANIFEST_VERSION}")
    if manifest["artifact_id"] != ARTIFACT_ID and manifest.get("artifact_family") != "synthetic-review-only":
        raise ReviewBlocked("unknown artifact requires explicit synthetic-review-only artifact_family")
    if manifest.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        raise ReviewBlocked("public_safe_status must remain NOT_PUBLIC_SAFE")
    if manifest.get("human_review_required") is not True:
        raise ReviewBlocked("human_review_required must be true")
    if manifest.get("ai_disposition_authority") is not False:
        raise ReviewBlocked("ai_disposition_authority must be false")
    if manifest.get("expected_review_outcome") not in {None, "BLOCKED"}:
        raise ReviewBlocked("expected_review_outcome may only declare BLOCKED")
    _validate_manifest_flags(manifest)
    _validate_claims(manifest)
    scan_manifest = {
        key: value
        for key, value in manifest.items()
        if key != "blocked_claim_classes"
        and not (key == "expected_block_reason" and manifest.get("expected_review_outcome") == "BLOCKED")
    }
    _validate_recursive_boundaries(scan_manifest, "artifact manifest")
    _validate_no_private_markers(manifest, "manifest")
    if manifest.get("expected_review_outcome") == "BLOCKED":
        raise ReviewBlocked("boundary-contract artifact remains expected BLOCKED")
    _validate_telemetry_contract(manifest)
    paths = _fixture_paths(manifest, repo_root)
    for label, path in paths.items():
        if not path.is_file():
            declared = (manifest.get("fixture_paths") or {}).get(label, "missing")
            raise ReviewBlocked(f"{label} fixture path missing: {declared}")
        _validate_fixture_path(path, repo_root)
        fixture = _load_json(path)
        _require_exact_keys(fixture, FIXTURE_ALLOWED_FIELDS, f"{label} fixture")
        if not isinstance(fixture.get("events"), list) or not fixture["events"]:
            raise ReviewBlocked(f"{label} fixture events must be a non-empty list")
        if not all(
            isinstance(event, dict)
            and event
            and all(isinstance(key, str) and isinstance(value, (str, int, float, bool, type(None))) for key, value in event.items())
            for event in fixture["events"]
        ):
            raise ReviewBlocked(f"{label} fixture event shape is unsupported")
        _validate_recursive_boundaries(fixture, f"{label} fixture")
        _validate_no_private_markers(fixture, f"{label} fixture")


def _validate_manifest_flags(manifest: dict[str, Any]) -> None:
    flag_checks = {
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "lifetime_ledger_changed": False,
        "public_proof_promoted": False,
        "runtime_proof": False,
    }
    for field, expected in flag_checks.items():
        if field in manifest and manifest[field] is not expected:
            raise ReviewBlocked(f"{field} must be {str(expected).lower()}")


def _validate_telemetry_contract(manifest: dict[str, Any]) -> None:
    contract = manifest.get("telemetry_contract")
    if not isinstance(contract, dict):
        raise ReviewBlocked("telemetry_contract must be an object")
    _require_exact_keys(contract, TELEMETRY_CONTRACT_ALLOWED_FIELDS, "telemetry_contract")
    if not isinstance(contract.get("source"), str) or not contract.get("source"):
        raise ReviewBlocked("telemetry_contract.source must be a non-empty fixture metadata source")
    event_ids = contract.get("event_ids")
    expected_event_ids = manifest.get("expected_event_ids")
    event_keys = contract.get("event_keys", [])
    expected_event_keys = manifest.get("expected_event_keys", [])
    if not isinstance(event_ids, list):
        raise ReviewBlocked("telemetry_contract.event_ids must be a list")
    if sorted(event_ids) != sorted(expected_event_ids or []):
        raise ReviewBlocked("telemetry_contract.event_ids must match expected_event_ids")
    if not isinstance(event_keys, list) or sorted(event_keys) != sorted(expected_event_keys or []):
        raise ReviewBlocked("telemetry_contract.event_keys must match expected_event_keys")
    if not event_ids and not event_keys:
        raise ReviewBlocked("telemetry contract must declare event_ids or event_keys")
    rule_ids = contract.get("wazuh_rule_ids")
    expected_rule_ids = manifest.get("expected_rule_ids")
    if not isinstance(rule_ids, list):
        raise ReviewBlocked("telemetry_contract.wazuh_rule_ids must be a list")
    if sorted(rule_ids) != sorted(expected_rule_ids or []):
        raise ReviewBlocked("telemetry_contract.wazuh_rule_ids must match expected_rule_ids")


def _validate_claims(manifest: dict[str, Any]) -> None:
    requested_claims = manifest.get("requested_claims")
    if not isinstance(requested_claims, list):
        raise ReviewBlocked("requested_claims must be a list")
    expected_owners = {
        "source_owner": "hawkinsoperations-detections",
        "validation_owner": "hawkinsoperations-validation",
        "platform_owner": "hawkinsoperations-platform",
        "proof_owner": "hawkinsoperations-proof",
        "product_owner": "hoxline",
    }
    for field, expected in expected_owners.items():
        if field in manifest and manifest.get(field) != expected:
            raise ReviewBlocked(f"{field} must be the exact source-owned repository {expected}")
    requested_text = json.dumps(requested_claims, sort_keys=True)
    for label, pattern in PROHIBITED_CLAIM_PATTERNS.items():
        if pattern.search(requested_text):
            raise ReviewBlocked(f"requested claim is unsupported and blocked: {label}")
    blocked = set(manifest.get("blocked_claim_classes", []))
    missing = [claim for claim in BLOCKED_CLAIM_FAMILIES if claim not in blocked]
    if missing:
        raise ReviewBlocked(f"manifest must list blocked claim classes: {', '.join(missing)}")


def _fixture_paths(manifest: dict[str, Any], repo_root: Path) -> dict[str, Path]:
    raw = manifest.get("fixture_paths")
    if not isinstance(raw, dict):
        raise ReviewBlocked("fixture_paths must be an object")
    _require_exact_keys(raw, {"positive", "negative"}, "fixture_paths")
    try:
        paths = {
            "positive": _contained_file(
                repo_root,
                raw["positive"],
                "positive fixture path",
                repo_root / "examples",
            ),
            "negative": _contained_file(
                repo_root,
                raw["negative"],
                "negative fixture path",
                repo_root / "examples",
            ),
        }
    except KeyError as exc:
        raise ReviewBlocked(f"fixture_paths missing key: {exc.args[0]}") from exc
    if paths["positive"] == paths["negative"]:
        raise ReviewBlocked("positive and negative fixtures must be different files")
    return paths


def _validate_fixture_path(path: Path, repo_root: Path) -> None:
    resolved = path.resolve()
    allowed_roots = [(repo_root / "examples" / "demo").resolve(), (repo_root / "examples" / "review").resolve()]
    if not any(_is_relative_to(resolved, allowed) for allowed in allowed_roots):
        raise ReviewBlocked("fixture path outside allowed example roots")


def _validate_no_private_markers(value: Any, label: str, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            full = f"{path}.{key}" if path else str(key)
            for pattern in PRIVATE_FIELD_PATTERNS:
                if pattern.search(str(key)) and not (
                    _normalize_security_key(key) in SECURITY_FALSE_KEY_TOKENS and item is False
                ):
                    raise ReviewBlocked(f"{label} contains prohibited private/raw field marker")
            _validate_no_private_markers(item, label, full)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_no_private_markers(item, label, f"{path}[{index}]")
    elif isinstance(value, str):
        for candidate in _decoded_text_variants(value):
            if ABSOLUTE_LOCAL_PATH.search(candidate) or _looks_like_local_or_escaping_path(candidate):
                raise ReviewBlocked(f"{label} contains an absolute local path")
            for pattern in PRIVATE_VALUE_PATTERNS:
                if pattern.search(candidate):
                    raise ReviewBlocked(f"{label} contains prohibited private/raw value marker")


def _machine_state(
    manifest: dict[str, Any],
    manifest_path: Path,
    run_id: str,
    final_status: str,
    stages: list[dict[str, Any]],
    outputs: dict[str, str],
    block_reason: str | None = None,
) -> dict[str, Any]:
    requested_claims = manifest.get("requested_claims", []) if manifest else []
    return {
        "schema_version": MACHINE_STATE_VERSION,
        "engine_version": ENGINE_VERSION,
        "run_id": run_id,
        "artifact_id": manifest.get("artifact_id", "UNKNOWN") if manifest else "UNKNOWN",
        "manifest_path": _display_path(manifest_path),
        "stages": stages,
        "outputs": outputs,
        "final_status": final_status,
        "block_reason": block_reason,
        "allowed_claim": _allowed_claims_for(manifest)[0] if final_status == "PASS" and manifest else None,
        "requested_claims": requested_claims,
        "blocked_claims": _blocked_claims(),
        "proof_boundary": manifest.get("proof_boundary", "fixture-only; not public proof") if manifest else "manifest blocked before proof boundary established",
        "runtime_boundary": manifest.get("runtime_boundary", "runtime prohibited") if manifest else "runtime prohibited",
        "signal_boundary": manifest.get("signal_boundary", "synthetic fixture signal only") if manifest else "synthetic fixture signal only",
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "human_review_required": True,
        "ai_disposition_authority": False,
        "endpoint_mutation": False,
        "wazuh_mutation": False,
        "runtime_proof": False,
        "private_evidence_committed": False,
        "public_proof_promoted": False,
        "lifetime_ledger_changed": False,
        "next_gate": manifest.get("next_gate", "human_review_gate") if manifest else "manifest_fix_required",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "product": PRODUCT,
    }


def _stage(stage_name: str, status: str, output_ref: str | None, summary: str, failure_mode: str | None = None) -> dict[str, Any]:
    return {
        "stage_name": stage_name,
        "status": status,
        "input_refs": ["artifact-manifest.json"],
        "output_ref": output_ref,
        "proof_boundary": "fixture-only; NOT_PUBLIC_SAFE; not runtime proof",
        "failure_mode": failure_mode,
        "claim_boundary": "unsupported public, runtime, production, customer, SOCaaS, autonomous, approval, authorization, and case-closure claims block",
        "summary": summary,
    }


def _pass_stages(outputs: dict[str, str]) -> list[dict[str, Any]]:
    summaries = {
        "artifact_intake": "manifest accepted and intake created",
        "evidence_graph": "evidence graph linked local fixture review nodes",
        "telemetry_contract_check": "declared fixture selector and source metadata checked",
        "controlled_validation": "positive and negative bundled fixtures validated",
        "synthetic_signal": "safe fixture signal simulated without endpoint mutation",
        "enrichment": "ATT&CK, event, source, and field mapping attached",
        "triage": "reviewer-readable triage summary generated",
        "proofcard": "ProofCard rendered under fixture-only ceiling",
        "claim_authority": "Claim Authority allowed bounded claim and blocked stronger claims",
        "reviewer_pack": "reviewer pack generated",
        "machine_state": "replayable machine-state generated",
    }
    return [_stage(name, "PASS", outputs.get(name), summaries[name]) for name in STAGE_REGISTRY]


def _blocked_stages(block_reason: str, outputs: dict[str, str]) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = []
    blocked_seen = False
    for name in STAGE_REGISTRY:
        if name == "artifact_intake":
            stages.append(_stage(name, "BLOCKED", outputs.get("blocked_review"), block_reason, block_reason))
            blocked_seen = True
        else:
            stages.append(_stage(name, "SKIPPED" if blocked_seen else "BLOCKED", None, "skipped after fail-closed gate", block_reason))
    return stages


def _reviewer_pack(manifest: dict[str, Any], state: dict[str, Any]) -> str:
    lines = [
        "# Hoxline Review Engine v1 Reviewer Pack",
        "",
        "## What This Is",
        "",
        "A deterministic local review of an artifact manifest through the Hoxline ProofOps machine.",
        "",
        "## What Happened",
        "",
        f"Artifact `{state['artifact_id']}` ran through artifact intake, evidence graph, telemetry contract check, controlled validation, synthetic signal, enrichment, triage, ProofCard, Claim Authority, reviewer pack, and machine-state stages.",
        "",
        "## Stage Table",
        "",
        "| Stage | Status | Summary |",
        "|---|---|---|",
    ]
    lines.extend(f"| `{stage['stage_name']}` | `{stage['status']}` | {stage['summary']} |" for stage in state["stages"])
    lines.extend(
        [
            "",
            "## What Hoxline Allowed",
            "",
            f"- {state['allowed_claim']}",
            "",
            "## What Hoxline Blocked",
            "",
        ]
    )
    lines.extend(f"- `{item['claim']}`: {item['safer_wording']}" for item in state["blocked_claims"])
    lines.extend(
        [
            "",
            "## What This Proves",
            "",
            "- The artifact manifest can be reviewed by deterministic local Hoxline stages.",
            "- The engine can generate replayable machine-state and reviewer artifacts from public-safe synthetic fixtures.",
            "- Claim Authority blocks unsupported public, runtime, production, customer, SOCaaS, autonomous, approval, authorization, and case-closure claims.",
            "",
            "## What This Does Not Prove",
            "",
            "- It does not prove live runtime behavior.",
            "- It does not prove public signal observation.",
            "- It does not prove public-safe status, production readiness, deployment, approval, authorization, or case closure.",
            "- It does not touch endpoints, users, groups, Wazuh, Splunk, Cribl, private infrastructure, ledgers, or website proof state.",
            "",
            "## Output Files",
            "",
        ]
    )
    lines.extend(f"- `{name}`" for name in EXPECTED_PASS_OUTPUTS)
    lines.extend(
        [
            "",
            "## Final Claim Boundary",
            "",
            f"- public_safe_status: `{state['public_safe_status']}`",
            f"- human_review_required: `{str(state['human_review_required']).lower()}`",
            f"- ai_disposition_authority: `{str(state['ai_disposition_authority']).lower()}`",
            f"- next_gate: `{state['next_gate']}`",
            "",
        ]
    )
    return "\n".join(lines)


def _blocked_review(state: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Hoxline Review Engine v1 Blocked Review",
            "",
            f"Artifact: `{state.get('artifact_id')}`",
            f"Final status: `{state['final_status']}`",
            f"Block reason: {state['block_reason']}",
            "",
            "## Boundary",
            "",
            "- Fail-closed gate blocked the review before stronger claims could be emitted.",
            "- public_safe_status remains `NOT_PUBLIC_SAFE`.",
            "- human_review_required remains `true`.",
            "- ai_disposition_authority remains `false`.",
            "- runtime proof, public proof promotion, endpoint mutation, Wazuh mutation, and ledger changes remain false.",
            "",
        ]
    )


def _run_summary(manifest: dict[str, Any], state: dict[str, Any], outputs: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "review-run-summary-v1",
        "engine_version": ENGINE_VERSION,
        "run_id": state["run_id"],
        "artifact_id": state["artifact_id"],
        "manifest_version": manifest.get("manifest_version") if manifest else None,
        "final_status": state["final_status"],
        "block_reason": state.get("block_reason"),
        "outputs": outputs,
        "public_safe_status": state["public_safe_status"],
        "human_review_required": state["human_review_required"],
        "ai_disposition_authority": state["ai_disposition_authority"],
        "endpoint_mutation": state["endpoint_mutation"],
        "runtime_proof": state["runtime_proof"],
        "wazuh_mutation": state["wazuh_mutation"],
        "private_evidence_committed": state["private_evidence_committed"],
        "public_proof_promoted": state["public_proof_promoted"],
        "lifetime_ledger_changed": state["lifetime_ledger_changed"],
    }


def _verify_pass_outputs(run_dir: Path, state: dict[str, Any], errors: list[str]) -> None:
    manifest = _load_json(run_dir / "artifact-manifest.json")
    telemetry = _load_json(run_dir / "telemetry-contract-check.json")
    validation = _load_json(run_dir / "validation-result.json")
    signal = _load_json(run_dir / "synthetic-signal.json")
    proofcard = _load_json(run_dir / "proofcard.json")
    claim_authority = _load_json(run_dir / "claim-authority.json")
    reviewer_pack = (run_dir / "reviewer-pack.md").read_text(encoding="utf-8")
    if telemetry.get("required_source") != manifest.get("telemetry_contract", {}).get("source"):
        errors.append("telemetry contract source must match artifact manifest")
    if sorted(telemetry.get("event_ids", [])) != sorted(manifest.get("expected_event_ids", [])):
        errors.append("telemetry contract event IDs must match artifact manifest")
    if sorted(telemetry.get("event_keys", [])) != sorted(manifest.get("expected_event_keys", [])):
        errors.append("telemetry contract event keys must match artifact manifest")
    if sorted(telemetry.get("wazuh_rule_family", [])) != sorted(manifest.get("expected_rule_ids", [])):
        errors.append("telemetry contract Wazuh rule metadata must match artifact manifest")
    if validation.get("result") != "pass" or validation.get("endpoint_mutation") is not False:
        errors.append("controlled validation must pass without endpoint mutation")
    if signal.get("source") != "safe bundled fixture" or signal.get("detection_fired") is not True:
        errors.append("synthetic signal must fire only from safe bundled fixture")
    if proofcard.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        errors.append("ProofCard must preserve NOT_PUBLIC_SAFE")
    blocked = {item.get("claim") for item in claim_authority.get("blocked_claims", [])}
    missing = [claim for claim in BLOCKED_CLAIM_FAMILIES if claim not in blocked]
    if missing:
        errors.append(f"blocked claims missing: {', '.join(missing)}")
    for heading in ("## What This Proves", "## What This Does Not Prove"):
        if heading not in reviewer_pack:
            errors.append(f"reviewer pack missing heading: {heading}")


def _blocked_claims() -> list[dict[str, str]]:
    return [
        {
            "claim": claim,
            "status": "BLOCKED",
            "safer_wording": {
                "production ready": "production readiness is not asserted",
                "public-safe runtime proof": "public-safe runtime proof is not asserted",
                "SOCaaS deployed": "SOCaaS deployment is not asserted",
                "customer deployed": "customer deployment is not asserted",
                "autonomous SOC": "autonomous SOC operation is not asserted",
                "AI-approved disposition": "AI-approved disposition is not asserted",
                "analyst-approved disposition": "analyst-approved disposition is not asserted",
                "final authorization": "final authorization is not asserted",
                "case closure": "case closure is not asserted",
                "website rendering as proof": "website rendering is not proof",
                "green CI as approval": "green CI is not approval",
            }[claim],
        }
        for claim in BLOCKED_CLAIM_FAMILIES
    ]


def _prepare_output_dir(output_dir: Path, force: bool) -> None:
    resolved = output_dir.resolve()
    if resolved == Path(resolved.anchor) or resolved == Path.cwd().resolve():
        raise ReviewEngineError("output directory must be a dedicated run directory")
    if output_dir.is_symlink():
        raise ReviewEngineError("output directory must not be a symbolic link")
    marker = output_dir / ".hoxline-review-output-v1"
    if output_dir.exists():
        if not force:
            raise ReviewEngineError(f"output directory already exists: {_display_path(output_dir)}")
        if not marker.is_file():
            raise ReviewEngineError("refusing to replace a directory not created by Hoxline Review Engine")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    marker.write_text("generated review output; safe to replace with --force\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_file_map(output_dir: Path, file_map: dict[str, Any]) -> None:
    for name, value in file_map.items():
        normalized = _normalize_repo_relative_path(name, "generated output path")
        path = (output_dir / normalized).resolve()
        if not _is_relative_to(path, output_dir.resolve()):
            raise ReviewEngineError("generated output path escapes its run root")
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _private_output_hits(run_dir: Path) -> list[str]:
    hits: list[str] = []
    for path in run_dir.rglob("*"):
        if not path.is_file() or path.suffix not in {".json", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        if ABSOLUTE_LOCAL_PATH.search(text):
            hits.append(f"{path.name}:absolute-local-path")
        for pattern in PRIVATE_VALUE_PATTERNS:
            if pattern.search(text):
                hits.append(f"{path.name}:{pattern.pattern}")
    return hits


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    repo_root = Path(__file__).resolve().parents[2]
    if _is_relative_to(resolved, repo_root):
        return resolved.relative_to(repo_root).as_posix()
    return resolved.name


def _resolve_path(path: Path, base: Path) -> Path:
    if path.is_absolute():
        return path
    return (base / path).resolve()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle, object_pairs_hook=_unique_json_object)
    except json.JSONDecodeError as exc:
        raise ReviewEngineError(f"input is not valid JSON: {_display_path(path)}") from exc
    if not isinstance(data, dict):
        raise ReviewEngineError(f"input must be a JSON object: {_display_path(path)}")
    return deepcopy(data)
