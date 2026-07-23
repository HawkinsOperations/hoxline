from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from .discovery import (
    REPO_NAMES,
    case_growth_files,
    discover_case_ids,
    file_sha256,
    git_blob_identity,
    git_commit_exists,
    last_git_update,
    load_structured,
    repo_branch,
    repo_dirty,
    repo_dirty_paths,
    repo_head_sha,
    repo_origin,
    repo_relative,
    resolve_repo_paths,
    semantic_fingerprint,
)


PROOF_CEILING = "CASE_GROWTH_INDEX_CONTROLLED_REPO_AGGREGATION_ONLY"

AUTHORITY_SOURCES = {
    ".github": ("org command-center routing", "governance/COMMAND_CENTER_INVARIANTS.json"),
    "hawkinsoperations-detections": ("detection source truth", "detections/DETECTION_PROMOTION_MATRIX.yml"),
    "hawkinsoperations-validation": ("controlled validation truth", "validation/VALIDATION_REGISTRY.yml"),
    "hawkinsoperations-platform": ("platform contract truth", "contracts/public-status-source-contract-v1.json"),
    "hawkinsoperations-proof": ("proof and claim-boundary truth", "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml"),
    "hawkinsoperations-website": ("rendering-only public status contract", "schemas/public-status-v0.schema.json"),
    "hoxline": ("case-growth and fixture-review product truth", "src/hoxline/case_growth/collector.py"),
}

CANONICAL_ORIGINS = {
    repository: f"github.com/HawkinsOperations/{repository}".casefold()
    for repository in REPO_NAMES
}

CONVERGENCE_SOURCE_MANIFEST = Path(".github/governance/CONVERGENCE_SOURCE_MANIFEST.json")
CONVERGENCE_SOURCE_MANIFEST_SCHEMA = "hawkinsoperations-convergence-source-manifest-v1"

BOUNDARY = {
    "runtime_public_proof_claimed": False,
    "signal_public_proof_claimed": False,
    "customer_deployment_claimed": False,
    "production_readiness_claimed": False,
    "public_safe_runtime_proof_claimed": False,
    "ai_approval_claimed": False,
    "analyst_approval_claimed": False,
    "final_authorization_claimed": False,
    "website_rendering_treated_as_proof": False,
    "green_ci_treated_as_approval": False,
}

ROW_FIELDS = [
    "case_id",
    "detection_id",
    "case_kind",
    "source_status",
    "source_evidence_refs",
    "validation_status",
    "validation_evidence_refs",
    "runtime_candidate_status",
    "runtime_evidence_refs",
    "scheduled_collector_status",
    "scheduled_collector_evidence_refs",
    "signal_status",
    "signal_evidence_refs",
    "proof_record_status",
    "proof_record_path",
    "proofcard_status",
    "proofcard_path",
    "claim_authority_status",
    "blocked_claim_count",
    "blocked_claims",
    "public_safe_status",
    "case_state",
    "metrics_available",
    "metrics_refs",
    "last_updated",
    "next_gate",
    "evidence_confidence",
    "notes",
]


def build_case_growth_index(repo_root: Path, generated_at: str | None = None) -> dict[str, Any]:
    repo_root = Path(repo_root)
    repo_paths = resolve_repo_paths(repo_root)
    if not any(path is not None for path in repo_paths.values()):
        raise ValueError(f"invalid repo root: no HawkinsOperations repos found under {repo_root}")
    if repo_paths.get("hoxline") is None:
        raise ValueError(f"invalid repo root: hoxline repo not found under {repo_root}")

    generated = generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    case_ids, scanned_count = discover_case_ids(repo_paths)
    rows: dict[str, dict[str, Any]] = {}
    data_quality_notes: list[str] = []

    repos_scanned = []
    for name in REPO_NAMES:
        path = repo_paths.get(name)
        repos_scanned.append(
            {
                "repo": name,
                "path": name if path is not None else "NOT_FOUND",
                "exists": path is not None,
                "branch": repo_branch(path) if path is not None else "NOT_FOUND",
                "dirty": repo_dirty(path) if path is not None else None,
                "authority_boundary": _repo_boundary(name),
                "files_scanned": len(case_growth_files(name, path)) if path is not None else 0,
            }
        )
        if path is None:
            data_quality_notes.append(f"{name} repo root NOT_FOUND during local aggregation")

    for case_id in sorted(case_ids):
        rows[case_id] = _base_row(case_id)

    _apply_detection_matrix(rows, repo_paths, data_quality_notes)
    _apply_validation_registry(rows, repo_paths, data_quality_notes)
    _apply_proof_index(rows, repo_paths, data_quality_notes)
    _apply_platform_contracts(rows, repo_paths, data_quality_notes)
    _apply_hoxline_metrics(rows, repo_paths, data_quality_notes)
    _apply_website_routes(rows, repo_paths)

    for row in rows.values():
        _finalize_row(row)
        _apply_last_updated(row, repo_paths)

    ordered_rows = [rows[key] for key in sorted(rows)]
    summary = _build_summary(ordered_rows)
    repo_slot_accuracy = _build_repo_slot_accuracy(repo_root, repo_paths)
    case_growth_health = _build_case_growth_health(summary)
    _add_cross_repo_quality_notes(ordered_rows, data_quality_notes)

    source_revisions = _build_source_revisions(repo_paths)
    contradictions, drift = _source_convergence_findings(repo_paths, source_revisions, summary, ordered_rows)
    global_current_authority = (
        not contradictions
        and not drift
        and all(item.get("current_authority") is True for item in source_revisions)
    )
    result = {
        "schema_version": "case-growth-index-v1",
        "generated_at": generated,
        "repo_root": "HawkinsOperations",
        "proof_ceiling": PROOF_CEILING,
        "historical_snapshot": False,
        "current_authority": global_current_authority,
        "snapshot_state": {
            "freshness": "CURRENT" if global_current_authority else "BLOCKED",
            "historical_snapshot": False,
            "current_authority": global_current_authority,
            "identity_model": "repo_path_git_blob_and_semantic_fingerprint_with_separate_head_observation",
            "generated_consumers_are_authority": False,
        },
        "source_revisions": source_revisions,
        "source_manifest_digest": _source_manifest_digest(source_revisions),
        "contradictions": contradictions,
        "drift": drift,
        "next_legal_action": _next_legal_action(source_revisions, contradictions, drift),
        "repos_scanned": repos_scanned,
        "repo_slot_accuracy": repo_slot_accuracy,
        "source_files_scanned_count": scanned_count,
        "case_ids_discovered_count": len(rows),
        "summary": summary,
        "case_growth_health": case_growth_health,
        "cases": ordered_rows,
        "data_quality_notes": data_quality_notes,
        "boundary": deepcopy(BOUNDARY),
    }
    result["reproducibility_sha256"] = _reproducibility_hash(result)
    return result


def _repo_boundary(repo_name: str) -> str:
    return {
        ".github": "org metadata and reviewer routing only; not proof authority",
        "hawkinsoperations-detections": "source package and source status authority only",
        "hawkinsoperations-validation": "controlled validation authority only",
        "hawkinsoperations-platform": "platform runtime-candidate, collector, receipt, and ledger contract authority only",
        "hawkinsoperations-proof": "proof ceiling, proof record, ProofCard, public-safe, blocked-claim, and next-gate authority",
        "hawkinsoperations-website": "route/rendering surface only; not proof authority",
        "hoxline": "product metrics and Hoxline Gauntlet artifact authority only",
    }[repo_name]


def _normalized_origin(value: str) -> str:
    origin = value.strip().replace("\\", "/")
    origin = re.sub(r"^git@", "", origin)
    if origin.startswith("github.com:"):
        origin = origin.replace(":", "/", 1)
    origin = re.sub(r"^(?:https?|ssh)://", "", origin, flags=re.IGNORECASE)
    return origin.removesuffix(".git").rstrip("/").casefold()


def _git_output(repo: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0


def _load_convergence_source_selections(repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    root = Path(repo_root).resolve()
    manifest_path = root / CONVERGENCE_SOURCE_MANIFEST
    if not manifest_path.is_file():
        return {}, [f"missing explicit seven-source selection manifest: {CONVERGENCE_SOURCE_MANIFEST.as_posix()}"]
    command_center = root / ".github"
    manifest_relative = "governance/CONVERGENCE_SOURCE_MANIFEST.json"
    if _normalized_origin(repo_origin(command_center)) != CANONICAL_ORIGINS[".github"]:
        return {}, ["seven-source selection manifest owner origin is not canonical"]
    tracked_path = _git_output(command_center, "ls-files", "--error-unmatch", "--", manifest_relative)
    committed_blob = _git_output(command_center, "rev-parse", f"HEAD:{manifest_relative}")
    worktree_blob = _git_output(command_center, "hash-object", "--", manifest_relative)
    if tracked_path != manifest_relative or committed_blob is None or worktree_blob != committed_blob:
        return {}, ["seven-source selection manifest must be tracked and clean at the checked command-center head"]
    try:
        manifest = load_structured(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {}, [f"seven-source selection manifest is not strict valid JSON: {exc}"]
    if not isinstance(manifest, dict):
        return {}, ["seven-source selection manifest must be an object"]
    errors: list[str] = []
    unknown_top_level = sorted(set(manifest) - {"schema", "manifest_id", "repositories", "constraints"})
    if unknown_top_level:
        errors.append(f"seven-source selection manifest contains unsupported fields: {unknown_top_level}")
    if manifest.get("schema") != CONVERGENCE_SOURCE_MANIFEST_SCHEMA:
        errors.append(f"seven-source selection manifest schema must be {CONVERGENCE_SOURCE_MANIFEST_SCHEMA}")
    entries = manifest.get("repositories")
    if not isinstance(entries, list):
        return {}, [*errors, "seven-source selection manifest repositories must be a list"]
    selections: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("seven-source selection manifest entries must be objects")
            continue
        repository = entry.get("repository")
        if not isinstance(repository, str) or repository not in REPO_NAMES:
            errors.append(f"seven-source selection manifest has unknown repository {repository!r}")
            continue
        if repository in selections:
            errors.append(f"seven-source selection manifest duplicates repository {repository}")
            continue
        expected_canonical = f"HawkinsOperations/{repository}"
        if entry.get("canonical_repository") != expected_canonical:
            errors.append(f"{repository}: selected canonical repository must be {expected_canonical}")
        if repository == ".github":
            unknown = sorted(
                set(entry)
                - {"repository", "canonical_repository", "revision_source", "tree_source"}
            )
            if unknown:
                errors.append(f".github: selection contains unsupported fields: {unknown}")
            if entry.get("revision_source") != "github_event_sha" or entry.get("tree_source") != "github_event_tree":
                errors.append(".github: dynamic command-center selection must use event SHA and event tree")
        else:
            unknown = sorted(
                set(entry)
                - {"repository", "canonical_repository", "revision", "reviewed_tree_sha"}
            )
            if unknown:
                errors.append(f"{repository}: selection contains unsupported fields: {unknown}")
            revision = entry.get("revision")
            tree = entry.get("reviewed_tree_sha")
            if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                errors.append(f"{repository}: selected revision must be an immutable 40-character SHA")
            if not isinstance(tree, str) or re.fullmatch(r"[0-9a-f]{40}", tree) is None:
                errors.append(f"{repository}: reviewed tree must be a 40-character Git tree SHA")
        selections[repository] = entry
    missing = sorted(set(REPO_NAMES) - set(selections))
    if missing or len(selections) != len(REPO_NAMES):
        errors.append(f"seven-source selection manifest must name exactly seven repositories; missing={missing}")
    constraints = manifest.get("constraints")
    if not isinstance(constraints, dict):
        errors.append("seven-source selection manifest constraints must be an object")
    else:
        expected_constraint_keys = {
            "exact_repository_count",
            "read_only",
            "default_branch_fallback",
            "require_detached_exact_revision",
            "record_checked_revisions",
            "consumer_outputs_are_not_authority",
            "proof_ceiling",
        }
        unknown = sorted(set(constraints) - expected_constraint_keys)
        missing_constraints = sorted(expected_constraint_keys - set(constraints))
        if unknown or missing_constraints:
            errors.append(
                "seven-source selection manifest constraints must have exact fields; "
                f"missing={missing_constraints}, unsupported={unknown}"
            )
        for key, expected in {
            "exact_repository_count": 7,
            "read_only": True,
            "default_branch_fallback": False,
            "require_detached_exact_revision": True,
            "record_checked_revisions": True,
            "consumer_outputs_are_not_authority": True,
        }.items():
            if constraints.get(key) != expected:
                errors.append(f"seven-source selection manifest constraint {key} must be {expected!r}")
        if constraints.get("proof_ceiling") != "CONTROLLED_REPO_CONVERGENCE_AND_LOCAL_FIXTURE_REVIEW_ONLY":
            errors.append("seven-source selection manifest proof ceiling is unsupported")
    return selections, errors


def _verify_selected_source_checkout(
    root: Path,
    repository: str,
    selections: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if repository not in REPO_NAMES:
        return [f"unknown source repository {repository!r}"]
    repo = root / repository
    if not repo.is_dir():
        return [f"{repository}: selected source repository is missing"]
    head = repo_head_sha(repo)
    tree = _git_output(repo, "rev-parse", "HEAD^{tree}")
    if head == "UNKNOWN" or tree is None:
        return [f"{repository}: checked source head/tree is unavailable"]
    entry = selections[repository]
    if repository == ".github":
        observed = os.environ.get(
            "HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA",
            "",
        ).strip()
        detached = repo_branch(repo).startswith("UNKNOWN_WITH_REASON:")
        if detached and re.fullmatch(r"[0-9a-f]{40}", observed) is None:
            errors.append(
                ".github: detached command-center checkout requires "
                "HAWKINS_COMMAND_CENTER_IMMUTABLE_OBSERVED_SHA"
            )
        elif observed and observed != head:
            errors.append(
                ".github: checked command-center head differs from the immutable "
                "workflow observation"
            )
        return errors
    selected = str(entry["revision"])
    reviewed_tree = str(entry["reviewed_tree_sha"])
    selected_tree = _git_output(repo, "rev-parse", f"{selected}^{{tree}}")
    if selected_tree is not None and selected_tree != reviewed_tree:
        errors.append(f"{repository}: manifest reviewed tree disagrees with its selected revision")
    selected_exists = git_commit_exists(repo, selected)
    checked_head_is_behind = head != selected and selected_exists and _is_ancestor(repo, head, selected)
    selected_is_ancestor_of_head = head != selected and selected_exists and _is_ancestor(repo, selected, head)
    if checked_head_is_behind:
        errors.append(
            f"{repository}: checked head is behind the explicit selected revision; "
            "an arbitrary same-blob ancestor is not current authority"
        )
    rewritten_content_identity = (
        head != selected
        and not checked_head_is_behind
        and not selected_is_ancestor_of_head
    )
    if rewritten_content_identity and tree != reviewed_tree:
        errors.append(
            f"{repository}: checked tree does not match the explicit reviewed tree; "
            "refresh the immutable source selection after content changes"
        )
    return errors


def verify_selected_source_checkout(repo_root: Path, repository: str) -> list[str]:
    """Prove a checked source is the manifest-selected content, not an arbitrary same-blob ancestor."""
    root = Path(repo_root).resolve()
    selections, errors = _load_convergence_source_selections(root)
    if errors:
        return errors
    return _verify_selected_source_checkout(root, repository, selections)


def verify_all_selected_source_checkouts(repo_root: Path) -> list[str]:
    root = Path(repo_root).resolve()
    selections, errors = _load_convergence_source_selections(root)
    if errors:
        return errors
    for repository in REPO_NAMES:
        errors.extend(_verify_selected_source_checkout(root, repository, selections))
    return errors


def _build_source_revisions(repo_paths: dict[str, Path | None]) -> list[dict[str, Any]]:
    revisions: list[dict[str, Any]] = []
    for repository in REPO_NAMES:
        repo = repo_paths.get(repository)
        authority_role, relative_path = AUTHORITY_SOURCES[repository]
        source = repo / relative_path if repo is not None else None
        source_exists = source is not None and source.is_file()
        sha = repo_head_sha(repo) if repo is not None else "UNKNOWN"
        branch = repo_branch(repo) if repo is not None else "NOT_FOUND"
        dirty = repo_dirty(repo) if repo is not None else False
        dirty_paths = repo_dirty_paths(repo) if repo is not None else []
        authority_dirty = relative_path.replace("\\", "/").casefold() in {
            path.replace("\\", "/").casefold() for path in dirty_paths
        }
        origin = repo_origin(repo) if repo is not None else "UNKNOWN"
        canonical_origin = _normalized_origin(origin) == CANONICAL_ORIGINS[repository]
        if repo is None:
            freshness = "MISSING_REPOSITORY"
        elif not source_exists:
            freshness = "MISSING_AUTHORITY_SOURCE"
        elif sha == "UNKNOWN":
            freshness = "UNVERSIONED_SOURCE"
        elif authority_dirty:
            freshness = "WORKTREE_MODIFIED"
        elif not canonical_origin:
            freshness = "REPOSITORY_IDENTITY_INVALID"
        else:
            freshness = "CURRENT"
        blob_identity = git_blob_identity(repo, sha, relative_path) if repo is not None else None
        committed_fingerprint = hashlib.sha256(blob_identity[1]).hexdigest() if blob_identity is not None else None
        semantic = semantic_fingerprint(relative_path, blob_identity[1]) if blob_identity is not None else None
        revisions.append(
            {
                "repository": repository,
                "authority_role": authority_role,
                "resolved_ref": branch,
                "source_commit_sha": sha,
                "source_observed_head_sha": sha,
                "current_observed_head_sha": sha,
                "source_observation_kind": "reviewed_immutable_commit",
                "source_parent_sha": None,
                "self_referential": False,
                "revision_scope": "content_addressed_authority",
                "source_path": relative_path,
                "authoritative_path": relative_path,
                "authoritative_git_blob_sha": blob_identity[0] if blob_identity is not None else None,
                "source_git_blob_sha": blob_identity[0] if blob_identity is not None else None,
                "source_file_sha256": (
                    committed_fingerprint
                    if committed_fingerprint is not None
                    else file_sha256(source) if source_exists and source is not None else None
                ),
                "authoritative_content_fingerprint": semantic,
                "source_semantic_fingerprint_sha256": semantic,
                "canonical_origin": CANONICAL_ORIGINS[repository],
                "observed_origin": _normalized_origin(origin),
                "repository_dirty_observed": dirty,
                "authority_source_dirty": authority_dirty,
                "source_freshness_state": freshness,
                "snapshot_freshness_state": "CURRENT",
                "historical_snapshot": False,
                "current_authority": source_exists and sha != "UNKNOWN" and canonical_origin and not authority_dirty,
                "missing_source_state": not source_exists,
                "dangling_reference_state": repo is not None and not source_exists,
                "contradictions": [],
                "drift": [],
                "next_legal_action": (
                    "none; preserve source ownership"
                    if freshness == "CURRENT"
                    else "review and commit scoped authority-source changes before regenerating"
                    if freshness == "WORKTREE_MODIFIED"
                    else f"restore {repository}/{relative_path} from its owning repository"
                ),
            }
        )
    return revisions


def _finding(
    code: str,
    owner: str,
    path: str,
    expected: Any,
    actual: Any,
    remediation: str,
    classification: str = "ACTIONABLE_DRIFT",
) -> dict[str, Any]:
    return {
        "code": code,
        "source_owner": owner,
        "source_path": path,
        "expected": expected,
        "actual": actual,
        "classification": classification,
        "next_legal_action": remediation,
    }


def _duplicates(values: list[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


def _source_convergence_findings(
    repo_paths: dict[str, Path | None],
    source_revisions: list[dict[str, Any]],
    summary: dict[str, int],
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contradictions: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []
    for revision in source_revisions:
        if revision["missing_source_state"]:
            contradictions.append(
                _finding(
                    "MISSING_AUTHORITY_SOURCE",
                    revision["repository"],
                    revision["source_path"],
                    "existing authoritative source",
                    "missing",
                    revision["next_legal_action"],
                )
            )

    structured_sources = (
        ("hawkinsoperations-detections", "detections/DETECTION_PROMOTION_MATRIX.yml", "entries"),
        ("hawkinsoperations-validation", "validation/VALIDATION_REGISTRY.yml", "packages"),
        ("hawkinsoperations-proof", "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml", "entries"),
    )
    for owner, relative_path, collection in structured_sources:
        repo = repo_paths.get(owner)
        if repo is None or not (repo / relative_path).is_file():
            continue
        data = load_structured(repo / relative_path) or {}
        ids = [str(item.get("detection_id")) for item in data.get(collection, []) if isinstance(item, dict) and item.get("detection_id")]
        for duplicate in _duplicates(ids):
            contradictions.append(
                _finding(
                    "DUPLICATE_CASE_ID",
                    owner,
                    relative_path,
                    "one entry per case ID",
                    duplicate,
                    f"remove or reconcile the duplicate {duplicate} entry in the owning source",
                )
            )

    proof_repo = repo_paths.get("hawkinsoperations-proof")
    if proof_repo is not None:
        proof_path = proof_repo / AUTHORITY_SOURCES["hawkinsoperations-proof"][1]
        if proof_path.is_file():
            proof_data = load_structured(proof_path) or {}
            for entry in proof_data.get("entries", []):
                if not isinstance(entry, dict):
                    continue
                case_id = str(entry.get("detection_id") or "UNKNOWN")
                for field in ("proof_record_path", "proof_card_path"):
                    ref = entry.get(field)
                    if ref and not (proof_repo / str(ref)).is_file():
                        contradictions.append(
                            _finding(
                                "DANGLING_PROOF_PATH",
                                "hawkinsoperations-proof",
                                str(ref),
                                "existing source-controlled file",
                                f"missing reference for {case_id}",
                                f"repair or explicitly clear {field} for {case_id} in the proof index",
                            )
                        )

    detection_repo = repo_paths.get("hawkinsoperations-detections")
    if detection_repo is not None and proof_repo is not None:
        matrix_path = detection_repo / AUTHORITY_SOURCES["hawkinsoperations-detections"][1]
        proof_path = proof_repo / AUTHORITY_SOURCES["hawkinsoperations-proof"][1]
        if matrix_path.is_file() and proof_path.is_file():
            matrix_entries = {
                str(item.get("detection_id")): item
                for item in (load_structured(matrix_path) or {}).get("entries", [])
                if isinstance(item, dict) and item.get("detection_id")
            }
            proof_entries = {
                str(item.get("detection_id")): item
                for item in (load_structured(proof_path) or {}).get("entries", [])
                if isinstance(item, dict) and item.get("detection_id")
            }
            for case_id, proof_entry in proof_entries.items():
                matrix_entry = matrix_entries.get(case_id, {})
                notes = str(matrix_entry.get("notes") or "")
                if proof_entry.get("proof_record_path") and re.search(r"(?i)\bno\b.*\bproof record\b", notes):
                    contradictions.append(
                        _finding(
                            "DETECTION_PROOF_RECORD_CONTRADICTION",
                            "hawkinsoperations-detections",
                            "detections/DETECTION_PROMOTION_MATRIX.yml",
                            f"proof record exists at {proof_entry['proof_record_path']}",
                            notes,
                            f"update the detection matrix note for {case_id} from the proof-owned current index",
                        )
                    )

    website_repo = repo_paths.get("hawkinsoperations-website")
    if website_repo is not None:
        website_path = website_repo / "public" / "data" / "public-status.json"
        if website_path.is_file():
            website = load_structured(website_path) or {}
            rendered = ((website.get("metrics") or {}).get("proof_records") or {}).get("value")
            current = summary["proof_records_count"]
            if rendered is not None and rendered != current:
                drift.append(
                    _finding(
                        "WEBSITE_PROOF_COUNT_DRIFT",
                        "hawkinsoperations-proof",
                        "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml",
                        current,
                        rendered,
                        "regenerate website public status from the proof-owned current index; website remains rendering-only",
                    )
                )

    case_ids = [str(row.get("case_id")) for row in rows]
    for duplicate in _duplicates(case_ids):
        contradictions.append(
            _finding(
                "DUPLICATE_GENERATED_CASE_ID",
                "hoxline",
                "generated cases",
                "unique case IDs",
                duplicate,
                "reconcile duplicate source entries before regenerating the snapshot",
            )
        )
    return contradictions, drift


def _next_legal_action(
    source_revisions: list[dict[str, Any]], contradictions: list[dict[str, Any]], drift: list[dict[str, Any]]
) -> str:
    if contradictions:
        return str(contradictions[0]["next_legal_action"])
    if drift:
        return str(drift[0]["next_legal_action"])
    if any(item["source_freshness_state"] == "WORKTREE_MODIFIED" for item in source_revisions):
        return "commit only the validated scoped changes, then regenerate the current snapshot from clean source revisions"
    return "none; current source-controlled inputs converge"


def _reproducibility_hash(index: dict[str, Any]) -> str:
    stable = deepcopy(index)
    stable.pop("generated_at", None)
    stable.pop("reproducibility_sha256", None)
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _content_normalized_cases(value: Any) -> Any:
    """Remove only commit-clock observations after source currentness is verified separately."""
    if not isinstance(value, list):
        return value
    normalized = deepcopy(value)
    for row in normalized:
        if isinstance(row, dict):
            row.pop("last_updated", None)
    return normalized


def _source_manifest_digest(source_revisions: list[dict[str, Any]]) -> str:
    manifest = [
        {
            "repository": item.get("repository"),
            "authority_role": item.get("authority_role"),
            "authoritative_path": item.get("authoritative_path") or item.get("source_path"),
            "authoritative_git_blob_sha": item.get("authoritative_git_blob_sha"),
            "authoritative_content_fingerprint": item.get("authoritative_content_fingerprint"),
        }
        for item in source_revisions
    ]
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _base_row(case_id: str) -> dict[str, Any]:
    detection_id = None if case_id.startswith("HOX-GAUNTLET-") else case_id
    return {
        "case_id": case_id,
        "detection_id": detection_id,
        "case_kind": _case_kind(case_id),
        "source_status": "NOT_FOUND",
        "source_evidence_refs": [],
        "validation_status": "NOT_FOUND",
        "validation_evidence_refs": [],
        "runtime_candidate_status": "NOT_INDEXED",
        "runtime_evidence_refs": [],
        "scheduled_collector_status": "NOT_INDEXED",
        "scheduled_collector_evidence_refs": [],
        "signal_status": "NOT_PROVEN",
        "signal_evidence_refs": [],
        "proof_record_status": "NOT_PROVEN",
        "proof_record_path": None,
        "proofcard_status": "NOT_PROVEN",
        "proofcard_path": None,
        "claim_authority_status": "NOT_INDEXED",
        "blocked_claim_count": 0,
        "blocked_claims": [],
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "case_state": "UNKNOWN_WITH_REASON",
        "metrics_available": False,
        "metrics_refs": [],
        "last_updated": "UNKNOWN_WITH_REASON: no git history available",
        "next_gate": "UNKNOWN_WITH_REASON: no next gate indexed",
        "evidence_confidence": "LOW",
        "notes": [],
    }


def _case_kind(case_id: str) -> str:
    if case_id.startswith("HOX-GAUNTLET-"):
        return "gauntlet"
    if case_id.startswith("HO-NDR-"):
        return "ndr_boundary"
    if case_id.startswith("HO-PIPE-"):
        return "pipeline"
    if case_id.startswith("ID-DET-"):
        return "identity_detection"
    if case_id.startswith("AWS-DET-"):
        return "cloud_detection"
    if case_id.startswith("HOD-"):
        return "legacy_detection"
    return "detection"


def _ensure(rows: dict[str, dict[str, Any]], case_id: str) -> dict[str, Any]:
    if case_id not in rows:
        rows[case_id] = _base_row(case_id)
    return rows[case_id]


def _add_refs(row: dict[str, Any], field: str, refs: list[str]) -> None:
    current = list(row[field])
    for ref in refs:
        if ref and ref not in current:
            current.append(ref)
    row[field] = current


def _apply_detection_matrix(rows: dict[str, dict[str, Any]], repo_paths: dict[str, Path | None], notes: list[str]) -> None:
    repo = repo_paths.get("hawkinsoperations-detections")
    if repo is None:
        return
    path = repo / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
    if not path.exists():
        notes.append("detections/DETECTION_PROMOTION_MATRIX.yml NOT_FOUND")
        return
    data = load_structured(path) or {}
    matrix_ref = repo_relative("hawkinsoperations-detections", repo, path)
    for entry in data.get("entries", []):
        if not isinstance(entry, dict) or "detection_id" not in entry:
            continue
        row = _ensure(rows, str(entry["detection_id"]))
        row["source_status"] = str(entry.get("source_status") or "UNKNOWN_WITH_REASON")
        row["public_safe_status"] = str(entry.get("public_safe_status") or row["public_safe_status"])
        row["case_kind"] = entry.get("detection_family") or row["case_kind"]
        refs = [matrix_ref]
        package_path = str(entry.get("package_path") or "")
        required = entry.get("required_files") if isinstance(entry.get("required_files"), list) else []
        if package_path and not package_path.startswith(("planned://", "external://")):
            refs.append(f"hawkinsoperations-detections/{package_path}")
            for required_file in required:
                refs.append(f"hawkinsoperations-detections/{package_path}/{required_file}")
        _add_refs(row, "source_evidence_refs", refs)
        _merge_blocked_claims(row, entry.get("blocked_claims"))
        if entry.get("next_gate"):
            row["next_gate"] = str(entry["next_gate"])
        if entry.get("notes"):
            row["notes"].append(f"detections: {entry['notes']}")


def _apply_validation_registry(rows: dict[str, dict[str, Any]], repo_paths: dict[str, Path | None], notes: list[str]) -> None:
    repo = repo_paths.get("hawkinsoperations-validation")
    if repo is None:
        return
    path = repo / "validation" / "VALIDATION_REGISTRY.yml"
    if not path.exists():
        notes.append("validation/VALIDATION_REGISTRY.yml NOT_FOUND")
        return
    data = load_structured(path) or {}
    registry_ref = repo_relative("hawkinsoperations-validation", repo, path)
    for entry in data.get("packages", []):
        if not isinstance(entry, dict) or "detection_id" not in entry:
            continue
        row = _ensure(rows, str(entry["detection_id"]))
        ceiling = str(entry.get("proof_ceiling") or "UNKNOWN_WITH_REASON")
        if "CONTROLLED_TEST_VALIDATED" in ceiling:
            row["validation_status"] = "CONTROLLED_TEST_VALIDATED"
        elif "VALIDATION_CONTRACT_ENFORCED" in ceiling:
            row["validation_status"] = "VALIDATION_CONTRACT_ENFORCED"
        else:
            row["validation_status"] = ceiling
        refs = [registry_ref]
        for key in ("validation_package_path", "fixture_file", "report_json", "report_markdown", "validator_script", "parity_script"):
            value = entry.get(key)
            if value:
                refs.append(f"hawkinsoperations-validation/{value}")
        _add_refs(row, "validation_evidence_refs", refs)
        if entry.get("notes"):
            row["notes"].append(f"validation: {entry['notes']}")
    for bridge in data.get("bridge_records", []):
        if isinstance(bridge, dict) and bridge.get("detection_id"):
            row = _ensure(rows, str(bridge["detection_id"]))
            _add_refs(
                row,
                "validation_evidence_refs",
                [
                    registry_ref,
                    f"hawkinsoperations-validation/{bridge.get('bridge_record_path')}",
                    f"hawkinsoperations-validation/{bridge.get('bridge_markdown_path')}",
                ],
            )


def _apply_proof_index(rows: dict[str, dict[str, Any]], repo_paths: dict[str, Path | None], notes: list[str]) -> None:
    repo = repo_paths.get("hawkinsoperations-proof")
    if repo is None:
        return
    path = repo / "proof" / "indexes" / "DETECTION_PROOF_STATUS_INDEX.yml"
    if not path.exists():
        notes.append("proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml NOT_FOUND")
        return
    data = load_structured(path) or {}
    index_ref = repo_relative("hawkinsoperations-proof", repo, path)
    for entry in data.get("entries", []):
        if not isinstance(entry, dict) or "detection_id" not in entry:
            continue
        row = _ensure(rows, str(entry["detection_id"]))
        for field in ("source_status", "validation_status", "signal_status", "public_safe_status"):
            if entry.get(field):
                row[field] = str(entry[field])
        runtime_status = str(entry.get("runtime_status") or "NOT_PROVEN")
        row["runtime_candidate_status"] = runtime_status
        proof_path = entry.get("proof_record_path")
        card_path = entry.get("proof_card_path")
        row["proof_record_path"] = proof_path
        row["proofcard_path"] = card_path
        row["proof_record_status"] = "PROOF_RECORD_EXISTS" if proof_path and (repo / str(proof_path)).exists() else "NOT_PROVEN"
        row["proofcard_status"] = "PROOFCARD_EXISTS" if card_path and (repo / str(card_path)).exists() else "NOT_PROVEN"
        if entry.get("next_gate"):
            row["next_gate"] = str(entry["next_gate"])
        if entry.get("notes"):
            row["notes"].append(f"proof: {entry['notes']}")
        row["claim_authority_status"] = str(
            (entry.get("candidate_review_state") or {}).get("claim_authority") or "BLOCKED_CLAIMS_INDEXED"
        )
        _merge_blocked_claims(row, entry.get("blocked_claims"))
        proof_refs = [index_ref]
        if proof_path:
            proof_refs.append(f"hawkinsoperations-proof/{proof_path}")
        _add_refs(row, "runtime_evidence_refs", proof_refs if runtime_status != "NOT_PROVEN" else [index_ref])
        _add_refs(row, "signal_evidence_refs", [index_ref])


def _apply_platform_contracts(rows: dict[str, dict[str, Any]], repo_paths: dict[str, Path | None], notes: list[str]) -> None:
    repo = repo_paths.get("hawkinsoperations-platform")
    if repo is None:
        return
    eligibility = repo / "contracts" / "examples" / "runtime-collector-eligibility-v0.sample.json"
    if eligibility.exists():
        data = load_structured(eligibility) or {}
        ref = repo_relative("hawkinsoperations-platform", repo, eligibility)
        for entry in data.get("detections", []):
            if not isinstance(entry, dict) or not entry.get("detection_id"):
                continue
            row = _ensure(rows, str(entry["detection_id"]))
            status = str(entry.get("current_safe_status") or entry.get("collector_eligibility") or "NOT_INDEXED")
            if entry.get("collector_target_proven") or entry.get("collector_row_observed"):
                row["runtime_candidate_status"] = "PRIVATE_RUNTIME_CANDIDATE"
            elif row["runtime_candidate_status"] in {"NOT_INDEXED", "NOT_FOUND"}:
                row["runtime_candidate_status"] = status
            _add_refs(row, "runtime_evidence_refs", [ref])
            if entry.get("next_gate") and row["next_gate"].startswith("UNKNOWN_WITH_REASON"):
                row["next_gate"] = str(entry["next_gate"])
    else:
        notes.append("platform runtime collector eligibility sample NOT_FOUND")

    workflow = repo / ".github" / "workflows" / "hoxline-schedule-gated-collection.yml"
    if workflow.exists():
        text = workflow.read_text(encoding="utf-8", errors="ignore")
        ref = repo_relative("hawkinsoperations-platform", repo, workflow)
        for detection_id in sorted(set(re.findall(r"--detection-id\s+([A-Z]+-[A-Z]+-\d{3})", text))):
            row = _ensure(rows, detection_id)
            row["scheduled_collector_status"] = "SCHEDULED_COLLECTOR_LANE_PRESENT_GATED"
            if row["runtime_candidate_status"] in {"NOT_INDEXED", "NOT_FOUND", "NOT_PROVEN"}:
                row["runtime_candidate_status"] = "PRIVATE_RUNTIME_CANDIDATE"
            _add_refs(row, "scheduled_collector_evidence_refs", [ref])
            _add_refs(row, "runtime_evidence_refs", [ref])
    else:
        notes.append("platform hoxline-schedule-gated-collection workflow NOT_FOUND")

    manifest = repo / "contracts" / "lifetime-case-ledger-v1-state-manifest.json"
    if manifest.exists():
        data = load_structured(manifest) or {}
        ref = repo_relative("hawkinsoperations-platform", repo, manifest)
        for detection_id in data.get("appended_detection_ids", []):
            row = _ensure(rows, str(detection_id))
            _add_refs(row, "runtime_evidence_refs", [ref])
        if (data.get("current_ledger_counts") or {}).get("closed_case_count") == 0:
            notes.append("platform lifetime ledger manifest reports closed_case_count=0")


def _apply_hoxline_metrics(rows: dict[str, dict[str, Any]], repo_paths: dict[str, Path | None], notes: list[str]) -> None:
    repo = repo_paths.get("hoxline")
    if repo is None:
        return
    for path in case_growth_files("hoxline", repo):
        if path.suffix.lower() != ".json":
            continue
        try:
            data = load_structured(path)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        artifact_id = data.get("artifact_id")
        if data.get("schema_version") == "work-impact-metrics-v0" and isinstance(artifact_id, str):
            row = _ensure(rows, artifact_id)
            row["case_kind"] = "gauntlet" if artifact_id.startswith("HOX-GAUNTLET-") else row["case_kind"]
            row["source_status"] = "SOURCE_EXISTS"
            row["validation_status"] = str(data.get("proof_ceiling") or "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY")
            row["metrics_available"] = True
            row["public_safe_status"] = "NOT_PUBLIC_SAFE"
            row["claim_authority_status"] = "BLOCKED_CLAIMS_INDEXED"
            row["next_gate"] = "human review before runtime, signal, customer, production, public wording, or final human gate promotion"
            ref = repo_relative("hoxline", repo, path)
            _add_refs(row, "source_evidence_refs", [ref])
            _add_refs(row, "validation_evidence_refs", [ref])
            _add_refs(row, "metrics_refs", [ref])
            boundary = data.get("boundary") if isinstance(data.get("boundary"), dict) else {}
            for key, value in boundary.items():
                if value is True:
                    notes.append(f"hoxline metrics boundary unexpected true value: {key}")
            gaps = data.get("evidence_gaps") if isinstance(data.get("evidence_gaps"), dict) else {}
            row["notes"].append(f"hoxline metrics evidence gaps indexed: {', '.join(sorted(gaps))}")


def _apply_website_routes(rows: dict[str, dict[str, Any]], repo_paths: dict[str, Path | None]) -> None:
    repo = repo_paths.get("hawkinsoperations-website")
    if repo is None:
        return
    for path in case_growth_files("hawkinsoperations-website", repo):
        if path.suffix.lower() not in {".ts", ".tsx", ".md", ".json"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for case_id in set(re.findall(r"\b(?:HO-DET-\d{3}|ID-DET-\d{3}|AWS-DET-\d{3}|HO-NDR-\d{3})\b", text)):
            if case_id in rows:
                rows[case_id]["notes"].append(
                    f"website route/rendering mention observed at {repo_relative('hawkinsoperations-website', repo, path)}; not treated as proof"
                )


def _merge_blocked_claims(row: dict[str, Any], claims: Any) -> None:
    if not isinstance(claims, list):
        return
    merged = list(row["blocked_claims"])
    for claim in claims:
        claim_text = str(claim)
        if claim_text not in merged:
            merged.append(claim_text)
    row["blocked_claims"] = merged
    row["blocked_claim_count"] = len(merged)


def _finalize_row(row: dict[str, Any]) -> None:
    if row["proof_record_path"] is None and row["proof_record_status"] == "NOT_PROVEN":
        row["proof_record_path"] = None
    if row["proofcard_path"] is None and row["proofcard_status"] == "NOT_PROVEN":
        row["proofcard_path"] = None
    row["blocked_claim_count"] = len(row["blocked_claims"])
    if row["blocked_claim_count"] and row["claim_authority_status"] == "NOT_INDEXED":
        row["claim_authority_status"] = "BLOCKED_CLAIMS_INDEXED"
    row["evidence_confidence"] = _confidence(row)
    row["case_state"] = _case_state(row)
    for field in ROW_FIELDS:
        row.setdefault(field, _base_row(str(row.get("case_id", "UNKNOWN")))[field])


def _confidence(row: dict[str, Any]) -> str:
    refs = sum(len(row[field]) for field in ("source_evidence_refs", "validation_evidence_refs", "runtime_evidence_refs", "metrics_refs"))
    if row["proof_record_status"] == "PROOF_RECORD_EXISTS" and row["validation_status"] == "CONTROLLED_TEST_VALIDATED":
        return "HIGH"
    if refs >= 3:
        return "MEDIUM"
    return "LOW"


def _case_state(row: dict[str, Any]) -> str:
    if row.get("_explicit_closed"):
        return "CLOSED"
    if row["public_safe_status"] in {"PUBLIC_SAFE", "APPROVED_PUBLIC_SAFE"}:
        return "PUBLIC_SAFE"
    if row["blocked_claim_count"] or not str(row["next_gate"]).startswith("UNKNOWN_WITH_REASON"):
        return "BLOCKED_WAITING_NEXT_GATE"
    if row["runtime_candidate_status"] == "PRIVATE_RUNTIME_EVIDENCE_CAPTURED":
        return "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"
    if row["runtime_candidate_status"] == "PRIVATE_RUNTIME_CANDIDATE":
        return "PRIVATE_RUNTIME_CANDIDATE"
    if row["metrics_available"]:
        return "METRICS_AVAILABLE"
    if row["validation_status"] == "CONTROLLED_TEST_VALIDATED":
        return "CONTROLLED_VALIDATION"
    if row["source_status"] == "SOURCE_EXISTS":
        return "SOURCE_ONLY"
    return "UNKNOWN_WITH_REASON"


def _apply_last_updated(row: dict[str, Any], repo_paths: dict[str, Path | None]) -> None:
    candidates: list[str] = []
    for field in (
        "source_evidence_refs",
        "validation_evidence_refs",
        "runtime_evidence_refs",
        "scheduled_collector_evidence_refs",
        "signal_evidence_refs",
        "metrics_refs",
    ):
        for ref in row[field]:
            repo_name, _, rel = ref.partition("/")
            repo = repo_paths.get(repo_name)
            if repo is not None and rel:
                updated = last_git_update(repo, rel)
                if updated:
                    candidates.append(updated)
    if candidates:
        row["last_updated"] = max(candidates)


def _build_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "cases_total": len(rows),
        "source_packages_count": sum(1 for row in rows if row["source_status"] == "SOURCE_EXISTS"),
        "controlled_validations_count": sum(1 for row in rows if row["validation_status"] == "CONTROLLED_TEST_VALIDATED"),
        "runtime_candidate_lanes_count": sum(
            1
            for row in rows
            if row["runtime_candidate_status"] in {"PRIVATE_RUNTIME_CANDIDATE", "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"}
        ),
        "private_runtime_evidence_captured_count": sum(
            1 for row in rows if row["runtime_candidate_status"] == "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"
        ),
        "scheduled_collector_lanes_count": sum(
            1 for row in rows if row["scheduled_collector_status"] == "SCHEDULED_COLLECTOR_LANE_PRESENT_GATED"
        ),
        "proof_records_count": sum(1 for row in rows if row["proof_record_status"] == "PROOF_RECORD_EXISTS"),
        "proofcards_count": sum(1 for row in rows if row["proofcard_status"] == "PROOFCARD_EXISTS"),
        "claim_authority_cases_count": sum(1 for row in rows if row["claim_authority_status"] != "NOT_INDEXED"),
        "metrics_available_count": sum(1 for row in rows if row["metrics_available"]),
        "public_safe_cases_count": sum(1 for row in rows if row["public_safe_status"] == "PUBLIC_SAFE"),
        "closed_cases_count": sum(1 for row in rows if row["case_state"] == "CLOSED"),
        "blocked_claims_count": sum(int(row["blocked_claim_count"]) for row in rows),
        "cases_with_next_gate_count": sum(1 for row in rows if not str(row["next_gate"]).startswith("UNKNOWN_WITH_REASON")),
        "cases_missing_proof_record_count": sum(1 for row in rows if row["proof_record_status"] != "PROOF_RECORD_EXISTS"),
        "cases_missing_proofcard_count": sum(1 for row in rows if row["proofcard_status"] != "PROOFCARD_EXISTS"),
        "cases_not_public_safe_count": sum(1 for row in rows if row["public_safe_status"] != "PUBLIC_SAFE"),
        "unknown_state_count": sum(1 for row in rows if row["case_state"] == "UNKNOWN_WITH_REASON"),
    }


def _build_repo_slot_accuracy(repo_root: Path, repo_paths: dict[str, Path | None]) -> dict[str, Any]:
    present = [name for name in REPO_NAMES if repo_paths.get(name) is not None]
    missing = [name for name in REPO_NAMES if repo_paths.get(name) is None]
    github_org_root = repo_root / ".github"
    github_sibling = repo_root.parent / "HawkinsOperations.github"
    if not missing:
        wording = "seven expected repo slots evaluated; seven present local repos scanned"
    else:
        wording = (
            f"seven expected repo slots evaluated; {len(present)} present local repos scanned; "
            f"missing local repo slots: {', '.join(missing)}"
        )
    return {
        "expected_repo_slots": len(REPO_NAMES),
        "present_local_repos": len(present),
        "missing_local_repos": missing,
        "github_org_root_exists": github_org_root.exists(),
        "hawkinsoperations_github_sibling_exists": github_sibling.exists(),
        "wording": wording,
    }


def _build_case_growth_health(summary: dict[str, int]) -> dict[str, Any]:
    cases_total = summary["cases_total"]
    source_packages = summary["source_packages_count"]
    health = {
        "validation_coverage_percent": _percent(summary["controlled_validations_count"], source_packages),
        "proof_record_coverage_percent": _percent(summary["proof_records_count"], cases_total),
        "proofcard_coverage_percent": _percent(summary["proofcards_count"], cases_total),
        "scheduled_collector_coverage_percent": _percent(summary["scheduled_collector_lanes_count"], cases_total),
        "runtime_candidate_coverage_percent": _percent(summary["runtime_candidate_lanes_count"], cases_total),
        "metrics_coverage_percent": _percent(summary["metrics_available_count"], cases_total),
        "public_safe_percent": _percent(summary["public_safe_cases_count"], cases_total),
        "closed_case_percent": _percent(summary["closed_cases_count"], cases_total),
        "blocked_claim_density": _ratio(summary["blocked_claims_count"], cases_total),
        "next_gate_coverage_percent": _percent(summary["cases_with_next_gate_count"], cases_total),
        "missing_proof_record_percent": _percent(summary["cases_missing_proof_record_count"], cases_total),
        "missing_proofcard_percent": _percent(summary["cases_missing_proofcard_count"], cases_total),
        "not_public_safe_percent": _percent(summary["cases_not_public_safe_count"], cases_total),
    }
    bottlenecks = _health_bottlenecks(summary, health)
    health.update(
        {
            "overall_health_status": _health_status(summary, health),
            "strongest_lane": _strongest_lane(health),
            "weakest_lane": _weakest_lane(health),
            "top_bottlenecks": bottlenecks,
            "recommended_next_build": _recommended_next_build(summary, health),
        }
    )
    return health


def _percent(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 2)


def _health_bottlenecks(summary: dict[str, int], health: dict[str, Any]) -> list[str]:
    bottlenecks: list[str] = []
    if summary["cases_total"] and summary["public_safe_cases_count"] == 0 and summary["cases_not_public_safe_count"] == summary["cases_total"]:
        bottlenecks.append("public_safe blocked for all indexed cases")
    if health["missing_proof_record_percent"] > 50:
        bottlenecks.append("proof records missing for most indexed cases")
    if health["missing_proofcard_percent"] > 50:
        bottlenecks.append("ProofCards missing for most indexed cases")
    if health["metrics_coverage_percent"] < 25:
        bottlenecks.append("case-level metrics available for only a small share of indexed cases")
    if not bottlenecks:
        bottlenecks.append("no dominant bottleneck detected from current summary counts")
    return bottlenecks[:4]


def _health_status(summary: dict[str, int], health: dict[str, Any]) -> str:
    if summary["cases_total"] == 0:
        return "UNKNOWN_WITH_REASON"
    if summary["public_safe_cases_count"] == 0 and summary["cases_not_public_safe_count"] == summary["cases_total"]:
        return "PUBLIC_SAFE_BLOCKED"
    if health["missing_proof_record_percent"] > 50 or health["missing_proofcard_percent"] > 50:
        return "PROOF_GAP_DOMINANT"
    if summary["runtime_candidate_lanes_count"] > 0 or summary["scheduled_collector_lanes_count"] > 0:
        return "RUNTIME_CANDIDATE_FORMING"
    if summary["controlled_validations_count"] >= max(1, int(summary["source_packages_count"] * 0.75)):
        return "CONTROLLED_VALIDATION_HEAVY"
    return "EARLY_PIPELINE_REAL"


def _strongest_lane(health: dict[str, Any]) -> str:
    candidates = {
        "controlled_validation": health["validation_coverage_percent"],
        "proof_records": health["proof_record_coverage_percent"],
        "proofcards": health["proofcard_coverage_percent"],
        "scheduled_collectors": health["scheduled_collector_coverage_percent"],
        "runtime_candidates": health["runtime_candidate_coverage_percent"],
        "metrics": health["metrics_coverage_percent"],
        "public_safe": health["public_safe_percent"],
        "closed_cases": health["closed_case_percent"],
    }
    return max(candidates, key=candidates.get)


def _weakest_lane(health: dict[str, Any]) -> str:
    candidates = {
        "proof_records": health["proof_record_coverage_percent"],
        "proofcards": health["proofcard_coverage_percent"],
        "scheduled_collectors": health["scheduled_collector_coverage_percent"],
        "runtime_candidates": health["runtime_candidate_coverage_percent"],
        "metrics": health["metrics_coverage_percent"],
        "public_safe": health["public_safe_percent"],
        "closed_cases": health["closed_case_percent"],
    }
    return min(candidates, key=candidates.get)


def _recommended_next_build(summary: dict[str, int], health: dict[str, Any]) -> str:
    if summary["cases_missing_proof_record_count"] >= summary["cases_missing_proofcard_count"] and summary["cases_missing_proof_record_count"] > 0:
        return "proof_record_backfill"
    if summary["cases_missing_proofcard_count"] > 0:
        return "proofcard_backfill"
    if summary["public_safe_cases_count"] == 0 and summary["cases_total"] > 0:
        return "public_safe_candidate_review_packet"
    if summary["runtime_candidate_lanes_count"] or summary["scheduled_collector_lanes_count"]:
        return "runtime_signal_review_gate"
    if health["closed_case_percent"] == 0 and summary["cases_total"] > 0:
        return "case_closure_contract"
    return "hygiene_cleanup_only"


def _add_cross_repo_quality_notes(rows: list[dict[str, Any]], notes: list[str]) -> None:
    for row in rows:
        if row["source_status"] == "SOURCE_EXISTS" and row["validation_status"] in {"NOT_FOUND", "UNKNOWN_WITH_REASON"}:
            notes.append(f"{row['case_id']} has source evidence without controlled validation evidence")
        if row["validation_status"] == "CONTROLLED_TEST_VALIDATED" and row["proof_record_status"] != "PROOF_RECORD_EXISTS":
            notes.append(f"{row['case_id']} has controlled validation but no proof record")
        if row["proof_record_status"] == "PROOF_RECORD_EXISTS" and row["proofcard_status"] != "PROOFCARD_EXISTS":
            notes.append(f"{row['case_id']} has proof record but no ProofCard")


def verify_case_growth_snapshot(repo_root: Path, snapshot: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    current = build_case_growth_index(repo_root, generated_at=str(snapshot.get("generated_at") or "1970-01-01T00:00:00Z"))
    historical = snapshot.get("historical_snapshot") is True
    current_authority = snapshot.get("current_authority") is True
    if historical and current_authority:
        errors.append("snapshot cannot be both historical_snapshot=true and current_authority=true")
    if not historical and not current_authority:
        errors.append("non-historical snapshot must declare current_authority=true")
    if snapshot.get("schema_version") != "case-growth-index-v1":
        errors.append("snapshot schema_version must be case-growth-index-v1")

    if _contains_absolute_local_path(snapshot):
        errors.append("snapshot contains an absolute local path")

    cases = snapshot.get("cases") if isinstance(snapshot.get("cases"), list) else []
    case_ids = [str(item.get("case_id")) for item in cases if isinstance(item, dict) and item.get("case_id")]
    for duplicate in _duplicates(case_ids):
        errors.append(f"duplicate case ID in snapshot: {duplicate}")

    boundary = snapshot.get("boundary") if isinstance(snapshot.get("boundary"), dict) else {}
    for key, value in boundary.items():
        if value is not False:
            errors.append(f"unauthorized boundary promotion: {key}={value!r}")
    for row in cases:
        if not isinstance(row, dict):
            continue
        case_id = row.get("case_id", "UNKNOWN")
        if row.get("public_safe_status") not in {None, "NOT_PUBLIC_SAFE"}:
            errors.append(f"{case_id}: unauthorized public-safe status {row.get('public_safe_status')!r}")
        if row.get("case_state") == "CLOSED":
            errors.append(f"{case_id}: unauthorized case closure")
        if row.get("signal_status") not in {None, "NOT_PROVEN"}:
            errors.append(f"{case_id}: signal status exceeds checked-source authority")
        errors.extend(f"{case_id}: {error}" for error in _case_claim_violations(row))

    stated_revisions = snapshot.get("source_revisions") if isinstance(snapshot.get("source_revisions"), list) else []
    if len(stated_revisions) != len(REPO_NAMES):
        errors.append(f"source_revisions must contain exactly {len(REPO_NAMES)} repositories")
    stated_names = [str(item.get("repository") or "") for item in stated_revisions if isinstance(item, dict)]
    if len(stated_names) != len(set(stated_names)):
        errors.append("source_revisions repository names must be unique")
    if set(stated_names) != set(REPO_NAMES):
        missing = sorted(set(REPO_NAMES) - set(stated_names))
        extra = sorted(set(stated_names) - set(REPO_NAMES))
        errors.append(f"source_revisions must match exact seven-repository set; missing={missing}, extra={extra}")
    current_by_repo = {item["repository"]: item for item in current["source_revisions"]}
    repo_paths = resolve_repo_paths(Path(repo_root))
    selection_errors: list[str] = []
    if current_authority:
        selection_errors = verify_all_selected_source_checkouts(Path(repo_root))
        errors.extend(selection_errors)
    for stated in stated_revisions:
        if not isinstance(stated, dict):
            errors.append("source_revisions entries must be objects")
            continue
        repository = str(stated.get("repository") or "")
        if repository not in current_by_repo:
            errors.append(f"unknown source repository in snapshot: {repository or 'MISSING'}")
            continue
        current_revision = current_by_repo[repository]
        stated_sha = stated.get("source_commit_sha")
        observed_head = stated.get("source_observed_head_sha")
        current_observed = stated.get("current_observed_head_sha")
        if stated.get("source_observation_kind") != "reviewed_immutable_commit":
            errors.append(f"{repository}: source_observation_kind must be reviewed_immutable_commit")
        if observed_head != stated_sha or current_observed != stated_sha:
            errors.append(
                f"{repository}: recorded observed-head fields must identify the same reviewed source commit"
            )
        resolved_ref = stated.get("resolved_ref")
        if not isinstance(resolved_ref, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", resolved_ref):
            errors.append(f"{repository}: resolved_ref is malformed")
        source_path = str(stated.get("authoritative_path") or stated.get("source_path") or "")
        if source_path != current_revision["source_path"]:
            errors.append(f"{repository}: authoritative source path disagrees with current owner path")
        stated_blob = stated.get("authoritative_git_blob_sha") or stated.get("source_git_blob_sha")
        current_blob = current_revision.get("authoritative_git_blob_sha")
        if stated_blob != current_blob:
            errors.append(
                f"{repository}: authoritative Git blob disagrees with the file at the checked current tree"
            )
        stated_semantic = (
            stated.get("authoritative_content_fingerprint")
            or stated.get("source_semantic_fingerprint_sha256")
        )
        current_semantic = current_revision.get("authoritative_content_fingerprint")
        if stated_semantic != current_semantic:
            errors.append(
                f"{repository}: authoritative semantic fingerprint disagrees with checked current content"
            )
        if stated.get("revision_scope") != "content_addressed_authority":
            errors.append(f"{repository}: revision_scope must be content_addressed_authority")
        if stated.get("self_referential") is not False:
            errors.append(f"{repository}: generated consumers must not be self-referential authority")
        if stated.get("canonical_origin") != current_revision.get("canonical_origin"):
            errors.append(f"{repository}: canonical repository origin disagrees with owner")
        if stated.get("observed_origin") != current_revision.get("observed_origin"):
            errors.append(f"{repository}: observed repository origin is not canonical")
        if not re.fullmatch(r"[0-9a-f]{40}", str(stated_sha or "")):
            errors.append(f"{repository}: source_commit_sha must be a 40-character Git SHA")
        elif repo_paths.get(repository) is None:
            errors.append(f"{repository}: source repository is missing")
        elif git_commit_exists(repo_paths[repository], str(stated_sha)):
            observed_identity = git_blob_identity(repo_paths[repository], str(stated_sha), source_path)
            if observed_identity is None or observed_identity[0] != current_blob:
                errors.append(
                    f"{repository}: observed commit does not carry the checked current authoritative blob"
                )
        else:
            # The observed branch tip is freshness metadata, not the authority
            # identity. A squash/rebase may make that commit unavailable while
            # the checked current path/blob/semantic identity remains exact.
            # `source_observation_kind` and the three equal observation fields
            # above keep this explicitly bounded rather than silently treating
            # an arbitrary ancestor as current authority.
            pass
        if stated.get("source_file_sha256") != current_revision.get("source_file_sha256") and not historical:
            errors.append(
                f"{repository}: authoritative source fingerprint drifted; regenerate from {current_revision['source_path']}"
            )
        if stated.get("missing_source_state") is True or stated.get("dangling_reference_state") is True:
            errors.append(f"{repository}: snapshot records missing or dangling authority source")
        allowed_freshness = {"CURRENT"}
        if current_authority and stated.get("source_freshness_state") not in allowed_freshness:
            errors.append(
                f"{repository}: current snapshot source_freshness_state must be one of {sorted(allowed_freshness)}, "
                f"got {stated.get('source_freshness_state')!r}"
            )
        if current_authority and current_revision.get("source_freshness_state") not in allowed_freshness:
            errors.append(
                f"{repository}: current repository source is not clean/current: "
                f"{current_revision.get('source_freshness_state')!r}"
            )

    stated_hash = snapshot.get("reproducibility_sha256")
    if stated_hash != _reproducibility_hash(snapshot):
        errors.append("snapshot reproducibility_sha256 does not reproduce from its normalized content")
    stated_source_manifest = snapshot.get("source_manifest_digest")
    if stated_source_manifest != _source_manifest_digest(stated_revisions):
        errors.append("snapshot source_manifest_digest does not reproduce from its authority identities")
    if current_authority and stated_source_manifest != current.get("source_manifest_digest"):
        errors.append("current snapshot source_manifest_digest disagrees with checked authority content")
    snapshot_state = snapshot.get("snapshot_state") if isinstance(snapshot.get("snapshot_state"), dict) else {}
    if snapshot_state.get("identity_model") != (
        "repo_path_git_blob_and_semantic_fingerprint_with_separate_head_observation"
    ):
        errors.append("snapshot identity model is missing or unsupported")
    if snapshot_state.get("generated_consumers_are_authority") is not False:
        errors.append("generated consumers must not be classified as authority")
    if snapshot_state.get("historical_snapshot") is not historical:
        errors.append("snapshot_state historical classification disagrees with snapshot")
    if snapshot_state.get("current_authority") is not current_authority:
        errors.append("snapshot_state current authority classification disagrees with snapshot")

    if current_authority:
        if snapshot.get("summary") != current.get("summary"):
            errors.append("current snapshot summary counts disagree with current authoritative repository state")
        if snapshot.get("case_ids_discovered_count") != current.get("case_ids_discovered_count"):
            errors.append("current snapshot case count disagrees with current authoritative repository state")
        for field in ("cases", "case_growth_health", "repo_slot_accuracy", "boundary"):
            before = snapshot.get(field)
            after = current.get(field)
            if field == "cases" and not selection_errors:
                before = _content_normalized_cases(before)
                after = _content_normalized_cases(after)
            if before != after:
                errors.append(f"current snapshot {field} disagrees with normalized current authoritative content")
    for finding in current.get("contradictions", []):
        errors.append(f"current contradiction {finding['code']}: {finding['actual']} ({finding['next_legal_action']})")
    for finding in current.get("drift", []):
        errors.append(f"current drift {finding['code']}: expected {finding['expected']}, actual {finding['actual']} ({finding['next_legal_action']})")
    return errors, current


ABSOLUTE_LOCAL_PATH = re.compile(
    r"(?i)(?:[A-Z]:[\\/]|(?<![\\/:])\\{2,}[^\\/\s]+[\\/]"
    r"|(?<![\\/:])//[^/\s]+/|(?<![A-Za-z0-9_./:-])/(?!/)[^\s\"'<>]+)"
)


def _contains_absolute_local_path(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_absolute_local_path(key) or _contains_absolute_local_path(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_absolute_local_path(item) for item in value)
    if isinstance(value, str):
        return ABSOLUTE_LOCAL_PATH.search(value) is not None
    return False


def _case_claim_violations(row: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    runtime = str(row.get("runtime_candidate_status") or "")
    authority = str(row.get("claim_authority_status") or "")
    if re.search(r"(?i)RUNTIME[_ -]?ACTIVE|PRODUCTION[_ -]?READY", runtime):
        violations.append(f"unauthorized runtime_candidate_status {runtime!r}")
    if re.search(r"(?i)(?:AI|ANALYST)[_ -]?APPROVED|FINAL[_ -]?AUTHORIZATION|CASE[_ -]?CLOSED", authority):
        violations.append(f"unauthorized claim_authority_status {authority!r}")
    safe_row = {key: value for key, value in row.items() if key != "blocked_claims"}
    text = json.dumps(safe_row, sort_keys=True)
    text = re.sub(
        r"(?i)\b(?:missing|blocked|not)(?:_[a-z0-9]+)*_(?:final_authorization|case_closure|ai_approved_disposition|analyst_approved_disposition)\b",
        "",
        text,
    )
    for label, pattern in (
        ("AI-approved disposition", r"(?i)AI[-_ ]approved disposition"),
        ("analyst-approved disposition", r"(?i)analyst[-_ ]approved disposition"),
        ("final authorization", r"(?i)final[-_ ]authorization"),
        ("case closure", r"(?i)case[-_ ](?:closure|closed)"),
    ):
        if re.search(pattern, text):
            violations.append(f"unauthorized {label} wording outside blocked_claims")
    return violations


def diff_case_growth_snapshot(repo_root: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    current = build_case_growth_index(repo_root, generated_at=str(snapshot.get("generated_at") or "1970-01-01T00:00:00Z"))
    historical = snapshot.get("historical_snapshot") is True
    before_revisions = {
        item.get("repository"): item
        for item in snapshot.get("source_revisions", [])
        if isinstance(item, dict) and item.get("repository")
    }
    changes: list[dict[str, Any]] = []
    for current_revision in current["source_revisions"]:
        repository = current_revision["repository"]
        before = before_revisions.get(repository, {})
        for field in (
            "source_commit_sha",
            "source_observed_head_sha",
            "current_observed_head_sha",
            "source_file_sha256",
            "authoritative_git_blob_sha",
            "authoritative_content_fingerprint",
            "source_path",
        ):
            if before.get(field) != current_revision[field]:
                observation_only_content_current = (
                    field in {"source_commit_sha", "source_observed_head_sha", "current_observed_head_sha"}
                    and before.get("authoritative_git_blob_sha")
                    == current_revision.get("authoritative_git_blob_sha")
                    and before.get("authoritative_content_fingerprint")
                    == current_revision.get("authoritative_content_fingerprint")
                )
                changes.append(
                    {
                        "field": field,
                        "source_owner": repository,
                        "source_path": current_revision["source_path"],
                        "before": before.get(field),
                        "after": current_revision[field],
                        "old_source_revision": before.get("source_commit_sha"),
                        "current_source_revision": current_revision["source_commit_sha"],
                        "classification": (
                            "EXPECTED_HISTORICAL_CONTEXT"
                            if historical
                            else "OBSERVATION_ONLY_CONTENT_CURRENT"
                            if observation_only_content_current
                            else "ACTIONABLE_DRIFT"
                        ),
                        "next_remediation": (
                            "retain as historical context"
                            if historical
                            else "refresh observed-head metadata when producing the next reviewer snapshot; no authority-content regeneration required"
                            if observation_only_content_current
                            else "regenerate the current snapshot from the owning source"
                        ),
                    }
                )
    before_summary = snapshot.get("summary") if isinstance(snapshot.get("summary"), dict) else {}
    for field, after in current["summary"].items():
        before = before_summary.get(field)
        if before != after:
            changes.append(
                {
                    "field": f"summary.{field}",
                    "source_owner": "hoxline",
                    "source_path": "derived from seven source-owned inputs",
                    "before": before,
                    "after": after,
                    "old_source_revision": None,
                    "current_source_revision": current_by_repo_sha(current, "hoxline"),
                    "classification": "EXPECTED_HISTORICAL_CONTEXT" if historical else "ACTIONABLE_DRIFT",
                    "next_remediation": "retain as historical context" if historical else "regenerate the current snapshot",
                }
            )
    actionable_changes = [item for item in changes if item["classification"] == "ACTIONABLE_DRIFT"]
    return {
        "schema_version": "case-growth-diff-v1",
        "historical_snapshot": historical,
        "current_authority": snapshot.get("current_authority") is True,
        "changes": changes,
        "contradictions": current["contradictions"],
        "drift": current["drift"],
        "next_legal_action": (
            current["next_legal_action"]
            if actionable_changes or current["drift"]
            else "none; authority content converges and only observed-head metadata changed"
            if changes
            else "none; snapshot converges"
        ),
    }


def current_by_repo_sha(index: dict[str, Any], repository: str) -> str | None:
    for item in index.get("source_revisions", []):
        if item.get("repository") == repository:
            return item.get("source_commit_sha")
    return None
