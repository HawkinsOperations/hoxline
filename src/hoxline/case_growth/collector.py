from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from .discovery import (
    REPO_NAMES,
    discover_case_ids,
    last_git_update,
    load_structured,
    repo_branch,
    repo_dirty,
    repo_relative,
    resolve_repo_paths,
    tracked_files,
)


PROOF_CEILING = "CASE_GROWTH_INDEX_CONTROLLED_REPO_AGGREGATION_ONLY"

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
                "path": str(path) if path is not None else "NOT_FOUND",
                "exists": path is not None,
                "branch": repo_branch(path) if path is not None else "NOT_FOUND",
                "dirty": repo_dirty(path) if path is not None else None,
                "authority_boundary": _repo_boundary(name),
                "files_scanned": len(tracked_files(path)) if path is not None else 0,
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
    _add_cross_repo_quality_notes(ordered_rows, data_quality_notes)

    return {
        "schema_version": "case-growth-index-v0",
        "generated_at": generated,
        "repo_root": str(repo_root),
        "proof_ceiling": PROOF_CEILING,
        "repos_scanned": repos_scanned,
        "source_files_scanned_count": scanned_count,
        "case_ids_discovered_count": len(rows),
        "summary": summary,
        "cases": ordered_rows,
        "data_quality_notes": data_quality_notes,
        "boundary": deepcopy(BOUNDARY),
    }


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
    for path in tracked_files(repo):
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
    for path in tracked_files(repo):
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


def _add_cross_repo_quality_notes(rows: list[dict[str, Any]], notes: list[str]) -> None:
    for row in rows:
        if row["source_status"] == "SOURCE_EXISTS" and row["validation_status"] in {"NOT_FOUND", "UNKNOWN_WITH_REASON"}:
            notes.append(f"{row['case_id']} has source evidence without controlled validation evidence")
        if row["validation_status"] == "CONTROLLED_TEST_VALIDATED" and row["proof_record_status"] != "PROOF_RECORD_EXISTS":
            notes.append(f"{row['case_id']} has controlled validation but no proof record")
        if row["proof_record_status"] == "PROOF_RECORD_EXISTS" and row["proofcard_status"] != "PROOFCARD_EXISTS":
            notes.append(f"{row['case_id']} has proof record but no ProofCard")
