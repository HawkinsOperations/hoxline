from __future__ import annotations

from typing import Any


def render_case_growth_markdown(index: dict[str, Any]) -> str:
    summary = index["summary"]
    health = index["case_growth_health"]
    repo_slots = index.get("repo_slot_accuracy", {})
    lines = [
        "# Hoxline Case Growth Index v1",
        "",
        f"Generated: `{index['generated_at']}`",
        f"Proof ceiling: `{index['proof_ceiling']}`",
        f"Repo-slot accuracy: `{repo_slots.get('wording', 'UNKNOWN_WITH_REASON')}`",
        f"Historical snapshot: `{str(index.get('historical_snapshot')).lower()}`",
        f"Current authority: `{str(index.get('current_authority')).lower()}`",
        f"Source manifest digest: `{index.get('source_manifest_digest')}`",
        f"Reproducibility SHA-256: `{index.get('reproducibility_sha256')}`",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    for key in (
        "cases_total",
        "source_packages_count",
        "controlled_validations_count",
        "runtime_candidate_lanes_count",
        "private_runtime_evidence_captured_count",
        "scheduled_collector_lanes_count",
        "proof_records_count",
        "proofcards_count",
        "claim_authority_cases_count",
        "metrics_available_count",
        "public_safe_cases_count",
        "closed_cases_count",
        "blocked_claims_count",
        "cases_with_next_gate_count",
        "cases_missing_proof_record_count",
        "cases_missing_proofcard_count",
        "cases_not_public_safe_count",
        "unknown_state_count",
    ):
        lines.append(f"| `{key}` | {summary[key]} |")

    lines.extend(
        [
            "",
            "## Source Revisions",
            "",
            "| Repository | Authority role | Authority path | Observed head | Git blob | Semantic fingerprint | Source freshness |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for source in index.get("source_revisions", []):
        lines.append(
            f"| {_cell(source['repository'])} | {_cell(source['authority_role'])} | "
            f"{_cell(source.get('authoritative_path') or source['source_path'])} | "
            f"`{source['source_commit_sha']}` | `{source.get('authoritative_git_blob_sha')}` | "
            f"`{source.get('authoritative_content_fingerprint')}` | `{source['source_freshness_state']}` |"
        )

    lines.extend(["", "## Convergence Findings", ""])
    findings = list(index.get("contradictions", [])) + list(index.get("drift", []))
    if findings:
        for finding in findings:
            lines.append(
                f"- `{finding['code']}` owner `{finding['source_owner']}` path `{finding['source_path']}`: "
                f"expected `{finding['expected']}`, actual `{finding['actual']}`; next: {finding['next_legal_action']}"
            )
    else:
        lines.append("- No missing, dangling, contradictory, or stale source-owned state detected.")
    lines.extend(["", f"Next legal action: {index.get('next_legal_action')}"])

    lines.extend(
        [
            "",
            "## Case Growth Health",
            "",
            "| Health metric | Value |",
            "| --- | ---: |",
        ]
    )
    for key in (
        "validation_coverage_percent",
        "proof_record_coverage_percent",
        "proofcard_coverage_percent",
        "scheduled_collector_coverage_percent",
        "runtime_candidate_coverage_percent",
        "metrics_coverage_percent",
        "public_safe_percent",
        "closed_case_percent",
        "blocked_claim_density",
        "next_gate_coverage_percent",
        "missing_proof_record_percent",
        "missing_proofcard_percent",
        "not_public_safe_percent",
    ):
        lines.append(f"| `{key}` | {health[key]} |")
    lines.extend(
        [
            "",
            "| Assessment | Value |",
            "| --- | --- |",
            f"| `overall_health_status` | `{health['overall_health_status']}` |",
            f"| `strongest_lane` | `{health['strongest_lane']}` |",
            f"| `weakest_lane` | `{health['weakest_lane']}` |",
            f"| `recommended_next_build` | `{health['recommended_next_build']}` |",
            "",
            "| Top bottleneck |",
            "| --- |",
        ]
    )
    for bottleneck in health["top_bottlenecks"]:
        lines.append(f"| {_cell(bottleneck)} |")
    lines.extend(
        [
            "",
            "The health section is derived from numeric index counts only. It does not promote runtime, signal, customer, production, approval, or public_safe runtime proof.",
        ]
    )

    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| case_id | source | validation | runtime_candidate | scheduled | proof | proofcard | metrics | public_safe | case_state | next_gate |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in index["cases"]:
        lines.append(
            "| {case_id} | {source_status} | {validation_status} | {runtime_candidate_status} | "
            "{scheduled_collector_status} | {proof_record_status} | {proofcard_status} | {metrics_available} | "
            "{public_safe_status} | {case_state} | {next_gate} |".format(
                case_id=_cell(row["case_id"]),
                source_status=_cell(row["source_status"]),
                validation_status=_cell(row["validation_status"]),
                runtime_candidate_status=_cell(row["runtime_candidate_status"]),
                scheduled_collector_status=_cell(row["scheduled_collector_status"]),
                proof_record_status=_cell(row["proof_record_status"]),
                proofcard_status=_cell(row["proofcard_status"]),
                metrics_available=str(row["metrics_available"]).lower(),
                public_safe_status=_cell(row["public_safe_status"]),
                case_state=_cell(row["case_state"]),
                next_gate=_cell(row["next_gate"]),
            )
        )

    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "| Boundary flag | Value |",
            "| --- | --- |",
        ]
    )
    for key, value in index["boundary"].items():
        lines.append(f"| `{key}` | `{str(value).lower()}` |")

    if index.get("data_quality_notes"):
        lines.extend(["", "## Data Quality Notes", ""])
        for note in index["data_quality_notes"]:
            lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def _cell(value: object) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return f"`{text}`"
