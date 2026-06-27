from __future__ import annotations

from typing import Any


def render_case_growth_markdown(index: dict[str, Any]) -> str:
    summary = index["summary"]
    lines = [
        "# Hoxline Case Growth Index v0",
        "",
        f"Generated: `{index['generated_at']}`",
        f"Proof ceiling: `{index['proof_ceiling']}`",
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
