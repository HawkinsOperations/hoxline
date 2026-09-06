from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from .case_growth import (
    build_case_growth_index,
    diff_case_growth_snapshot,
    render_case_growth_markdown,
    verify_case_growth_snapshot,
)
from .gauntlet import GauntletError, build_full_loop_run, render_markdown, verify_full_loop_run_file
from .gauntlet import decide_claim_authority_v1, render_proofcard_v1, summarize_gauntlet_run_v1
from .demo import DemoError, build_demo_run, default_output_dir, render_quickstart_console, verify_demo_run_dir, write_demo_run
from .metrics import build_work_impact_report
from .review_engine import (
    ReviewEngineError,
    render_batch_console,
    render_run_console,
    run_batch_review,
    run_review,
    summarize_review_run,
    verify_batch_run,
    verify_review_run,
)
from .reviewer import ReviewerPacketError, verify_public_reviewer_packet_file


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "detection-quality":
        from .detection_quality import QualityReviewError, compare_replay, read_report, render_review, run_review
        try:
            report = run_review(Path(args.repo_root), args.detections_ref, args.validation_ref, args.platform_ref)
            if args.verify:
                compare_replay(read_report(Path(args.verify).read_text(encoding="utf-8")), report)
            print(json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_review(report), end="\n")
            return 0
        except (QualityReviewError, OSError) as exc:
            print(json.dumps({"status": "BLOCKED", "error": str(exc), "human_review_required": True, "ai_disposition_authority": False}))
            return 2

    if args.command == "gauntlet" and args.gauntlet_command == "run":
        return _run_gauntlet(args)
    if args.command == "gauntlet" and args.gauntlet_command == "metrics":
        return _run_gauntlet_metrics(args)
    if args.command == "gauntlet" and args.gauntlet_command == "verify":
        return _verify_gauntlet(args)
    if args.command == "gauntlet" and args.gauntlet_command == "summarize":
        return _summarize_gauntlet(args)
    if args.command == "claim-authority" and args.claim_authority_command == "decide":
        return _decide_claim_authority(args)
    if args.command == "proofcard" and args.proofcard_command == "render":
        return _render_proofcard(args)
    if args.command == "reviewer" and args.reviewer_command == "verify":
        return _verify_reviewer(args)
    if args.command == "demo" and args.demo_command in {"quickstart", "run"}:
        return _run_demo(args)
    if args.command == "demo" and args.demo_command == "verify":
        return _verify_demo(args)
    if args.command == "review" and args.review_command == "run":
        return _run_review(args)
    if args.command == "review" and args.review_command == "verify":
        return _verify_review(args)
    if args.command == "review" and args.review_command == "summarize":
        return _summarize_review(args)
    if args.command == "review" and args.review_command == "batch" and args.review_batch_command == "run":
        return _run_review_batch(args)
    if args.command == "review" and args.review_command == "batch" and args.review_batch_command == "verify":
        return _verify_review_batch(args)
    if args.command == "case-growth" and args.case_growth_command == "index":
        return _run_case_growth_index(args)
    if args.command == "case-growth" and args.case_growth_command == "verify":
        return _run_case_growth_verify(args)
    if args.command == "case-growth" and args.case_growth_command == "diff":
        return _run_case_growth_diff(args)

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hoxline")
    subparsers = parser.add_subparsers(dest="command")

    quality_parser = subparsers.add_parser("detection-quality", help="replay validation-owned source mutation quality through platform")
    quality_parser.add_argument("--repo-root", required=True)
    quality_parser.add_argument("--detections-ref", required=True)
    quality_parser.add_argument("--validation-ref", required=True)
    quality_parser.add_argument("--platform-ref", required=True)
    quality_parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    quality_parser.add_argument("--verify", help="compare a saved owner report with freshly executed source/corpus")

    gauntlet_parser = subparsers.add_parser("gauntlet", help="run Hoxline Gauntlet workflows")
    gauntlet_subparsers = gauntlet_parser.add_subparsers(dest="gauntlet_command")

    run_parser = gauntlet_subparsers.add_parser("run", help="run a full-loop artifact review")
    run_parser.add_argument("--artifact", required=True, help="artifact id to evaluate")
    run_parser.add_argument("--format", choices=("json", "markdown"), default="json", help="output format")
    run_parser.add_argument("--output", help="optional output file path")

    metrics_parser = gauntlet_subparsers.add_parser("metrics", help="emit Hoxline Gauntlet work-impact metrics")
    metrics_parser.add_argument("--events", required=True, help="controlled-test events fixture path")
    metrics_parser.add_argument("--artifact", required=True, help="sample artifact JSON path")
    metrics_parser.add_argument("--proofcard", required=True, help="sample ProofCard JSON path")
    metrics_parser.add_argument("--claim-output", required=True, help="sample Claim Authority output JSON path")
    metrics_parser.add_argument("--format", choices=("json",), default="json", help="output format")
    metrics_parser.add_argument("--output", help="optional output file path")

    verify_parser = gauntlet_subparsers.add_parser("verify", help="verify a full-loop Gauntlet JSON output")
    verify_parser.add_argument("--input", required=True, help="Gauntlet full-loop JSON output to verify")
    verify_parser.add_argument(
        "--schema",
        default="schemas/gauntlet-full-loop-run-v0.schema.json",
        help="Gauntlet full-loop output schema path",
    )

    summarize_parser = gauntlet_subparsers.add_parser("summarize", help="summarize a Gauntlet v1 JSON run")
    summarize_parser.add_argument("--input", required=True, help="Gauntlet v1 JSON run to summarize")

    claim_parser = subparsers.add_parser("claim-authority", help="evaluate structured Claim Authority decisions")
    claim_subparsers = claim_parser.add_subparsers(dest="claim_authority_command")
    decide_parser = claim_subparsers.add_parser("decide", help="decide allowed and blocked claims for a Gauntlet v1 run")
    decide_parser.add_argument("--input", required=True, help="Gauntlet v1 JSON run to decide")

    proofcard_parser = subparsers.add_parser("proofcard", help="render ProofCard outputs")
    proofcard_subparsers = proofcard_parser.add_subparsers(dest="proofcard_command")
    render_parser = proofcard_subparsers.add_parser("render", help="render a deterministic ProofCard v1 JSON view")
    render_parser.add_argument("--input", required=True, help="Gauntlet v1 JSON run to render")

    reviewer_parser = subparsers.add_parser("reviewer", help="verify Hoxline public reviewer packets")
    reviewer_subparsers = reviewer_parser.add_subparsers(dest="reviewer_command")
    reviewer_verify_parser = reviewer_subparsers.add_parser("verify", help="verify a public reviewer packet")
    reviewer_verify_parser.add_argument("--input", required=True, help="public reviewer packet JSON to verify")
    reviewer_verify_parser.add_argument(
        "--schema",
        default="schemas/public-reviewer-packet-v0.schema.json",
        help="public reviewer packet schema path",
    )

    demo_parser = subparsers.add_parser("demo", help="run deterministic Hoxline reviewer demos")
    demo_subparsers = demo_parser.add_subparsers(dest="demo_command")
    quickstart_parser = demo_subparsers.add_parser("quickstart", help="run the one-command reviewer demo")
    _add_demo_run_args(quickstart_parser)
    run_demo_parser = demo_subparsers.add_parser("run", help="run the one-command reviewer demo")
    _add_demo_run_args(run_demo_parser)
    demo_verify_parser = demo_subparsers.add_parser("verify", help="verify a generated demo run")
    demo_verify_parser.add_argument("--input", required=True, help="demo run directory or run-summary.json path")

    review_parser = subparsers.add_parser("review", help="run reusable Hoxline Review Engine workflows")
    review_subparsers = review_parser.add_subparsers(dest="review_command")
    review_run_parser = review_subparsers.add_parser("run", help="run Review Engine v1 from an artifact manifest")
    review_run_parser.add_argument("--artifact", required=True, help="artifact manifest JSON path")
    review_run_parser.add_argument("--output", help="output directory; defaults to .hoxline/runs/<timestamp>")
    review_run_parser.add_argument("--force", action="store_true", help="replace the output directory if it already exists")
    review_run_parser.add_argument("--format", choices=("text", "json"), default="text", help="console output format")
    review_verify_parser = review_subparsers.add_parser("verify", help="verify a Review Engine machine-state.json")
    review_verify_parser.add_argument("--run", required=True, help="machine-state.json path")
    review_summary_parser = review_subparsers.add_parser("summarize", help="summarize a Review Engine machine-state.json")
    review_summary_parser.add_argument("--run", required=True, help="machine-state.json path")
    review_batch_parser = review_subparsers.add_parser("batch", help="run multi-artifact Review Engine workflows")
    review_batch_subparsers = review_batch_parser.add_subparsers(dest="review_batch_command")
    review_batch_run_parser = review_batch_subparsers.add_parser("run", help="run a batch from a multi-artifact review index")
    review_batch_run_parser.add_argument("--index", required=True, help="multi-artifact review index JSON path")
    review_batch_run_parser.add_argument("--output", help="output directory; defaults to .hoxline/batch-runs/<timestamp>")
    review_batch_run_parser.add_argument("--force", action="store_true", help="replace the output directory if it already exists")
    review_batch_run_parser.add_argument("--format", choices=("text", "json"), default="text", help="console output format")
    review_batch_verify_parser = review_batch_subparsers.add_parser("verify", help="verify a batch-machine-state.json")
    review_batch_verify_parser.add_argument("--run", required=True, help="batch-machine-state.json path")

    case_growth_parser = subparsers.add_parser("case-growth", help="aggregate seven-repo case growth metrics")
    case_growth_subparsers = case_growth_parser.add_subparsers(dest="case_growth_command")
    case_growth_index_parser = case_growth_subparsers.add_parser("index", help="emit the Hoxline Case Growth Index v0")
    case_growth_index_parser.add_argument("--repo-root", required=True, help="HawkinsOperations local org repo root")
    case_growth_index_parser.add_argument("--format", choices=("json", "markdown"), default="json", help="output format")
    case_growth_index_parser.add_argument("--output", help="optional output path")
    case_growth_index_parser.add_argument(
        "--paired-output-base",
        help="write a content-bound JSON/Markdown pair using this path without a suffix",
    )
    case_growth_verify_parser = case_growth_subparsers.add_parser("verify", help="fail closed when a snapshot drifts from current authority")
    case_growth_verify_parser.add_argument("--repo-root", required=True, help="HawkinsOperations local org repo root")
    case_growth_verify_parser.add_argument("--snapshot", required=True, help="checked-in Case Growth snapshot JSON")
    case_growth_verify_parser.add_argument("--format", choices=("json", "text"), default="json", help="output format")
    case_growth_diff_parser = case_growth_subparsers.add_parser("diff", help="show source-owned snapshot drift")
    case_growth_diff_parser.add_argument("--repo-root", required=True, help="HawkinsOperations local org repo root")
    case_growth_diff_parser.add_argument("--snapshot", required=True, help="checked-in Case Growth snapshot JSON")
    case_growth_diff_parser.add_argument("--format", choices=("json", "markdown"), default="json", help="output format")
    return parser

def _add_demo_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--artifact", default="HO-DET-010", help="artifact id to demonstrate")
    parser.add_argument("--mode", default="safe-fixture", choices=("safe-fixture",), help="demo execution mode")
    parser.add_argument("--fixture", help="optional positive fixture JSON path")
    parser.add_argument("--negative-fixture", help="optional negative fixture JSON path")
    parser.add_argument("--output", help="output directory; defaults to .hoxline/demo-runs/<timestamp>")
    parser.add_argument("--force", action="store_true", help="replace the output directory if it already exists")
    parser.add_argument("--stdout-only", action="store_true", help="print the walkthrough without writing files")

def _run_gauntlet(args: argparse.Namespace) -> int:
    artifact_path = Path(args.artifact)
    if artifact_path.is_file():
        try:
            report = _build_gauntlet_v0_lab_report(artifact_path)
        except (GauntletError, OSError) as exc:
            print(f"Hoxline Gauntlet: error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            output = json.dumps(report, indent=2) + "\n"
        else:
            output = _render_gauntlet_v0_lab_markdown(report)

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0

    try:
        report = build_full_loop_run(args.artifact)
    except GauntletError as exc:
        print(f"Hoxline Gauntlet: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = json.dumps(report, indent=2) + "\n"
    else:
        output = render_markdown(report)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


def _run_gauntlet_metrics(args: argparse.Namespace) -> int:
    try:
        report = build_work_impact_report(
            events_path=Path(args.events),
            artifact_path=Path(args.artifact),
            proofcard_path=Path(args.proofcard),
            claim_output_path=Path(args.claim_output),
        )
    except (OSError, ValueError) as exc:
        print(f"Hoxline Gauntlet metrics: error: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


def _run_case_growth_index(args: argparse.Namespace) -> int:
    try:
        index = build_case_growth_index(Path(args.repo_root))
    except (OSError, ValueError) as exc:
        print(f"Hoxline Case Growth Index: error: {exc}", file=sys.stderr)
        return 2

    json_output = json.dumps(index, indent=2) + "\n"
    markdown_output = render_case_growth_markdown(index)
    output = json_output if args.format == "json" else markdown_output

    if args.paired_output_base:
        try:
            _write_case_growth_pair(Path(args.paired_output_base), json_output, markdown_output)
        except OSError as exc:
            print(f"Hoxline Case Growth Index: paired output error: {exc}", file=sys.stderr)
            return 2

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


def _write_case_growth_pair(base_path: Path, json_output: str, markdown_output: str) -> None:
    if base_path.suffix:
        raise OSError("paired output base must not include a suffix")
    base_path.parent.mkdir(parents=True, exist_ok=True)
    targets = ((base_path.with_suffix(".json"), json_output), (base_path.with_suffix(".md"), markdown_output))
    temporary: list[tuple[Path, Path]] = []
    try:
        for target, content in targets:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(content)
                temporary.append((Path(handle.name), target))
        for temp_path, target in temporary:
            os.replace(temp_path, target)
    finally:
        for temp_path, _ in temporary:
            if temp_path.exists():
                temp_path.unlink()


def _run_case_growth_verify(args: argparse.Namespace) -> int:
    try:
        snapshot_path = Path(args.snapshot)
        snapshot = _load_json(snapshot_path)
        errors, current = verify_case_growth_snapshot(Path(args.repo_root), snapshot)
        markdown_path = snapshot_path.with_suffix(".md")
        if not markdown_path.is_file():
            errors.append(f"paired Case Growth Markdown is missing: {markdown_path.name}")
        elif markdown_path.read_text(encoding="utf-8") != render_case_growth_markdown(snapshot):
            errors.append("paired Case Growth Markdown is not the exact render of the checked JSON")
    except (OSError, ValueError) as exc:
        print(f"Hoxline Case Growth verify: error: {exc}", file=sys.stderr)
        return 2
    payload = {
        "status": "FAIL" if errors else "PASS",
        "error_count": len(errors),
        "errors": errors,
        "current_reproducibility_sha256": current["reproducibility_sha256"],
        "next_legal_action": errors[0] if errors else "none; snapshot converges with current authority",
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Hoxline Case Growth verify: {payload['status']}")
        for error in errors:
            print(f"- {error}")
    return 1 if errors else 0


def _run_case_growth_diff(args: argparse.Namespace) -> int:
    try:
        snapshot = _load_json(Path(args.snapshot))
        report = diff_case_growth_snapshot(Path(args.repo_root), snapshot)
    except (OSError, ValueError) as exc:
        print(f"Hoxline Case Growth diff: error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        lines = ["# Hoxline Case Growth Diff v1", "", f"Historical snapshot: `{str(report['historical_snapshot']).lower()}`", ""]
        lines.extend(
            f"- `{item['field']}`: `{item['before']}` -> `{item['after']}`; owner `{item['source_owner']}`; "
            f"path `{item['source_path']}`; `{item['classification']}`; next: {item['next_remediation']}"
            for item in report["changes"]
        )
        lines.extend(["", f"Next legal action: {report['next_legal_action']}"])
        print("\n".join(lines))
    return 0


def _verify_gauntlet(args: argparse.Namespace) -> int:
    try:
        errors = verify_full_loop_run_file(Path(args.input), Path(args.schema))
    except (GauntletError, OSError) as exc:
        print(f"Hoxline Gauntlet verify: FAIL: {exc}", file=sys.stderr)
        return 2

    if errors:
        print(f"Hoxline Gauntlet verify: FAIL: {len(errors)} error(s)")
        for error in errors:
            print(f"- {error}")
        return 1

    report = _load_json(Path(args.input))
    if report.get("schema_version") == "gauntlet-run-v1":
        decision = decide_claim_authority_v1(report)
        print("Hoxline Gauntlet verify: PASS")
        _print_decision_summary(decision)
    else:
        print("Hoxline Gauntlet verify: PASS")
    return 0


def _summarize_gauntlet(args: argparse.Namespace) -> int:
    try:
        report = _load_json(Path(args.input))
    except (GauntletError, OSError) as exc:
        print(f"Hoxline Gauntlet summarize: FAIL: {exc}", file=sys.stderr)
        return 2
    print(summarize_gauntlet_run_v1(report), end="")
    return 0


def _decide_claim_authority(args: argparse.Namespace) -> int:
    try:
        report = _load_json(Path(args.input))
    except (GauntletError, OSError) as exc:
        print(f"Hoxline Claim Authority decide: FAIL: {exc}", file=sys.stderr)
        return 2
    decision = decide_claim_authority_v1(report)
    print(json.dumps(decision, indent=2, sort_keys=True))
    return 1 if not decision["allowed_claims"] else 0


def _render_proofcard(args: argparse.Namespace) -> int:
    try:
        report = _load_json(Path(args.input))
    except (GauntletError, OSError) as exc:
        print(f"Hoxline ProofCard render: FAIL: {exc}", file=sys.stderr)
        return 2
    print(render_proofcard_v1(report), end="")
    return 0


def _verify_reviewer(args: argparse.Namespace) -> int:
    try:
        errors = verify_public_reviewer_packet_file(Path(args.input), Path(args.schema))
    except (ReviewerPacketError, OSError) as exc:
        print(f"Hoxline Reviewer verify: FAIL: {exc}", file=sys.stderr)
        return 2

    if errors:
        print(f"Hoxline Reviewer verify: FAIL: {len(errors)} error(s)")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Hoxline Reviewer verify: PASS")
    return 0

def _run_demo(args: argparse.Namespace) -> int:
    if args.artifact != "HO-DET-010":
        print(f"Hoxline demo: error: unsupported artifact for demo: {args.artifact}", file=sys.stderr)
        return 2
    try:
        run = build_demo_run(
            fixture_path=Path(args.fixture) if args.fixture else None,
            negative_fixture_path=Path(args.negative_fixture) if args.negative_fixture else None,
        )
        output_dir = Path(args.output) if args.output else default_output_dir()
        if not args.stdout_only:
            write_demo_run(output_dir, run, force=args.force)
    except (DemoError, OSError) as exc:
        print(f"Hoxline demo: FAIL: {exc}", file=sys.stderr)
        return 2

    print(render_quickstart_console(output_dir, run), end="")
    return 0


def _verify_demo(args: argparse.Namespace) -> int:
    errors = verify_demo_run_dir(Path(args.input))
    if errors:
        print(f"Hoxline demo verify: FAIL: {len(errors)} error(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Hoxline demo verify: PASS")
    return 0


def _run_review(args: argparse.Namespace) -> int:
    try:
        run = run_review(Path(args.artifact), Path(args.output) if args.output else None, force=args.force)
    except (ReviewEngineError, OSError) as exc:
        print(f"Hoxline review: FAIL: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(run["machine_state"], indent=2, sort_keys=True))
    else:
        print(render_run_console(run), end="")
    return 0 if run["machine_state"]["final_status"] == "PASS" else 1


def _run_review_batch(args: argparse.Namespace) -> int:
    try:
        batch = run_batch_review(Path(args.index), Path(args.output) if args.output else None, force=args.force)
    except (ReviewEngineError, OSError) as exc:
        print(f"Hoxline review batch: FAIL: {exc}", file=sys.stderr)
        return 2
    state = batch["batch_machine_state"]
    if args.format == "json":
        print(json.dumps(state, indent=2, sort_keys=True))
    else:
        print(render_batch_console(batch), end="")
    return 0 if state["final_status"] in {"PASS", "MIXED"} else 1


def _verify_review_batch(args: argparse.Namespace) -> int:
    errors = verify_batch_run(Path(args.run))
    if errors:
        print(f"Hoxline review batch verify: FAIL: {len(errors)} error(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Hoxline review batch verify: PASS")
    return 0


def _verify_review(args: argparse.Namespace) -> int:
    errors = verify_review_run(Path(args.run))
    if errors:
        print(f"Hoxline review verify: FAIL: {len(errors)} error(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Hoxline review verify: PASS")
    return 0


def _summarize_review(args: argparse.Namespace) -> int:
    try:
        print(summarize_review_run(Path(args.run)), end="")
    except (ReviewEngineError, OSError) as exc:
        print(f"Hoxline review summarize: FAIL: {exc}", file=sys.stderr)
        return 2
    return 0
def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise GauntletError(f"input must be a JSON object: {path}")
    return data


def _build_gauntlet_v0_lab_report(artifact_path: Path) -> dict[str, object]:
    artifact = _load_json(artifact_path)
    artifact_id = artifact.get("artifact_id")
    if artifact_id != "HOX-GAUNTLET-001":
        raise GauntletError("gauntlet v0 lab artifact path must identify HOX-GAUNTLET-001")

    proof_ceiling = artifact.get("proof_ceiling")
    if proof_ceiling != "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY":
        raise GauntletError("gauntlet v0 lab proof ceiling must remain controlled validation / product demo only")

    blocked_claims = artifact.get("blocked_claims")
    if not isinstance(blocked_claims, list) or not blocked_claims:
        raise GauntletError("gauntlet v0 lab artifact must list blocked claims")

    safe_claim = artifact.get("safe_claim")
    if not isinstance(safe_claim, str) or not safe_claim:
        raise GauntletError("gauntlet v0 lab artifact must include a safe claim")

    return {
        "schema_version": "gauntlet-v0-lab-summary",
        "artifact_id": artifact_id,
        "scenario": artifact.get("scenario"),
        "proof_ceiling": proof_ceiling,
        "stages": [
            {"stage": "AI-assisted security work", "state": "SOURCE_CONTROLLED_TEST_DRAFT"},
            {"stage": "Artifact Intake", "state": "ACCEPTED"},
            {"stage": "Evidence Graph", "state": "PRESENT"},
            {"stage": "Telemetry Contract Check", "state": "CONTROLLED_TEST_VALIDATED"},
            {"stage": "Controlled Validation", "state": "PASSED_CONTROLLED_FIXTURES"},
            {"stage": "Runtime Candidate Ledger", "state": "NOT_PROMOTED"},
            {"stage": "Signal Observation", "state": "NOT_OBSERVED"},
            {"stage": "Human Review Gate", "state": "PENDING"},
            {"stage": "ProofCard", "state": "READY_FOR_REVIEW"},
            {"stage": "Claim Authority", "state": "SAFE_CLAIM_WITH_BLOCKED_CLAIMS"},
            {"stage": "Safe Claim / Blocked Claim", "state": "EVIDENCE_BOUND_DECISION"},
        ],
        "safe_claim": safe_claim,
        "blocked_claims": blocked_claims,
        "public_safe": False,
        "runtime_proven": False,
        "signal_observed": False,
        "human_review_final": False,
    }


def _render_gauntlet_v0_lab_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Hoxline Gauntlet v0 Lab Summary",
        "",
        f"Artifact: `{report['artifact_id']}`",
        f"Proof ceiling: `{report['proof_ceiling']}`",
        "",
        "## Stages",
    ]
    stages = report["stages"]
    if isinstance(stages, list):
        for stage in stages:
            if isinstance(stage, dict):
                lines.append(f"- {stage['stage']}: {stage['state']}")
    lines.extend(
        [
            "",
            "## Safe Claim",
            str(report["safe_claim"]),
            "",
            "## Blocked Claims",
        ]
    )
    blocked_claims = report["blocked_claims"]
    if isinstance(blocked_claims, list):
        for claim in blocked_claims:
            lines.append(f"- {claim}")
    return "\n".join(lines) + "\n"


def _print_decision_summary(decision: dict[str, object]) -> None:
    print(f"proof_ceiling: {decision['proof_ceiling']}")
    print(f"proof_ceiling_meaning: {decision['proof_ceiling_meaning']}")
    print(f"review_lane: {decision['review_lane']}")
    print(f"public_safe_status: {decision['public_safe_status']}")
    print(f"runtime_active: {str(decision['runtime_active']).lower()}")
    print(f"signal_observed: {str(decision['signal_observed']).lower()}")
    print(f"human_review_required: {str(decision['human_review_required']).lower()}")
    print(f"next_gate: {decision['next_gate']}")
    print("allowed_claims:")
    for claim in decision["allowed_claims"]:
        print(f"- {claim}")
    print("blocked_claims:")
    for claim in decision["blocked_claims"]:
        print(f"- {claim['claim']}: {claim['safer_wording']}")
    print("missing_evidence:")
    for item in decision["missing_evidence"]:
        print(f"- {item}")


if __name__ == "__main__":
    raise SystemExit(main())
