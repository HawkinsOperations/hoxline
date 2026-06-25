from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .gauntlet import GauntletError, build_full_loop_run, render_markdown, verify_full_loop_run_file
from .gauntlet import decide_claim_authority_v1, render_proofcard_v1, summarize_gauntlet_run_v1
from .demo import DemoError, build_demo_run, default_output_dir, render_quickstart_console, verify_demo_run_dir, write_demo_run
from .reviewer import ReviewerPacketError, verify_public_reviewer_packet_file


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "gauntlet" and args.gauntlet_command == "run":
        return _run_gauntlet(args)
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

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hoxline")
    subparsers = parser.add_subparsers(dest="command")

    gauntlet_parser = subparsers.add_parser("gauntlet", help="run Hoxline Gauntlet workflows")
    gauntlet_subparsers = gauntlet_parser.add_subparsers(dest="gauntlet_command")

    run_parser = gauntlet_subparsers.add_parser("run", help="run a full-loop artifact review")
    run_parser.add_argument("--artifact", required=True, help="artifact id to evaluate")
    run_parser.add_argument("--format", choices=("json", "markdown"), default="json", help="output format")
    run_parser.add_argument("--output", help="optional output file path")

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

def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise GauntletError(f"input must be a JSON object: {path}")
    return data


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
