from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .gauntlet import GauntletError, build_full_loop_run, render_markdown, verify_full_loop_run_file
from .gauntlet import decide_claim_authority_v1, render_proofcard_v1, summarize_gauntlet_run_v1


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

    return parser


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


def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise GauntletError(f"input must be a JSON object: {path}")
    return data


def _print_decision_summary(decision: dict[str, object]) -> None:
    print(f"proof_ceiling: {decision['proof_ceiling']}")
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
