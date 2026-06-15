from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .gauntlet import GauntletError, build_full_loop_run, render_markdown, verify_full_loop_run_file


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "gauntlet" and args.gauntlet_command == "run":
        return _run_gauntlet(args)
    if args.command == "gauntlet" and args.gauntlet_command == "verify":
        return _verify_gauntlet(args)

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

    print("Hoxline Gauntlet verify: PASS")
    return 0
