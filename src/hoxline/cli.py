from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .gauntlet import GauntletError, build_full_loop_run, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "gauntlet" and args.gauntlet_command == "run":
        return _run_gauntlet(args)

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
