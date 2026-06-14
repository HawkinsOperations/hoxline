from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .policy import load_policy
from .scanner import Finding, scan_paths


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan_with_options(args.paths, args.policy, args.exclude, args.format)

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="claimfirewall")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="scan files for blocked claims")
    scan_parser.add_argument("paths", nargs="+", help="files or directories to scan")
    scan_parser.add_argument("--exclude", action="append", default=[], help="glob pattern to exclude from scanning")
    scan_parser.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    scan_parser.add_argument(
        "--policy",
        default="policy/blocked_claims.yml",
        help="path to blocked claims policy",
    )

    return parser


def _scan_with_options(
    paths: list[str],
    policy_path: str,
    exclude_patterns: list[str],
    output_format: str,
) -> int:
    try:
        policy = load_policy(Path(policy_path))
        findings = scan_paths(paths, policy, exclude_patterns)
    except (FileNotFoundError, ValueError, OSError) as exc:
        if output_format == "json":
            print(json.dumps({"error": str(exc), "findings": []}, indent=2))
        else:
            print(f"Hoxline Claim Firewall: error: {exc}", file=sys.stderr)
        return 2

    if output_format == "json":
        print(json.dumps({"findings": [finding.to_dict() for finding in findings]}, indent=2))
        return 1 if findings else 0

    if findings:
        print(f"Hoxline Claim Firewall: blocked claims found ({len(findings)})")
        for finding in findings:
            print(_format_finding(finding))
        return 1

    print("Hoxline Claim Firewall: no blocked claims found")
    return 0


def _format_finding(finding: Finding) -> str:
    return (
        f"{finding.file_path}:{finding.line_number}: "
        f"{finding.matched_claim} | reason: {finding.reason} | "
        f"suggested ceiling: {finding.suggested_ceiling}"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
