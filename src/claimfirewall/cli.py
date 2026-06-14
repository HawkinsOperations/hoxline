from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .claim_authority import load_claim_authority_policy
from .claim_authority import scan_paths as scan_claim_authority_paths
from .policy import load_policy
from .scanner import Finding, scan_paths


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan_with_options(args.paths, args.policy, args.exclude, args.format, args.evidence_state)

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="claimfirewall")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="scan files for blocked claims")
    scan_parser.add_argument("paths", nargs="+", help="files or directories to scan")
    scan_parser.add_argument("--exclude", action="append", default=[], help="glob pattern to exclude from scanning")
    scan_parser.add_argument(
        "--evidence-state",
        action="append",
        default=[],
        help="evidence state available to Claim Authority policy evaluation",
    )
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
    evidence_states: list[str] | None = None,
) -> int:
    try:
        authority_policy = _load_authority_policy_if_present(Path(policy_path))
        if authority_policy is not None:
            report = scan_claim_authority_paths(
                paths,
                authority_policy,
                evidence_states=evidence_states or [],
                exclude_patterns=exclude_patterns,
            )
            if output_format == "json":
                print(json.dumps(report.to_dict(), indent=2))
            elif report.allowed:
                print("Hoxline Claim Authority: claim wording allowed by configured policy")
            else:
                print(f"Hoxline Claim Authority: blocked claims found ({len(report.blocked_claims)})")
                for blocked in report.blocked_claims:
                    location = ""
                    if blocked.file_path is not None and blocked.line_number is not None:
                        location = f"{blocked.file_path}:{blocked.line_number}: "
                    print(
                        f"{location}{blocked.phrase} | reason: {blocked.reason} | "
                        f"suggested wording: {blocked.safer_replacement} | "
                        f"required evidence: {', '.join(blocked.missing_evidence)}"
                    )
            return 0 if report.allowed else 1

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


def _load_authority_policy_if_present(policy_path: Path):
    try:
        return load_claim_authority_policy(policy_path)
    except ValueError as exc:
        if "Not a Claim Authority policy" in str(exc):
            return None
        raise


def _format_finding(finding: Finding) -> str:
    return (
        f"{finding.file_path}:{finding.line_number}: "
        f"{finding.matched_claim} | reason: {finding.reason} | "
        f"suggested ceiling: {finding.suggested_ceiling}"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
