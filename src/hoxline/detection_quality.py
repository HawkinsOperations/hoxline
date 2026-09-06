"""Review validation-owned source execution through the platform handoff."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
from typing import Any


class QualityReviewError(ValueError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def read_report(text: str) -> dict:
    def unique(pairs):
        result, seen = {}, set()
        for key, value in pairs:
            normalized = unicodedata.normalize("NFKC", key).casefold()
            if normalized in seen:
                raise QualityReviewError("ambiguous duplicate report keys")
            seen.add(normalized); result[key] = value
        return result
    def invalid(value):
        raise QualityReviewError("non-finite report number")
    try:
        report = json.loads(text, object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, RecursionError) as exc:
        raise QualityReviewError("malformed or ambiguous quality report") from exc
    if not isinstance(report, dict):
        raise QualityReviewError("quality report must be an object")
    return report


def compare_replay(supplied: dict, observed: dict) -> None:
    # Compare the whole reexecuted owner result, not supplied checksums/metrics.
    if canonical(supplied) != canonical(observed):
        raise QualityReviewError("report differs from fresh validation-owned replay")


def _environment() -> dict:
    result = {key: value for key, value in os.environ.items() if not key.casefold().startswith("git_")}
    result.update(GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
    return result


def _platform_identity(root: Path, revision: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise QualityReviewError("platform requires an exact commit SHA")
    def git(*args):
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, env=_environment())
        if result.returncode:
            raise QualityReviewError("platform source identity unavailable")
        return result.stdout.strip()
    if Path(git("rev-parse", "--show-toplevel")).resolve() != root.resolve():
        raise QualityReviewError("platform root is not its Git top level")
    if git("config", "--local", "--get-all", "remote.origin.url") not in (
        "https://github.com/HawkinsOperations/hawkinsoperations-platform.git",
        "https://github.com/HawkinsOperations/hawkinsoperations-platform",
        "git@github.com:HawkinsOperations/hawkinsoperations-platform.git",
    ):
        raise QualityReviewError("platform repository identity mismatch")
    if git("rev-parse", "HEAD") != revision or git("status", "--porcelain", "--untracked-files=no"):
        raise QualityReviewError("platform must be clean at the requested head")


def run_review(org_root: Path, detections_ref: str, validation_ref: str, platform_ref: str) -> dict:
    org_root = org_root.resolve()
    platform = org_root / "hawkinsoperations-platform"
    _platform_identity(platform, platform_ref)
    result = subprocess.run([
        sys.executable, "-E", "-B", str(platform / "scripts/ho_factory.py"),
        "detection-quality-run", "--repo-root", str(org_root),
        "--detections-ref", detections_ref, "--validation-ref", validation_ref,
    ], cwd=platform, capture_output=True, text=True, env=_environment())
    if result.returncode:
        raise QualityReviewError("platform rejected the validation-owned quality run")
    report = read_report(result.stdout)
    _platform_identity(platform, platform_ref)
    if report.get("schema") != "hawkinsoperations-detection-quality-v1" or report.get("owner_repository") != "HawkinsOperations/hawkinsoperations-validation" or report.get("status") != "PASS":
        raise QualityReviewError("unexpected validation owner, schema, or execution status")
    return report


def render_review(report: dict) -> str:
    metrics, mutations = report["quality"], report["mutation_metrics"]
    lines = ["# Detection source quality review", "",
             f"Executed: {report['detections_evaluated']} source rules; {metrics['events_evaluated']} controlled events.",
             f"Observed: TP={metrics['true_positive']} TN={metrics['true_negative']} FP={metrics['false_positive']} FN={metrics['false_negative']}; precision={metrics['precision']} recall={metrics['recall']} F1={metrics['f1']}.",
             f"Mutations: {mutations['generated']} generated; {mutations['killed']} killed; {mutations['survived']} survived; {mutations['errors']} errors; score={mutations['mutation_score']}.", "",
             "| Detection | Events | FP / FN | Killed / generated | Survived |",
             "|---|---:|---:|---:|---:|"]
    for package in report["packages"]:
        q, m = package["quality"], package["mutation_metrics"]
        lines.append(f"| {package['detection_id']} | {q['events_evaluated']} | {q['false_positive']} / {q['false_negative']} | {m['killed']} / {m['generated']} | {m['survived']} |")
    lines.extend(["", "Validation owns the results; platform delegates execution; Hoxline renders this review.",
                  "AI engineering labor authored candidate changes and tests. AI cannot set expected outcomes, approve disposition, close cases, or promote proof.",
                  "Survivors need corpus review; they are not silently counted as kills. Parser errors are not kills.",
                  f"Ceiling: {report['boundary']['proof_ceiling']}; NOT_PUBLIC_SAFE; human review required.",
                  "Does not prove SIEM backend parity, endpoint execution, runtime signal, production quality, or public-safe proof.",
                  f"Replay SHA-256: `{report['replay_sha256']}`."])
    return "\n".join(lines) + "\n"
