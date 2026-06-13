from __future__ import annotations

import json
from pathlib import Path

from claimfirewall.cli import main


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy" / "blocked_claims.yml"


def test_cli_pass_exit_code(capsys) -> None:
    status = main(["scan", str(ROOT / "examples" / "pass.md"), "--policy", str(POLICY)])

    output = capsys.readouterr()
    assert status == 0
    assert "no blocked claims" in output.out


def test_cli_fail_exit_code(capsys) -> None:
    status = main(["scan", str(ROOT / "examples" / "fail.md"), "--policy", str(POLICY)])

    output = capsys.readouterr()
    assert status == 1
    assert "blocked claims found" in output.out


def test_cli_json_output_valid(capsys) -> None:
    status = main(["scan", str(ROOT / "examples" / "fail.md"), "--policy", str(POLICY), "--format", "json"])

    output = capsys.readouterr()
    data = json.loads(output.out)
    assert status == 1
    assert data["findings"]
    assert {"file_path", "line_number", "matched_claim", "reason", "suggested_ceiling"} <= set(data["findings"][0])


def test_cli_missing_policy_is_nonzero(capsys) -> None:
    status = main(["scan", str(ROOT / "examples" / "pass.md"), "--policy", "missing.yml"])

    output = capsys.readouterr()
    assert status == 2
    assert "Policy file not found" in output.err


def test_cli_missing_path_is_nonzero(capsys) -> None:
    status = main(["scan", "missing.md", "--policy", str(POLICY)])

    output = capsys.readouterr()
    assert status == 2
    assert "Scan path not found" in output.err


def test_cli_exclude_behavior(capsys) -> None:
    status = main(
        [
            "scan",
            str(ROOT),
            "--policy",
            str(POLICY),
            "--exclude",
            "examples/fail.md",
            "--exclude",
            "policy/blocked_claims.yml",
        ]
    )

    output = capsys.readouterr()
    assert status == 0
    assert "no blocked claims" in output.out
