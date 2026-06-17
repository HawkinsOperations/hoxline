from __future__ import annotations

import json
from pathlib import Path

from hoxline.cli import main
from hoxline.gauntlet import render_proofcard_v1


ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "examples" / "gauntlet" / "ho-det-001-gauntlet-run-v1.json"
PROOFCARD = ROOT / "examples" / "gauntlet" / "ho-det-001-proofcard-v1.json"
SCHEMA = ROOT / "schemas" / "proofcard-v1.schema.json"


def test_proofcard_v1_example_has_required_fields() -> None:
    schema = _json(SCHEMA)
    proofcard = _json(PROOFCARD)

    for field in schema["required"]:
        assert field in proofcard
    assert proofcard["public_safe"] is False
    assert proofcard["human_review_required"] is True
    assert "runtime_evidence" in proofcard["missing_evidence"]


def test_proofcard_render_outputs_deterministic_json(capsys) -> None:
    status = main(["proofcard", "render", "--input", str(RUN)])

    output = capsys.readouterr()
    rendered = json.loads(output.out)
    assert status == 0
    assert rendered == json.loads(render_proofcard_v1(_json(RUN)))
    assert rendered["proof_ceiling"] == "CONTROLLED_TEST_VALIDATED"
    assert rendered["proof_owner"] == "hawkinsoperations-proof"
    for field in _json(SCHEMA)["required"]:
        assert field in rendered


def _json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
