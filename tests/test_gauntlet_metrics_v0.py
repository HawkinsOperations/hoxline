from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hoxline.cli import main
from hoxline.metrics import build_work_impact_report, evaluate_detection_fixture, load_synthetic_events


ARTIFACT = ROOT / "examples" / "gauntlet" / "sample-artifact.json"
CLAIM_OUTPUT = ROOT / "examples" / "gauntlet" / "sample-claim-authority-output.json"
EXPECTED_RESULTS = ROOT / "examples" / "gauntlet" / "expected-detection-results.json"
EVENTS = ROOT / "examples" / "gauntlet" / "synthetic-events.json"
PROOFCARD = ROOT / "examples" / "gauntlet" / "sample-proofcard.json"
SAMPLE_METRICS = ROOT / "examples" / "gauntlet" / "sample-work-impact-metrics.json"
SCHEMA = ROOT / "schemas" / "work-impact-metrics-v0.schema.json"


class HoxlineGauntletMetricsV0Test(unittest.TestCase):
    def test_synthetic_event_fixture_loads(self) -> None:
        fixture = load_synthetic_events(EVENTS)
        events = fixture["events"]

        self.assertEqual(fixture["artifact_id"], "HOX-GAUNTLET-001")
        self.assertIsInstance(events, list)
        self.assertEqual(len(events), 12)
        self.assertGreaterEqual(sum(1 for event in events if event["expected_detection_match"]), 3)
        self.assertGreaterEqual(sum(1 for event in events if not event["expected_detection_match"]), 6)
        self.assertTrue(
            any(
                event["parent_process_name"] == "synthetic_browser.exe"
                and event["process_name"] == "notepad.exe"
                and event["expected_detection_match"] is False
                for event in events
            )
        )

    def test_evaluator_emits_exact_expected_confusion_matrix(self) -> None:
        metrics = evaluate_detection_fixture(EVENTS)
        expected = _load_json(EXPECTED_RESULTS)

        self.assertEqual(metrics.events_total, expected["events_total"])
        self.assertEqual(metrics.expected_positive, expected["expected_positive"])
        self.assertEqual(metrics.expected_negative, expected["expected_negative"])
        self.assertEqual(metrics.true_positive, expected["expected_true_positive"])
        self.assertEqual(metrics.true_negative, expected["expected_true_negative"])
        self.assertEqual(metrics.false_positive, expected["expected_false_positive"])
        self.assertEqual(metrics.false_negative, expected["expected_false_negative"])

    def test_detection_rates_are_numeric_and_correct(self) -> None:
        metrics = evaluate_detection_fixture(EVENTS)
        expected = _load_json(EXPECTED_RESULTS)

        self.assertIsInstance(metrics.precision, float)
        self.assertIsInstance(metrics.recall, float)
        self.assertIsInstance(metrics.f1, float)
        self.assertIsInstance(metrics.false_positive_rate, float)
        self.assertEqual(metrics.precision, expected["expected_precision"])
        self.assertEqual(metrics.recall, expected["expected_recall"])
        self.assertEqual(metrics.f1, expected["expected_f1"])
        self.assertEqual(metrics.false_positive_rate, expected["expected_false_positive_rate"])

    def test_work_impact_report_emits_numeric_sections(self) -> None:
        report = _build_report()

        self.assertEqual(report["dataset"]["events_total"], 12)
        self.assertEqual(report["detection_quality"]["true_positive"], 4)
        self.assertEqual(report["detection_quality"]["true_negative"], 8)
        self.assertEqual(report["detection_quality"]["false_positive"], 0)
        self.assertEqual(report["detection_quality"]["false_negative"], 0)
        self.assertEqual(report["telemetry_coverage"]["coverage_percent"], 100.0)
        self.assertEqual(report["claim_authority"]["block_rate_percent"], 85.71)
        self.assertEqual(report["proofcard"]["completeness_percent"], 100.0)
        self.assertTrue(report["work_impact"]["measurable_output"])
        self.assertGreater(report["work_impact"]["numeric_metrics_emitted_count"], 0)

    def test_report_keeps_all_prohibited_proof_flags_false(self) -> None:
        report = _build_report()

        self.assertEqual(report["proof_ceiling"], "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY")
        for value in report["boundary"].values():
            self.assertIs(value, False)

    def test_cli_metrics_command_prints_json(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = main(
                [
                    "gauntlet",
                    "metrics",
                    "--events",
                    str(EVENTS),
                    "--artifact",
                    str(ARTIFACT),
                    "--proofcard",
                    str(PROOFCARD),
                    "--claim-output",
                    str(CLAIM_OUTPUT),
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(status, 0)
        output = json.loads(buffer.getvalue())
        self.assertEqual(output["schema_version"], "work-impact-metrics-v0")
        self.assertEqual(output["dataset"]["events_total"], 12)
        self.assertIn("detection_quality", output)
        self.assertTrue(output["work_impact"]["measurable_output"])

    def test_sample_work_impact_metrics_matches_evaluator_output(self) -> None:
        self.assertEqual(_load_json(SAMPLE_METRICS), _build_report())

    def test_schema_validates_sample_report_when_available(self) -> None:
        sample = _load_json(SAMPLE_METRICS)
        schema = _load_json(SCHEMA)
        try:
            import jsonschema
        except ImportError:
            self.assert_required_fields_manually(sample)
        else:
            jsonschema.validate(sample, schema)

    def assert_required_fields_manually(self, sample: dict[str, object]) -> None:
        required = {
            "schema_version",
            "artifact_id",
            "metrics_generated_at",
            "proof_ceiling",
            "dataset",
            "detection_quality",
            "telemetry_coverage",
            "claim_authority",
            "proofcard",
            "evidence_gaps",
            "work_impact",
            "boundary",
        }
        self.assertTrue(required <= set(sample))
        self.assertTrue(sample["work_impact"]["measurable_output"])
        self.assertEqual(sample["proof_ceiling"], "CONTROLLED_VALIDATION_PRODUCT_DEMO_ONLY")
        for value in sample["boundary"].values():
            self.assertIs(value, False)


def _build_report() -> dict[str, object]:
    return build_work_impact_report(
        events_path=EVENTS,
        artifact_path=ARTIFACT,
        proofcard_path=PROOFCARD,
        claim_output_path=CLAIM_OUTPUT,
    )


def _load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return data


if __name__ == "__main__":
    unittest.main()
