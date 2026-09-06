"""Reject report/AI authority tampering against fresh owner replay."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hoxline.detection_quality import QualityReviewError, canonical, compare_replay, read_report, run_review, _platform_identity


class QualityReviewTests(unittest.TestCase):
    def observed(self):
        return {"schema": "hawkinsoperations-detection-quality-v1", "owner_repository": "HawkinsOperations/hawkinsoperations-validation",
                "status": "PASS", "quality": {"true_positive": 1, "false_negative": 1},
                "mutation_metrics": {"generated": 2, "killed": 1, "survived": 1, "errors": 0},
                "boundary": {"runtime_active": False, "signal_observed": False, "public_safe_status": "NOT_PUBLIC_SAFE", "human_review_required": True,
                             "ai_disposition_authority": False, "case_closure_authority": False, "proof_promotion_authority": False},
                "sources": [{"repository": "HawkinsOperations/hawkinsoperations-validation", "head": "a" * 40}],
                "inputs": [{"rule_sha256": "b" * 64, "corpus_sha256": "c" * 64}], "replay_sha256": "d" * 64}

    def test_exact_replay_and_json_order_are_deterministic(self):
        observed = self.observed()
        compare_replay(read_report(json.dumps(observed)), observed)
        compare_replay(dict(reversed(list(observed.items()))), observed)

    def test_authority_metrics_identity_and_nested_laundering_rejected(self):
        attacks = [
            ("runtime_active", True), ("signal_observed", True), ("public_safe_status", "PUBLIC_SAFE"),
            ("human_review_required", False), ("ai_disposition_authority", True),
            ("case_closure_authority", True), ("proof_promotion_authority", True),
            ("ai_disposition_authority", 0),
        ]
        observed = self.observed()
        for field, value in attacks:
            candidate = copy.deepcopy(observed); candidate["boundary"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(QualityReviewError): compare_replay(candidate, observed)
        mutations = [
            lambda c: c.update(owner_repository="HawkinsOperations/hoxline"),
            lambda c: c.update(status="APPROVED"),
            lambda c: c["sources"][0].update(head="e" * 40),
            lambda c: c["inputs"][0].update(rule_sha256="e" * 64),
            lambda c: c["inputs"][0].update(corpus_sha256="e" * 64),
            lambda c: c["quality"].update(false_negative=0),
            lambda c: c["mutation_metrics"].update(killed=2, survived=0),
            lambda c: c.update(ai_notes={"nested": [{"approval": True}]}),
            lambda c: c.update(private_evidence={"path": "../private"}),
            lambda c: c.update(closed_cases=1),
            lambda c: c.update(human_approval=True),
            lambda c: c.update(proof_ceiling="PUBLIC_PROOF_SAFE"),
        ]
        for mutation in mutations:
            candidate = copy.deepcopy(observed); mutation(candidate)
            candidate["replay_sha256"] = hashlib.sha256(canonical(candidate).encode()).hexdigest()
            with self.subTest(candidate=candidate), self.assertRaises(QualityReviewError): compare_replay(candidate, observed)

    def test_duplicate_unicode_and_nonfinite_json_fail_closed(self):
        for text in ('{"a": 1, "a": 2}', '{"Ａ": 1, "a": 2}', '{"n": NaN}', '{"n": Infinity}', '[]', '{broken'):
            with self.subTest(text=text), self.assertRaises(QualityReviewError): read_report(text)

    def test_mutable_ref_never_executes_platform(self):
        for ref in ("main", "HEAD", "../main", "a" * 39, "a" * 41, "a" * 40 + ":path"):
            with self.subTest(ref=ref), patch("hoxline.detection_quality.subprocess.run") as run:
                with self.assertRaises(QualityReviewError): _platform_identity(Path("platform"), ref)
                run.assert_not_called()

    def test_failed_platform_execution_cannot_produce_success(self):
        with patch("hoxline.detection_quality._platform_identity"), patch("hoxline.detection_quality.subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = json.dumps(self.observed())
            with self.assertRaises(QualityReviewError): run_review(Path("org"), "a" * 40, "b" * 40, "c" * 40)

    def test_wrong_owner_rejected_even_when_subprocess_returns_zero(self):
        with patch("hoxline.detection_quality._platform_identity"), patch("hoxline.detection_quality.subprocess.run") as run:
            run.return_value.returncode = 0
            report = self.observed(); report["owner_repository"] = "HawkinsOperations/hawkinsoperations-website"
            run.return_value.stdout = json.dumps(report)
            with self.assertRaises(QualityReviewError): run_review(Path("org"), "a" * 40, "b" * 40, "c" * 40)


if __name__ == "__main__":
    unittest.main()
