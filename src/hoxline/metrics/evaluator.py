from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


REQUIRED_EVENT_FIELDS = (
    "event_id",
    "event_time",
    "host",
    "user",
    "parent_process_name",
    "process_name",
    "process_command_line",
    "file_path",
    "expected_detection_match",
    "rationale",
)

BROWSER_PARENT_NAMES = {
    "browser.exe",
    "chrome.exe",
    "edge.exe",
    "firefox.exe",
    "msedge.exe",
    "synthetic_browser.exe",
}

SCRIPT_INTERPRETER_NAMES = {
    "cmd.exe",
    "cscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
}

CACHE_PATH_MARKERS = (
    "\\browser\\cache\\",
    "/browser/cache/",
    "\\chrome\\user data\\default\\cache\\",
    "/chrome/user data/default/cache/",
    "\\edge\\user data\\default\\cache\\",
    "/edge/user data/default/cache/",
    "\\firefox\\profiles\\synthetic\\cache2\\",
    "/firefox/profiles/synthetic/cache2/",
)


@dataclass(frozen=True)
class DetectionMetrics:
    events_total: int
    expected_positive: int
    expected_negative: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float

    def as_dict(self) -> dict[str, int | float]:
        return {
            "events_total": self.events_total,
            "expected_positive": self.expected_positive,
            "expected_negative": self.expected_negative,
            "true_positive": self.true_positive,
            "true_negative": self.true_negative,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
        }


def load_synthetic_events(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("synthetic event fixture must be a JSON object")
    if data.get("schema_version") != "synthetic-events-v0":
        raise ValueError("synthetic event fixture schema_version must be synthetic-events-v0")
    if data.get("artifact_id") != "HOX-GAUNTLET-001":
        raise ValueError("synthetic event fixture artifact_id must be HOX-GAUNTLET-001")
    events = data.get("events")
    if not isinstance(events, list):
        raise ValueError("synthetic event fixture must include an events list")
    for event in events:
        _validate_event(event)
    return data


def evaluate_detection_fixture(path: str | Path) -> DetectionMetrics:
    fixture = load_synthetic_events(path)
    events = fixture["events"]
    if not isinstance(events, list):
        raise ValueError("synthetic event fixture must include an events list")

    true_positive = true_negative = false_positive = false_negative = 0
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("synthetic event must be an object")
        expected = event["expected_detection_match"] is True
        observed = matches_browser_cache_script_interpreter(event)
        if expected and observed:
            true_positive += 1
        elif not expected and not observed:
            true_negative += 1
        elif not expected and observed:
            false_positive += 1
        else:
            false_negative += 1

    events_total = len(events)
    expected_positive = true_positive + false_negative
    expected_negative = true_negative + false_positive
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    f1 = _ratio(2 * precision * recall, precision + recall)
    false_positive_rate = _ratio(false_positive, false_positive + true_negative)

    return DetectionMetrics(
        events_total=events_total,
        expected_positive=expected_positive,
        expected_negative=expected_negative,
        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
    )


def matches_browser_cache_script_interpreter(event: dict[str, Any]) -> bool:
    parent = str(event.get("parent_process_name", "")).lower()
    process = str(event.get("process_name", "")).lower()
    file_path = str(event.get("file_path", "")).lower()
    return (
        parent in BROWSER_PARENT_NAMES
        and process in SCRIPT_INTERPRETER_NAMES
        and any(marker in file_path for marker in CACHE_PATH_MARKERS)
    )


def telemetry_coverage(events: list[dict[str, Any]], required_fields: list[str]) -> dict[str, int | float]:
    present_fields = [
        field
        for field in required_fields
        if all(isinstance(event, dict) and field in event and event[field] not in ("", None) for event in events)
    ]
    required_count = len(required_fields)
    present_count = len(present_fields)
    missing_count = required_count - present_count
    return {
        "required_fields_count": required_count,
        "present_fields_count": present_count,
        "missing_fields_count": missing_count,
        "coverage_percent": _percent(present_count, required_count),
    }


def _validate_event(event: object) -> None:
    if not isinstance(event, dict):
        raise ValueError("synthetic event must be an object")
    missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
    if missing:
        raise ValueError(f"synthetic event missing required fields: {', '.join(missing)}")
    if not isinstance(event["expected_detection_match"], bool):
        raise ValueError("expected_detection_match must be boolean")


def _ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def _percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)
