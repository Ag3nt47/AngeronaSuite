from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from angerona.core.detection_packages import PackageValidationError, load_package
from tools import evaluate_detections as cli

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "cohorts"


def _arguments(output, cohort=None, candidate=None):
    return ["--active", str(EXAMPLES / "active.json"),
            "--candidate", str(candidate or EXAMPLES / "candidate.json"),
            "--cohort", str(cohort or EXAMPLES / "labelled.json"), "--output", str(output)]


def _cohort(tmp_path, change):
    document = json.loads((EXAMPLES / "labelled.json").read_text(encoding="utf-8"))
    change(document)
    path = tmp_path / "cohort.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_actual_fixture_gated_replay_reports_tradeoffs_and_binds_every_result(tmp_path):
    output = tmp_path / "comparison.json"
    assert cli.main(_arguments(output)) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["quality_available"] is True
    assert report["quality_gate"]["status"] == "measured"
    assert report["active"]["true_positive"] == 2
    assert report["active"]["false_positive"] == 2
    assert report["candidate"]["true_positive"] == 2
    assert report["candidate"]["false_positive"] == 1
    assert report["candidate"]["false_negative"] == 2
    assert report["candidate"]["true_negative"] == 3
    assert report["candidate"]["precision"] == pytest.approx(2 / 3)
    assert report["candidate"]["recall"] == .5
    assert report["candidate"]["false_positive_rate"] == .25
    assert set(report["comparison"]["new_event_ids"]) == {"new-positive", "new-false-positive"}
    assert set(report["comparison"]["lost_event_ids"]) == {
        "developer-benign", "backup-benign", "lost-positive",
    }
    digest = report.pop("report_digest")
    assert digest == "sha256:" + hashlib.sha256(cli._canonical(report)).hexdigest()
    report["candidate"]["false_negative"] = 0
    assert digest != "sha256:" + hashlib.sha256(cli._canonical(report)).hexdigest()
    assert not list(tmp_path.glob("*.tmp"))


def test_declared_source_loss_withholds_all_quality_metrics(tmp_path):
    path = _cohort(tmp_path, lambda value: value["loss"].update(dropped_rows=3, overflow=True))
    output = tmp_path / "comparison.json"
    assert cli.main(_arguments(output, path)) == 3
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["quality_available"] is False
    assert report["comparison"]["loss"]["dropped_rows"] == 3
    assert report["comparison"]["precision"] is None
    assert all(value is None for value in report["candidate"].values())
    assert report["quality_gate"]["status"] == "withheld"


@pytest.mark.parametrize("label", [None, "malicious", 1])
def test_every_quality_row_requires_an_explicit_boolean_label(tmp_path, label):
    path = _cohort(tmp_path, lambda value: value["rows"][0].update(label=label))
    output = tmp_path / "comparison.json"
    assert cli.main(_arguments(output, path)) == 2
    assert not output.exists()


def test_high_water_preserves_exclusions_and_does_not_expand_the_scored_cohort(tmp_path):
    path = _cohort(tmp_path, lambda value: value.update(high_water=7))
    output = tmp_path / "comparison.json"
    assert cli.main(_arguments(output, path)) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["comparison"]["row_count"] == 7
    assert report["comparison"]["loss"]["excluded_after_high_water"] == 1
    assert "new-false-positive" not in report["comparison"]["candidate_event_ids"]


def test_candidate_quality_gate_fails_without_hiding_measured_false_negatives(tmp_path):
    output = tmp_path / "comparison.json"
    assert cli.main(_arguments(output) + ["--max-false-negatives", "0"]) == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["candidate"]["false_negative"] == 2
    assert report["quality_gate"]["status"] == "fail"


def test_fixture_gate_and_input_content_are_preserved(tmp_path):
    from angerona.core.detection_packages import seal_package

    package = json.loads((EXAMPLES / "candidate.json").read_text(encoding="utf-8"))
    package["fixtures"][0]["expected_match"] = False
    candidate = tmp_path / "bad-package.json"
    candidate.write_text(json.dumps(seal_package(package)), encoding="utf-8")
    before = candidate.read_bytes()
    assert cli.main(_arguments(tmp_path / "result.json", candidate=candidate)) == 2
    assert candidate.read_bytes() == before
    assert not (tmp_path / "result.json").exists()
    assert cli.main(_arguments(candidate, candidate=candidate)) == 2


def test_cohort_limits_duplicate_keys_and_non_finite_numbers_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "cohort.json"
    path.write_text('{"schema":1,"schema":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        cli.load_cohort(path)
    path.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="finite"):
        cli.load_cohort(path)
    monkeypatch.setattr(cli, "MAX_INPUT_BYTES", 16)
    path.write_bytes(b" " * 17)
    with pytest.raises(ValueError, match="budget"):
        cli.load_cohort(path)


def test_package_loader_bounds_actual_read_and_rejects_duplicate_fields(tmp_path, monkeypatch):
    from angerona.core import detection_packages

    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * 17)
    monkeypatch.setattr(detection_packages, "MAX_PACKAGE_BYTES", 16)
    with pytest.raises(PackageValidationError, match="maximum size"):
        load_package(path)
    monkeypatch.setattr(detection_packages, "MAX_PACKAGE_BYTES", 100)
    path.write_text('{"id":"one","id":"two"}', encoding="utf-8")
    with pytest.raises(PackageValidationError, match="duplicate"):
        load_package(path)
