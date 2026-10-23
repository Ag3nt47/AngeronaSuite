from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from angerona.core.detection_evaluation import capture_replay_cohort
from angerona.core.detection_packages import load_package
from tools import evaluate_detections as cli


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "cohorts"


def cohort(events, *, source="test-only-labelled-events"):
    return capture_replay_cohort([
        dict(event_id=f"id-{index}", revision=index, event=event, label=index % 2 == 0,
             label_source="synthetic test only") for index, event in enumerate(events)
    ], source_id=source, source_kind="synthetic", high_water=len(events))


def package():
    return load_package(EXAMPLES / "candidate.json")


def test_actual_cli_disjoint_replay_keeps_misses_and_seals_holdout_scope(tmp_path):
    output = tmp_path / "comparison.json"
    arguments = ["--candidate", str(EXAMPLES / "candidate.json"), "--cohort",
                 str(EXAMPLES / "labelled.json"), "--training-cohort",
                 str(EXAMPLES / "training.json"), "--output", str(output)]
    assert cli.main(arguments) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["holdout"]["status"] == "disjoint"
    assert report["holdout"]["evaluation_rows"] == 8
    assert report["holdout"]["training_rows"] == 4
    assert not report["holdout"]["independent_review_verified"]
    assert report["candidate"]["false_positive"] == 1
    assert report["candidate"]["false_negative"] == 2
    seal = report.pop("report_digest")
    assert seal == "sha256:" + hashlib.sha256(cli._canonical(report)).hexdigest()
    # Outputs cannot replace a declared training source.
    arguments[-1] = str(EXAMPLES / "training.json")
    before = (EXAMPLES / "training.json").read_bytes()
    assert cli.main(arguments) == 2
    assert (EXAMPLES / "training.json").read_bytes() == before


def test_new_ids_labels_and_revisions_cannot_hide_training_payload_overlap():
    evaluation = cohort([{"activity": "positive"}, {"activity": "benign"}])
    training = capture_replay_cohort([
        dict(event_id="renamed", revision=999, event={"activity": "positive"},
             label=False, label_source="changed label")
    ], source_id="renamed-source", source_kind="synthetic", high_water=999)
    with pytest.raises(ValueError, match="overlaps a training"):
        cli.assess_holdout(evaluation, [training], [package()])


def test_package_fixture_cannot_be_reported_as_held_out():
    candidate = package()
    evaluation = cohort([candidate.document["fixtures"][0]["event"], {"unique": "benign"}])
    with pytest.raises(ValueError, match="overlaps a package fixture"):
        cli.assess_holdout(evaluation, [cohort([{"train": 1}])], [candidate])


def test_identical_payload_cannot_inflate_denominators_even_under_distinct_ids():
    evaluation = cohort([{"same": 1}, {"same": 1}])
    with pytest.raises(ValueError, match="duplicate event payloads"):
        cli.assess_holdout(evaluation, [cohort([{"train": 1}])], [package()])


def test_holdout_requires_declared_training_and_benign_denominator():
    evaluation = cohort([{"only": "positive"}])
    with pytest.raises(ValueError, match="explicit training"):
        cli.assess_holdout(evaluation, [], [package()])
    with pytest.raises(ValueError, match="both positive and benign"):
        cli.assess_holdout(evaluation, [cohort([{"train": 1}])], [package()])


def test_incomplete_training_never_receives_disjoint_holdout_credit():
    from angerona.core.detection_evaluation import CohortLoss
    evaluation = cohort([{"positive": 1}, {"benign": 2}])
    training = capture_replay_cohort([
        dict(event_id="training", revision=1, event={"unseen": "training"}, label=True,
             label_source="test-only")
    ], source_id="lost-source", source_kind="synthetic", high_water=1,
        loss=CohortLoss(dropped_rows=1))
    with pytest.raises(ValueError, match="complete labelled"):
        cli.assess_holdout(evaluation, [training], [package()])


def test_duplicate_training_and_mutated_package_are_rejected():
    evaluation = cohort([{"positive": 1}, {"benign": 2}])
    training = cohort([{"train": 1}])
    with pytest.raises(ValueError, match="Duplicate training"):
        cli.assess_holdout(evaluation, [training, training], [package()])
    candidate = package()
    candidate.document["logic"]["detection"]["selection"]["indicator"] = "changed"
    with pytest.raises(ValueError, match="digest"):
        cli.assess_holdout(evaluation, [training], [candidate])


def test_holdout_has_total_row_and_training_count_bounds(monkeypatch):
    evaluation = cohort([{"positive": 1}, {"benign": 2}])
    training = cohort([{"train": 1}])
    with pytest.raises(ValueError, match="1 through 8"):
        cli.assess_holdout(evaluation, [training] * 9, [package()])
    monkeypatch.setattr(cli, "MAX_HOLDOUT_COMPARISON_ROWS", 2)
    with pytest.raises(ValueError, match="40000 total rows"):
        cli.assess_holdout(evaluation, [training], [package()])
