from __future__ import annotations

import time
from dataclasses import replace

import pytest

from angerona.core.detection_evaluation import (
    CohortLoss,
    CohortValidationError,
    DetectionEvaluationError,
    capture_replay_cohort,
    compare_detection_packages,
)
from angerona.core.detection_packages import DetectionPackage, seal_package


def _package(marker: str, *, package_id: str = "org.angerona.cycle32", max_ms: float = 50):
    document = {
        "schema_version": 1,
        "id": package_id,
        "version": "1.0.0",
        "owner": "Angerona tests",
        "description": "Cycle 32 inert replay fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "medium",
        "confidence": 80,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": marker},
            "condition": "selection",
        }},
        "fixtures": [
            {"name": "hit", "event": {"cmdline": f"tool {marker}"}, "expected_match": True},
            {"name": "miss", "event": {"cmdline": "notepad"}, "expected_match": False},
        ],
        "performance": {"max_eval_ms": max_ms, "max_events_per_second": 1000},
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor."},
        "expires_at": "2099-01-01T00:00:00Z",
    }
    return DetectionPackage(seal_package(document))


def _rows(*, labels: bool = True):
    return [
        {
            "event_id": "evt-shared",
            "revision": 1,
            "event": {"cmdline": "tool shared"},
            "label": True if labels else None,
            "label_source": "curator" if labels else None,
        },
        {
            "event_id": "evt-old",
            "revision": 2,
            "event": {"cmdline": "tool old"},
            "label": True if labels else None,
            "label_source": "curator" if labels else None,
        },
        {
            "event_id": "evt-new",
            "revision": 3,
            "event": {"cmdline": "tool new"},
            "label": False if labels else None,
            "label_source": "curator" if labels else None,
        },
        {
            "event_id": "evt-none",
            "revision": 4,
            "event": {"cmdline": "notepad"},
            "label": False if labels else None,
            "label_source": "curator" if labels else None,
        },
    ]


def test_immutable_cohort_binds_source_high_water_loss_and_excludes_later_rows():
    source = _rows()
    source.append({
        "event_id": "evt-later",
        "revision": 11,
        "event": {"cmdline": "tool new later"},
        "label": True,
        "label_source": "curator",
    })
    cohort = capture_replay_cohort(
        source,
        source_id="evidence-store:host-a",
        source_kind="evidence-store",
        high_water=4,
        captured_at=1000.0,
    )
    assert [row.event_id for row in cohort.rows] == [
        "evt-shared", "evt-old", "evt-new", "evt-none"
    ]
    assert cohort.loss.excluded_after_high_water == 1
    assert cohort.loss.complete
    summary = cohort.summary()
    assert summary["high_water"] == 4
    assert summary["source_digest"].startswith("sha256:")
    assert summary["cohort_digest"].startswith("sha256:")
    assert "cmdline" not in str(summary)

    # Caller and returned event mutations cannot change sealed bytes.
    source[0]["event"]["cmdline"] = "mutated"
    detached = cohort.rows[0].event()
    detached["cmdline"] = "also-mutated"
    assert cohort.rows[0].event()["cmdline"] == "tool shared"
    cohort.assert_intact()


def test_post_capture_mutation_invalidates_digest_instead_of_replaying():
    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="curated-replay", high_water=4,
        captured_at=1000.0,
    )
    object.__setattr__(
        cohort.rows[0], "event_json", '{"cmdline":"mutated after sealing"}'
    )
    with pytest.raises(CohortValidationError, match="digest"):
        cohort.assert_intact()
    with pytest.raises(CohortValidationError, match="digest"):
        compare_detection_packages(cohort, active=None, candidate=_package("new"))


def test_active_candidate_comparison_has_exact_new_lost_shared_ids_and_metrics():
    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="curated-replay", high_water=4,
        captured_at=1000.0,
    )
    active = (_package("shared", package_id="org.angerona.shared"), _package(
        "old", package_id="org.angerona.old"
    ))
    candidate = (_package("shared", package_id="org.angerona.shared2"), _package(
        "new", package_id="org.angerona.new"
    ))
    result = compare_detection_packages(
        cohort, active=active, candidate=candidate, evaluated_at=1001.0
    )
    assert result.active_event_ids == ("evt-old", "evt-shared")
    assert result.candidate_event_ids == ("evt-new", "evt-shared")
    assert result.new_event_ids == ("evt-new",)
    assert result.lost_event_ids == ("evt-old",)
    assert result.shared_event_ids == ("evt-shared",)
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.labels_used == 4
    assert result.complete
    result.assert_intact()


def test_unlabelled_replay_never_claims_precision_or_recall():
    cohort = capture_replay_cohort(
        _rows(labels=False), source_id="host", source_kind="evidence-store", high_water=4,
        captured_at=1000.0,
    )
    result = compare_detection_packages(
        cohort, active=None, candidate=_package("new"), evaluated_at=1001.0
    )
    assert result.precision is None
    assert result.recall is None
    assert result.labels_used == 0
    assert "not fully labelled" in result.metric_reason


def test_loss_or_rule_budget_failure_marks_evaluation_incomplete(monkeypatch):
    cohort = capture_replay_cohort(
        _rows(),
        source_id="host",
        source_kind="evidence-store",
        high_water=4,
        loss=CohortLoss(overflow=True, dropped_rows=2, incomplete_reason="ring overflow"),
        captured_at=1000.0,
    )
    original = DetectionPackage.evaluate

    def slow_evaluate(self, event):
        time.sleep(0.002)
        return original(self, event)

    monkeypatch.setattr(DetectionPackage, "evaluate", slow_evaluate)
    result = compare_detection_packages(
        cohort,
        active=None,
        candidate=_package("new", max_ms=0.05),
        evaluated_at=1001.0,
    )
    assert not result.complete
    assert result.rule_stats[0].budget_violations == 4
    assert result.precision is None and result.recall is None
    assert "source loss" in result.metric_reason


def test_duplicate_ids_oversized_sets_and_non_json_values_fail_closed():
    rows = _rows()
    rows[1]["event_id"] = rows[0]["event_id"]
    with pytest.raises(CohortValidationError, match="unique"):
        capture_replay_cohort(
            rows, source_id="host", source_kind="import", high_water=4,
            captured_at=1000.0,
        )

    bad = [{"event_id": "evt-bad", "revision": 1, "event": {"bad": object()}}]
    with pytest.raises(CohortValidationError, match="strict JSON"):
        capture_replay_cohort(
            bad, source_id="host", source_kind="import", high_water=1,
            captured_at=1000.0,
        )

    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="import", high_water=4,
        captured_at=1000.0,
    )
    with pytest.raises(DetectionEvaluationError, match="twice"):
        compare_detection_packages(
            cohort,
            active=None,
            candidate=(_package("new"), _package("new")),
        )


def test_evaluation_mutation_is_detected():
    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="import", high_water=4,
        captured_at=1000.0,
    )
    result = compare_detection_packages(
        cohort, active=None, candidate=_package("new"), evaluated_at=1001.0
    )
    changed = replace(result, row_count=999)
    with pytest.raises(DetectionEvaluationError, match="digest|incomplete"):
        changed.assert_intact()


def test_comparison_rejects_open_source_reasons_and_inconsistent_exact_sets():
    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="import", high_water=4,
        captured_at=1000.0,
    )
    result = compare_detection_packages(
        cohort, active=None, candidate=_package("new"), evaluated_at=1001.0
    )
    with pytest.raises(DetectionEvaluationError, match="source kind"):
        replace(result, source_kind=r"C:\Users\operator\private.evtx").assert_intact()
    with pytest.raises(DetectionEvaluationError, match="reason set"):
        replace(result, reasons=("caller supplied free-form reason",)).assert_intact()
    with pytest.raises(DetectionEvaluationError, match="new-event"):
        replace(result, new_event_ids=()).assert_intact()


def test_rule_failure_withholds_metrics_even_when_labels_and_source_are_complete(
    monkeypatch,
):
    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="curated-replay", high_water=4,
        captured_at=1000.0,
    )
    original = DetectionPackage.evaluate

    def failed_evaluate(self, event):
        if event.get("cmdline") == "tool old":
            raise RuntimeError("bounded simulated evaluator failure")
        return original(self, event)

    monkeypatch.setattr(DetectionPackage, "evaluate", failed_evaluate)
    result = compare_detection_packages(
        cohort, active=None, candidate=_package("new"), evaluated_at=1001.0
    )
    assert not result.complete
    assert result.precision is None and result.recall is None
    assert result.labels_used == 0
    assert "incomplete" in result.metric_reason


def test_replay_rule_event_product_and_wall_clock_work_are_bounded(monkeypatch):
    import angerona.core.detection_evaluation as evaluation

    cohort = capture_replay_cohort(
        _rows(), source_id="host", source_kind="curated-replay", high_water=4,
        captured_at=1000.0,
    )
    monkeypatch.setattr(evaluation, "MAX_REPLAY_EVALUATIONS", 3)
    with pytest.raises(DetectionEvaluationError, match="work budget"):
        compare_detection_packages(cohort, active=None, candidate=_package("new"))

    monkeypatch.setattr(evaluation, "MAX_REPLAY_EVALUATIONS", 250_000)
    ticks = iter((0.0, 31.0, 31.0, 31.0, 31.0, 31.0))
    monkeypatch.setattr(evaluation.time, "perf_counter", lambda: next(ticks, 31.0))
    result = compare_detection_packages(
        cohort, active=None, candidate=_package("new"), evaluated_at=1001.0
    )
    assert not result.complete
    assert result.precision is None and result.recall is None
    assert "work budget" in result.rule_stats[0].errors[0]
