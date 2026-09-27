from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.shark import aar_report as aar
from angerona.shark.run_manifest import expected_red_team_plan


_DIGEST = hashlib.sha256(b"inert report fixture").hexdigest()


def _history(paths=None):
    return {
        "run_id": "inert-report-run", "kind": "red_team", "status": "completed",
        "campaign": {"score_eligible": True}, "generated": "test",
        "steps": [{
            "stage": "Initial Access", "technique": "T1566.001 marker",
            "description": "inert local fixture", "ts_start": 100.0,
            "ts_end": 101.0, "ok": True, "step_id": "step-one",
            "artifact_paths": paths or [r"D:\fixture\marker.txt"],
        }],
    }


def _detector(history, **extra):
    return Event("Fixture Detector", "inert analytic evidence", Severity.HIGH, 101.0, {
        "run_id": history["run_id"], "step_id": "step-one",
        "path": history["steps"][0]["artifact_paths"][0],
        "observed_content_sha256": _DIGEST,
        "evidence_type": "native_analytic_detection", "detector_verdict": "positive",
        **extra,
    })


def _response(detector, **extra):
    path = detector.details["path"]
    return Event("Adversary Combat", "inert action receipt", Severity.HIGH, 102.0, {
        "run_id": detector.details["run_id"], "step_id": detector.details["step_id"],
        "trigger_ts": detector.ts, "trigger_module": detector.module, "path": path,
        "mitigated": True, "action_succeeded": True, "postcondition_verified": True,
        "actions": ["quarantine_file"], "action_ids": ["committed-fixture-action"],
        "verified_actions": [{
            "action": "quarantine_file", "action_id": "committed-fixture-action",
            "target": path, "postcondition_verified": True,
            "details": {"path": path, "sha256": _DIGEST},
        }],
        **extra,
    })


def _evaluate(history, events, *, authenticated=False):
    bus = EventBus()
    bus.arm(BusAuthority(b"a" * 32))
    for event in events:
        bus.publish(event)
    return aar.evaluate(
        history, bus.recent(100), require_authenticated=authenticated,
        event_verifier=bus.verify, native_verifier=lambda _event, _step: True,
    )


def test_bus_signed_combat_claim_without_journal_never_proves_containment():
    history = _history()
    detector = _detector(history)
    row = _evaluate(history, [detector, _response(detector)], authenticated=True)[0]
    assert row.response_action_reported and not row.response_action_applied
    assert not row.target_containment_verified
    assert row.containment_latency is None
    assert not row.finding_resolved  # containment does not install a detector fix
    assert aar._closure_metrics([row])["verified_closures"] == 0
    assert aar._containment_metrics(history, [row]) == {
        "count": 0, "eligible": 1, "rate": 0.0, "outcome": "failed",
    }


@pytest.mark.parametrize("change", [
    "wrapper", "legacy", "honeypot", "missing_postcondition", "wrong_action_id",
    "wrong_target", "changed_content", "missing_digest", "missing_expected_digest",
    "conflicting_expected_digest", "wrong_trigger_module", "wrong_trigger_timestamp",
    "wrong_run", "wrong_step", "timestamp_only", "replaced_summary_path",
])
def test_reported_action_without_exact_containment_never_passes(change):
    history = _history()
    detector = _detector(history)
    response = _response(detector)
    details = response.details
    action = details["verified_actions"][0]
    if change == "wrapper":
        response = replace(response, module="Active Response SOAR")
    elif change == "legacy":
        details.pop("verified_actions")
    elif change == "honeypot":
        action["action"] = "activate_honeypots"
        details["actions"] = ["activate_honeypots"]
    elif change == "missing_postcondition":
        action.pop("postcondition_verified")
    elif change == "wrong_action_id":
        action["action_id"] = "unrelated-action"
    elif change == "wrong_target":
        action["target"] = r"D:\fixture\replacement.txt"
    elif change == "changed_content":
        action["details"]["sha256"] = "b" * 64
    elif change == "missing_digest":
        action["details"].pop("sha256")
    elif change == "missing_expected_digest":
        detector.details.pop("observed_content_sha256")
    elif change == "conflicting_expected_digest":
        detector.details["sha256"] = "c" * 64
    elif change == "wrong_trigger_module":
        details["trigger_module"] = "Other Detector"
    elif change == "wrong_trigger_timestamp":
        details["trigger_ts"] = float("nan")
    elif change == "wrong_run":
        details["run_id"] = "other-run"
    elif change == "wrong_step":
        details["step_id"] = "other-step"
    elif change == "timestamp_only":
        response = replace(response, details={"trigger_ts": detector.ts, "mitigated": True})
    elif change == "replaced_summary_path":
        details["path"] = r"D:\fixture\replacement.txt"
    row = _evaluate(history, [detector, response])[0]
    assert not row.target_containment_verified
    assert aar._containment_metrics(history, [row])["outcome"] == "failed"


def test_same_timestamp_other_producer_or_target_cannot_correlate():
    history = _history()
    detector = _detector(history)
    for update in ({"trigger_module": "Other Detector"},
                   {"path": r"D:\other\marker.txt"}):
        row = _evaluate(history, [detector, _response(detector, **update)])[0]
        assert row.remediation is None
        assert not row.response_action_reported


def test_probe_cleanup_and_absence_are_never_response_evidence():
    history = _history()
    detector = _detector(history)
    cleanup = replace(_response(detector), module="Red Team Attack Engine",
                      message="Test cleanup removed the marker")
    row = _evaluate(history, [detector, cleanup])[0]
    assert row.catch is not None
    assert row.remediation is None
    assert not row.target_containment_verified


def test_aar_labels_simulation_only_match_without_implying_native_detection():
    history = _history()
    simulation = Event(
        "Purple Remediation Guard", "inert validation", Severity.HIGH, 101.0,
        {"evidence_type": "simulation_contract_validation"},
    )
    row = aar.StepVerdict(
        "Initial Access", "T1566.001 marker", "inert local fixture", 100.0, True,
        simulation_validation=simulation, simulation_validation_latency=1.0,
        catch=simulation, catch_latency=1.0,
    )
    rendered = aar.render(history, [row], "RED TEAM")
    assert (
        "Matched detection evidence (simulation validation or native analytics): 1/1"
        in rendered
    )
    assert "Native analytics   : 0/1" in rendered
    assert "Analytic catches on expected-positive steps" not in rendered
    assert "Actions reported   : 0/1 steps with matched detection evidence" in rendered
    assert "analytic catches" not in rendered.casefold()


def _comprehensive_planned_verdicts():
    safety = {"cycles": 1, "comprehensive": True, "campaign": True}
    plan = expected_red_team_plan(safety)
    history = {
        "run_id": "planned-native-opportunity", "kind": "red_team",
        "status": "completed", "safety_contract": safety,
        "campaign": {"score_eligible": True, "expected_plan": plan},
        "generated": "test", "steps": [],
    }
    rows = [
        aar.StepVerdict(
            str(row["stage"]), str(row["technique"]), "planned inert step",
            100.0 + index, True, category=str(row["category"]),
        )
        for index, row in enumerate(plan)
    ]
    return history, rows


def test_comprehensive_native_opportunities_keep_process_observation_separate():
    history, rows = _comprehensive_planned_verdicts()
    opportunity = aar._redteam_native_opportunities(history, 37)
    assert opportunity == {
        "file_marker_steps": 36,
        "process_observation_only_steps": 1,
        "unclassified_steps": 0,
        "total_expected_positive_steps": 37,
        "basis": "reviewed Red Team plan; opportunity only, not sensor coverage",
    }
    rendered = aar.render(history, rows, "RED TEAM")
    assert "Native analytics   : 0/37" in rendered
    assert (
        "Planned native opportunities: 36 FIM file-marker step(s); "
        "1 process observation-only; 0 unclassified."
    ) in rendered


def test_missing_or_changed_plan_claims_no_classified_native_opportunities():
    history, rows = _comprehensive_planned_verdicts()
    history["campaign"].pop("expected_plan")
    missing = aar._redteam_native_opportunities(history, 37)
    assert missing["file_marker_steps"] == 0
    assert missing["process_observation_only_steps"] == 0
    assert missing["unclassified_steps"] == 37

    history, rows = _comprehensive_planned_verdicts()
    history["campaign"]["expected_plan"][0]["key"] = "future_unreviewed_step"
    altered = aar._redteam_native_opportunities(history, 37)
    assert altered["file_marker_steps"] == 0
    assert altered["unclassified_steps"] == 37


def test_withheld_native_opportunities_are_counts_only_and_signed(
    tmp_path, monkeypatch,
):
    key_path = tmp_path / "fixture.key"
    key_path.write_text((b"r" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    history, rows = _comprehensive_planned_verdicts()
    history["status"] = "incomplete"
    history["campaign"]["score_eligible"] = False
    rendered = aar.render(history, rows, "RED TEAM")
    assert "Native analytics   : WITHHELD (0/37 planned contracts)" in rendered
    assert "Planned native opportunities: 36 FIM file-marker" in rendered
    result = aar._write_report(tmp_path, history, rows, rendered, "redteam_aar")
    payload = json.loads(result.report_bytes)
    assert report_attest.verify(payload) == "ok"
    taxonomy = payload["evidence_taxonomy"]
    assert taxonomy["denominator"] == 37
    assert taxonomy["native_analytic_detection"] == {"count": 0, "rate": None}
    assert taxonomy["native_analytic_opportunity"]["file_marker_steps"] == 36
    assert "rate" not in taxonomy["native_analytic_opportunity"]
    forged = copy.deepcopy(payload)
    forged["evidence_taxonomy"]["native_analytic_opportunity"]["file_marker_steps"] = 37
    assert report_attest.verify(forged) != "ok"


@pytest.mark.parametrize("origin_digest", ["exact", "wrong", "missing"])
def test_delegated_receipt_must_bind_original_authenticated_detector(origin_digest):
    history = _history()
    bus = EventBus()
    bus.arm(BusAuthority(b"d" * 32))
    bus.publish(_detector(history))
    detector = bus.recent(1)[0]
    response = _response(
        detector, trigger_module="Active Response SOAR Request", trigger_ts=101.5,
        origin_module=detector.module, origin_ts=detector.ts,
        origin_event_digest=detector.hmac_sig if origin_digest == "exact" else
                            "b" * 64 if origin_digest == "wrong" else None,
    )
    bus.publish(response)
    row = aar.evaluate(
        history, bus.recent(10), require_authenticated=False,
        event_verifier=bus.verify, native_verifier=lambda _event, _step: True,
    )[0]
    assert row.target_containment_verified is (origin_digest == "exact")


def test_all_artifacts_need_independent_verified_actions():
    history = _history([r"D:\fixture\one.txt", r"D:\fixture\two.txt"])
    first = _detector(history)
    second = _detector(history, path=history["steps"][0]["artifact_paths"][1])
    partial = _evaluate(history, [first, second, _response(first)])[0]
    assert not partial.target_containment_verified
    assert "1/2" in partial.containment_reason
    second_response = _response(second, action_ids=["second-action"])
    second_response.details["verified_actions"][0]["action_id"] = "second-action"
    complete = _evaluate(history, [first, second, _response(first), second_response])[0]
    assert complete.target_containment_verified


@pytest.mark.parametrize("created", [None, 77.0, 55.0])
def test_process_receipt_requires_exact_instance_and_all_children(created):
    history = _history()
    step = history["steps"][0]
    step.update(artifact_paths=[], pid=1234, pids=[1234, 1235],
                correlation_tokens=["inert-token"])
    detector = _detector(_history(), path=None, pid=1234, process_create_time=55.0,
                         cmdline="inert-token")
    response = _response(detector, path=None, pid=1234, process_create_time=55.0,
                         actions=["terminate_process"])
    response.details["verified_actions"] = [{
        "action": "terminate_process", "action_id": "committed-fixture-action",
        "target": "inert-child (1234)", "postcondition_verified": True,
        "details": {"pid": 1234, "process_create_time": created},
    }]
    row = _evaluate(history, [detector, response])[0]
    assert not row.target_containment_verified  # second child is still unverified
    step["pids"] = [1234]
    row = _evaluate(history, [detector, response])[0]
    assert row.target_containment_verified is (created == 55.0)


def test_repeated_artifact_cannot_reuse_an_earlier_steps_detector_or_response():
    history = _history()
    history["steps"][0].pop("step_id")
    history["steps"].append({**history["steps"][0], "ts_start": 100.5})
    detector = _detector(_history())
    detector.details.pop("step_id")
    response = _response(_detector(_history()))
    response.details.pop("step_id")
    first, second = _evaluate(history, [detector, response])
    assert first.target_containment_verified
    assert second.catch is None and not second.target_containment_verified
    assert aar._containment_metrics(history, [first, second])["outcome"] == "partial"


def test_positional_signed_artifact_digest_can_prove_removed_fixture():
    history = _history()
    history["steps"][0]["evidence_receipt"] = {"artifact_receipts": [{
        "name": "marker.txt", "status": "hashed", "sha256": _DIGEST,
    }]}
    detector = _detector(history)
    detector.details.pop("observed_content_sha256")
    assert _evaluate(history, [detector, _response(detector)])[0].target_containment_verified


@pytest.mark.parametrize("state", ["verified", "partial", "failed", "inconclusive"])
def test_signed_report_exports_separate_containment_metrics_and_outcome(tmp_path, monkeypatch, state):
    key_path = tmp_path / "fixture.key"
    key_path.write_text((b"r" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    history = _history()
    detector = _detector(history)
    rows = _evaluate(history, [detector, _response(detector)] if state != "failed" else [detector])
    if state == "partial":
        rows.append(aar.StepVerdict("Initial Access", "T1566.001 marker", "miss", 103.0, True))
    elif state == "inconclusive":
        history["status"] = "incomplete"
        history["campaign"]["score_eligible"] = False
    text = aar.render(history, rows, "RED TEAM")
    result = aar._write_report(tmp_path, history, rows, text, "redteam_aar")
    payload = json.loads(result.report_bytes)
    assert report_attest.verify(payload) == "ok"
    assert aar.verified_aar_handoff_text(result) == text
    assert payload["outcome"] == state
    metric = payload["epistemic_metrics"]["verified_containment"]
    assert metric["eligible"] == len(rows)
    assert metric["rate"] == (None if state == "inconclusive" else
                              0.5 if state == "partial" else 0.0 if state == "failed" else 1.0)
    if state == "inconclusive":
        assert "Response success   : WITHHELD" in text
        assert payload["verified_closure_rate"] is None
    tampered = copy.deepcopy(payload)
    tampered["outcome"] = "forged"
    assert report_attest.verify(tampered) != "ok"
