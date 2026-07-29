from __future__ import annotations

import json
import time

import pytest

from angerona.core import drill_resolution
from angerona.core.eventbus import Event, Severity
from angerona.shark.aar_report import StepVerdict, _closure_metrics, evaluate, render


def _key(data_dir) -> None:
    (data_dir / "bus.key").write_text(bytes(range(32)).hex(), encoding="ascii")


def _finding() -> list[dict]:
    return [{"mitre": "T1003", "name": "Credential Access (simulated)"}]


def _apply(data_dir, *, run_id: str = "run-source", applied_at: float | None = None):
    return drill_resolution.apply_contracts(
        _finding(),
        run_id,
        data_dir,
        installed=["T1003"],
        cleanup_count=2,
        applied_at=applied_at,
    )[0]


def test_applied_action_is_not_closed_until_fresh_exact_proof(tmp_path):
    _key(tmp_path)
    applied = _apply(tmp_path)
    state = drill_resolution.resolution_snapshot(tmp_path)["t1003"]
    assert state["state"] == "APPLIED"
    assert not state.get("verified_at")
    assert applied["application_receipt"]["result"] == {
        "detector_candidate_installed": True,
        "technique": "T1003",
        "inert_markers_cleaned": 2,
    }
    assert drill_resolution.verify_action_receipt(
        applied["application_receipt"],
        tmp_path,
    )

    same_run = drill_resolution.verify_detector_evidence(
        "T1003",
        "run-source",
        detector="Purple Remediation Guard",
        event_ts=time.time() + 1,
        event_details={"mitre": "T1003"},
        data_dir=tmp_path,
    )
    assert not same_run["ok"]
    assert "different drill run" in same_run["error"]
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == "APPLIED"


def test_verification_rejects_wrong_detector_technique_and_contract_digest(tmp_path):
    _key(tmp_path)
    applied = _apply(tmp_path)
    event_ts = time.time() + 1
    common = {
        "mitre": "T1003",
        "verification_run_id": "run-proof",
        "event_ts": event_ts,
        "data_dir": tmp_path,
    }
    wrong_detector = drill_resolution.verify_detector_evidence(
        detector="Telemetry Scanner",
        event_details={"mitre": "T1003"},
        **common,
    )
    assert not wrong_detector["ok"]
    assert "not contract-authorized" in wrong_detector["error"]

    wrong_technique = drill_resolution.verify_detector_evidence(
        detector="Purple Remediation Guard",
        event_details={"mitre": "T1059"},
        **common,
    )
    assert not wrong_technique["ok"]
    assert "technique does not match" in wrong_technique["error"]

    wrong_contract = drill_resolution.verify_detector_evidence(
        detector="Purple Remediation Guard",
        event_details={"mitre": "T1003"},
        expected_contract_id=applied["contract_id"],
        expected_contract_digest="0" * 64,
        **common,
    )
    assert not wrong_contract["ok"]
    assert "contract digest does not match" in wrong_contract["error"]


def test_fresh_proof_closes_idempotently_and_rerun_miss_reopens(tmp_path):
    _key(tmp_path)
    applied = _apply(tmp_path)
    event_ts = time.time() + 1
    kwargs = {
        "mitre": "T1003",
        "verification_run_id": "run-proof",
        "detector": "Purple Remediation Guard",
        "event_ts": event_ts,
        "event_details": {
            "mitre": "T1003",
            "artifact_path": "_redteam_lsass_dump_probe.txt",
        },
        "data_dir": tmp_path,
        "expected_contract_id": applied["contract_id"],
        "expected_contract_digest": applied["contract_digest"],
    }
    first = drill_resolution.verify_detector_evidence(**kwargs)
    second = drill_resolution.verify_detector_evidence(**kwargs)
    assert first["ok"] and not first["idempotent"]
    assert second["ok"] and second["idempotent"]
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == (
        drill_resolution.VERIFIED_STATE
    )

    drill_resolution.record_findings(
        _finding(),
        "run-regression",
        tmp_path,
        observed_at=time.time() + 2,
    )
    reopened = drill_resolution.resolution_snapshot(tmp_path)["t1003"]
    assert reopened["state"] == "REOPENED"
    assert reopened["reopened_by_run_id"] == "run-regression"


def test_expired_verification_loses_closure_credit(tmp_path):
    _key(tmp_path)
    old = time.time() - (40 * 86_400)
    _apply(tmp_path, applied_at=old)
    result = drill_resolution.verify_detector_evidence(
        "T1003",
        "run-old-proof",
        detector="Purple Remediation Guard",
        event_ts=old + 10,
        event_details={"mitre": "T1003"},
        data_dir=tmp_path,
        verified_at=old + 20,
    )
    assert result["ok"]
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == "EXPIRED"
    refreshed = drill_resolution.verify_detector_evidence(
        "T1003",
        "run-fresh-proof",
        detector="Purple Remediation Guard",
        event_ts=time.time() + 1,
        event_details={"mitre": "T1003"},
        data_dir=tmp_path,
    )
    assert refreshed["ok"]
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == (
        drill_resolution.VERIFIED_STATE
    )


def test_tampered_state_fails_closed_and_is_not_overwritten(tmp_path):
    _key(tmp_path)
    _apply(tmp_path)
    path = drill_resolution.state_path(tmp_path)
    tampered = json.loads(path.read_text(encoding="utf-8"))
    contract = next(iter(tampered["contracts"].values()))
    contract["state"] = drill_resolution.VERIFIED_STATE
    path.write_text(json.dumps(tampered), encoding="utf-8")

    assert drill_resolution.integrity_status(tmp_path) == "bad"
    assert drill_resolution.resolution_snapshot(tmp_path) == {}
    with pytest.raises(drill_resolution.StateIntegrityError, match="not trusted"):
        drill_resolution.apply_contracts(
            _finding(),
            "attacker-run",
            tmp_path,
            installed=["T1003"],
        )
    still_tampered = json.loads(path.read_text(encoding="utf-8"))
    assert next(iter(still_tampered["contracts"].values()))["state"] == (
        drill_resolution.VERIFIED_STATE
    )


def test_contract_is_typed_and_contains_no_executable_payload(tmp_path):
    _key(tmp_path)
    applied = _apply(tmp_path)
    contract = drill_resolution.contract_snapshot(tmp_path)[applied["contract_id"]]
    assert contract["action_kind"] == (
        "install-detector-candidate-and-clean-inert-markers"
    )
    forbidden = {"command", "shell", "script", "code", "argv", "powershell"}

    def keys(value):
        if isinstance(value, dict):
            for key, child in value.items():
                yield str(key).casefold()
                yield from keys(child)
        elif isinstance(value, list):
            for child in value:
                yield from keys(child)

    assert forbidden.isdisjoint(set(keys(dict(contract))))
    assert contract["authorization"]["mode"] == "operator-reviewed"
    assert contract["rollback"]["kind"] == "remove-purple-guard-technique"


def test_rollback_removes_only_exact_policy_and_has_a_verified_receipt(tmp_path):
    _key(tmp_path)
    applied = drill_resolution.apply_contracts(
        [
            {"mitre": "T1003", "name": "Credential Access"},
            {"mitre": "T1059", "name": "Benign Execution"},
        ],
        "run-source",
        tmp_path,
        installed=["T1003", "T1059"],
    )
    from angerona.modules.purple_guard import install_policies, _read_policy

    install_policies(
        [{"mitre": "T1003"}, {"mitre": "T1059"}],
        "run-source",
        tmp_path,
    )
    target = next(row for row in applied if row["mitre"] == "T1003")
    result = drill_resolution.rollback_contract(
        "T1003",
        target["contract_id"],
        tmp_path,
    )
    assert result["ok"] and not result["idempotent"]
    assert result["contract"]["state"] == "ROLLED_BACK"
    assert drill_resolution.verify_action_receipt(
        result["contract"]["rollback_receipt"],
        tmp_path,
    )
    policy = _read_policy(tmp_path)["techniques"]
    assert "T1003" not in policy
    assert "T1059" in policy
    assert drill_resolution.rollback_contract(
        "T1003",
        target["contract_id"],
        tmp_path,
    )["idempotent"]


def test_duplicate_occurrences_and_scorecard_use_unique_finding_classes(tmp_path):
    _key(tmp_path)
    drill_resolution.record_findings(_finding(), "run-one", tmp_path)
    drill_resolution.record_findings(_finding(), "run-one", tmp_path)
    raw = json.loads(
        drill_resolution.state_path(tmp_path).read_text(encoding="utf-8")
    )
    assert len(raw["issues"]["t1003"]["occurrences"]) == 1

    rows = [
        StepVerdict(
            "Credential Access",
            "T1003 marker",
            "one",
            1.0,
            True,
            action_applied=True,
            finding_resolved=True,
        ),
        StepVerdict(
            "Credential Access",
            "T1003 marker",
            "repeat",
            2.0,
            True,
            action_applied=True,
            finding_resolved=True,
        ),
        StepVerdict(
            "Discovery",
            "read-only",
            "not actionable",
            3.0,
            True,
            category="unmonitored",
        ),
    ]
    assert _closure_metrics(rows) == {
        "actionable_classes": 1,
        "actions_applied": 1,
        "verified_closures": 1,
    }
    report = render({"run_id": "x", "generated": "test"}, rows, "RED TEAM")
    assert "Action contracts   : 1/1" in report
    assert "Verified closure   : 1/1" in report


def test_reconcile_run_turns_real_purple_echo_into_nonzero_closure(tmp_path):
    _key(tmp_path)
    _apply(tmp_path)
    started = time.time() + 1
    path = tmp_path / "drill-sandbox" / "_redteam_lsass_dump_probe.txt"
    history = {
        "run_id": "run-proof",
        "steps": [
            {
                "stage": "Credential Access (simulated)",
                "technique": "T1003 marker",
                "description": "inert marker",
                "ts_start": started,
                "ts_end": started + 0.1,
                "artifact_paths": [str(path)],
            }
        ],
    }
    catch = Event(
        "Purple Remediation Guard",
        "exact candidate detected",
        Severity.HIGH,
        ts=started + 0.2,
        details={"path": str(path), "mitre": "T1003"},
    )
    verdicts = evaluate(
        history,
        [catch],
        {"Credential Access (simulated)": "detection"},
    )
    metrics = drill_resolution.reconcile_verdicts(
        verdicts,
        "run-proof",
        tmp_path,
    )
    assert metrics["actions_applied"] == 1
    assert metrics["verified_closures"] == 1
    assert verdicts[0].finding_resolved
    report = render(history, verdicts, "RED TEAM ATTACK")
    assert "Verified closure   : 1/1 unique gap class(es)  (100%)" in report
