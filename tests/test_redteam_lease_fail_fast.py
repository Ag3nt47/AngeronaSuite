from __future__ import annotations

from angerona.modules.purple_guard import RedTeamValidationError, RedTeamValidationLease
from angerona.shark import red_team
from angerona.shark.red_team import RedTeamEngine


def test_redteam_stops_after_validation_authority_is_lost(tmp_path, monkeypatch) -> None:
    narration: list[str] = []
    engine = RedTeamEngine(tmp_path, on_event=narration.append)
    engine.run_id = "redteam-lease-loss-fixture"
    engine._complexity = 1
    engine._campaign = False
    engine._comprehensive = False
    engine._validation_lease = object()
    engine._evidence_lease = True
    engine._running.set()
    engine._expected_plan = [
        {"cycle": 1, "key": "initial_access", "stage": "Initial Access",
         "technique": "fixture", "plan_step_id": "RTP1-C01-INITIAL"},
        {"cycle": 1, "key": "credential_access", "stage": "Credential Access",
         "technique": "fixture", "plan_step_id": "RTP1-C01-CREDENTIAL"},
    ]
    calls = 0

    def assert_identity(_lease, *, run_id):
        nonlocal calls
        assert run_id == engine.run_id
        calls += 1
        if calls > 1:
            raise RedTeamValidationError("marker custody is stale")

    monkeypatch.setattr(
        RedTeamValidationLease, "assert_target_identity", staticmethod(assert_identity)
    )
    monkeypatch.setattr(
        RedTeamValidationLease, "assert_live_producers", staticmethod(
            lambda _lease, *, run_id: None
        )
    )

    def _step_initial_access(_jitter):
        engine._record("Initial Access", "fixture", "completed", 1.0)

    def _step_credential_access(_jitter):
        raise AssertionError("a doomed later step must not execute")

    monkeypatch.setattr(engine, "_step_initial_access", _step_initial_access)
    monkeypatch.setattr(engine, "_step_credential_access", _step_credential_access)
    monkeypatch.setattr(red_team.random, "shuffle", lambda _stages: None)
    statuses: list[str] = []

    def write_history(status="completed"):
        statuses.append(status)
        return status

    monkeypatch.setattr(engine, "_write_history", write_history)
    engine._run_playbook((0.0, 0.0), 0.0)

    assert calls == 2
    assert statuses == ["incomplete"]
    assert [step.ok for step in engine.steps] == [True, False]
    assert "marker custody is stale" in engine.steps[1].detail
    assert engine.is_running is False
    assert any("stopped early" in line for line in narration)
