"""Workflow scheduling only; no scanner/mutation/native efficacy is simulated."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import queue
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.response_proof import ProducerResponseProofs
from angerona.modules.adversary_combat import AdversaryCombat, HostMutationHeld
from angerona.shark import simulation_session as sessions


def _session(root, bus=None):
    return sessions.SimulationSession(manager=SimpleNamespace(modules={}), bus=bus,
        recorder=None, data_root=root, red_team_engine=None, shark_engine=None)


def _prepared(root, *, comprehensive=True, intensity='Low', shark=False):
    cfg = {'run_shark' if shark else 'run_redteam': True,
           'comprehensive': comprehensive, 'intensity': intensity}
    return sessions.prepare_session(cfg, data_root=root, default_target=root / 'sandbox').runs[0]


def test_policy_uses_validated_contract_count_floor_and_cap_without_changing_ttl(tmp_path):
    cases = (({'comprehensive': False}, 30.0), ({}, 55.5),
             ({'intensity': 'Extreme'}, 60.0), ({'shark': True}, 30.0))
    for options, expected in cases:
        prepared = _prepared(tmp_path, **options)
        manifest, ttl = prepared.manifest(), prepared.admitted_ttl_seconds
        assert sessions.validate_prepared_run(prepared)
        budget = sessions._workflow_settlement_budget(prepared)
        assert budget.seconds == expected
        assert budget.planned_contracts == json.loads(prepared.preflight_json)['budget']['detection_contract_steps']
        assert budget.run_id == prepared.run_id and budget.plan_sha256 == prepared.plan_sha256
        assert prepared.manifest() == manifest and prepared.admitted_ttl_seconds == ttl
        assert sessions._SETTLE_SECONDS == 30
        with pytest.raises(FrozenInstanceError):
            budget.seconds = 600.0


def test_legacy_unknown_is_declared_floor_not_a_current_plan_validation_bypass(tmp_path):
    budget = sessions._workflow_settlement_budget()
    assert budget.seconds == 30.0 and budget.planned_contracts is None
    assert budget.basis == 'legacy-unknown'
    prepared = _prepared(tmp_path)
    body = json.loads(prepared.preflight_json)
    del body['budget']['detection_contract_steps']
    with pytest.raises(sessions.SessionHeld, match='validated frozen plan'):
        sessions._workflow_settlement_budget(replace(prepared, preflight_json=json.dumps(body)))


@pytest.mark.parametrize('count', [True, False, -1, 97, 1.5, None, '37', [], float('nan'), float('inf')])
def test_tampered_or_malformed_count_never_changes_the_allowance(tmp_path, count):
    prepared = _prepared(tmp_path)
    original = sessions._workflow_settlement_budget(prepared)
    body = json.loads(prepared.preflight_json)
    body['budget']['detection_contract_steps'] = count
    with pytest.raises(sessions.SessionHeld):
        sessions._workflow_settlement_budget(replace(prepared, preflight_json=json.dumps(body)))
    assert sessions._workflow_settlement_budget(prepared) == original


class _Clock:
    def __init__(self, *, finish_after=None, work=None, cancel=None):
        self.now = 1000.0
        self.started = self.now
        self.finish_after, self.work, self.cancel = finish_after, work, cancel
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert 0 < seconds <= 0.1
        self.sleeps.append(seconds)
        self.now = round(self.now + seconds, 9)
        if self.cancel is not None and self.now - self.started >= 5:
            self.cancel.set()
        if (self.finish_after is not None and self.now - self.started >= self.finish_after
                and self.work is not None and self.work.unfinished_tasks):
            self.work.task_done()


def _waiting_session(tmp_path, monkeypatch, *, finish_after=None, expiry=200.0, legacy=False, cancel=False):
    bus = EventBus()
    bus.arm(BusAuthority(b'w' * 32))
    session = _session(tmp_path, bus)
    # These fixtures isolate queue/deadline scheduling. The real producer
    # freshness graph and its refusal cases are covered by dedicated tests;
    # no synthetic sensor or native containment claim is made here.
    monkeypatch.setattr(session, '_begin_final_producer_observation', lambda _run_id: object())
    monkeypatch.setattr(session, '_final_producer_observation_state', lambda _observation: 'complete')
    prepared = _prepared(tmp_path)
    budget = sessions._workflow_settlement_budget(prepared)
    session._workflow_current_budget = None if legacy else budget
    session._cache['current_run_id'] = '' if legacy else prepared.run_id
    # A dequeued real Queue task remains unfinished until task_done, as in Combat.
    work = queue.Queue()
    work.put(object())
    work.get_nowait()
    combat = object.__new__(AdversaryCombat)
    combat._lifecycle_generation = 1  # Stable scheduling-only response worker.
    session.manager.modules['Adversary Combat'] = combat
    monkeypatch.setattr(AdversaryCombat, 'response_snapshot',
        lambda _combat: {'queue_depth': work.qsize(), 'queue_pending': work.unfinished_tasks})
    clock = _Clock(finish_after=finish_after, work=work, cancel=session.cancelled if cancel else None)
    monkeypatch.setattr(sessions, 'time', SimpleNamespace(monotonic=clock.monotonic, sleep=clock.sleep))
    session._run_deadline = clock.now + expiry
    return session, prepared, budget, clock, work, bus


def test_real_unfinished_task_can_drain_after_baseline_with_authenticated_warning(tmp_path, monkeypatch):
    session, prepared, budget, clock, work, bus = _waiting_session(tmp_path, monkeypatch, finish_after=32)
    original_expiry = session._run_deadline
    assert session._settle_admitted_responses() is True
    record = session.workflow_settlement_snapshot(prepared.run_id)
    assert record['responses_drained'] is True and record['pending'] == 0
    assert record['elapsed_seconds'] == pytest.approx(32) and record['allowance_seconds'] == 55.5
    assert record['baseline_exceeded'] is True and record['warning']
    assert record['diagnostic_published'] is True
    warnings = [event for event in bus.recent(20) if event.module == 'Simulation Session']
    assert len(warnings) == 1 and bus.verify(warnings[0])
    assert warnings[0].details['response_authorized'] is False
    assert warnings[0].details['disposition'] == 'health'
    assert warnings[0].details['elapsed_seconds'] == pytest.approx(32)
    assert session.snapshot()['workflow_settlement_warning'] == record['warning']
    assert session._run_deadline == original_expiry and budget.seconds == 55.5
    assert work.unfinished_tasks == 0 and clock.sleeps
    record['responses_drained'] = False
    assert session.workflow_settlement_snapshot(prepared.run_id)['responses_drained'] is True


@pytest.mark.parametrize('expiry,legacy,expected', [(200, False, 55.5), (12, False, 12), (0, False, 0), (200, True, 30)])
def test_original_expiry_cap_and_unknown_floor_still_hold_real_unfinished_work(
    tmp_path, monkeypatch, expiry, legacy, expected,
):
    session, prepared, budget, clock, work, _bus = _waiting_session(tmp_path, monkeypatch,
        finish_after=100, expiry=expiry, legacy=legacy)
    original_expiry = session._run_deadline
    assert session._settle_admitted_responses() is False
    key = '' if legacy else prepared.run_id
    record = session.workflow_settlement_snapshot(key)
    assert record['allowance_seconds'] == expected
    assert record['elapsed_seconds'] == pytest.approx(expected)
    assert record['outcome'] == 'expired' and record['pending'] == 1
    assert session._run_deadline == original_expiry and work.unfinished_tasks == 1
    assert record['basis'] == ('legacy-unknown' if legacy else budget.basis)


def test_stop_does_not_fake_drain_or_spin_on_the_cancel_event(tmp_path, monkeypatch):
    session, prepared, _budget, _clock, work, _bus = _waiting_session(tmp_path, monkeypatch,
        finish_after=32, cancel=True)
    assert session._settle_admitted_responses() is True
    assert session.cancelled.is_set() and work.unfinished_tasks == 0
    assert session.workflow_settlement_snapshot(prepared.run_id)['elapsed_seconds'] == pytest.approx(32)


@pytest.mark.parametrize('pending', [True, -1, None, '0'])
def test_unknown_or_invalid_pending_never_means_completed(tmp_path, monkeypatch, pending):
    session, prepared, _budget, _clock, _work, _bus = _waiting_session(tmp_path, monkeypatch)
    monkeypatch.setattr(AdversaryCombat, 'response_snapshot', lambda _combat: {'queue_pending': pending})
    assert session._settle_admitted_responses() is False
    assert session.workflow_settlement_snapshot(prepared.run_id)['outcome'] == 'unavailable'


def test_wrong_combat_scope_is_held_and_overdue_zero_snapshot_is_not_late_success(tmp_path, monkeypatch):
    session, prepared, _budget, clock, _work, _bus = _waiting_session(tmp_path, monkeypatch)
    session.manager.modules['Adversary Combat'] = SimpleNamespace()
    assert session._settle_admitted_responses() is False
    assert session.workflow_settlement_snapshot(prepared.run_id)['outcome'] == 'unavailable'
    replacement = object.__new__(AdversaryCombat)
    replacement._lifecycle_generation = 1
    session.manager.modules['Adversary Combat'] = replacement
    def delayed_zero(_combat):
        clock.now += 60
        return {'queue_pending': 0}
    monkeypatch.setattr(AdversaryCombat, 'response_snapshot', delayed_zero)
    assert session._settle_admitted_responses() is False
    assert session.workflow_settlement_snapshot(prepared.run_id)['outcome'] == 'expired'


def test_each_prepare_freezes_fresh_budget_and_queue_flood_cannot_increase_it(tmp_path):
    session = _session(tmp_path)
    first = session.prepare({'run_redteam': True, 'intensity': 'Low'}, default_target=tmp_path / 'sandbox')
    frozen = session._workflow_budgets[first.runs[0].run_id]
    assert frozen.seconds == 55.5
    session._workflow_settlements[first.runs[0].run_id] = {'baseline_exceeded': True}
    session._cache['workflow_settlement_warning'] = 'prior run'
    session.manager.modules['Adversary Combat'] = SimpleNamespace(queue_pending=1000000)
    assert session._workflow_budgets[first.runs[0].run_id] is frozen
    second = session.prepare({'run_redteam': True, 'comprehensive': False}, default_target=tmp_path / 'sandbox')
    assert second.runs[0].run_id != first.runs[0].run_id
    assert list(session._workflow_budgets) == [second.runs[0].run_id]
    assert session._workflow_budgets[second.runs[0].run_id].seconds == 30
    assert not session._workflow_settlements and session._workflow_current_budget is None
    assert session.snapshot()['workflow_settlement_policy_seconds'] is None
    assert session.snapshot()['workflow_settlement_warning'] == ''


def test_larger_workflow_budget_never_renews_real_original_event_or_producer_receipt(tmp_path):
    assert sessions._workflow_settlement_budget(_prepared(tmp_path)).seconds == 55.5
    bus = EventBus()
    bus.arm(BusAuthority(b'e' * 32))
    event = Event('YARA Scanner', 'Expired authentic observation', Severity.HIGH, time.time() - 31,
                  {'path': str(tmp_path / 'inert.txt'), 'response_authorized': False})
    bus.publish(event)
    event = bus.recent(1)[0]  # EventBus signs a detached copy, preserving caller bytes.
    assert bus.verify(event)
    combat = object.__new__(AdversaryCombat)
    combat._bus = bus
    with pytest.raises(HostMutationHeld, match='Original response evidence expired'):
        AdversaryCombat._require_current_response_event(combat, event)
    proofs = ProducerResponseProofs()
    proofs.retain(event, generation=1, now=100.0, review={'scope': 'fixture'})
    assert proofs.verify(event, generation=1, now=129.9, review={'scope': 'fixture'})
    proofs.retain(event, generation=1, now=125.0, review={'scope': 'fixture'})
    assert not proofs.verify(event, generation=1, now=130.0, review={'scope': 'fixture'})


@pytest.mark.parametrize('finish_after,release_fails,cancel,expected_phase',
                         [(32, False, False, 'completed'), (100, False, False, 'held'),
                          (32, True, False, 'held'), (32, False, True, 'cancelled')])
def test_true_drain_report_and_release_are_all_still_required_for_finalization(
    tmp_path, monkeypatch, finish_after, release_fails, cancel, expected_phase,
):
    """Scheduling-only graph; the signed/native efficacy fixtures remain separate."""
    from angerona.modules import file_integrity, purple_guard, yara_scanner
    session, _prepared_run, _budget, clock, _work, _bus = _waiting_session(
        tmp_path, monkeypatch, finish_after=finish_after, cancel=cancel)
    plan = session.prepare({'run_redteam': True, 'intensity': 'Low'}, default_target=tmp_path / 'sandbox')
    calls = []
    engine = SimpleNamespace(_cancel=threading.Event(), run_id='', _thread=None)
    def start(prepared, **_kwargs):
        engine.run_id = prepared.run_id
        engine._thread = threading.Thread(target=lambda: None)
        engine._thread.start()
        engine._thread.join(timeout=1)
        assert engine._thread.ident is not None and not engine._thread.is_alive()
        return True
    engine.start_prepared = start
    engine.hold_evidence_for_aar = lambda: None
    engine.evidence_cleanup_scope = lambda: 'scheduling-only'
    engine.release_evidence_after_aar = lambda _scope: calls.append('engine-release')
    engine.stop_and_clean = lambda: calls.append('engine-stop')
    session.red_team_engine = engine
    monkeypatch.setattr(session, '_check_graph', lambda: None)
    monkeypatch.setattr(session, '_observe_engine_progress', lambda *_args: None)
    monkeypatch.setattr(session, '_build_report', lambda _current: calls.append('report') or object())
    monkeypatch.setattr(session, '_note_report_performance', lambda *_args: None)
    monkeypatch.setattr(sessions, 'RedTeamRunObserver', lambda *_args: SimpleNamespace(
        drain=lambda **_kwargs: None, close=lambda: calls.append('observer-close')))
    monkeypatch.setattr(file_integrity, 'watch_roots', lambda: [tmp_path / 'sandbox'])
    monkeypatch.setattr(yara_scanner, 'scan_roots', lambda: [tmp_path / 'sandbox'])
    lease = object()
    monkeypatch.setattr(purple_guard, 'acquire_redteam_validation_lease', lambda *_args, **_kwargs: lease)
    def release(actual):
        assert actual is lease
        calls.append('lease-release')
        if release_fails:
            raise RuntimeError('inert release refusal')
    monkeypatch.setattr(purple_guard.RedTeamValidationLease, 'release', release)
    session._run()
    assert session.snapshot()['phase'] == expected_phase
    assert session.finished.is_set() and len(session.completed_reports()) == 1
    assert calls.index('report') < calls.index('lease-release')
    assert calls.count('lease-release') == 1
    record = session.workflow_settlement_snapshot(plan.runs[0].run_id)
    assert record['responses_drained'] is (finish_after == 32)
    assert record['baseline_exceeded'] is True
    assert session.snapshot()['workflow_settlement_warning']
    assert session.retirement_snapshot()['retirement_held'] is release_fails
    assert session.retirement_snapshot()['custody_released'] is (not release_fails)
    if expected_phase == 'held':
        assert session.launch_diagnostics()
    assert clock.now - clock.started <= 60
