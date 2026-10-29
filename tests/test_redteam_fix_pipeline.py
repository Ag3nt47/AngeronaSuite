from __future__ import annotations

import time
import copy
import json
import os
import threading
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import drill_resolution
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.practice_verification import _find_response, verify_practice_fixes
from angerona.core.storage import FlightRecorder
from angerona.modules.purple_guard import PurpleGuard, install_policies
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.shark.aar_report import StepVerdict, evaluate


def _key(root) -> None:
    (root / "bus.key").write_text(bytes(range(32)).hex(), encoding="ascii")


def _offline_practice_inventory(monkeypatch):
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot
    # This fixture supplies only general readiness. The exact owned child is
    # still independently observed by the real native issuer API.
    monkeypatch.setattr(process_monitor, "process_snapshot", lambda *a, **k:
        ProcessSnapshot((), time.time(), True, 0, 0, 0, 0, "", True))


def _shared_practice_combat(root, manager, response):
    from angerona.modules.adversary_combat import AdversaryCombat, CombatPolicy
    combat = AdversaryCombat(root, rollback_anchor={})
    combat.bind(manager.bus)
    combat.bind_manager(manager)
    combat.policy = lambda: CombatPolicy(
        block_network=False, isolate_host=False, activate_honeypots=False,
    )
    manager.modules[combat.name] = combat
    response.bind_manager(manager)
    combat.start()
    deadline = time.monotonic() + 5
    while not combat.response_ready() and time.monotonic() < deadline:
        time.sleep(.01)
    assert combat.response_ready(), combat.health_note
    return combat


def _assert_issuer_original_response(bus, result):
    verification_id = result["results"][0]["verification_id"]
    events = bus.recent(500)
    detection = next(event for event in events
        if event.module == "Purple Remediation Guard"
        and event.details.get("practice_verification_id") == verification_id)
    response = next(event for event in events
        if event.module == "Active Response SOAR"
        and event.details.get("trigger_ts") == detection.ts
        and event.details.get("mitigated") is True)
    assert bus.verify(detection) and bus.verify(response)
    assert response.details["delegation_mode"] == "issuer-original-event"
    assert response.details["origin_event_digest"] == detection.hmac_sig
    assert response.details["queue_request_id"] is None
    assert not any(event.module in {"Active Response SOAR Request", "Red Team Practice Lab"}
                   for event in events)


@pytest.fixture
def source_canary(tmp_path, monkeypatch):
    """Actual issuer/file custody; only unrelated inventory and queue intake are inert."""
    if os.name != "nt":
        pytest.skip("Windows exact canary custody")
    from angerona.core.practice_verification import _write_registered_marker
    from angerona.modules.adversary_combat import AdversaryCombat, CombatPolicy
    from angerona.modules.purple_guard import RedTeamValidationLease, acquire_redteam_validation_lease
    _offline_practice_inventory(monkeypatch)
    root = tmp_path / "runtime"
    root.mkdir()
    _key(root)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (False, "Source Observe"))
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard, combat = PurpleGuard(root), AdversaryCombat(root, rollback_anchor={})
    guard.bind(bus)
    combat.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={guard.name: guard, combat.name: combat})
    combat.bind_manager(manager)
    monkeypatch.setattr(combat, "policy", lambda: CombatPolicy(
        block_network=False, isolate_host=False, activate_honeypots=False, process_action="terminate"))
    # Tests dispatch the exact original directly; the real worker still owns
    # lifecycle/journal preparation, and the real detector mints its own proof.
    monkeypatch.setattr(combat, "_submit", lambda _event: None)
    lease, run_id = None, None
    try:
        combat.start()
        deadline = time.monotonic() + 5
        while not combat.response_ready() and time.monotonic() < deadline:
            time.sleep(.01)
        assert combat.response_ready()
        target = root / "drill-sandbox"
        lease = acquire_redteam_validation_lease(manager, bus, recorder, root, target, timeout=3)
        run_id = uuid.uuid4().hex
        RedTeamValidationLease.consume_for_run(lease, run_id=run_id, target=target, data_root=root)
        marker = target / f"_redteam_lsass_dump_practice_{run_id}.txt"
        _write_registered_marker(marker, "ANGERONA inert boundary control\n", run_id, lease=lease)
        guard.scan_once(guard._policy_snapshot())
        event = next(event for event in reversed(bus.recent(100))
                     if event.module == guard.name and event.details.get("path") == str(marker))
        assert bus.verify(event)
        yield SimpleNamespace(root=root, marker=marker, event=event, lease=lease, guard=guard, run_id=run_id,
                              combat=combat, manager=manager, bus=bus, recorder=recorder)
    finally:
        modules = tuple(manager.modules.values())
        threads = tuple(module._thread for module in modules if module._thread is not None)
        if lease is not None:
            RedTeamValidationLease.release(lease)
        if run_id is not None:
            from angerona.core.practice_scope import unregister_run
            unregister_run(run_id)
        for module in modules:
            module.stop()
        for thread in threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in threads)
        recorder.close()


def test_source_canary_success_preserves_host_hold_and_public_undo_denial(source_canary):
    graph = source_canary
    action = graph.combat._quarantine_file(str(graph.marker), graph.event, "combat-000000000001")
    assert action is not None and action.status == "applied"
    assert not graph.marker.exists()
    status = graph.combat.response_snapshot()
    assert status["state"] == "AUTHORITY HELD" and status["ready"] is False
    assert status["canary_ready"] is True
    assert "Source Observe" in status["reason"]
    assert graph.combat.undo_action(action.action_id)["ok"] is False
    assert not graph.marker.exists()
    assert Path(action.details["quarantine"]).is_file()


@pytest.mark.parametrize("change", ["expired", "released", "replaced", "foreign-manager", "raw-practice", "foreign-target"])
def test_source_canary_cannot_authorize_stale_foreign_or_metadata_only_targets(source_canary, monkeypatch, change):
    from angerona.modules.purple_guard import RedTeamValidationLease, _lease_authority
    graph = source_canary
    event, target = graph.event, graph.marker
    if change == "expired":
        _lease_authority(graph.lease).run_deadline_monotonic = time.monotonic() - 1
    elif change == "released":
        RedTeamValidationLease.release(graph.lease)
    elif change == "replaced":
        old_identity = target.stat().st_ino
        RedTeamValidationLease.begin_marker_containment(graph.lease, graph.combat, event, target)
        data = target.read_bytes()
        target.replace(graph.root / "retained-original-control.txt")
        target.write_bytes(data)
        assert target.stat().st_ino != old_identity
    elif change == "foreign-manager":
        monkeypatch.setattr(graph.combat, "_manager", SimpleNamespace(
            modules=graph.manager.modules, bus=graph.bus, recorder=graph.recorder))
    else:
        event = copy.deepcopy(event)
        if change == "raw-practice":
            event.details["detector_receipt_mac"] = "0" * 64
            event.details["disposition"] = "practice"
        else:
            target = graph.root / "ordinary-host-file.txt"
            target.write_bytes(b"ordinary unrelated file")
            event.details["path"] = str(target)
            event.details["response_contract"]["targets"]["path"] = str(target)
        event = replace(event, hmac_sig=graph.recorder.authority.sign(event))
        assert graph.bus.verify(event), "The negative must reach the private issuer-proof boundary"
    before = target.read_bytes()
    assert graph.combat._quarantine_file(str(target), event, "combat-000000000002") is None
    assert target.read_bytes() == before
    assert not any(row.get("status") == "applied" for row in graph.combat.list_actions())


@pytest.mark.parametrize("change", ["expired", "released", "stop", "disabled-policy"])
def test_source_canary_rechecks_authority_after_durable_intent(source_canary, monkeypatch, change):
    from angerona.modules.purple_guard import RedTeamValidationLease, _lease_authority
    graph = source_canary
    policy, entered = graph.combat.policy(), []
    original = graph.combat._journal_intent
    def revoke_after_intent(action):
        original(action)
        entered.append(action.action_id)
        if change == "expired":
            _lease_authority(graph.lease).run_deadline_monotonic = time.monotonic() - 1
        elif change == "released":
            RedTeamValidationLease.release(graph.lease)
        elif change == "stop":
            graph.combat.stop()
        else:
            monkeypatch.setattr(graph.combat, "policy", lambda: replace(policy, enabled=False))
    monkeypatch.setattr(graph.combat, "_journal_intent", revoke_after_intent)
    identity = graph.marker.stat().st_ino
    assert graph.combat._quarantine_file(str(graph.marker), graph.event, "combat-000000000003") is None
    assert len(entered) == 1
    assert graph.marker.stat().st_ino == identity


def test_source_ordinary_process_network_and_program_effects_stay_held(source_canary, monkeypatch):
    import subprocess
    import sys
    import psutil
    from angerona.modules.adversary_combat import CombatPolicy
    graph = source_canary
    monkeypatch.setattr(graph.combat, "_run_firewall", lambda *_a, **_k: pytest.fail("No firewall effect"))
    child = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-I", "-c", "import time;time.sleep(15)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        created = psutil.Process(child.pid).create_time()
        event = Event("ordinary-host-detector", "public practice labels grant no authority", Severity.HIGH,
                      details={"pid": child.pid, "process_create_time": created, "disposition": "practice",
                               "response_authorized": True, "response_contract": {
                                   "version": 1, "actions": ["terminate_process"],
                                   "targets": {"pid": child.pid, "process_create_time": created}}})
        event = replace(event, hmac_sig=graph.recorder.authority.sign(event))
        assert graph.bus.verify(event)
        assert graph.combat._block_remote_ip("192.0.2.25", event, "combat-000000000004") is None
        assert graph.combat._block_program("C:/ordinary.exe", child.pid, created, event, "combat-000000000004") is None
        assert graph.combat._act_on_process(child.pid, CombatPolicy(), event, "combat-000000000004") is None
        assert child.poll() is None, "A real owned but unleased child must not inherit canary authority"
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="Actual final Windows process dispatch")
@pytest.mark.parametrize("change", ["expired", "stop", "disabled-policy"])
def test_source_owned_child_rechecks_issuer_and_stop_at_final_native_dispatch(tmp_path, monkeypatch, change):
    from angerona.modules.purple_guard import _lease_authority
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (False, "Source Observe"))
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard, response = PurpleGuard(tmp_path), ActiveResponseSOAR()
    guard.bind(bus)
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={guard.name: guard, response.name: response})
    combat = _shared_practice_combat(tmp_path, manager, response)
    baseline = combat.policy()
    enabled = [True]
    monkeypatch.setattr(combat, "policy", lambda: replace(baseline, enabled=enabled[0]))
    acquire = combat._acquire_termination_lease
    held_at_refusal, producers = [], []

    def wrapped_acquire(action):
        real = acquire(action)
        producers[:] = tuple(manager.modules.values())
        class FinalDispatch:
            def __getattr__(self, name):
                return getattr(real, name)

            def terminate(self, *, before_dispatch=None):
                def revoke_after_native_validation():
                    if change == "expired":
                        _lease_authority(guard._validation_lease).run_deadline_monotonic = time.monotonic() - 1
                    elif change == "stop":
                        combat.stop()
                    else:
                        enabled[0] = False
                    try:
                        before_dispatch()
                    except Exception:
                        # This is the actual retained kernel object after the
                        # real adapter's final native identity check, not a fake
                        # Process.kill/terminate callback or mere PID assertion.
                        real.validate(alive=True)
                        held_at_refusal.append(not real.dispatch_started)
                        raise
                real.terminate(before_dispatch=revoke_after_native_validation)
        return FinalDispatch()

    monkeypatch.setattr(combat, "_acquire_termination_lease", wrapped_acquire)
    try:
        result = verify_practice_fixes(
            ["T1059"], source_run_id="boundary-source", data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db", bus=bus, purple_guard=guard,
            active_response=response, manager=manager, recorder=recorder, recorder_timeout=3,
        )
        assert result["ok"] is False
        assert held_at_refusal == [True], "The actual final callback must be reached and refuse before termination"
        assert not any(row.get("action") == "terminate_process" and row.get("status") == "applied"
                       for row in combat.list_actions())
    finally:
        modules = tuple(dict.fromkeys([*producers, *manager.modules.values()]))
        threads = tuple(module._thread for module in modules if module._thread is not None)
        for module in modules:
            module.stop()
        for thread in threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in threads)
        recorder.close()


@pytest.mark.parametrize("change", ["expired", "stop", "replacement"])
def test_source_immediate_canary_rollback_preserves_when_scope_ends(source_canary, monkeypatch, change):
    from angerona.modules.purple_guard import _lease_authority
    graph = source_canary
    original_bytes = graph.marker.read_bytes()
    moved = []
    append = graph.combat._append_journal
    def fail_terminal_after_move(record):
        if record.get("record_type") == "commit" and record.get("action") == "quarantine_file":
            quarantine = Path(record["details"]["quarantine"])
            assert quarantine.is_file() and not graph.marker.exists()
            moved.append(quarantine)
            if change == "expired":
                _lease_authority(graph.lease).run_deadline_monotonic = time.monotonic() - 1
            elif change == "stop":
                graph.combat.stop()
            else:
                graph.marker.write_bytes(b"foreign replacement must survive")
            raise OSError("inert terminal-failure injection")
        return append(record)
    monkeypatch.setattr(graph.combat, "_append_journal", fail_terminal_after_move)
    assert graph.combat._quarantine_file(str(graph.marker), graph.event, "combat-000000000005") is None
    assert len(moved) == 1
    assert moved[0].read_bytes() == original_bytes
    assert graph.combat._mutation_blocked is True
    if change == "replacement":
        assert graph.marker.read_bytes() == b"foreign replacement must survive"
    else:
        assert not graph.marker.exists()


@pytest.mark.parametrize("installed", [False, True], ids=["source-canary", "inert-installed-ordinary-control"])
def test_direct_file_response_honors_an_already_disabled_quarantine_policy(source_canary, monkeypatch, installed):
    graph = source_canary
    event, target = graph.event, graph.marker
    if installed:
        # Only this private fixture control is reachable; the fake authority
        # does not enable a real host/process/firewall provider.
        monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert installed fixture"))
        target = graph.root / "ordinary-disabled-control.txt"
        target.write_bytes(b"test-owned ordinary control")
        event = Event("ordinary-fixture-detector", "disabled quarantine", Severity.HIGH, details={
            "path": str(target), "response_authorized": True, "response_contract": {
                "version": 1, "actions": ["quarantine_file"], "targets": {"path": str(target)}}})
        event = replace(event, hmac_sig=graph.recorder.authority.sign(event))
    baseline = graph.combat.policy()
    monkeypatch.setattr(graph.combat, "policy", lambda: replace(baseline, quarantine_files=False))
    before = (target.stat().st_ino, target.read_bytes())
    assert graph.combat._quarantine_file(str(target), event, "combat-000000000006") is None
    assert (target.stat().st_ino, target.read_bytes()) == before


def test_installed_owned_control_rechecks_quarantine_policy_after_intent(source_canary, monkeypatch):
    graph = source_canary
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "Inert installed fixture"))
    target = graph.root / "ordinary-fsync-control.txt"
    target.write_bytes(b"test-owned ordinary control")
    event = Event("ordinary-fixture-detector", "post-intent policy revocation", Severity.HIGH, details={
        "path": str(target), "response_authorized": True, "response_contract": {
            "version": 1, "actions": ["quarantine_file"], "targets": {"path": str(target)}}})
    event = replace(event, hmac_sig=graph.recorder.authority.sign(event))
    baseline, entered = graph.combat.policy(), []
    intent = graph.combat._journal_intent
    def revoke(action):
        intent(action)
        entered.append(action.action_id)
        monkeypatch.setattr(graph.combat, "policy", lambda: replace(baseline, quarantine_files=False))
    monkeypatch.setattr(graph.combat, "_journal_intent", revoke)
    identity = target.stat().st_ino
    assert graph.combat._quarantine_file(str(target), event, "combat-000000000007") is None
    assert len(entered) == 1 and target.stat().st_ino == identity


@pytest.mark.parametrize("process_action, mode", [("none", "balanced"), ("terminate", "contain")])
def test_direct_canary_child_request_cannot_override_current_operation_policy(source_canary, monkeypatch, process_action, mode):
    from angerona.core.practice_verification import _publish_process_probe, _retire_process
    graph = source_canary
    _probe, process = _publish_process_probe(graph.bus, graph.run_id, lease=graph.lease)
    try:
        deadline = time.monotonic() + 5
        event = None
        while event is None and time.monotonic() < deadline:
            graph.guard.scan_process_once(graph.guard._policy_snapshot())
            event = next((row for row in reversed(graph.bus.recent(200))
                          if row.module == graph.guard.name and row.details.get("pid") == process.pid
                          and row.details.get("receipt_type") == "purple_simulation_validation"), None)
            if event is None:
                time.sleep(.02)
        assert event is not None and graph.bus.verify(event), "Actual enrolled child must reach its real detector proof"
        baseline = graph.combat.policy()
        request_policy = replace(baseline, process_action="terminate", mode="maximum")
        monkeypatch.setattr(graph.combat, "policy", lambda: replace(baseline, process_action=process_action, mode=mode))
        assert graph.combat._act_on_process(process.pid, request_policy, event, "combat-000000000008") is None
        assert process.poll() is None, "A caller's request cannot override disabled/suspend-only current policy"
    finally:
        assert _retire_process(process)


def test_active_response_processes_burst_oldest_first(monkeypatch) -> None:
    bus = EventBus()
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(
        module,
        "_event_in_response_scope",
        lambda event: bool((event.details or {}).get("in_scope")),
    )
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))
    base = time.time()
    bus.publish(Event("Detector", "first", Severity.HIGH, base + 1, {"in_scope": True}))
    bus.publish(Event("Detector", "second", Severity.HIGH, base + 2, {"in_scope": True}))
    bus.publish(Event("Detector", "newest rejected", Severity.HIGH, base + 3,
                      {"in_scope": False}))

    assert module.process_pending_once() == 2
    assert acted == ["first", "second"]
    assert module.process_pending_once() == 0


def test_soar_automation_processes_burst_oldest_first(monkeypatch) -> None:
    bus = EventBus()
    module = SOARModule()
    module.bind(bus)
    handled: list[str] = []
    monkeypatch.setattr(module, "_track_attack", lambda _event: None)
    monkeypatch.setattr(module, "_run_playbook", lambda event: handled.append(event.message))
    base = time.time()
    bus.publish(Event("Detector", "first", Severity.HIGH, base + 1))
    bus.publish(Event("Detector", "second", Severity.HIGH, base + 2))
    bus.publish(Event("Console", "newest ignored", Severity.CRITICAL, base + 3))

    assert module.process_pending_once() == 2
    assert handled == ["first", "second"]
    assert module.process_pending_once() == 0


def test_info_flood_cannot_hide_event_from_active_response(monkeypatch) -> None:
    bus = EventBus(ring_size=3)
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))

    bus.publish(Event("Detector", "must-survive", Severity.HIGH))
    for index in range(100):
        bus.publish(Event("Telemetry", f"noise-{index}", Severity.INFO))

    assert module.process_pending_once() == 1
    assert acted == ["must-survive"]
    assert module.process_pending_once() == 0


def test_active_response_priority_cursor_preserves_opt_in_medium_floor(
    monkeypatch,
) -> None:
    bus = EventBus(ring_size=3)
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "MEDIUM")
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))

    bus.publish(Event(
        "Detector",
        "medium-policy-event",
        Severity.MEDIUM,
        details={"active_attack": True},
    ))

    assert module.process_pending_once() == 1
    assert acted == ["medium-policy-event"]
    assert module.process_pending_once() == 0


def test_info_flood_cannot_hide_event_from_soar_automation(monkeypatch) -> None:
    bus = EventBus(ring_size=3)
    module = SOARModule()
    module.bind(bus)
    handled: list[str] = []
    monkeypatch.setattr(module, "_track_attack", lambda _event: None)
    monkeypatch.setattr(module, "_run_playbook", lambda event: handled.append(event.message))

    bus.publish(Event("Detector", "must-survive", Severity.HIGH))
    for index in range(100):
        bus.publish(Event("Telemetry", f"noise-{index}", Severity.INFO))

    assert module.process_pending_once() == 1
    assert handled == ["must-survive"]
    assert module.process_pending_once() == 0


def test_priority_overflow_never_synthesizes_active_response(monkeypatch) -> None:
    bus = EventBus(ring_size=2, priority_ring_size=2)
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))

    for index in range(3):
        bus.publish(Event("Detector", f"real-{index}", Severity.HIGH))

    assert module.process_pending_once() == 2
    assert acted == ["real-1", "real-2"]
    assert module.priority_overflow_count == 1
    # The overflow health diagnostic enters the priority lane for visibility,
    # but it is never fed to kill/rollback on the following poll.
    assert module.process_pending_once() == 0
    assert acted == ["real-1", "real-2"]


def test_later_purple_proof_survives_earlier_fim_catch(tmp_path) -> None:
    _key(tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    started = time.time() + 1
    marker = tmp_path / "drill-sandbox" / "_redteam_lsass_dump_probe.txt"
    history = {
        "run_id": "proof-run",
        "steps": [{
            "stage": "Credential Access (simulated)",
            "technique": "T1003 marker",
            "description": "inert marker",
            "ts_start": started,
            "ts_end": started + 0.1,
            "artifact_paths": [str(marker)],
        }],
    }
    fim = Event(
        "File Integrity Monitor", "file appeared", Severity.HIGH, started + 0.1,
        {"path": str(marker), "evidence_type": "native_analytic_detection",
         "detector_verdict": "positive"},
    )
    purple = Event(
        "Purple Remediation Guard", "candidate detected", Severity.HIGH, started + 0.2,
        {"path": str(marker), "mitre": "T1003",
         "detector_policy": "reviewed-redteam-candidate",
         "evidence_type": "simulation_contract_validation",
         "detector_verdict": "positive"},
    )
    response = Event(
        "Active Response SOAR", "artifact removed", Severity.HIGH, started + 0.3,
        {"path": str(marker), "trigger_ts": purple.ts, "mitigated": True},
    )

    verdicts = evaluate(
        history,
        [fim, purple, response],
        {"Credential Access (simulated)": "detection"},
    )
    assert verdicts[0].catch is fim
    assert verdicts[0].verification_catch is purple
    assert verdicts[0].remediation is response
    metrics = drill_resolution.reconcile_verdicts(
        verdicts,
        "proof-run",
        tmp_path,
    )
    assert metrics["verified_closures"] == 1


def test_rerendering_source_miss_does_not_reopen_verified_fix(tmp_path) -> None:
    _key(tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    proof = drill_resolution.verify_detector_evidence(
        "T1003",
        "proof-run",
        detector="Purple Remediation Guard",
        event_ts=time.time() + 1,
        event_details={
            "mitre": "T1003",
            "artifact_path": "_redteam_lsass_dump_proof.txt",
            "detector_policy": "reviewed-redteam-candidate",
        },
        data_dir=tmp_path,
    )
    assert proof["ok"]
    drill_resolution.record_findings(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        observed_at=time.time() - 10,
    )
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == (
        drill_resolution.VERIFIED_STATE
    )


def test_one_purple_hit_cannot_hide_a_repeated_technique_miss(tmp_path) -> None:
    _key(tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    now = time.time()
    proof = Event(
        "Purple Remediation Guard",
        "one occurrence detected",
        Severity.HIGH,
        now,
        {
            "mitre": "T1003",
            "artifact_path": "_redteam_lsass_dump_one.txt",
            "detector_policy": "reviewed-redteam-candidate",
        },
    )
    caught = StepVerdict(
        "Credential Access",
        "T1003 marker",
        "first occurrence",
        now - 1,
        True,
        catch=proof,
        verification_catch=proof,
    )
    missed = StepVerdict(
        "Credential Access",
        "T1003 marker",
        "second occurrence",
        now - 0.5,
        True,
    )

    metrics = drill_resolution.reconcile_verdicts(
        [caught, missed],
        "mixed-run",
        tmp_path,
    )

    assert metrics["verified_closures"] == 0
    assert caught.finding_resolved is False
    assert missed.finding_resolved is False
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == "APPLIED"


def test_practice_fix_requires_detection_recorder_response_and_cleanup(
    tmp_path, monkeypatch,
) -> None:
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    combat = _shared_practice_combat(tmp_path, manager, response)
    install_policies([{"mitre": "T1003"}], "source-run", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    try:
        result = verify_practice_fixes(
            ["T1003"],
            source_run_id="source-run",
            data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db",
            bus=bus,
            purple_guard=guard,
            active_response=response,
            manager=manager, recorder=recorder,
            # The production budget is 10 seconds. Keep the test bounded while
            # allowing a loaded Windows runner to finish its SQLite WAL commit.
            recorder_timeout=5.0,
        )
    finally:
        combat.stop()
        recorder.close()

    assert result["ok"], json.dumps(result, indent=2)
    assert result["verified"] == result["total"] == 1
    _assert_issuer_original_response(bus, result)
    assert guard._validation_lease is None
    checks = result["results"][0]["checks"]
    assert all(checks.values())
    assert not list((tmp_path / "drill-sandbox").glob("*_practice_*.txt"))
    closure = drill_resolution.resolution_snapshot(tmp_path)["t1003"]
    assert closure["state"] == drill_resolution.VERIFIED_STATE
    assert closure["verification_mode"] == "practice-probe"
    assert closure["verification_receipt_id"]


@pytest.mark.parametrize("outcome", ["late-success", "priority-overflow"])
def test_practice_observes_committed_receipt_without_repeating_native_action(
    tmp_path, monkeypatch, outcome,
) -> None:
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard, response = PurpleGuard(tmp_path), ActiveResponseSOAR()
    guard.bind(bus)
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    combat = _shared_practice_combat(tmp_path, manager, response)
    install_policies([{"mitre": "T1059"}], "source-run", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1059", "name": "Benign Execution"}], "source-run", tmp_path,
        installed=["T1059"],
    )
    release_receipt = threading.Event()
    receipts, observations = [], []
    emit = combat.emit
    observe = response.observe_issuer_completion
    priority_since = bus.priority_since

    def delayed_emit(message, *args, **details):
        if (details.get("trigger_module") == guard.name
                and details.get("action_succeeded") is True
                and details.get("actions") == ["terminate_process"]):
            receipts.append(details)
            # The action has already committed. Release only when the verifier
            # enters observation; no real-time scheduling assumption is needed.
            assert release_receipt.wait(8.0)
        return emit(message, *args, **details)

    def observe_without_dispatch(event, *, timeout):
        observations.append(event.hmac_sig)
        assert 0.0 <= timeout <= 5.0
        release_receipt.set()
        with monkeypatch.context() as patch:
            submit = combat._submit
            observer_thread = threading.get_ident()
            def deny_observer_submission(candidate):
                if (threading.get_ident() == observer_thread
                        and candidate.hmac_sig == event.hmac_sig):
                    pytest.fail("observation resubmitted its original action")
                return submit(candidate)
            patch.setattr(combat, "_submit", deny_observer_submission)
            completed = observe(event, timeout=timeout)
        if outcome == "priority-overflow":
            def overflow(cursor):
                current, events, _overflow = priority_since(cursor)
                return current, events, True
            monkeypatch.setattr(bus, "priority_since", overflow)
        return completed

    monkeypatch.setattr(combat, "emit", delayed_emit)
    monkeypatch.setattr(response, "observe_issuer_completion", observe_without_dispatch)
    try:
        result = verify_practice_fixes(
            ["T1059"], source_run_id="source-run", data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db", bus=bus, purple_guard=guard,
            active_response=response, manager=manager, recorder=recorder,
            recorder_timeout=5.0,
        )
        actions = [row for row in combat.list_actions(limit=500)
                   if row.get("action") == "terminate_process" and row.get("status") == "applied"]
    finally:
        release_receipt.set()
        combat.stop()
        recorder.close()
    assert len(receipts) == len(actions) == len(observations) == 1
    assert len(receipts[0]["action_ids"]) == 1
    assert guard._validation_lease is None
    if outcome == "late-success":
        assert result["ok"], json.dumps(result, indent=2)
        _assert_issuer_original_response(bus, result)
        assert all(result["results"][0]["checks"].values())
    else:
        assert not result["ok"]
        assert result["verified"] == 0
        assert "overflowed during response observation" in result["results"][0]["error"]


@pytest.mark.parametrize("broken", ["valid", "digest", "module", "mode", "signature"])
def test_practice_response_summary_requires_exact_signed_original(tmp_path, monkeypatch, broken):
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    try:
        bus = EventBus()
        bus.arm(recorder.authority)
        bus.publish(Event("Purple Remediation Guard", "original", Severity.HIGH))
        trigger = bus.recent(1)[0]
        details = {"trigger_ts": trigger.ts, "trigger_module": trigger.module,
                   "origin_event_digest": trigger.hmac_sig,
                   "delegation_mode": "issuer-original-event", "mitigated": True}
        if broken == "digest": details["origin_event_digest"] = "0" * 64
        elif broken == "module": details["trigger_module"] = "another detector"
        elif broken == "mode": details["delegation_mode"] = "copied metadata"
        bus.publish(Event("Active Response SOAR", "receipt", Severity.HIGH, details=details))
        response = bus.recent(1)[0]
        if broken == "signature":
            response = Event(response.module, "altered receipt", response.severity,
                             ts=response.ts, details=response.details, hmac_sig=response.hmac_sig)
        found = _find_response(bus, trigger, trigger.ts, events=[response])
        assert (found is response) is (broken == "valid")
    finally:
        recorder.close()


def test_process_practice_fix_kills_only_its_tagged_child_and_closes(
    tmp_path, monkeypatch,
) -> None:
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    combat = _shared_practice_combat(tmp_path, manager, response)
    install_policies([{"mitre": "T1059"}], "source-run", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1059", "name": "Benign Execution"}],
        "source-run",
        tmp_path,
        installed=["T1059"],
    )
    try:
        result = verify_practice_fixes(
            ["T1059"],
            source_run_id="source-run",
            data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db",
            bus=bus,
            purple_guard=guard,
            active_response=response,
            manager=manager, recorder=recorder,
            recorder_timeout=5.0,
        )
    finally:
        combat.stop()
        recorder.close()

    assert result["ok"], json.dumps(result, indent=2)
    _assert_issuer_original_response(bus, result)
    assert guard._validation_lease is None
    assert result["results"][0]["checks"]["response_succeeded"] is True
    assert result["results"][0]["checks"]["postcondition_satisfied"] is True
    closure = drill_resolution.resolution_snapshot(tmp_path)["t1059"]
    assert closure["state"] == drill_resolution.VERIFIED_STATE
    assert closure["verification_mode"] == "practice-probe"
