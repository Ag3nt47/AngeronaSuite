"""Only a live issuer lease can authorize deterministic practice controls."""
from __future__ import annotations

import subprocess
import threading
import time
import os
from types import SimpleNamespace

import pytest

from angerona.core import practice_verification as practice
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.storage import FlightRecorder
from angerona.modules import purple_guard as purple
from angerona.modules.soar_engine import ActiveResponseSOAR


@pytest.fixture(autouse=True)
def controlled_inventory(monkeypatch):
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot
    monkeypatch.setattr(process_monitor, "process_snapshot", lambda *a, **k:
        ProcessSnapshot((), time.time(), True, 0, 0, 0, 0, "", True))


def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus(ring_size=4096)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard, response = purple.PurpleGuard(tmp_path), ActiveResponseSOAR()
    guard.bind(bus)
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    return dict(source_run_id="prior-run", data_dir=tmp_path,
        db_path=tmp_path / "flight-recorder.db", bus=bus,
        purple_guard=guard, active_response=response, manager=manager,
        recorder=recorder, recorder_timeout=3)


@pytest.mark.parametrize("mismatch", ["missing-manager", "bus", "recorder", "module", "db"])
def test_mismatched_evidence_plane_refuses_before_controls(tmp_path, monkeypatch, mismatch):
    values = runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(practice, "_write_registered_marker", lambda *_a, **_k:
        pytest.fail("a marker was created before binding admission"))
    monkeypatch.setattr(practice, "_publish_process_probe", lambda *_a, **_k:
        pytest.fail("a child was created before binding admission"))
    if mismatch == "missing-manager":
        values["manager"] = None
    elif mismatch == "bus":
        values["manager"].bus = EventBus()
    elif mismatch == "recorder":
        values["manager"].recorder = object()
    elif mismatch == "module":
        values["manager"].modules["Purple Remediation Guard"] = object()
    else:
        values["db_path"] = tmp_path / "other.db"
    try:
        result = practice.verify_practice_fixes(["T1059"], **values)
        assert result["ok"] is False and result["verified"] == 0
        assert result["results"] == [] and "binding" in result["error"]
    finally:
        values["recorder"].close()


def test_issuer_failure_never_creates_a_marker_or_child(tmp_path, monkeypatch):
    values = runtime(tmp_path, monkeypatch)
    def unavailable(*_args, **_kwargs):
        raise purple.RedTeamValidationError("inert issuer unavailable")
    monkeypatch.setattr(purple, "acquire_redteam_validation_lease", unavailable)
    monkeypatch.setattr(practice, "_write_registered_marker", lambda *_a, **_k:
        pytest.fail("marker provenance was substituted for issuer authority"))
    monkeypatch.setattr(practice, "_publish_process_probe", lambda *_a, **_k:
        pytest.fail("tag text was substituted for issuer authority"))
    try:
        result = practice.verify_practice_fixes(["T1003", "T1059"], **values)
        assert not result["ok"] and result["verified"] == 0
        assert len(result["results"]) == 2
        assert all("issuer unavailable" in row["error"] for row in result["results"])
    finally:
        values["recorder"].close()


def test_incomplete_inventory_keeps_real_issuer_gate_closed(tmp_path, monkeypatch):
    import time
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot
    values = runtime(tmp_path, monkeypatch)
    values["recorder_timeout"] = .2
    monkeypatch.setattr(process_monitor, "process_snapshot", lambda *a, **k:
        ProcessSnapshot((), time.time(), False, 0, 0, 0, 0, "inert unavailable", False))
    monkeypatch.setattr(practice, "_write_registered_marker", lambda *_a, **_k:
        pytest.fail("incomplete inventory reached artifact creation"))
    monkeypatch.setattr(practice, "_publish_process_probe", lambda *_a, **_k:
        pytest.fail("incomplete inventory reached process creation"))
    try:
        result = practice.verify_practice_fixes(["T1059"], **values)
        assert not result["ok"] and result["verified"] == 0
        assert result["results"][0]["status"] == "FIX_APPLIED_RETEST_FAILED"
        assert values["purple_guard"]._validation_lease is None
    finally:
        values["purple_guard"].stop()
        values["recorder"].close()


def test_cleanup_does_not_return_or_repeat_actions_without_terminal_proof():
    release, entered = threading.Event(), threading.Event()
    calls, result = [], []
    class Owned:
        waits = 0
        def poll(self):
            return None
        def terminate(self):
            calls.append("terminate")
            raise OSError("inert denied")
        def kill(self):
            calls.append("kill")
            raise OSError("inert denied")
        def wait(self, *, timeout):
            self.waits += 1
            if self.waits <= 2:
                raise subprocess.TimeoutExpired("owned inert child", timeout)
            entered.set()
            if not release.wait(.01):
                raise subprocess.TimeoutExpired("owned inert child", timeout)
            return 1
    worker = threading.Thread(target=lambda: result.append(practice._retire_process(Owned())))
    worker.start()
    try:
        assert entered.wait(1)
        assert worker.is_alive() and result == []
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and result == [True]
    assert calls == ["terminate", "kill"]


def test_marker_cleanup_keeps_a_file_when_issuer_custody_refuses(tmp_path, monkeypatch):
    marker = tmp_path / "_redteam_lsass_dump_replaced.txt"
    marker.write_text("replacement must survive", encoding="utf-8")
    calls = []
    monkeypatch.setattr(purple.RedTeamValidationLease, "remove_registered_artifact",
        lambda lease, path, *, run_id: calls.append((lease, path, run_id)) or False)
    lease = object()
    assert practice._cleanup_markers((marker,), lease=lease, run_id="owned-run") is False
    assert marker.read_text(encoding="utf-8") == "replacement must survive"
    assert calls == [(lease, marker, "owned-run")]


def test_pending_handoff_observation_refuses_nonpending_or_broken_custody(tmp_path, monkeypatch):
    from angerona.core.eventbus import Event
    lease, recorder = object(), object()
    bus = SimpleNamespace(verify=lambda _event: True)
    guard = SimpleNamespace(name="Purple Remediation Guard", _bus=bus, _validation_lease=lease)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={guard.name: guard})
    path = tmp_path / "_redteam_lsass_dump_owned.txt"
    key = os.path.normcase(str(path))
    event = Event(guard.name, "inert original", details={
        "path": str(path), "receipt_type": "purple_simulation_validation",
        "evidence_kind": "inert_file_marker", "lease_id": "lease",
        "receipt_id": "receipt", "run_id": "run", "target": str(tmp_path),
    })
    def fresh():
        return SimpleNamespace(manager=manager, bus=bus, module=guard, recorder=recorder,
            lock=threading.RLock(), released=False, artifact_custody_failed=False,
            consumed=True, run_deadline_monotonic=time.monotonic() + 10,
            lease_id="lease", receipt_id="receipt", bound_run_id="run", target=tmp_path,
            artifact_handoffs={key}, artifact_handles={key: (None, {})})
    current = [fresh()]
    monkeypatch.setattr(purple, "_lease_authority", lambda _lease: current[0])
    def pending():
        return practice._pending_marker_handoff(lease, event, manager=manager,
            bus=bus, guard=guard, recorder=recorder)
    assert pending() is True
    for change in (
        lambda state: setattr(state, "released", True),
        lambda state: setattr(state, "artifact_custody_failed", True),
        lambda state: setattr(state, "manager", object()),
        lambda state: setattr(state, "recorder", object()),
        lambda state: state.artifact_handoffs.clear(),
        lambda state: state.artifact_handles.update({key: (731, {})}),
        lambda state: setattr(state, "run_deadline_monotonic", 0),
    ):
        current[0] = fresh()
        change(current[0])
        assert pending() is False


def test_failed_native_binding_retires_owned_child_without_synthetic_event(monkeypatch):
    calls = []
    class Child:
        pid = 731
        def poll(self):
            return None
        def terminate(self):
            calls.append("terminate")
        def wait(self, *, timeout):
            calls.append("wait")
            return 1
    monkeypatch.setattr(purple.RedTeamValidationLease, "enroll_process_challenge",
        lambda *_a, **_k: calls.append("enroll"))
    def reject(*_args, **_kwargs):
        calls.append("bind")
        raise purple.RedTeamValidationError("inert exact observation rejected")
    monkeypatch.setattr(purple.RedTeamValidationLease, "bind_process_challenge", reject)
    monkeypatch.setattr(practice.subprocess, "Popen", lambda *a, **k: calls.append("spawn") or Child())
    bus = SimpleNamespace(publish=lambda _event: pytest.fail("synthetic observation was published"))
    with pytest.raises(purple.RedTeamValidationError, match="exact observation rejected"):
        practice._publish_process_probe(bus, "a" * 32, lease=object())
    assert calls == ["enroll", "spawn", "bind", "terminate", "wait"]


def test_packaged_runtime_refuses_python_probe_without_launch(monkeypatch):
    monkeypatch.setattr(practice.sys, "frozen", True, raising=False)
    monkeypatch.setattr(practice.subprocess, "Popen", lambda *_a, **_k:
        pytest.fail("a packaged app executable was used as a Python interpreter"))
    monkeypatch.setattr(purple.RedTeamValidationLease, "enroll_process_challenge",
        lambda *_a, **_k: pytest.fail("an unsupported probe was enrolled"))
    with pytest.raises(RuntimeError, match="no admitted inert Python probe interpreter"):
        practice._publish_process_probe(object(), "a" * 32, lease=object())


def test_posture_hands_its_existing_manager_and_recorder_to_verifier(tmp_path, monkeypatch):
    from angerona.modules.posture_hardening import PostureHardening
    values = runtime(tmp_path, monkeypatch)
    module = PostureHardening(tmp_path)
    module.bind(values["bus"])
    module.bind_manager(values["manager"])
    observed = []
    def verify(techniques, **kwargs):
        observed.append((techniques, kwargs))
        return {"ok": False, "results": []}
    monkeypatch.setattr(practice, "verify_practice_fixes", verify)
    try:
        module.verify_redteam_practice({"run_id": "prior-run", "contracts": [{"mitre": "T1003"}]})
        assert len(observed) == 1
        techniques, passed = observed[0]
        assert techniques == ["T1003"]
        assert passed["manager"] is values["manager"]
        assert passed["recorder"] is values["recorder"]
        assert passed["db_path"] == values["db_path"]
        assert passed["bus"] is values["bus"]
    finally:
        values["recorder"].close()
