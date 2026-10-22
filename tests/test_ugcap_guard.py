from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules.ugcap_guard import UGCAPGuardModule


class Manager:
    def __init__(self):
        self.config = SimpleNamespace(ugcap_enabled=False, data_dir="fixture", save=lambda: None)
        self.ugcap_paused = False
        self.requires_ugcap_restart = False
        self.resumed = 0
        self.activations = 0
        self.allow_activation = True

    def pause_for_ugcap(self, reason):
        self.ugcap_paused = True
        return {"paused": True, "held": [], "scope": "fixture"}

    def freeze_enclave_mesh(self):
        pass

    def activate_enclave_mesh(self, report):
        self.activations += 1
        return self.allow_activation

    def resume_after_ugcap(self, *, permit=None):
        def open_gate():
            self.ugcap_paused = False
        if permit is not None and permit(open_gate) is not True:
            return {"paused": True}
        self.resumed += 1
        return {"paused": False}


class Daemon:
    def __init__(self, result=None):
        self.result = result or {"status": "verified", "report_id": "r1", "generation": "g1"}
        self.calls = []
        self.secrets = []

    def execute(self, command, payload, *, secret, timeout):
        self.calls.append(command)
        self.secrets.append(secret)
        return dict(self.result)

    def close(self):
        pass


def make_guard(daemon=None):
    daemon = daemon or Daemon()
    guard = UGCAPGuardModule(daemon_factory=lambda _root: daemon, clock=lambda: 1800000000.0)
    guard.bind(EventBus())
    manager = Manager()
    guard.bind_manager(manager)
    return guard, manager, daemon


def test_constructor_does_not_launch_hardware_or_child():
    called = []
    guard = UGCAPGuardModule(daemon_factory=lambda _: called.append(True))
    assert not called and guard.dashboard_snapshot()["coverage"]["worker"] == "not-started"


def test_passcode_is_copied_and_worker_copy_wiped(tmp_path):
    guard, manager, daemon = make_guard()
    secret = bytearray(b"fixture high entropy passphrase")
    assert guard.queue_verify(str(tmp_path / "vault.ugcap"), secret)
    guard._process_one()
    assert manager.resumed == 1 and not manager.ugcap_paused
    assert daemon.secrets[0] is not secret and not any(daemon.secrets[0])
    assert any(secret)
    assert "passphrase" not in str(guard.dashboard_snapshot())


def test_failed_mesh_activation_keeps_workspace_locked(tmp_path):
    guard, manager, _ = make_guard()
    manager.allow_activation = False
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    assert manager.resumed == 0 and manager.ugcap_paused
    assert guard.dashboard_snapshot()["status"] == "error-locked"


def test_operator_lock_invalidates_worker_restore_approval(tmp_path):
    guard, manager, daemon = make_guard()
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    assert not manager.ugcap_paused
    assert guard.queue_lock()
    assert manager.ugcap_paused
    guard._process_one()
    assert daemon.calls == ["verify", "lock"]
    assert daemon.secrets[-1] is None


def test_operator_lock_revokes_pending_verify_before_it_can_resume(tmp_path):
    entered, release = threading.Event(), threading.Event()
    class Delayed(Daemon):
        def execute(self, *args, **kwargs):
            entered.set()
            assert release.wait(5)
            return super().execute(*args, **kwargs)
    guard, manager, daemon = make_guard(Delayed())
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    worker = threading.Thread(target=guard._process_one)
    worker.start()
    try:
        assert entered.wait(2)
        assert guard.queue_lock()
        assert manager.ugcap_paused
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and manager.resumed == 0 and manager.activations == 0
    assert not any(daemon.secrets[0])


def test_lock_exactly_at_final_resume_permission_never_opens_gate(tmp_path):
    guard, manager, _ = make_guard()
    def resume(*, permit):
        guard.queue_lock()
        called = []
        assert permit(lambda: called.append(True)) is False
        assert not called
        return {"paused": True}
    manager.resume_after_ugcap = resume
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    assert manager.ugcap_paused and guard.dashboard_snapshot()["status"] != "verified"


def test_stop_revokes_inflight_verification(tmp_path):
    guard, manager, daemon = make_guard()
    old_execute = daemon.execute
    def execute(*args, **kwargs):
        guard.stop()
        return old_execute(*args, **kwargs)
    daemon.execute = execute
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    assert manager.resumed == 0 and manager.ugcap_paused


@pytest.mark.parametrize("result", [
    {"status": "restored", "restart_required": True},
    {"status": "restored", "recovery_required": True},
    {"status": "restored", "errors": [{"path": "src/fixture.py", "error": "custody"}]},
    {"status": "restored", "deferred": ["fixture.exe"]},
    {"status": "failed"},
])
def test_any_partial_restore_or_restart_keeps_gate_closed(result, tmp_path):
    guard, manager, daemon = make_guard(Daemon(result))
    assert guard.queue_restore(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"),
                               ["src/fixture.py"], "report-1")
    guard._process_one()
    assert manager.ugcap_paused and manager.resumed == 0
    assert daemon.calls == ["restore"]


def test_drift_requests_host_isolation_and_freezes_workspace(tmp_path):
    guard, manager, _ = make_guard(Daemon({"status": "drift", "report_id": "r1", "generation": "g1"}))
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    event = next(event for event in guard._bus.recent(10) if event.details.get("event_type") == "ugcap_divergence")
    assert event.details["response_contract"]["actions"] == ["isolate_host"]
    assert event.details["response_contract"]["targets"] == {"host": "local"}
    assert manager.ugcap_paused and manager.resumed == 0


def test_no_passcode_accepted_before_required_clean_bootstrap(tmp_path):
    guard, manager, daemon = make_guard()
    manager.requires_ugcap_restart = True
    assert not guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    assert guard.dashboard_snapshot()["status"] == "restart-required"
    assert not daemon.calls


def test_enabling_policy_reenables_the_guard_command_service():
    guard, manager, _ = make_guard()
    calls = []
    manager.set_enabled = lambda name, enabled: calls.append((name, enabled))
    assert guard.configure_settings(ugcap_enabled=True)["queued"]
    assert calls == [(guard.name, True)]


def test_cadence_requests_user_challenge_once_and_never_decrypts():
    guard, manager, daemon = make_guard()
    guard._settings["ugcap_enabled"] = True
    guard._tick()
    guard._tick()
    assert manager.ugcap_paused and guard.dashboard_snapshot()["status"] == "user-challenge-required"
    assert not daemon.calls
    assert len(guard._bus.recent(10)) == 1


def test_incomplete_and_empty_reports_never_resume(tmp_path):
    guard, manager, _ = make_guard(Daemon({"status": "incomplete", "coverage": {"complete": False}}))
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    assert manager.ugcap_paused and manager.resumed == 0


def test_public_snapshot_omits_full_source_maps_and_observations(tmp_path):
    report = {"status": "verified", "report_id": "r1", "generation": "g1",
              "verified_files": {"src/secret.py": "a" * 64}, "observations": {"raw": "private"},
              "verification_receipt": {"verified_files": {"src/secret.py": "a" * 64},
                                       "source_manifest_digest": "b" * 64}}
    guard, _, _ = make_guard(Daemon(report))
    guard.queue_verify(str(tmp_path / "vault.ugcap"), bytearray(b"inert test passphrase"))
    guard._process_one()
    snapshot = str(guard.dashboard_snapshot())
    assert "secret.py" not in snapshot and "observations" not in snapshot
