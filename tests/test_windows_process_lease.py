from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from angerona.core.windows_process_lease import (
    ProcessLeaseError, ProcessObjectIdentity, WindowsProcessLease, _Native, _RIGHTS,
)
from angerona.core import windows_process_lease as lease_module
from angerona.modules import adversary_combat as combat_module
from angerona.modules.adversary_combat import AdversaryCombat, CombatAction


class FakeNative:
    def __init__(self):
        self.target = ProcessObjectIdentity(4242, 116444736500000000, r"c:\fixture\target.exe")
        self.exited = False
        self.calls = []
        self.on_terminate = None
        self.complete = True
        self.close_error = False

    def open(self, pid, rights, inherit):
        self.calls.append(("open", pid, rights, inherit))
        return 101

    def identity(self, handle):
        self.calls.append(("identity", handle))
        return self.target

    def object_identity(self, handle):
        self.calls.append(("object_identity", handle))
        return self.target.pid, self.target.birth_ticks

    def wait(self, handle, milliseconds):
        self.calls.append(("wait", handle, milliseconds))
        return self.exited

    def terminate(self, handle, code):
        self.calls.append(("terminate", handle, code))
        if self.on_terminate:
            self.on_terminate()
        self.exited = self.complete

    def exit_code(self, handle):
        self.calls.append(("exit_code", handle))
        return 1

    def close(self, handle):
        self.calls.append(("close", handle))
        if self.close_error:
            raise ProcessLeaseError("fixture close failure")


def acquire(native=None, **kwargs):
    return WindowsProcessLease(4242, 50.0, r"C:\fixture\target.exe",
                               _native=native or FakeNative(), **kwargs)


def test_one_least_rights_non_inheritable_handle_binds_every_native_call():
    native = FakeNative()
    with acquire(native) as lease:
        assert lease.dispatch_started is False
        lease.terminate()
        assert lease.dispatch_started is True
        lease.wait_terminated()
        proof = lease.terminal_proof()
        assert proof["native_wait_signaled"] is True
        assert proof["native_birth_ticks"] == native.target.birth_ticks
        assert proof["native_exit_code"] == 1
        with pytest.raises(ProcessLeaseError, match="already dispatched"):
            lease.terminate()
        assert not any(call[0] == "close" for call in native.calls)
    lease.close()
    assert native.calls[0] == ("open", 4242, _RIGHTS, False)
    assert [call[0] for call in native.calls].count("open") == 1
    assert [call[0] for call in native.calls].count("close") == 1
    assert all(call[1] == 101 for call in native.calls[1:])
    with pytest.raises(ProcessLeaseError, match="closed"):
        lease.validate(alive=False)


@pytest.mark.parametrize("pid,birth,image", [
    (True, 50, r"C:\fixture\target.exe"), (0, 50, r"C:\fixture\target.exe"),
    (2**32, 50, r"C:\fixture\target.exe"), (4242, True, r"C:\fixture\target.exe"),
    (4242, float("nan"), r"C:\fixture\target.exe"),
    (4242, float("inf"), r"C:\fixture\target.exe"),
    (4242, 0, r"C:\fixture\target.exe"), (4242, 50, "relative.exe"),
    (4242, 50, r"\\server\share\target.exe"),
    (4242, 50, r"\\?\C:\fixture\target.exe"),
    (4242, 50, "C:\\fixture\\target.exe\0"),
])
def test_invalid_expected_identity_never_opens(pid, birth, image):
    native = FakeNative()
    with pytest.raises(ProcessLeaseError):
        WindowsProcessLease(pid, birth, image, _native=native)
    assert native.calls == []


@pytest.mark.parametrize("change", ["pid", "birth_ticks", "image", "exited", "unreadable"])
def test_mismatch_or_unknown_closes_without_mutation(change):
    native = FakeNative()
    if change == "exited":
        native.exited = True
    elif change == "unreadable":
        native.identity = lambda _handle: (_ for _ in ()).throw(OSError("denied"))
    else:
        values = {"pid": 4243, "birth_ticks": native.target.birth_ticks + 100_000,
                  "image": r"c:\fixture\other.exe"}
        native.target = dataclasses.replace(native.target, **{change: values[change]})
    with pytest.raises((ProcessLeaseError, OSError)):
        acquire(native)
    assert native.calls[-1] == ("close", 101)
    assert not any(call[0] == "terminate" for call in native.calls)


def test_access_denial_does_not_close_a_handle_never_acquired():
    native = FakeNative()
    native.open = lambda *_args: (_ for _ in ()).throw(OSError("access denied"))
    with pytest.raises(OSError, match="access denied"):
        acquire(native)
    assert native.calls == []


@pytest.mark.parametrize("now", [60.0, -1.0, float("nan")])
def test_expired_or_regressed_monotonic_clock_refuses_before_dispatch(now):
    clock = [0.0]
    native = FakeNative()
    with acquire(native, _monotonic=lambda: clock[0]) as lease:
        clock[0] = now
        with pytest.raises(ProcessLeaseError):
            lease.terminate()
        assert lease.dispatch_started is False
    assert not any(call[0] == "terminate" for call in native.calls)


def test_exit_after_acquisition_refuses_without_touching_replacement_pid():
    native = FakeNative()
    with acquire(native) as lease:
        native.exited = True
        with pytest.raises(ProcessLeaseError, match="liveness"):
            lease.terminate()
        assert lease.dispatch_started is False
    assert [call[0] for call in native.calls].count("open") == 1


def test_last_native_read_expiry_does_not_mark_dispatch_started():
    native = FakeNative()
    clock = [0.0]
    with acquire(native, _monotonic=lambda: clock[0]) as lease:
        original = native.identity

        def expire_during_read(handle):
            result = original(handle)
            clock[0] = 60
            return result

        native.identity = expire_during_read
        with pytest.raises(ProcessLeaseError, match="expired"):
            lease.terminate()
        assert lease.dispatch_started is False
    assert not any(call[0] == "terminate" for call in native.calls)


def test_postexit_proof_uses_retained_object_when_image_path_is_gone():
    native = FakeNative()
    with acquire(native) as lease:
        lease.terminate()
        native.identity = lambda _handle: (_ for _ in ()).throw(OSError("image gone"))
        lease.wait_terminated()
        assert lease.terminal_proof()["native_image_observation"] == "before-termination"


def test_timeout_and_unknown_exit_cannot_produce_terminal_evidence():
    native = FakeNative()
    native.complete = False
    with acquire(native) as lease:
        lease.terminate()
        with pytest.raises(ProcessLeaseError, match="completion"):
            lease.wait_terminated()
        with pytest.raises(ProcessLeaseError, match="liveness"):
            lease.terminal_proof()


def test_wait_budget_is_bounded_by_remaining_lease():
    clock = [0.0]
    native = FakeNative()
    with acquire(native, _monotonic=lambda: clock[0]) as lease:
        lease.terminate()
        clock[0] = 59.5
        lease.wait_terminated()
    assert ("wait", 101, 500) in native.calls


def test_close_error_is_observable_and_never_retries_reused_handle():
    native = FakeNative()
    lease = acquire(native)
    native.close_error = True
    with pytest.raises(ProcessLeaseError, match="close failure"):
        lease.close()
    lease.close()
    assert native.calls.count(("close", 101)) == 1


def action():
    return CombatAction(
        action_id="act-9999999999999999", combat_id="combat-999999999999",
        action="terminate_process", applied_at=100.0, reversible=False,
        target="4242", details={"pid": 4242, "create_time": 50.0,
                                "exe": r"C:\fixture\target.exe",
                                "mutation_generation": "9" * 32},
        trigger_module="inert-process-custody", trigger_ts=99.0,
    )


@pytest.fixture
def transaction(tmp_path, monkeypatch):
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    assert module._reconcile_state() is True
    monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", True)
    native = FakeNative()
    clock = [0.0]
    monkeypatch.setattr(module, "_acquire_termination_lease", lambda _action: acquire(
        native, _monotonic=lambda: clock[0]))
    process = SimpleNamespace(kill=lambda: pytest.fail("PID-based kill was used"))
    return module, native, clock, process


def records(module):
    return module._read_journal(strict=True)[0]


def test_transaction_handle_survives_intent_and_terminal_and_pid_lookup_change(
    transaction, monkeypatch,
):
    module, native, _clock, process = transaction
    intent_ready, resume = threading.Event(), threading.Event()
    original_intent = module._journal_intent
    original_append = module._append_journal
    seen_terminal = []

    def delayed_intent(candidate):
        original_intent(candidate)
        intent_ready.set()
        assert resume.wait(10)

    def terminal(candidate):
        if candidate.get("record_type") == "commit":
            assert not any(call[0] == "close" for call in native.calls)
            seen_terminal.append(True)
        return original_append(candidate)

    monkeypatch.setattr(module, "_journal_intent", delayed_intent)
    monkeypatch.setattr(module, "_append_journal", terminal)
    lookup = {4242: process}
    monkeypatch.setattr(combat_module, "psutil", SimpleNamespace(
        Process=lambda pid: lookup[pid]))
    output = []
    worker = threading.Thread(target=lambda: output.append(
        module._terminate_process_transaction(process, action())))
    worker.start()
    try:
        assert intent_ready.wait(10)
        lookup[4242] = SimpleNamespace(kill=lambda: pytest.fail("replacement was killed"))
        assert not any(call[0] == "close" for call in native.calls)
    finally:
        resume.set()
        worker.join(15)
    assert not worker.is_alive()
    assert output[0] is not None
    assert seen_terminal == [True]
    assert [value["record_type"] for value in records(module)] == ["intent", "commit"]
    assert output[0].details["native_wait_signaled"] is True
    assert native.calls[-1] == ("close", 101)
    assert [call[0] for call in native.calls].count("open") == 1


@pytest.mark.parametrize("change", ["expired", "exited", "changed", "intent_failure"])
def test_transaction_rechecks_after_durable_intent_before_possible_effect(
    transaction, monkeypatch, change,
):
    module, native, clock, process = transaction
    original_intent = module._journal_intent

    def changed_after_intent(candidate):
        original_intent(candidate)
        if change == "expired":
            clock[0] = 60
        elif change == "exited":
            native.exited = True
        elif change == "changed":
            native.target = dataclasses.replace(native.target, birth_ticks=1)
        else:
            raise OSError("fixture intent write failed")

    monkeypatch.setattr(module, "_journal_intent", changed_after_intent)
    assert module._terminate_process_transaction(process, action()) is None
    history = records(module)
    assert [value["record_type"] for value in history] == ["intent", "failure"]
    assert not module._mutation_blocked
    assert not any(call[0] == "terminate" for call in native.calls)
    assert native.calls[-1] == ("close", 101)


def test_native_acquisition_failure_has_no_pid_kill_fallback(transaction, monkeypatch):
    module, native, _clock, process = transaction
    monkeypatch.setattr(module, "_acquire_termination_lease", lambda _action:
                        (_ for _ in ()).throw(OSError("access denied")))
    assert module._terminate_process_transaction(process, action()) is None
    assert native.calls == []
    assert [value["record_type"] for value in records(module)] == ["failure"]
    assert not module._mutation_blocked


@pytest.mark.parametrize("failure", ["native_error", "wait_timeout", "wait_error",
                                     "terminal_expiry", "terminal_identity",
                                     "exit_status_unknown", "terminal_write", "close"])
def test_possible_effect_uncertainty_keeps_irreversible_recovery_circuit(
    transaction, monkeypatch, failure,
):
    module, native, clock, process = transaction
    if failure == "native_error":
        native.on_terminate = lambda: (_ for _ in ()).throw(OSError("ambiguous native call"))
    elif failure == "wait_timeout":
        native.complete = False
    elif failure == "wait_error":
        original_wait = native.wait

        def fail_wait(handle, milliseconds):
            if milliseconds:
                raise OSError("unknown wait result")
            return original_wait(handle, milliseconds)
        native.wait = fail_wait
    elif failure == "exit_status_unknown":
        native.exit_code = lambda _handle: (_ for _ in ()).throw(OSError("status unknown"))
    elif failure in {"terminal_expiry", "terminal_identity", "terminal_write"}:
        original_append = module._append_journal

        def fail_terminal(candidate):
            if candidate.get("record_type") == "commit":
                if failure == "terminal_write":
                    raise OSError("terminal unavailable")
                if failure == "terminal_identity":
                    native.target = dataclasses.replace(native.target, birth_ticks=1)
                else:
                    clock[0] = 60
            return original_append(candidate)
        monkeypatch.setattr(module, "_append_journal", fail_terminal)
    else:
        native.close_error = True
    assert module._terminate_process_transaction(process, action()) is None
    assert module._mutation_blocked
    assert module.health == 0
    history = records(module)
    assert history[0]["record_type"] == "intent"
    assert history[-1]["record_type"] == "orphan"
    if failure != "close":
        assert not any(value["record_type"] == "commit" for value in history)
    assert native.calls.count(("close", 101)) == 1
    assert action().action_id in module._pending_recovery_records()


@pytest.mark.parametrize("image", [r"C:\fixture\lsass.exe", r"C:\Windows\fixture.exe"])
def test_native_image_protected_policy_cannot_be_bypassed_by_psutil_name(
    tmp_path, monkeypatch, image,
):
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    native = FakeNative()
    native.target = dataclasses.replace(native.target, image=image.lower())
    real_lease = WindowsProcessLease(4242, 50, image, _native=native)
    monkeypatch.setattr(lease_module, "WindowsProcessLease", lambda *_a, **_k: real_lease)
    # Preserve the production system-root decision on Windows. On other
    # platforms this fixture supplies the equivalent policy without path I/O.
    monkeypatch.setattr(module, "_is_system_path", lambda path:
                        str(path).lower().startswith("c:\\windows\\"))
    with pytest.raises(ValueError, match="protected"):
        module._acquire_termination_lease(action())
    assert native.calls[-1] == ("close", 101)


@pytest.mark.skipif(os.name == "nt", reason="non-Windows refusal")
def test_native_adapter_unavailable_off_windows():
    with pytest.raises(ProcessLeaseError, match="unavailable"):
        WindowsProcessLease(4242, 50, r"C:\fixture\target.exe")


@pytest.mark.skipif(os.name != "nt", reason="owned Windows process-object validation")
@pytest.mark.parametrize("terminate", [False, True])
def test_native_owned_child_original_handle_and_unrelated_child_survive(terminate):
    # Only our exact Popen children are eligible; never enumerate host targets.
    children = [subprocess.Popen(
        [sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    ) for _ in range(2)]
    native = _Native()
    first, unrelated = children
    try:
        original = native.identity(int(first._handle))
        other = native.identity(int(unrelated._handle))
        with WindowsProcessLease(first.pid, original.create_time, original.image) as lease:
            assert lease.identity == original
            assert native.wait(int(first._handle), 0) is False
            with pytest.raises(ProcessLeaseError, match="completion"):
                lease.wait_terminated(timeout=0.01)
            if terminate:
                lease.terminate()
            else:
                first.stdin.write(b"x")
                first.stdin.flush()
            lease.wait_terminated()
            assert lease.terminal_proof()["native_wait_signaled"] is True
            assert native.wait(int(first._handle), 0) is True
            assert native.identity(int(unrelated._handle)) == other
            assert unrelated.poll() is None
        assert first.wait(timeout=5) == (1 if terminate else 0)
        assert unrelated.poll() is None
    finally:
        for child in children:
            if child.poll() is None:
                child.stdin.write(b"x")
                child.stdin.flush()
            child.wait(timeout=5)
            child.stdin.close()
