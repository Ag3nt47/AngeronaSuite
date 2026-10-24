"""Beacon tests use in-memory transports and subprocess-local file sinks only."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import spyware_beacon as beacon


def config(**changes):
    values = {name: False if name in beacon._BOOL_FIELDS else ""
              for name in beacon._CONFIG_FIELDS}
    values.update(spyware_beacon_enabled=True, spyware_beacon_channel=True,
                  aria_push_enabled=True, aria_push_kind="webhook",
                  aria_push_url="https://8.8.8.8/unit-test-only")
    values.update(changes)
    return SimpleNamespace(**values)


def capture(sent):
    def send(url, data, headers):
        sent.append((url, data, headers))
        return 200, "ok"
    return send


@pytest.mark.parametrize("flag", [False, "true", 1, None])
def test_explicit_boolean_opt_in_required(flag):
    sent = []
    instance = beacon.EmergencyBeacon(config(spyware_beacon_enabled=flag), transport=capture(sent))
    assert not instance.enqueue({"rule_code": "SPYWARE_MEMORY"})
    instance.tick()
    assert not sent


def test_minimal_payload_and_nonblocking_enqueue():
    sent = []
    instance = beacon.EmergencyBeacon(config(), clock=lambda: 1700000000, transport=capture(sent))
    assert instance.enqueue({"id": "password=SHOULD_NOT_LEAK", "rule_code": "SPYWARE_MEMORY",
                             "severity": "HIGH", "pid": 123, "report": "raw-secrets",
                             "path": "C:/private/vault", "url": "https://private.invalid/token"})
    assert not sent
    instance.tick()
    assert len(sent) == 1
    outgoing = json.loads(sent[0][1])["message"]
    payload = json.loads(outgoing.split("\n", 1)[1])
    assert set(payload) == {"incident_id", "timestamp", "rule_code", "severity", "pid"}
    assert payload["rule_code"] == "SPYWARE_MEMORY" and payload["pid"] == 123
    for forbidden in ("SHOULD_NOT_LEAK", "raw-secrets", "private/vault", "private.invalid"):
        assert forbidden not in outgoing
        assert forbidden not in json.dumps(instance.snapshot())
    assert instance.snapshot()["sent"] == 1


@pytest.mark.parametrize("url", ["http://8.8.8.8/x", "https://127.0.0.1/x",
                                  "https://169.254.169.254/x", "https://10.0.0.1/x",
                                  "file:///etc/passwd"])
def test_ssrf_is_blocked_before_injected_transport(url):
    sent = []
    instance = beacon.EmergencyBeacon(config(aria_push_url=url), transport=capture(sent))
    assert instance.enqueue({"rule_code": "SPYWARE_NETWORK"})
    instance.tick()
    assert not sent
    assert instance.snapshot()["state"] == "retry_pending"


def test_deduplication_rate_limit_and_retry_bound():
    current = [1000.0]
    sent = []
    instance = beacon.EmergencyBeacon(config(), clock=lambda: current[0], transport=capture(sent))
    for index in range(4):
        assert instance.enqueue({"id": str(index), "rule_code": "SPYWARE_MEMORY"})
    assert not instance.enqueue({"id": "0", "rule_code": "SPYWARE_MEMORY"})
    for _ in range(6):
        instance.tick()
    assert len(sent) == 3 and instance.snapshot()["pending"] == 1
    current[0] += 60.1
    instance.tick()
    assert len(sent) == 4

    attempts = []
    def failed(*_args):
        attempts.append(True)
        raise RuntimeError("https://secret.invalid/password=SECRET")
    failure = beacon.EmergencyBeacon(config(), clock=lambda: current[0], transport=failed)
    failure.enqueue({"rule_code": "SPYWARE_MEMORY"})
    failure.tick()
    current[0] += 5.1
    failure.tick()
    current[0] += 30.1
    failure.tick()
    current[0] += 61
    failure.tick()
    assert len(attempts) == 3 and failure.snapshot()["failed"] == 1
    assert "SECRET" not in json.dumps(failure.snapshot())


def test_disable_revokes_pending_delivery():
    cfg, sent = config(), []
    instance = beacon.EmergencyBeacon(cfg, transport=capture(sent))
    instance.enqueue({"rule_code": "SPYWARE_MEMORY"})
    cfg.spyware_beacon_enabled = False
    instance.tick()
    assert not sent and instance.snapshot()["pending"] == 0
    cfg.spyware_beacon_enabled = True
    cfg.aria_push_enabled = "true"
    assert not instance.enqueue({"rule_code": "SPYWARE_MEMORY"})


def test_signal_gate_and_successful_destinations_are_not_retried():
    current, sent, signal = [1000.0], [], []
    cfg = config(spyware_beacon_signal=True, mobile_enabled=True,
                 mobile_signal_cli="unit-test-no-binary", mobile_host_number="+15555550100",
                 mobile_dest_number="+15555550101")
    def send_signal(text):
        signal.append(text)
        return len(signal) >= 2
    instance = beacon.EmergencyBeacon(cfg, clock=lambda: current[0],
                                     transport=capture(sent), signal_sender=send_signal)
    instance.enqueue({"rule_code": "SPYWARE_MEMORY"})
    instance.tick()
    assert len(sent) == 1 and len(signal) == 1
    current[0] += 5.1
    instance.tick()
    assert len(sent) == 1 and len(signal) == 2 and instance.snapshot()["sent"] == 1
    cfg.mobile_enabled = False
    instance.enqueue({"id": "second", "rule_code": "SPYWARE_MEMORY"})
    instance.tick()
    assert len(signal) == 2


def test_snapshot_remains_responsive_during_transport():
    entered, release = threading.Event(), threading.Event()
    def slow(*_args):
        entered.set()
        assert release.wait(3)
        return 200, "ok"
    instance = beacon.EmergencyBeacon(config(), transport=slow)
    instance.enqueue({"rule_code": "SPYWARE_MEMORY"})
    worker = threading.Thread(target=instance.tick)
    worker.start()
    try:
        assert entered.wait(3)
        before = time.monotonic()
        assert instance.snapshot()["sending"] is True
        assert time.monotonic() - before < 0.5
    finally:
        release.set()
        worker.join(3)


def startup():
    return {"version": 1, "run": "a" * 32, "key": "b" * 64, "pid": os.getpid(),
            "birth": 100.0, "settings": str(Path.cwd() / "unit-test-settings.json"),
            "config": beacon._config_snapshot(config())}


def wire(initial, sequence, kind="heartbeat", key=None):
    return beacon._canonical(beacon._wrap({"run": initial["run"], "seq": sequence, "kind": kind},
                                          key or bytes.fromhex(initial["key"]))) + b"\n"


def run_watch(raw, *, initial=None, identity=None, authority=None):
    initial = initial or startup()
    sent = []
    result = beacon._watch_loop(io.BytesIO(raw), initial, sender=sent.append,
                                identity_probe=identity or (lambda *_: "alive"),
                                authority_probe=authority or (lambda *_: True),
                                destination_probe=lambda *_: True, poll_seconds=0.01,
                                heartbeat_timeout=0.1)
    return result, sent


def test_authenticated_normal_stop_wins_over_exit():
    initial = startup()
    probes = iter(["alive", "gone"])
    result, sent = run_watch(wire(initial, 1) + wire(initial, 2, "stop"),
                             identity=lambda *_: next(probes, "gone"))
    assert result == "normal_stop" and not sent


@pytest.mark.parametrize("state,expected", [
    ("gone", "SPYWARE_ENGINE_EXIT"),
    ("unknown", "identity_unverifiable"),
    ("reused", "identity_unverifiable"),
])
def test_pipe_eof_rechecks_exact_parent_identity_before_classifying(state, expected):
    initial = startup()
    # Windows can close a terminating parent's pipe before its process identity
    # changes to gone. Bootstrap and the first EOF probe still see it alive.
    probes = iter(["alive", "alive", state])
    result, sent = run_watch(wire(initial, 1),
                             identity=lambda *_: next(probes, state))
    assert result == expected
    assert sent == ([{"rule_code": expected, "severity": "CRITICAL", "pid": initial["pid"]}]
                    if state == "gone" else [])


def test_pipe_eof_from_live_parent_still_sends_one_bounded_heartbeat_alert(monkeypatch):
    initial = startup()
    clock, sent = [0.0], []
    frames = [("message", json.loads(wire(initial, 1))), ("eof", None)]
    waits = []
    class TimedQueue:
        def get(self, *, timeout):
            waits.append(timeout)
            if frames:
                return frames.pop(0)
            clock[0] += timeout
            raise queue.Empty
    monkeypatch.setattr(beacon, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    result = beacon._consume_watch_messages(TimedQueue(), threading.Event(),
        key=bytes.fromhex(initial["key"]), run=initial["run"], pid=initial["pid"],
        birth=initial["birth"], settings=Path(initial["settings"]), initial=initial["config"],
        config=config(), sender=lambda event: sent.append((clock[0], event)),
        identity_probe=lambda *_: "alive", authority_probe=lambda *_: True,
        destination_probe=lambda *_: True, on_ready=None, heartbeat_timeout=10.0,
        poll_seconds=1.0)
    assert result == "SPYWARE_HEARTBEAT_LOST"
    assert sent == [(beacon._EOF_EXIT_GRACE,
                     {"rule_code": result, "severity": "CRITICAL", "pid": initial["pid"]})]
    assert waits == [1.0, 1.0, beacon._EOF_EXIT_GRACE]


@pytest.mark.parametrize(
    "raw", [b"", b"not-json\n", b"x" * (beacon._MAX_WIRE + 1)],
    ids=["empty-input", "malformed-json", "oversized-frame"],
)
def test_unauthenticated_or_invalid_state_never_sends(raw):
    result, sent = run_watch(raw)
    assert result in {"unauthenticated_state", "invalid_state"} and not sent


def test_replay_and_wrong_key_fail_closed():
    initial = startup()
    for raw in (wire(initial, 1) + wire(initial, 1), wire(initial, 1, key=b"z" * 32)):
        result, sent = run_watch(raw)
        assert result == "invalid_state" and not sent


@pytest.mark.parametrize("state", ["unknown", "reused"])
def test_ambiguous_identity_and_pid_reuse_never_send(state):
    initial, calls = startup(), [0]
    def identity(*_args):
        calls[0] += 1
        return "alive" if calls[0] == 1 else state
    result, sent = run_watch(wire(initial, 1), identity=identity)
    assert result == "identity_unverifiable" and not sent


def test_persisted_authorization_revocation_prevents_emergency():
    initial, calls = startup(), [0]
    def authority(*_args):
        calls[0] += 1
        return calls[0] == 1
    result, sent = run_watch(wire(initial, 1), authority=authority)
    assert result == "authorization_revoked" and not sent


@pytest.mark.parametrize("revoke", [True, False])
def test_open_pipe_reader_retires_after_revocation_or_partial_frame_stall(revoke):
    initial = startup()
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb")
    ready, sent = threading.Event(), []
    before = {thread.ident for thread in threading.enumerate()}
    try:
        # Bootstrap readline may prefetch the first heartbeat. Keep the writer
        # open and leave an incomplete next frame so readline cannot finish.
        os.write(write_fd, b"bootstrap\n" + wire(initial, 1) + b'{"partial":')
        assert stream.readline() == b"bootstrap\n"
        result = beacon._watch_loop(stream, initial, sender=sent.append,
            identity_probe=lambda *_: "alive",
            authority_probe=lambda *_: not (revoke and ready.is_set()),
            destination_probe=lambda *_: True, on_ready=ready.set,
            heartbeat_timeout=0.05, poll_seconds=0.01)
        assert ready.is_set(), "bootstrap prefetch lost its authenticated heartbeat"
        assert result == ("authorization_revoked" if revoke else "SPYWARE_HEARTBEAT_LOST")
        assert len(sent) == (0 if revoke else 1)
        assert not [thread for thread in threading.enumerate()
                    if thread.ident not in before and thread.name == "SpywareBeacon-pipe-read"], \
            "watcher returned with its buffered stdin reader still alive"
    finally:
        # Release a defective reader before fixture cleanup can itself block.
        os.close(write_fd)
        stream.close()


def test_destination_secret_revocation_fails_closed(tmp_path, monkeypatch):
    from angerona.core import secure_store
    initial = beacon._config_snapshot(config())
    monkeypatch.setattr(secure_store, "read_secret_values", lambda *_args, **_kwargs: {})
    assert not beacon._stored_destination_current(tmp_path / "settings.json", initial)
    monkeypatch.setattr(secure_store, "read_secret_values", lambda *_args, **_kwargs:
                        {"ANGERONA_ARIA_PUSH_URL": initial["aria_push_url"]})
    assert beacon._stored_destination_current(tmp_path / "settings.json", initial)


def _private_settings(tmp_path, cfg):
    from angerona.core.engine_transport import create_private_file, private_directory
    directory = private_directory(tmp_path / "beacon-fixture")
    path = directory / "settings.json"
    saved = beacon._config_snapshot(cfg)
    saved.pop("aria_push_url")
    with os.fdopen(create_private_file(path), "w", encoding="utf-8") as stream:
        json.dump(saved, stream)
    return path


@pytest.fixture
def independent_watcher(tmp_path):
    """Two directly retained physical-interpreter children; file-only sender."""
    from beacon_native_fixture import BeaconCase
    pytest.importorskip("psutil")
    cfg = config()
    settings = _private_settings(tmp_path, cfg)
    output = settings.parent / "fake-beacon.json"
    initial = startup()
    initial["settings"] = str(settings)
    case = None
    try:
        case = BeaconCase(beacon, initial, output, settings.parent / "engine-ready.json")
        case.start()
        yield case, settings, output
    finally:
        if case is not None:
            case.close()


def _wait_for(predicate, seconds=5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.025)
    assert predicate(), "bounded subprocess condition did not occur"


def _watcher_result(case, reason):
    deadline = time.monotonic() + 5.0
    assert case.watcher.wait(deadline) == 0
    assert case.watcher.next_frame(deadline) == {"result": reason, "reader_retired": True}


def test_independent_watcher_survives_exact_parent_exit(independent_watcher):
    case, _settings, output = independent_watcher
    case.engine.process.kill()
    case.engine.wait(time.monotonic() + 5.0)
    _wait_for(output.exists)
    event = json.loads(output.read_text())
    assert event == {"rule_code": "SPYWARE_ENGINE_EXIT", "severity": "CRITICAL", "pid": case.engine_pid}
    _watcher_result(case, "SPYWARE_ENGINE_EXIT")


def test_independent_watcher_reports_stalled_heartbeat(independent_watcher):
    case, _settings, output = independent_watcher
    _wait_for(output.exists)
    assert case.engine.process.poll() is None
    assert json.loads(output.read_text())["rule_code"] == "SPYWARE_HEARTBEAT_LOST"
    _watcher_result(case, "SPYWARE_HEARTBEAT_LOST")
    assert case.engine.process.poll() is None


def test_independent_watcher_normal_stop_never_sends(independent_watcher):
    case, _settings, output = independent_watcher
    case.normal_stop()
    assert not output.exists()


def test_independent_watcher_honors_saved_disable_before_parent_death(independent_watcher):
    case, settings, output = independent_watcher
    saved = json.loads(settings.read_text())
    saved["spyware_beacon_enabled"] = False
    settings.write_text(json.dumps(saved))
    _watcher_result(case, "authorization_revoked")
    case.engine.process.kill()
    case.engine.wait(time.monotonic() + 5.0)
    assert not output.exists()


def test_production_watchdog_launch_and_graceful_stop(tmp_path, monkeypatch):
    from beacon_native_fixture import OwnedChildren
    # A missing Signal binary precludes a live notification even on failure.
    cfg = config(spyware_beacon_channel=False, spyware_beacon_signal=True,
                 aria_push_enabled=False, mobile_enabled=True,
                 mobile_signal_cli=str(tmp_path / "DOES_NOT_EXIST_signal_cli.exe"),
                 mobile_host_number="+15555550100", mobile_dest_number="+15555550101")
    settings = _private_settings(tmp_path, cfg)
    cfg.data_dir = settings.parent
    instance = beacon.EmergencyBeacon(cfg)
    owners = None
    try:
        owners = OwnedChildren(beacon)
        monkeypatch.setattr(beacon, "sys", SimpleNamespace(
            executable=owners.contract["image"]["path"], frozen=False))
        monkeypatch.setattr(beacon, "subprocess", SimpleNamespace(
            Popen=owners.production_launcher(settings.parent / "production-ready.json"),
            PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
            CREATE_NO_WINDOW=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
        # Launch assertion is inside cleanup, including pre-READY failures.
        assert instance.start_watchdog()
        assert instance.snapshot()["watchdog"] == "running"
        instance.heartbeat()
    finally:
        instance.close(graceful=True)
        try:
            def retired():
                instance.snapshot()  # Nonblocking harvest; never join.
                return instance._watch_process is None and instance._watch_retire_thread is None
            _wait_for(retired, seconds=6)
        finally:
            if owners is not None:
                for child in owners.children:
                    child.other_readers = [instance._watch_ready_reader, instance._watch_retire_thread]
                owners.close()
    assert instance.snapshot()["watchdog"] == "stopped"
    assert all(child.proof is not None for child in owners.children)
    assert len(owners.physical_adaptations) == 1
    assert owners.physical_adaptations[0]["unmodified_production_launcher"] is False


class _WatchHandle:
    def __init__(self):
        self.closed = False
        self.close_calls = 0

    def Close(self):
        self.close_calls += 1
        self.closed = True


class _WatchProcess:
    def __init__(self, *, wait=None, ready=b"READY\n"):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(ready)
        self.stderr = None
        self.returncode = None
        self._handle = _WatchHandle()
        self.wait_calls = []
        self._wait = wait

    def poll(self):
        return self.returncode

    def wait(self, *, timeout):
        self.wait_calls.append(timeout)
        if self._wait is not None:
            self._wait()
        self.returncode = 0
        return 0

    def kill(self):
        raise AssertionError("production cleanup must never force-kill")


def _owned_instance(process):
    instance = beacon.EmergencyBeacon(config())
    instance._watch_process = process
    instance._watch_key = b"x" * 32
    instance._watch_run = "a" * 32
    instance._watch_config = beacon._config_snapshot(instance.config)
    instance._watch_state = "running"
    return instance


def _retirement_finished(instance):
    instance.snapshot()
    return instance._watch_retire_thread is None


def test_graceful_cleanup_keeps_ownership_while_waiting_without_blocking_snapshot():
    entered, release = threading.Event(), threading.Event()
    def wait():
        entered.set()
        assert release.wait(2)
    process = _WatchProcess(wait=wait)
    instance = _owned_instance(process)
    try:
        before = time.monotonic()
        instance.close(graceful=True)
        assert time.monotonic() - before < 0.5
        assert entered.wait(1)
        assert instance.snapshot()["watchdog"] == "stopping"
        assert instance._watch_process is process
        assert instance.start_watchdog() is False
        assert process.wait_calls == [5.0]
    finally:
        release.set()
        _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance.snapshot()["watchdog"] == "stopped"
    assert instance._watch_process is None
    assert process.stdin.closed and process.stdout.closed
    assert process._handle.close_calls == (1 if os.name == "nt" else 0)


def test_expired_graceful_wait_keeps_original_child_and_can_retry():
    def wait():
        raise subprocess.TimeoutExpired("inert-owned-child", 5.0)
    process = _WatchProcess(wait=wait)
    instance = _owned_instance(process)
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is process
    assert instance.snapshot()["watchdog"] == "unavailable: watcher cleanup unresolved"
    assert not process.stdout.closed
    assert instance.start_watchdog() is False
    process._wait = None
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance.snapshot()["watchdog"] == "stopped"
    assert process.wait_calls == [5.0, 5.0]


def test_unretired_ready_reader_holds_ownership_and_stdout():
    class Reader:
        def __init__(self):
            self.alive = True
            self.joins = []
        def is_alive(self):
            return self.alive
        def join(self, timeout):
            self.joins.append(timeout)
    reader = Reader()
    process = _WatchProcess()
    instance = _owned_instance(process)
    instance._watch_ready_reader = reader
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is process
    assert not process.stdout.closed
    assert reader.joins == [0.5]
    reader.alive = False
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is None


def test_intentional_detach_never_waits_kills_or_sends_stop():
    process = _WatchProcess()
    instance = _owned_instance(process)
    instance.close(graceful=False)
    assert process.wait_calls == []
    assert process.returncode is None
    assert instance._watch_process is None
    assert instance.snapshot()["watchdog"] == "detached"
    assert process.stdin.closed
    assert not process.stdout.closed
    assert process._handle.close_calls == 0


def test_detach_after_admitted_graceful_cleanup_does_not_discard_worker():
    entered, release = threading.Event(), threading.Event()
    def wait():
        entered.set()
        assert release.wait(2)
    process = _WatchProcess(wait=wait)
    instance = _owned_instance(process)
    try:
        instance.close(graceful=True)
        assert entered.wait(1)
        worker = instance._watch_retire_thread
        instance.close(graceful=False)
        assert instance._watch_process is process
        assert instance._watch_retire_thread is worker
        assert instance.snapshot()["watchdog"] == "stopping"
        assert process.wait_calls == [5.0]
    finally:
        release.set()
        _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance.snapshot()["watchdog"] == "stopped"


@pytest.mark.parametrize("failure", ["construct", "start"])
def test_cleanup_thread_setup_failure_keeps_ownership(monkeypatch, failure):
    process = _WatchProcess()
    instance = _owned_instance(process)
    real_thread = threading.Thread
    def thread(*args, **kwargs):
        if failure == "construct":
            raise RuntimeError("inert thread construction refusal")
        result = real_thread(*args, **kwargs)
        result.start = lambda: (_ for _ in ()).throw(RuntimeError("inert thread start refusal"))
        return result
    with monkeypatch.context() as scoped:
        scoped.setattr(beacon, "threading", SimpleNamespace(Thread=thread))
        instance.close(graceful=True)
        assert instance.snapshot()["watchdog"] == "unavailable: watcher cleanup not started"
        assert instance._watch_process is process
        assert process.wait_calls == []
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is None


@pytest.mark.parametrize("stream_name", ["stdin", "stdout"])
def test_stream_close_failure_keeps_retirement_unresolved(stream_name):
    class Broken(io.BytesIO):
        fail = True
        def close(self):
            if self.fail:
                raise OSError("inert close refusal")
            return super().close()
    process = _WatchProcess()
    broken = Broken()
    setattr(process, stream_name, broken)
    instance = _owned_instance(process)
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is process
    assert instance.snapshot()["watchdog"] == "unavailable: watcher cleanup unresolved"
    broken.fail = False
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is None


def _inert_launch(monkeypatch, tmp_path, popen):
    from angerona.core import engine_transport, persistent_engine, secure_store
    instance = beacon.EmergencyBeacon(config(data_dir=tmp_path))
    monkeypatch.setattr(beacon, "_settings_authorized", lambda *_: True)
    monkeypatch.setattr(beacon, "_stored_destination_current", lambda *_: True)
    monkeypatch.setattr(secure_store, "_path_traverses_reparse", lambda *_: False)
    monkeypatch.setattr(engine_transport, "private_directory", lambda path: path)
    monkeypatch.setattr(persistent_engine, "_child_environment", lambda: {})
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        Process=lambda pid: SimpleNamespace(create_time=lambda: 100.0)))
    monkeypatch.setattr(beacon, "subprocess", SimpleNamespace(Popen=popen,
        PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
        CREATE_NO_WINDOW=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
    return instance


def test_launch_failure_without_child_is_unavailable(tmp_path, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise OSError("inert child launch refusal")
    instance = _inert_launch(monkeypatch, tmp_path, refuse)
    assert instance.start_watchdog() is False
    assert instance._watch_process is None
    assert instance._watch_retire_thread is None
    assert instance.snapshot()["watchdog"].startswith("unavailable:")


@pytest.mark.parametrize("failure", ["bootstrap-write", "invalid-ready"])
def test_post_launch_failure_retires_original_child(tmp_path, monkeypatch, failure):
    process = _WatchProcess(ready=b"NOT-READY\n")
    if failure == "bootstrap-write":
        class Broken(io.BytesIO):
            def write(self, _raw):
                raise OSError("inert bootstrap write refusal")
        process.stdin = Broken()
    instance = _inert_launch(monkeypatch, tmp_path, lambda *_a, **_kw: process)
    try:
        assert instance.start_watchdog() is False
    finally:
        instance.close(graceful=True)
        _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is None
    assert process.wait_calls == [5.0]
    assert process.stdin.closed and process.stdout.closed


def test_snapshot_never_joins_completed_cleanup_worker():
    class Finished:
        def is_alive(self):
            return False
        def join(self, *_args, **_kwargs):
            raise AssertionError("snapshot must not join")
    process = _WatchProcess()
    instance = _owned_instance(process)
    instance._watch_retire_thread = Finished()
    instance._watch_retire_result = (True, "stopped", process)
    assert instance.snapshot()["watchdog"] == "stopped"
    assert instance._watch_process is None


def test_detach_after_expired_graceful_cleanup_keeps_unresolved_child():
    def wait():
        raise subprocess.TimeoutExpired("inert-owned-child", 5.0)
    process = _WatchProcess(wait=wait)
    instance = _owned_instance(process)
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    state = instance.snapshot()["watchdog"]
    instance.close(graceful=False)
    assert instance._watch_process is process
    assert instance.snapshot()["watchdog"] == state
    assert process.wait_calls == [5.0]
    process._wait = None
    instance.close(graceful=True)
    _wait_for(lambda: _retirement_finished(instance), seconds=3)
    assert instance._watch_process is None


class _RetirementPipe:
    """Synthetic write-end failures; no descriptor, process or transport."""
    def __init__(self, *, failure="close", error=BrokenPipeError, closes=True):
        self.failure, self.error, self.closes = failure, error, closes
        self.closed = False
        self.operations = []

    def write(self, raw):
        assert type(raw) is bytes and not self.closed
        self.operations.append("write")
        if self.failure == "write":
            raise BrokenPipeError("inert stop write refusal")
        return len(raw)

    def flush(self):
        self.operations.append("flush")
        if self.failure == "flush":
            raise BrokenPipeError("inert stop flush refusal")

    def close(self):
        self.operations.append("close")
        if self.closes:
            self.closed = True
        raise self.error("inert buffered close refusal")


def _call_retirement(instance, process, monkeypatch, *, reader=None, frame=b"inert stop\n", platform="nt"):
    # Replace only this module's os reference. No interpreter-wide OS patch.
    with monkeypatch.context() as scoped:
        scoped.setattr(beacon, "os", SimpleNamespace(name=platform))
        instance._retire_watchdog(process, frame, reader, "stopped")
    return instance._watch_retire_result


@pytest.mark.parametrize("failure", ["write", "flush", "close"])
@pytest.mark.parametrize("platform", ["nt", "posix"])
def test_closed_broken_pipe_still_requires_wait_reader_stream_and_handle_proof(monkeypatch, failure, platform):
    process = _WatchProcess()
    pipe = _RetirementPipe(failure=failure)
    process.stdin = pipe
    process.stderr = io.BytesIO()
    instance = _owned_instance(process)

    class Reader:
        alive = True
        joins = []
        def is_alive(self):
            return self.alive
        def join(self, timeout):
            assert process.returncode == 0
            self.joins.append(timeout)
            self.alive = False
    reader = Reader()
    instance._watch_ready_reader = reader
    original_wait = process.wait
    def wait(*, timeout):
        assert pipe.closed, "retirement waited before write-end closure"
        return original_wait(timeout=timeout)
    process.wait = wait
    original_close = process._handle.Close
    def close_handle():
        assert not reader.alive and all(stream.closed for stream in (process.stdin, process.stdout, process.stderr))
        original_close()
    process._handle.Close = close_handle

    assert _call_retirement(instance, process, monkeypatch, reader=reader, platform=platform) == (
        True, "stopped", process)
    assert process.wait_calls == [5.0] and reader.joins == [0.5]
    assert pipe.operations == (["write", "close"] if failure == "write" else ["write", "flush", "close"])
    assert all(stream.closed for stream in (process.stdin, process.stdout, process.stderr))
    assert process._handle.close_calls == (1 if platform == "nt" else 0)
    # Only a proven result may release the original ownership in GUI harvest.
    instance._watch_retire_thread = SimpleNamespace(is_alive=lambda: False)
    assert instance.snapshot()["watchdog"] == "stopped"
    assert instance._watch_process is None and instance._watch_ready_reader is None


@pytest.mark.parametrize("frame", [None, b"inert stop\n"], ids=["buffered-close", "stop-flush-and-close"])
def test_real_cpython_buffered_broken_pipe_close_can_finish_owned_retirement(monkeypatch, frame):
    class RefusingRaw(io.RawIOBase):
        write_calls = 0
        def writable(self):
            return True
        def write(self, raw):
            assert len(raw) > 0
            self.write_calls += 1
            raise BrokenPipeError("inert raw write refusal")
    raw = RefusingRaw()
    buffered = io.BufferedWriter(raw, buffer_size=64)
    buffered.write(b"pending inert bytes")
    process = _WatchProcess()
    process.stdin = buffered
    process.stderr = io.BytesIO()
    instance = _owned_instance(process)
    try:
        assert _call_retirement(instance, process, monkeypatch, frame=frame) == (True, "stopped", process)
        assert buffered.closed and raw.closed and raw.write_calls >= 1
        assert process.wait_calls == [5.0] and process.poll() == 0
        assert process.stdout.closed and process.stderr.closed and process._handle.closed
        assert process._handle.close_calls == 1
    finally:
        if not buffered.closed:
            try:
                buffered.close()
            except (BrokenPipeError, ValueError):
                pass
        raw.close()  # The only real owned object is an in-memory RawIOBase.


@pytest.mark.parametrize("error,closes", [
    (BrokenPipeError, False), (OSError, False), (OSError, True), (RuntimeError, True),
], ids=["broken-pipe-still-open", "oserror-still-open", "oserror-after-close", "runtime-error-after-close"])
def test_other_pipe_close_faults_never_grant_retirement(monkeypatch, error, closes):
    process = _WatchProcess()
    pipe = _RetirementPipe(error=error, closes=closes)
    process.stdin = pipe
    instance = _owned_instance(process)
    assert _call_retirement(instance, process, monkeypatch) == (
        False, "unavailable: watcher cleanup unresolved", process)
    assert pipe.closed is closes and process.wait_calls == []
    assert not process.stdout.closed and not process._handle.closed
    instance._watch_retire_thread = SimpleNamespace(is_alive=lambda: False)
    assert instance.snapshot()["watchdog"] == "unavailable: watcher cleanup unresolved"
    assert instance._watch_process is process and instance._watch_key == b"x" * 32


@pytest.mark.parametrize("failure", [
    "wait-timeout", "poll-mismatch", "reader-alive", "stdout-error", "stdout-unclosed",
    "stderr-error", "stderr-unclosed", "handle-error", "handle-unclosed", "handle-missing",
])
def test_closed_broken_pipe_does_not_bypass_remaining_retirement_guards(monkeypatch, failure):
    process = _WatchProcess()
    process.stdin = _RetirementPipe()
    process.stderr = io.BytesIO()
    instance = _owned_instance(process)
    class Reader:
        def is_alive(self):
            return failure == "reader-alive"
        def join(self, timeout):
            assert timeout == 0.5
    reader = Reader()
    instance._watch_ready_reader = reader
    if failure == "wait-timeout":
        def timeout():
            raise subprocess.TimeoutExpired("inert-original-child", 5.0)
        process._wait = timeout
    elif failure == "poll-mismatch":
        process.poll = lambda: 1
    elif failure.startswith(("stdout-", "stderr-")):
        class Unclosed(io.BytesIO):
            def close(self):
                if failure.endswith("-error"):
                    raise OSError("inert stream close refusal")
                # A close method returning without closure is not a receipt.
        setattr(process, failure.split("-", 1)[0], Unclosed())
    elif failure == "handle-error":
        def refuse():
            raise OSError("inert original-handle close refusal")
        process._handle.Close = refuse
    elif failure == "handle-unclosed":
        process._handle.Close = lambda: None
    elif failure == "handle-missing":
        process._handle = None
    try:
        assert _call_retirement(instance, process, monkeypatch, reader=reader) == (
            False, "unavailable: watcher cleanup unresolved", process)
        assert process.stdin.closed and process.wait_calls == [5.0]
        instance._watch_retire_thread = SimpleNamespace(is_alive=lambda: False)
        assert instance.snapshot()["watchdog"] == "unavailable: watcher cleanup unresolved"
        assert instance._watch_process is process and instance._watch_ready_reader is reader
        assert instance._watch_key == b"x" * 32
    finally:
        for stream in (process.stdout, process.stderr):
            if isinstance(stream, io.BytesIO):
                io.BytesIO.close(stream)  # In-memory fake only, no OS handle.
