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


@pytest.mark.parametrize("raw", [b"", b"not-json\n", b"x" * (beacon._MAX_WIRE + 1)])
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
    """Real independent processes, fake file-only sender, no egress path."""
    pytest.importorskip("psutil")
    cfg = config()
    settings = _private_settings(tmp_path, cfg)
    output = settings.parent / "fake-beacon.json"
    source = str(Path(beacon.__file__).resolve().parents[2])
    watcher_code = (
        "import sys,json;from pathlib import Path;"
        f"sys.path.insert(0,{source!r});"
        "from angerona.core.spyware_beacon import _watch_loop;"
        "initial=json.loads(sys.stdin.buffer.readline());"
        f"sink=Path({str(output)!r});"
        "_watch_loop(sys.stdin.buffer,initial,"
        "sender=lambda event:sink.write_text(json.dumps(event)),"
        "destination_probe=lambda *_:True,"
        "on_ready=lambda:print('READY',flush=True),"
        "heartbeat_timeout=2.0,poll_seconds=0.02)"
    )
    parent_code = (
        "import sys,os,json,time,subprocess,psutil;"
        f"sys.path.insert(0,{source!r});"
        "from angerona.core.spyware_beacon import _wrap,_canonical;"
        f"initial={startup()!r};"
        f"initial['settings']={str(settings)!r};"
        "initial['pid']=os.getpid();initial['birth']=psutil.Process().create_time();"
        f"child=subprocess.Popen([sys.executable,'-I','-c',{watcher_code!r}],"
        "stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True);"
        "child.stdin.write(_canonical(initial)+bytes([10]));"
        "message={'run':initial['run'],'seq':1,'kind':'heartbeat'};"
        "child.stdin.write(_canonical(_wrap(message,bytes.fromhex(initial['key'])))+bytes([10]));"
        "child.stdin.flush();ready=child.stdout.readline();"
        "print(json.dumps({'pid':child.pid,'engine_pid':os.getpid(),'ready':ready.decode().strip()}),flush=True);"
        "command=sys.stdin.buffer.readline();"
        "message['seq']=2;message['kind']='stop';"
        "child.stdin.write(_canonical(_wrap(message,bytes.fromhex(initial['key'])))+bytes([10]));"
        "child.stdin.flush();child.stdin.close();child.wait(timeout=5)"
    )
    parent = subprocess.Popen([sys.executable, "-I", "-c", parent_code], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(parent.stdout.readline()), daemon=True).start()
    watcher_pid = None
    try:
        raw = lines.get(timeout=8)
        if not raw:
            pytest.fail("fixture parent failed: " + parent.stderr.read(4000).decode())
        info = json.loads(raw)
        watcher_pid = info["pid"]
        assert info["ready"] == "READY"
        yield parent, watcher_pid, settings, output, info["engine_pid"]
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.wait(timeout=5)
        if watcher_pid:
            import psutil
            try:
                child = psutil.Process(watcher_pid)
                child.wait(timeout=4)
            except psutil.NoSuchProcess:
                pass
            except psutil.TimeoutExpired:
                child.kill()


def _wait_for(predicate, seconds=5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.025)
    assert predicate(), "bounded subprocess condition did not occur"


def _watcher_exited(pid):
    import psutil
    try:
        # On POSIX the fixture engine still owns this child and may not have
        # reaped it yet. A zombie has terminated and cannot retain stdin locks.
        return psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True


def test_independent_watcher_survives_exact_parent_exit(independent_watcher):
    import psutil
    parent, _pid, _settings, output, engine_pid = independent_watcher
    psutil.Process(engine_pid).kill()
    parent.wait(timeout=5)
    _wait_for(output.exists)
    event = json.loads(output.read_text())
    assert event == {"rule_code": "SPYWARE_ENGINE_EXIT", "severity": "CRITICAL", "pid": engine_pid}


def test_independent_watcher_reports_stalled_heartbeat(independent_watcher):
    parent, _pid, _settings, output, _engine_pid = independent_watcher
    _wait_for(output.exists)
    assert parent.poll() is None
    assert json.loads(output.read_text())["rule_code"] == "SPYWARE_HEARTBEAT_LOST"
    _wait_for(lambda: _watcher_exited(_pid))
    assert parent.poll() is None


def test_independent_watcher_normal_stop_never_sends(independent_watcher):
    parent, _pid, _settings, output, _engine_pid = independent_watcher
    parent.stdin.write(b"stop\n")
    parent.stdin.flush()
    assert parent.wait(timeout=5) == 0
    assert not output.exists()


def test_independent_watcher_honors_saved_disable_before_parent_death(independent_watcher):
    parent, watcher_pid, settings, output, _engine_pid = independent_watcher
    saved = json.loads(settings.read_text())
    saved["spyware_beacon_enabled"] = False
    settings.write_text(json.dumps(saved))
    _wait_for(lambda: _watcher_exited(watcher_pid))
    parent.kill()
    parent.wait(timeout=5)
    assert not output.exists()


def test_production_watchdog_launch_and_graceful_stop(tmp_path):
    # Signal CLI does not exist, so even a regression cannot send a live message.
    cfg = config(spyware_beacon_channel=False, spyware_beacon_signal=True,
                 aria_push_enabled=False, mobile_enabled=True,
                 mobile_signal_cli=str(tmp_path / "DOES_NOT_EXIST_signal_cli.exe"),
                 mobile_host_number="+15555550100", mobile_dest_number="+15555550101")
    settings = _private_settings(tmp_path, cfg)
    cfg.data_dir = settings.parent
    instance = beacon.EmergencyBeacon(cfg)
    assert instance.start_watchdog()
    process = instance._watch_process
    try:
        assert instance.snapshot()["watchdog"] == "running"
        instance.heartbeat()
    finally:
        instance.close(graceful=True)
    assert process.wait(timeout=6) == 0
    assert instance.snapshot()["watchdog"] == "stopped"
