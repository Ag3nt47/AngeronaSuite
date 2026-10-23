from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core import live_debug as debug


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert predicate()


def replay_log(service, relative, *, limit=2000):
    for _turn in range(limit):
        service._tail_log(relative)
        if not service._logs[relative]["backlog"]:
            return
    pytest.fail("Bounded log replay did not finish")


def bus():
    result = EventBus()
    result.arm(BusAuthority(secrets.token_bytes(32)))
    return result


class NoTransport:
    def __init__(self, service):
        self.service = service

    def start(self):
        pass

    def stop(self, timeout=3):
        pass


def test_stop_during_start_retains_owner_and_prevents_late_activation(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    owned, results = [], []

    class HeldTransport:
        def __init__(self, service):
            self.stopped = False
            owned.append(self)

        def start(self):
            entered.set()
            assert release.wait(10)

        def stop(self, timeout=3):
            self.stopped = True
            return True

    monkeypatch.setattr(debug, "_NamedPipeServer", HeldTransport)
    service = debug.LiveDebugService(bus(), tmp_path, enabled=True, export_logs=False)
    worker = threading.Thread(target=lambda: results.append(service.start()))
    worker.start()
    try:
        assert entered.wait(5)
        assert service.status()["starting"] is True
        assert service.start() is False  # A second caller cannot replace the owner.
        before = time.monotonic()
        assert service.stop(timeout=0.03) is False
        assert time.monotonic() - before < 1
        assert service.status()["shutdown_pending"] is True
        assert len(owned) == 1 and service._server is owned[0]
    finally:
        release.set()
        worker.join(10)
        assert service.stop(timeout=2) is True
    assert not worker.is_alive() and results == [False]
    assert owned[0].stopped and service._thread is None
    assert service.status()["running"] is False
    assert service.status()["starting"] is False
    assert service.status()["shutdown_pending"] is False
    assert not service.submit_diagnostic("test", "late event")


@pytest.fixture
def memory_service(tmp_path, monkeypatch):
    monkeypatch.setattr(debug, "_NamedPipeServer", NoTransport)
    service = debug.LiveDebugService(bus(), tmp_path, enabled=True, export_logs=False)
    assert service.start()
    try:
        yield service
    finally:
        service.stop()


@pytest.fixture
def native_service(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows named-pipe transport")
    service = debug.LiveDebugService(bus(), tmp_path, enabled=True, export_logs=False)
    assert service.start(), service.status()
    try:
        yield service
    finally:
        service.stop()
        assert all(not thread.is_alive() for thread in service._server.threads)
        assert not service._thread.is_alive()


def connected(service):
    client = debug.LiveDebugClient(service.endpoint, os.getpid(), service.birth)
    client.connect()
    assert client.read(2)["kind"] == "hello"
    return client


def next_kind(client, kind, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = client.read(0.25)
        if record is not None and record["kind"] == kind:
            return record
    pytest.fail(f"No {kind} record")


def test_disabled_service_has_no_subscription_or_transport(tmp_path, monkeypatch):
    def forbidden(*_args):
        raise AssertionError("disabled service opened a pipe")
    monkeypatch.setattr(debug, "_NamedPipeServer", forbidden)
    service = debug.LiveDebugService(bus(), tmp_path)
    assert not service.start()
    assert not service.submit(Event("m", "x"))
    assert service.bus.subscriber_metrics() == ()


def test_all_event_severities_keep_original_provenance_and_redact_secrets(memory_service):
    service = memory_service
    digest = "a" * 64
    for severity in Severity:
        service.bus.publish(Event("Sensor", "password=hunter2 https://alice:pw@example.test/x?token=abc "
                                  "Bearer abcdefghijklmnop sk-examplekeyabcdefghijklmnopqrstuvwxyz",
                                  severity, details={
                                      "pid": 42, "sha256": digest, "process_create_time": 123.0,
                                      "private_key": "never export me", "payload": {"password": "hidden"},
                                      "coverage": {"services": {"status": "unknown", "error": "token=secret", "raw": "NO"}},
                                  }))
    wait_until(lambda: len([r for r in service.recent()["records"] if r["kind"] == "event"]) == len(Severity))
    records = [r for r in service.recent()["records"] if r["kind"] == "event"]
    assert {r["severity"] for r in records} == {s.name for s in Severity}
    for record in records:
        rendered = json.dumps(record)
        assert "hunter2" not in rendered and "alice" not in rendered and "sk-examplekey" not in rendered
        assert "never export me" not in rendered and "hidden" not in rendered
        assert "token=abc" not in rendered and "token=secret" not in rendered
        assert record["details"]["sha256"] == digest
        assert record["details"]["process_create_time"] == 123.0
        assert record["details"]["coverage"]["services"]["status"] == "unknown"
        assert "raw" not in record["details"]["coverage"]["services"]
        assert len(record["original_hmac"]) == 64
        assert record["original_integrity_verified"] is True
        assert record["advisory_only"] is True


def test_unsigned_unarmed_event_never_claims_integrity(tmp_path):
    service = debug.LiveDebugService(EventBus(), tmp_path)
    record = service._event_view(Event("m", "x"))
    assert not record["original_integrity_verified"]
    assert not record["live_receipt_verified_at_export"]


def test_secret_command_flags_and_private_keys_are_redacted():
    text = 'tool --password "HumanSecret123" --token plainshorttoken -Passphrase "Two words" /secret:tiny'
    rendered = debug.sanitize_text(text)
    for secret in ("HumanSecret123", "plainshorttoken", "Two words", "tiny"):
        assert secret not in rendered
    assert "omitted" in debug.sanitize_text("-----BEGIN RSA PRIVATE KEY-----\nsecret bytes")


def test_history_gap_and_page_copy_are_bounded_and_independent(tmp_path):
    service = debug.LiveDebugService(bus(), tmp_path, history_size=3)
    for index in range(6):
        service._append(dict(kind="diagnostic", message=str(index), details={"pid": index}))
    page = service.recent(0, 1)
    assert len(page["records"]) == 1
    assert page["gap"] == 3 and page["first_seq"] == 4 and page["last_seq"] == 6
    page["records"][0]["details"]["pid"] = -1
    assert service.recent(3, 1)["records"][0]["details"]["pid"] == 3
    assert [r["seq"] for r in service.recent(4)["records"]] == [5, 6]


def test_backpressure_is_nonblocking_and_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(debug, "_NamedPipeServer", NoTransport)
    service = debug.LiveDebugService(bus(), tmp_path, enabled=True, queue_size=2, export_logs=False)
    entered, release = threading.Event(), threading.Event()
    original = service._event_view

    def held(event):
        entered.set()
        assert release.wait(5)
        return original(event)

    monkeypatch.setattr(service, "_event_view", held)
    assert service.start()
    try:
        service.bus.publish(Event("m", "first"))
        assert entered.wait(2)
        start = time.monotonic()
        for index in range(100):
            service.submit(Event("m", str(index)))
        elapsed = time.monotonic() - start
        assert elapsed < 0.5
        assert service.status()["queue_dropped"] == 98
        release.set()
        wait_until(lambda: any(r.get("reason") == "ingestion-overflow" for r in service.recent()["records"]))
    finally:
        release.set()
        service.stop()


def test_missing_log_is_informational_and_later_creation_recovers(tmp_path):
    service = debug.LiveDebugService(bus(), tmp_path)
    relative = "diagnostics/crash.log"
    replay_log(service, relative)
    service._tail_log(relative)
    records = service.recent()["records"]
    assert len(records) == 1 and records[0]["state"] == "not-created"
    path = tmp_path / relative
    path.parent.mkdir()
    path.write_text("ValueError: password=hidden\n", encoding="utf-8")
    replay_log(service, relative)
    records = service.recent()["records"]
    assert records[-2]["state"] == "available"
    assert "hidden" not in records[-1]["message"]


def test_log_utf8_lines_rotation_and_initial_tail_report_gaps(tmp_path):
    path = tmp_path / "diagnostics" / "crash.log"
    path.parent.mkdir()
    path.write_bytes((b"old line " + b"." * 120 + b"\n") * (debug.LOG_INITIAL_BYTES // 128)
                     + "new snowman ☃\n".encode())
    service = debug.LiveDebugService(bus(), tmp_path, history_size=10_000)
    replay_log(service, "diagnostics/crash.log")
    records = service.recent(limit=1000)["records"]
    assert any(r.get("reason") == "initial-log-tail" for r in records)
    assert any("snowman ☃" in r.get("message", "") for r in service.recent(service.status()["cursor"] - 10)["records"])
    path.write_bytes(b"rotated\n")
    replay_log(service, "diagnostics/crash.log")
    tail = service.recent(service.status()["cursor"] - 2)["records"]
    assert tail[0]["reason"] == "log-rotated-or-truncated"
    assert tail[1]["message"] == "rotated"


def test_oversized_log_line_omitted_without_exporting_partial_secret(tmp_path):
    path = tmp_path / "logs" / "crash.log"
    path.parent.mkdir()
    path.write_bytes(b"password=" + b"short secret " * 9000 + b"\nnormal error\n")
    service = debug.LiveDebugService(bus(), tmp_path, history_size=200)
    replay_log(service, "logs/crash.log")
    records = service.recent()["records"]
    assert any(r.get("reason") == "oversized-log-line" for r in records)
    assert any(r.get("message") == "normal error" for r in records)
    assert "short secret" not in json.dumps(records)


def test_newline_flood_is_one_counted_notice_not_blank_history_amplification(tmp_path):
    path = tmp_path / "diagnostics" / "crash.log"
    path.parent.mkdir()
    path.write_bytes(b"\n" * debug.LOG_READ_BYTES)
    service = debug.LiveDebugService(bus(), tmp_path)
    replay_log(service, "diagnostics/crash.log")
    rows = service.recent()["records"]
    counted = [row for row in rows if row.get("state") == "blank-lines-coalesced"]
    assert len(counted) == 1
    assert counted[0]["blank_lines"] == debug.LOG_READ_BYTES
    assert counted[0]["blank_bytes"] == debug.LOG_READ_BYTES
    assert not any(row["kind"] == "diagnostic" for row in rows)
    assert service.status()["cursor"] == 2


def test_short_nonblank_lines_resume_with_record_budget_and_exact_order(tmp_path):
    path = tmp_path / "diagnostics" / "crash.log"
    path.parent.mkdir()
    expected = [str(number) for number in range(8192)]
    path.write_text("\n".join(expected) + "\n", encoding="ascii")
    service = debug.LiveDebugService(bus(), tmp_path, history_size=2000)
    actual, cursor, turns = [], 0, 0
    while True:
        before = service.status()["cursor"]
        service._tail_log("diagnostics/crash.log")
        turns += 1
        view = service.recent(cursor, limit=1000)
        assert view["gap"] == 0
        assert service.status()["cursor"] - before <= debug.LOG_RECORDS_PER_TURN + 2
        actual.extend(row["message"] for row in view["records"] if row["kind"] == "diagnostic")
        cursor = view["cursor"]
        assert len(service._logs["diagnostics/crash.log"]["pending"]) <= debug.LOG_READ_BYTES + debug.MAX_TEXT
        if not service._logs["diagnostics/crash.log"]["backlog"]:
            break
        assert turns < 1000
    assert turns >= len(expected) // debug.LOG_RECORDS_PER_TURN
    assert actual == expected


def test_mixed_blank_runs_and_partial_line_resume_without_losing_nonblank_text(tmp_path):
    path = tmp_path / "logs" / "crash.log"
    path.parent.mkdir()
    expected = [f"fixture {number}" for number in range(400)]
    path.write_text("\n\n".join(expected) + "\npartial", encoding="utf-8")
    service = debug.LiveDebugService(bus(), tmp_path, history_size=2000)
    replay_log(service, "logs/crash.log")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(" continued\n")
    replay_log(service, "logs/crash.log")
    rows = service.recent(limit=1000)["records"]
    assert [row["message"] for row in rows if row["kind"] == "diagnostic"] == [*expected, "partial continued"]
    assert sum(row.get("blank_lines", 0) for row in rows) == len(expected) - 1


def test_log_time_budget_resumes_without_decoding_remaining_lines(tmp_path, monkeypatch):
    from types import SimpleNamespace
    path = tmp_path / "logs" / "crash.log"
    path.parent.mkdir()
    path.write_bytes(b"line\n" * 20)
    service = debug.LiveDebugService(bus(), tmp_path)
    now = [0.0]
    real_append = service._append

    def costed_append(record):
        real_append(record)
        now[0] += .002

    monkeypatch.setattr(service, "_append", costed_append)
    monkeypatch.setattr(debug, "time", SimpleNamespace(monotonic=lambda: now[0], time=time.time))
    service._tail_log("logs/crash.log", deadline=.005)
    rows = service.recent()["records"]
    assert sum(row["kind"] == "diagnostic" for row in rows) == 2
    assert service._logs["logs/crash.log"]["backlog"]
    replay_log(service, "logs/crash.log")
    assert sum(row["kind"] == "diagnostic" for row in service.recent()["records"]) == 20


def test_expired_native_io_slice_still_parses_one_bounded_record(tmp_path):
    path = tmp_path / "logs" / "crash.log"
    path.parent.mkdir()
    path.write_bytes(b"first error\nsecond error\n")
    service = debug.LiveDebugService(bus(), tmp_path)
    service._tail_log("logs/crash.log", deadline=0.0)
    rows = service.recent()["records"]
    assert [row["message"] for row in rows if row["kind"] == "diagnostic"] == ["first error"]
    assert service._logs["logs/crash.log"]["backlog"]
    replay_log(service, "logs/crash.log")
    assert [row["message"] for row in service.recent()["records"] if row["kind"] == "diagnostic"] == [
        "first error", "second error"]


def test_event_lane_runs_between_busy_logs_and_round_robin_reaches_later_source(tmp_path, monkeypatch):
    monkeypatch.setattr(debug, "_NamedPipeServer", NoTransport)
    first = tmp_path / debug.LOG_SOURCES[0]
    first.parent.mkdir()
    first.write_bytes(b"x\n" * 32768)
    second = tmp_path / debug.LOG_SOURCES[1]
    second.parent.mkdir(exist_ok=True)
    second.write_bytes(b"later source error\n")
    service = debug.LiveDebugService(bus(), tmp_path, enabled=True, export_logs=True)
    order = []
    injected = threading.Event()
    tail, event_view = service._tail_log, service._event_view

    def observed_tail(relative, **kwargs):
        order.append(relative)
        tail(relative, **kwargs)
        if not injected.is_set():
            injected.set()
            service.bus.publish(Event("Fixture", "event between log turns"))

    def observed_event(event):
        order.append("EVENT")
        return event_view(event)

    monkeypatch.setattr(service, "_tail_log", observed_tail)
    monkeypatch.setattr(service, "_event_view", observed_event)
    assert service.start()
    try:
        wait_until(lambda: "EVENT" in order and debug.LOG_SOURCES[1] in order)
        assert order.index("EVENT") < order.index(debug.LOG_SOURCES[1])
        wait_until(lambda: any(row.get("message") == "later source error" for row in service.recent()["records"]))
        assert service.status()["queue_dropped"] == 0
    finally:
        service.stop()


def test_global_log_budget_preserves_rotating_source_cursor(tmp_path, monkeypatch):
    from types import SimpleNamespace
    service = debug.LiveDebugService(bus(), tmp_path)
    now, observed = [0.0], []

    def bounded_turn(relative, **_kwargs):
        observed.append(relative)
        now[0] += debug.LOG_CYCLE_SECONDS

    monkeypatch.setattr(service, "_tail_log", bounded_turn)
    monkeypatch.setattr(debug, "time", SimpleNamespace(monotonic=lambda: now[0]))
    for _ in debug.LOG_SOURCES:
        service._poll_logs()
    assert observed == list(debug.LOG_SOURCES)


def test_log_hardlinks_and_nonallowlisted_files_are_rejected(tmp_path):
    path = tmp_path / "logs" / "crash.log"
    path.parent.mkdir()
    outside = tmp_path / "credential.txt"
    outside.write_text("private contents")
    os.link(outside, path)
    service = debug.LiveDebugService(bus(), tmp_path)
    service._tail_log("logs/crash.log")
    assert service.recent()["records"][-1]["state"] == "unavailable"
    assert "private contents" not in json.dumps(service.recent())
    with pytest.raises(PermissionError):
        with service._open_log("credential.txt"):
            pytest.fail("nonallowlisted source was opened")


def test_windows_resolved_log_handle_cannot_escape_expected_root(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows final-handle path proof")
    import win32file
    path = tmp_path / "logs" / "crash.log"
    path.parent.mkdir()
    path.write_text("public fixture\n")
    outside = tmp_path / "credential.txt"
    outside.write_text("private redirected fixture\n")
    original = win32file.CreateFile

    def redirected(name, *args):
        return original(str(outside) if name == str(path) else name, *args)

    monkeypatch.setattr(win32file, "CreateFile", redirected)
    service = debug.LiveDebugService(bus(), tmp_path)
    service._tail_log("logs/crash.log")
    rows = service.recent()["records"]
    assert rows[-1]["state"] == "unavailable"
    assert rows[-1]["error_type"] == "PermissionError"
    assert "private redirected fixture" not in json.dumps(rows)


def hello(pid=123):
    return dict(protocol=debug.PROTOCOL, kind="hello", run_id="a" * 32, seq=0,
                ts=1.0, pid=pid, birth=10.0, status={"cursor": 1})


@pytest.mark.parametrize("field,value", [("kind", []), ("seq", True), ("seq", -1),
                                         ("seq", 2**64), ("ts", float("nan")),
                                         ("birth", "10"), ("run_id", "bad")])
def test_client_rejects_malformed_identity_with_clear_error(field, value):
    client = debug.LiveDebugClient(debug.endpoint_for_pid(123), 123)
    record = hello()
    record[field] = value
    with pytest.raises(debug.LiveDebugError):
        client._accept(record)


def test_client_rejects_replay_and_undisclosed_gaps_but_accepts_explicit_gap():
    client = debug.LiveDebugClient(debug.endpoint_for_pid(123), 123)
    client._accept(hello())
    record = dict(protocol=debug.PROTOCOL, kind="event", run_id="a" * 32, seq=2, ts=1.0)
    with pytest.raises(debug.LiveDebugError, match="without a gap"):
        client._accept(record)
    client._accept(dict(record, kind="gap", seq=1, reason="retention", lost_records=1))
    client._accept(record)
    with pytest.raises(debug.LiveDebugError, match="Replayed"):
        client._accept(record)


@pytest.mark.parametrize("raw", [b'{"protocol":"angerona-live-debug-v1","x":1,"x":2}',
                                b'{"protocol":"angerona-live-debug-v1","x":NaN}',
                                b'{"protocol":"angerona-live-debug-v1","x":"\\u001b"}',
                                b"x" * (debug.MAX_FRAME_BYTES + 1)], ids=["duplicate", "nan", "controls", "oversize"])
def test_bounded_json_decoder_rejects_ambiguous_or_unsafe_frames(raw):
    with pytest.raises(debug.LiveDebugError):
        debug._decode(raw)


def test_interrupted_pending_read_drains_kernel_io_before_event_close(monkeypatch):
    if os.name != "nt":
        pytest.skip("pywin32 pending read lifecycle")
    import win32file
    from types import SimpleNamespace
    actions = []
    pipe = debug._Pipe(object())
    overlap = SimpleNamespace(hEvent=SimpleNamespace(Close=lambda: actions.append("close-event")))
    monkeypatch.setattr(pipe, "_overlap", lambda: overlap)
    monkeypatch.setattr(win32file, "AllocateReadBuffer", lambda count: bytearray(count))
    monkeypatch.setattr(win32file, "ReadFile", lambda *_args: actions.append("issue-read"))

    def interrupted(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(pipe, "_wait", interrupted)
    monkeypatch.setattr(debug, "_cancel_pipe_io", lambda _handle: actions.append("cancel"))

    def completion(_handle, _overlap, wait):
        if not wait:
            actions.append("check-pending")
            error = OSError("pending")
            error.winerror = 996
            raise error
        actions.append("drain")
        return 0

    monkeypatch.setattr(win32file, "GetOverlappedResult", completion)
    with pytest.raises(KeyboardInterrupt):
        pipe.read(1)
    assert actions == ["issue-read", "check-pending", "cancel", "drain", "close-event"]


def test_stop_counts_and_records_queued_loss(tmp_path):
    service = debug.LiveDebugService(bus(), tmp_path)
    service._running = True
    assert service.submit(Event("fixture", "queued event"))
    service.stop()
    assert service.status()["queue_dropped"] == 1
    assert service.recent()["records"][-1]["reason"] == "service-stopped"
    assert service.bus.subscriber_metrics() == ()


def test_native_multi_client_live_events_and_timeout_recovery(native_service):
    first, second = connected(native_service), connected(native_service)
    try:
        assert next_kind(first, "coverage")["state"] == "live"
        assert next_kind(second, "coverage")["state"] == "live"
        for _ in range(5):
            assert first.read(0.01) is None
        native_service.bus.publish(Event("Fixture Sensor", "synthetic integration event", Severity.CRITICAL,
                                        details={"pid": 4321}))
        for client in (first, second):
            record = next_kind(client, "event")
            assert record["module"] == "Fixture Sensor"
            assert record["original_integrity_verified"] is True
    finally:
        first.close()
        second.close()


def test_native_pipe_rejects_write_handle_and_anonymous_reader(native_service):
    import win32api
    import win32con
    import win32file
    import win32security
    import pywintypes
    with pytest.raises(pywintypes.error):
        win32file.CreateFile(native_service.endpoint, win32con.GENERIC_WRITE, 0, None,
                             win32con.OPEN_EXISTING, 0, None)
    win32security.ImpersonateAnonymousToken(win32api.GetCurrentThread())
    try:
        with pytest.raises(pywintypes.error):
            win32file.CreateFile(native_service.endpoint, win32con.GENERIC_READ, 0, None,
                                 win32con.OPEN_EXISTING, 0, None)
    finally:
        win32security.RevertToSelf()


def test_native_client_checks_os_server_pid_before_reading(native_service, monkeypatch):
    import win32pipe
    monkeypatch.setattr(win32pipe, "GetNamedPipeServerProcessId", lambda _handle: os.getpid() + 1)
    client = debug.LiveDebugClient(native_service.endpoint, os.getpid())
    try:
        with pytest.raises(debug.LiveDebugError, match="OS diagnostic server PID"):
            client.connect()
        assert client._pipe is None
    finally:
        client.close()


def test_native_birth_mismatch_is_rejected(native_service):
    client = debug.LiveDebugClient(native_service.endpoint, os.getpid(), 1.0)
    with pytest.raises(debug.LiveDebugError, match="process identity changed"):
        client.connect()
    assert client._process_handle is None


def test_native_first_instance_collision_fails_without_replacing_live_server(native_service, tmp_path):
    competing = debug.LiveDebugService(bus(), tmp_path, enabled=True, export_logs=False)
    assert competing.start() is False
    assert competing.status()["error"]
    client = connected(native_service)
    client.close()


def test_native_pending_read_can_be_cancelled_cleanly(native_service):
    client = connected(native_service)
    next_kind(client, "coverage")
    exited = threading.Event()

    def reader():
        try:
            client.read(30)
        except debug.LiveDebugError:
            pass
        finally:
            client.close()
            exited.set()

    thread = threading.Thread(target=reader)
    thread.start()
    time.sleep(0.03)
    client.cancel()
    assert exited.wait(2)
    thread.join()


def test_native_slow_client_does_not_delay_fast_client_or_producer(native_service):
    import win32con
    import win32file
    slow = win32file.CreateFile(native_service.endpoint, win32con.GENERIC_READ, 0, None,
                                win32con.OPEN_EXISTING, 0, None)
    healthy = connected(native_service)
    received = threading.Event()

    def drain():
        try:
            for _ in range(400):
                record = healthy.read(0.25)
                if record and record.get("message") == "final marker":
                    received.set()
                    return
        except debug.LiveDebugError:
            pass

    thread = threading.Thread(target=drain)
    thread.start()
    try:
        started = time.monotonic()
        for _ in range(100):
            native_service.bus.publish(Event("Fixture", "normal message. " * 450))
        native_service.bus.publish(Event("Fixture", "final marker"))
        assert time.monotonic() - started < 1.0
        assert received.wait(5)
        wait_until(lambda: native_service.status()["client_count"] <= 1, 6)
    finally:
        healthy.cancel()
        thread.join(2)
        healthy.close()
        slow.Close()
        assert not thread.is_alive()


def test_native_history_reader_survives_a_bounded_disk_persistence_pause(native_service):
    # Fill more than the native pipe buffer before attaching. This reproduces
    # a reader taking >1 second to persist one already-read history chunk.
    initial_cursor = native_service.status()["cursor"]
    for index in range(80):
        native_service.bus.publish(Event("Fixture", f"history-{index}: " + "normal. " * 850))
    wait_until(lambda: native_service.status()["cursor"] == initial_cursor + 80)
    client = connected(native_service)
    try:
        time.sleep(1.3)
        seen = []
        deadline = time.monotonic() + 6
        while len(seen) < 80 and time.monotonic() < deadline:
            row = client.read(.25)
            if row is not None and row["kind"] == "event":
                seen.append(row["seq"])
        assert seen == list(range(initial_cursor + 1, initial_cursor + 81))
        assert native_service.status()["queue_dropped"] == 0
    finally:
        client.close()


def cli_module():
    spec = importlib.util.spec_from_file_location("live_debug_cli_test", Path(__file__).parents[1] / "tools" / "live_debug.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_snapshot_and_local_annotation_are_advisory(tmp_path, capsys):
    cli = cli_module()
    clients = []

    class Client:
        def __init__(self, *_args):
            self.closed = False
            self.rows = iter([hello(), dict(protocol=debug.PROTOCOL, kind="event", run_id="a" * 32,
                                           seq=1, message="event", ts=1)])
            clients.append(self)

        def connect(self):
            pass

        def read(self, timeout):
            return next(self.rows)

        def close(self):
            self.closed = True

    assert cli.main(["--pid", "123"], client_factory=Client) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["kind"] for r in rows] == ["hello", "event"]
    assert clients[-1].closed
    output = tmp_path / "review.jsonl"
    assert cli.main(["--pid", "123", "--annotate", "1", "--verdict", "false-positive",
                     "--note", "password=hidden", "--output", str(output)], client_factory=Client) == 0
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert rows[-1]["kind"] == "annotation" and rows[-1]["advisory_only"]
    assert "hidden" not in rows[-1]["note"]
    target = rows[-2]
    canonical = json.dumps(target, ensure_ascii=True, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("ascii")
    assert rows[-1]["target_view_sha256"] == hashlib.sha256(canonical).hexdigest()


def test_cli_follow_duration_cannot_truncate_retained_snapshot(monkeypatch, capsys):
    cli = cli_module()
    clock, closed = [0.0], []
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])

    class Client:
        def __init__(self, *_args):
            initial = hello()
            initial["status"]["cursor"] = 2
            self.rows = iter([initial, {"kind": "event", "seq": 1}, {"kind": "event", "seq": 2}])

        def connect(self):
            pass

        def read(self, timeout):
            clock[0] += 0.05
            return next(self.rows)

        def close(self):
            closed.append(True)

    assert cli.main(["--pid", "123", "--duration", "0.01"], client_factory=Client) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["seq"] for row in rows] == [0, 1, 2]
    assert closed == [True]


def test_caller_log_rotation_is_bounded_and_refuses_unrelated_or_linked_file(tmp_path):
    cli = cli_module()
    output = tmp_path / "review.jsonl"
    writer = cli.RotatingViewLog(output, max_bytes=debug.MAX_FRAME_BYTES, backups=2)
    for index in range(100):
        writer.write(dict(protocol=debug.PROTOCOL, kind="diagnostic", message="normal. " * 120, seq=index))
    files = list(tmp_path.glob("review.jsonl*"))
    assert len(files) == 3
    assert all(path.stat().st_size <= debug.MAX_FRAME_BYTES for path in files)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("leave intact")
    with pytest.raises(debug.LiveDebugError):
        cli.RotatingViewLog(unrelated)
    linked = tmp_path / "linked.jsonl"
    os.link(output, linked)
    with pytest.raises(debug.LiveDebugError):
        cli.RotatingViewLog(linked)


def test_cli_output_error_does_not_recursively_rewrite_failed_output(tmp_path, monkeypatch, capsys):
    cli = cli_module()
    writes = []

    class Client:
        def __init__(self, *_args):
            pass

        def connect(self):
            pass

        def read(self, timeout):
            return hello()

        def close(self):
            pass

    def failed_write(_self, _record):
        writes.append(1)
        raise OSError("disk unavailable")

    monkeypatch.setattr(cli.RotatingViewLog, "write", failed_write)
    assert cli.main(["--pid", "123", "--output", str(tmp_path / "log.jsonl")], client_factory=Client) == 2
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(writes) == 1
    assert rows[-1]["kind"] == "client_error"


def test_cli_cannot_annotate_unseen_retention_gap(capsys):
    cli = cli_module()

    class Client:
        def __init__(self, *_args):
            self.rows = iter([dict(hello(), status={"cursor": 9}),
                              dict(protocol=debug.PROTOCOL, kind="gap", run_id="a" * 32,
                                   seq=7, reason="retention", lost_records=7, ts=1)])

        def connect(self):
            pass

        def read(self, timeout):
            return next(self.rows)

        def close(self):
            pass

    assert cli.main(["--pid", "123", "--annotate", "4", "--verdict", "false-positive",
                     "--note", "reviewed reason"], client_factory=Client) == 2
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert not any(row["kind"] == "annotation" for row in rows)
    assert "no longer retained" in rows[-1]["reason"]


def test_cli_annotation_requires_reason():
    cli = cli_module()
    with pytest.raises(SystemExit) as error:
        cli.main(["--pid", "123", "--annotate", "1", "--verdict", "false-positive"])
    assert error.value.code == 2
