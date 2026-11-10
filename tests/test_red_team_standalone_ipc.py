"""Private transport, remote presentation and marker capability regression gates.

These cases launch no application or native helper process. Windows capability
cases operate only on newly created files owned by this test process.
"""
from __future__ import annotations

from dataclasses import replace
import io
import os
import threading
from types import SimpleNamespace

import pytest

from angerona.shark.red_team_ipc import (
    ToolBinding, ToolChannel, ToolProtocolError, bootstrap, canonical,
    open_hello, parse_bootstrap, seal_hello,
)
from angerona.telemetry.process_snapshot_worker import _receive, _send


KEY = b"x" * 32
BINDING = ToolBinding("1" * 32, 1001, "134377029371751523", 1002,
                      "134377029371751524", 1003, "134377029371751525")


def frame(*, side="child", binding=BINDING, kind="launch", payload=None):
    sink = io.BytesIO()
    channel = ToolChannel(io.BytesIO(), sink, binding, KEY, side=side)
    channel.send(kind, payload if payload is not None else {"config": {}})
    return sink.getvalue()


def reader(raw, *, binding=BINDING, side="core", alive=lambda: True):
    return ToolChannel(io.BytesIO(raw), io.BytesIO(), binding, KEY, side=side, alive=alive)


def test_bootstrap_and_native_hello_bind_exact_parent_wrapper_child():
    value = bootstrap(KEY, BINDING.session, BINDING.parent_pid, BINDING.parent_birth,
                      BINDING.wrapper_pid, BINDING.wrapper_birth, startup_deadline_ns=123456789)
    assert parse_bootstrap(value) == value
    expected = {name: getattr(BINDING, name) for name in (
        "session", "parent_pid", "parent_birth", "wrapper_pid", "wrapper_birth")}
    assert open_hello(seal_hello(BINDING, KEY), KEY, expected) == BINDING
    for field in ("parent_pid", "wrapper_pid"):
        with pytest.raises(ToolProtocolError):
            open_hello(seal_hello(BINDING, KEY), KEY, {**expected, field: expected[field] + 1})
    with pytest.raises(ToolProtocolError):
        parse_bootstrap({**value, "extra": True})


@pytest.mark.parametrize("field,value", [
    ("child_pid", True), ("child_pid", 1001), ("child_birth", "0134377029371751525"),
    ("session", "f" * 31), ("parent_birth", "nan"),
])
def test_native_binding_rejects_bool_root_pid_noncanonical_birth_and_session(field, value):
    with pytest.raises(ToolProtocolError):
        replace(BINDING, **{field: value})


def test_replay_is_refused_without_advancing_or_accepting_a_second_request():
    raw = frame()
    peer = reader(raw + raw)
    assert peer.receive()["kind"] == "launch"
    with pytest.raises(ToolProtocolError, match="sequence"):
        peer.receive()
    assert peer._received == 1


@pytest.mark.parametrize("change", ["mac", "payload", "birth", "session", "sequence", "verb"])
def test_tampered_or_cross_generation_envelope_is_refused(change):
    value = _receive(io.BytesIO(frame()), 2 * 1024 * 1024)
    if change == "mac":
        value["mac"] = "0" * 64
    else:
        key, replacement = {
            "payload": ("payload", {"config": {"auto_remediate": True}}),
            "birth": ("child_birth", "134377029371751526"),
            "session": ("session", "2" * 32),
            "sequence": ("sequence", True),
            "verb": ("kind", "arbitrary-exec"),
        }[change]
        value["body"][key] = replacement
    output = io.BytesIO()
    _send(output, value, 2 * 1024 * 1024)
    with pytest.raises(ToolProtocolError):
        reader(output.getvalue()).receive()


def test_direction_and_native_lifetime_are_mandatory():
    with pytest.raises(ToolProtocolError):
        reader(frame(side="core", kind="show", payload={})).receive()
    for unavailable in (False, 1):
        with pytest.raises(ToolProtocolError, match="native generation"):
            reader(frame(), alive=lambda: unavailable).receive()


@pytest.mark.parametrize("value", [object(), {"x": (1, 2)}, {"x": float("nan")},
                                  {"x": [0] * 4097}, {str(i): i for i in range(129)}])
def test_only_bounded_plain_json_can_cross_the_pipe(value):
    with pytest.raises(ToolProtocolError):
        canonical(value)


def test_tool_capture_cannot_hide_startup_or_failure_as_an_empty_scope():
    from angerona.gui.red_team_bridge import RedTeamToolOwner
    owner = RedTeamToolOwner(lambda *_args: None)
    with pytest.raises(ToolProtocolError):
        owner.capture_scope()
    owner._retired.set()  # Explicit inert native-retired fixture state.
    assert owner.capture_scope() == (owner, owner._epoch, "retired")


def test_stop_always_retires_the_exact_job_even_after_wrapper_exits():
    from angerona.gui.red_team_bridge import RedTeamToolOwner
    calls = []
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._native_owner = SimpleNamespace(
        prepare_tree_retirement=lambda **_kwargs: calls.append("capture"),
        poll=lambda: 0, terminate=lambda: calls.append("terminate-exact-job"),
        wait_tree=lambda **_kwargs: calls.append("wait"), close=lambda: calls.append("close"))
    assert owner.stop(1.)
    assert calls == ["capture", "terminate-exact-job", "wait", "close"]
    assert owner.lifecycle_snapshot()["retirement_phase"] == "retired"


@pytest.mark.parametrize("failure", ["non-inheritable", "unknown-before-rights", "multiple-rights"])
def test_received_descriptors_remain_owned_until_admitted_and_all_failures_close_them(tmp_path, monkeypatch, failure):
    import array
    from angerona.shark import red_team_ipc as ipc
    descriptors = [os.open(tmp_path / str(index), os.O_CREAT | os.O_RDWR, 0o600) for index in range(2)]
    rights = array.array("i", descriptors if failure == "multiple-rights" else descriptors[:1]).tobytes()
    ancillary = [(1, 1, rights)]
    if failure == "unknown-before-rights":
        ancillary.insert(0, (999, 999, b"ignored"))
    channel = SimpleNamespace(recvmsg=lambda *_args: (b"a" * 32, ancillary, 0, None))
    def cannot_protect(_descriptor, _inherit):
        raise OSError("inert non-inheritability failure")
    monkeypatch.setattr(ipc, "socket", SimpleNamespace(SOL_SOCKET=1, SCM_RIGHTS=1,
        CMSG_SPACE=lambda _size: 16, MSG_TRUNC=32, MSG_CTRUNC=8))
    monkeypatch.setattr(ipc, "os", SimpleNamespace(name="posix", close=os.close,
        set_inheritable=cannot_protect))
    try:
        with pytest.raises((OSError, ToolProtocolError)):
            ipc.receive_descriptor(channel, "a" * 32)
        for descriptor in descriptors if failure == "multiple-rights" else descriptors[:1]:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_remote_history_reader_never_enters_local_key_or_history_loader(monkeypatch, tmp_path):
    from PySide6.QtWidgets import QApplication
    from angerona.gui import red_team_console as console
    application = QApplication.instance() or QApplication([])
    called = []
    monkeypatch.setattr(console, "list_history", lambda *_: pytest.fail("child loaded Core history"))
    monkeypatch.setattr(console, "load_verified_history_text", lambda *_: pytest.fail("child loaded Core keys"))
    worker = console._HistoryWorker("list", tmp_path, reader=lambda operation, name: called.append((operation, name)))
    worker.run()
    assert called == [("list", "")]
    assert application is not None


@pytest.mark.parametrize("kind", ["launch", "stop", "close"])
def test_queued_old_owner_requests_cannot_control_replacement_tool(tmp_path, kind):
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import QApplication, QWidget
    from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner
    application = QApplication.instance() or QApplication([])
    class Parent(QWidget):
        _shark_narration = Signal(str)
        def __init__(self):
            super().__init__()
            self.config = SimpleNamespace(data_dir=tmp_path)
            self.calls = []
        def _run_simulation(self, cfg):
            self.calls.append(("launch", cfg))
        def _stop_simulation(self):
            self.calls.append(("stop", None))
    parent = Parent()
    bridge = RedTeamBridge(parent)
    prior = RedTeamToolOwner(lambda *_args: None)
    prior._ready.set()
    bridge.owner = prior
    cfg = {"run_shark": False, "run_redteam": True, "intensity": "Low", "campaign": False,
        "comprehensive": False, "target_dir": None, "custom": None, "auto_remediate": True,
        "analogy": False, "complexity": 1}
    payload = {"config": cfg} if kind == "launch" else {}
    worker = threading.Thread(target=lambda: bridge._incoming.emit(
        (prior, prior._epoch), kind, payload, "a" * 32))
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    prior._ready.clear()
    prior._retired.set()
    current = RedTeamToolOwner(lambda *_args: None)
    current._ready.set()
    bridge.owner = current
    application.processEvents()
    assert not parent.calls and bridge._closing is False
    # A current authenticated owner still reaches the original Core adapter.
    bridge._incoming.emit((current, current._epoch), "launch", {"config": cfg}, "b" * 32)
    assert parent.calls == [("launch", cfg)]
    bridge._timer.stop()
    parent.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows duplicated write-only capability")
def test_actual_marker_write_capability_returns_an_exact_readonly_deny_delete_pin(tmp_path):
    from angerona.gui.red_team_app import write_reserved_capability
    from angerona.gui.red_team_bridge import RedTeamToolOwner, ReservedMarkerWriter, ToolRequest
    from angerona.telemetry.process_snapshot_worker import _Pin
    import base64

    path = tmp_path / "new-inert-marker.txt"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_BINARY, 0o600)
    owner = RedTeamToolOwner(lambda *_args: None)
    # This capability-only fixture creates no helper Job. Its self query pin
    # must never be treated as a process that test cleanup may terminate.
    owner.abort_lifetime = lambda: None
    owner.stop = lambda _timeout: True
    pin = _Pin(os.getpid())  # Query-only self pin; no child or host mutation.
    owner._child = pin
    captured = []
    def write(reservation_id, handle, payload, *, descriptor=None):
        captured.append((reservation_id, handle, payload))
        request = ToolRequest()
        request.result = write_reserved_capability(dict(reservation_id=reservation_id,
            handle=handle, content_b64=base64.b64encode(payload).decode("ascii")), None)
        request.done.set()
        return request
    owner.request_marker = write
    result = None
    try:
        creation_fd, descriptor = descriptor, None
        result = ReservedMarkerWriter(owner).complete_new_marker(creation_fd, path, b"inert-only\n")
        assert os.read(result, 99) == b"inert-only\n"
        with pytest.raises(OSError):
            os.write(result, b"replacement")
        with pytest.raises(OSError):
            path.rename(tmp_path / "replacement.txt")
        assert captured[0][2] == b"inert-only\n"
        assert os.fstat(result).st_ino == path.stat().st_ino
    finally:
        if result is not None:
            os.close(result)
        if descriptor is not None:
            # complete_new_marker consumes the descriptor even on failure.
            try:
                os.close(descriptor)
            except OSError:
                pass
        pin.release_unadmitted()


@pytest.mark.skipif(os.name != "nt", reason="Windows duplicated capability custody")
def test_uncertain_post_duplicate_failure_retires_owner_or_keeps_deny_delete_reservation(tmp_path, monkeypatch):
    from angerona.gui import red_team_bridge as bridge
    from angerona.telemetry.process_snapshot_worker import _Pin
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    pin = _Pin(os.getpid())
    owner._child = pin
    calls, remote = [], []
    owner.abort_lifetime = lambda: calls.append("abort-owned-lifetime")
    owner.stop = lambda timeout: calls.append(("retire-owned-lifetime", timeout)) or False
    duplicate = bridge.duplicate_write_capability
    def uncertain(descriptor, child):
        remote.append(duplicate(descriptor, child))
        raise OSError("inert post-duplication query-close failure")
    monkeypatch.setattr(bridge, "duplicate_write_capability", uncertain)
    path = tmp_path / "new-reserved-marker.txt"
    creation_fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_BINARY, 0o600)
    try:
        with pytest.raises(OSError, match="post-duplication"):
            # The writer consumes creation_fd even when transfer fails.
            bridge.ReservedMarkerWriter(owner).complete_new_marker(creation_fd, path, b"inert")
        assert calls == ["abort-owned-lifetime", ("retire-owned-lifetime", 5.)]
        assert len(owner._marker_reservations) == 1
        with pytest.raises(OSError):
            path.rename(tmp_path / "replacement.txt")
    finally:
        for handle in remote:
            pin.native.close(handle)
        for descriptor in owner._marker_reservations:
            os.close(descriptor)
        owner._marker_reservations.clear()
        pin.release_unadmitted()


@pytest.mark.skipif(os.name != "nt", reason="Windows duplicated capability custody")
def test_creation_close_then_error_never_closes_a_reused_numeric_descriptor(tmp_path, monkeypatch):
    import base64
    from angerona.gui import red_team_bridge as bridge
    from angerona.gui.red_team_app import write_reserved_capability
    from angerona.telemetry.process_snapshot_worker import _Pin
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    pin = _Pin(os.getpid())
    owner._child = pin
    owner.abort_lifetime = lambda: None
    owner.stop = lambda _timeout: False
    def write(reservation_id, handle, payload, *, descriptor=None):
        request = bridge.ToolRequest()
        request.result = write_reserved_capability(dict(reservation_id=reservation_id,
            handle=handle, content_b64=base64.b64encode(payload).decode("ascii")), None)
        request.done.set()
        return request
    owner.request_marker = write
    path = tmp_path / "marker.txt"
    creation_fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_BINARY, 0o600)
    calls, reused = [], []
    real_os = os
    class CloseFault:
        def __getattr__(self, name):
            return getattr(real_os, name)
        def close(self, descriptor):
            if descriptor == creation_fd:
                calls.append(descriptor)
                real_os.close(descriptor)
                reused.append(real_os.open(tmp_path / "other-owned-file.txt",
                    real_os.O_CREAT | real_os.O_EXCL | real_os.O_RDWR | real_os.O_BINARY, 0o600))
                assert reused[-1] == creation_fd
                raise OSError("inert close completed then raised")
            real_os.close(descriptor)
    monkeypatch.setattr(bridge, "os", CloseFault())
    try:
        with pytest.raises(OSError, match="close completed"):
            bridge.ReservedMarkerWriter(owner).complete_new_marker(creation_fd, path, b"inert")
        assert calls == [creation_fd]
        assert len(reused) == 1 and os.fstat(reused[0]).st_ino == (tmp_path / "other-owned-file.txt").stat().st_ino
    finally:
        for descriptor in reused:
            real_os.close(descriptor)
        for descriptor in owner._marker_reservations:
            real_os.close(descriptor)
        owner._marker_reservations.clear()
        pin.release_unadmitted()


def test_serial_probe_preflight_admits_original_worst_case_without_changing_hard_limit(tmp_path):
    from angerona.shark.run_manifest import MAX_ADMITTED_DRILL_SECONDS, preflight_run
    value = preflight_run(kind="red_team", cycles=1, jitter_range=(0, 0),
        noise_chance=0, target_dir=tmp_path, custom=None, campaign=False)
    assert value.accepted
    assert value.budget["projected_serial_process_seconds"] == 16 * 30
    assert value.budget["admitted_run_ttl_seconds"] >= 16 * 30 + 75
    assert value.budget["max_admitted_run_ttl_seconds"] == MAX_ADMITTED_DRILL_SECONDS == 4500


@pytest.mark.parametrize("limited", [False, True])
def test_nonempty_core_history_reply_round_trips_into_actual_child_listing(tmp_path, monkeypatch, limited):
    """Exercise producer, queued work, authenticated reply and child conversion.

    Native admission is an explicit in-memory fixture. The private history
    verifier returns a real typed nonempty listing; issuer verification and
    native process behavior are separate gates. No application/helper launches.
    """
    import time
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import QApplication, QDialog, QWidget
    from angerona.gui import aar_history, red_team_app, red_team_console
    from angerona.gui.aar_history import HistoryListing
    from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner

    application = QApplication.instance() or QApplication([])
    expected_rows = [
        ("redteam_aar_20261109_120000.txt", 1794247200.5, "redteam_aar"),
        ("shark_aar_20261109_115959.txt", 1794247199.25, "shark_aar"),
    ]
    listing = HistoryListing(list(expected_rows), limited=limited)
    # The fix belongs to this JSON producer. The general IPC contract must
    # continue refusing tuples, including this exact formerly failing shape.
    with pytest.raises(ToolProtocolError):
        canonical({"rows": listing.rows, "limited": listing.limited})
    history_calls = []

    def read_history(path):
        history_calls.append(path)
        return listing

    monkeypatch.setattr(aar_history, "list_history", read_history)

    class CoreParent(QWidget):
        _shark_narration = Signal(str)

        def __init__(self):
            super().__init__()
            self.config = SimpleNamespace(data_dir=tmp_path)

    parent = CoreParent()
    bridge = RedTeamBridge(parent)
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._ready.set()  # Exact current-owner admission seam, no native child.
    bridge.owner = owner
    sink = io.BytesIO()
    owner._channel = ToolChannel(io.BytesIO(), sink, BINDING, KEY,
        side="core", alive=lambda: True)
    nonce = "c" * 32
    delivered = []
    hosts = []

    def remote_call(kind, payload):
        assert kind == "history-list" and payload == {}
        assert owner._queue.empty()
        bridge._handle_incoming((owner, owner._epoch), kind, payload, nonce)
        assert len(bridge._tasks) == 1
        bridge._tasks[0].join(2)
        assert not bridge._tasks[0].is_alive()
        application.processEvents()  # Deliver the real background Qt signal.
        assert owner._queue.qsize() == 1
        complete = owner._queue.task_done

        def finish_one_message():
            complete()
            owner._stop.set()  # One bounded writer turn, no native lifetime.

        with monkeypatch.context() as writer_turn:
            writer_turn.setattr(owner._queue, "task_done", finish_one_message)
            owner._write_loop()
        assert owner.lifecycle_snapshot()["startup_failure"] is None
        reply = ToolChannel(io.BytesIO(sink.getvalue()), io.BytesIO(), BINDING, KEY,
            side="child", alive=lambda: True).receive()
        assert reply["kind"] == "reply" and reply["reply_to"] == nonce
        assert reply["payload"] == {"ok": True, "result": {
            "rows": [list(row) for row in expected_rows], "limited": limited}}
        assert all(type(row) is list for row in reply["payload"]["result"]["rows"])
        delivered.append(reply)
        request = red_team_app._Reply()
        request.value = reply["payload"]
        request.done.set()
        return request.wait(0)

    class MinimalConsole(QDialog):
        def __init__(self, host, default_target=None):
            super().__init__(host)
            self.setWindowTitle("Synthetic remote history fixture")
            hosts.append(host)

    # Retain the actual child Host.history method and reply unwrapping; replace
    # only the surrounding full workspace and event-loop lifetime for this test.
    monkeypatch.setattr(red_team_console, "RedTeamConsole", MinimalConsole)
    monkeypatch.setattr(red_team_app, "emit_startup_observation", lambda *_args: None)
    client = SimpleNamespace(startup_started_at=time.monotonic(), stop=threading.Event(),
        reader=None, writer=None, start=lambda: None, tell=lambda *_args, **_kwargs: None,
        call=remote_call)
    reconstructed = []

    def one_child_event_loop(_application):
        reconstructed.append(hosts[0].history("list", ""))
        return 0

    monkeypatch.setattr(QApplication, "exec", one_child_event_loop)
    quit_on_last_window_closed = application.quitOnLastWindowClosed()
    try:
        assert red_team_app._run_qt(client, dict(data_dir=str(tmp_path),
            default_target=str(tmp_path / "inert-drill"), stylesheet="", version="1.15.0")) == 0
        assert len(delivered) == 1 and history_calls == [tmp_path / "aar_history"]
        assert len(reconstructed) == 1 and type(reconstructed[0]) is HistoryListing
        assert reconstructed[0].rows == expected_rows and reconstructed[0].limited is limited
        assert all(type(row) is tuple for row in reconstructed[0].rows)
        assert listing.rows == expected_rows and all(type(row) is tuple for row in listing.rows)
        assert client.stop.is_set() and owner._queue.empty()
    finally:
        bridge._timer.stop()
        owner._stop.set()
        for worker in bridge._tasks:
            if worker.ident is not None:
                worker.join(2)
            assert not worker.is_alive()
        for host in hosts:
            host._close_ready = True
            host.console.close()
            host.close()
            host.deleteLater()
        parent.close()
        parent.deleteLater()
        application.processEvents()
        application.setQuitOnLastWindowClosed(quit_on_last_window_closed)
