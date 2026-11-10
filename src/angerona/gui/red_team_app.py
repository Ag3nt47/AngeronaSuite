"""Independent Red Team Qt application and bounded execution endpoint.

The only credential received is a per-process ephemeral pipe MAC key. Core
retains report verification, enrollment, policies and response authority.
"""
from __future__ import annotations

import base64
import math
import os
from pathlib import Path
import queue
import re
import socket
import stat
import subprocess
import sys
import threading
import time

from angerona.shark.red_team_ipc import (
    MAX_ARTIFACT, VERIFICATION_SECONDS, ToolBinding, ToolChannel, ToolProtocolError,
    emit_startup_observation, parse_bootstrap, receive_descriptor, seal_hello,
)
from angerona.telemetry.process_snapshot_worker import (
    _arm_parent_lifetime, _birth_of, _own_birth, _receive, _send,
)


class _Reply:
    def __init__(self):
        self.done = threading.Event()
        self.value = None

    def wait(self, timeout):
        if not self.done.wait(timeout) or type(self.value) is not dict or self.value.get("ok") is not True:
            raise ToolProtocolError("Core request unavailable or refused; no local authority fallback")
        return self.value.get("result")


def write_reserved_capability(payload, descriptor_channel):
    """Write only an already-duplicated capability. No path or code is accepted."""
    if (type(payload) is not dict or set(payload) != {"reservation_id", "handle", "content_b64"}
            or type(payload["reservation_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", payload["reservation_id"])
            or type(payload["content_b64"]) is not str or len(payload["content_b64"]) > (MAX_ARTIFACT * 4 // 3 + 8)):
        raise ToolProtocolError("Reserved marker command differs")
    content = base64.b64decode(payload["content_b64"], validate=True)
    if not 0 < len(content) <= MAX_ARTIFACT:
        raise ToolProtocolError("Reserved marker content outside bound")
    descriptor = None
    try:
        if os.name == "nt":
            import msvcrt
            handle = payload["handle"]
            if type(handle) is not int or not 0 < handle < (1 << 64) - 1:
                raise ToolProtocolError("Reserved native write capability unavailable")
            descriptor = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        else:
            if payload["handle"] is not None or descriptor_channel is None:
                raise ToolProtocolError("Inherited marker descriptor channel unavailable")
            descriptor = receive_descriptor(descriptor_channel, payload["reservation_id"])
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 0
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ToolProtocolError("Reserved write capability is not one empty ordinary file")
        offset = 0
        while offset < len(content):
            count = os.write(descriptor, content[offset:])
            if count <= 0:
                raise ToolProtocolError("Reserved marker write made no progress")
            offset += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if ((after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
                or after.st_nlink != 1 or after.st_size != len(content)):
            raise ToolProtocolError("Reserved marker capability identity changed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return dict(reservation_id=payload["reservation_id"], closed=True, bytes_written=len(content))


class ToolClient:
    def __init__(self, channel, fd_channel, deliver):
        self.channel, self.fd_channel, self.deliver = channel, fd_channel, deliver
        self.startup_started_at = time.monotonic()
        self.stop = threading.Event()
        self.queue = queue.Queue(maxsize=64)
        self.pending = {}
        self.lock = threading.Lock()
        self.reader = self.writer = None
        self.probes = {}

    def start(self):
        self.writer = threading.Thread(target=self._write, name="RedTeamChildWriter", daemon=False)
        self.reader = threading.Thread(target=self._read, name="RedTeamChildReader", daemon=False)
        self.writer.start()
        self.reader.start()

    def request(self, kind, payload):
        reply = _Reply()
        self.queue.put_nowait((kind, payload, "", reply))
        return reply

    def tell(self, kind, payload, *, reply_to=""):
        self.queue.put_nowait((kind, payload, reply_to, None))

    def call(self, kind, payload, timeout=10):
        return self.request(kind, payload).wait(timeout)

    def _write(self):
        try:
            while not self.stop.is_set():
                try:
                    kind, payload, reply_to, reply = self.queue.get(timeout=.1)
                except queue.Empty:
                    continue
                try:
                    with self.lock:
                        nonce = self.channel.send(kind, payload, reply_to=reply_to)
                        if reply is not None:
                            self.pending[nonce] = reply
                finally:
                    self.queue.task_done()
        except (EOFError, OSError, RuntimeError, ValueError, TypeError):
            self.stop.set()
            self.deliver("channel-ended", {})

    def _read(self):
        try:
            while not self.stop.is_set():
                body = self.channel.receive()
                if body["reply_to"]:
                    with self.lock:
                        reply = self.pending.pop(body["reply_to"], None)
                    if reply is None or body["kind"] != "reply":
                        raise ToolProtocolError("Core reply does not name a live child request")
                    reply.value = body["payload"]
                    reply.done.set()
                elif body["kind"] == "write-marker":
                    result = write_reserved_capability(body["payload"], self.fd_channel)
                    self.tell("marker-written", result, reply_to=body["nonce"])
                elif body["kind"] == "start-probe":
                    result = self._start_probe(body["payload"])
                    self.tell("probe-started", result, reply_to=body["nonce"])
                elif body["kind"] == "retire-probe":
                    result = self._retire_probe(body["payload"])
                    self.tell("probe-ended", result, reply_to=body["nonce"])
                else:
                    self.deliver(body["kind"], body["payload"])
                    if body["kind"] == "close-ready":
                        break
        except (EOFError, OSError, RuntimeError, ValueError, TypeError):
            self.deliver("channel-ended", {})
        finally:
            self.stop.set()
            with self.lock:
                for reply in self.pending.values():
                    reply.done.set()
                self.pending.clear()
            # These are exact Popen objects launched by this endpoint, never a
            # PID supplied by the user/child peer or a process-table search.
            for probe_id in tuple(self.probes):
                try:
                    self._retire_probe({"probe_id": probe_id})
                except (OSError, RuntimeError, ValueError):
                    pass

    def _start_probe(self, payload):
        if (type(payload) is not dict or set(payload) != {"probe_id", "token"}
                or type(payload["probe_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", payload["probe_id"])
                or type(payload["token"]) is not str or not re.fullmatch(r"ANGERONA_REDTEAM_[0-9a-f]{8}", payload["token"])
                or payload["probe_id"] in self.probes or any(process.poll() is None for process in self.probes.values())):
            raise ToolProtocolError("Only one current bounded process probe is admitted")
        for prior in tuple(self.probes):
            self._retire_probe({"probe_id": prior})
        command = ([sys.executable, "--red-team-inert-probe", payload["token"]] if getattr(sys, "frozen", False) else
            [str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)),
             "-I", "-S", "-c", "import time; time.sleep(30)", payload["token"]])
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.probes[payload["probe_id"]] = process
        return dict(probe_id=payload["probe_id"], pid=process.pid, birth=_birth_of(process.pid))

    def _retire_probe(self, payload):
        if type(payload) is not dict or set(payload) != {"probe_id"} or type(payload["probe_id"]) is not str:
            raise ToolProtocolError("Exact process probe retirement unavailable")
        process = self.probes.get(payload["probe_id"])
        if process is None:
            raise ToolProtocolError("Process probe was not owned by this endpoint")
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=3)
        self.probes.pop(payload["probe_id"])
        return dict(probe_id=payload["probe_id"], exited=True)


class _PublicRecord:
    def __init__(self, value):
        if type(value) is not dict:
            raise ToolProtocolError("Core public record schema unavailable")
        self.value = value

    def to_dict(self):
        return dict(self.value)


class _DeviceLabProxy:
    """Closed service methods; no Device Lab key is loaded by the child UI."""
    def __init__(self, client):
        self.client = client

    def _call(self, operation, args, kwargs):
        return self.client.call("device-lab", dict(operation=operation, args=list(args), kwargs=kwargs))

    def create_enrollment(self, *args, **kwargs):
        record, challenge = self._call("create-enrollment", args, kwargs)
        return _PublicRecord(record), _PublicRecord(challenge)

    def confirm_enrollment(self, *args, **kwargs):
        return self._call("confirm-enrollment", args, kwargs)

    def confirm_local_enrollment(self, *args, **kwargs):
        return self._call("confirm-local-enrollment", args, kwargs)

    def list_enrollments(self):
        return [_PublicRecord(value) for value in self._call("list-enrollments", (), {})]

    def collect_local_observations(self, *args, **kwargs):
        return self._call("collect-local-observations", args, kwargs)

    def assess(self, *args, **kwargs):
        return _PublicRecord(self._call("assess", args, kwargs))


def _run_qt(client, initial):
    """Build only this process's Qt host. Importing this module starts no Core."""
    emit_startup_observation("qt-ui", "started", client.startup_started_at)
    from types import SimpleNamespace
    from PySide6.QtCore import QObject, QTimer, Signal, Slot
    from PySide6.QtWidgets import QApplication, QDialog, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget
    from angerona.gui.aar_history import HistoryListing
    from angerona.gui.red_team_console import RedTeamConsole
    from angerona.gui.window_controls import configure_work_window

    class Host(QWidget):
        _shark_narration = Signal(str)
        incoming = Signal(str, object)

        def __init__(self):
            super().__init__()
            if (type(initial) is not dict or set(initial) != {"data_dir", "default_target", "stylesheet", "version"}
                    or any(type(initial[key]) is not str for key in initial)
                    or len(initial["stylesheet"]) > 131072):
                raise ToolProtocolError("Core tool initialization schema unavailable")
            self.config = SimpleNamespace(data_dir=Path(initial["data_dir"]))
            self._pending_simulation_cfg = None
            self.manager = None
            self.readiness = {"ready": False, "state": "PENDING", "reason": "Waiting for current Core readiness."}
            self._red_team_remote_backend = self
            self._device_proxy = _DeviceLabProxy(client)
            self._views = []
            self.setStyleSheet(initial["stylesheet"])
            self.console = RedTeamConsole(self, default_target=initial["default_target"])
            self.console.installEventFilter(self)
            self.incoming.connect(self.receive)
            self._closing = self._close_ready = False
            self._paint_reported = False
            self.console.show()

        def eventFilter(self, watched, event):
            from PySide6.QtCore import QEvent
            if watched is self.console and event.type() == QEvent.Paint and not self._paint_reported:
                self._paint_reported = True
                emit_startup_observation("qt-ui", "completed", client.startup_started_at)
                # Presentation diagnostic only. Core never treats this child
                # report as a detector, response or native lifetime proof.
                client.tell("ui-ready", {"window_title": self.console.windowTitle()[:200]})
            if watched is self.console and event.type() == QEvent.Close and not self._close_ready:
                event.ignore()
                if not self._closing:
                    self._closing = True
                    self.console.launch_btn.setEnabled(False)
                    self.console.live_status.setText("Closing — waiting for Core session, report and lease retirement…")
                    client.tell("close", {})
                return True
            return super().eventFilter(watched, event)

        def _qss(self):
            return initial["stylesheet"]

        def _run_simulation(self, cfg):
            client.tell("launch", {"config": cfg})
            return {"status": "queued", "reason": "Core is checking the requested local simulation.", "dispatched": False}

        def _stop_simulation(self):
            client.tell("stop", {})

        def _cancel_simulation_launch(self):
            client.tell("cancel", {})

        def response_readiness(self, require_process):
            client.tell("readiness", {"require_process": bool(require_process)})
            return dict(self.readiness)

        def device_service(self):
            return self._device_proxy

        def history(self, operation, name):
            if operation == "list":
                data = client.call("history-list", {})
                return HistoryListing([tuple(row) for row in data["rows"]], limited=data["limited"])
            return client.call("history-read", {"name": name})

        @Slot(str, object)
        def receive(self, kind, payload):
            if kind == "narration":
                self._shark_narration.emit(payload["text"])
            elif kind == "readiness-result":
                self.readiness = payload
                # Render cached state without immediately issuing another RPC.
                self.console._apply_response_readiness(payload)
            elif kind == "show":
                self.console.showNormal()
                self.console.raise_()
                self.console.activateWindow()
            elif kind == "select-tab":
                names = {"run": "Run", "device-lab": "Device Security Lab", "history": "History", "github-tools": "GitHub Tools"}
                expected = names.get(payload.get("tab"))
                if expected:
                    for index in range(self.console._tabs.count()):
                        if expected in self.console._tabs.tabText(index):
                            self.console._tabs.setCurrentIndex(index)
                            break
            elif kind == "close-ready":
                self._close_ready = True
                self.console.close()
                QApplication.instance().quit()
            elif kind == "channel-ended":
                # Core channel loss is not protection or cancellation proof.
                self.console.live_status.setText("Core channel ended; simulation status is unavailable.")
                self.console.launch_btn.setEnabled(False)
                self._close_ready = True
                QTimer.singleShot(0, QApplication.instance().quit)
            elif kind == "display":
                self._display(payload)
            elif kind == "report":
                view = QDialog(self.console)
                view.setWindowTitle("Angerona Red Team — After-Action Report")
                layout = QVBoxLayout(view)
                text = QPlainTextEdit()
                text.setReadOnly(True)
                text.setPlainText(payload["text"])
                layout.addWidget(text)
                close = QPushButton("Close")
                close.clicked.connect(view.close)
                layout.addWidget(close)
                configure_work_window(view)
                view.resize(920, 700)
                self._views.append(view)
                view.show()

        def _display(self, payload):
            event, values = payload.get("event"), payload.get("values")
            if type(values) is not list:
                raise ToolProtocolError("Core display projection schema unavailable")
            # Deliberately fixed methods, never getattr/eval/pickle dispatch.
            if event == "launch-status":
                self.console.set_launch_status(*values)
            elif event == "bind-session":
                self.console.bind_performance_session(*values)
            elif event == "session-lifecycle":
                from angerona.gui.red_team_console import SessionLifecycleProjection
                data = dict(values[0])
                data["plans_by_run"] = tuple(tuple(row) for row in data["plans_by_run"])
                self.console.record_session_lifecycle(SessionLifecycleProjection(**data))
            elif event == "performance":
                from angerona.shark.simulation_session import RunPerformanceSnapshot
                data = dict(values[0])
                data["producer_generations"] = tuple(tuple(row) for row in data["producer_generations"])
                self.console.record_performance_snapshot(RunPerformanceSnapshot(**data))
            elif event == "execution":
                self.console.update_execution_progress(*values)
            elif event == "render-progress":
                self.console._render_execution_progress()
            elif event == "verified-report":
                kind, run_id, report, error = values
                self.console.record_verified_report(kind, run_id, report, error=error)
            elif event == "cleanup-failure":
                self.console.record_cleanup_failure(*values)
            elif event == "finish":
                self.console.finish_run()
            elif event == "button-enabled":
                self.console.launch_btn.setEnabled(values[0])
            elif event == "flag":
                name, value = values
                if name == "run-pending":
                    self.console._run_pending = value
                elif name == "run-cancelled":
                    self.console._run_cancelled = value
                else:
                    raise ToolProtocolError("Unsupported Core display flag")
                self.console._render_execution_progress()
            else:
                raise ToolProtocolError("Unsupported Core display projection")

    application = QApplication.instance() or QApplication(["Angerona Red Team"])
    application.setQuitOnLastWindowClosed(False)
    # Constructor history/device readers may request Core data. Start transport
    # first and retain early public updates until the host signal is connected.
    buffered = queue.Queue(maxsize=64)
    delivery_lock = threading.Lock()
    destination = [None]
    def deliver(kind, payload):
        with delivery_lock:
            if destination[0] is None:
                buffered.put_nowait((kind, payload))
            else:
                destination[0](kind, payload)
    client.deliver = deliver
    client.start()
    host = Host()
    with delivery_lock:
        destination[0] = host.incoming.emit
        while not buffered.empty():
            kind, payload = buffered.get_nowait()
            host.incoming.emit(kind, payload)
    try:
        return application.exec()
    finally:
        client.stop.set()
        for thread in (client.writer, client.reader):
            if thread is not None and thread is not threading.current_thread():
                thread.join(3)


def worker_main():
    """Reserved entry called before ordinary Config, sensors or Core startup."""
    started = time.monotonic()
    phase = "stdio"
    source = sink = None
    source_fd = sink_fd = None
    descriptor_channel = None
    result = 2
    close_held = False
    try:
        emit_startup_observation(phase, "started", started)
        source_fd = os.dup(0)
        source = os.fdopen(source_fd, "rb", buffering=0, closefd=False)
        sink_fd = os.dup(1)
        sink = os.fdopen(sink_fd, "wb", buffering=0, closefd=False)
        # Imported UI/Qt libraries must not write into the protocol channel.
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, 1)
        finally:
            os.close(null)
        emit_startup_observation(phase, "completed", started)
        phase = "bootstrap"
        emit_startup_observation(phase, "started", started)
        initial = parse_bootstrap(_receive(source, 4096))
        deadline = initial["startup_deadline_ns"] / 1_000_000_000
        remaining = deadline - time.monotonic()
        if not math.isfinite(remaining) or not 0 < remaining <= VERIFICATION_SECONDS:
            raise ToolProtocolError("Original source verification deadline expired or differs")
        emit_startup_observation(phase, "completed", started)
        phase = "parent-binding"
        emit_startup_observation(phase, "started", started)
        binding_fields = {key: initial[key] for key in ("parent_pid", "parent_birth", "wrapper_pid", "wrapper_birth")}
        _arm_parent_lifetime(binding_fields)
        emit_startup_observation(phase, "completed", started)
        if not getattr(sys, "frozen", False):
            from angerona.resilience.source_guard import SourceGuard
            phase = "source-seal"
            emit_startup_observation(phase, "started", started)
            expected = os.environ.get("ANGERONA_PEER_SOURCE_DIGEST")
            if type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ToolProtocolError("Parent source seal is required for the tool child")
            SourceGuard.capture(Path(__file__).absolute().parents[3], expected_digest=expected, deadline=deadline)
            emit_startup_observation(phase, "completed", started)
        if initial["fd_channel"] is not None:
            if os.name == "nt":
                raise ToolProtocolError("Unix descriptor channel on Windows")
            descriptor_channel = socket.socket(fileno=initial["fd_channel"])
            if descriptor_channel.family != socket.AF_UNIX or descriptor_channel.type != socket.SOCK_STREAM:
                raise ToolProtocolError("Inherited descriptor channel type differs")
            descriptor_channel.set_inheritable(False)
        binding = ToolBinding(initial["session"], **binding_fields, child_pid=os.getpid(), child_birth=_own_birth())
        key = bytes.fromhex(initial["key"])
        phase = "hello"
        emit_startup_observation(phase, "started", started)
        _send(sink, seal_hello(binding, key), 4096)
        emit_startup_observation(phase, "completed", started)
        def parent_current():
            try:
                return _birth_of(binding.parent_pid) == binding.parent_birth
            except (OSError, RuntimeError, ValueError):
                return False
        channel = ToolChannel(source, sink, binding, key, side="child", alive=parent_current)
        phase = "initialize"
        emit_startup_observation(phase, "started", started)
        first = channel.receive()
        if first["kind"] != "initialize" or first["reply_to"]:
            raise ToolProtocolError("Core initialization must precede tool UI")
        emit_startup_observation(phase, "completed", started)
        client = ToolClient(channel, descriptor_channel, lambda _kind, _payload: None)
        client.startup_started_at = started
        phase = "qt-ui"
        result = _run_qt(client, first["payload"])
    except Exception as error:
        emit_startup_observation(phase, "failed", started, error)
    finally:
        for stream in (source, sink):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    close_held = True
        # closefd=False keeps constructor/stream cleanup from ambiguously
        # consuming these owned numeric descriptors. Each is attempted once.
        for descriptor in (source_fd, sink_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    close_held = True
        if descriptor_channel:
            try:
                descriptor_channel.close()
            except OSError:
                close_held = True
    return 2 if close_held else result
