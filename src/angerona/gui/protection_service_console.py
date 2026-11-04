"""Read-only desktop status for the separately installed protection service.

This console never constructs a sensor graph or opens service storage.
Service status belongs to one retained background reader. An explicit
administrator startup request has its own retained helper process.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
import time
import sys

from PySide6.QtCore import QProcess, QProcessEnvironment, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QMainWindow,
    QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from angerona.core.engine_service_status import EngineServiceStatusClient, MAX_MODULES
from angerona.core.startup_protocol import notify_dashboard_ready


STALE_SECONDS = 10.0
_RETIREMENT_HOLD = None


def _hold_reader(reader):
    global _RETIREMENT_HOLD

    if _RETIREMENT_HOLD is not reader:
        reader._preceding_retirement_owner = _RETIREMENT_HOLD
        _RETIREMENT_HOLD = reader


@dataclass(frozen=True)
class StatusView:
    version: str
    state: str
    mode: str
    discovered: int
    sampled: int
    enabled: int
    running: int
    truncated: bool
    coverage_reason: str

    @classmethod
    def from_payload(cls, value):
        """Copy bounded presentation fields after the native client's proof."""
        if (type(value) is not dict or value.get("service") != "AngeronaProtection"
                or value.get("protection_verified") is not False
                or value.get("authority") != [] or value.get("mutating_operations") != []
                or value.get("event_text_available") is not False
                or value.get("storage_access_available") is not False
                or value.get("state") not in {"starting", "ready"}
                or value.get("mode") not in {"starting", "chill", "full"}):
            raise ValueError("Invalid read-only service status")
        for field, maximum in (("version", 32), ("coverage_reason", 160)):
            text = value.get(field)
            if (type(text) is not str or not 1 <= len(text) <= maximum
                    or any(ord(char) < 32 or ord(char) == 127 for char in text)):
                raise ValueError("Invalid bounded service presentation text")
        counts = value.get("modules")
        if (type(counts) is not dict or type(counts.get("truncated")) is not bool
                or any(type(counts.get(key)) is not int or not 0 <= counts[key] <= 100_000
                       for key in ("discovered", "sampled", "enabled", "running"))
                or not 0 <= counts["running"] <= counts["enabled"] <= counts["sampled"] <= MAX_MODULES
                or counts["sampled"] > counts["discovered"]):
            raise ValueError("Invalid bounded service module counts")
        return cls(value["version"], value["state"], value["mode"], counts["discovered"],
                   counts["sampled"], counts["enabled"], counts["running"], counts["truncated"],
                   value["coverage_reason"])


@dataclass(frozen=True)
class ReaderSnapshot:
    sequence: int = 0
    view: StatusView | None = None
    sampled_monotonic: float | None = None
    error: str = ""
    request_ticket: int = 0


class ServiceStatusReader:
    """One non-daemon reader and one coalesced pending request, no Qt access."""
    def __init__(self, *, client_factory=None, clock=time.monotonic):
        self._factory = client_factory or EngineServiceStatusClient
        self._clock = clock
        self._wake, self._stop, self._retired = threading.Event(), threading.Event(), threading.Event()
        self._snapshot = ReaderSnapshot()
        self._busy = False
        self._request_lock = threading.Lock()
        self._requested_ticket = 0
        self._cleanup_proven = True
        self._held_client = None
        self.thread: threading.Thread | None = None

    @property
    def snapshot(self):
        return self._snapshot

    @property
    def busy(self):
        return self._busy

    @property
    def retired(self):
        return self._retired.is_set()

    @property
    def cleanup_proven(self):
        return self._cleanup_proven

    def start(self):
        if self.thread is not None or self._stop.is_set() or _RETIREMENT_HOLD is not None:
            raise RuntimeError("Service status reader cannot be restarted")
        self.thread = threading.Thread(target=self._run, name="ProtectionServiceStatusReader", daemon=False)
        try:
            self.thread.start()
        except BaseException:
            self.request_detach()
            raise
        self.request()

    def request(self):
        return self.request_ticket() is not None

    def request_ticket(self):
        """Exact coalesced read intent; no service or native work on the caller."""
        with self._request_lock:
            if self._stop.is_set() or self._retired.is_set():
                return None
            self._requested_ticket += 1
            ticket = self._requested_ticket
            self._wake.set()
            return ticket

    def request_detach(self):
        # Cancels queued/future work. A native call already in progress keeps
        # its owner until it returns; observation timeouts never prove exit.
        self._stop.set()
        self._wake.set()
        if self.thread is None:
            self._retired.set()

    def wait_retired(self, timeout=0.0):
        if self.thread is None:
            return self._stop.is_set()
        try:
            self.thread.join(max(0.0, timeout))
        except RuntimeError:
            # A start failure is not evidence that a possibly admitted thread
            # has retired. Keep the owner and refuse a replacement.
            return False
        return self._retired.is_set() and not self.thread.is_alive() and self._cleanup_proven

    def _client_retired(self, client):
        try:
            proven = client.cleanup_proven is True
        except BaseException:
            proven = False
        if proven:
            return True
        if self._held_client is not client:
            self._held_client = client
            self._cleanup_proven = False
            previous = self._snapshot
            self._snapshot = ReaderSnapshot(previous.sequence + 1, previous.view, previous.sampled_monotonic,
                                            "NativeCleanupUnproven")
            self.request_detach()
            _hold_reader(self)
        return False

    def _run(self):
        client = None
        try:
            while not self._stop.is_set():
                self._wake.wait()
                self._wake.clear()
                if self._stop.is_set():
                    break
                self._busy = True
                with self._request_lock:
                    request_ticket = self._requested_ticket
                previous = self._snapshot
                try:
                    if client is None:
                        client = self._factory()
                    value = client.status()
                    if not self._client_retired(client):
                        break
                    view = StatusView.from_payload(value)
                    result = ReaderSnapshot(previous.sequence + 1, view, self._clock(), request_ticket=request_ticket)
                except Exception as error:
                    if client is not None and not self._client_retired(client):
                        break
                    # Never paint arbitrary native error text, local paths or
                    # imported content. Prior data remains explicitly stale.
                    result = ReaderSnapshot(previous.sequence + 1, previous.view, previous.sampled_monotonic,
                                            type(error).__name__[:64], request_ticket)
                finally:
                    self._busy = False
                if not self._stop.is_set():
                    self._snapshot = result
        except BaseException:
            previous = self._snapshot
            if not self._stop.is_set():
                self._snapshot = ReaderSnapshot(previous.sequence + 1, previous.view, previous.sampled_monotonic,
                                                "StatusReaderStopped")
        finally:
            if client is None or self._client_retired(client):
                client = None
            self._busy = False
            self._retired.set()


def _label(text=""):
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def _operator_elevation_available():
    """Check the presentation prerequisite without querying the package on Qt."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return False
    from angerona.core.windows_package_identity import (
        EXPECTED_PACKAGE_FAMILY_NAME, EXPECTED_PACKAGE_PUBLISHER_ID,
    )
    return bool(EXPECTED_PACKAGE_FAMILY_NAME and EXPECTED_PACKAGE_PUBLISHER_ID)


def _operator_elevation_launch():
    from angerona.core.privilege import operator_elevation_launch

    return operator_elevation_launch()


class ProtectionServiceConsole(QMainWindow):
    """Read-only service status and a separate, explicit startup request."""
    def __init__(self, *, reader=None, start_reader=True, clock=time.monotonic,
                 startup_endpoint=None):
        super().__init__()
        self.reader = reader or ServiceStatusReader()
        self._clock, self._closing = clock, False
        self._startup_endpoint = startup_endpoint
        self._startup_notice_scheduled = False
        self._startup_notice_thread = None
        self._elevation_process = None
        self.setWindowTitle("Angerona — Installed Service Status")
        self.setMinimumSize(360, 340)
        screen = QApplication.primaryScreen()
        width, height = (820, 600)
        if screen is not None:
            area = screen.availableGeometry()
            width, height = min(width, max(360, area.width() - 40)), min(height, max(340, area.height() - 40))
        self.resize(width, height)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.setCentralWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        from angerona.gui.action_progress import ActionActivities, ActionProgressView
        self._activities = ActionActivities(self)
        self._manual_activity = None
        self._manual_ticket = None
        self.progress_view = ActionProgressView(self._activities, self)
        layout.addWidget(self.progress_view)
        title = _label("Installed protection service")
        title.setStyleSheet("font-size: 21px; font-weight: 600")
        layout.addWidget(title)
        layout.addWidget(_label("Read-only status from the separately installed AngeronaProtection service. "
                                "Closing this console leaves that service running."))
        self.banner = _label("Connecting to the installed service. Coverage remains unverified.")
        self.banner.setStyleSheet("color: #b26b00; font-weight: 600; margin-top: 8px")
        layout.addWidget(self.banner)
        form = QFormLayout()
        self.version, self.lifecycle, self.mode = _label("Unavailable"), _label("Unavailable"), _label("Unavailable")
        form.addRow("Service version", self.version)
        form.addRow("Lifecycle", self.lifecycle)
        form.addRow("Runtime mode", self.mode)
        layout.addLayout(form)
        counts = QGridLayout()
        self.counts = {}
        for column, (key, title) in enumerate((("discovered", "Discovered"), ("sampled", "Sampled"),
                                               ("enabled", "Enabled"), ("running", "Running"))):
            counts.addWidget(_label(title), 0, column)
            label = _label("—")
            label.setStyleSheet("font-size: 20px; font-weight: 600")
            counts.addWidget(label, 1, column)
            self.counts[key] = label
        layout.addLayout(counts)
        self.scope = _label("Module counts are unavailable. Running counts do not establish detector coverage.")
        layout.addWidget(self.scope)
        self.coverage = _label("Coverage unverified. This console cannot inspect events, files, keys or response policy.")
        layout.addWidget(self.coverage)
        self.age = _label("No successful service status has been received.")
        layout.addWidget(self.age)
        layout.addWidget(self._elevation_settings())
        layout.addStretch()
        layout.addWidget(_label("Status polling reports service gaps. The administrator setting "
                                "starts a separate dashboard only after Windows approval."))
        actions = QHBoxLayout()
        self.refresh = QPushButton("Refresh status")
        self.refresh.clicked.connect(lambda: self._request(manual=True))
        actions.addWidget(self.refresh)
        actions.addStretch()
        self.detach = QPushButton("Close console")
        self.detach.clicked.connect(self.close)
        actions.addWidget(self.detach)
        layout.addLayout(actions)
        self._last_request = self._clock()
        self.timer = QTimer(self)
        self.timer.setInterval(200)
        self.timer.timeout.connect(self._tick)
        self.timer.start()
        if start_reader:
            self.reader.start()

    def _elevation_settings(self):
        from angerona.core.privilege import OPERATOR_ELEVATION_WARNING

        settings = QGroupBox("Settings")
        layout = QVBoxLayout(settings)
        self.elevation_toggle = QCheckBox("Run Angerona with administrator privileges")
        self.elevation_toggle.setChecked(False)
        self.elevation_toggle.setEnabled(_operator_elevation_available())
        self.elevation_toggle.clicked.connect(self._request_operator_elevation)
        layout.addWidget(self.elevation_toggle)
        self.elevation_warning = _label(OPERATOR_ELEVATION_WARNING)
        layout.addWidget(self.elevation_warning)
        self.elevation_status = _label(
            "Administrator startup is held. An independently signed and approved "
            "Windows package is required." if not self.elevation_toggle.isEnabled() else
            "Administrator startup is off."
        )
        layout.addWidget(self.elevation_status)
        return settings

    def _request_operator_elevation(self, checked):
        if (not checked or self._closing or not self.elevation_toggle.isEnabled()
                or self._elevation_process is not None):
            return
        self.elevation_toggle.setEnabled(False)
        try:
            executable, environment = _operator_elevation_launch()
            if (not isinstance(executable, Path) or not executable.is_absolute()
                    or executable.name.casefold() != "angeronastartup.exe"
                    or type(environment) is not dict
                    or any(type(key) is not str or type(value) is not str
                           for key, value in environment.items())):
                raise ValueError("Invalid verified startup launch specification")
        except Exception:
            self.elevation_toggle.setChecked(False)
            self.elevation_status.setText("Administrator startup is held. Package launch authority could not be verified.")
            return

        child_environment = QProcessEnvironment()
        for name, value in environment.items():
            child_environment.insert(name, value)
        process = QProcess(self)
        process.setProcessEnvironment(child_environment)
        process.setProgram(str(executable))
        process.setArguments(["--operator-elevation"])
        process.setWorkingDirectory(str(executable.parent))
        process.setStandardInputFile(QProcess.nullDevice())
        process.setStandardOutputFile(QProcess.nullDevice())
        process.setStandardErrorFile(QProcess.nullDevice())
        process.errorOccurred.connect(lambda error: self._elevation_error(process, error))
        process.finished.connect(lambda code, status: self._elevation_finished(process, code, status))
        self._elevation_process = process
        self.elevation_status.setText("Waiting for Windows consent and administrator dashboard readiness…")
        try:
            process.start()
        except Exception:
            if self._release_elevation_process(process):
                self.elevation_status.setText("Administrator startup could not be verified.")
            else:
                self.elevation_status.setText("Waiting for the startup helper to retire.")

    def _elevation_error(self, process, error):
        if error != QProcess.ProcessError.FailedToStart:
            return
        if self._release_elevation_process(process):
            self.elevation_status.setText("The verified startup helper could not start.")
            self.elevation_toggle.setEnabled(not self._closing)

    def _release_elevation_process(self, process):
        if (self._elevation_process is not process
                or process.state() != QProcess.ProcessState.NotRunning):
            return False
        self._elevation_process = None
        process.deleteLater()
        self.elevation_toggle.setChecked(False)
        return True

    def _elevation_finished(self, process, code, status):
        if not self._release_elevation_process(process):
            return
        if status == QProcess.ExitStatus.NormalExit and code == 0:
            self.elevation_status.setText("Administrator dashboard readiness verified. Closing this console…")
            self.close()
        else:
            self.elevation_status.setText(
                "Administrator dashboard readiness was not verified. This console remains available."
            )

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._startup_endpoint is not None and not self._startup_notice_scheduled:
            self._startup_notice_scheduled = True
            QTimer.singleShot(0, self._publish_startup_ready)

    def _publish_startup_ready(self):
        self._startup_notice_scheduled = False
        if self._closing or not self.isVisible() or self.isMinimized():
            return
        endpoint = self._startup_endpoint
        if endpoint is None:
            return
        self._startup_endpoint = None
        notifier = threading.Thread(
            target=notify_dashboard_ready, args=(endpoint,),
            name="ProtectionConsoleReadyNotifier", daemon=True,
        )
        self._startup_notice_thread = notifier
        try:
            notifier.start()
        except RuntimeError:
            # The startup listener retains its own bounded readiness deadline.
            return

    def _pending_window_work(self):
        return self._elevation_process is not None or (
            self._startup_notice_thread is not None and self._startup_notice_thread.is_alive()
        )

    def _request(self, *, manual=False):
        if self._closing:
            return
        if manual and callable(getattr(self.reader, "request_ticket", None)):
            ticket = self.reader.request_ticket()
            if ticket is not None:
                self._manual_ticket = ticket
                self._manual_activity = self._activities.begin("service-status", "Refreshing authenticated service status…")
                self._last_request = self._clock()
        elif self.reader.request():
            self._last_request = self._clock()

    def _tick(self):
        if self._closing:
            if self.reader.wait_retired() and not self._pending_window_work():
                self.close()
            elif not self.reader.cleanup_proven:
                self.banner.setText("Client native cleanup remains unverified. This console retains its owner; "
                                    "the protection service is unchanged.")
            return
        now = self._clock()
        if now - self._last_request >= 2.0:
            self._request()
        result = self.reader.snapshot
        if (self._manual_activity is not None and
                (getattr(result, "request_ticket", 0) >= self._manual_ticket
                 or not self.reader.cleanup_proven or getattr(self.reader, "retired", False))):
            self._activities.finish(self._manual_activity)
            self._manual_activity = None
            self._manual_ticket = None
        if result.view is not None:
            view = result.view
            self.version.setText(view.version)
            self.lifecycle.setText(view.state.capitalize())
            self.mode.setText(view.mode.capitalize())
            for key, label in self.counts.items():
                label.setText(str(getattr(view, key)))
            self.scope.setText(("Partial module sample. " if view.truncated else "Module progress sample. ")
                               + "Running counts do not establish detector coverage.")
            self.coverage.setText("Coverage unverified. " + view.coverage_reason)
        if result.sampled_monotonic is None:
            self.age.setText("No successful service status has been received.")
        else:
            age = max(0.0, now - result.sampled_monotonic)
            self.age.setText(f"Last successful status: {age:.1f} seconds ago."
                             + (" Previous data is stale." if result.error or age > STALE_SECONDS else ""))
        if result.error:
            self.banner.setText("Service unavailable or identity not verified. Coverage remains unverified. "
                                + "Status reader: " + result.error)
        elif result.sampled_monotonic is None:
            self.banner.setText("Connecting to the installed service. Coverage remains unverified.")
        elif now - result.sampled_monotonic > STALE_SECONDS:
            self.banner.setText("Service status is stale. Coverage remains unverified.")
        else:
            self.banner.setText("Service status received. Detector coverage remains unverified.")
        if not self.reader.cleanup_proven:
            self.refresh.setEnabled(False)

    def closeEvent(self, event):
        self._activities.close()
        self._closing = True
        self.reader.request_detach()
        self.refresh.setEnabled(False)
        self.elevation_toggle.setEnabled(False)
        if self._pending_window_work():
            self.banner.setText("Waiting for the current startup request to retire before closing.")
            self.detach.setEnabled(False)
            event.ignore()
        elif self.reader.wait_retired():
            self.timer.stop()
            event.accept()
        else:
            self.banner.setText("Client native cleanup remains unverified. This console retains its owner; "
                                "the protection service is unchanged." if not self.reader.cleanup_proven else
                                "Disconnecting console. Waiting for its current status read to retire; "
                                "the protection service is unchanged.")
            self.detach.setText("Cleanup needs attention" if not self.reader.cleanup_proven else "Disconnecting…")
            self.detach.setEnabled(False)
            event.ignore()


def run_console(*, startup_endpoint=None):
    """Called only after the main entry's ordinary-user client admission."""
    if _RETIREMENT_HOLD is not None:
        raise RuntimeError("A previous service status reader still owns its retirement")
    app = QApplication([])
    app.setApplicationName("Angerona Installed Service Status")
    app.setQuitOnLastWindowClosed(True)
    window = ProtectionServiceConsole(start_reader=False, startup_endpoint=startup_endpoint)
    app.aboutToQuit.connect(window.reader.request_detach)
    try:
        window.show()
        window.reader.start()
        return app.exec()
    finally:
        window.reader.request_detach()
        if window._pending_window_work():
            # Retain both Qt owners if an external event-loop exit bypasses closeEvent.
            window._retained_application = app
            _hold_reader(window)
            raise RuntimeError("Service console startup work retirement remains unproven")
        if not window.reader.wait_retired():
            # Normal window close waits visibly. An external event-loop exit
            # must still retain the exact reader and must not report clean exit.
            _hold_reader(window.reader)
            print("[Angerona] Service console reader retirement remains pending; "
                  "the protection service was not stopped.", file=sys.stderr, flush=True)
            raise RuntimeError("Service console reader retirement remains unproven")
