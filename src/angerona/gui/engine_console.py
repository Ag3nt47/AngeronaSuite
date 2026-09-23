"""Detachable desktop view; all sensing and response stay in the engine."""
from __future__ import annotations

from collections import deque
import queue
import threading
import time
import os

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.engine_transport import EngineError
from angerona.core.persistent_engine import EngineClient, ensure_engine


class ConsoleWorker:
    """One network worker; bounded queues and no blocking calls on the GUI."""

    def __init__(self):
        self.commands: queue.Queue = queue.Queue(maxsize=8)
        self.frames: queue.Queue = queue.Queue(maxsize=4)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="EngineConsoleClient", daemon=True)
        self.client = None
        self.cursor = -1
        self.instance = ""
        self.pending: deque[str] = deque(maxlen=16)
        self.dropped_frames = 0

    def start(self):
        self.commands.put_nowait(("connect", None))
        self.thread.start()

    def submit(self, operation, value=None):
        try:
            self.commands.put_nowait((operation, value))
            return True
        except queue.Full:
            return False

    def _post(self, frame):
        if self.frames.full():
            try:
                self.frames.get_nowait()
            except queue.Empty:
                pass
            self.dropped_frames += 1
        frame["dropped_frames"] = self.dropped_frames
        self.frames.put_nowait(frame)

    def _command(self, operation, value):
        if operation == "connect":
            self.client = ensure_engine()
            return None
        if self.client is None:
            raise EngineError("Protection engine is disconnected")
        if operation == "chill":
            return self.client.set_chill(value)
        if operation == "enable":
            return self.client.set_module(value[0], value[1])
        if operation == "restart":
            return self.client.restart_module(value)
        if operation == "selftest":
            return self.client.self_test(value)
        if operation == "retention":
            return self.client.patch_settings(value)
        if operation == "stop":
            return self.client.stop_engine(confirmation="stop-protection")
        raise EngineError("Unknown console command")

    def run(self):
        while not self.stop.is_set():
            message = ""
            try:
                try:
                    operation, value = self.commands.get_nowait()
                    result = self._command(operation, value)
                    if result is not None:
                        self.pending.append(result["id"])
                        message = "Operation queued"
                except queue.Empty:
                    pass
                if self.client is None:
                    self.stop.wait(1.0)
                    continue
                status = self.client.status()
                if status["instance"] != self.instance:
                    self.cursor = -1
                    self.instance = status["instance"]
                    self.pending.clear()
                events = self.client.events(self.cursor)
                self.cursor = events["cursor"]
                if self.pending:
                    identity = self.pending.popleft()
                    progress = self.client.operation_status(identity)
                    if progress["state"] in {"queued", "running"}:
                        self.pending.append(identity)
                    message = f"{progress['operation']}: {progress['state']}"
                    if "result" in progress:
                        message += " — " + str(progress["result"])[:500]
                self._post({"status": status, "events": events, "message": message})
            except (EngineError, OSError) as exc:
                self._post({"error": str(exc), "message": message})
            except Exception as exc:
                self._post({"error": "Console connection failed: " + type(exc).__name__})
            self.stop.wait(2.0)

    def detach(self):
        # No authenticated stop request and no process termination. The
        # bounded in-flight socket exchange may finish after the window closes.
        self.stop.set()


class EngineConsole(QMainWindow):
    def __init__(self, *, start_worker: bool = True):
        super().__init__()
        self.setWindowTitle("Angerona — Protection Console")
        self.resize(1160, 820)
        self.worker = ConsoleWorker()
        self._rows = {}
        self._ready = False
        self._settings_instance = ""
        self.runtime_metrics = None
        self.metrics_publisher = None
        if os.environ.get("ANGERONA_RUNTIME_METRICS") == "1":
            from angerona.core.runtime_metrics import RuntimeMetrics, optional_publisher
            from angerona.core.data_paths import data_dir
            self.runtime_metrics = RuntimeMetrics(gui=True, extra_queues={
                "console_display": lambda: {"depth": self.worker.frames.qsize(), "capacity": 4,
                                           "dropped": self.worker.dropped_frames},
                "console_commands": lambda: {"depth": self.worker.commands.qsize(), "capacity": 8,
                                            "dropped": 0},
            })
            self.metrics_publisher = optional_publisher(self.runtime_metrics, data_dir())
        container = QWidget()
        self.setCentralWidget(container)
        layout = QVBoxLayout(container)
        title = QLabel("Angerona protection engine")
        title.setStyleSheet("font-size: 24px; font-weight: 600; margin-bottom: 8px")
        layout.addWidget(title)
        layout.addWidget(QLabel("Protection runs in its own process. Closing this window leaves it running."))
        self.banner = QLabel("Connecting to protection…")
        self.banner.setWordWrap(True)
        layout.addWidget(self.banner)
        self.response = QLabel()
        self.response.setWordWrap(True)
        layout.addWidget(self.response)
        controls = QHBoxLayout()
        self.connect_button = QPushButton("Start / reconnect")
        self.connect_button.clicked.connect(lambda: self._submit("connect"))
        controls.addWidget(self.connect_button)
        self.chill = QCheckBox("Chill mode")
        self.chill.clicked.connect(lambda checked: self._submit("chill", checked))
        controls.addWidget(self.chill)
        controls.addStretch()
        stop = QPushButton("Stop protection…")
        stop.clicked.connect(self._stop_protection)
        controls.addWidget(stop)
        layout.addLayout(controls)
        retention_controls = QHBoxLayout()
        self.retention_enabled = QCheckBox("Clean old alert files")
        self.retention_enabled.setChecked(True)
        self.retention_days = QSpinBox()
        self.retention_days.setRange(1, 3650)
        self.retention_days.setSuffix(" days")
        self.retention_days.setValue(30)
        self.retention_limit = QSpinBox()
        self.retention_limit.setRange(8, 16384)
        self.retention_limit.setSuffix(" MiB")
        self.retention_limit.setValue(256)
        retention_controls.addWidget(self.retention_enabled)
        retention_controls.addWidget(self.retention_days)
        retention_controls.addWidget(self.retention_limit)
        retention_save = QPushButton("Save alert limits")
        retention_save.clicked.connect(lambda: self._submit("retention", {
            "alert_retention_enabled": self.retention_enabled.isChecked(),
            "alert_retention_days": self.retention_days.value(),
            "alert_retention_max_mib": self.retention_limit.value(),
        }))
        retention_controls.addWidget(retention_save)
        retention_controls.addStretch()
        layout.addLayout(retention_controls)
        self.modules = QTableWidget(0, 6)
        self.modules.setHorizontalHeaderLabels(["Module", "State", "Health", "Mode", "Availability", "Reason"])
        self.modules.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.modules.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.modules.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.modules.horizontalHeader().setStretchLastSection(True)
        self.modules.setColumnWidth(0, 250)
        self.modules.setColumnWidth(4, 130)
        layout.addWidget(self.modules, 3)
        module_controls = QHBoxLayout()
        self.buttons = []
        for label, operation in (("Enable", "enable"), ("Disable", "disable"),
                                 ("Restart", "restart"), ("Self-test", "selftest")):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, op=operation: self._module_command(op))
            module_controls.addWidget(button)
            self.buttons.append(button)
        module_controls.addStretch()
        layout.addLayout(module_controls)
        self.progress = QLabel("Live events")
        self.progress.setWordWrap(True)
        layout.addWidget(self.progress)
        self.events = QPlainTextEdit()
        self.events.setReadOnly(True)
        self.events.setMaximumBlockCount(1000)
        layout.addWidget(self.events, 2)
        footer = QLabel("Source installs provide ordinary-user coverage. Unavailable or unconfigured modules are excluded from the active count. "
                        "For advanced configuration, stop this engine before reopening the full Angerona interface.")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self._drain)
        self.timer.start()
        self._set_controls(False)
        if start_worker:
            self.worker.start()

    def _set_controls(self, ready):
        self._ready = ready
        self.chill.setEnabled(ready)
        for button in self.buttons:
            button.setEnabled(ready)

    def _submit(self, operation, value=None):
        if not self.worker.submit(operation, value):
            self.progress.setText("Control queue is busy. Wait for the current operation.")
        else:
            self.progress.setText("Request queued…")

    def _module_command(self, operation):
        row = self.modules.currentRow()
        if row < 0:
            self.progress.setText("Select a module first.")
            return
        name = self.modules.item(row, 0).text()
        if operation in {"enable", "disable"}:
            self._submit("enable", (name, operation == "enable"))
        else:
            self._submit(operation, name)

    def _stop_protection(self):
        result = QMessageBox.question(self, "Stop Angerona protection?",
                                      "This stops the protection engine and its monitoring. "
                                      "Closing this window alone keeps protection running.\n\nStop protection?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        if result == QMessageBox.StandardButton.Yes:
            self._submit("stop")

    def _drain(self):
        started = time.perf_counter()
        if self.runtime_metrics is not None:
            self.runtime_metrics.heartbeat(expected_seconds=0.5)
        while True:
            try:
                frame = self.worker.frames.get_nowait()
            except queue.Empty:
                break
            self.render_frame(frame)
        if self.runtime_metrics is not None:
            self.runtime_metrics.record_tick((time.perf_counter() - started) * 1000)

    def render_frame(self, frame):
        if "error" in frame:
            self.banner.setText("Protection status unknown — " + frame["error"])
            self.banner.setStyleSheet("color: #d97d22; font-weight: 600")
            self._set_controls(False)
            return
        status = frame["status"]
        self.banner.setText(f"Engine: {status['state']} · {status['mode']} · {status['enabled_count']} enabled modules · "
                            f"PID {status['pid']}\n{status['reason']}")
        self.banner.setStyleSheet("font-weight: 600")
        self._set_controls(status["state"] == "ready")
        if self._settings_instance != status["instance"] and status.get("settings"):
            settings = status["settings"]
            self.retention_enabled.setChecked(settings.get("alert_retention_enabled", True))
            self.retention_days.setValue(settings.get("alert_retention_days", 30))
            self.retention_limit.setValue(settings.get("alert_retention_max_mib", 256))
            self._settings_instance = status["instance"]
        self.chill.blockSignals(True)
        self.chill.setChecked(status["mode"] == "Chill")
        self.chill.blockSignals(False)
        response = status.get("response", {})
        self.response.setText("Automatic defense: " + str(response.get("state", "unknown")) +
                              " — " + str(response.get("reason", "")) +
                              ". Ollama is optional.")
        selected = None
        if self.modules.currentRow() >= 0:
            selected = self.modules.item(self.modules.currentRow(), 0).text()
        rows = status["modules"]
        self.modules.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = [row["name"], "Chill paused" if row["paused"] else row["status"],
                      f"{row['health']}%", row["mode"], row["usage"], row["health_note"] or row["reason"]]
            for column, value in enumerate(values):
                item = self.modules.item(index, column)
                if item is None:
                    item = QTableWidgetItem()
                    self.modules.setItem(index, column, item)
                item.setText(value)
                item.setToolTip(value)
            if row["name"] == selected:
                self.modules.selectRow(index)
        events = frame.get("events", {})
        if events.get("overflow"):
            self.events.appendPlainText("[Console] Event cursor exceeded retained history; a gap was reported by the engine.")
        for event in events.get("events", []):
            suffix = " [message shortened]" if event.get("message_truncated") else ""
            self.events.appendPlainText(f"[{event['severity']}] {event['module']}: {event['message']}" + suffix)
        if frame.get("message"):
            self.progress.setText(frame["message"])
        if frame.get("dropped_frames"):
            self.progress.setText((frame.get("message", "") + " " +
                f"Console skipped {frame['dropped_frames']} display batches; some events are omitted here. "
                "Engine protection continues.").strip())

    def closeEvent(self, event):
        self.timer.stop()
        self.worker.detach()
        if self.metrics_publisher is not None:
            self.metrics_publisher.stop()
        super().closeEvent(event)
