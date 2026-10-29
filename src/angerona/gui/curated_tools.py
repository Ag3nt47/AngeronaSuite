"""Shared, asynchronous presentation of maintained third-party scanner adapters."""
from __future__ import annotations

import copy
import contextlib
import importlib
import json
import queue
import threading
import time
import uuid
from urllib.parse import urlsplit

from PySide6.QtCore import QObject, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QTabWidget, QToolButton,
    QVBoxLayout, QWidget,
)
from shiboken6 import isValid

_PROJECT = "https://github.com/interplains/Zero-Breach-Toolkit"
_RELEASE = _PROJECT + "/releases/tag/v0.1.10"
_SETTINGS = {
    "github_tools_enabled": ("Enable curated scanners", True),
    "github_tools_auto_prepare": ("Prepare the pinned scanner after dashboard startup", True),
    "github_tools_allow_download": ("Allow verified downloads for missing scanner files", True),
    "spyware_scan_native_enabled": ("Include native SpywareGuard in Spyware Scan", True),
    "spyware_scan_zero_breach_enabled": ("Include Zero-Breach in Spyware Scan", True),
    "spyware_scan_verify_admin": ("Verify current privilege coverage before Spyware Scan", True),
    "breach_auto_isolate_enabled": ("Automatically request network lockdown for confirmed breaches", True),
}
_LIMITS = {
    "github_tools_job_limit_mib": ("Working data per job (MiB)", 256, 64, 1024),
    "github_tools_report_limit_mib": ("Retained reports (MiB)", 64, 8, 256),
    "github_tools_timeout_seconds": ("Scan deadline (seconds)", 300, 30, 900),
    "spyware_scan_cpu_percent": ("Scanner CPU ceiling (%)", 70, 10, 90),
    "spyware_scan_memory_mib": ("Scanner memory ceiling (MiB)", 512, 128, 2048),
    "spyware_scan_background_percent": ("Routine background pace during scan (%)", 10, 5, 50),
}


def _backend():
    return importlib.import_module("angerona.core.curated_tools")


def _label(text=""):
    result = QLabel(text)
    result.setWordWrap(True)
    result.setTextFormat(Qt.TextFormat.PlainText)
    result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return result


def _literal(value, limit=32768):
    if type(value) in (dict, list, tuple):
        try:
            value = json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return "Unsupported external result data."
    return str(value if value is not None else "").replace("\x00", "")[:limit]


def _config(manager):
    candidate = getattr(manager, "cfg", None)
    return candidate if candidate is not None else getattr(manager, "config", None)


def _open_link(url):
    # Links come from the maintained catalog or validated source-library names.
    if type(url) is not str or len(url) > 512:
        return
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return
    if (parsed.scheme != "https" or parsed.username or parsed.password or port
            or parsed.hostname not in {"github.com", "archivegenocide.com",
                                       "creativecommons.org", "spdx.org", "learn.microsoft.com",
                                       "raw.githubusercontent.com", "malpedia.caad.fkie.fraunhofer.de"}):
        return
    QDesktopServices.openUrl(QUrl(url))


class CuratedToolsController(QObject):
    """One worker permit and copied publications for every view of the tools."""

    status_changed = Signal(dict)
    credits_ready = Signal(object)
    settings_saved = Signal()

    def __init__(self, manager, parent=None, *, service_factory=None):
        super().__init__(parent)
        self.manager = manager
        self._factory = service_factory
        self._service = None
        self._busy = False
        self._closed = False
        self._auto_started = False
        self._operation = None
        self._worker = None
        self._pending_priority = None
        self._native_priority_module = None
        self._native_request_id = ""
        self._focus_lease = None
        self._focus_renewed_at = 0.0
        self._cancel_requested = threading.Event()
        self._done = threading.Event()
        self._done.set()
        self._frames = queue.Queue(maxsize=32)
        self._snapshot = dict(state="not_loaded", message="Ready to check the pinned scanner.",
                              installed=False, verified=False, version="0.1.10", busy=False)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._drain)

    def snapshot(self):
        return copy.deepcopy(self._snapshot)

    def _publish(self, **values):
        self._snapshot.update(values)
        self._snapshot["busy"] = self._busy
        self.status_changed.emit(self.snapshot())

    def _frame(self, kind, value):
        try:
            self._frames.put_nowait((kind, value))
        except queue.Full:
            if kind != "progress":
                # Progress frames can be replaced; a final result must survive.
                try:
                    self._frames.get_nowait()
                except queue.Empty:
                    pass
                self._frames.put_nowait((kind, value))

    def _start(self, action, options=None):
        if self._closed or self._busy or (self._worker is not None and self._worker.is_alive()):
            return False
        cfg = _config(self.manager)
        if action in {"prepare", "scan", "priority_scan", "open_tool", "self_test"}:
            if (getattr(self.manager, "ugcap_paused", False)
                    or (action != "priority_scan" and not getattr(cfg, "github_tools_enabled", True))):
                self._publish(state="held", message="Curated scanners are disabled or the workspace is locked.")
                return False
        self._busy = True
        self._snapshot["active_action"] = action
        self._cancel_requested.clear()
        self._done.clear()
        self._publish(message={"status": "Checking scanner files…", "prepare": "Preparing the pinned scanner…",
                               "scan": "Starting the selected scan…", "self_test": "Checking the scanner adapter…",
                               "revert": "Reverting the managed scanner…", "open_tool": "Opening the advanced toolkit…",
                               "priority_scan": "Scheduling the selected spyware checks immediately…",
                               "settings": "Saving tool settings…", "credits": "Loading project credits…"}.get(action, "Working…"))
        self._timer.start()

        def work():
            operation = None
            try:
                backend = _backend()
                operation = backend.ToolOperation()
                self._operation = operation
                if self._cancel_requested.is_set():
                    operation.cancel()
                operation.check()
                if self._service is None:
                    factory = self._factory or backend.CuratedToolService
                    self._service = factory(cfg=cfg)
                service = self._service
                progress = lambda message: self._frame("progress", _literal(message, 1000))
                if action == "settings":
                    self._save_config(cfg, options or {})
                    result = service.status()
                elif action == "credits":
                    result = self._credits(backend)
                elif action == "scan":
                    result = service.scan(backend.ToolScanRequest(**(options or {})), operation, progress=progress)
                elif action == "priority_scan":
                    result = self._priority_work(backend, service, cfg, operation, options or {}, progress)
                elif action == "prepare":
                    result = service.prepare(operation, progress=progress,
                                             allow_download=bool(getattr(cfg, "github_tools_allow_download", True)))
                elif action == "revert":
                    self._save_config(cfg, {"github_tools_enabled": False, "github_tools_auto_prepare": False})
                    result = service.revert(operation, progress=progress)
                elif action in {"self_test", "open_tool", "clear_reports"}:
                    result = getattr(service, action)(operation, progress=progress)
                else:
                    result = service.status()
                self._frame("result", (action, result))
            except Exception as error:
                cancelled = self._cancel_requested.is_set()
                self._frame("error", dict(state="cancelled" if cancelled else "unavailable", verified=False,
                                          message="Operation cancelled; review partial coverage." if cancelled
                                          else f"Tool operation failed: {type(error).__name__}: {_literal(error, 700)}"))
            finally:
                self._operation = None
                self._done.set()

        try:
            self._worker = threading.Thread(target=work, name="AngeronaCuratedTools", daemon=True)
            self._worker.start()
        except Exception:
            self._busy = False
            self._done.set()
            self._publish(state="unavailable", message="The tool worker could not start.")
            return False
        return True

    def _priority_work(self, backend, service, cfg, operation, options, progress):
        request_id = uuid.uuid4().hex
        deadline = time.monotonic() + min(900, max(30, int(getattr(cfg, "github_tools_timeout_seconds", 300))))
        if hasattr(operation, "deadline"):
            operation.deadline = min(operation.deadline, deadline)
        native_enabled = bool(options.pop("native_enabled", getattr(cfg, "spyware_scan_native_enabled", True)))
        tool_enabled = bool(options.pop("zero_breach_enabled", getattr(cfg, "spyware_scan_zero_breach_enabled", True)))
        if not native_enabled and not tool_enabled:
            raise ValueError("Select at least one spyware scanner.")
        options.setdefault("priority", getattr(cfg, "spyware_scan_priority", "above-normal"))
        options.setdefault("max_cpu_percent", getattr(cfg, "spyware_scan_cpu_percent", 70))
        options.setdefault("max_memory_mib", getattr(cfg, "spyware_scan_memory_mib", 512))
        modules = getattr(self.manager, "modules", {})
        native = modules.get("SpywareGuard") if type(modules) is dict else None
        native_state = dict(state="disabled", coverage="Native scan not selected.")
        tool_result = dict(state="disabled", coverage="Zero-Breach not selected.")
        focus = getattr(self.manager, "priority_scan_focus", None)
        lease = focus(owner=request_id, background_percent=getattr(cfg, "spyware_scan_background_percent", 10)) if callable(focus) else contextlib.nullcontext()
        self._native_request_id = request_id
        try:
            with self._focus_scope(lease, request_id) as active_lease:
                self._focus_lease = active_lease
                self._focus_renewed_at = time.monotonic()
                if native_enabled:
                    if native is not None and callable(getattr(native, "request_priority_scan", None)):
                        try:
                            admitted = native.request_priority_scan(request_id)
                            if admitted:
                                self._native_priority_module = native
                                native_state = dict(state="queued", request_id=request_id)
                                progress("Native SpywareGuard scan scheduled; preparing selected toolkit checks.")
                            else:
                                native_state = dict(state="held", coverage="Native scanner could not admit this request.")
                        except Exception as error:
                            native_state = dict(state="failed", error=f"{type(error).__name__}: {_literal(error, 300)}")
                    else:
                        native_state = dict(state="unavailable", coverage="Native priority-scanning interface is unavailable.")
                operation.check()
                checked_status = None
                if getattr(cfg, "spyware_scan_verify_admin", True):
                    checked_status = service.status()
                    self._frame("metadata", {"admin_state": checked_status.get("admin_state", {"verified": False})})
                if tool_enabled:
                    if not getattr(cfg, "github_tools_enabled", True):
                        tool_result = dict(state="disabled", coverage="Curated scanner integrations are disabled in settings.")
                    else:
                        tool_status = checked_status or service.status()
                        if tool_status.get("execution_available") is False:
                            tool_result = dict(state="unavailable", coverage={"held": tool_status.get(
                                "execution_hold_reason", "An unprivileged scanner runtime is unavailable.")})
                        else:
                            if not tool_status.get("verified"):
                                service.prepare(operation, progress=progress,
                                                allow_download=bool(getattr(cfg, "github_tools_allow_download", True)))
                            tool_result = service.scan(backend.ToolScanRequest(**options), operation, progress=progress)
                if self._native_priority_module is not None:
                    while True:
                        operation.check()
                        native_state = native.priority_scan_snapshot()
                        if native_state.get("request_id") != request_id:
                            native_state = dict(state="incomplete", error="The native scan generation changed; its result was not accepted.")
                            break
                        if native_state.get("state") not in {"queued", "running"}:
                            break
                        if time.monotonic() >= deadline:
                            native.cancel_priority_scan(request_id)
                            native_state = dict(native_state, state="incomplete", error="Native scan exceeded its deadline.")
                            break
                        operation.cancelled.wait(.1)
            incomplete = native_state.get("state") in {"failed", "held", "unavailable", "incomplete", "cancelled"}
            incomplete = incomplete or tool_result.get("state") in {"failed", "unavailable", "incomplete", "cancelled", "disabled"} and tool_enabled
            return dict(state="incomplete" if incomplete else "completed",
                        message="Spyware scan finished. Review each scanner's findings and coverage.",
                        request_id=request_id, native=native_state, coverage={"native": native_state, "zero_breach": tool_result.get("coverage")},
                        findings=tool_result.get("findings", []), report=tool_result.get("report"),
                        details={"native": native_state, "zero_breach": tool_result})
        finally:
            self._native_priority_module = None
            self._native_request_id = ""
            self._focus_lease = None

    @contextlib.contextmanager
    def _focus_scope(self, lease, request_id):
        with lease as active:
            try:
                yield active
            finally:
                native = self._native_priority_module
                if native is not None:
                    try:
                        snapshot = native.priority_scan_snapshot()
                        if snapshot.get("request_id") == request_id and snapshot.get("state") in {"queued", "running"}:
                            native.cancel_priority_scan(request_id)
                            deadline = time.monotonic() + 2
                            while time.monotonic() < deadline:
                                snapshot = native.priority_scan_snapshot()
                                if (snapshot.get("request_id") != request_id
                                        or snapshot.get("state") not in {"queued", "running"}):
                                    break
                                time.sleep(.05)
                            self._frame("metadata", {"native_scan_completion": snapshot})
                    except Exception:
                        self._frame("metadata", {"native_scan_completion": {"state": "unavailable"}})

    @staticmethod
    def _save_config(cfg, options):
        if cfg is None:
            raise ValueError("Tool settings are unavailable.")
        values = {}
        for name in _SETTINGS:
            if name in options:
                if type(options[name]) is not bool:
                    raise ValueError("Invalid scanner setting.")
                values[name] = options[name]
        for name, (_title, _default, low, high) in _LIMITS.items():
            if name in options:
                if type(options[name]) is not int or not low <= options[name] <= high:
                    raise ValueError("Invalid scanner storage or deadline limit.")
                values[name] = options[name]
        if "spyware_scan_priority" in options:
            if options["spyware_scan_priority"] not in {"above-normal", "high"}:
                raise ValueError("Unsupported spyware scan priority.")
            values["spyware_scan_priority"] = options["spyware_scan_priority"]
        candidate = copy.deepcopy(cfg)
        for name, value in values.items():
            setattr(candidate, name, value)
        candidate.save()
        for name, value in values.items():
            setattr(cfg, name, value)

    @staticmethod
    def _credits(backend):
        rows = list(backend.credits())
        try:
            from angerona.core.data_paths import data_dir
            from angerona.core.github_tool_catalog import GitHubToolCatalog, repository_identity
            for item in GitHubToolCatalog(data_dir() / "github-source-library").list_imports():
                repository = repository_identity("https://github.com/" + item["repository"])
                rows.append(dict(name=repository, url="https://github.com/" + repository,
                                 version=item["commit"], license=item["license"],
                                 notice="Source-library attribution metadata; review does not authorize execution."))
        except Exception:
            rows.append(dict(name="Source library", notice="Source-library credits are currently unavailable."))
        return rows[:64]

    def _drain(self):
        if not self._closed and self._busy:
            lease = self._focus_lease
            if lease is not None and time.monotonic() - self._focus_renewed_at >= 10:
                renew = getattr(lease, "renew", None)
                try:
                    if callable(renew) and renew():
                        self._focus_renewed_at = time.monotonic()
                except Exception:
                    pass
            usage = {}
            if self._service is not None and callable(getattr(self._service, "resource_snapshot", None)):
                try:
                    usage = self._service.resource_snapshot()
                    if type(usage) is not dict:
                        usage = {"state": "unavailable"}
                except Exception:
                    usage = {"state": "unavailable"}
            native = self._native_priority_module
            if native is not None:
                try:
                    usage = dict(usage, native=native.priority_scan_snapshot())
                except Exception:
                    usage = dict(usage, native={"state": "unavailable"})
            if usage and usage != self._snapshot.get("resource_usage"):
                self._publish(resource_usage=usage)
        for _ in range(32):
            try:
                kind, value = self._frames.get_nowait()
            except queue.Empty:
                break
            if self._closed:
                continue
            if kind == "progress":
                self._publish(message=value)
            elif kind == "metadata":
                self._publish(**value)
            elif kind == "error":
                self._busy = False
                self._publish(**value)
            else:
                action, result = value
                self._busy = False
                if action == "credits":
                    if self._pending_priority is None:
                        self.credits_ready.emit(result)
                    self._publish(message="Project credits loaded.")
                else:
                    update = result if type(result) is dict else dict(message=_literal(result))
                    self._publish(**update)
                    if action == "settings":
                        self.settings_saved.emit()
        if not self._busy and self._pending_priority is not None:
            # A result publication is not thread retirement. Reuse the one
            # worker permit only after its actual Python thread has exited;
            # the backend separately retains native child-tree custody.
            if self._worker is None or not self._worker.is_alive():
                options, self._pending_priority = self._pending_priority, None
                self._start("priority_scan", options)
            return
        if not self._busy and self._frames.empty():
            self._timer.stop()

    def refresh(self):
        return self._start("status")

    def prepare(self):
        return self._start("prepare")

    def scan(self, **options):
        return self._start("scan", options)

    def priority_scan(self, **options):
        if self._closed:
            return False
        if self._busy:
            if self._snapshot.get("active_action") == "priority_scan":
                self._publish(message="The dedicated spyware scan is already scheduled or running at its selected priority.")
                return True
            if self._pending_priority is None:
                self._pending_priority = dict(options)
            self._cancel_current()
            self._publish(message="Priority scan queued; finishing and retiring the current owned tool operation…")
            return True
        return self._start("priority_scan", options)

    def self_test(self):
        return self._start("self_test")

    def open_tool(self):
        return self._start("open_tool")

    def revert(self):
        return self._start("revert")

    def clear_reports(self):
        return self._start("clear_reports")

    def load_credits(self):
        return self._start("credits")

    def save_options(self, values):
        return self._start("settings", dict(values))

    def cancel(self):
        self._pending_priority = None
        self._cancel_current()
        self._publish(message="Cancellation requested; waiting for owned tool retirement…")

    def _cancel_current(self):
        self._cancel_requested.set()
        operation = self._operation
        if operation is not None:
            operation.cancel()
        native = self._native_priority_module
        if native is not None:
            native.cancel_priority_scan(self._native_request_id)

    def auto_prepare(self):
        cfg = _config(self.manager)
        if (self._auto_started or self._closed or not getattr(cfg, "github_tools_enabled", True)
                or not getattr(cfg, "github_tools_auto_prepare", True)):
            return False
        self._auto_started = True
        return self.prepare()

    def shutdown(self):
        self._closed = True
        self._pending_priority = None
        self._timer.stop()
        self._cancel_requested.set()
        if self._operation is not None:
            self._operation.cancel()
        native = self._native_priority_module
        if native is not None:
            native.cancel_priority_scan(self._native_request_id)
        service = self._service
        if service is not None and callable(getattr(service, "cancel_all", None)):
            service.cancel_all()

    def wait_for_shutdown(self, timeout=5.0):
        deadline = time.monotonic() + max(0, timeout)
        if not self._done.wait(max(0, deadline - time.monotonic())):
            return False
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(max(0, deadline - time.monotonic()))
            if worker.is_alive():
                return False
        service = self._service
        wait = getattr(service, "wait_for_shutdown", None) if service is not None else None
        return bool(wait(max(0, deadline - time.monotonic()))) if callable(wait) else True


def get_curated_tools_controller(manager):
    controller = getattr(manager, "_curated_tools_controller", None)
    if not isinstance(controller, CuratedToolsController):
        controller = CuratedToolsController(manager, QApplication.instance())
        manager._curated_tools_controller = controller
    return controller


class CuratedToolsSettings(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        cfg = _config(controller.manager)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Scanner setup runs after the dashboard paints. Scanning requires an explicit action."))
        self.controls = {}
        for name, (title, default) in _SETTINGS.items():
            check = QCheckBox(title)
            check.setChecked(bool(getattr(cfg, name, default)))
            self.controls[name] = check
            layout.addWidget(check)
        limits = QFormLayout()
        for name, (title, default, low, high) in _LIMITS.items():
            spin = QSpinBox()
            spin.setRange(low, high)
            spin.setValue(int(getattr(cfg, name, default)))
            self.controls[name] = spin
            limits.addRow(title, spin)
        layout.addLayout(limits)
        self.priority = QComboBox()
        for title, value in (("Above normal", "above-normal"), ("High", "high")):
            self.priority.addItem(title, value)
        selected = self.priority.findData(getattr(cfg, "spyware_scan_priority", "above-normal"))
        self.priority.setCurrentIndex(max(0, selected))
        limits.addRow("Spyware Scan priority", self.priority)
        save = QPushButton("Save tool settings")
        self.save_button = save
        save.clicked.connect(self._save)
        layout.addWidget(save, 0, Qt.AlignmentFlag.AlignLeft)
        clear = QPushButton("Delete scanner reports…")
        self.clear_reports_button = clear
        clear.clicked.connect(self._clear_reports)
        layout.addWidget(clear, 0, Qt.AlignmentFlag.AlignLeft)
        self.controller.status_changed.connect(self._update_busy)
        layout.addWidget(_label("Advanced standalone phone checks use a private password prompt. "
                                "Optional pattern, backup and acquisition components need their own reviewed runtime."))
        layout.addStretch(1)
        self._update_busy(self.controller.snapshot())

    def _update_busy(self, snapshot):
        self.save_button.setEnabled(not snapshot.get("busy"))
        self.clear_reports_button.setEnabled(not snapshot.get("busy"))

    def _save(self):
        values = {name: widget.isChecked() if name in _SETTINGS else widget.value()
                  for name, widget in self.controls.items()}
        values["spyware_scan_priority"] = self.priority.currentData()
        self.controller.save_options(values)

    def _clear_reports(self):
        if QMessageBox.question(self, "Delete scanner reports",
                                "Delete unchanged reports and working data from completed managed scanner jobs? "
                                "Unknown or modified files, preferences and source-library imports are preserved.",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.controller.clear_reports()


class SpywareScanControls(QWidget):
    """Compact copied status and per-request priority/tool selections."""

    def __init__(self, manager, parent=None, *, controller=None):
        super().__init__(parent)
        self.controller = controller or get_curated_tools_controller(manager)
        cfg = _config(manager)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.resources = _label("Spyware Scan · idle · tool process CPU/RAM/I/O measurements unavailable")
        self.privileges = _label("Privileges have not been verified for this scan.")
        layout.addWidget(self.resources)
        layout.addWidget(self.privileges)
        self.toggle = QToolButton()
        self.toggle.setText("Scanner selection and priority")
        self.toggle.setCheckable(True)
        self.toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        layout.addWidget(self.toggle)
        self.options = QWidget()
        form = QFormLayout(self.options)
        self.native = QCheckBox("Native SpywareGuard")
        self.native.setChecked(bool(getattr(cfg, "spyware_scan_native_enabled", True)))
        self.zero_breach = QCheckBox("Zero-Breach Toolkit")
        self.zero_breach.setChecked(bool(getattr(cfg, "spyware_scan_zero_breach_enabled", True)))
        form.addRow(self.native)
        form.addRow(self.zero_breach)
        self.priority = QComboBox()
        for title, value in (("Above normal", "above-normal"), ("High", "high")):
            self.priority.addItem(title, value)
        self.priority.setCurrentIndex(max(0, self.priority.findData(getattr(cfg, "spyware_scan_priority", "above-normal"))))
        form.addRow("Priority", self.priority)
        self.cpu = QSpinBox()
        self.cpu.setRange(10, 90)
        self.cpu.setValue(int(getattr(cfg, "spyware_scan_cpu_percent", 70)))
        form.addRow("CPU ceiling (%)", self.cpu)
        self.memory = QSpinBox()
        self.memory.setRange(128, 2048)
        self.memory.setValue(int(getattr(cfg, "spyware_scan_memory_mib", 512)))
        form.addRow("Memory ceiling (MiB)", self.memory)
        form.addRow(_label("Priority favors the selected checks while the operating system retains control. "
                           "Privilege verification reports coverage; it does not grant administrator rights."))
        self.options.hide()
        self.toggle.toggled.connect(self.options.setVisible)
        self.toggle.toggled.connect(lambda opened: self.toggle.setArrowType(
            Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow))
        layout.addWidget(self.options)
        self.controller.status_changed.connect(self._apply)
        self._apply(self.controller.snapshot())

    def start(self, **options):
        return self.controller.priority_scan(native_enabled=self.native.isChecked(),
                                             zero_breach_enabled=self.zero_breach.isChecked(),
                                             priority=self.priority.currentData(), max_cpu_percent=self.cpu.value(),
                                             max_memory_mib=self.memory.value(), **options)

    def _apply(self, snapshot):
        usage = snapshot.get("resource_usage")
        usage = usage if type(usage) is dict else {}
        native = usage.get("native")
        native = native if type(native) is dict else {}
        job_state = snapshot.get("state", "idle")
        if snapshot.get("busy"):
            job_state = "native running" if native.get("state") == "running" else "requested / preparing"
            if usage.get("process_alive"):
                job_state = "native + tool running" if native.get("state") == "running" else "tool running"
        pieces = [f"Spyware Scan · {_literal(job_state, 60)}"]
        for label, names in (("CPU", ("cpu_percent", "cpu")), ("RAM", ("memory_mib", "rss_mib")),
                             ("I/O", ("io_bytes", "io_total_bytes"))):
            value = next((usage[name] for name in names if name in usage), None)
            pieces.append(f"{label}: {_literal(value, 50) if value is not None else 'unavailable'}")
        if "read_bytes" in usage and "write_bytes" in usage:
            pieces[-1] = f"I/O: {_literal(usage['read_bytes'], 30)} read / {_literal(usage['write_bytes'], 30)} written"
        self.resources.setText(" · ".join(pieces))
        admin = snapshot.get("admin_state", usage.get("admin_state", usage.get("admin", snapshot.get("admin"))))
        self.privileges.setText("Privilege coverage: " + (" ".join(_literal(admin, 220).split()) if admin is not None
                                                         else "not yet verified for this scan"))


class CuratedScannerWidget(QWidget):
    analysis_requested = Signal()

    def __init__(self, manager, parent=None, *, controller=None):
        super().__init__(parent)
        self.controller = controller or get_curated_tools_controller(manager)
        self._credits_dialog = None
        self._credits_requested = False
        self._settings_dialog = None
        self._after_action_dialog = None
        self._advanced_dialog = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(7)
        title = _label("Zero-Breach Toolkit")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        layout.addWidget(_label("Checks known spyware traces using the pinned toolkit. Coverage, gaps and findings remain separate."))
        self.status = _label()
        layout.addWidget(self.status)
        row = QGridLayout()
        self._primary_actions = row
        self.install_button = QPushButton("Install / repair")
        self.run_button = QPushButton("Run scan")
        self.priority_button = QPushButton("Spyware Scan")
        self.cancel_button = QPushButton("Stop scan")
        self.credits_button = QPushButton("Credits")
        self._primary_buttons = (self.install_button, self.run_button, self.priority_button, self.cancel_button, self.credits_button)
        for index, button in enumerate(self._primary_buttons):
            row.addWidget(button, 0, index)
        layout.addLayout(row)
        self.install_button.clicked.connect(self.controller.prepare)
        self.run_button.clicked.connect(lambda: self._scan())
        self.priority_button.clicked.connect(lambda: self._scan(priority=True))
        self.cancel_button.clicked.connect(self.controller.cancel)
        self.credits_button.clicked.connect(self._request_credits)
        self.priority_controls = SpywareScanControls(manager, self, controller=self.controller)
        layout.addWidget(self.priority_controls)
        mode_row = QFormLayout()
        self.mode = QComboBox()
        self.mode.setMinimumContentsLength(16)
        self.mode.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        for label, value in (("Default desktop", "default"), ("Full desktop", "full"),
                             ("Browser checks", "browser"), ("Selected evidence", "targeted")):
            self.mode.addItem(label, value)
        mode_row.addRow("Scan", self.mode)
        mode_row.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        layout.addLayout(mode_row)
        self.options_toggle = QToolButton()
        self.options_toggle.setText("Scan options")
        self.options_toggle.setToolTip("Choose local evidence, indicator files and optional scan flags.")
        self.options_toggle.setCheckable(True)
        self.options_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.options_toggle.setArrowType(Qt.ArrowType.RightArrow)
        layout.addWidget(self.options_toggle)
        self.options = QGroupBox()
        options_layout = QVBoxLayout(self.options)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.device = QComboBox()
        self.device.setMinimumContentsLength(16)
        self.device.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        for label, value in (("Desktop / selected files", "desktop"), ("Existing Android collection", "android"),
                             ("iPhone backup", "backup"), ("iPhone filesystem export", "filesystem"),
                             ("iPhone sysdiagnose", "sysdiagnose")):
            self.device.addItem(label, value)
        form.addRow("Evidence type", self.device)
        self.targets = QPlainTextEdit()
        self.targets.setPlaceholderText("Selected local paths, one per line; never enter a backup password here.")
        self.targets.setMaximumHeight(76)
        self.targets.document().setMaximumBlockCount(16)
        form.addRow("Local evidence", self.targets)
        self.iocs = QLineEdit()
        self.iocs.setMaxLength(2048)
        self.iocs.setPlaceholderText("Optional local indicator file")
        form.addRow("Custom indicators", self.iocs)
        options_layout.addLayout(form)
        choose = QHBoxLayout()
        select_folder = QPushButton("Choose folder…")
        select_file = QPushButton("Choose file…")
        select_iocs = QPushButton("Indicator file…")
        select_folder.clicked.connect(lambda: self._choose(True))
        select_file.clicked.connect(lambda: self._choose(False))
        select_iocs.clicked.connect(self._choose_iocs)
        for button in (select_folder, select_file, select_iocs):
            choose.addWidget(button)
        choose.addStretch(1)
        options_layout.addLayout(choose)
        self.quick = QCheckBox("Quick scan (records skipped hashing)")
        self.preview = QCheckBox("Preview scope without claiming a completed scan")
        self.extended = QCheckBox("Include existing Windows event records")
        for check in (self.quick, self.preview, self.extended):
            options_layout.addWidget(check)
        options_layout.addWidget(_label("Built-in indicators run offline. Advanced toolkit options explain standalone "
                                        "encrypted backups, pattern engines and device acquisition."))
        self.options.hide()
        self.options_toggle.toggled.connect(self._toggle_options)
        layout.addWidget(self.options)
        actions = QGridLayout()
        self._secondary_actions = actions
        self.verify_button = QPushButton("Verify / self-test")
        self.settings_button = QPushButton("Settings")
        self.analysis_button = QPushButton("Analysis / sandbox")
        self.advanced_button = QPushButton("Advanced toolkit options…")
        self.revert_button = QPushButton("Revert")
        self.project_button = QPushButton("Project ↗")
        self._secondary_buttons = (self.verify_button, self.settings_button, self.analysis_button,
                                   self.advanced_button, self.revert_button, self.project_button)
        for index, button in enumerate(self._secondary_buttons):
            actions.addWidget(button, index // 3, index % 3)
        layout.addLayout(actions)
        self.verify_button.clicked.connect(self.controller.self_test)
        self.settings_button.clicked.connect(self._show_settings)
        self.analysis_button.clicked.connect(self.analysis_requested.emit)
        self.advanced_button.clicked.connect(self._show_advanced)
        self.revert_button.clicked.connect(self._revert)
        self.project_button.clicked.connect(lambda: _open_link(_PROJECT))
        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        self.results.setUndoRedoEnabled(False)
        self.results.setMinimumHeight(130)
        self.results.document().setMaximumBlockCount(2000)
        self.results.setPlaceholderText("Scan coverage and results appear here. Source-analysis sandbox controls are separate from host scanning.")
        layout.addWidget(self.results, 1)
        review = QHBoxLayout()
        self.investigate_button = QPushButton("Investigate")
        self.investigate_button.setToolTip("Open the detailed after-action report and response availability.")
        self.trace_button = QPushButton("Trace evidence")
        self.investigate_button.clicked.connect(self._investigate)
        self.trace_button.clicked.connect(lambda: self._investigate(trace=True))
        review.addWidget(self.investigate_button)
        review.addWidget(self.trace_button)
        layout.addLayout(review)
        self.controller.status_changed.connect(self._apply)
        self.controller.credits_ready.connect(self._show_credits)
        self._apply(self.controller.snapshot())
        self._action_columns = None
        self._reflow_actions()

    def _toggle_options(self, opened):
        self.options.setVisible(opened)
        self.options_toggle.setArrowType(Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow)

    def _reflow_actions(self):
        if not hasattr(self, "_secondary_buttons"):
            return
        parent = self.parentWidget()
        available = min(self.width(), parent.width()) if parent is not None else self.width()
        available -= self.layout().contentsMargins().left() + self.layout().contentsMargins().right()

        def fitted(buttons, maximum, grid):
            for button in buttons:
                button.ensurePolished()
            spacing = max(0, grid.horizontalSpacing())
            for count in range(maximum, 0, -1):
                widths = [max(button.minimumSizeHint().width() for button in buttons[column::count])
                          for column in range(count)]
                if sum(widths) + spacing * (count - 1) <= available:
                    return count
            return 1

        columns = (fitted(self._primary_buttons, 5, self._primary_actions),
                   fitted(self._secondary_buttons, 3, self._secondary_actions))
        if columns == getattr(self, "_action_columns", None):
            return
        self._action_columns = columns
        for grid, buttons, count in ((self._primary_actions, self._primary_buttons, columns[0]),
                                     (self._secondary_actions, self._secondary_buttons, columns[1])):
            for button in buttons:
                grid.removeWidget(button)
            for column in range(6):
                grid.setColumnStretch(column, 0)
            for index, button in enumerate(buttons):
                grid.addWidget(button, index // count, index % count)
            grid.setColumnStretch(count, 1)
            grid.invalidate()
        self.updateGeometry()

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        self._reflow_actions()

    def _choose(self, folder):
        selected = QFileDialog.getExistingDirectory(self, "Select local evidence") if folder else QFileDialog.getOpenFileName(self, "Select local evidence")[0]
        if selected:
            lines = self.targets.toPlainText().splitlines()
            self.targets.setPlainText("\n".join((*lines, selected)[-16:]))
            self.mode.setCurrentIndex(self.mode.findData("targeted"))

    def _choose_iocs(self):
        selected = QFileDialog.getOpenFileName(self, "Select local indicator file")[0]
        if selected:
            self.iocs.setText(selected)

    def _scan(self, *, priority=False):
        targets = tuple(line.strip() for line in self.targets.toPlainText().splitlines() if line.strip())[:16]
        device = self.device.currentData()
        mode = self.mode.currentData()
        if (mode == "targeted" or device != "desktop") and not targets:
            self.status.setText("Choose the local evidence path before scanning.")
            self.options_toggle.setChecked(True)
            return
        selected = dict(mode="targeted" if device == "android" else mode,
                        targets=targets, phone=device in {"backup", "filesystem", "sysdiagnose"},
                        ios_input=device if device in {"backup", "filesystem", "sysdiagnose"} else "backup",
                        quick=self.quick.isChecked(), preview=self.preview.isChecked(),
                        extended_windows=self.extended.isChecked(), include_feeds=False,
                        iocs=(self.iocs.text().strip(),) if self.iocs.text().strip() else ())
        if selected["quick"] and selected["mode"] == "targeted":
            self.status.setText("Quick mode applies to desktop checks; turn it off for selected evidence.")
            return
        if priority:
            self.priority_controls.start(**selected)
        else:
            selected.update(priority=self.priority_controls.priority.currentData(),
                            max_cpu_percent=self.priority_controls.cpu.value(),
                            max_memory_mib=self.priority_controls.memory.value())
            self.controller.scan(**selected)

    def _apply(self, state):
        busy = bool(state.get("busy"))
        verified = bool(state.get("verified"))
        executable = state.get("execution_available") is not False
        enabled = bool(getattr(_config(self.controller.manager), "github_tools_enabled", True))
        self.status.setText(f"{_literal(state.get('state', 'unknown'), 80)} · v{_literal(state.get('version', '0.1.10'), 40)}\n"
                            + _literal(state.get("message"), 1200))
        self.install_button.setEnabled(not busy and enabled)
        self.run_button.setEnabled(not busy and verified and enabled and executable)
        self.priority_button.setEnabled(not self.controller._closed)
        self.advanced_button.setEnabled(not busy)
        self.verify_button.setEnabled(not busy and verified and enabled and executable)
        self.cancel_button.setEnabled(busy)
        self.revert_button.setEnabled(not busy and bool(state.get("installed")))
        self.credits_button.setEnabled(not busy)
        self.settings_button.setEnabled(not busy)
        selected = {key: state[key] for key in ("state", "message", "coverage", "findings", "details", "report", "latest_report")
                    if key in state}
        content = _literal(selected)
        if self.results.toPlainText() != content:
            vertical = self.results.verticalScrollBar().value()
            self.results.setPlainText(content)
            self.results.verticalScrollBar().setValue(vertical)

    def _revert(self):
        if QMessageBox.question(self, "Revert Zero-Breach integration",
                                "Disable automatic scanner preparation and retire its managed scanner copy? "
                                "Preferences, reports and imported source are preserved.",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.controller.revert()

    def _investigate(self, *, trace=False):
        from angerona.gui.breach_display import AfterActionReportDialog
        report = self.controller.snapshot()
        dialog = self._after_action_dialog
        if dialog is None or not isValid(dialog):
            dialog = AfterActionReportDialog(report, self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        else:
            dialog.update_report(report)
        if trace:
            dialog.show_trace()
        self._after_action_dialog = dialog
        dialog.show()

    def _show_settings(self):
        if self._settings_dialog is not None and isValid(self._settings_dialog):
            self._settings_dialog.show()
            self._settings_dialog.raise_()
            return
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.setWindowTitle("GitHub tools settings")
        dialog.resize(580, 430)
        layout = QVBoxLayout(dialog)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(CuratedToolsSettings(self.controller, dialog))
        layout.addWidget(scroll)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        self._settings_dialog = dialog
        dialog.show()

    def _show_advanced(self):
        if self._advanced_dialog is not None and isValid(self._advanced_dialog):
            self._advanced_dialog.show()
            self._advanced_dialog.raise_()
            return
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.setWindowTitle("Zero-Breach — advanced toolkit options")
        dialog.resize(680, 470)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(
            "Integrated adapter\n"
            "Default, full, browser and selected-evidence checks; existing Android collections; "
            "iPhone backup/filesystem/sysdiagnose inputs; preview, quick checks and local indicator files. "
            "Actual coverage and missing dependencies are recorded in each report.\n\n"
            "Standalone advanced capabilities\n"
            "The upstream release also provides encrypted-backup prompts, optional YARA patterns, "
            "indicator updates, evidence ZIP exports and AndroidQF acquisition. Android acquisition "
            "changes device state and needs its owner's consent. Backup passwords belong in the "
            "toolkit's private terminal prompt.\n\n"
            "Advanced execution inside Angerona is held until its separate dependency/acquisition "
            "runtime is reviewed. Use the official pinned release below to review standalone setup. "
            "The included source, versions and required notices remain available in Credits.\n\n"
            "A host-evidence scan and the Source Library's analysis sandbox have different scopes. "
            "Sandbox readiness and response authority retain their existing checks.")
        layout.addWidget(text, 1)
        row = QHBoxLayout()
        release = QPushButton("Official pinned release / downloads ↗")
        release.clicked.connect(lambda: _open_link(_RELEASE))
        status = QPushButton("Check advanced adapter status")
        status.setEnabled(self.controller.snapshot().get("execution_available") is not False)
        status.setToolTip(_literal(self.controller.snapshot().get("execution_hold_reason", ""), 1000))
        status.clicked.connect(self.controller.open_tool)
        row.addWidget(release)
        row.addWidget(status)
        layout.addLayout(row)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        self._advanced_dialog = dialog
        dialog.show()

    def _show_credits(self, rows):
        requested, self._credits_requested = self._credits_requested, False
        if not requested or not self.isVisible():
            return
        if self._credits_dialog is not None and isValid(self._credits_dialog):
            self._credits_dialog.close()
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.setWindowTitle("GitHub tools — credits and licenses")
        dialog.resize(720, 520)
        layout = QVBoxLayout(dialog)
        layout.addWidget(_label("Upstream projects, research providers and applicable licenses. Inclusion does not imply endorsement."))
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText("\n\n".join(_literal(row, 12000) for row in rows[:64])[:96000])
        layout.addWidget(text, 1)
        links = QHBoxLayout()
        choices = QComboBox()
        choices.setObjectName("CreditsLinks")
        choices.setAccessibleName("Credited project and license links")
        choices.setMinimumContentsLength(18)
        choices.setMaximumWidth(440)
        choices.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        seen = set()
        for row in rows[:64]:
            if type(row) is not dict:
                continue
            for key in ("url", "license_url", "source_url", "notice_url"):
                url = row.get(key)
                if type(url) is str and len(url) <= 512 and url not in seen:
                    seen.add(url)
                    choices.addItem(_literal(row.get("name", "Project"), 40) + " — " + url, url)
        open_link = QPushButton("Open selected link ↗")
        open_link.setEnabled(bool(seen))
        open_link.clicked.connect(lambda: _open_link(choices.currentData()))
        links.addWidget(choices, 1)
        links.addWidget(open_link)
        layout.addLayout(links)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        self._credits_dialog = dialog
        dialog.show()

    def _request_credits(self):
        self._credits_requested = True
        if not self.controller.load_credits():
            self._credits_requested = False

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self._apply(self.controller.snapshot())
        if self.controller.snapshot().get("state") == "not_loaded":
            self.controller.refresh()


class GitHubToolsDialog(QDialog):
    def __init__(self, manager, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Angerona — GitHub tools")
        self.setModal(False)
        self.setMinimumSize(560, 400)
        screen = self.screen()
        available = screen.availableGeometry() if screen is not None else None
        self.resize(min(1040, int(available.width() * .9)) if available else 1040,
                    min(740, int(available.height() * .88)) if available else 740)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.scanner = CuratedScannerWidget(manager, self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.scanner)
        self.tabs.addTab(scroll, "Curated scanners")
        from angerona.gui.github_tools import GitHubToolsPanel
        self.source_library = GitHubToolsPanel(self)
        source_scroll = QScrollArea()
        source_scroll.setWidgetResizable(True)
        source_scroll.setWidget(self.source_library)
        self.tabs.addTab(source_scroll, "Source library & analysis")
        settings = QScrollArea()
        settings.setWidgetResizable(True)
        settings.setWidget(CuratedToolsSettings(self.scanner.controller, self))
        self.tabs.addTab(settings, "Settings")
        self.scanner.analysis_requested.connect(self.open_analysis)
        layout.addWidget(self.tabs)

    def open_analysis(self):
        self.tabs.setCurrentIndex(1)
        self.source_library.tabs.setCurrentWidget(self.source_library.analysis_lab)

    def retire_view(self):
        # Source-review work belongs to its view; scanner work belongs to App.
        self.source_library._lifetime["closed"] = True
        self.source_library.cancel_pending()
        self.close()
