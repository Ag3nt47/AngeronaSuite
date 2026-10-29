"""Shared, asynchronous presentation of maintained third-party scanner adapters."""
from __future__ import annotations

import copy
import contextlib
import importlib
import json
import math
import queue
import threading
import time
import uuid
from urllib.parse import urlsplit

from PySide6.QtCore import QObject, QRectF, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QActionGroup, QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox,
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
        self._snapshot["scan_progress"] = None
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
                                          scan_progress=None,
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
        completed_stages = set()
        total_stages = 2 + int(native_enabled) + int(tool_enabled)

        def scan_progress(stage, *, terminal=False):
            return dict(request_id=request_id, unit="workflow_stages", stage=stage,
                        finished=len(completed_stages), total=total_stages,
                        planned_stages=("preflight",) + (("native",) if native_enabled else ())
                        + (("toolkit",) if tool_enabled else ()) + ("aggregation",),
                        finished_stages=tuple(sorted(completed_stages)),
                        state="finished" if terminal else "running",
                        native_state=native_state.get("state", "unavailable"),
                        tool_state=tool_result.get("state", "unavailable"))

        def publish_stage(stage):
            self._frame("metadata", {"scan_progress": scan_progress(stage)})

        publish_stage("preflight")
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
                completed_stages.add("preflight")
                if native_enabled and self._native_priority_module is None:
                    completed_stages.add("native")
                publish_stage("toolkit" if tool_enabled else "native")
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
                    completed_stages.add("toolkit")
                    publish_stage("native" if self._native_priority_module is not None else "aggregation")
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
                    completed_stages.add("native")
                publish_stage("aggregation")
            incomplete = native_enabled and native_state.get("state") != "completed"
            incomplete = incomplete or (tool_enabled and tool_result.get("state") not in {
                "complete", "findings", "references", "withdrawn",
            })
            completed_stages.add("aggregation")
            return dict(state="incomplete" if incomplete else "completed",
                        message=("Spyware scan ended with incomplete coverage. Review each scanner's findings and gaps."
                                 if incomplete else "Spyware scan finished. Review each scanner's findings and coverage."),
                        request_id=request_id, native=native_state, coverage={"native": native_state, "zero_breach": tool_result.get("coverage")},
                        findings=tool_result.get("findings", []), report=tool_result.get("report"),
                        details={"native": native_state, "zero_breach": tool_result},
                        scan_progress=scan_progress("finished", terminal=True))
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
                    native_snapshot = native.priority_scan_snapshot()
                    if (type(native_snapshot) is dict
                            and native_snapshot.get("request_id") == self._native_request_id):
                        usage = dict(usage, native=native_snapshot)
                    else:
                        usage = dict(usage, native={"state": "unavailable",
                                                   "reason": "The native scan generation changed."})
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
        progress = self._snapshot.get("scan_progress")
        if type(progress) is dict:
            progress = dict(progress, stage="cancelling", state="cancelling")
        self._publish(message="Cancellation requested; waiting for owned tool retirement…",
                      scan_progress=progress)

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


class ClickChoice(QComboBox):
    """Keep a parent scroll gesture from silently changing a scan choice."""

    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class ClickNumber(QSpinBox):
    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


def style_spyware_scan_button(button):
    button.setStyleSheet(
        "QPushButton { background:#b91c1c; color:#fff1f2; border:1px solid #ef4444; "
        "border-radius:6px; padding:7px 14px; font-weight:800; }"
        "QPushButton:hover { background:#dc2626; }"
        "QPushButton:disabled { background:#442126; color:#b9a3a6; }"
    )


class ScanProgressRing(QWidget):
    """Cosmetic rotation around measured stage progress; never estimates time."""

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.setFixedSize(68, 68)
        self.percent = None
        self.busy = False
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._rotate)
        self.set_state(None, None, False)

    def set_state(self, finished, total, busy):
        valid = (type(finished) is int and type(total) is int
                 and 0 < total <= 1_000_000 and 0 <= finished <= total)
        self.percent = finished * 100 // total if valid else None
        self.busy = bool(busy)
        text = f"{self.percent}% of workflow stages finished" if valid else "Progress count unavailable"
        self.setAccessibleName(text)
        self.setToolTip(text + ". This is not a percentage of files checked or protection coverage.")
        self._sync_timer()
        self.update()

    def _sync_timer(self):
        from angerona.gui.header_controls import motion_allowed
        if self.busy and self.isVisible() and motion_allowed(self.config):
            self._timer.start()
        else:
            self._timer.stop()

    def _rotate(self):
        self._angle = (self._angle + 9) % 360
        self.update()

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event):  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(5, 5, self.width() - 10, self.height() - 10)
        painter.setPen(QPen(QColor("#334155"), 4))
        painter.drawEllipse(rect)
        pen = QPen(QColor("#fb7185" if self.busy else "#38bdf8"), 4)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        if self.busy:
            painter.drawArc(rect, -self._angle * 16, 100 * 16)
        elif self.percent is not None:
            painter.drawArc(rect, 90 * 16, -round(360 * self.percent / 100) * 16)
        painter.setPen(QColor("#f8fafc"))
        font = painter.font()
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                         f"{self.percent}%" if self.percent is not None else "—")


class SpywareScanControls(QWidget):
    """Readable request scope, included checks and copied workflow observations."""

    def __init__(self, manager, parent=None, *, controller=None, scope_controls=True):
        super().__init__(parent)
        self.controller = controller or get_curated_tools_controller(manager)
        self._has_scope_controls = scope_controls
        cfg = _config(manager)
        self._scope_mode = "full"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self._section_grid = QGridLayout()
        self.scope_group = QGroupBox("Scope")
        scope = QVBoxLayout(self.scope_group)
        self.scope_button = QToolButton()
        self.scope_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.scope_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.scope_button.setAccessibleName("Change spyware scan scope")
        menu = QMenu(self.scope_button)
        self._scope_actions = {}
        group = QActionGroup(menu)
        group.setExclusive(True)
        for title, mode in (("Entire PC · supported full checks", "full"),
                            ("Browser checks", "browser"), ("Standard system checks", "default"),
                            ("Selected local evidence", "targeted")):
            action = menu.addAction(title)
            action.setCheckable(True)
            action.setChecked(mode == "full")
            group.addAction(action)
            action.triggered.connect(lambda _checked=False, value=mode: self._set_scope(value))
            self._scope_actions[mode] = action
        self.scope_button.setMenu(menu)
        scope.addWidget(self.scope_button)
        self.scope_description = _label()
        scope.addWidget(self.scope_description)
        self.scope_paths = QPlainTextEdit()
        self.scope_paths.setPlaceholderText("Selected local paths, one per line")
        self.scope_paths.setMaximumHeight(64)
        self.scope_paths.document().setMaximumBlockCount(16)
        self.scope_choose = QPushButton("Choose evidence folder…")
        self.scope_choose.clicked.connect(self._choose_scope_folder)
        scope.addWidget(self.scope_paths)
        scope.addWidget(self.scope_choose)
        self.scope_error = _label()
        scope.addWidget(self.scope_error)
        self._set_scope("full")
        self.scope_group.setVisible(scope_controls)

        self.checks_group = QGroupBox("Included checks")
        checks = QVBoxLayout(self.checks_group)
        self.native = QCheckBox("Native SpywareGuard")
        self.native.setChecked(bool(getattr(cfg, "spyware_scan_native_enabled", True)))
        self.zero_breach = QCheckBox("Zero-Breach Toolkit")
        self.zero_breach.setChecked(bool(getattr(cfg, "spyware_scan_zero_breach_enabled", True)))
        checks.addWidget(self.native)
        checks.addWidget(self.zero_breach)
        self.toggle = QToolButton()
        self.toggle.setText("Priority and resource limits")
        self.toggle.setCheckable(True)
        self.toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        checks.addWidget(self.toggle)
        self.options = QWidget()
        form = QFormLayout(self.options)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.priority = ClickChoice()
        for title, value in (("Above normal", "above-normal"), ("High", "high")):
            self.priority.addItem(title, value)
        self.priority.setCurrentIndex(max(0, self.priority.findData(getattr(cfg, "spyware_scan_priority", "above-normal"))))
        form.addRow("Priority", self.priority)
        self.cpu = ClickNumber()
        self.cpu.setRange(10, 90)
        self.cpu.setValue(int(getattr(cfg, "spyware_scan_cpu_percent", 70)))
        form.addRow("CPU ceiling (%)", self.cpu)
        self.memory = ClickNumber()
        self.memory.setRange(128, 2048)
        self.memory.setValue(int(getattr(cfg, "spyware_scan_memory_mib", 512)))
        form.addRow("Memory ceiling (MiB)", self.memory)
        self.options.hide()
        self.toggle.toggled.connect(self.options.setVisible)
        self.toggle.toggled.connect(lambda opened: self.toggle.setArrowType(
            Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow))
        checks.addWidget(self.options)
        self._section_grid.addWidget(self.scope_group, 0, 0)
        self._section_grid.addWidget(self.checks_group, 0, 1 if scope_controls else 0)
        layout.addLayout(self._section_grid)

        self.progress_group = QGroupBox("Progress")
        progress = QHBoxLayout(self.progress_group)
        self.progress_ring = ScanProgressRing(cfg)
        progress.addWidget(self.progress_ring)
        captions = QVBoxLayout()
        self.progress_stage = _label("Ready for an explicit scan request.")
        self.progress_stage.setStyleSheet("font-weight:700;")
        self.progress_count = _label("No workflow is running.")
        captions.addWidget(self.progress_stage)
        captions.addWidget(self.progress_count)
        captions.addWidget(_label("Percent tracks finished workflow stages, not files checked or protection coverage."))
        progress.addLayout(captions, 1)
        self.cancel_button = QPushButton("Stop scan")
        self.cancel_button.clicked.connect(self.controller.cancel)
        progress.addWidget(self.cancel_button)
        layout.addWidget(self.progress_group)

        self.explanation_group = QGroupBox("What's happening now")
        explanation = QVBoxLayout(self.explanation_group)
        self.stage_explanation = _label()
        explanation.addWidget(self.stage_explanation)
        timeline = QHBoxLayout()
        self.stage_chips = {}
        for stage, title in (("preflight", "Preflight"), ("native", "Native"),
                             ("toolkit", "Toolkit"), ("aggregation", "Report")):
            chip = _label(title)
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setToolTip("A finished workflow stage is not a clean-host verdict.")
            self.stage_chips[stage] = chip
            timeline.addWidget(chip, 1)
        explanation.addLayout(timeline)
        self.explanation_toggle = QToolButton()
        self.explanation_toggle.setText("Coverage and permission details")
        self.explanation_toggle.setCheckable(True)
        self.explanation_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.explanation_toggle.setArrowType(Qt.ArrowType.RightArrow)
        explanation.addWidget(self.explanation_toggle)
        self.explanation_details = _label(
            "Native SpywareGuard checks its supported live system sources; its thread's resource "
            "totals are not separately measured here. Zero-Breach runs "
            "separate supported checks in an owned ordinary-user process. A scope selection "
            "changes toolkit checks; native live checks retain their supported system scope.\n\n"
            "Full mode does not read or verify every file. Missing collectors, permissions and "
            "incomplete checks stay explicit. Privilege verification observes the current token; "
            "it does not elevate the app.\n\n"
            "The report is assembled after selected work settles. External toolkit findings "
            "remain leads for review; response still requires validated evidence, an exact target "
            "and existing authority. Workflow completion alone does not mean the PC is clean."
        )
        self.explanation_details.hide()
        self.explanation_toggle.toggled.connect(self.explanation_details.setVisible)
        self.explanation_toggle.toggled.connect(lambda opened: self.explanation_toggle.setArrowType(
            Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow))
        explanation.addWidget(self.explanation_details)
        layout.addWidget(self.explanation_group)

        self.resource_group = QGroupBox("Resource and privilege details")
        resources = QVBoxLayout(self.resource_group)
        self.resources = _label()
        self.privileges = _label()
        resources.addWidget(self.resources)
        resources.addWidget(self.privileges)
        self.privileges.setToolTip("Current-token observations do not grant administrator rights or response authority.")
        layout.addWidget(self.resource_group)
        self.controller.status_changed.connect(self._apply)
        self._apply(self.controller.snapshot())

    def _set_scope(self, mode):
        self._scope_mode = mode
        titles = {"full": "Entire PC · change scope…", "browser": "Browser checks · change scope…",
                  "default": "Standard system checks · change scope…", "targeted": "Selected local evidence · change scope…"}
        self.scope_button.setText(titles[mode])
        self.scope_description.setText({
            "full": "Supported system-wide spyware checks; this does not verify every file.",
            "browser": "Toolkit browser checks. Selected native checks keep their supported system scope.",
            "default": "Standard toolkit checks. Selected native checks keep their supported system scope.",
            "targeted": "Selected toolkit evidence. Selected native checks keep their supported system scope.",
        }[mode])
        self._scope_actions[mode].setChecked(True)
        self.scope_paths.setVisible(mode == "targeted")
        self.scope_choose.setVisible(mode == "targeted")
        self.scope_error.clear()
        self.scope_error.hide()

    def _choose_scope_folder(self):
        selected = QFileDialog.getExistingDirectory(self, "Choose local spyware evidence")
        if selected:
            lines = self.scope_paths.toPlainText().splitlines()
            self.scope_paths.setPlainText("\n".join((*lines, selected)[-16:]))

    def start(self, **options):
        selected = dict(mode=self._scope_mode,
                        targets=tuple(line.strip() for line in self.scope_paths.toPlainText().splitlines() if line.strip())[:16]
                        if self._scope_mode == "targeted" else ())
        selected.update(options)
        if selected["mode"] == "targeted" and not selected.get("targets"):
            self.scope_error.setText("Choose local evidence before starting this scope.")
            self.scope_error.show()
            return False
        return self.controller.priority_scan(native_enabled=self.native.isChecked(),
                                             zero_breach_enabled=self.zero_breach.isChecked(),
                                             priority=self.priority.currentData(), max_cpu_percent=self.cpu.value(),
                                             max_memory_mib=self.memory.value(), **selected)

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        if not hasattr(self, "checks_group"):
            return
        stacked = self.width() < 650 or not self._has_scope_controls
        if stacked != getattr(self, "_sections_stacked", None):
            self._sections_stacked = stacked
            self._section_grid.removeWidget(self.checks_group)
            self._section_grid.addWidget(self.checks_group, 1 if stacked else 0, 0 if stacked else 1)

    def _apply(self, snapshot):
        busy = snapshot.get("busy") is True
        progress = snapshot.get("scan_progress")
        progress = progress if type(progress) is dict and progress.get("unit") == "workflow_stages" else {}
        finished, total = progress.get("finished"), progress.get("total")
        self.progress_ring.set_state(finished, total, busy)
        labels = {"preflight": "Verifying available checks", "toolkit": "Running supported toolkit checks",
                  "native": "Waiting for native SpywareGuard", "aggregation": "Reviewing results and retiring owned work",
                  "cancelling": "Stopping owned scan work", "finished": "Workflow finished · review findings and coverage"}
        stage = labels.get(progress.get("stage"))
        if progress.get("stage") == "finished" and snapshot.get("state") == "incomplete":
            stage = "Workflow finished · incomplete coverage"
        self.progress_stage.setText(stage or ("Working · exact progress unavailable" if busy else
                                              f"Scan state: {_literal(snapshot.get('state', 'idle'), 60)}"))
        state = snapshot.get("state")
        color = ("#38bdf8" if busy else "#4ade80" if state == "completed" else
                 "#fb7185" if state in {"failed", "unavailable"} else
                 "#fbbf24" if state in {"held", "incomplete", "cancelled"} else "#cbd5e1")
        self.progress_stage.setStyleSheet(f"font-weight:700;color:{color};")
        explanations = {
            "preflight": "Checking which selected scanners and privileges are available. Next: run the supported checks.",
            "toolkit": "The toolkit is checking supported spyware traces. Its exact file completion is unavailable. Next: wait for remaining native work.",
            "native": "Waiting for this request's native SpywareGuard checks. Next: assemble findings and explicit coverage gaps.",
            "aggregation": "Selected work has settled; results and owned-work retirement are being reviewed. Next: publish the report.",
            "cancelling": "Cancellation has been requested. Next: wait for owned checks to stop and review any partial evidence.",
            "finished": "The request has ended. Next: investigate findings and coverage gaps; completion does not establish a clean PC.",
        }
        fallback = {
            "held": "The requested checks are held by current runtime or permission limits. Next: review coverage and the existing setup requirements.",
            "failed": "The request failed. Next: review its diagnostic report and partial coverage before trying again.",
            "unavailable": "A required scanner or status source is unavailable. Next: review setup and the reported coverage gap.",
            "cancelled": "The request was cancelled. Next: review any partial evidence; cancellation does not establish a clean PC.",
            "incomplete": "Some selected checks did not complete. Next: review the report's explicit coverage gaps and findings.",
        }.get(state, "Waiting for an explicit request or structured worker status. No completion percentage is estimated from elapsed time.")
        explanation = explanations.get(progress.get("stage"), fallback)
        if progress.get("stage") == "finished" and state == "incomplete":
            explanation = ("Some selected checks were held, unavailable or did not complete. Next: review findings "
                           "and coverage gaps. Finished workflow stages do not establish a clean PC.")
        self.stage_explanation.setText(explanation)
        planned = progress.get("planned_stages")
        finished_stages = progress.get("finished_stages")
        planned = planned if type(planned) in (tuple, list) else ()
        finished_stages = finished_stages if type(finished_stages) in (tuple, list) else ()
        for key, chip in self.stage_chips.items():
            selected = key in planned
            done = selected and key in finished_stages
            current = selected and key == progress.get("stage") and busy
            accent = "#4ade80" if done else "#38bdf8" if current else "#64748b"
            chip.setStyleSheet(f"color:{accent};border:1px solid {accent};border-radius:4px;padding:3px;")
            chip.setAccessibleName(f"{chip.text()}: {'finished' if done else 'current' if current else 'pending' if selected else 'not scheduled'}")
        if self.progress_ring.percent is None:
            self.progress_count.setText("Indeterminate · the worker has not supplied a completion count.")
        else:
            self.progress_count.setText(f"{finished}/{total} workflow stages finished")
        self.cancel_button.setEnabled(busy)
        usage = snapshot.get("resource_usage")
        usage = usage if type(usage) is dict else {}

        def number(value, unit, divisor=1):
            if type(value) not in (int, float):
                return "unavailable"
            try:
                measured = float(value) / divisor
            except (OverflowError, ValueError):
                return "unavailable"
            if not math.isfinite(measured) or measured < 0:
                return "unavailable"
            return f"{measured:,.1f}{unit}"

        cpu = usage.get("cpu_percent", usage.get("cpu"))
        memory = usage.get("rss_mib", usage.get("memory_mib"))
        read, written = usage.get("read_bytes"), usage.get("write_bytes")
        io = (f"{number(read, ' MiB', 1024**2)} read / {number(written, ' MiB', 1024**2)} written"
              if type(read) in (int, float) and type(written) in (int, float) else "unavailable")
        alive = usage.get("process_alive")
        presence = "running" if alive is True else "stopped" if alive is False else "liveness unavailable"
        self.resources.setText(f"Toolkit process · {presence} · latest available sample\n"
                               f"CPU: {number(cpu, '%')}     RAM: {number(memory, ' MiB')}\nI/O: {io}")
        admin = snapshot.get("admin_state", usage.get("admin_state"))
        if type(admin) is dict and admin.get("verified") is True:
            token = "Elevated token" if admin.get("elevated") is True else "Ordinary-user token"
            integrity = _literal(admin.get("integrity", "not reported"), 60)
            self.privileges.setText(f"Privilege verification: {token} · integrity: {integrity}. No new authority is granted.")
        else:
            self.privileges.setText("Privilege verification: unavailable or not yet verified. Coverage limits remain in effect.")


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
        style_spyware_scan_button(self.priority_button)
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
        self.priority_controls = SpywareScanControls(manager, self, controller=self.controller, scope_controls=False)
        layout.addWidget(self.priority_controls)
        mode_row = QFormLayout()
        self.mode = ClickChoice()
        self.mode.setMinimumContentsLength(16)
        self.mode.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        for label, value in (("Standard system checks", "default"), ("Entire PC · supported full checks", "full"),
                             ("Browser checks", "browser"), ("Selected evidence", "targeted")):
            self.mode.addItem(label, value)
        self.mode.setCurrentIndex(self.mode.findData("full"))
        mode_row.addRow("Scope", self.mode)
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
        self.device = ClickChoice()
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
        from angerona.gui.window_fit import install_window_fit
        self._window_fit = install_window_fit(self)

    def open_analysis(self):
        self.tabs.setCurrentIndex(1)
        self.source_library.tabs.setCurrentWidget(self.source_library.analysis_lab)

    def retire_view(self):
        # Source-review work belongs to its view; scanner work belongs to App.
        self.source_library._lifetime["closed"] = True
        self.source_library.cancel_pending()
        self.close()
