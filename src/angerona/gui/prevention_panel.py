"""Read-only inspection and staged Windows prevention; no desktop authority."""
from __future__ import annotations

from dataclasses import asdict
import json
import re
import threading
from typing import Protocol

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QComboBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QTextBrowser, QVBoxLayout, QWidget,
)

from angerona.core.windows_prevention import CATALOG, LogonAuditPlan, inspect_logon_policy, prepare_logon_plan
from angerona.core.response_capability import canonicalize_parameters


class InstalledPreventionClient(Protocol):
    """Optional installed-service adapter, supplied by trusted app composition.

    Implementations reauthenticate OS peers and exact externally signed approvals
    at the service, and honor cancellation before dispatch. The diagnostic service
    currently supplies none. No GUI callback can mint capability/signing keys.
    """
    def prepare_logon(self, *, cancel: threading.Event) -> dict: ...
    def prepare_restore(self, original_id: str, *, cancel: threading.Event) -> dict: ...
    def apply_plan(self, plan: LogonAuditPlan, *, cancel: threading.Event) -> dict: ...


class _PreventionJob:
    """One detached job, no Qt references or signals in the native worker."""
    def __init__(self, action):
        self.cancel = threading.Event()
        self.done = threading.Event()
        self.result = None
        self.presentation = ""
        self.error = ""
        self._action = action

    def run(self):
        try:
            if self.cancel.is_set():
                return
            result = self._action(self.cancel)
            if result is not None:
                try:
                    self.result, _encoded = canonicalize_parameters(result)
                    self.presentation = json.dumps(self.result, indent=2, sort_keys=True, allow_nan=False)
                except Exception:
                    self.error = "Malformed or oversized backend result rejected; no success is claimed."
        except Exception:
            self.error = "Operation unavailable, denied or rejected. No successful change is claimed; review the protected backend journal before retrying."
        finally:
            self._action = None
            self.done.set()


class PreventionPanel(QWidget):
    def __init__(self, manager=None, parent=None, *, inspector=None, client: InstalledPreventionClient | None = None):
        super().__init__(parent)
        self._inspect = inspector or inspect_logon_policy
        self._client = client if client is not None else getattr(manager, "windows_prevention_client", None)
        self._plan = None
        self._job = None
        self._task = ""
        self._cancel_owner = [None]
        self.destroyed.connect(lambda _object=None, owner=self._cancel_owner:
                               owner[0].set() if owner[0] is not None else None)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(50)
        self._poll_timer.timeout.connect(self._poll)
        root = QVBoxLayout(self)
        title = QLabel("WINDOWS PREVENTION · staged plans and native readback")
        title.setStyleSheet("font-weight:700; color:#67e8f9;")
        root.addWidget(title)
        self.status = QLabel("Not inspected · native policy and event-collection coverage are unknown.")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        self.authority = QLabel("Deployment held: this source application has no installed prevention mutation consumer."
                                if self._client is None else
                                "Installed adapter supplied · every change still requires service authentication, two independent signed approvals, durable recovery state and fresh preconditions.")
        self.authority.setWordWrap(True)
        self.authority.setStyleSheet("color:#fbbf24;")
        root.addWidget(self.authority)
        row = QHBoxLayout()
        self.inspect_button = QPushButton("Inspect native policy")
        self.prepare_button = QPushButton("Stage Logon audit plan")
        self.apply_button = QPushButton("Send approved plan")
        self.copy_button = QPushButton("Copy exact plan")
        self.inspect_button.clicked.connect(self._refresh)
        self.prepare_button.clicked.connect(self._prepare)
        self.apply_button.clicked.connect(self._apply)
        self.copy_button.clicked.connect(self._copy)
        for button in (self.inspect_button, self.prepare_button, self.apply_button, self.copy_button):
            row.addWidget(button)
        root.addLayout(row)
        recovery = QHBoxLayout()
        self.original_id = QLineEdit()
        self.original_id.setMaxLength(32)
        self.original_id.setPlaceholderText("Original authenticated plan ID for recovery")
        self.restore_button = QPushButton("Stage recovery plan")
        self.restore_button.clicked.connect(self._restore)
        recovery.addWidget(self.original_id, 1)
        recovery.addWidget(self.restore_button)
        root.addLayout(recovery)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumBlockCount(300)
        self.details.setPlainText("Inspection does not change audit policy or enable privileges. Configuration readback is separate from fresh Security-event collection.\n\n"
            "Plans expire after five minutes. Recovery requires the authenticated original journal, a new purpose-bound proposal and separate approvals. "
            "Closing cancels queued work; a native change already dispatched must finish and be reconciled by the backend.")
        root.addWidget(self.details, 2)
        self.catalog = QComboBox()
        for title, state, _description, _url in CATALOG:
            self.catalog.addItem(title + " · " + state)
        self.catalog.currentIndexChanged.connect(self._catalog_changed)
        root.addWidget(self.catalog)
        self.guide = QTextBrowser()
        self.guide.setOpenLinks(False)
        self.guide.setOpenExternalLinks(False)
        self.guide.anchorClicked.connect(self._open_reference)
        root.addWidget(self.guide, 1)
        self._catalog_changed(0)
        self._buttons()

    def _catalog_changed(self, index):
        title, state, description, url = CATALOG[index]
        self.guide.setHtml(f"<b>{title}</b> · {state}<p>{description}</p><a style='color:#67e8f9' href='{url}'>Microsoft implementation and recovery guidance</a>")

    def _open_reference(self, url):
        # Explicit click; only the built-in official reference list can be opened.
        if url.toString() in {row[3] for row in CATALOG}:
            QDesktopServices.openUrl(QUrl(url))

    def _buttons(self):
        busy = self._job is not None and not self._job.done.is_set()
        self.inspect_button.setEnabled(not busy)
        self.prepare_button.setEnabled(not busy)
        self.apply_button.setEnabled(not busy and self._plan is not None and self._client is not None)
        self.copy_button.setEnabled(not busy and self._plan is not None)
        self.restore_button.setEnabled(not busy and self._client is not None)

    def _start(self, task, action):
        if self._job is not None and not self._job.done.is_set():
            return False
        job = _PreventionJob(action)
        self._job, self._task = job, task
        self._cancel_owner[0] = job.cancel
        self.status.setText("Working off the GUI thread · " + task)
        self._buttons()
        threading.Thread(target=job.run, name="Windows Prevention " + task, daemon=True).start()
        self._poll_timer.start()
        return True

    def _refresh(self):
        inspector = self._inspect
        self._start("inspect", lambda _cancel: inspector())

    def _prepare(self):
        inspector, client = self._inspect, self._client
        self._plan = None

        def prepare(cancel):
            if client is not None:
                return client.prepare_logon(cancel=cancel)
            observation = inspector()
            if cancel.is_set():
                return None
            if type(observation) is not dict or observation.get("bits") is None:
                return dict(observation=observation, reason="Cannot stage a change without native prior-state evidence")
            if observation["bits"] == 3:
                return dict(observation=observation, reason="Success and failure audit policy already configured; fresh event collection remains unknown")
            return dict(plan=asdict(prepare_logon_plan(observation["bits"])), observation=observation,
                        reason="Preview only; no authorization or host change")

        self._start("prepare", prepare)

    def _restore(self):
        original_id, client = self.original_id.text(), self._client
        if client is None or not re.fullmatch(r"[0-9a-f]{32}", original_id):
            self.status.setText("Recovery requires a canonical original plan ID and the installed protected backend.")
            return
        self._plan = None
        self._start("prepare recovery", lambda cancel: client.prepare_restore(original_id, cancel=cancel))

    def _apply(self):
        plan, client = self._plan, self._client
        if plan is None or client is None:
            return
        self._plan = None  # No double-click, close/reopen or failure can silently retry a mutation.
        self._start("submit approved plan", lambda cancel: client.apply_plan(plan, cancel=cancel))

    def _copy(self):
        if self._plan is not None:
            QApplication.clipboard().setText(json.dumps(asdict(self._plan), indent=2, sort_keys=True))

    def _poll(self):
        job = self._job
        if job is None or not job.done.is_set():
            return
        self._poll_timer.stop()
        self._job = None
        self._cancel_owner[0] = None
        if job.cancel.is_set():
            self._plan = None
            self.status.setText("Queued work cancelled. Already dispatched changes require backend readback and journal review.")
        elif job.error:
            self._plan = None
            self.status.setText(job.error)
        else:
            result = job.result
            try:
                if type(result) is dict and type(result.get("plan")) is dict:
                    self._plan = LogonAuditPlan(**result["plan"])
                self.details.setPlainText(job.presentation)
                observation = result.get("observation", result) if type(result) is dict else {}
                state = observation.get("state", "unknown") if type(observation) is dict else "unknown"
                state = state if state in {"configured", "partial", "denied", "unavailable", "unknown"} else "unknown"
                self.status.setText("Staged exact plan · no host change" if self._plan is not None else
                                    "Reported policy state: " + state + " · fresh event collection and runtime protection remain unknown.")
            except Exception:
                self._plan = None
                self.status.setText("Malformed or oversized backend result rejected; no success is claimed.")
        self._buttons()

    def hideEvent(self, event):  # noqa: N802
        self._poll_timer.stop()
        self._plan = None
        if self._job is not None:
            self._job.cancel.set()
        super().hideEvent(event)

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        if self._job is not None:
            self._poll_timer.start()
        self._buttons()
