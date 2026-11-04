"""Review or remove an installed sign-in task using one bounded worker.

This surface displays cached task facts. Administrator startup is session-only.
Backend authority remains installed/native and is rechecked by every operation.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import partial
import sys
import threading

from PySide6.QtCore import QEvent, Qt, Slot
from PySide6.QtWidgets import QAbstractScrollArea, QGridLayout, QGroupBox, QLabel, QMessageBox, QPushButton, QSizePolicy, QVBoxLayout

from angerona.gui.async_snapshot import AsyncSnapshot

_REASONS = {
    "not-checked": "Installed startup has not been checked. Choose Check status to read the current task.",
    "status-unproved": "Startup status is unproved. Choose Check status when you are ready to review it.",
    "operation-unproved": "The startup change is unproved and may have taken effect. Check status before another change. No cleanup or retry runs automatically.",
    "enrolled": "The existing administrator sign-in task was verified. This version holds its automatic administrator launch.",
    "enrolled-legacy-conflict": "The administrator task was verified. This version holds its automatic administrator launch. A separate legacy startup entry is preserved and needs review.",
    "not-enrolled": "No installed administrator sign-in task was found for the current account.",
    "revoked": "The exact administrator sign-in task was removed. The running application stays open.",
    "revoked-legacy-preserved": "The administrator task was removed. A separate legacy startup entry remains and needs review; the running application stays open.",
    "source-or-platform-held": "Unavailable in Source Observe or on this platform. Task review requires the verified installed Windows package.",
    "package-authority-held": "The independently trusted installed package could not be verified. Review the signed installation before checking or removing the task.",
    "modern-entry-held": "The verified installed startup entry could not be established. Review or repair the signed installation.",
    "native-unavailable": "Windows task status is unavailable. The task state and any attempted removal remain unproved.",
    "native-output-held": "Windows returned an unavailable or unrecognized task result. Review status before another change.",
    "native-retirement-held": "The Windows verification worker has not proved retirement. The task state and any attempted change remain unproved.",
    "current-user-held": "The current Windows account identity could not be verified. Task review is held.",
    "initial-admin-required": "To remove this task, first approve administrator access for this session in the signed installation.",
    "legacy-conflict": "A separate legacy startup entry exists. It is preserved for review.",
    "task-definition-held": "The existing task does not match the reviewed sign-in contract. It is preserved for review.",
    "task-security-held": "The task access controls do not match the reviewed administrator-only write policy. Its enrollment is unproved and needs review.",
    "reenrollment-review": "The task belongs to a different package version or startup target. The existing task is preserved for review.",
    "native-race-held": "Windows task or account facts changed during verification. The result is unproved; check status before another change.",
    "session-consent-required": "Administrator access requires your approval for each session.",
}
_PRESENT = frozenset({"enrolled", "enrolled-legacy-conflict"})
_ABSENT = frozenset({"not-enrolled", "revoked", "revoked-legacy-preserved", "legacy-conflict"})
_CHANGED = frozenset({"revoked", "revoked-legacy-preserved"})
_CONFLICT = frozenset({"enrolled-legacy-conflict", "revoked-legacy-preserved", "legacy-conflict"})
_VERBS = frozenset({"status", "revoke"})


@dataclass(frozen=True)
class _View:
    code: str
    enabled: bool | None = None
    changed: bool = False
    requires_review: bool = True


@dataclass(frozen=True)
class _Job:
    verb: str
    sequence: int
    generation: int
    stop: threading.Event


@dataclass(frozen=True)
class _Result:
    verb: str
    sequence: int
    generation: int
    view: _View


@dataclass(frozen=True)
class _Consent:
    verb: str
    generation: int
    revision: int
    sequence: int


def _valid_view(value):
    if type(value) is not _View:
        return False
    code, enabled, changed, review = value.code, value.enabled, value.changed, value.requires_review
    return bool(type(code) is str and len(code) <= 64 and code in _REASONS
        and (enabled is None or type(enabled) is bool)
        and type(changed) is bool and type(review) is bool
        and (code not in _PRESENT or enabled is True)
        and (code not in _ABSENT or enabled is False)
        and (code in _PRESENT | _ABSENT or enabled is None)
        and changed is (code in _CHANGED)
        and (code not in _CONFLICT or review is True))


def copy_installed_status(value) -> _View:
    """Copy only the exact backend DTO and closed scalar semantics."""
    from angerona.core.installed_autostart import InstalledAutostartStatus

    if type(value) is not InstalledAutostartStatus:
        return _View("status-unproved")
    view = _View(value.code, value.enabled, value.changed, value.requires_review)
    if (not _valid_view(view) or view.code in {"not-checked", "status-unproved", "operation-unproved"}):
        return _View("status-unproved")
    return view


def _run_backend(job: _Job) -> _Result:
    """Worker entry: detached immutable inputs, no widget or Qt operation."""
    unproved = "status-unproved" if job.verb == "status" else "operation-unproved"
    if job.stop.is_set() or job.verb not in _VERBS:
        return _Result(job.verb, job.sequence, job.generation, _View(unproved))
    try:
        from angerona.core import autostart

        operation = {"status": autostart.installed_admin_status,
                     "revoke": autostart.revoke_installed_admin_autostart}[job.verb]
        view = copy_installed_status(operation())
        if view.code == "status-unproved" and job.verb != "status":
            view = _View("operation-unproved")
    except Exception:
        view = _View(unproved)
    return _Result(job.verb, job.sequence, job.generation, view)


class InstalledStartupControls(QGroupBox):
    """Embed in Settings System with its QDialog as ``retirement_owner``.

    No query runs at construction. All reads/changes begin with a user action.
    The owner must expose finished/destroyed signals so closing Settings retires
    this instance even when Qt only hides the parent dialog.
    """

    def __init__(self, retirement_owner, parent=None):
        super().__init__("Startup", parent)
        full_title = "Existing administrator sign-in task"
        self.setToolTip(full_title)
        self.setAccessibleName(full_title)
        self.setMinimumWidth(0)
        if not hasattr(retirement_owner, "finished") or not hasattr(retirement_owner, "destroyed"):
            raise ValueError("installed-startup-controls-require-dialog-owner")
        self._closed = False
        self._generation = 1
        self._stop = threading.Event()
        self._sequence = 0
        self._revision = 0
        self._consent_sequence = 0
        self._busy = False
        self._active_job = None
        self._confirmation = None
        self._eligible = sys.platform == "win32" and getattr(sys, "frozen", False) is True
        self._view = _View("not-checked" if self._eligible else "source-or-platform-held")
        layout = QVBoxLayout(self)
        from angerona.gui.action_progress import ActionActivities, ActionProgressView
        self._activities = ActionActivities(self)
        self._activity = None
        self.progress_view = ActionProgressView(self._activities, self)
        layout.addWidget(self.progress_view)
        description = QLabel(
            "Starting Angerona with administrator privileges requires your approval each session. "
            "You can check or remove an existing administrator sign-in task here.")
        description.setWordWrap(True)
        description.setTextFormat(Qt.PlainText)
        layout.addWidget(description)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.PlainText)
        layout.addWidget(self.status_label)
        self.detail_label = QLabel()
        self.detail_label.setWordWrap(True)
        self.detail_label.setTextFormat(Qt.PlainText)
        layout.addWidget(self.detail_label)
        self._actions_grid = QGridLayout()
        self._action_columns = None
        self._actions_parent = None
        self._actions_viewport = None
        self.check_button = QPushButton("Check")
        self.enrollment_info_button = QPushButton("Info")
        self.enrollment_info_button.setCheckable(True)
        self.revoke_button = QPushButton("Remove…")
        self.check_button.clicked.connect(self.request_status)
        self.revoke_button.clicked.connect(partial(self._confirm, "revoke"))
        self._action_buttons = (self.check_button, self.enrollment_info_button, self.revoke_button)
        for button, full_label in zip(self._action_buttons, (
                "Check administrator sign-in startup status",
                "Administrator sign-in enrollment information",
                "Remove administrator sign-in task…")):
            button.setToolTip(full_label)
            button.setAccessibleName(full_label)
        layout.addLayout(self._actions_grid)
        self._enrollment_info = QLabel(
            "Automatic administrator sign-in enrollment is unavailable. The verified Windows "
            "installation can request administrator access for the current session. Windows asks "
            "for your approval each time.")
        self._enrollment_info.setWordWrap(True)
        self._enrollment_info.setTextFormat(Qt.PlainText)
        self._enrollment_info.hide()
        self.enrollment_info_button.clicked.connect(
            lambda: self._enrollment_info.setVisible(self.enrollment_info_button.isChecked()))
        layout.addWidget(self._enrollment_info)
        scope = QLabel(
            "Task status is separate from protection health. Checking or removing this task "
            "is separate from ordinary startup preferences and Settings Save.")
        scope.setWordWrap(True)
        scope.setTextFormat(Qt.PlainText)
        layout.addWidget(scope)
        self._reader = AsyncSnapshot(self, self._prepare, self._apply,
                                     name="InstalledStartupControls", status=self._reader_status)
        retirement_owner.finished.connect(self.shutdown)
        retirement_owner.destroyed.connect(self.shutdown)
        self.destroyed.connect(self.shutdown)
        for label in (description, self.status_label, self.detail_label, self._enrollment_info, scope):
            policy = label.sizePolicy()
            policy.setHorizontalPolicy(QSizePolicy.Ignored)
            policy.setHeightForWidth(True)
            label.setSizePolicy(policy)
            label.setMinimumWidth(0)
        self._watch_actions_parent()
        self._reflow_actions()
        self._render()

    def _watch_actions_parent(self):
        parent = self.parentWidget()
        ancestor = parent
        viewport = None
        while ancestor is not None:
            if isinstance(ancestor, QAbstractScrollArea):
                viewport = ancestor.viewport()
                break
            ancestor = ancestor.parentWidget()
        for name, current in (("_actions_parent", parent), ("_actions_viewport", viewport)):
            previous = getattr(self, name, None)
            if current is previous:
                continue
            if previous is not None:
                try:
                    previous.removeEventFilter(self)
                except RuntimeError:
                    pass
            setattr(self, name, current)
            if current is not None:
                current.installEventFilter(self)

    def _reflow_actions(self):
        if not hasattr(self, "_action_buttons") or getattr(self, "_reflowing_actions", False):
            return
        self._reflowing_actions = True
        try:
            # A scroll page may be reparented after this group is constructed.
            self._watch_actions_parent()
            parent = self.parentWidget()
            # The enclosing page supplies the budget even when an old grid's
            # minimum temporarily keeps this group wider. Never use that old
            # child width to decide whether the parent may shrink.
            width = parent.contentsRect().width() if parent is not None else self.width()
            viewport = self._actions_viewport
            if viewport is not None:
                width = min(width, viewport.contentsRect().width())
            if parent is not None and parent.layout() is not None:
                margins = parent.layout().contentsMargins()
                width -= margins.left() + margins.right()
            # The parent budget includes this group's frame/content margins
            # as well as its layout margins. Omitting the former can admit a
            # grid a few pixels wider than the scroll viewport can contain.
            frame = self.contentsMargins()
            margins = self.layout().contentsMargins()
            available = max(0, width - frame.left() - frame.right()
                            - margins.left() - margins.right())
            for button in self._action_buttons:
                button.ensurePolished()
            widths = [button.sizeHint().width() for button in self._action_buttons]
            gap = max(0, self._actions_grid.horizontalSpacing())
            columns = 1
            for count in (3, 2, 1):
                if sum(max(widths[column::count]) for column in range(count)) + gap * (count - 1) <= available:
                    columns = count
                    break
            if columns == self._action_columns:
                return
            self._action_columns = columns
            for button in self._action_buttons:
                self._actions_grid.removeWidget(button)
            for column in range(self._actions_grid.columnCount()):
                self._actions_grid.setColumnStretch(column, 0)
            for index, button in enumerate(self._action_buttons):
                self._actions_grid.addWidget(button, index // columns, index % columns)
            for column in range(columns):
                self._actions_grid.setColumnStretch(column, 1)
        finally:
            self._reflowing_actions = False

    def eventFilter(self, watched, event):  # noqa: N802
        if (watched in (getattr(self, "_actions_parent", None), getattr(self, "_actions_viewport", None))
                and event.type() in (QEvent.Type.Resize, QEvent.Type.LayoutRequest)):
            self._reflow_actions()
        return False

    def event(self, event):
        result = super().event(event)
        if event.type() == QEvent.Type.ParentChange and hasattr(self, "_actions_parent"):
            self._watch_actions_parent()
        if event.type() in (QEvent.Type.LayoutRequest, QEvent.Type.FontChange, QEvent.Type.StyleChange,
                            QEvent.Type.ParentChange):
            self._reflow_actions()
        return result

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        self._reflow_actions()

    def _allowed(self, verb):
        if not self._eligible or self._closed:
            return False
        if verb == "revoke":
            return self._view.enabled is True and self._view.code in _PRESENT
        return verb == "status"

    def _render(self):
        """Copy cached scalar state to widgets; no backend/getter/native work."""
        if self._closed:
            return
        idle = not self._busy and not self._reader.busy and self._confirmation is None
        self.check_button.setEnabled(idle and self._allowed("status"))
        self.revoke_button.setEnabled(idle and self._allowed("revoke"))
        if self._busy and self._active_job is not None:
            self.status_label.setText({"status": "Checking installed startup…",
                                       "revoke": "Removing the verified administrator sign-in task…"}[self._active_job.verb])
        elif self._view.enabled is True:
            self.status_label.setText("Administrator sign-in task: verified at the last check")
        elif self._view.enabled is False:
            self.status_label.setText("Installed administrator sign-in task: absent at the last check")
        else:
            self.status_label.setText("Administrator sign-in task: unavailable" if not self._eligible else "Administrator sign-in task: unproved")
        detail = _REASONS[self._view.code]
        if self._view.requires_review:
            detail = "Review required. " + detail
        self.detail_label.setText(detail)

    @Slot()
    def request_status(self):
        self._start("status")

    def _start(self, verb):
        if (verb not in _VERBS or self._closed or self._busy or self._reader.busy
                or self._confirmation is not None or not self._allowed(verb)):
            return False
        self._sequence += 1
        self._active_job = _Job(verb, self._sequence, self._generation, self._stop)
        self._activity = self._activities.begin("startup-authority", "Installed startup: " + verb + "…", replace=True)
        self._busy = True
        self._render()
        self._reader.request()
        return self._busy

    def _prepare(self):
        job = self._active_job
        if job is None or self._closed or job.generation != self._generation or job.stop.is_set():
            raise ValueError("installed-startup-job-retired")
        return partial(_run_backend, job)

    def _apply(self, result):
        if self._closed:
            return
        job = self._active_job
        if job is None:
            return
        if type(result) is not _Result:
            self._finish_unproved(job)
            return
        if (type(result.sequence) is not int or type(result.generation) is not int
                or result.verb != job.verb or result.sequence != job.sequence
                or result.generation != job.generation or job.generation != self._generation):
            return
        if not _valid_view(result.view):
            self._finish_unproved(job)
            return
        self._active_job = None
        self._activities.finish(self._activity)
        self._activity = None
        self._busy = False
        self._revision += 1
        self._view = result.view
        self._render()

    def _finish_unproved(self, job):
        self._activities.finish(self._activity)
        self._activity = None
        self._active_job = None
        self._busy = False
        self._revision += 1
        self._view = _View("status-unproved" if job.verb == "status" else "operation-unproved")
        self._render()

    def _reader_status(self, state):
        if self._closed:
            return
        if state == "unavailable" and self._active_job is not None:
            self._finish_unproved(self._active_job)
        elif state == "updating":
            self._render()

    def _confirm(self, verb, *_args):
        if (verb != "revoke" or self._closed or self._busy or self._reader.busy
                or self._confirmation is not None or not self._allowed(verb)):
            return
        self._consent_sequence += 1
        consent = _Consent(verb, self._generation, self._revision, self._consent_sequence)
        title = "Remove administrator sign-in task?"
        message = (
            "Remove only this verified installed sign-in task? The running application stays open. "
            "Any separate legacy startup entry is preserved and can still start Angerona.")
        dialog = QMessageBox(QMessageBox.Warning, title, message,
                            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, self)
        dialog.setTextFormat(Qt.PlainText)
        dialog.setDefaultButton(QMessageBox.No)
        dialog.setEscapeButton(QMessageBox.Cancel)
        dialog.setModal(False)
        dialog.setWindowModality(Qt.NonModal)
        self._confirmation = dialog
        dialog.finished.connect(partial(self._confirmed, consent, dialog))
        self._render()
        dialog.show()

    def _confirmed(self, consent, dialog, result):
        current = self._confirmation is dialog
        if current:
            self._confirmation = None
        try:
            dialog.deleteLater()
        except RuntimeError:
            pass
        if (not current or self._closed or result != QMessageBox.Yes
                or consent.generation != self._generation or consent.revision != self._revision
                or consent.sequence != self._consent_sequence or self._busy or self._reader.busy
                or not self._allowed(consent.verb)):
            self._render()
            return
        # Recheck both busy states after the modeless user interaction. The
        # immutable verb never reads a mutable button label or config setting.
        self._start(consent.verb)

    @Slot()
    def shutdown(self, *_args):
        if self._closed:
            return
        self._closed = True
        self._activities.close()
        self._activity = None
        self._generation += 1
        self._stop.set()
        self._reader.close()
        dialog, self._confirmation = self._confirmation, None
        if dialog is not None:
            try:
                dialog.reject()
                dialog.deleteLater()
            except RuntimeError:
                pass
        self._active_job = None
        # A backend operation already admitted may finish within its own bounds.
        # Closing this owner drops results; it grants no cleanup/retry authority.

    def closeEvent(self, event):  # noqa: N802
        self.shutdown()
        super().closeEvent(event)
