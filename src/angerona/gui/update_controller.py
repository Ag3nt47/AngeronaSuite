"""One nonblocking controller for manual and optional daily update checks."""
from __future__ import annotations

import threading
import re
import secrets
import time
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal, Qt
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QComboBox, QSpinBox, QDialogButtonBox, QMessageBox, QFileDialog)
from shiboken6 import isValid

from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.gui.action_progress import ActionActivities
from angerona.updater.github_updater import UpdateReport, check_installed_updates
from angerona.updater.source_stage import prepare_source_update


@dataclass(frozen=True)
class _Delivery:
    report: UpdateReport
    origin: str
    epoch: int
    serial: int


def _revoke(event: threading.Event, *_args) -> None:
    """Destruction callback retains only plain cancellation state, never Qt."""
    event.set()


def _read_check(state: Path, root: Path, origin: str, epoch: int, serial: int) -> _Delivery:
    return _Delivery(check_installed_updates(state, root, force=origin == "manual"), origin, epoch, serial)


def _read_stage(root: Path, staging: Path, target: str, cancelled: threading.Event) -> dict:
    try:
        return {"ok": True, "result": prepare_source_update(root, staging, target, cancelled=cancelled.is_set)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "error_type": type(exc).__name__}


class _ActivationConsent:
    """One local consent generation; never a parent lease or mutation capability."""

    def __init__(self, serial: int) -> None:
        self.serial = serial
        self.approval_id = secrets.token_hex(16)
        self.writer_thread = None
        self.api_started = False
        self.proposal_binding = None
        self.decline_proposal = False
        self.cancelled = threading.Event()
        self.writer_done = threading.Event()
        self.writer_done.set()
        self.lock = threading.Lock()
        self.request = None
        self.handoff = False
        self.cancellation_proven = True
        self.cancellation_version = 0
        self.cancellation_processed = -1

    def cancel(self) -> None:
        with self.lock:
            if not self.handoff:
                self.cancelled.set()

    def shutdown_ready(self) -> bool:
        with self.lock:
            return self.writer_done.is_set() and (self.handoff or (
                self.request is None and self.cancellation_proven))


def _cancel_activation_states(states, *_args):
    for state in tuple(states):
        state.cancel()


def _pending_activation_cancellations(states):
    pending = []
    for state in tuple(states):
        with state.lock:
            if (state.cancelled.is_set() and not state.handoff
                    and state.cancellation_processed < state.cancellation_version):
                pending.append(state)
    return tuple(pending)


def _activation_error(serial: int, error: Exception) -> dict:
    source_error = (type(error).__module__ == "angerona.core.source_activation"
                    and type(error).__name__ == "SourceActivationError")
    reason = (str(error)[:2048] if source_error else
              "Source activation could not be verified; the running installation is unchanged.")
    return {"ok": False, "serial": serial, "error_type": type(error).__name__, "reason": reason}


def _read_activation_review(root, state_root, stage, manifest, serial, consent):
    try:
        from angerona.core.source_activation import (
            prepare_source_activation, current_source_activation_context,
        )
        if consent.cancelled.is_set():
            return {"ok": False, "serial": serial, "reason": "Source review was cancelled."}
        preview = prepare_source_activation(root, state_root, stage, manifest,
            cancelled=consent.cancelled.is_set)
        try:
            context = current_source_activation_context(root, state_root)
        except Exception:
            context = None  # A direct launch cannot acquire an external owner here.
        return {"ok": True, "serial": serial, "preview": preview, "context": context}
    except Exception as error:
        return _activation_error(serial, error)


def _read_queued_activation(root, state_root):
    try:
        from angerona.core.source_activation import inspect_source_activation, current_source_activation_context
        snapshot = inspect_source_activation(root, state_root)
        context = None
        if snapshot.get("status") == "queued-reconfirm":
            try:
                context = current_source_activation_context(root, state_root)
            except Exception:
                pass
        return {"snapshot": snapshot, "context": context}
    except Exception as error:
        return {"snapshot": {"status": "held", "reason": _activation_error(0, error)["reason"]}, "context": None}


def _cancel_owned_activation(state_root, consent):
    with consent.lock:
        if consent.handoff:
            return "handoff"
        approval = getattr(consent, "approval_binding", None)
        proven = consent.cancellation_proven and consent.request is None
        proposal = consent.proposal_binding if consent.decline_proposal else None
    status = "absent" if proven else "held"
    if not proven and approval is not None:
        from angerona.core.source_activation import cancel_source_activation_approval
        result = cancel_source_activation_approval(
            state_root, approval["activation_id"], approval["plan_sha256"], consent.approval_id)
        status = result.get("status") if type(result) is dict else "held"
        with consent.lock:
            if status in {"cancelled", "absent"}:
                consent.request = None
                consent.cancellation_proven = True
            else:
                consent.cancellation_proven = False
    if proposal is not None:
        from angerona.core.source_activation import cancel_source_activation_proposal
        result = cancel_source_activation_proposal(state_root, proposal["activation_id"], proposal["plan_sha256"])
        proposal_status = result.get("status") if type(result) is dict else "held"
        with consent.lock:
            if proposal_status in {"cancelled", "absent"}:
                consent.proposal_binding = None
                consent.decline_proposal = False
                if approval is None and consent.request is None:
                    consent.cancellation_proven = True
                    status = "absent"
            else:
                return "proposal-held"  # No source request authority is inferred.
    return status


def _read_activation_request(state_root, preview, context, consent, queued):
    api_started = False
    try:
        from angerona.core.source_activation import (
            approve_source_activation, queue_source_activation_proposal,
        )
        if consent.cancelled.is_set():
            with consent.lock:
                consent.approval_binding = None
                consent.cancellation_proven = True
            return {"ok": False, "serial": consent.serial, "reason": "Source approval was cancelled."}
        api_started = True
        with consent.lock:
            consent.api_started = True
        if queued:
            result = queue_source_activation_proposal(
                state_root, preview["activation_id"], preview["plan_sha256"],
                cancelled=consent.cancelled.is_set)
        else:
            result = approve_source_activation(
                state_root, preview["activation_id"], preview["plan_sha256"], context,
                accepted=True, approval_id=consent.approval_id, cancelled=consent.cancelled.is_set)
            if type(result) is dict and result.get("status") == "requested":
                binding = {key: result.get(key) for key in (
                    "activation_id", "plan_sha256", "request_sha256")}
                if (binding["activation_id"] != preview["activation_id"]
                        or binding["plan_sha256"] != preview["plan_sha256"]
                        or type(binding["request_sha256"]) is not str
                        or not re.fullmatch(r"[0-9a-f]{64}", binding["request_sha256"])):
                    raise ValueError("The durable request binding differs from this approval")
                with consent.lock:
                    consent.request = binding
                    consent.cancellation_proven = False
                if consent.cancelled.is_set():
                    _cancel_owned_activation(state_root, consent)
                    return {"ok": False, "serial": consent.serial, "reason": "Source approval was cancelled."}
        return {"ok": True, "serial": consent.serial, "queued": queued, "result": result}
    except Exception as error:
        if not api_started:
            with consent.lock:
                consent.approval_binding = None
                consent.cancellation_proven = True
        return _activation_error(consent.serial, error)
    finally:
        with consent.lock:
            # A newly completed writer is a new observable cancellation state,
            # including completion after a previous bounded cancellation hold.
            consent.cancellation_version += 1
            consent.writer_done.set()


def _read_activation_cancellation(state_root, states):
    held = False
    for consent in states:
        with consent.lock:
            version = consent.cancellation_version
        try:
            consent.cancel()
            deadline = time.monotonic() + 30
            while not consent.writer_done.wait(.05):
                worker = consent.writer_thread
                if worker is not None and not worker.is_alive():
                    # Exact retirement proves this never-entered writer cannot
                    # publish later. No live writer is inferred from Qt state.
                    with consent.lock:
                        if not consent.api_started:
                            consent.approval_binding = None
                            consent.cancellation_proven = True
                    consent.writer_done.set()
                    break
                if time.monotonic() >= deadline:
                    break
            if not consent.writer_done.is_set():
                held = True
                continue
            with consent.lock:
                version = consent.cancellation_version
            held |= _cancel_owned_activation(state_root, consent) not in {"cancelled", "absent", "handoff"}
        except Exception:
            with consent.lock:
                consent.cancellation_proven = False
            held = True
        finally:
            with consent.lock:
                consent.cancellation_processed = max(consent.cancellation_processed, version)
    return {"held": held}


def _read_storage_review(root, state, serial, cancelled):
    try:
        from angerona.core.source_activation_storage import review_source_update_storage
        return {"ok": True, "serial": serial, "review": review_source_update_storage(root, state, cancelled=cancelled.is_set)}
    except Exception as error:
        return {"ok": False, "serial": serial, "error_type": type(error).__name__}


def _read_storage_action(root, state, action, cancelled):
    try:
        from angerona.core.source_activation_storage import (
            export_source_update_backup, delete_source_update_backup, set_source_update_storage_policy,
        )
        common = dict(accepted=True, cancelled=cancelled.is_set)
        if action["kind"] == "export":
            result = export_source_update_backup(root, state, action["activation_id"], action["review_sha256"],
                destination=action["destination"], **common)
        elif action["kind"] == "delete":
            result = delete_source_update_backup(root, state, action["activation_id"], action["review_sha256"], permanent=True, **common)
        elif action["kind"] == "policy":
            result = set_source_update_storage_policy(root, state, action["review_sha256"], completed_backups=action["completed_backups"],
                max_bytes=action["max_bytes"], **common)
        else:
            raise ValueError("Unknown fixed source storage action")
        return {"ok": True, "result": result}
    except Exception as error:
        return {"ok": False, "error_type": type(error).__name__}


class SourceUpdateStorageDialog(QDialog):
    """One modeless view; actual backend workers remain with UpdateController."""
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.setObjectName("SourceUpdateStorage")
        self.setWindowTitle("Angerona — Source update storage")
        self.setWindowModality(Qt.NonModal)
        self.resize(760, 540)
        self._controller, self._review = controller, None
        layout = QVBoxLayout(self)
        self._totals = QLabel("Review retained source backups. Current, pending, lineage and unknown records stay protected. "
                              "Export is recommended before permanent deletion; no automatic deletion occurs.")
        self._totals.setWordWrap(True)
        self._totals.setTextFormat(Qt.PlainText)
        layout.addWidget(self._totals)
        self._selection = QComboBox(self)
        self._selection.currentIndexChanged.connect(self._selected)
        layout.addWidget(self._selection)
        self._details = QLabel("")
        self._details.setWordWrap(True)
        self._details.setTextFormat(Qt.PlainText)
        layout.addWidget(self._details)
        buttons = QHBoxLayout()
        self._refresh = QPushButton("Review current storage")
        self._export = QPushButton("Export selected backup")
        self._delete = QPushButton("Permanently delete selected backup")
        self._refresh.clicked.connect(controller.review_storage)
        self._export.clicked.connect(self._export_selected)
        self._delete.clicked.connect(self._delete_selected)
        for button in (self._refresh, self._export, self._delete):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        recheck = QPushButton("Recheck prepared update")
        recheck.clicked.connect(controller.recheck_prepared_activation)
        layout.addWidget(recheck)
        limits = QHBoxLayout()
        limits.addWidget(QLabel("Completed backups"))
        self._count = QSpinBox(self)
        self._count.setRange(1, 8)
        self._count.setValue(2)
        limits.addWidget(self._count)
        limits.addWidget(QLabel("Retained limit (MiB)"))
        self._space = QSpinBox(self)
        self._space.setRange(64, 4096)
        self._space.setValue(2048)
        limits.addWidget(self._space)
        self._save = QPushButton("Change retention limits")
        self._save.clicked.connect(self._save_policy)
        limits.addWidget(self._save)
        layout.addLayout(limits)
        self._status = QLabel("Limits hold a new update before STOP; they never silently delete backups.")
        self._status.setWordWrap(True)
        self._status.setTextFormat(Qt.PlainText)
        layout.addWidget(self._status)
        from angerona.gui.action_progress import ActionProgressView
        layout.addWidget(ActionProgressView(controller.activities, self, config=controller._config))
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.close)
        layout.addWidget(close)
        controller.storage_review_ready.connect(self._apply_review)
        controller.storage_action_ready.connect(self._apply_action)
        controller.storage_busy_changed.connect(self._availability)
        self._availability()

    def _question(self, title, text):
        question = QMessageBox(self)
        question.setWindowTitle(title)
        question.setTextFormat(Qt.PlainText)
        question.setWindowModality(Qt.ApplicationModal)
        question.setProperty("_angerona_no_reveal", True)
        question.setProperty("_angerona_security_prompt", True)
        question.setText(text)
        question.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        question.setDefaultButton(QMessageBox.No)
        question.setEscapeButton(QMessageBox.No)
        try:
            return question.exec() == QMessageBox.Yes
        finally:
            if isValid(question):
                question.deleteLater()

    def _row(self):
        row = self._selection.currentData()
        return dict(row) if type(row) is dict else None

    def _selected(self, *_args):
        row = self._row()
        self._details.setText("No completed backup selected." if row is None else
            f"ID: {row['activation_id']}\nRecorded status: {row['status']}\nLogical bytes: {row['logical_bytes']}\n"
            + ("Protected: " + row.get("protected_reason", "unknown-custody") if row["protected"] else "Requires a fresh exact review and explicit confirmation."))
        self._availability()

    def _availability(self, *_args):
        busy = self._controller.storage_busy() or not self._controller.alive()
        row = self._row()
        self._refresh.setEnabled(not busy)
        self._export.setEnabled(not busy and self._review is not None and row is not None and row["export_allowed"] is True)
        self._delete.setEnabled(not busy and self._review is not None and row is not None
                                and row["protected"] is False and row["delete_requires_confirmation"] is True)
        self._save.setEnabled(not busy and self._review is not None and self._review["policy_status"] == "ready")
        self._count.setEnabled(not busy)
        self._space.setEnabled(not busy)

    def _apply_review(self, value):
        if not isValid(self):
            return
        if not value.get("ok"):
            self._review = None
            self._status.setText("Storage review is held or unavailable. No deletion or policy change was performed.")
            self._availability()
            return
        review = value["review"]
        self._review = dict(review)
        self._totals.setText(f"Retained: {review['retained_bytes']} bytes; completed backups: {review['completed_backups']}. "
                            f"Control volume free: {review['free_bytes']} bytes; source volume free: {review['source_free_bytes']} bytes; "
                            f"fixed reserve per required volume: {review['free_reserve_bytes']} bytes.")
        self._selection.clear()
        for row in review["operations"]:
            self._selection.addItem(f"{row['activation_id']} — {row['status']} — {row['logical_bytes']} bytes", dict(row))
        self._count.setValue(review["budget"]["completed_backups"])
        self._space.setValue(review["budget"]["max_bytes"] // (1024 * 1024))
        self._status.setText("An incomplete policy transaction remains held; no default allowance is inferred."
            if review["policy_status"] != "ready" else
            "Review bound to current retained bytes. Changed, active or protected records refuse deletion.")
        self._selected()

    def _export_selected(self):
        row, review = self._row(), self._review
        if row is None or review is None or row["export_allowed"] is not True:
            return
        destination, _filter = QFileDialog.getSaveFileName(
            self, "Export source update backup", "Angerona-source-backup-" + row["activation_id"] + ".zip",
            "ZIP archives (*.zip)", options=QFileDialog.DontConfirmOverwrite)
        if not destination:
            return
        # The chooser selects only an export destination. The worker rechecks
        # exact backup/review binding, local custody, space and no-overwrite.
        if self._question("Export source update backup",
            f"Export verified backup {row['activation_id']} ({row['logical_bytes']} logical bytes) to:\n"
            f"{destination}\n\nThe ZIP is written directly on that destination volume. "
            "An existing file is never overwritten; the original backup remains retained. Continue?"):
            self._controller.storage_action("export", review["review_sha256"], row["activation_id"],
                                            accepted=True, destination=destination)

    def _delete_selected(self):
        row, review = self._row(), self._review
        if row is None or review is None or row["protected"] or row["delete_requires_confirmation"] is not True:
            return
        if self._question("Permanently delete source update backup",
            f"Permanently delete backup {row['activation_id']} ({row['logical_bytes']} logical bytes)?\n\n"
            "This removes retained rollback/archive data and cannot be undone through Angerona. "
            "Export is recommended first, but is not required for your explicit permanent-delete choice. "
            "Current source, active updates, lineage, settings and custom data stay protected. Continue?"):
            self._controller.storage_action("delete", review["review_sha256"], row["activation_id"], accepted=True)

    def _save_policy(self):
        if self._review is None:
            return
        count, maximum = self._count.value(), self._space.value() * 1024 * 1024
        if self._question("Change source update retention limits",
            f"Keep at most {count} completed backups within {maximum} logical bytes?\n\n"
            "Existing backups are not deleted automatically. New updates hold before STOP when capacity is unavailable. "
            "The fixed free-space reserve and protection rules remain required."):
            self._controller.storage_action("policy", self._review["review_sha256"], accepted=True,
                                            completed_backups=count, max_bytes=maximum)

    def _apply_action(self, value):
        if not isValid(self):
            return
        if not value.get("ok"):
            self._status.setText("Storage action held. Review exact retained state before retrying.")
        else:
            result = value["result"]
            status = result.get("status")
            if status == "exported":
                self._status.setText("Verified private backup export: " + str(result.get("path", "")))
            elif status == "deleted":
                self._status.setText(f"Deleted {result['deleted_files']} verified files ({result['deleted_bytes']} bytes).")
            elif status == "changed":
                self._status.setText("Retention policy changed. Existing backups were preserved.")
            elif status == "declined":
                self._status.setText("Action declined; retained data was preserved.")
            else:
                self._status.setText("Storage action held or partial. Its private progress receipt is preserved; no complete deletion is claimed.")
        self._review = None
        self._availability()
        self._controller.review_storage()

    def closeEvent(self, event):
        self._controller.cancel_storage_action()
        event.accept()  # Parent retains this one reusable view and all actual workers.


class UpdateController(QObject):
    report_ready = Signal(object)
    update_available = Signal(object)
    candidate_ready = Signal(object)
    activation_ready = Signal(object)
    activation_held = Signal(str)
    activation_request_ready = Signal(object)
    storage_review_ready = Signal(object)
    storage_action_ready = Signal(object)
    storage_busy_changed = Signal(bool)
    status_changed = Signal(str)
    check_busy_changed = Signal(bool)

    def __init__(self, config, source_root: Path, parent=None) -> None:
        super().__init__(parent)
        self.activities = ActionActivities(self)
        self._check_activity = None
        self._download_activity = None
        self._config = config
        self._source_root = Path(source_root)
        self._last_report: UpdateReport | None = None
        self._last_origin = ""
        self._last_epoch = -1
        self._serial = 0
        self._last_serial = -1
        self._origin = "daily"
        self._epoch = 0
        self._manual_claimed = False
        self._daily_allowed = bool(getattr(config, "github_daily_check_enabled", False))
        self._target = ""
        self._closed = False
        self._cancelled = threading.Event()
        self.destroyed.connect(partial(_revoke, self._cancelled))
        self._check = AsyncSnapshot(self, self._prepare_check, self._apply_report,
                                    name="GitHub Update Check", status=self._check_status)
        self._download = AsyncSnapshot(self, self._prepare_download, self._apply_candidate,
                                       name="GitHub Source Candidate", status=self._download_status)
        self._activation_serial = 0
        self._activation_stage = None
        self._activation_preview = None
        self._activation_context = None
        self._activation_states = []
        self.destroyed.connect(partial(_cancel_activation_states, self._activation_states))
        self._activation_consent = None
        self._activation_mode_queued = False
        self._activation_review = AsyncSnapshot(self, self._prepare_activation_review,
            self._apply_activation_review, name="Source Activation Review")
        self._activation_request = AsyncSnapshot(self, self._prepare_activation_request,
            self._apply_activation_request, name="Source Activation Approval")
        self._activation_cancel = AsyncSnapshot(self, self._prepare_activation_cancel,
            self._apply_activation_cancel, name="Source Activation Revocation")
        self._activation_resume = AsyncSnapshot(self,
            lambda: partial(_read_queued_activation, self._source_root, self._activation_state_root()),
            self._apply_queued_activation, name="Queued Source Activation Review")
        self._storage_serial = 0
        self._last_storage_review = None
        self._storage_action_data = None
        self._storage_cancelled = threading.Event()
        self.destroyed.connect(partial(_revoke, self._storage_cancelled))
        self._storage_activity = None
        self._storage_review_reader = AsyncSnapshot(self, self._prepare_storage_review,
            self._apply_storage_review, name="Source Update Storage Review")
        self._storage_action_reader = AsyncSnapshot(self, self._prepare_storage_action,
            self._apply_storage_action, name="Source Update Storage Action")
        self._activation_initial = QTimer(self)
        self._activation_initial.setSingleShot(True)
        self._activation_initial.setInterval(5000)
        self._activation_initial.timeout.connect(self._activation_resume.request)
        self._activation_initial.start()
        self._timer = QTimer(self)
        self._timer.setInterval(60 * 60 * 1000)
        self._timer.timeout.connect(self.check_daily)
        self._initial = QTimer(self)
        self._initial.setSingleShot(True)
        self._initial.setInterval(5000)
        self._initial.timeout.connect(self.check_daily)
        if self._daily_allowed:
            self._timer.start()
            self._initial.start()

    def alive(self) -> bool:
        return not self._closed and not self._cancelled.is_set() and isValid(self)

    def set_daily_preference(self, enabled: bool) -> None:
        """Suspend automatic delivery immediately while an opt-out is staged."""
        if not self.alive():
            return
        enabled = enabled is True
        if enabled != self._daily_allowed:
            self._epoch += 1
            self._daily_allowed = enabled
        if enabled:
            if not self._timer.isActive():
                self._timer.start()
        else:
            self._timer.stop()
            self._initial.stop()

    def preferences_changed(self, *, check_due: bool = True) -> None:
        if not self.alive():
            return
        self.set_daily_preference(bool(getattr(self._config, "github_daily_check_enabled", False)))
        if check_due:
            self.check_daily()

    def check_daily(self) -> None:
        if (self.alive() and self._daily_allowed
                and bool(getattr(self._config, "github_daily_check_enabled", False)) and not self._check.busy):
            self._origin = "daily"
            self._manual_claimed = False
            self._check.request()

    def check_now(self) -> None:
        if not self.alive():
            return
        self._check_activity = self.activities.begin("manual-check", "Checking canonical GitHub metadata…")
        if self._check.busy:
            self._manual_claimed = True
            return
        self._origin = "manual"
        self._manual_claimed = True
        self._check.request()

    def _prepare_check(self):
        self._serial += 1
        return partial(_read_check, Path(self._config.data_dir) / "github-updates",
                       self._source_root, self._origin, self._epoch, self._serial)

    def prompt_eligible(self, report: UpdateReport) -> bool:
        return (self.alive() and report is self._last_report and self._last_serial == self._serial
                and (self._last_origin == "manual" or (
                    self._last_epoch == self._epoch and self._daily_allowed
                    and bool(getattr(self._config, "github_daily_check_enabled", False)))))

    def manual_report(self, report: UpdateReport) -> bool:
        return self.prompt_eligible(report) and self._last_origin == "manual"

    def _apply_report(self, delivery: _Delivery) -> None:
        if not self.alive() or delivery.serial != self._serial:
            return
        self.check_busy_changed.emit(False)
        if not self.alive() or delivery.serial != self._serial:
            return  # A reentrant receiver started a newer operation or closed us.
        manual = self._manual_claimed or delivery.origin == "manual"
        self._manual_claimed = False
        if manual and delivery.origin == "daily" and delivery.report.status == "not_due":
            # The automatic operation did not fetch. Honor the manual intent
            # through ONE normal force=True attempt, retaining the 60s floor.
            self._origin = "manual"
            self._manual_claimed = True
            self._check.request(invalidate=True)
            return
        if not manual and (delivery.epoch != self._epoch or not self._daily_allowed
                           or not bool(getattr(self._config, "github_daily_check_enabled", False))):
            if not self._download.busy:
                self.status_changed.emit("Automatic update check completed after opt-out; no report or prompt was delivered.")
            return
        report = delivery.report
        self._last_report = report
        self._last_origin = "manual" if manual else "daily"
        self._last_epoch = delivery.epoch
        self._last_serial = delivery.serial
        self.status_changed.emit(report.summary())
        if not self.prompt_eligible(report):
            return
        self.report_ready.emit(report)
        if self.prompt_eligible(report) and report.available:
            self.update_available.emit(report)

    def download_source_candidate(self, revision: str) -> None:
        if not self.alive() or self._download.busy:
            return
        report = self._last_report
        if (report is None or not self.prompt_eligible(report)
                or revision != report.remote_revision or report.source_status != "different"):
            self.status_changed.emit("No observed source revision is eligible for preparation.")
            return
        self._target = revision
        self._download_activity = self.activities.begin("source-candidate", "Preparing isolated source update candidate…", replace=True)
        self._download.request()

    def _prepare_download(self):
        return partial(_read_stage, self._source_root,
                       Path(self._config.data_dir) / "github-updates" / "stages",
                       self._target, self._cancelled)

    def _apply_candidate(self, value: dict) -> None:
        if self.alive():
            self.candidate_ready.emit(value)

    def _check_status(self, status: str) -> None:
        if not self.alive():
            return
        if status == "updating":
            serial = self._serial
            self.check_busy_changed.emit(True)
            if self.alive() and serial == self._serial:
                self.status_changed.emit("Checking canonical GitHub metadata in the background…")
        elif status == "unavailable":
            self.activities.finish(self._check_activity)
            self._check_activity = None
            serial = self._serial
            self.check_busy_changed.emit(False)
            if self.alive() and serial == self._serial:
                self.status_changed.emit("The update check could not complete; update status is unknown.")
        elif status == "current":
            self.activities.finish(self._check_activity)
            self._check_activity = None

    def _download_status(self, status: str) -> None:
        if not self.alive():
            return
        if status == "updating":
            self.status_changed.emit("Preparing an isolated source candidate and preserving user edits…")
        elif status == "unavailable":
            self.activities.finish(self._download_activity)
            self._download_activity = None
            self.status_changed.emit("Source preparation failed; the original installation is unchanged.")
        elif status == "current":
            self.activities.finish(self._download_activity)
            self._download_activity = None


    def storage_busy(self):
        return self._storage_review_reader.busy or self._storage_action_reader.busy

    def review_storage(self):
        if not self.alive() or self._storage_action_reader.busy:
            return False
        self._storage_cancelled.clear()
        self._storage_serial += 1
        self._storage_activity = self.activities.begin("source-update-storage", "Reviewing retained source update data…", replace=True)
        self._storage_review_reader.request(invalidate=True)
        self.storage_busy_changed.emit(self.storage_busy())
        return self._storage_review_reader.busy

    def _prepare_storage_review(self):
        return partial(_read_storage_review, self._source_root, self._activation_state_root(),
                       self._storage_serial, self._storage_cancelled)

    def _apply_storage_review(self, value):
        self.activities.finish(self._storage_activity)
        self._storage_activity = None
        if not self.alive() or type(value) is not dict or value.get("serial") != self._storage_serial:
            return
        review = value.get("review")
        valid = (value.get("ok") is True and type(review) is dict
                 and review.get("schema") == "angerona.source-activation-storage-review/v1"
                 and review.get("policy_status") in {"ready", "held-incomplete-policy"}
                 and review.get("automatic_deletion") is False and review.get("startup_inhibited") is False
                 and type(review.get("same_volume")) is bool
                 and review.get("source_root") == str(self._source_root)
                 and review.get("state_root") == str(self._activation_state_root())
                 and type(review.get("review_sha256")) is str
                 and re.fullmatch(r"[0-9a-f]{64}", review["review_sha256"]) is not None
                 and type(review.get("operations")) is list and len(review["operations"]) <= 8192
                 and type(review.get("budget")) is dict)
        if valid:
            valid = (type(review["budget"].get("completed_backups")) is int
                     and 1 <= review["budget"]["completed_backups"] <= 8
                     and type(review["budget"].get("max_bytes")) is int
                     and 64 * 1024**2 <= review["budget"]["max_bytes"] <= 4 * 1024**3
                     and all(type(review.get(key)) is int and review[key] >= 0
                             for key in ("retained_bytes", "completed_backups", "free_bytes", "source_free_bytes", "free_reserve_bytes")))
        if valid:
            for row in review["operations"]:
                if (type(row) is not dict or type(row.get("activation_id")) is not str
                        or re.fullmatch(r"[0-9a-f]{32}", row["activation_id"]) is None
                        or type(row.get("logical_bytes")) is not int or row["logical_bytes"] < 0
                        or any(type(row.get(key)) is not bool for key in ("protected", "export_allowed", "delete_requires_confirmation"))
                        or type(row.get("status")) is not str or len(row["status"]) > 80
                        or type(row.get("protected_reason")) is not str or len(row["protected_reason"]) > 80):
                    valid = False
                    break
        self._last_storage_review = review if valid else None
        self.storage_review_ready.emit({"ok": valid, "review": review if valid else None})
        self.storage_busy_changed.emit(self.storage_busy())

    def storage_action(self, kind, review_sha, activation_id=None, *, accepted=False,
                       completed_backups=None, max_bytes=None, destination=None):
        if (accepted is not True or not self.alive() or self.storage_busy()
                or self._activation_request.busy or any(state.handoff for state in self._activation_states)
                or self._last_storage_review is None or review_sha != self._last_storage_review["review_sha256"]
                or kind not in {"export", "delete", "policy"}):
            return False
        action = {"kind": kind, "review_sha256": review_sha}
        if kind != "policy":
            rows = [row for row in self._last_storage_review["operations"] if row["activation_id"] == activation_id]
            if len(rows) != 1 or (kind == "delete" and (rows[0]["protected"] or not rows[0]["delete_requires_confirmation"])):
                return False
            if kind == "export" and not rows[0]["export_allowed"]:
                return False
            action["activation_id"] = activation_id
            if kind == "export":
                if (type(destination) is not str or not destination or len(destination) > 32760
                        or "\x00" in destination or not Path(destination).is_absolute()
                        or destination.startswith(("\\\\", "//"))
                        or Path(destination).suffix.lower() != ".zip"):
                    return False
                action["destination"] = destination
        else:
            if self._last_storage_review["policy_status"] != "ready":
                return False
            if (type(completed_backups) is not int or not 1 <= completed_backups <= 8
                    or type(max_bytes) is not int or not 64 * 1024**2 <= max_bytes <= 4 * 1024**3):
                return False
            action.update(completed_backups=completed_backups, max_bytes=max_bytes)
        self._storage_cancelled.clear()
        self._storage_action_data = action
        self._storage_activity = self.activities.begin("source-update-storage", "Settling the exact requested storage action…", replace=True)
        self._storage_action_reader.request()
        self.storage_busy_changed.emit(self.storage_busy())
        return self._storage_action_reader.busy

    def _prepare_storage_action(self):
        return partial(_read_storage_action, self._source_root, self._activation_state_root(),
                       dict(self._storage_action_data), self._storage_cancelled)

    def _apply_storage_action(self, value):
        self.activities.finish(self._storage_activity)
        self._storage_activity = None
        self._last_storage_review = None
        if self.alive():
            self.storage_action_ready.emit(value if type(value) is dict else {"ok": False})
            self.storage_busy_changed.emit(self.storage_busy())

    def cancel_storage_action(self):
        self._storage_cancelled.set()


    def recheck_prepared_activation(self):
        if self._activation_stage is None:
            self.status_changed.emit("Prepare a source candidate before requesting activation review.")
            return False
        from types import SimpleNamespace
        return self.review_source_candidate(SimpleNamespace(stage_id=self._activation_stage[0],
            manifest_sha256=self._activation_stage[1]))

    def _activation_state_root(self):
        return Path(self._config.data_dir) / "github-updates"

    def _activation_current(self, serial):
        consent = self._activation_consent
        return (self.alive() and type(serial) is int and serial == self._activation_serial
                and consent is not None and consent.serial == serial
                and not consent.cancelled.is_set())

    def _new_activation_consent(self):
        # A synchronous STOP handoff may enter a modal error path. Reentrant
        # review cannot discard that exact consent before its owner revokes it.
        if any(state.handoff for state in self._activation_states):
            self.status_changed.emit("An approved source STOP handoff is still settling.")
            return None
        # Old generations remain strongly retained until cancellation is proved.
        for state in self._activation_states:
            state.cancel()
        self._activation_states[:] = [state for state in self._activation_states
                                      if not state.shutdown_ready()]
        if len(self._activation_states) >= 4:
            self.status_changed.emit("An earlier source approval is still settling; activation is held.")
            return None
        self._activation_serial += 1
        consent = _ActivationConsent(self._activation_serial)
        self._activation_states.append(consent)
        self._activation_consent = consent
        self._activation_preview = self._activation_context = None
        if any(state.cancelled.is_set() for state in self._activation_states):
            self._activation_cancel.request()
        return consent

    def review_source_candidate(self, result):
        """Review a real StageResult on a worker; this never stops the app."""
        if not self.alive() or self._activation_review.busy or self._activation_request.busy:
            return False
        stage, manifest = getattr(result, "stage_id", None), getattr(result, "manifest_sha256", None)
        if (type(stage) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", stage)
                or type(manifest) is not str or not re.fullmatch(r"[0-9a-f]{64}", manifest)):
            self.status_changed.emit("The source candidate has no immutable manifest binding; activation is held.")
            return False
        if self._new_activation_consent() is None:
            return False
        self._activation_stage = (stage, manifest)
        self.status_changed.emit("Verifying the immutable source plan and current launch controller…")
        self._activation_review.request()
        return True

    def _prepare_activation_review(self):
        consent = self._activation_consent
        if not self._activation_current(consent.serial) or self._activation_stage is None:
            raise RuntimeError("No current source review")
        return partial(_read_activation_review, self._source_root, self._activation_state_root(),
                       *self._activation_stage, consent.serial, consent)

    @staticmethod
    def _valid_activation_preview(value, root):
        if (type(value) is not dict or type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("status") not in {"ready", "queued-reconfirm", "requested"}
                or value.get("source_root") != str(root)
                or value.get("dependencies_compatible") is not True
                or type(value.get("conflicts")) is not int or value["conflicts"] != 0
                or type(value.get("preserved_changes")) is not int
                or not 0 <= value["preserved_changes"] <= 8192):
            return False
        for key, length in (("activation_id", 32), ("plan_sha256", 64),
                ("manifest_sha256", 64), ("resolution_sha256", 64),
                ("original_inventory_sha256", 64), ("original_head", 40), ("target_revision", 40)):
            if type(value.get(key)) is not str or not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value[key]):
                return False
        paths = value.get("changed_paths")
        return (type(paths) is list and 0 < len(paths) <= 8192
                and all(type(path) is str and 0 < len(path) <= 4096 and "\0" not in path
                        for path in paths))

    def _activation_projection(self):
        preview = self._activation_preview
        keys = ("activation_id", "plan_sha256", "stage_id", "manifest_sha256",
                "resolution_sha256", "original_inventory_sha256", "original_head",
                "target_revision", "base_revision", "source_root", "preserved_changes", "changed_paths")
        projection = {key: preview.get(key) for key in keys}
        projection["changed_paths"] = tuple(preview["changed_paths"])
        projection.update(serial=self._activation_serial, supervised=self._activation_context is not None)
        return projection  # Deliberately excludes launch context and its private token.

    def _apply_activation_review(self, value):
        if type(value) is not dict or not self._activation_current(value.get("serial")):
            return
        if not value.get("ok") or not self._valid_activation_preview(value.get("preview"), self._source_root):
            reason = str(value.get("reason", "Source activation review is held; the running installation is unchanged."))[:2048]
            self.status_changed.emit(reason)
            self.activation_held.emit(reason)
            return
        self._activation_preview = dict(value["preview"])
        context = value.get("context")
        self._activation_context = dict(context) if type(context) is dict else None
        self.activation_ready.emit(self._activation_projection())

    def approve_activation(self, serial, *, accepted):
        if accepted is not True or not self._activation_current(serial) or self._activation_request.busy or self._activation_cancel.busy or self._storage_action_reader.busy:
            return False
        if not self._valid_activation_preview(self._activation_preview, self._source_root):
            return False
        consent = self._activation_consent
        with consent.lock:
            if consent.handoff or consent.request is not None or not consent.writer_done.is_set():
                return False
        consent.writer_done.clear()
        with consent.lock:
            consent.approval_binding = {key: self._activation_preview[key]
                                       for key in ("activation_id", "plan_sha256")}
            consent.cancellation_proven = False
        self._activation_mode_queued = self._activation_context is None
        self.status_changed.emit("Recording exact source-update consent; the app remains running until handoff…")
        self._activation_request.request()
        consent.writer_thread = self._activation_request.thread
        # A rejected snapshot admission must not manufacture a completed writer.
        if not self._activation_request.busy:
            consent.writer_done.set()
            self.status_changed.emit("Source approval admission is held.")
            return False
        return True

    def decline_activation(self, serial):
        if self._activation_current(serial):
            with self._activation_consent.lock:
                self._activation_consent.decline_proposal = True
                if self._activation_consent.proposal_binding is not None:
                    self._activation_consent.cancellation_proven = False
            self._activation_consent.cancel()
            self._activation_cancel.request()

    def _prepare_activation_request(self):
        consent = self._activation_consent
        if not self._activation_current(consent.serial):
            raise RuntimeError("Source approval is no longer current")
        return partial(_read_activation_request, self._activation_state_root(),
                       dict(self._activation_preview), self._activation_context,
                       consent, self._activation_mode_queued)

    def _apply_activation_request(self, value):
        serial = value.get("serial") if type(value) is dict else None
        if not self._activation_current(serial):
            self._activation_cancel.request()
            return
        consent = self._activation_consent
        if not value.get("ok"):
            self.status_changed.emit("Source approval is held; no restart was requested.")
            consent.cancel()
            self._activation_cancel.request()
            return
        result = value.get("result")
        if type(result) is dict and result.get("status") == "queued-reconfirm" and value.get("queued") is True:
            with consent.lock:
                consent.cancellation_proven = True
            self.status_changed.emit("Source update queued for review on the next canonical launch; this app remains running.")
            return
        if type(result) is not dict or result.get("status") != "requested" or value.get("queued") is not False:
            consent.cancel()
            self._activation_cancel.request()
            return
        delivery = {key: result.get(key) for key in ("activation_id", "plan_sha256", "request_sha256")}
        delivery["serial"] = serial
        self.activation_request_ready.emit(delivery)
        # Only the current synchronous MainWindow receiver may retain consent
        # for its actual normal STOP. A late/unhandled delivery is cancelled.
        with consent.lock:
            handed_off = consent.handoff
        if not handed_off:
            consent.cancel()
            self._activation_cancel.request()

    def accept_activation_handoff(self, value):
        if type(value) is not dict or not self._activation_current(value.get("serial")):
            return None
        consent, context = self._activation_consent, self._activation_context
        if type(context) is not dict:
            return None
        with consent.lock:
            binding = {key: value.get(key) for key in ("activation_id", "plan_sha256", "request_sha256")}
            if consent.cancelled.is_set() or consent.request != binding or not consent.writer_done.is_set():
                return None
            consent.handoff = True
        return {"launch_id": context["launch_id"], "activation_id": binding["activation_id"],
                "request_sha256": binding["request_sha256"], "core_pid": context["core_pid"],
                "core_birth": context["core_birth"]}

    def reject_activation_handoff(self, value):
        if type(value) is not dict or type(value.get("serial")) is not int:
            return
        for consent in self._activation_states:
            if consent.serial != value["serial"]:
                continue
            with consent.lock:
                expected = {key: value.get(key) for key in ("activation_id", "plan_sha256", "request_sha256")}
                if consent.request != expected:
                    return
                consent.handoff = False
            consent.cancel()
            self._activation_cancel.request()
            return

    def _prepare_activation_cancel(self):
        return partial(_read_activation_cancellation, self._activation_state_root(),
                       _pending_activation_cancellations(self._activation_states))

    def _apply_activation_cancel(self, result):
        if type(result) is dict and result.get("held") is True and self.alive():
            self.status_changed.emit("An earlier source approval remains held until exact cancellation is verified.")
        if _pending_activation_cancellations(self._activation_states):
            # A later cancelled generation may arrive after the worker took
            # its snapshot. Drain that new state before closing on STOP.
            # Already-processed held failures are never automatic retries.
            self._activation_cancel.request()
        elif self._closed:
            self._activation_cancel.close()

    def _apply_queued_activation(self, value):
        if not self.alive() or type(value) is not dict or type(value.get("snapshot")) is not dict:
            return
        result = value["snapshot"]
        if result.get("status") in {"requested", "held"}:
            self.status_changed.emit(str(result.get("reason", "An earlier source update remains held for exact review; no STOP was requested."))[:2048])
            return
        if result.get("status") != "queued-reconfirm" or self._activation_review.busy or self._activation_request.busy:
            return
        if not self._valid_activation_preview(result, self._source_root):
            self.status_changed.emit("Queued source review is incomplete; no approval was inferred.")
            return
        if type(value.get("context")) is not dict:
            self.status_changed.emit("Saved source update awaits a verified canonical launch owner and fresh confirmation.")
            return
        consent = self._new_activation_consent()
        if consent is None:
            return
        consent.proposal_binding = {key: result[key] for key in ("activation_id", "plan_sha256")}
        self._activation_stage = (result["stage_id"], result["manifest_sha256"])
        self._activation_preview = dict(result)
        self._activation_context = dict(value["context"])
        self.activation_ready.emit(self._activation_projection())

    def owned_workers(self):
        snapshots = (self._check, self._download, self._activation_review, self._activation_request,
                     self._activation_cancel, self._activation_resume,
                     self._storage_review_reader, self._storage_action_reader)
        return tuple(snapshot.thread for snapshot in snapshots if snapshot.thread is not None)

    def activation_custody_released(self):
        return all(state.shutdown_ready() for state in self._activation_states)

    def close(self, *_args) -> None:
        if self._closed:
            return
        self._closed = True
        self.activities.close()
        self._cancelled.set()
        for timer in (self._timer, self._initial, self._activation_initial):
            if isValid(timer):
                timer.stop()
        self._check.close()
        self._download.close()
        for state in self._activation_states:
            state.cancel()
        self._storage_cancelled.set()
        self._storage_review_reader.close()
        self._storage_action_reader.close()
        self._activation_review.close()
        self._activation_request.close()
        self._activation_resume.close()
        # Keep cancellation alive until its exact backend operation returns.
        if self._activation_states:
            self._activation_cancel.request()
        else:
            self._activation_cancel.close()
