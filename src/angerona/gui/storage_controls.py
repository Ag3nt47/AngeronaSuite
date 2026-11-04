"""Storage choices from cached recovery state and one asynchronous volume probe."""
from __future__ import annotations

import ntpath
import os
import shutil
import tempfile
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QGridLayout, QGroupBox, QLabel, QMessageBox,
    QPushButton, QSpinBox, QVBoxLayout,
)

from angerona.gui.async_snapshot import AsyncSnapshot


MIB = 1024 * 1024


def _volume_label(path: Path) -> str:
    drive, _tail = ntpath.splitdrive(str(path))
    return drive + "\\" if drive else str(path)


def _collect_volume_capacity(data_root: Path, reserve: int) -> tuple[dict, int | None]:
    """Read two known locations without walking either tree; worker use only.

    Device identity deduplicates locations on the same filesystem, including
    aliases. Failed identity or capacity queries remain explicit unknown rows.
    """
    candidates = [("Runtime data", data_root)]
    rows, devices = [], {}
    try:
        candidates.append(("Temporary files", Path(tempfile.gettempdir())))
    except OSError as exc:
        rows.append({"label": "temporary-files volume", "scopes": ["Temporary files"],
                     "free": None, "error": type(exc).__name__})
    for scope, path in candidates:
        label = _volume_label(path)
        try:
            identity = int(os.stat(path).st_dev)
        except OSError as exc:
            rows.append({"label": label, "scopes": [scope],
                         "free": None, "error": type(exc).__name__})
            continue
        if identity and identity in devices:
            devices[identity]["scopes"].append(scope)
            continue
        row = {"label": label, "scopes": [scope], "free": None, "error": ""}
        rows.append(row)
        if identity:
            devices[identity] = row
        try:
            row["free"] = shutil.disk_usage(path).free
        except OSError as exc:
            row["error"] = type(exc).__name__
    low = [row for row in rows if row["free"] is not None and row["free"] <= reserve]
    unknown = [row for row in rows if row["free"] is None]
    known = [row for row in rows if row["free"] is not None]
    selected = (min(low, key=lambda row: row["free"]) if low else unknown[0] if unknown
                else min(known, key=lambda row: row["free"]))
    descriptions = []
    gaps = []
    for row in rows:
        scope = " and ".join(row["scopes"])
        amount = f"{row['free'] / MIB:.0f} MiB free" if row["free"] is not None else "capacity unavailable"
        descriptions.append(f"{scope} on {row['label']}: {amount}")
        if row["error"]:
            gaps.append(f"{scope} capacity unavailable ({row['error']})")
    return {
        "volume_label": selected["label"],
        "volume_scopes": tuple(selected["scopes"]),
        "volume_summary": "; ".join(descriptions),
        "volume_gaps": tuple(gaps),
    }, selected["free"]


def shadow_module(manager):
    return getattr(manager, "modules", {}).get("Shadow Shield")


def apply_storage_policy(module, config) -> None:
    if module is not None:
        module.configure_storage_policy(
            cache_enabled=config.shadow_cache_enabled,
            vss_enabled=config.shadow_vss_enabled,
            max_mib=config.shadow_cache_max_mib,
            min_free_mib=config.shadow_min_free_mib,
        )


def storage_warning(status: dict, free_bytes: int | None, reserve_bytes: int) -> str:
    """Stable warning category; changing byte counts must not create popup storms."""
    if free_bytes is not None and free_bytes <= reserve_bytes:
        return "drive-low"
    if status.get("held") and status.get("cache_enabled", True):
        return "cache-held"
    used, limit = status.get("used_bytes"), status.get("limit_bytes")
    if status.get("cache_enabled", True) and type(used) is int and type(limit) is int and limit > 0 and used >= limit * .8:
        return "cache-near-limit"
    if free_bytes is None:
        return "drive-unavailable"
    return ""


def _cleanup_text(status: dict) -> str:
    pending = bool(status.get("cleanup_pending"))
    report = status.get("cleanup_report")
    if not isinstance(report, dict):
        return "Deletion queued or running; wait for completion" if pending else ""
    files, size = report.get("removed_files"), report.get("removed_bytes")
    measured = type(files) is int and files >= 0 and type(size) is int and size >= 0
    progress = f"removed {files:,} files ({size / MIB:.1f} MiB)" if measured else "removal totals unavailable"
    # A prior terminal report cannot attest a newly queued request. Pending
    # always wins over a complete flag until maintenance publishes its result.
    if pending:
        if report.get("complete") is True:
            return "Deletion queued or running; wait for completion"
        state = "Deletion running" if measured and files else "Deletion queued or running"
        return f"{state}: {progress}; wait for completion"
    if report.get("complete") is True and measured:
        return f"Deletion complete: {progress}"
    reason = str(report.get("reason") or "completion was not verified")[:500]
    return f"Deletion incomplete: {progress}; {reason}"


def _usage_text(status: dict) -> str:
    used, limit = status.get("used_bytes"), status.get("limit_bytes")
    text = "Recovery usage is not measured yet."
    if type(used) is int and type(limit) is int:
        text = f"Recovery copies: {used / MIB:.1f} / {limit / MIB:.0f} MiB"
        if not status.get("inventory_complete", True):
            text += " (incomplete inventory; copying held)"
    if status.get("reason"):
        text += f". {str(status['reason'])[:500]}"
    cleanup = _cleanup_text(status)
    if cleanup:
        text = text.rstrip(".") + ". " + cleanup + "."
    return text


def confirm_cache_cleanup(parent, module, completed=None, before_request=None, *, still_current=None):
    """Queue only after an explicit second choice; all file work stays in worker."""
    dialog = QMessageBox(QMessageBox.Warning, "Delete recovery copies?",
        "This permanently deletes Shadow Shield's cached file versions and removes "
        "those restore points. It does not delete your original Documents/Desktop "
        "files, Windows shadow copies, alerts, evidence or other temporary files.",
        QMessageBox.Yes | QMessageBox.No, parent)
    dialog.setDefaultButton(QMessageBox.No)
    dialog.setTextFormat(Qt.PlainText)
    dialog.setEscapeButton(QMessageBox.No)
    if still_current is not None:
        dialog.setProperty("_angerona_no_reveal", True)
    def finished(result):
        accepted = False
        if (result == QMessageBox.Yes and module is not None
                and (still_current is None or still_current())):
            if before_request is not None:
                before_request()
            accepted = bool(module.request_cache_cleanup())
        if completed is not None:
            completed(accepted)
        dialog.deleteLater()
    dialog.finished.connect(finished)
    # QDialog.open() is asynchronous but still makes its parent window modal.
    # A pending deletion choice must leave dashboard and shutdown controls usable.
    dialog.setWindowModality(Qt.NonModal)
    dialog.show()
    return dialog


class StorageControls(QGroupBox):
    """Settings fields; expensive collection/deletion never occurs in this widget."""

    def __init__(self, config, manager=None, parent=None):
        super().__init__("Drive space and recovery data", parent)
        self._config, self._manager = config, manager
        self._confirmation = None
        layout = QVBoxLayout(self)
        from angerona.gui.action_progress import ActionActivities, ActionProgressView
        self._activities = ActionActivities(self, publish_global=False)
        self._cleanup_activity = None
        self._cleanup_module = None
        self.progress_view = ActionProgressView(self._activities, self, config=config)
        layout.addWidget(self.progress_view)
        explanation = QLabel(
            "Shadow Shield saves earlier Documents/Desktop versions for ransomware "
            "recovery. New copies stop at the total limit or free-space reserve. "
            "A warning offers block, delete or change-limit choices. Existing copies "
            "are preserved until you explicitly delete them.")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.cache_enabled = QCheckBox("Allow bounded recovery copies")
        self.cache_enabled.setChecked(config.shadow_cache_enabled)
        layout.addWidget(self.cache_enabled)
        grid = QGridLayout()
        self.max_mib = QSpinBox()
        self.max_mib.setRange(64, 16384)
        self.max_mib.setSuffix(" MiB")
        self.max_mib.setValue(config.shadow_cache_max_mib)
        self.min_free_mib = QSpinBox()
        self.min_free_mib.setRange(512, 65536)
        self.min_free_mib.setSuffix(" MiB")
        self.min_free_mib.setValue(config.shadow_min_free_mib)
        grid.addWidget(QLabel("Total recovery cache limit:"), 0, 0)
        grid.addWidget(self.max_mib, 0, 1)
        grid.addWidget(QLabel("Keep at least this much drive space free:"), 1, 0)
        grid.addWidget(self.min_free_mib, 1, 1)
        layout.addLayout(grid)
        self.vss_enabled = QCheckBox("Also request automatic Windows shadow copies (advanced)")
        self.vss_enabled.setChecked(config.shadow_vss_enabled)
        layout.addWidget(self.vss_enabled)
        note = QLabel(
            "Windows shadow storage has a separate Windows-managed quota and can grow "
            "after a snapshot. Automatic snapshots are off by default. Configure and "
            "review Windows shadow storage before enabling. Temporary files, diagnostic "
            "logs and protected evidence are never blanket-deleted by this control.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.usage = QLabel()
        self.usage.setTextFormat(Qt.PlainText)
        self.usage.setWordWrap(True)
        layout.addWidget(self.usage)
        actions = QGridLayout()
        self.block_button = QPushButton("Block new recovery data")
        self.delete_button = QPushButton("Delete recovery copies…")
        self.block_button.clicked.connect(self._block)
        self.delete_button.clicked.connect(self._delete)
        actions.addWidget(self.block_button, 0, 0)
        actions.addWidget(self.delete_button, 0, 1)
        layout.addLayout(actions)
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def refresh(self):
        module = shadow_module(self._manager)
        status = module.storage_status() if module is not None else {}
        if self._cleanup_activity is None and status.get("cleanup_pending") is True:
            self._cleanup_module = module
            self._cleanup_activity = self._activities.begin("recovery-cleanup", "Observing the requested recovery-copy cleanup…")
        if self._cleanup_activity is not None and self._cleanup_module is not None:
            try:
                cleanup_status = self._cleanup_module.storage_status()
            except Exception:
                cleanup_status = {}
            if cleanup_status.get("cleanup_pending") is not True:
                self._activities.finish(self._cleanup_activity)
                self._cleanup_activity = None
                self._cleanup_module = None
            else:
                report = cleanup_status.get("cleanup_report") or {}
                report = report if type(report) is dict else {}
                removed = report.get("removed_files")
                label = f"Deleting recovery copies · {removed:,} files removed; total unknown" if type(removed) is int and removed >= 0 else "Deleting recovery copies · total unknown…"
                self._activities.update(self._cleanup_activity, label=label)
        self.usage.setText(_usage_text(status))
        self.delete_button.setEnabled(module is not None and not status.get("cleanup_pending"))

    def write_candidate(self, candidate):
        candidate.shadow_cache_enabled = self.cache_enabled.isChecked()
        candidate.shadow_cache_max_mib = self.max_mib.value()
        candidate.shadow_min_free_mib = self.min_free_mib.value()
        candidate.shadow_vss_enabled = self.vss_enabled.isChecked()
        candidate.validate_shadow_storage_settings()

    def _block(self):
        self.cache_enabled.setChecked(False)
        module = shadow_module(self._manager)
        if module is not None:
            module.configure_storage_policy(cache_enabled=False,
                vss_enabled=False, max_mib=self.max_mib.value(),
                min_free_mib=self.min_free_mib.value())
        self.vss_enabled.setChecked(False)
        self.usage.setText("New recovery data blocked for this run. Save Settings to keep this choice.")

    def _delete(self):
        if self._confirmation is not None:
            self._confirmation.raise_()
            return
        requested_module = shadow_module(self._manager)
        def completed(accepted):
            self._confirmation = None
            if accepted:
                self._cleanup_module = requested_module
                self._cleanup_activity = self._activities.begin("recovery-cleanup", "Deleting the explicitly selected recovery copies…", replace=True)
            self.usage.setText("Deletion requested; wait for completion." if accepted else "Recovery copies preserved.")
            self.refresh()
        self._confirmation = confirm_cache_cleanup(
            self, requested_module, completed, before_request=self._block)

    def closeEvent(self, event):
        self._activities.close()
        self._timer.stop()
        if self._confirmation is not None:
            self._confirmation.reject()
        super().closeEvent(event)


class _StorageReviewDialog(QDialog):
    """Resizable review workspace; deletion still requires its separate prompt."""

    def __init__(self, text, parent=None):
        super().__init__(parent)
        from angerona.gui.window_controls import configure_work_window
        from angerona.gui.window_fit import install_window_fit

        self.setWindowTitle("Angerona storage needs review")
        self.setModal(False)
        self.resize(760, 340)
        self.setMinimumSize(420, 240)
        self.setSizeGripEnabled(True)
        self._clicked_button = None
        layout = QVBoxLayout(self)
        self._message = QLabel(text, self)
        self._message.setTextFormat(Qt.PlainText)
        self._message.setWordWrap(True)
        self._message.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self._message, 1)
        self._buttons = QDialogButtonBox(self)
        self.block_button = self._buttons.addButton("Block new recovery data", QDialogButtonBox.RejectRole)
        self.delete_button = self._buttons.addButton("Delete recovery copies…", QDialogButtonBox.DestructiveRole)
        self.change_button = self._buttons.addButton("Allow / change limits…", QDialogButtonBox.ActionRole)
        self.block_button.setDefault(True)
        self._buttons.clicked.connect(self._choose)
        layout.addWidget(self._buttons)
        configure_work_window(self)
        install_window_fit(self, scroll_content=True)

    def _choose(self, button):
        self._clicked_button = button
        self.done(QDialog.Rejected)

    def buttons(self):
        return self._buttons.buttons()

    def clickedButton(self):  # noqa: N802 - retained review-surface Qt contract
        return self._clicked_button

    def text(self):
        return self._message.text()

    def keyPressEvent(self, event):  # noqa: N802 - Qt signature
        if event.key() == Qt.Key_Escape:
            self.block_button.click()
            event.accept()
            return
        super().keyPressEvent(event)


class StorageWarningController(QObject):
    """One retained nonmodal warning; data-volume probing runs on one reader."""

    _NOTICE = "storage:recovery"
    _REVIEW_HOLD = "awaiting storage decision; open Storage settings to resume"

    def __init__(self, config, manager, parent, open_settings, *, notifications=None):
        super().__init__(parent)
        self._config, self._manager = config, manager
        self._open_settings = open_settings
        self._notifications = notifications
        self._warning = self._confirmation = None
        self._notice_key = self._review_request = None
        self._warning_key = self._confirmation_key = None
        self._acknowledged = set()
        self._acknowledged_notice = None
        self._closed = False
        from angerona.gui.action_progress import ActionActivities
        self.activities = ActionActivities(self)
        self._cleanup_activity = None
        self._cleanup_module = None
        self._reader = AsyncSnapshot(self, self._prepare, self._apply,
            name="StorageCapacityReader", status=self._reader_status)
        self._timer = QTimer(self)
        self._timer.setInterval(30_000)
        self._timer.timeout.connect(self.poll)
        self._timer.start()
        QApplication.instance().aboutToQuit.connect(self.close)

    def poll(self):
        if not self._closed:
            if self._cleanup_activity is not None:
                try:
                    status = self._cleanup_module.storage_status()
                except Exception:
                    status = {}
                if status.get("cleanup_pending") is True:
                    report = status.get("cleanup_report")
                    removed = report.get("removed_files") if type(report) is dict else None
                    label = f"Recovery cleanup · {removed:,} files removed; total unknown" if type(removed) is int and removed >= 0 else "Recovery cleanup is queued or running; total unknown…"
                    self.activities.update(self._cleanup_activity, label=label)
                    return  # Only cached counters; do not probe drives per second.
                self.activities.finish(self._cleanup_activity)
                self._cleanup_activity = None
                self._cleanup_module = None
                self._timer.setInterval(30_000)
            self._reader.request()

    def _prepare(self):
        root = Path(self._config.data_dir)
        identity = self._identity()
        module, enabled, _, _, min_free_mib = identity
        reserve = min_free_mib * MIB
        def read():
            status = module.storage_status() if module is not None else {}
            if not enabled:
                status = dict(status, held=False, used_bytes=None)
            volumes, free = _collect_volume_capacity(root, reserve)
            status = dict(status, **volumes, _warning_identity=identity)
            return status, free, reserve
        return read

    def _identity(self):
        config = self._config
        return (shadow_module(self._manager), config.shadow_cache_enabled, config.shadow_vss_enabled,
                config.shadow_cache_max_mib, config.shadow_min_free_mib)

    def _reader_status(self, state):
        if state == "unavailable":
            self._review_request = None

    def _apply(self, result):
        if self._closed:
            return
        status, free, reserve = result
        category = storage_warning(status, free, reserve)
        if self._notifications is not None:
            self._publish_notice(status, free, category)
            return
        if not category:
            self._acknowledged.clear()
            return
        if category in self._acknowledged or self._warning is not None or self._confirmation is not None:
            return
        self._acknowledged.add(category)
        identity = self._identity()
        self._hold_writes(identity)
        self._show_review(self._review_text(status, free), identity[0])

    def _publish_notice(self, status, free, category):
        identity = self._identity()
        previous = self._notice_key
        requested, self._review_request = self._review_request, None
        if status.get("_warning_identity", identity) != identity:
            if previous is not None and previous[1] != identity:
                self._clear_notice()
            return
        if not category and previous is not None and previous[1] == identity:
            # Our own pending hold disables cache writes. That disables the
            # ordinary cache-limit predicate but still requires a decision.
            if status.get("reason") == self._REVIEW_HOLD:
                category = previous[0]
        if not category:
            self._acknowledged.clear()
            self._acknowledged_notice = None
            self._clear_notice()
            return
        key = (category, identity)
        if key == self._acknowledged_notice or category in self._acknowledged:
            self._clear_notice()
            return
        if key != previous:
            self._hold_writes(identity)
        self._notice_key = key
        message = self._review_text(status, free)
        self._notifications.upsert(self._NOTICE, "Recovery storage needs review",
                                   message, lambda: self._review(key))
        if requested == key:
            self._present_review(message, key)

    def _clear_notice(self):
        self._notice_key = None
        self._notifications.remove(self._NOTICE)

    def _current(self, key):
        return not self._closed and self._notice_key == key and key[1] == self._identity()

    def _review(self, key):
        if not self._current(key):
            self.poll()
            return
        if self._review_request != key:
            self._review_request = key
            self._reader.request(invalidate=True)

    def _present_review(self, message, key):
        for dialog, bound in ((self._confirmation, self._confirmation_key),
                              (self._warning, self._warning_key)):
            if dialog is None:
                continue
            if bound == key:
                if dialog.isMinimized():
                    dialog.showNormal()
                dialog.raise_()
                dialog.activateWindow()
                return
            dialog.reject()
        self._show_review(message, key[1][0], key)

    @staticmethod
    def _hold_writes(identity):
        module, _, _, max_mib, min_free_mib = identity
        # Keep the saved preference unchanged while an unresolved warning holds
        # new recovery writes. Settings Save explicitly reapplies that preference.
        if module is not None:
            module.configure_storage_policy(cache_enabled=False, vss_enabled=False,
                max_mib=max_mib, min_free_mib=min_free_mib, review_pending=True)

    @staticmethod
    def _review_text(status, free):
        summary = status.get("volume_summary")
        free_text = (str(summary) + ". " if summary else
                     f"Drive space free: {free / MIB:.0f} MiB. " if free is not None
                     else "Drive space unavailable. ")
        gaps = status.get("volume_gaps", ())
        if gaps:
            free_text += "Capacity coverage incomplete: " + "; ".join(gaps) + ". "
        return (free_text + _usage_text(status) + "\n\nNew recovery data is held for this run. "
            "Choose whether to block it, delete existing recovery copies, or allow/change "
            "the limit in Settings. The free-space reserve remains enforced. Other "
            "temporary files and protected evidence require separate review.")

    def _acknowledge(self, key):
        self._acknowledged_notice = key
        self._clear_notice()

    def _show_review(self, message, module, key=None):
        dialog = _StorageReviewDialog(message, parent=self.parent())
        if key is not None:
            dialog.setProperty("_angerona_no_reveal", True)
        block, delete, change = dialog.block_button, dialog.delete_button, dialog.change_button
        delete.setEnabled(module is not None)
        self._warning = dialog
        self._warning_key = key
        def finished(_result):
            clicked = dialog.clickedButton()
            self._warning = None
            self._warning_key = None
            dialog.deleteLater()
            if self._closed or (key is not None and not self._current(key)):
                return
            if clicked is block:
                self._config.shadow_cache_enabled = False
                self._config.shadow_vss_enabled = False
                self._acknowledged.update(("cache-held", "cache-near-limit"))
                if key is not None:
                    self._acknowledge((key[0], self._identity()))
            elif clicked is delete:
                def done(accepted):
                    self._confirmation = None
                    self._confirmation_key = None
                    if accepted and not self._closed:
                        if key is not None:
                            self._acknowledge(key)
                        self._cleanup_module = module
                        self._cleanup_activity = self.activities.begin("recovery-cleanup", "Deleting the explicitly selected recovery copies…", replace=True)
                        self._timer.setInterval(2000)
                        self.poll()
                still_current = None if key is None else lambda: self._current(key)
                self._confirmation = confirm_cache_cleanup(
                    self.parent(), module, done, still_current=still_current)
                self._confirmation_key = key
            elif clicked is change:
                self._open_settings("General")
        dialog.finished.connect(finished)
        dialog.setWindowModality(Qt.NonModal)
        dialog.show()

    def close(self, *_args):
        self._closed = True
        self.activities.close()
        self._timer.stop()
        self._reader.close()
        if self._notifications is not None:
            self._clear_notice()
        for dialog in (self._warning, self._confirmation):
            if dialog is not None:
                dialog.reject()
