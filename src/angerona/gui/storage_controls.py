"""Storage choices from cached recovery state and one asynchronous volume probe."""
from __future__ import annotations

import ntpath
import os
import shutil
import tempfile
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QGridLayout, QGroupBox, QLabel, QMessageBox,
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


def confirm_cache_cleanup(parent, module, completed=None, before_request=None):
    """Queue only after an explicit second choice; all file work stays in worker."""
    dialog = QMessageBox(QMessageBox.Warning, "Delete recovery copies?",
        "This permanently deletes Shadow Shield's cached file versions and removes "
        "those restore points. It does not delete your original Documents/Desktop "
        "files, Windows shadow copies, alerts, evidence or other temporary files.",
        QMessageBox.Yes | QMessageBox.No, parent)
    dialog.setDefaultButton(QMessageBox.No)
    dialog.setTextFormat(Qt.PlainText)
    dialog.setEscapeButton(QMessageBox.No)
    def finished(result):
        accepted = False
        if result == QMessageBox.Yes and module is not None:
            if before_request is not None:
                before_request()
            accepted = bool(module.request_cache_cleanup())
        if completed is not None:
            completed(accepted)
        dialog.deleteLater()
    dialog.finished.connect(finished)
    dialog.open()
    return dialog


class StorageControls(QGroupBox):
    """Settings fields; expensive collection/deletion never occurs in this widget."""

    def __init__(self, config, manager=None, parent=None):
        super().__init__("Drive space and recovery data", parent)
        self._config, self._manager = config, manager
        self._confirmation = None
        layout = QVBoxLayout(self)
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
        def completed(accepted):
            self._confirmation = None
            self.usage.setText("Deletion requested; wait for completion." if accepted else "Recovery copies preserved.")
            self.refresh()
        self._confirmation = confirm_cache_cleanup(
            self, shadow_module(self._manager), completed, before_request=self._block)

    def closeEvent(self, event):
        self._timer.stop()
        if self._confirmation is not None:
            self._confirmation.reject()
        super().closeEvent(event)


class StorageWarningController(QObject):
    """One retained nonmodal warning; data-volume probing runs on one reader."""

    def __init__(self, config, manager, parent, open_settings):
        super().__init__(parent)
        self._config, self._manager = config, manager
        self._open_settings = open_settings
        self._warning = self._confirmation = None
        self._acknowledged = set()
        self._closed = False
        self._reader = AsyncSnapshot(self, self._prepare, self._apply,
            name="StorageCapacityReader")
        self._timer = QTimer(self)
        self._timer.setInterval(30_000)
        self._timer.timeout.connect(self.poll)
        self._timer.start()
        QApplication.instance().aboutToQuit.connect(self.close)

    def poll(self):
        if not self._closed:
            self._reader.request()

    def _prepare(self):
        root = Path(self._config.data_dir)
        module = shadow_module(self._manager)
        reserve = self._config.shadow_min_free_mib * MIB
        enabled = self._config.shadow_cache_enabled
        def read():
            status = module.storage_status() if module is not None else {}
            if not enabled:
                status = dict(status, held=False, used_bytes=None)
            volumes, free = _collect_volume_capacity(root, reserve)
            status = dict(status, **volumes)
            return status, free, reserve
        return read

    def _apply(self, result):
        status, free, reserve = result
        category = storage_warning(status, free, reserve)
        if not category:
            self._acknowledged.clear()
            return
        if category in self._acknowledged or self._warning is not None or self._confirmation is not None:
            return
        self._acknowledged.add(category)
        module = shadow_module(self._manager)
        # Keep the saved preference unchanged while an unresolved warning holds
        # new recovery writes. Settings Save explicitly reapplies that preference.
        if module is not None:
            module.configure_storage_policy(cache_enabled=False, vss_enabled=False,
                max_mib=self._config.shadow_cache_max_mib,
                min_free_mib=self._config.shadow_min_free_mib,
                review_pending=True)
        summary = status.get("volume_summary")
        free_text = (str(summary) + ". " if summary else
                     f"Drive space free: {free / MIB:.0f} MiB. " if free is not None
                     else "Drive space unavailable. ")
        gaps = status.get("volume_gaps", ())
        if gaps:
            free_text += "Capacity coverage incomplete: " + "; ".join(gaps) + ". "
        dialog = QMessageBox(QMessageBox.Warning, "Angerona storage needs review",
            free_text + _usage_text(status) + "\n\nNew recovery data is held for this run. "
            "Choose whether to block it, delete existing recovery copies, or allow/change "
            "the limit in Settings. The free-space reserve remains enforced. Other "
            "temporary files and protected evidence require separate review.", parent=self.parent())
        block = dialog.addButton("Block new recovery data", QMessageBox.RejectRole)
        delete = dialog.addButton("Delete recovery copies…", QMessageBox.DestructiveRole)
        change = dialog.addButton("Allow / change limits…", QMessageBox.ActionRole)
        dialog.setDefaultButton(block)
        dialog.setTextFormat(Qt.PlainText)
        dialog.setEscapeButton(block)
        delete.setEnabled(module is not None)
        self._warning = dialog
        def finished(_result):
            clicked = dialog.clickedButton()
            self._warning = None
            if clicked is block:
                self._config.shadow_cache_enabled = False
                self._config.shadow_vss_enabled = False
                self._acknowledged.update(("cache-held", "cache-near-limit"))
            elif clicked is delete:
                def done(_accepted):
                    self._confirmation = None
                self._confirmation = confirm_cache_cleanup(self.parent(), module, done)
            elif clicked is change:
                self._open_settings("General")
            dialog.deleteLater()
        dialog.finished.connect(finished)
        dialog.setWindowModality(Qt.NonModal)
        dialog.show()

    def close(self, *_args):
        self._closed = True
        self._timer.stop()
        self._reader.close()
        for dialog in (self._warning, self._confirmation):
            if dialog is not None:
                dialog.reject()
