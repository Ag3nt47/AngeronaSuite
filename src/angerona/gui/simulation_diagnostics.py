"""Modeless read-only diagnostics for an authenticated simulation report.

Report authentication, strict JSON preparation and file output run outside Qt's
GUI thread. A proposed fix is review data, never an executable response action.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel, QIODevice, QModelIndex, QSaveFile, Qt, Slot,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QDialog, QFileDialog,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QSplitter, QTableView, QVBoxLayout,
)
from shiboken6 import isValid

from angerona.gui.action_progress import ActionActivities, ActionProgressView
from angerona.gui.action_worker import start_finite_action
from angerona.gui.window_controls import configure_work_window
from angerona.gui.window_fit import install_window_fit


_MAX_BYTES = 4 * 1024 * 1024
_MAX_ROWS = 512
_MAX_NODES = 160000
_DETAIL_LIMIT = 64000
_IDENTITY_KEYS = (
    "run_id", "report_kind", "report_sha256", "head_sha256", "sequence",
    "report_state", "coverage_score_eligible",
)
_ROW_TEXT = (
    "stage", "technique", "category", "detection_status", "response_status",
    "status", "reason_code", "reason", "fix_kind", "fix_status",
)
_STATUSES = {"pass", "fail", "inconclusive", "unscored"}


@dataclass(frozen=True)
class _Snapshot:
    data: dict
    json_text: str


def _prepare_snapshot(data):
    """Reject unsupported/oversize DTOs without invoking arbitrary copy hooks."""
    nodes = 0
    active = set()

    def clone(value, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES or depth > 24:
            raise ValueError("Diagnostic JSON exceeds structural limits")
        kind = type(value)
        if value is None or kind in (bool, int):
            if kind is int and value.bit_length() > 1024:
                raise ValueError("Diagnostic integer exceeds bounds")
            return value
        if kind is str:
            if len(value) > _MAX_BYTES:
                raise ValueError("Diagnostic string exceeds bounds")
            return value
        if kind is float:
            if not math.isfinite(value):
                raise ValueError("Diagnostic JSON contains a non-finite value")
            return value
        if kind not in (dict, list) or id(value) in active:
            raise ValueError("Diagnostic JSON must contain only acyclic plain data")
        active.add(id(value))
        try:
            if kind is list:
                return [clone(item, depth + 1) for item in value]
            if any(type(key) is not str for key in value):
                raise ValueError("Diagnostic JSON requires plain string keys")
            return {clone(key, depth + 1): clone(item, depth + 1) for key, item in value.items()}
        finally:
            active.remove(id(value))

    copied = clone(data)
    if type(copied) is not dict or copied.get("schema") != "angerona.simulation-diagnostics.v1":
        raise ValueError("Unexpected simulation diagnostics schema")
    if copied.get("report_state") not in {"complete", "diagnostic"}:
        raise ValueError("Diagnostic report state is unavailable")
    if copied.get("overall_status") not in {"passing", "failing", "inconclusive"}:
        raise ValueError("Diagnostic overall status is unavailable")
    if type(copied.get("coverage_score_eligible")) is not bool:
        raise ValueError("Diagnostic coverage eligibility is unavailable")
    for key in ("run_id", "report_kind"):
        if type(copied.get(key)) is not str or not copied[key]:
            raise ValueError("Diagnostic immutable report identity is unavailable")
    for key in ("report_sha256", "head_sha256"):
        value = copied.get(key)
        if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("Diagnostic immutable digest identity is unavailable")
    if type(copied.get("sequence")) is not int or copied["sequence"] < 0:
        raise ValueError("Diagnostic immutable sequence is unavailable")
    for key in ("omitted_rows", "omitted_text_characters"):
        if type(copied.get(key)) is not int or copied[key] < 0:
            raise ValueError("Diagnostic omission count is unavailable")
    if copied["report_state"] == "diagnostic" and copied["coverage_score_eligible"]:
        raise ValueError("A diagnostic-only report cannot grant coverage eligibility")
    rows = copied.get("rows")
    if type(rows) is not list or len(rows) > _MAX_ROWS:
        raise ValueError("Diagnostic rows exceed the bounded view")
    seen = set()
    for row in rows:
        if type(row) is not dict or type(row.get("index")) is not int or row["index"] < 0 or row["index"] in seen:
            raise ValueError("Diagnostic row identity is missing or duplicated")
        seen.add(row["index"])
        if any(type(row.get(key)) is not str for key in _ROW_TEXT):
            raise ValueError("Diagnostic row fields are incomplete")
        if any(type(row.get(key)) is not list or any(type(item) is not str for item in row[key])
                for key in ("evidence", "next_steps", "source_areas")):
            raise ValueError("Diagnostic row evidence or next steps are incomplete")
        if any(row[key] not in _STATUSES for key in ("status", "detection_status", "response_status")):
            raise ValueError("Diagnostic row status vocabulary is unsupported")
        if row["fix_status"] not in {"not-applied", "none"}:
            raise ValueError("Diagnostic fix status cannot claim an applied change")
        if not copied["coverage_score_eligible"] and any(row[key] in {"pass", "fail"}
                for key in ("status", "detection_status", "response_status")):
            raise ValueError("An ineligible diagnostic row cannot grant pass/fail scoring")
    # Use the producer's serialized representation for its 4 MiB admission
    # budget. Pretty-print expansion must not reject an otherwise valid DTO;
    # the selected-row pane retains its separate readable formatting.
    text = json.dumps(copied, ensure_ascii=True, allow_nan=False)
    if len(text.encode("ascii")) > _MAX_BYTES:
        raise ValueError("Complete diagnostics exceed the 4 MiB copy/export limit; nothing was truncated")
    return _Snapshot(copied, text)


def _load_verified_diagnostics(source, worker):
    # Root's backend authenticates the immutable current AAR before mapping it.
    from angerona.core.simulation_diagnostics import (
        diagnostics_for_handoff, load_report_diagnostics,
    )
    if worker.isInterruptionRequested():
        raise RuntimeError("Diagnostic request cancelled before authentication")
    mode, payload = source
    if mode == "handoff":
        data = diagnostics_for_handoff(payload)
    else:
        data_dir, arguments = payload
        data = load_report_diagnostics(data_dir, **arguments)
    if worker.isInterruptionRequested():
        raise RuntimeError("Diagnostic request cancelled after authentication")
    return _prepare_snapshot(data)


def _export_snapshot(filename, payload, worker):
    output = QSaveFile(filename)
    output.setDirectWriteFallback(False)
    try:
        if worker.isInterruptionRequested():
            raise RuntimeError("Diagnostic export cancelled before file creation")
        if not output.open(QIODevice.OpenModeFlag.WriteOnly):
            raise OSError(output.errorString())
        for offset in range(0, len(payload), 64 * 1024):
            if worker.isInterruptionRequested():
                raise RuntimeError("Diagnostic export cancelled; no partial file committed")
            chunk = payload[offset:offset + 64 * 1024]
            if output.write(chunk) != len(chunk):
                raise OSError(output.errorString())
            worker.piece.emit(json.dumps({"done": offset + len(chunk), "total": len(payload)}))
        if worker.isInterruptionRequested():
            raise RuntimeError("Diagnostic export cancelled; no partial file committed")
        if not output.commit():
            raise OSError(output.errorString())
        return "Complete diagnostics exported. Original evidence and security policy are unchanged."
    except Exception:
        output.cancelWriting()
        raise


def _cancel_jobs(jobs):
    for worker in tuple(jobs):
        if isValid(worker):
            worker.requestInterruption()


def _label(text=""):
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setMinimumWidth(0)
    return label


class _Rows(QAbstractTableModel):
    HEADERS = ("Step", "Stage", "Technique", "Detection", "Response", "Status", "Why")
    KEYS = ("index", "stage", "technique", "detection_status", "response_status", "status", "reason")

    def __init__(self, parent):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else None
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.rows):
            return None
        row = self.rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return str(row[self.KEYS[index.column()]])[:280]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 5:
            return QColor({"pass": "#31c96b", "fail": "#ff6b6b"}.get(row["status"], "#f2bd50"))
        return None

    def replace(self, rows):
        same = [row["index"] for row in rows] == [row["index"] for row in self.rows]
        if same:
            self.rows = rows
            if rows:
                self.dataChanged.emit(self.index(0, 0), self.index(len(rows) - 1, len(self.HEADERS) - 1))
        else:
            self.beginResetModel()
            self.rows = rows
            self.endResetModel()


class SimulationDiagnosticsPanel(QDialog):
    """Read-only workspace; multiple instances and other windows stay usable."""

    def __init__(self, parent=None, *, config=None, handoff=None, data_dir=None,
                 report_kind=None, expected_run_id=None, expected_report_sha256=None,
                 expected_head_sha256=None, expected_sequence=None, patch_review=None,
                 auto_load=True):
        super().__init__(parent)
        self.setWindowTitle("Red Team — Verified step diagnostics")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setModal(False)
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint)
        self.setMinimumSize(440, 320)
        self.resize(1120, 780)
        self._closed = False
        self._snapshot = None
        self._snapshot_version = None
        self._jobs = {}
        self._worker = None
        self._source_version = 0
        self._refresh_pending = False
        self._patch_review = patch_review
        self._source = None
        if handoff is not None:
            self._source = ("handoff", handoff)
        elif data_dir is not None and report_kind is not None:
            self._source = ("report", (data_dir, dict(report_kind=report_kind,
                expected_run_id=expected_run_id, expected_report_sha256=expected_report_sha256,
                expected_head_sha256=expected_head_sha256, expected_sequence=expected_sequence)))
        self.destroyed.connect(lambda *_args, jobs=self._jobs: _cancel_jobs(jobs))
        self._activities = ActionActivities(self)
        root = QVBoxLayout(self)
        root.addWidget(_label("RED TEAM · Verified step diagnostics"))
        root.addWidget(_label("Read-only review of the authenticated immutable report. Observed facts, "
            "coverage gaps and proposed fixes remain separate. This view grants no response authority."))
        self.progress_view = ActionProgressView(self._activities, self, config=config)
        root.addWidget(self.progress_view)
        self.summary = _label("No report authenticated yet.")
        self.identity = _label()
        root.addWidget(self.summary)
        root.addWidget(self.identity)
        controls = QHBoxLayout()
        self.filter = QComboBox()
        self.filter.addItems(("All steps", "Pass", "Fail", "Held / inconclusive"))
        self.filter.setToolTip("Filter observed row status; the overall report result stays unchanged.")
        self.filter.currentIndexChanged.connect(self._apply_filter)
        controls.addWidget(self.filter)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search stage, technique, category or reason…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._apply_filter)
        controls.addWidget(self.search, 1)
        self.refresh_button = QPushButton("Refresh verified report")
        self.refresh_button.clicked.connect(self.refresh_diagnostics)
        controls.addWidget(self.refresh_button)
        root.addLayout(controls)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableView()
        self.model = _Rows(self.table)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((55, 130, 100, 110, 110, 110, 300)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().selectionChanged.connect(self._show_selected)
        split.addWidget(self.table)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a step to inspect verified facts and proposed review actions.")
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        root.addWidget(split, 1)
        self.message = _label("Raw host diagnostics are private; review exports before sharing.")
        root.addWidget(self.message)
        buttons = QHBoxLayout()
        self.copy_button = QPushButton("Copy full diagnostics JSON")
        self.copy_button.clicked.connect(self.copy_json)
        buttons.addWidget(self.copy_button)
        self.export_button = QPushButton("Export full JSON…")
        self.export_button.clicked.connect(self.export_json)
        buttons.addWidget(self.export_button)
        self.patch_button = QPushButton("Open fix review…")
        self.patch_button.clicked.connect(self.review_selected_fix)
        buttons.addWidget(self.patch_button)
        buttons.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        root.addLayout(buttons)
        configure_work_window(self)
        self._fit = install_window_fit(self)
        self._update_buttons()
        if auto_load and self._source is not None:
            self.refresh_diagnostics()

    def set_handoff(self, handoff):
        self._source = ("handoff", handoff)
        self._source_version += 1
        self.message.setText("A new immutable report was selected; its diagnostics are not authenticated yet.")
        if self._closed:
            return True  # Reused modeless window authenticates on its next show.
        return self.refresh_diagnostics()

    def refresh_diagnostics(self):
        if self._closed or self._source is None:
            return False
        if self._worker is not None:
            self._refresh_pending = True
            self.message.setText("Refresh queued until the current exact native operation retires.")
            return True
        source, version = self._source, self._source_version
        return self._start("load", version, lambda owner: _load_verified_diagnostics(source, owner))

    def _start(self, kind, version, function, total=0):
        if self._closed or self._worker is not None:
            return False
        worker = start_finite_action(function, name="SimulationDiagnostics" + kind.title(),
            finished=self._settled, piece=self._piece)
        if worker is None:
            self.message.setText("Diagnostics action admission is held or all bounded worker slots are occupied. Retry when available.")
            return False
        label = "Authenticating the immutable AAR and mapping step diagnostics…" if kind == "load" else "Exporting complete diagnostics JSON…"
        handle = self._activities.begin("diagnostics-" + kind, label, total=total)
        self._worker = worker
        self._jobs[worker] = dict(kind=kind, version=version, handle=handle, total=total)
        if worker.admission_error:
            self._activities.finish(handle)
            self.message.setText("Diagnostics worker launch failed; its exact native retirement is unproved. No new result is verified.")
        else:
            suffix = " Previous verified data remains displayed during authentication." if kind == "load" and self._snapshot else ""
            self.message.setText(label + " Progress is unknown until actual producer units are available." + suffix)
        self._update_buttons()
        return not bool(worker.admission_error)

    @Slot(str)
    def _piece(self, text):
        job = self._jobs.get(self.sender())
        if self._closed or not job or job["kind"] != "export":
            return
        try:
            value = json.loads(text)
            done, total = value["done"], value["total"]
            if type(done) is not int or type(total) is not int or total != job["total"] or not 0 <= done <= total:
                return
        except (ValueError, KeyError, TypeError):
            return
        self._activities.update(job["handle"], done=done, total=total)

    @Slot()
    def _settled(self):
        worker = self.sender()
        job = self._jobs.pop(worker, None)
        if job is None:
            return
        if self._worker is worker:
            self._worker = None
        self._activities.finish(job["handle"])
        if self._closed:
            return
        result, error = worker.outcome
        if job["version"] != self._source_version and job["kind"] == "load":
            self.message.setText("Older diagnostic result ignored; the newly selected report still requires authentication.")
        elif error:
            self.message.setText("No new diagnostic result verified: " + error +
                (" Previous verified data remains displayed." if self._snapshot else ""))
        elif job["kind"] == "load" and isinstance(result, _Snapshot):
            self._snapshot = result
            self._snapshot_version = job["version"]
            self._render_summary()
            self._apply_filter()
            self.message.setText("Verified report diagnostics loaded. Proposed fixes still require their own review and validation.")
        elif job["kind"] == "export":
            self.message.setText(str(result))
        else:
            self.message.setText("No compatible diagnostic result was returned; no new evidence is verified.")
        self._update_buttons()
        if self._refresh_pending:
            self._refresh_pending = False
            self.refresh_diagnostics()

    def _render_summary(self):
        data = self._snapshot.data
        eligible = "eligible" if data["coverage_score_eligible"] else "ineligible"
        self.summary.setText(f"Overall: {data['overall_status']} · Report: {data['report_state']} · "
            f"Coverage score: {eligible} · Steps: {len(data['rows'])} · Omitted rows: {data['omitted_rows']} · "
            f"Text characters omitted by producer: {data['omitted_text_characters']}")
        self.identity.setText(" · ".join(f"{key}: {data[key]}" for key in _IDENTITY_KEYS if key in data))

    def _selected_row(self):
        selected = self.table.selectionModel().selectedRows()
        index = selected[0].row() if selected else -1
        return self.model.rows[index] if 0 <= index < len(self.model.rows) else None

    def _apply_filter(self, *_args):
        selected = self._selected_row()
        selected_id = selected["index"] if selected is not None else None
        vertical = self.table.verticalScrollBar().value()
        horizontal = self.table.horizontalScrollBar().value()
        detail_scroll = self.detail.verticalScrollBar().value()
        query, group = self.search.text().casefold(), self.filter.currentIndex()
        rows = self._snapshot.data["rows"] if self._snapshot else []

        def included(row):
            status = row["status"].lower()
            passing, failing = status == "pass", status == "fail"
            if group == 1 and not passing or group == 2 and not failing or group == 3 and (passing or failing):
                return False
            return not query or any(query in row[key].casefold() for key in ("stage", "technique", "category", "reason"))

        filtered = [row for row in rows if included(row)]
        self.model.replace(filtered)
        match = next((number for number, row in enumerate(filtered) if row["index"] == selected_id), None)
        if match is not None:
            self.table.selectRow(match)
        elif selected_id is not None:
            self.table.clearSelection()
        self._show_selected()
        self.table.verticalScrollBar().setValue(vertical)
        self.table.horizontalScrollBar().setValue(horizontal)
        self.detail.verticalScrollBar().setValue(detail_scroll)

    def _show_selected(self, *_args):
        row = self._selected_row()
        if row is None:
            self.detail.clear()
        else:
            facts = {key: row[key] for key in ("index", *_ROW_TEXT[:8], "evidence")}
            text = "FACTS FROM THE VERIFIED REPORT\n" + json.dumps(facts, indent=2, ensure_ascii=True)
            text += "\n\nPROPOSED REVIEW AND VALIDATION — NO FIX APPLIED BY THIS VIEW\n"
            text += json.dumps({key: row[key] for key in ("next_steps", "source_areas", "fix_kind", "fix_status")}, indent=2, ensure_ascii=True)
            if len(text) > _DETAIL_LIMIT:
                text = text[:_DETAIL_LIMIT] + "\n[Selected detail display bounded; full bounded JSON remains available through Copy/Export.]"
            if text != self.detail.toPlainText():
                scroll = self.detail.verticalScrollBar().value()
                self.detail.setPlainText(text)
                self.detail.verticalScrollBar().setValue(scroll)
        self._update_buttons()

    def _update_buttons(self):
        ready = self._snapshot is not None and not self._closed
        self.copy_button.setEnabled(ready)
        self.export_button.setEnabled(ready and self._worker is None)
        self.refresh_button.setEnabled(not self._closed and self._source is not None and self._worker is None)
        row = self._selected_row()
        self.patch_button.setEnabled(ready and callable(self._patch_review) and row is not None
            and self._worker is None and self._snapshot_version == self._source_version
            and bool(row["next_steps"]) and row["fix_status"] == "not-applied" and row["fix_kind"] != "none")

    def copy_json(self):
        if self._closed or self._snapshot is None:
            return False
        QApplication.clipboard().setText(self._snapshot.json_text)
        self.message.setText("Complete verified diagnostics copied. Raw host information remains private; review before sharing.")
        return True

    def export_json(self):
        if self._closed or self._snapshot is None or self._worker is not None:
            return False
        filename, _selected = QFileDialog.getSaveFileName(self, "Export complete private step diagnostics",
            "angerona-simulation-diagnostics.json", "JSON files (*.json)")
        if not filename:
            return False
        if not Path(filename).is_absolute() or Path(filename).suffix.lower() != ".json":
            self.message.setText("Choose an absolute .json destination; no export was started.")
            return False
        payload = self._snapshot.json_text.encode("ascii")
        return self._start("export", self._source_version,
            lambda owner: _export_snapshot(filename, payload, owner), len(payload))

    def review_selected_fix(self):
        row = self._selected_row()
        if self._closed or self._snapshot is None or self._worker is not None or self._snapshot_version != self._source_version or row is None or not row["next_steps"] or not callable(self._patch_review) or row["fix_status"] != "not-applied" or row["fix_kind"] == "none":
            return False
        # Only already prepared plain data is detached. No action/saved-artifact
        # identity is invented, and no report text is evaluated as code or a URL.
        request = {"diagnostics_identity": {key: self._snapshot.data[key] for key in _IDENTITY_KEYS if key in self._snapshot.data}, "row": row}
        try:
            self._patch_review(json.loads(json.dumps(request, ensure_ascii=True, allow_nan=False)))
        except Exception as error:
            self.message.setText("Fix review could not be opened: " + type(error).__name__ + ". No change was applied by this panel.")
            return False
        self.message.setText("Sent to AngeronaPatch for review. No change has been applied by this panel.")
        return True

    def showEvent(self, event):  # noqa: N802
        if self._closed:
            self._closed = False
            self._source_version += 1
            self._update_buttons()
            self.refresh_diagnostics()
        super().showEvent(event)

    def closeEvent(self, event):  # noqa: N802
        self._closed = True
        self._refresh_pending = False
        self._activities.close()
        _cancel_jobs(self._jobs)
        self._update_buttons()
        super().closeEvent(event)
