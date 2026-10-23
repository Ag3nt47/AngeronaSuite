"""Read-only local diagnostic client with bounded, local reviewer annotations.

The stream is an advisory redacted view. A review cannot acknowledge an alert,
change an allowlist, change a response rule, or write back to the source process.
"""
from __future__ import annotations

import atexit
from collections import deque
from dataclasses import dataclass
from datetime import datetime
import json
import math
import os
from pathlib import Path
import threading
import time
import weakref

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QThread, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QSpinBox, QSplitter, QTableView,
    QVBoxLayout, QWidget,
)


_MAX_RECORD_BYTES = 32 * 1024
_MAX_EXPORT_BYTES = 256 * 1024
_PENDING_LIMIT = 256
_UI_BATCH = 64
_VERDICTS = ("needs-review", "confirmed-threat", "false-positive", "health", "exposure")
_ACTIVE_WORKERS: set[QThread] = set()


def _shutdown_streams() -> None:
    """Finish bounded pipe workers before Python destroys their Qt wrappers."""
    workers = tuple(_ACTIVE_WORKERS)
    for worker in workers:
        worker.request_stop()
    deadline = time.monotonic() + 4.0
    for worker in workers:
        try:
            worker.wait(max(0, int((deadline - time.monotonic()) * 1000)))
        except RuntimeError:
            # QApplication.shutdown() may already have deleted a completed
            # wrapper while its queued finished callback was still pending.
            _ACTIVE_WORKERS.discard(worker)


atexit.register(_shutdown_streams)


def _retain(worker: QThread) -> None:
    # Independent ownership survives a panel being deleted during a bounded
    # connect/read. A running QThread must never be destroyed with its widget.
    _ACTIVE_WORKERS.add(worker)
    reference = weakref.ref(worker)
    worker.finished.connect(lambda: _ACTIVE_WORKERS.discard(reference()))
    worker.destroyed.connect(lambda *_: _ACTIVE_WORKERS.discard(reference()))


def _request_stop_all(workers: list) -> None:
    for worker in tuple(workers):
        if isinstance(worker, _StreamWorker):
            worker.request_stop()


def _clone_record(record: object) -> dict:
    if not isinstance(record, dict):
        raise ValueError("record is not a JSON object")
    raw = json.dumps(record, allow_nan=False, ensure_ascii=True, separators=(",", ":"))
    if len(raw) > _MAX_RECORD_BYTES:
        raise ValueError("record exceeds the 32 KiB view limit")
    copied = json.loads(raw)
    pending = [(copied, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 16 or nodes > 2048:
            raise ValueError("record exceeds structural limits")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
    return copied


def _client_factory(endpoint: str, *, expected_pid: int, expected_birth: float | None):
    from angerona.core.live_debug import LiveDebugClient
    return LiveDebugClient(endpoint, expected_pid=expected_pid, expected_birth=expected_birth)


class _StreamWorker(QThread):
    """Own pipe I/O; Qt consumes bounded batches, never a per-record signal."""

    def __init__(self, pid: int, birth: float | None, factory=None, *, pending_limit=_PENDING_LIMIT):
        super().__init__()  # Deliberately has no QWidget parent.
        self.pid, self.birth = pid, birth
        self._factory = factory or _client_factory
        self._pending_limit = max(1, min(_PENDING_LIMIT, pending_limit))
        self._pending: deque[dict] = deque()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._client = None
        self._lost = 0
        self._state = "connecting"
        self._message = f"Connecting to PID {pid}…"

    def request_stop(self) -> None:
        self._stop.set()
        with self._lock:
            client = self._client
        # cancel() only signals/cancels pending I/O. Handle cleanup is always
        # performed by run() below, outside the Qt thread.
        if client is not None and callable(getattr(client, "cancel", None)):
            try:
                client.cancel()
            except Exception:
                pass

    def _status(self, state: str, message: str) -> None:
        with self._lock:
            self._state, self._message = state, message[:700]

    def offer(self, record: object) -> None:
        try:
            copied = _clone_record(record)
        except (TypeError, ValueError, OverflowError, RecursionError):
            copied = {"kind": "coverage", "source": "local-review-client",
                "message": "A diagnostic view was rejected by client bounds; evidence coverage is UNKNOWN.",
                "reason": "invalid-or-oversized-record", "collection_complete": False,
                "advisory_only": True, "ts": time.time()}
        with self._lock:
            if len(self._pending) >= self._pending_limit:
                self._pending.popleft()
                self._lost += 1
            self._pending.append(copied)

    def take(self, limit: int = _UI_BATCH) -> tuple[list[dict], int, str, str, int]:
        with self._lock:
            rows = [self._pending.popleft() for _ in range(min(limit, len(self._pending)))]
            lost, self._lost = self._lost, 0
            return rows, lost, self._state, self._message, len(self._pending)

    def run(self) -> None:
        client = None
        try:
            if type(self.pid) is not int or not 1 <= self.pid <= 0xFFFFFFFF:
                raise ValueError("Enter a positive Windows process ID")
            if self.birth is not None and (type(self.birth) not in (int, float)
                    or not math.isfinite(self.birth) or self.birth <= 0):
                raise ValueError("Expected process birth must be a positive finite timestamp")
            from angerona.core.live_debug import endpoint_for_pid
            if self._stop.is_set():
                return
            client = self._factory(endpoint_for_pid(self.pid), expected_pid=self.pid, expected_birth=self.birth)
            with self._lock:
                self._client = client
            if self._stop.is_set():
                return
            client.connect(timeout=3.0)
            self._status("connected", f"Connected to PID {self.pid}; advisory diagnostic view")
            while not self._stop.is_set():
                record = client.read(timeout=0.25)
                if record is not None and not self._stop.is_set():
                    self.offer(record)
        except Exception as exc:
            if not self._stop.is_set():
                self._status("failed", f"Connection failed: {type(exc).__name__}: {exc}")
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            with self._lock:
                self._client = None
            if self._stop.is_set():
                self._status("disconnected", "Disconnected")


@dataclass
class _Row:
    identifier: int
    record: dict
    columns: tuple[str, ...]
    annotation: dict | None = None


class _RecordModel(QAbstractTableModel):
    HEADERS = ("Time", "Type", "Source", "Severity", "Summary", "Local review")

    def __init__(self, maximum: int, parent=None):
        super().__init__(parent)
        self.rows: list[_Row] = []
        self.maximum = maximum
        self.evicted = 0
        self._next_id = 0

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
        if role == Qt.ItemDataRole.DisplayRole:
            row = self.rows[index.row()]
            if index.column() == 5:
                return row.annotation["verdict"] if row.annotation else "unreviewed"
            return row.columns[index.column()]
        return None

    def append(self, records: list[dict]) -> None:
        if not records:
            return
        if len(records) > self.maximum:
            self.evicted += len(records) - self.maximum
            records = records[-self.maximum:]
        excess = max(0, len(self.rows) + len(records) - self.maximum)
        if excess:
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            del self.rows[:excess]
            self.evicted += excess
            self.endRemoveRows()
        start = len(self.rows)
        self.beginInsertRows(QModelIndex(), start, start + len(records) - 1)
        for record in records:
            self._next_id += 1
            stamp = record.get("event_ts", record.get("ts"))
            try:
                display_time = datetime.fromtimestamp(float(stamp)).astimezone().strftime("%H:%M:%S")
            except (TypeError, ValueError, OverflowError, OSError):
                display_time = ""
            columns = (display_time, str(record.get("kind", "unknown"))[:80],
                str(record.get("module") or record.get("source") or "")[:180],
                str(record.get("severity", ""))[:30],
                str(record.get("message") or record.get("reason") or record.get("status") or "")[:500])
            self.rows.append(_Row(self._next_id, record, columns))
        self.endInsertRows()


class _ExportWorker(threading.Thread):
    def __init__(self, path: Path, payload: bytes):
        super().__init__(name="LiveDebugEvidenceExport", daemon=True)
        self.path, self.payload = path, payload
        self.saved = False
        self.error = ""

    def isFinished(self):  # noqa: N802
        return self.ident is not None and not self.is_alive()

    def wait(self, timeout_ms: int) -> bool:
        self.join(timeout_ms / 1000)
        return not self.is_alive()

    def run(self) -> None:
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(self.payload)
                stream.flush()
                os.fsync(stream.fileno())
            self.saved = True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"[:700]
        finally:
            self.payload = b""


def _label(text="") -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class LiveDebugPanel(QWidget):
    """Opt-in diagnostic client; no automatic connection and no policy writes."""

    def __init__(self, parent=None, *, client_factory=None, default_pid=None, max_rows=1000):
        super().__init__(parent)
        if type(max_rows) is not int or not 500 <= max_rows <= 2000:
            raise ValueError("Diagnostic view must retain between 500 and 2000 rows")
        self._client_factory = client_factory
        self._worker: _StreamWorker | None = None
        self._exports: list[_ExportWorker] = []
        self._workers: list = []
        self._closed = False
        self._status_text = "Disconnected. Enable the source's live diagnostic setting before connecting."
        self._lost = 0
        self._connected_pid = None
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._drain)
        workers, timer = self._workers, self._timer
        self.destroyed.connect(lambda *_: (_request_stop_all(workers), timer.stop()))

        root = QVBoxLayout(self)
        root.addWidget(_label("LIVE AI REVIEW · Local diagnostic client"))
        root.addWidget(_label("Connect to an explicitly selected Angerona PID. Redacted views are advisory; "
            "local notes do not change alerts, allowlists, containment, or source code."))
        connection = QHBoxLayout()
        connection.addWidget(_label("Server PID"))
        self.pid_input = QSpinBox()
        self.pid_input.setRange(0, 2_147_483_647)
        self.pid_input.setValue(default_pid if type(default_pid) is int and 0 < default_pid <= 2_147_483_647 else 0)
        connection.addWidget(self.pid_input)
        self.birth_input = QLineEdit()
        self.birth_input.setMaxLength(40)
        self.birth_input.setPlaceholderText("Optional expected process birth timestamp")
        connection.addWidget(self.birth_input, 1)
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_pid)
        connection.addWidget(self.connect_button)
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.clicked.connect(self.disconnect_stream)
        connection.addWidget(self.disconnect_button)
        root.addLayout(connection)
        self.status = _label(self._status_text)
        root.addWidget(self.status)
        self.counters = _label(f"View: 0 / {max_rows} rows · Client gaps: 0 · History evicted: 0")
        root.addWidget(self.counters)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableView()
        self.model = _RecordModel(max_rows, self)
        self.table.setModel(self.model)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 85)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 175)
        self.table.setColumnWidth(3, 85)
        self.table.setColumnWidth(5, 130)
        self.table.selectionModel().selectionChanged.connect(self._show_selected)
        splitter.addWidget(self.table)
        self.record_detail = QPlainTextEdit()
        self.record_detail.setReadOnly(True)
        self.record_detail.setPlaceholderText("Select a row to inspect the full bounded diagnostic view as plain text.")
        splitter.addWidget(self.record_detail)
        root.addWidget(splitter, 1)
        review = QHBoxLayout()
        self.verdict = QComboBox()
        self.verdict.addItems(_VERDICTS)
        review.addWidget(self.verdict)
        self.review_reason = QLineEdit()
        self.review_reason.setMaxLength(4096)
        self.review_reason.setPlaceholderText("Required explanation for this local review")
        review.addWidget(self.review_reason, 1)
        self.review_button = QPushButton("Add local review")
        self.review_button.clicked.connect(lambda: self.annotate_selected())
        review.addWidget(self.review_button)
        self.export_button = QPushButton("Export selected…")
        self.export_button.clicked.connect(lambda: self.export_selected())
        review.addWidget(self.export_button)
        root.addLayout(review)
        self.review_status = _label("Reviews are local notes retained only in this bounded view until exported.")
        root.addWidget(self.review_status)

    def _set_status(self, text: str) -> None:
        self._status_text = text[:700]
        self.status.setText(self._status_text)

    def connect_to_pid(self) -> bool:
        if self._closed or self._worker is not None:
            return False
        pid = self.pid_input.value()
        birth_text = self.birth_input.text().strip()
        try:
            if pid <= 0:
                raise ValueError("Enter a positive server PID")
            birth = float(birth_text) if birth_text else None
            if birth is not None and (not math.isfinite(birth) or birth <= 0):
                raise ValueError("Expected birth must be a positive finite timestamp")
        except ValueError as exc:
            self._set_status(str(exc))
            return False
        worker = _StreamWorker(pid, birth, self._client_factory)
        self._worker = worker
        self._workers.append(worker)
        _retain(worker)
        self._connected_pid = pid
        self.connect_button.setEnabled(False)
        self.disconnect_button.setEnabled(True)
        self.pid_input.setEnabled(False)
        self.birth_input.setEnabled(False)
        self._set_status(f"Connecting to PID {pid}…")
        worker.start()
        self._timer.start()
        return True

    def disconnect_stream(self) -> None:
        if self._worker is not None:
            self._worker.request_stop()
            self._set_status("Disconnecting diagnostic client…")
            self.disconnect_button.setEnabled(False)

    def _drain(self) -> None:
        worker = self._worker
        if worker is not None:
            rows, lost, _state, message, pending = worker.take()
            if lost:
                self._lost += lost
                rows.insert(0, {"kind": "gap", "source": "local-review-client",
                    "message": "Client pending buffer overflow; earlier views were dropped.",
                    "dropped_events": lost, "advisory_only": True, "ts": time.time()})
            self.model.append(rows)
            self._set_status(message)
            if worker.isFinished() and pending == 0:
                self._worker = None
                self._workers.remove(worker)
                self.connect_button.setEnabled(not self._closed)
                self.pid_input.setEnabled(not self._closed)
                self.birth_input.setEnabled(not self._closed)
                self.disconnect_button.setEnabled(False)
        for export in tuple(self._exports):
            if export.isFinished():
                self._exports.remove(export)
                self._workers.remove(export)
                self.review_status.setText("Selected evidence and local review exported." if export.saved
                    else "Export failed: " + export.error)
                self.export_button.setEnabled(not self._closed)
        self.counters.setText(f"View: {len(self.model.rows)} / {self.model.maximum} rows · "
            f"Client gaps: {self._lost} · History evicted: {self.model.evicted}")
        if self._worker is None and not self._exports:
            self._timer.stop()

    def _selected(self) -> tuple[int, _Row] | None:
        indexes = self.table.selectionModel().selectedRows()
        index = indexes[0].row() if indexes else -1
        return (index, self.model.rows[index]) if 0 <= index < len(self.model.rows) else None

    def _show_selected(self, *_args) -> None:
        selected = self._selected()
        if selected is None:
            self.record_detail.clear()
            self.review_reason.clear()
            return
        _, row = selected
        self.record_detail.setPlainText(json.dumps(row.record, indent=2, ensure_ascii=True, allow_nan=False))
        self.verdict.setCurrentText(row.annotation["verdict"] if row.annotation else "needs-review")
        self.review_reason.setText(row.annotation["reason"] if row.annotation else "")

    def annotate_selected(self, verdict: str | None = None, reason: str | None = None) -> bool:
        selected = self._selected()
        verdict = verdict if verdict is not None else self.verdict.currentText()
        reason = (reason if reason is not None else self.review_reason.text()).strip()
        if selected is None or verdict not in _VERDICTS or not reason or len(reason) > 4096:
            self.review_status.setText("Select a record and supply a verdict with a nonempty explanation.")
            return False
        index, row = selected
        row.annotation = {"verdict": verdict, "reason": reason, "reviewed_at": time.time(), "scope": "local-note-only"}
        self.model.dataChanged.emit(self.model.index(index, 5), self.model.index(index, 5))
        self.review_status.setText("Local review recorded. Source evidence and security policy are unchanged.")
        return True

    def export_selected(self, path: str | Path | None = None) -> bool:
        selected = self._selected()
        if selected is None or self._exports or self._closed:
            self.review_status.setText("Select a record before exporting; wait for an active export to finish.")
            return False
        _, row = selected
        if path is None:
            path, _ = QFileDialog.getSaveFileName(self, "Export selected diagnostic view", "angerona-live-review.json", "JSON files (*.json)")
            if not path:
                return False
        target = Path(path)
        if not target.is_absolute() or target.suffix.lower() != ".json":
            self.review_status.setText("Choose an absolute path for a new .json file; existing files are never overwritten.")
            return False
        payload = json.dumps({"schema": "angerona.live-debug.local-review.v1", "exported_at": time.time(),
            "advisory_only": True, "original_view": row.record, "local_review": row.annotation,
            "policy_changes": False}, indent=2, ensure_ascii=True, allow_nan=False).encode("ascii")
        if len(payload) > _MAX_EXPORT_BYTES:
            self.review_status.setText("Selected evidence exceeds the bounded export limit.")
            return False
        export = _ExportWorker(target, payload)
        self._exports.append(export)
        self._workers.append(export)
        self.export_button.setEnabled(False)
        self.review_status.setText("Exporting the selected view and local note…")
        export.start()
        self._timer.start()
        return True

    def snapshot_text(self) -> str:
        """Bounded plain snapshot for an explicitly requested Black Box bundle."""
        result = {"schema": "angerona.live-debug.review-snapshot.v1", "status": self._status_text,
            "server_pid": self._connected_pid, "advisory_only": True, "client_gaps": self._lost,
            "history_evicted": self.model.evicted, "visible_records": len(self.model.rows), "records": []}
        for row in reversed(tuple(self.model.rows)[-20:]):
            result["records"].append({"original_view": row.record, "local_review": row.annotation})
            if len(json.dumps(result, ensure_ascii=True)) > 64 * 1024 - 200:
                result["records"].pop()
                break
        result["records"].reverse()
        result["omitted_visible_records"] = len(self.model.rows) - len(result["records"])
        return json.dumps(result, ensure_ascii=True, separators=(",", ":"))

    def stop_workers(self, timeout_ms: int = 150) -> bool:
        """Cancel reads and wait a bounded interval; retain any finishing worker."""
        self._closed = True
        self._timer.stop()
        _request_stop_all(self._workers)
        deadline = time.monotonic() + max(0, min(timeout_ms, 4000)) / 1000
        stopped = True
        for worker in tuple(self._workers):
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            stopped = worker.wait(remaining) and stopped
        return stopped

    def closeEvent(self, event):  # noqa: N802
        self.stop_workers()
        super().closeEvent(event)
