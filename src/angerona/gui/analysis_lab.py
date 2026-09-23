"""Responsive operator controls for the fixed offline analyzer catalog."""
from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QPlainTextEdit, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from angerona.core import tool_analysis_jobs as jobs
from angerona.core.github_tool_catalog import plain_text
from angerona.core.source_sandbox import _atomic_bytes_write

_WORKERS = threading.BoundedSemaphore(2)


class AnalysisLabPanel(QWidget):
    def __init__(self, parent=None, *, root=None):
        super().__init__(parent)
        self._root = root
        self._ready = False
        self._busy = False
        self._loaded = False
        self._rows = []
        self._report = None
        self._operation = None
        self._queue = queue.Queue(maxsize=40)
        self._lifetime = {'closed': False, 'operation': None}
        lifetime = self._lifetime

        def destroyed(*_args):
            lifetime['closed'] = True
            if lifetime['operation'] is not None:
                lifetime['operation'].cancel()

        self.destroyed.connect(destroyed)
        layout = QVBoxLayout(self)
        self.status = QLabel('Open Analysis Lab to check its optional emulator and reviewed runtime.')
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        note = QLabel('Analyze a copy of local UTF-8 source. Offline, diskless QEMU guest; '
                      '2,000 files / 16 MiB, five minutes. Results are external analysis. '
                      'Imported repositories never become runnable tools.')
        note.setWordWrap(True)
        layout.addWidget(note)
        setup = QHBoxLayout()
        self.setup_button = QPushButton('Set up Lab emulator…')
        self.prepare_button = QPushButton('Prepare runtime')
        self.check_button = QPushButton('Check readiness')
        self.cleanup_button = QPushButton('Clear interrupted jobs')
        self.setup_button.clicked.connect(self._setup)
        self.prepare_button.clicked.connect(self._prepare)
        self.check_button.clicked.connect(self._check)
        self.cleanup_button.clicked.connect(self._cleanup)
        setup.addWidget(self.setup_button)
        setup.addWidget(self.prepare_button)
        setup.addWidget(self.check_button)
        setup.addWidget(self.cleanup_button)
        layout.addLayout(setup)
        inputs = QHBoxLayout()
        self.tool = QComboBox()
        self.tool.addItem('Bandit · Python checks', 'bandit')
        self.tool.addItem('Gitleaks · secret checks', 'gitleaks')
        self.input_path = QLineEdit()
        self.input_path.setPlaceholderText('Select a local project folder')
        self.input_path.setAccessibleName('Analysis source folder')
        self.browse_button = QPushButton('Browse…')
        self.browse_button.clicked.connect(self._browse)
        self.input_path.textChanged.connect(self._buttons)
        inputs.addWidget(self.tool)
        inputs.addWidget(self.input_path, 1)
        inputs.addWidget(self.browse_button)
        layout.addLayout(inputs)
        actions = QHBoxLayout()
        self.run_button = QPushButton('Run analysis')
        self.cancel_button = QPushButton('Cancel analysis')
        self.export_button = QPushButton('Export report…')
        self.run_button.clicked.connect(self._run)
        self.cancel_button.clicked.connect(self.cancel_pending)
        self.export_button.clicked.connect(self._export)
        for button in (self.run_button, self.cancel_button, self.export_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.history = QListWidget()
        self.history.setAccessibleName('External analysis history')
        self.history.currentRowChanged.connect(self._select_report)
        self.report_text = QPlainTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setAccessibleName('Redacted analysis results')
        self.report_text.document().setMaximumBlockCount(5000)
        splitter.addWidget(self.history)
        splitter.addWidget(self.report_text)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll)
        self._buttons()

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        if not self._loaded and not self._busy:
            root = self._root
            self._start('load', lambda _op, _progress: self._load(root), 'Checking Analysis Lab…')

    @staticmethod
    def _load(root):
        root = Path(root) if root is not None else jobs.default_root()
        return root, jobs.readiness(root), jobs.history(root)

    def _buttons(self, *_args):
        self.run_button.setEnabled(not self._busy and self._ready and bool(self.input_path.text().strip()))
        for widget in (self.setup_button, self.prepare_button, self.check_button, self.cleanup_button, self.browse_button,
                       self.input_path, self.tool, self.history):
            widget.setEnabled(not self._busy)
        self.cancel_button.setEnabled(self._busy)
        self.export_button.setEnabled(not self._busy and self._report is not None)

    def _setup(self):
        from angerona.gui.analysis_qemu_setup import QEMUSetupDialog
        dialog = QEMUSetupDialog(self, root=self._root)
        dialog.exec()
        dialog.deleteLater()
        self._ready = False
        self._loaded = False
        self._buttons()
        root = self._root
        self._start('load', lambda _op, _progress: self._load(root), 'Checking Analysis Lab…')

    def _start(self, kind, work, message):
        if self._busy:
            return
        if not _WORKERS.acquire(blocking=False):
            self.status.setText('Analysis workers are busy. Wait for the current operation to finish.')
            return
        self._busy = True
        operation = jobs.AnalysisOperation()
        self._operation = operation
        self._lifetime['operation'] = operation
        pending, lifetime = self._queue, self._lifetime

        def progress(value):
            if not lifetime['closed']:
                try:
                    pending.put_nowait(('progress', plain_text(value), None))
                except queue.Full:
                    pass

        def worker():
            try:
                value = work(operation, progress)
                outcome = kind, value, None
            except Exception as exc:
                detail = plain_text(str(exc))[:350] if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__
                outcome = kind, None, detail
            finally:
                _WORKERS.release()
            if not lifetime['closed']:
                # Drop progress rather than blocking delivery of the final outcome.
                while True:
                    try:
                        pending.put_nowait(outcome)
                        break
                    except queue.Full:
                        try:
                            pending.get_nowait()
                        except queue.Empty:
                            # The GUI may have drained progress after Full.
                            # Retry the final outcome even when nothing remains
                            # for this producer to evict.
                            pass

        self.status.setText(message)
        self._buttons()
        try:
            threading.Thread(target=worker, daemon=True, name='OfflineAnalysisLab').start()
        except Exception:
            _WORKERS.release()
            self._busy = False
            self._operation = None
            self._lifetime['operation'] = None
            self._buttons()
            raise
        self._timer.start()

    def _poll(self):
        while True:
            try:
                kind, value, error = self._queue.get_nowait()
            except queue.Empty:
                return
            if kind == 'progress':
                if self._operation is None or not self._operation.cancelled.is_set():
                    self.status.setText(value)
                continue
            self._timer.stop()
            if self._operation is not None and self._operation.cancelled.is_set():
                error = 'Analysis cancelled; no late result was accepted.'
            self._operation = None
            self._lifetime['operation'] = None
            self._busy = False
            if error:
                self._ready = False
                self.status.setText(error)
            elif kind == 'load':
                self._root, (self._ready, message), rows = value
                self._loaded = True
                self._populate(rows)
                self.status.setText(message)
            elif kind in {'prepare', 'cleanup'}:
                self._ready = False
                self.status.setText(value)
            elif kind == 'check':
                self._ready, message = value
                self.status.setText(message)
            elif kind == 'run':
                self._populate([value, *self._rows])
                self.history.setCurrentRow(0)
                self.status.setText('Analysis completed. Findings need review; zero findings is not a security guarantee.')
            elif kind == 'export':
                self.status.setText('Redacted external-analysis report exported.')
            self._buttons()
            return

    def _populate(self, rows):
        self.history.blockSignals(True)
        self._rows = rows
        self.history.clear()
        self.history.addItems([f"{row['tool']} · {len(row['findings'])} findings · {row['job'][:8]}" for row in rows])
        self.history.blockSignals(False)

    def _select_report(self, index):
        if not 0 <= index < len(self._rows):
            return
        self._report = self._rows[index]
        row = self._report
        lines = [f"External analysis · {row['tool']} {row['tool_version']}",
                 f"Files analyzed: {row['file_count']} · Skipped entries: {row['skipped']} · Parse errors: {row['errors']}",
                 f"Input SHA-256: {row['input_sha256']}",
                 'Secret values and source snippets are excluded. No response actions are authorized.', '']
        for finding in row['findings']:
            name = row['files'][finding['file']]
            lines.append(f"{finding['severity']}  {finding['rule']}  {name}:{finding['line']}")
        if not row['findings']:
            lines.append('No findings in eligible files. Skipped files and unsupported content were not analyzed.')
        self.report_text.setPlainText(plain_text('\n'.join(lines)))
        self._buttons()

    def _browse(self):
        directory = QFileDialog.getExistingDirectory(self, 'Select source to analyze')
        if directory:
            self.input_path.setText(directory)

    def _prepare(self):
        root = self._root or jobs.default_root()
        self._root = root
        self._start('prepare', lambda op, progress: jobs.prepare_runtime(root, op, progress),
                    'Downloading the pinned runtime and verifying every artifact…')

    def _check(self):
        root = self._root or jobs.default_root()
        self._root = root
        self._start('check', lambda op, _progress: jobs.check_runtime(root, op),
                    'Checking QEMU isolation, process limits and both analyzers with harmless fixtures…')

    def _cleanup(self):
        root = self._root or jobs.default_root()
        self._root = root
        self._start('cleanup', lambda op, _progress: jobs.clear_interrupted_jobs(root, op),
                    'Stopping interrupted analysis VMs and clearing their temporary input copies…')

    def _run(self):
        if not self._ready or not self.input_path.text().strip():
            self.status.setText('Prepare the runtime, Check readiness and select a source folder first.')
            return
        root, directory, tool = self._root, self.input_path.text().strip(), self.tool.currentData()
        self._start('run', lambda op, _progress: jobs.run_analysis(root, directory, tool, op),
                    'Copying bounded source input and starting the offline analyzer…')

    def cancel_pending(self):
        if self._operation is not None:
            if self._operation.cancel():
                self.status.setText('Cancelling and stopping the isolated analysis process…')
            else:
                self.status.setText('Finishing the redacted report save…')

    def _export(self):
        if self._report is None:
            return
        selected, _filter = QFileDialog.getSaveFileName(self, 'Export redacted analysis report',
                                                      'analysis-report.json', 'JSON (*.json)')
        if selected:
            path, report = Path(selected), dict(self._report)
            def work(operation, _progress):
                operation.check()
                operation.seal()
                _atomic_bytes_write(path, json.dumps(report, ensure_ascii=True, indent=2).encode(), root=path.parent)
            self._start('export', work, 'Saving the redacted external-analysis report…')
