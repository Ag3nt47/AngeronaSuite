"""Non-executing GitHub source review integrated into the Red Team console."""
from __future__ import annotations

import queue
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QPlainTextEdit,
    QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget,
)

from angerona.core.data_paths import data_dir
from angerona.core.github_tool_catalog import (
    GitHubToolCatalog, ImportCancelled, ImportOperation, analysis_readiness,
    plain_text, resolve_import,
)

_WORKERS = threading.BoundedSemaphore(2)


class GitHubToolsPanel(QWidget):
    def __init__(self, parent=None, *, root: Path | None = None):
        super().__init__(parent)
        self._root = root
        self._catalog: GitHubToolCatalog | None = None
        self._plan = None
        self._rows: list[dict] = []
        self._busy = False
        self._operation: ImportOperation | None = None
        self._results: queue.Queue = queue.Queue(maxsize=1)
        self._lifetime = {"closed": False, "operation": None}
        lifetime = self._lifetime

        def on_destroyed(*_args):
            lifetime["closed"] = True
            if lifetime["operation"] is not None:
                lifetime["operation"].cancel()

        self.destroyed.connect(on_destroyed)
        layout = QVBoxLayout(self)
        title = QLabel("GitHub Tools — source review")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        note = QLabel("Import a pinned public repository and inspect its source as text. "
                      "Review status never grants permission to execute downloaded code.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.suggestions = QComboBox()
        self.suggestions.addItem("Choose a source-review example…", "")
        self.suggestions.addItem("Gitleaks", "https://github.com/gitleaks/gitleaks")
        self.suggestions.addItem("Bandit", "https://github.com/PyCQA/bandit")
        self.suggestions.currentIndexChanged.connect(self._suggestion)
        layout.addWidget(self.suggestions)
        inputs = QHBoxLayout()
        self.repository = QLineEdit()
        self.repository.setPlaceholderText("https://github.com/owner/repository")
        self.repository.setAccessibleName("GitHub repository URL")
        self.repository.setMaxLength(256)
        self.revision = QLineEdit("HEAD")
        self.revision.setPlaceholderText("Branch, tag or commit")
        self.revision.setAccessibleName("Repository revision")
        self.revision.setMaxLength(200)
        inputs.addWidget(self.repository, 3)
        inputs.addWidget(self.revision, 1)
        layout.addLayout(inputs)
        self.repository.textChanged.connect(self._invalidate_plan)
        self.revision.textChanged.connect(self._invalidate_plan)

        self.tabs = QTabWidget()
        source = QWidget()
        source_layout = QVBoxLayout(source)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.imports = QListWidget()
        self.imports.setAccessibleName("Imported repositories")
        self.files = QListWidget()
        self.files.setAccessibleName("Source archive files")
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setAccessibleName("Plain text source preview")
        self.preview.document().setMaximumBlockCount(8000)
        splitter.addWidget(self.imports)
        splitter.addWidget(self.files)
        splitter.addWidget(self.preview)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 2)
        source_layout.addWidget(splitter)
        self.tabs.addTab(source, "Source")
        self.verification = QPlainTextEdit()
        self.verification.setReadOnly(True)
        self.tabs.addTab(self.verification, "Verification")
        lab = QWidget()
        lab_layout = QVBoxLayout(lab)
        readiness = QLabel(analysis_readiness())
        readiness.setTextFormat(Qt.TextFormat.PlainText)
        readiness.setWordWrap(True)
        lab_layout.addWidget(readiness)
        self.run_button = QPushButton("Run analysis — unavailable")
        self.run_button.setEnabled(False)
        self.run_button.setToolTip(analysis_readiness())
        self.run_button.clicked.connect(self._explain_analysis_gate)
        lab_layout.addWidget(self.run_button)
        lab_layout.addStretch()
        self.tabs.addTab(lab, "Analysis Lab")
        layout.addWidget(self.tabs, 1)

        self.status = QLabel("Open this tab to load your source library.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        actions = QHBoxLayout()
        self.resolve_button = QPushButton("Resolve revision")
        self.import_button = QPushButton("Import pinned source")
        self.review_button = QPushButton("Mark reviewed")
        self.revoke_button = QPushButton("Revoke")
        self.cancel_button = QPushButton("Cancel")
        for button in (self.resolve_button, self.import_button, self.review_button,
                       self.revoke_button, self.cancel_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.resolve_button.clicked.connect(self._resolve)
        self.import_button.clicked.connect(self._import)
        self.review_button.clicked.connect(lambda: self._review("reviewed"))
        self.revoke_button.clicked.connect(lambda: self._review("revoked"))
        self.cancel_button.clicked.connect(self.cancel_pending)
        self.imports.currentRowChanged.connect(self._select_import)
        self.files.currentTextChanged.connect(self._select_file)
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll)
        self._loaded = False
        self._update_buttons()

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self._lifetime["closed"] = False
        if not self._loaded and not self._busy:
            root = self._root

            def load(_operation):
                catalog = GitHubToolCatalog(root or data_dir() / "github-source-library")
                return catalog, catalog.list_imports()

            self._start("load", load, "Loading source library…")

    def cancel_pending(self) -> None:
        if self._operation is not None:
            if self._operation.cancel():
                self.status.setText("Cancelling… The current network read may take up to 10 seconds.")
            else:
                self.status.setText("The verified import is being saved; finishing its index transaction.")

    def _explain_analysis_gate(self) -> None:
        # A direct signal emission cannot bypass the missing execution authority.
        self.run_button.setEnabled(False)
        self.status.setText(analysis_readiness())

    def _suggestion(self, _index):
        if self.suggestions.currentData():
            self.repository.setText(self.suggestions.currentData())

    def _invalidate_plan(self, *_args):
        self._plan = None
        self._update_buttons()

    def _row(self):
        index = self.imports.currentRow()
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def _update_buttons(self):
        row = self._row()
        self.resolve_button.setEnabled(not self._busy and self._catalog is not None)
        self.import_button.setEnabled(not self._busy and self._plan is not None)
        self.review_button.setEnabled(not self._busy and row is not None and row["state"] == "review_only")
        self.revoke_button.setEnabled(not self._busy and row is not None and row["state"] != "revoked")
        self.cancel_button.setEnabled(self._busy)
        for widget in (self.repository, self.revision, self.suggestions, self.imports, self.files):
            widget.setEnabled(not self._busy)

    def _start(self, kind, work, message):
        if self._busy:
            return
        if not _WORKERS.acquire(blocking=False):
            self.status.setText("Source review workers are busy; reopen this tab after they finish.")
            return
        self._busy = True
        operation = ImportOperation()
        self._operation = operation
        self._lifetime["operation"] = operation
        results, lifetime = self._results, self._lifetime

        def run():
            try:
                result = work(operation)
                outcome = (kind, result, "")
            except ImportCancelled as exc:
                outcome = (kind, None, str(exc))
            except Exception as exc:
                # Never render response bodies, credentials or arbitrary exception reprs.
                detail = str(exc)[:300] if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__
                outcome = (kind, None, "Source review failed: " + plain_text(detail))
            finally:
                _WORKERS.release()
            if not lifetime["closed"]:
                results.put_nowait(outcome)

        self.status.setText(message)
        self._update_buttons()
        try:
            threading.Thread(target=run, daemon=True, name="GitHubSourceReview").start()
        except Exception:
            _WORKERS.release()
            self._busy = False
            self._update_buttons()
            raise
        self._timer.start()

    def _poll(self):
        try:
            kind, result, error = self._results.get_nowait()
        except queue.Empty:
            return
        self._timer.stop()
        if self._operation is not None and self._operation.cancelled.is_set():
            error = "Source review operation cancelled."
        self._busy = False
        self._operation = None
        self._lifetime["operation"] = None
        if error:
            self.status.setText(error)
        elif kind == "load":
            self._catalog, rows = result
            self._loaded = True
            self._populate(rows)
            self.status.setText("Source library loaded. Resolve a revision to prepare an import.")
        elif kind == "resolve":
            self._plan = result
            self.verification.setPlainText(
                f"Repository: {result.repository}\nRequested: {result.revision}\n"
                f"Pinned commit: {result.commit}\nReported license: {result.license}\n\n"
                "Ready to import this exact source snapshot. Archive size and SHA-256 are "
                "checked on download. Source review does not establish executable trust."
            )
            self.tabs.setCurrentWidget(self.verification)
            self.status.setText("Revision resolved. Inspect the commit, then import pinned source.")
        elif kind in {"import", "review"}:
            self._populate(result)
            self.status.setText("Source library saved. Review labels never enable execution.")
        elif kind == "files":
            self.files.blockSignals(True)
            self.files.clear()
            self.files.addItems(result)
            self.files.blockSignals(False)
            self.status.setText(f"Verified archive digest; {len(result):,} files available for text review.")
        elif kind == "preview":
            self.preview.setPlainText(result)
            self.status.setText("Plain text preview. Repository contents are untrusted data.")
        self._update_buttons()

    def _populate(self, rows):
        self.imports.blockSignals(True)
        self.imports.clear()
        self._rows = rows
        self.imports.addItems([
            f'{row["repository"]}\n{row["commit"][:12]} · {row["state"].replace("_", " ")}'
            for row in rows
        ])
        self.imports.blockSignals(False)
        self.files.clear()
        self.preview.clear()

    def _resolve(self):
        url, revision = self.repository.text(), self.revision.text()
        self._plan = None
        self._start("resolve", lambda operation: resolve_import(url, revision, operation),
                    "Resolving the public repository revision…")

    def _import(self):
        catalog, plan = self._catalog, self._plan
        if catalog is None or plan is None:
            return

        def work(operation):
            catalog.import_source(plan, operation)
            return catalog.list_imports()

        self._start("import", work, "Downloading and validating the pinned source archive…")

    def _review(self, state):
        catalog, row = self._catalog, self._row()
        if catalog is not None and row is not None:
            self._start("review", lambda operation: (
                operation.check(), catalog.set_review_state(row["id"], state, operation)
            )[1], "Verifying the source digest and saving its review state…")

    def _select_import(self, _index):
        if self._busy:
            return
        row, catalog = self._row(), self._catalog
        self.files.clear()
        self.preview.clear()
        if row is not None and catalog is not None:
            self.verification.setPlainText(
                plain_text("\n".join(f"{key}: {value}" for key, value in row.items()))
                + "\n\nStored archive integrity is checked when browsing. "
                "This is local source-review metadata, not executable approval."
            )
            self._start("files", lambda _operation: catalog.files(row["id"]), "Checking imported source…")
        self._update_buttons()

    def _select_file(self, filename):
        row, catalog = self._row(), self._catalog
        if not self._busy and filename and row is not None and catalog is not None:
            self._start("preview", lambda _operation: catalog.preview(row["id"], filename),
                        "Reading bounded source text…")
