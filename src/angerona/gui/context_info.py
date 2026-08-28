"""Reusable contextual Info tab and read-only-boundary source sandbox UI."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from angerona.core.data_paths import data_dir, project_root
from angerona.core.menu_info import MenuInfoTopic, get_menu_info, normalize_tab_label
from angerona.core.source_sandbox import SourceSandboxWorkspace
from angerona.gui.animations import RunSpinner


def _display_location(value: str) -> str:
    try:
        runtime_root = str(data_dir())
    except Exception:
        runtime_root = "<runtime data unavailable>"
    return str(value).replace("{data}", runtime_root)


class SourceSandboxDialog(QDialog):
    """Edit allow-listed working copies without touching installed code."""

    def __init__(
        self,
        workspace: SourceSandboxWorkspace,
        parent=None,
        *,
        preselect: str | None = None,
        find_text: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.workspace.ensure()
        self._current = ""
        self._changing_file = False
        self._initial_find_text = str(find_text or "")
        self.setWindowTitle("Angerona — Isolated Source Sandbox")
        self.setMinimumSize(760, 520)
        self.resize(1040, 720)
        self.setModal(False)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

        root = QVBoxLayout(self)
        banner = QLabel(
            "ISOLATED WORKING COPY — Save and Reset affect only the sandbox. "
            "Installed Angerona code and live sensors are never changed here."
        )
        banner.setWordWrap(True)
        banner.setStyleSheet(
            "background:#0c4a6e;color:#e0f2fe;font-weight:700;"
            "padding:8px 12px;border-radius:6px;"
        )
        root.addWidget(banner)

        picker = QHBoxLayout()
        picker.addWidget(QLabel("Implementation file:"))
        self.file_box = QComboBox()
        for item in self.workspace.files:
            self.file_box.addItem(item.relative_path, item.relative_path)
        picker.addWidget(self.file_box, 1)
        root.addLayout(picker)

        self.source_path = QLabel()
        self.source_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.source_path.setWordWrap(True)
        self.working_path = QLabel()
        self.working_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.working_path.setWordWrap(True)
        root.addWidget(self.source_path)
        root.addWidget(self.working_path)

        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setTabStopDistance(
            4 * self.editor.fontMetrics().horizontalAdvance(" ")
        )
        try:
            from angerona.gui.sandbox_editor import PythonHighlighter

            self._highlighter = PythonHighlighter(self.editor.document())
        except Exception:
            self._highlighter = None
        root.addWidget(self.editor, 1)

        self.status = QLabel(
            "No code is executed from this editor. Use Check Syntax before saving."
        )
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color:#94a3b8;")
        root.addWidget(self.status)

        buttons = QHBoxLayout()
        check = QPushButton("Check Syntax")
        save = QPushButton("Save Sandbox Copy")
        reset = QPushButton("Reset Current Copy")
        reset_all = QPushButton("Reset All Sandbox Changes")
        close = QPushButton("Close")
        check.clicked.connect(self._check_syntax)
        save.clicked.connect(self._save)
        reset.clicked.connect(self._reset_current)
        reset_all.clicked.connect(self._reset_all)
        close.clicked.connect(self.close)
        buttons.addWidget(check)
        buttons.addWidget(save)
        buttons.addWidget(reset)
        buttons.addWidget(reset_all)
        buttons.addStretch()
        buttons.addWidget(close)
        root.addLayout(buttons)

        self.file_box.currentIndexChanged.connect(self._select_file)
        if self.file_box.count():
            initial_index = self.file_box.findData(str(preselect or ""))
            if initial_index < 0:
                initial_index = 0
            self._changing_file = True
            self.file_box.setCurrentIndex(initial_index)
            self._changing_file = False
            self._select_file(initial_index)

    def _confirm_discard(self) -> bool:
        if not self.editor.document().isModified():
            return True
        answer = QMessageBox.question(
            self,
            "Unsaved sandbox changes",
            "Discard the unsaved changes in this editor? Installed code is not affected.",
            QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Discard

    def _select_file(self, index: int) -> None:
        if self._changing_file or index < 0:
            return
        requested = str(self.file_box.itemData(index) or "")
        if self._current and requested != self._current and not self._confirm_discard():
            self._changing_file = True
            old_index = self.file_box.findData(self._current)
            self.file_box.setCurrentIndex(old_index)
            self._changing_file = False
            return
        item = self.workspace.file(requested)
        self._current = requested
        self.source_path.setText(f"Installed source (read-only here): {item.source_path}")
        self.working_path.setText(f"Sandbox copy: {item.working_path}")
        self.editor.setPlainText(self.workspace.read(requested))
        self.editor.document().setModified(False)
        state = "modified" if self.workspace.changed(requested) else "matches installed source"
        location = ""
        if self._initial_find_text:
            find_text = self._initial_find_text
            self._initial_find_text = ""
            if self.editor.find(find_text):
                location = f" Opened at {find_text}."
        self.status.setText(f"Loaded isolated copy — {state}.{location}")

    def _check_syntax(self) -> bool:
        if not self._current:
            return False
        try:
            if self._current.casefold().endswith(".py"):
                ast.parse(self.editor.toPlainText(), filename=self._current)
            self.status.setText("Syntax check passed. No code was executed.")
            self.status.setStyleSheet("color:#22c55e;")
            return True
        except SyntaxError as exc:
            self.status.setText(
                f"Syntax check failed at line {exc.lineno}: {exc.msg}. Nothing was saved."
            )
            self.status.setStyleSheet("color:#ef4444;")
            return False

    def _save(self) -> None:
        if not self._current or not self._check_syntax():
            return
        try:
            item = self.workspace.save(self._current, self.editor.toPlainText())
            self.editor.document().setModified(False)
            self.status.setText(
                f"Saved sandbox copy only: {item.working_path}"
            )
            self.status.setStyleSheet("color:#22c55e;")
        except Exception as exc:
            self.status.setText(f"Sandbox save failed: {exc}")
            self.status.setStyleSheet("color:#ef4444;")

    def _reset_current(self) -> None:
        if not self._current:
            return
        if QMessageBox.question(
            self,
            "Reset sandbox copy",
            "Discard this file's sandbox changes and recopy the installed source? "
            "Installed code will not be changed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self.workspace.reset((self._current,))
        self.editor.setPlainText(self.workspace.read(self._current))
        self.editor.document().setModified(False)
        self.status.setText("Sandbox copy reset to the installed source.")
        self.status.setStyleSheet("color:#22c55e;")

    def _reset_all(self) -> None:
        if QMessageBox.question(
            self,
            "Reset all sandbox changes",
            "Discard every working-copy change for this menu? Installed code will "
            "not be changed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self.workspace.reset()
        if self._current:
            self.editor.setPlainText(self.workspace.read(self._current))
            self.editor.document().setModified(False)
        self.status.setText("All sandbox copies reset to installed source.")
        self.status.setStyleSheet("color:#22c55e;")

    def closeEvent(self, event) -> None:  # noqa: N802
        if not self._confirm_discard():
            event.ignore()
            return
        event.accept()


class ContextInfoTab(QWidget):
    """The visible Info tab, refreshed for the last functional tab visited."""

    def __init__(self, surface: str, parent=None) -> None:
        super().__init__(parent)
        self.surface = surface
        self.topic: MenuInfoTopic | None = None
        self.workspace: SourceSandboxWorkspace | None = None
        self._sandbox_dialog: SourceSandboxDialog | None = None

        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        self.layout = QVBoxLayout(body)
        self.layout.setContentsMargins(12, 10, 12, 10)
        self.layout.setSpacing(10)

        self.heading = QLabel("Info")
        self.heading.setStyleSheet("font-size:18px;font-weight:700;color:#38bdf8;")
        self.layout.addWidget(self.heading)
        self.loading_spinner = RunSpinner()
        self.layout.addWidget(self.loading_spinner)
        self._load_generation = 0
        self._scheduled_generation = 0
        self._topic_finish_timer = QTimer(self)
        self._topic_finish_timer.setSingleShot(True)
        self._topic_finish_timer.timeout.connect(
            self._finish_scheduled_topic_loading
        )
        self.overview = QLabel()
        self.overview.setWordWrap(True)
        self.overview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.layout.addWidget(self.overview)

        section = QLabel("Functions and meanings")
        section.setStyleSheet("font-weight:700;color:#93c5fd;")
        self.layout.addWidget(section)
        self.meanings = QTableWidget(0, 2)
        self.meanings.setHorizontalHeaderLabels(["Function / term", "Meaning"])
        self.meanings.verticalHeader().setVisible(False)
        self.meanings.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.meanings.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.meanings.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.meanings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.meanings.setMinimumHeight(150)
        self.meanings.setSortingEnabled(True)
        self.meanings.cellDoubleClicked.connect(self._show_meaning_detail)
        self.layout.addWidget(self.meanings)

        paths_title = QLabel("Related files and locations")
        paths_title.setStyleSheet("font-weight:700;color:#93c5fd;")
        self.layout.addWidget(paths_title)
        self.paths = QTableWidget(0, 2)
        self.paths.setHorizontalHeaderLabels(["Type", "Absolute path / location"])
        self.paths.verticalHeader().setVisible(False)
        self.paths.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.paths.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.paths.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.paths.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.paths.setMinimumHeight(170)
        self.paths.setSortingEnabled(True)
        self.paths.cellDoubleClicked.connect(self._copy_path_detail)
        self.layout.addWidget(self.paths)

        sandbox_note = QLabel(
            "Code sandbox: opens private working copies under Angerona's runtime "
            "data folder. Saving or resetting there never modifies installed code."
        )
        sandbox_note.setWordWrap(True)
        sandbox_note.setStyleSheet("color:#94a3b8;")
        self.layout.addWidget(sandbox_note)
        buttons = QHBoxLayout()
        self.open_sandbox = QPushButton("Open Code Sandbox")
        self.reset_sandbox = QPushButton("Reset Sandbox Changes")
        self.copy_paths = QPushButton("Copy Locations")
        self.open_sandbox.clicked.connect(self._open_sandbox)
        self.reset_sandbox.clicked.connect(self._reset_sandbox)
        self.copy_paths.clicked.connect(self._copy_locations)
        buttons.addWidget(self.open_sandbox)
        buttons.addWidget(self.reset_sandbox)
        buttons.addWidget(self.copy_paths)
        buttons.addStretch()
        self.layout.addLayout(buttons)
        self.sandbox_status = QLabel()
        self.sandbox_status.setWordWrap(True)
        self.sandbox_status.setStyleSheet("color:#94a3b8;")
        self.layout.addWidget(self.sandbox_status)
        self.layout.addStretch()

        scroll.setWidget(body)
        outer.addWidget(scroll)

    def set_topic(self, topic: MenuInfoTopic | None, *, animate: bool = True) -> None:
        self._load_generation += 1
        generation = self._load_generation
        if animate:
            self.loading_spinner.start("Loading overview")
        else:
            self.loading_spinner.stop()
        self.topic = topic
        self.meanings.setSortingEnabled(False)
        self.paths.setSortingEnabled(False)
        if topic is None:
            self.heading.setText("Info unavailable")
            self.overview.setText(
                "No contextual description has been registered for this menu yet."
            )
            self.meanings.setRowCount(0)
            self.paths.setRowCount(0)
            self.workspace = None
            self.open_sandbox.setEnabled(False)
            self.reset_sandbox.setEnabled(False)
            self.meanings.setSortingEnabled(True)
            self.paths.setSortingEnabled(True)
            if animate:
                self._schedule_topic_finish(generation)
            return

        self.heading.setText(f"About {topic.title}")
        self.overview.setText(topic.overview)
        self.meanings.setRowCount(len(topic.functions))
        for row, (name, meaning) in enumerate(topic.functions):
            self.meanings.setItem(row, 0, QTableWidgetItem(name))
            self.meanings.setItem(row, 1, QTableWidgetItem(meaning))
        self.meanings.resizeRowsToContents()

        rows: list[tuple[str, str]] = []
        try:
            self.workspace = SourceSandboxWorkspace(
                f"{self.surface}-{topic.key}", topic.source_paths
            )
            available_by_name = {
                item.relative_path: str(item.source_path)
                for item in self.workspace.files
            }
            sandbox_location = str(self.workspace.root)
            sandbox_available = self.workspace.available
            sandbox_status = (
                f"Sandbox scope: {len(self.workspace.files)} available implementation "
                f"file(s) · {self.workspace.root}"
            )
        except Exception as exc:
            # Contextual help is part of several primary windows.  A protected,
            # unavailable, or temporarily unreadable sandbox directory must not
            # prevent Settings (or another menu) from opening.  Keep the help
            # and source locations useful while making the unavailable action
            # explicit instead of raising out of the window constructor.
            self.workspace = None
            root = project_root()
            available_by_name = {
                relative: str(root / relative)
                for relative in topic.source_paths
                if (root / relative).is_file()
            }
            sandbox_location = "Unavailable in this session"
            sandbox_available = False
            sandbox_status = (
                "Code sandbox unavailable in this session. Settings and help "
                f"remain usable. Details: {exc}"
            )
        for relative in topic.source_paths:
            rows.append(
                ("Source", available_by_name.get(relative, f"{relative} (not available in this build)"))
            )
        rows.extend(("Runtime", _display_location(value)) for value in topic.locations)
        rows.append(("Sandbox", sandbox_location))
        self.paths.setRowCount(len(rows))
        for row, (kind, location) in enumerate(rows):
            self.paths.setItem(row, 0, QTableWidgetItem(kind))
            self.paths.setItem(row, 1, QTableWidgetItem(location))
        self.paths.resizeRowsToContents()
        self.meanings.setSortingEnabled(True)
        self.paths.setSortingEnabled(True)
        self.open_sandbox.setEnabled(sandbox_available)
        self.reset_sandbox.setEnabled(sandbox_available)
        self.sandbox_status.setText(sandbox_status)
        if not sandbox_available:
            self.open_sandbox.setToolTip(sandbox_status)
            self.reset_sandbox.setToolTip(sandbox_status)
        if animate:
            self._schedule_topic_finish(generation)

    def _show_meaning_detail(self, row: int, _column: int) -> None:
        name = self.meanings.item(row, 0)
        meaning = self.meanings.item(row, 1)
        if name is None or meaning is None:
            return
        QMessageBox.information(
            self,
            str(name.text())[:200],
            str(meaning.text())[:8_000],
        )

    def _copy_path_detail(self, row: int, _column: int) -> None:
        kind = self.paths.item(row, 0)
        location = self.paths.item(row, 1)
        if location is None:
            return
        exact = str(location.text())[:16_384]
        QGuiApplication.clipboard().setText(exact)
        self.sandbox_status.setText(
            f"{str(kind.text()) if kind else 'Location'} copied exactly: {exact}"
        )

    def _schedule_topic_finish(self, generation: int) -> None:
        """Finish only the newest Info refresh on this widget's owned timer."""
        self._scheduled_generation = generation
        self._topic_finish_timer.start(180)

    def _finish_scheduled_topic_loading(self) -> None:
        self._finish_topic_loading(self._scheduled_generation)

    def _finish_topic_loading(self, generation: int) -> None:
        if generation == self._load_generation:
            self.loading_spinner.finish("Overview ready")

    def _open_sandbox(self) -> None:
        if self.workspace is None or not self.workspace.available:
            return
        try:
            dialog = SourceSandboxDialog(self.workspace, self)
            self._sandbox_dialog = dialog
            dialog.destroyed.connect(lambda *_: setattr(self, "_sandbox_dialog", None))
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()
        except Exception as exc:
            QMessageBox.warning(self, "Code Sandbox", f"Could not open the sandbox:\n{exc}")

    def _reset_sandbox(self) -> None:
        if self.workspace is None or not self.workspace.available:
            return
        changed = self.workspace.changed_paths()
        if not changed:
            self.sandbox_status.setText("Sandbox already matches the installed source.")
            return
        if QMessageBox.question(
            self,
            "Reset sandbox changes",
            f"Discard changes in {len(changed)} sandbox file(s)? Installed code will "
            "not be changed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self.workspace.reset()
        self.sandbox_status.setText(
            "Sandbox changes reset. Installed code was not modified."
        )

    def _copy_locations(self) -> None:
        lines: list[str] = []
        for row in range(self.paths.rowCount()):
            kind = self.paths.item(row, 0)
            location = self.paths.item(row, 1)
            if kind and location:
                lines.append(f"{kind.text()}: {location.text()}")
        QGuiApplication.clipboard().setText("\n".join(lines))
        self.sandbox_status.setText("Related locations copied to the clipboard.")


class TabbedInfoController(QObject):
    """Keep one Info tab contextual to the last non-Info tab selected."""

    def __init__(
        self,
        tabs: QTabWidget,
        surface: str,
        resolver: Callable[[str], MenuInfoTopic | None] | None = None,
    ) -> None:
        super().__init__(tabs)
        self.tabs = tabs
        self.surface = surface
        self.resolver = resolver or (lambda label: get_menu_info(surface, label))
        self.last_functional_index = max(0, tabs.currentIndex())
        self.info = ContextInfoTab(surface, tabs)
        self.info_index = tabs.addTab(self.info, "Info")
        tabs.currentChanged.connect(self._changed)
        self._refresh(animate=False)

    def _changed(self, index: int) -> None:
        if index != self.info_index:
            self.last_functional_index = index
            return
        self._refresh(animate=True)

    def _refresh(self, *, animate: bool) -> None:
        if 0 <= self.last_functional_index < self.tabs.count():
            label = self.tabs.tabText(self.last_functional_index)
            self.info.set_topic(self.resolver(label), animate=animate)


def attach_context_info(
    tabs: QTabWidget,
    surface: str,
    *,
    resolver: Callable[[str], MenuInfoTopic | None] | None = None,
) -> TabbedInfoController:
    """Append one exact ``Info`` tab to a completed QTabWidget."""
    existing = getattr(tabs, "_angerona_info_controller", None)
    if isinstance(existing, TabbedInfoController):
        return existing
    controller = TabbedInfoController(tabs, surface, resolver)
    tabs._angerona_info_controller = controller  # type: ignore[attr-defined]
    return controller


def module_info_topic(module, tab_label: str) -> MenuInfoTopic:
    """Build contextual module documentation without importing module internals."""
    normalized = normalize_tab_label(tab_label)
    descriptions = {
        "overview": ("Controls", "Start, stop, restart, test, and inspect this module."),
        "performance": ("Performance", "Live event rate, health trend, throttle, and worker state."),
        "history": ("History", "The module's bounded recent event record and keyword filter."),
        "dependencies": ("Dependencies", "Required and optional runtime components used by this module."),
        "api keys": ("Credentials", "Read-only provider readiness; credential changes remain in Settings."),
        "help": ("Help", "Setup and troubleshooting guidance for eligible AI modules."),
    }
    meaning = descriptions.get(normalized, (tab_label, "The selected module view."))
    sources = ["src/angerona/gui/pages.py"]
    try:
        source = Path(inspect.getsourcefile(type(module)) or "").resolve()
        relative = source.relative_to(project_root().resolve()).as_posix()
        if relative not in sources:
            sources.insert(0, relative)
    except (OSError, TypeError, ValueError):
        pass
    name = str(getattr(module, "name", type(module).__name__))
    description = str(
        getattr(module, "description", "This defensive module contributes to Angerona's local protection pipeline.")
    )
    return MenuInfoTopic(
        key=f"module-{normalize_tab_label(name).replace(' ', '-')}-{normalized.replace(' ', '-')}",
        title=f"{name} — {tab_label}",
        overview=description,
        functions=(
            meaning,
            ("Health", "The module's self-reported operating state, not a guarantee that every threat is detectable."),
            ("Sandbox", "A private working copy for inspection and experiments; Reset never rewrites installed code."),
        ),
        source_paths=tuple(sources),
        locations=("{data}/settings.json", "{data}/shared_logs"),
    )
