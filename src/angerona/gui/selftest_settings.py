"""Settings entry point for the bounded module checks and their source."""
from __future__ import annotations

import ast

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from angerona.core.selftest_guidance import module_guidance
from angerona.core.selftest_remediation import recovery_setting_key


def _bundled_test(module) -> tuple[str, str]:
    """Use the declared method owner and fixed bundled source namespace."""
    if getattr(module, "_angerona_origin", "") != "builtin":
        return "", ""
    for owner in type(module).__mro__:
        if "self_test" not in owner.__dict__:
            continue
        package = owner.__module__.split(".")
        if len(package) == 3 and package[:2] in (["angerona", "modules"], ["angerona", "core"]) and package[2].isidentifier():
            return f"src/{'/'.join(package)}.py", owner.__name__
        break
    return "", ""


def _method_source(source: str, owner: str) -> str:
    """Find the exact class method without importing or executing this copy."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef) and node.name == owner:
            for member in node.body:
                if isinstance(member, ast.FunctionDef) and member.name == "self_test":
                    start = min([member.lineno, *(d.lineno for d in member.decorator_list)])
                    return "\n".join(source.splitlines()[start - 1:member.end_lineno])
    return ""


class SelfTestSettingsPanel(QWidget):
    def __init__(self, dashboard, config, read_source, parent=None):
        super().__init__(parent)
        self._modules = getattr(getattr(dashboard, "manager", None), "modules", {})
        self._run_check = getattr(dashboard, "_run_self_test", None)
        self._read_source = read_source
        self._recovery_modules = set(getattr(config, "selftest_auto_recover_modules", ()))
        self._sandbox_windows = {}
        layout = QVBoxLayout(self)

        summary = QLabel("Run the module’s installed diagnostic and review its result, coverage and next steps.")
        summary.setWordWrap(True)
        layout.addWidget(summary)
        actions = QHBoxLayout()
        self.modules = QComboBox(self)
        self.modules.setAccessibleName("Module to test")
        self.modules.addItems(sorted(self._modules))
        actions.addWidget(self.modules, 1)
        self.run_selected = QPushButton("Run selected test", self)
        self.run_selected.clicked.connect(lambda: self._start([self.modules.currentText()]))
        actions.addWidget(self.run_selected)
        self.run_all = QPushButton("Run all tests", self)
        self.run_all.clicked.connect(lambda: self._start(None))
        actions.addWidget(self.run_all)
        layout.addLayout(actions)
        timeout_row = QHBoxLayout()
        timeout_row.addWidget(QLabel("Time allowed per module"))
        self.time_budget = QComboBox(self)
        for seconds in (15, 30, 45):
            self.time_budget.addItem(f"{seconds} seconds", seconds)
        index = self.time_budget.findData(getattr(config, "selftest_timeout_seconds", 30))
        self.time_budget.setCurrentIndex(index if index >= 0 else 1)
        self.time_budget.setToolTip("Save to apply. Checks finish as soon as their results are ready.")
        timeout_row.addWidget(self.time_budget)
        timeout_row.addStretch(1)
        layout.addLayout(timeout_row)

        self.description = QLabel(self)
        self.description.setTextFormat(Qt.TextFormat.PlainText)
        self.description.setWordWrap(True)
        layout.addWidget(self.description)
        self.auto_recovery = QCheckBox("Automatically recover this module after a confirmed worker fault", self)
        self.auto_recovery.toggled.connect(self._set_recovery)
        layout.addWidget(self.auto_recovery)
        self.recovery_note = QLabel(self)
        self.recovery_note.setWordWrap(True)
        layout.addWidget(self.recovery_note)
        source_actions = QHBoxLayout()
        self.view_source = QPushButton("View test code", self)
        self.view_source.clicked.connect(self._show_source)
        self.edit_copy = QPushButton("Edit sandbox copy", self)
        self.edit_copy.clicked.connect(self._open_sandbox)
        self.open_upstream = QPushButton("Open repository source", self)
        self.open_upstream.clicked.connect(self._open_repository)
        for button in (self.run_selected, self.run_all, self.view_source, self.edit_copy, self.open_upstream):
            button.setAutoDefault(False)
        for button in (self.view_source, self.edit_copy, self.open_upstream):
            source_actions.addWidget(button)
        source_actions.addStretch(1)
        layout.addLayout(source_actions)

        self.source = QPlainTextEdit(self)
        self.source.setReadOnly(True)
        self.source.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.source.setPlaceholderText("Select View test code to inspect the bundled diagnostic method.")
        layout.addWidget(self.source, 1)
        self.status = QLabel(self)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.modules.currentIndexChanged.connect(self._select)
        self._select()

    def _selected(self):
        return self._modules.get(self.modules.currentText())

    def _select(self):
        module = self._selected()
        self._path, self._owner = _bundled_test(module)
        key = recovery_setting_key(module)
        self.auto_recovery.blockSignals(True)
        self.auto_recovery.setChecked(bool(key and key in self._recovery_modules))
        self.auto_recovery.blockSignals(False)
        self.auto_recovery.setEnabled(bool(key))
        self.recovery_note.setText(
            "Save to apply. Recovery can briefly interrupt this module while Self-Test verifies its replacement."
            if key else "Automatic worker recovery is unavailable for this module. Review its specific guidance.")
        self.source.clear()
        self.description.setText(
            f"{module.description}\n\n{module_guidance(module)}" if module is not None else
            "No registered modules are available in this Settings session.")
        self.status.setText("Edits are kept in the sandbox. Tests run the installed module.")
        self.run_selected.setEnabled(module is not None and callable(self._run_check))
        self.run_all.setEnabled(bool(self._modules) and callable(self._run_check))
        for button in (self.view_source, self.edit_copy, self.open_upstream):
            button.setEnabled(bool(self._path))

    def _set_recovery(self, checked: bool):
        key = recovery_setting_key(self._selected())
        if key and checked:
            self._recovery_modules.add(key)
        elif key:
            self._recovery_modules.discard(key)

    def auto_recovery_modules(self) -> list[str]:
        return sorted(self._recovery_modules)

    def _start(self, names):
        if callable(self._run_check) and self._run_check(names=names):
            self.status.setText("Self-Test started. Results will open when the checks finish.")
        else:
            self.status.setText("Self-Test is busy or unavailable. Wait for the active work to finish.")

    def _show_source(self):
        if not self._path:
            return
        source, reason = self._read_source(self._path)
        if source is None:
            self.status.setText(reason or "The installed copy has no readable test source. Use repository source.")
            return
        try:
            method = _method_source(source, self._owner)
        except (SyntaxError, ValueError) as exc:
            self.status.setText(f"The checkout test source could not be parsed. {type(exc).__name__}.")
            return
        self.source.setPlainText(method)
        self.status.setText(f"Checkout copy of {self._path}" if method else
                            "The expected diagnostic method was missing from the checkout copy.")

    def _open_repository(self):
        if self._path:
            QDesktopServices.openUrl(QUrl(f"https://github.com/Ag3nt47/AngeronaSuite/blob/main/{self._path}"))

    def _open_sandbox(self):
        if not self._path:
            return
        existing = self._sandbox_windows.get(self._path)
        if existing is not None:
            existing.showNormal()
            existing.raise_()
            existing.activateWindow()
            return
        from angerona.core.source_sandbox import SourceSandboxWorkspace
        from angerona.gui.context_info import SourceSandboxDialog

        try:
            workspace = SourceSandboxWorkspace(f"selftest-{self._path.rsplit('/', 1)[-1]}", (self._path,))
            if not workspace.available:
                self.status.setText("The sandbox needs bundled source files. Repository source is available separately.")
                return
            dialog = SourceSandboxDialog(workspace, self, preselect=self._path, find_text="def self_test(")
            self._sandbox_windows[self._path] = dialog
            dialog.destroyed.connect(lambda *_args, path=self._path: self._sandbox_windows.pop(path, None))
            dialog.show()
        except (OSError, RuntimeError, ValueError) as exc:
            self.status.setText(f"The source sandbox could not be opened. {str(exc)[:300]}")
