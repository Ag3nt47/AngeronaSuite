"""sandbox_editor.py — Isolated Source Sandbox (CODE: SBOX).

A standalone diagnostic editor for working copies of Angerona security modules.
Installed product source is immutable from this surface. Candidate source is
saved only below Angerona's bounded data sandbox and is never loaded into the
elevated production interpreter.

Safety model
------------
1. Process isolation — opening the editor does not pause production sensors or
   replace the process-global ``EventBus`` publisher. A self-test runs in a
   disposable Python process with a sanitized environment, temporary data root,
   and a hard deadline.
2. AST gate — candidate code is not saved unless ``ast.parse()`` succeeds.
3. Working-copy history — each saved candidate can be reverted in the sandbox.
4. Review boundary — promotion into installed source is intentionally absent.

Run standalone:  ``python -m angerona.gui.sandbox_editor``
Embed in the app: ``launch_sandbox_editor(manager, bus, threat_callback=...)``.
"""
from __future__ import annotations

import ast
import inspect
import sys
import time
import traceback
from pathlib import Path
from typing import Callable, Dict, List, Optional

from PySide6.QtCore import Qt, QRegularExpression, QThread, Signal
from PySide6.QtGui import (
    QColor, QFont, QKeySequence, QShortcut, QSyntaxHighlighter, QTextCharFormat,
    QTextCursor)
from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QSplitter, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.module_base import BaseModule
from angerona.core.sandbox_runner import run_isolated_self_test
from angerona.core.source_sandbox import SourceSandboxWorkspace


# ── Syntax highlighting ───────────────────────────────────────────────────────
class PythonHighlighter(QSyntaxHighlighter):
    """Minimal but professional Python highlighter (keywords, strings, comments,
    decorators, numbers, def/class names)."""

    _KEYWORDS = (
        "False None True and as assert async await break class continue def del "
        "elif else except finally for from global if import in is lambda nonlocal "
        "not or pass raise return try while with yield"
    ).split()

    def __init__(self, document) -> None:
        super().__init__(document)
        self._rules: List[tuple[QRegularExpression, QTextCharFormat]] = []

        def fmt(hex_color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(hex_color))
            if bold:
                f.setFontWeight(QFont.Bold)
            f.setFontItalic(italic)
            return f

        kw_fmt = fmt("#38bdf8", bold=True)
        for kw in self._KEYWORDS:
            self._rules.append((QRegularExpression(rf"\b{kw}\b"), kw_fmt))

        self._rules.append((QRegularExpression(r"\bdef\s+(\w+)"), fmt("#c084fc", bold=True)))
        self._rules.append((QRegularExpression(r"\bclass\s+(\w+)"), fmt("#f59e0b", bold=True)))
        self._rules.append((QRegularExpression(r"@\w+"), fmt("#f472b6")))            # decorators
        self._rules.append((QRegularExpression(r"\b[0-9]+\.?[0-9]*\b"), fmt("#fbbf24")))  # numbers
        # strings (single/double, incl. simple f/r prefixes)
        self._rules.append((QRegularExpression(r"[rbfRBF]?'[^'\\]*(\\.[^'\\]*)*'"), fmt("#34d399")))
        self._rules.append((QRegularExpression(r'[rbfRBF]?"[^"\\]*(\\.[^"\\]*)*"'), fmt("#34d399")))
        self._comment_fmt = fmt("#64748b", italic=True)

    def highlightBlock(self, text: str) -> None:  # noqa: N802 (Qt signature)
        for rx, f in self._rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                # If the rule captured a group (def/class name) prefer it.
                if m.lastCapturedIndex() >= 1:
                    self.setFormat(m.capturedStart(1), m.capturedLength(1), f)
                else:
                    self.setFormat(m.capturedStart(), m.capturedLength(), f)
        # Comments last so they win over everything on the line.
        hs = text.find("#")
        if hs >= 0:
            self.setFormat(hs, len(text) - hs, self._comment_fmt)


# ── Isolated self_test runner ─────────────────────────────────────────────────
class IsolatedTestWorker(QThread):
    """Validate a candidate and test the installed baseline out of process.

    Candidate source is parsed as data and is deliberately not imported or
    executed. The baseline ``self_test`` remains useful proof that the installed
    module is healthy while an operator drafts a separately reviewed change.
    """

    done = Signal(bool, str)   # (passed, captured_output)

    def __init__(
        self,
        module: BaseModule,
        workspace: SourceSandboxWorkspace,
        relative_path: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._module_name = type(module).__module__
        self._class_name = type(module).__name__
        self._expected_name = str(getattr(module, "name", ""))
        self._workspace = workspace
        self._relative_path = relative_path

    def run(self) -> None:
        try:
            candidate = self._workspace.reload(self._relative_path)
            ast.parse(candidate, filename=self._relative_path)
            passed, output = run_isolated_self_test(
                self._module_name, self._class_name, self._expected_name,
            )
            output = (
                "Sandbox candidate passed syntax validation and was not executed.\n"
                "Installed baseline self_test result:\n" + output
            )
        except Exception:
            passed = False
            output = traceback.format_exc()
        self.done.emit(passed, output)


# ── History ledger ────────────────────────────────────────────────────────────
class HistoryDialog(QDialog):
    def __init__(self, module_name: str, entries: List[dict], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Edit history — {module_name}")
        self.setMinimumSize(560, 360)
        lay = QVBoxLayout(self)
        view = QTextEdit()
        view.setReadOnly(True)
        if entries:
            lines = []
            for e in reversed(entries):
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("ts", 0)))
                lines.append(f"[{ts}]  {e.get('action', '?')}  ({e.get('bytes', 0)} bytes)"
                             f"\n    {e.get('note', '')}")
            view.setPlainText("\n\n".join(lines))
        else:
            view.setPlainText("No edits recorded for this module yet.")
        lay.addWidget(view)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        lay.addWidget(close)


# ── Main sandbox window ───────────────────────────────────────────────────────
class SandboxEditor(QMainWindow):
    """Editor for isolated, non-executable source working copies."""

    def __init__(
        self,
        manager,
        bus,
        threat_callback: Optional[Callable[[str], None]] = None,
        parent=None,
        preselect: Optional[str] = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.manager = manager
        self.bus = bus
        self._threat_cb = threat_callback

        self.setWindowTitle("Angerona — Isolated Source Sandbox")
        self.resize(1180, 720)

        self._backups: Dict[str, List[str]] = {}   # name -> stack of prior sources
        self._history: Dict[str, List[dict]] = {}   # name -> ledger entries
        self._workspaces: Dict[str, SourceSandboxWorkspace] = {}
        self._workspace_paths: Dict[str, str] = {}
        self._current: Optional[str] = None
        self._test_worker: Optional[IsolatedTestWorker] = None
        self._close_confirmed = False

        self._build_ui()
        self._populate_modules()
        # Auto-open the requested module's file (used by a module window's
        # "Edit code (Sandbox)" button so you land straight on its code).
        if preselect:
            self._select_and_open(preselect)

    def _select_and_open(self, name: str) -> None:
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            if it.data(0, Qt.UserRole) == name:
                self.tree.setCurrentItem(it)
                self._open_selected()
                return

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)

        banner = QLabel(
            "🧪  ISOLATED WORKING COPY — installed code is read-only and candidates "
            "are never loaded live"
        )
        banner.setStyleSheet(
            "background:#0c4a6e; color:#e0f2fe; font-weight:800; padding:8px 12px;"
            "border-radius:6px;")
        root.addWidget(banner)

        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        # Left — module tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Module", "Status"])
        self.tree.setColumnWidth(0, 220)
        self.tree.itemDoubleClicked.connect(lambda *_: self._open_selected())
        split.addWidget(self.tree)

        # Center — editor
        center = QWidget()
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        self.path_lbl = QLabel("(no module open)")
        self.path_lbl.setStyleSheet("color:#94a3b8; font-size:11px;")
        cl.addWidget(self.path_lbl)
        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Consolas", 11))
        self.editor.setTabStopDistance(4 * self.editor.fontMetrics().horizontalAdvance(" "))
        self._highlighter = PythonHighlighter(self.editor.document())
        cl.addWidget(self.editor, 1)

        # Find bar (Ctrl+F). QPlainTextEdit already handles Ctrl+C/V/X/Z/Y/A natively.
        self._find_bar = QWidget()
        fbl = QHBoxLayout(self._find_bar)
        fbl.setContentsMargins(0, 0, 0, 0)
        self._find_input = QLineEdit()
        self._find_input.setPlaceholderText("Find… (Enter = next, Esc = close)")
        self._find_input.returnPressed.connect(lambda: self._find_next(True))
        fnext = QPushButton("Next"); fprev = QPushButton("Prev")
        fnext.clicked.connect(lambda: self._find_next(True))
        fprev.clicked.connect(lambda: self._find_next(False))
        fbl.addWidget(self._find_input, 1); fbl.addWidget(fprev); fbl.addWidget(fnext)
        self._find_bar.setVisible(False)
        cl.addWidget(self._find_bar)
        split.addWidget(center)

        # Ctrl+F opens find; Esc closes it.
        QShortcut(QKeySequence.Find, self.editor).activated.connect(self._show_find)
        QShortcut(QKeySequence("Esc"), self._find_input).activated.connect(
            lambda: self._find_bar.setVisible(False))

        # Right — console + history
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(QLabel("Test console / results"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        rl.addWidget(self.console, 1)
        split.addWidget(right)

        split.setSizes([240, 620, 320])

        # Buttons
        btn_row = QHBoxLayout()
        for label, slot in (
            ("Open Module", self._open_selected),
            ("Validate Sandbox Copy", self._run_test),
            ("🤖 Ask AI", self._ask_ai),
            ("🔎 Find", self._show_find),
            ("Save Sandbox Copy", self._apply_changes),
            ("Revert Sandbox Copy", self._revert),
            ("View History", self._view_history),
        ):
            b = QPushButton(label)
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        btn_row.addStretch()
        close_btn = QPushButton("Exit Sandbox")
        close_btn.setStyleSheet("background:#166534; color:#dcfce7; font-weight:700;")
        close_btn.clicked.connect(self.close)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

        self.setStyleSheet(self._qss())

    @staticmethod
    def _qss() -> str:
        return (
            "QMainWindow, QWidget { background:#0b1220; color:#e2e8f0; }"
            "QTreeWidget, QPlainTextEdit, QTextEdit { background:#0f172a; color:#e2e8f0;"
            "  border:1px solid #1e293b; border-radius:6px; }"
            "QPushButton { background:#1e293b; color:#e2e8f0; border:1px solid #334155;"
            "  border-radius:6px; padding:6px 12px; }"
            "QPushButton:hover { background:#334155; }"
            "QHeaderView::section { background:#111827; color:#93c5fd; border:none; padding:4px; }"
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        if not self._close_confirmed:
            if QMessageBox.question(
                self, "Exit Sandbox",
                "Leave the sandbox?\n\nProduction sensors stay active. A running isolated "
                "self-test will be allowed to reach its hard deadline before cleanup.",
            ) != QMessageBox.Yes:
                event.ignore()
                return
            self._close_confirmed = True

        # A self-test may be blocked in native/module code and cannot be killed
        # safely. Keep this window alive (but hidden) until it returns; deleting
        # its QThread used to abort all of Angerona in Qt6Core.dll.
        from angerona.gui.thread_lifecycle import defer_close_until_threads

        if defer_close_until_threads(self, event, (self._test_worker,)):
            return
        event.accept()

    # ── Module list ───────────────────────────────────────────────────────────
    def _populate_modules(self) -> None:
        self.tree.clear()
        for name, mod in sorted(self.manager.modules.items()):
            item = QTreeWidgetItem([name, getattr(mod, "status", "stopped")])
            item.setData(0, Qt.UserRole, name)
            self.tree.addTopLevelItem(item)

    def _selected_name(self) -> Optional[str]:
        it = self.tree.currentItem()
        return it.data(0, Qt.UserRole) if it else None

    # ── Actions ───────────────────────────────────────────────────────────────
    def _open_selected(self) -> None:
        name = self._selected_name()
        if not name:
            self._log("[!] select a module first.")
            return
        mod = self.manager.modules.get(name)
        try:
            workspace, relative = self._workspace_for_module(name, mod)
            self.editor.setPlainText(workspace.reload(relative))
        except Exception as exc:
            self._log(f"[!] sandbox open failed: {exc}")
            return
        self._current = name
        item = workspace.file(relative)
        self.path_lbl.setText(
            f"Sandbox: {item.working_path}  ·  Read-only source: {item.source_path}"
        )
        self._log(f"Opened isolated working copy for {name}: {item.working_path}")

    def _run_test(self) -> None:
        name = self._selected_name() or self._current
        if not name:
            self._log("[!] select a module first.")
            return
        mod = self.manager.modules.get(name)
        if mod is None:
            self._log(f"[!] {name} not found.")
            return
        if self._test_worker is not None and self._test_worker.isRunning():
            self._log("[!] an isolated self-test is already running.")
            return
        try:
            workspace, relative = self._workspace_for_module(name, mod)
            workspace.save(relative, self.editor.toPlainText())
        except SyntaxError as exc:
            self._log(f"[BLOCKED] Syntax error line {exc.lineno}: {exc.msg} — not saved.")
            self._highlight_error(exc.lineno)
            return
        except Exception as exc:
            self._log(f"[!] sandbox validation failed: {exc}")
            return
        self._log(
            f"── Validating sandbox syntax and running installed baseline "
            f"self_test() for {name} …"
        )
        self._test_worker = IsolatedTestWorker(mod, workspace, relative, self)
        self._test_worker.done.connect(self._on_test_done)
        self._test_worker.finished.connect(self._test_worker.deleteLater)
        self._test_worker.start()

    def _on_test_done(self, passed: bool, output: str) -> None:
        tag = "PASS ✓" if passed else "FAIL ✗"
        self._log(f"[{tag}]\n{output}\n")

    def _apply_changes(self) -> None:
        if not self._current:
            self._log("[!] open a module before applying changes.")
            return
        new_src = self.editor.toPlainText()
        try:
            mod = self.manager.modules.get(self._current)
            workspace, relative = self._workspace_for_module(self._current, mod)
            prior = workspace.reload(relative)
            workspace.save(relative, new_src)
        except SyntaxError as exc:
            self._log(f"[BLOCKED] Syntax error line {exc.lineno}: {exc.msg} — not saved.")
            self._highlight_error(exc.lineno)
            return
        except Exception as exc:
            self._log(f"[!] sandbox save failed: {exc}")
            return
        self._backups.setdefault(self._current, []).append(prior)
        self._record_history(self._current, "apply", len(new_src.encode()),
                             f"saved isolated copy {workspace.file(relative).working_path}")
        self._log(
            "Saved sandbox copy. Installed source and running module were not changed."
        )
        self._reload_sandbox(self._current)

    def _revert(self) -> None:
        if not self._current:
            self._log("[!] open a module first.")
            return
        stack = self._backups.get(self._current)
        if not stack:
            self._log("[!] no previous version to revert to for this session.")
            return
        prior = stack.pop()
        mod = self.manager.modules.get(self._current)
        try:
            workspace, relative = self._workspace_for_module(self._current, mod)
            workspace.save(relative, prior)
            self.editor.setPlainText(prior)
        except Exception as exc:
            self._log(f"[!] sandbox revert failed: {exc}")
            return
        self._record_history(self._current, "revert", len(prior.encode()),
                             "restored previous sandbox version")
        self._log(
            f"Reverted {self._current}'s sandbox copy. Installed source is unchanged."
        )
        self._reload_sandbox(self._current)

    def _view_history(self) -> None:
        name = self._current or self._selected_name()
        if not name:
            self._log("[!] select a module first.")
            return
        HistoryDialog(name, self._history.get(name, []), self).exec()

    # ── Find (Ctrl+F) ─────────────────────────────────────────────────────────
    def _show_find(self) -> None:
        self._find_bar.setVisible(True)
        cur = self.editor.textCursor()
        if cur.hasSelection():
            self._find_input.setText(cur.selectedText())
        self._find_input.setFocus()
        self._find_input.selectAll()

    def _find_next(self, forward: bool = True) -> None:
        from PySide6.QtGui import QTextDocument
        term = self._find_input.text()
        if not term:
            return
        flags = QTextDocument.FindFlags()
        if not forward:
            flags |= QTextDocument.FindBackward
        if not self.editor.find(term, flags):
            # wrap around
            cur = self.editor.textCursor()
            operation = (QTextCursor.MoveOperation.Start if forward else
                         QTextCursor.MoveOperation.End)
            cur.movePosition(operation)
            self.editor.setTextCursor(cur)
            self.editor.find(term, flags)

    # ── Ask AI ────────────────────────────────────────────────────────────────
    def _ask_ai(self) -> None:
        """Open a chat with online AIs (order per Settings: Claude → … → Ollama),
        seeded with the current module's code + question."""
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._log(f"[!] Ask AI unavailable: {exc}")
            return
        name = self._current or "(no module open)"
        code = self.editor.toPlainText()
        prompt = (
            f"I'm editing the '{name}' module of a Python/PySide6 EDR security suite "
            "(Project Angerona) in an isolated working-copy sandbox. Review the code and "
            "answer my "
            "questions / propose fixes. Keep changes minimal and preserve the BaseModule "
            "contract.\n\n--- current file ---\n" + code[:12000])
        AIConsultDialog(f"Sandbox Ask AI — {name}", prompt,
                        default_filename=f"{name}_ai_notes.md", parent=self).show()

    # ── Working-copy operations ───────────────────────────────────────────────
    def _workspace_for_module(
        self, name: str, mod: BaseModule | None
    ) -> tuple[SourceSandboxWorkspace, str]:
        cached = self._workspaces.get(name)
        if cached is not None:
            return cached, self._workspace_paths[name]
        if mod is None:
            raise ValueError(f"module is unavailable: {name}")
        source_root, relative = _module_source_layout(mod)
        workspace = SourceSandboxWorkspace(
            f"module-{type(mod).__module__}-{name}",
            (relative,),
            source_root=source_root,
        )
        if not workspace.available:
            raise ValueError(f"could not resolve an immutable source file for {name}")
        workspace.ensure()
        self._workspaces[name] = workspace
        self._workspace_paths[name] = relative
        return workspace, relative

    def _reload_sandbox(self, name: str) -> None:
        """Reload editor text from the working copy; never reload Python code."""
        mod = self.manager.modules.get(name)
        try:
            workspace, relative = self._workspace_for_module(name, mod)
            self.editor.setPlainText(workspace.reload(relative))
        except Exception as exc:
            self._log(f"[!] sandbox reload failed: {exc}")
            return
        self._log("Reloaded sandbox copy only; production interpreter is unchanged.")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _record_history(self, name: str, action: str, nbytes: int, note: str) -> None:
        self._history.setdefault(name, []).append(
            {"ts": time.time(), "action": action, "bytes": nbytes, "note": note})

    def _highlight_error(self, lineno: Optional[int]) -> None:
        if not lineno:
            return
        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        for _ in range(max(0, lineno - 1)):
            cursor.movePosition(QTextCursor.MoveOperation.Down)
        self.editor.setTextCursor(cursor)

    def _log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.console.append(f"<span style='color:#64748b'>[{ts}]</span> {msg}")


# ── Module-level helpers ──────────────────────────────────────────────────────
def _module_source_file(mod) -> Optional[Path]:
    if mod is None:
        return None
    pymod = sys.modules.get(type(mod).__module__)
    f = getattr(pymod, "__file__", None)
    if f:
        return Path(f)
    try:
        return Path(inspect.getsourcefile(type(mod)))  # type: ignore[arg-type]
    except Exception:
        return None


def _module_source_layout(mod: BaseModule) -> tuple[Path, str]:
    """Return an import-root and relative module path without resolving links."""
    source = _module_source_file(mod)
    if source is None:
        raise ValueError("module source file is unavailable")
    source = Path(source).absolute()
    if source.suffix.casefold() == ".pyc":
        source = source.with_suffix(".py")
    module_parts = type(mod).__module__.split(".")
    expected = Path(*module_parts).with_suffix(".py")
    expected_parts = tuple(part.casefold() for part in expected.parts)
    source_parts = tuple(part.casefold() for part in source.parts)
    if len(source_parts) >= len(expected_parts) and source_parts[-len(expected_parts):] == expected_parts:
        root = source.parents[len(expected.parts) - 1]
        return root, expected.as_posix()
    return source.parent, source.name


def launch_sandbox_editor(manager, bus, threat_callback=None, parent=None,
                          preselect=None, *, reveal: bool = True) -> SandboxEditor:
    """Embed entry point: build + show the sandbox over an existing app.
    `preselect` = a module name to auto-open its file immediately."""
    win = SandboxEditor(manager, bus, threat_callback=threat_callback, parent=parent,
                        preselect=preselect)
    if not reveal:
        win.setProperty("_angerona_no_reveal", True)
    win.show()
    return win


def _standalone() -> int:
    """Run the sandbox on the real module set, no main window."""
    from angerona.core.config import Config
    from angerona.core.eventbus import EventBus
    from angerona.core.module_manager import ModuleManager

    app = QApplication.instance() or QApplication(sys.argv)
    bus = EventBus()
    manager = ModuleManager(bus, Config.load())
    manager.discover()
    win = SandboxEditor(manager, bus)
    from angerona.gui.header_controls import show_with_window_reveal
    show_with_window_reveal(win, config=manager.config, color="#22c55e")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(_standalone())
