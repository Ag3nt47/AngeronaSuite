"""sandbox_editor.py — Live-Fire Sandbox & Editor (CODE: SBOX).

A standalone diagnostic + hot-swap code editor for Project Angerona's security
modules. It lets an operator isolate, inspect, test, and edit the raw ``.py`` of
any ``BaseModule`` and reload it live — behind hard safety guardrails.

Safety model
------------
1. Environmental isolation — on launch it asks the ``ModuleManager`` to stop every
   active daemon thread, overrides the Threat Level indicator to
   "⚠️ DIAGNOSTIC OVERRIDE: TESTING IN PROGRESS", and suppresses all outbound
   ``EventBus`` traffic so test noise can't trigger SOAR / cloud escalation.
2. AST gate — code is never written to disk unless ``ast.parse()`` succeeds.
3. Backups + history — every applied change is backed up (in-memory + temp file)
   and logged to a timestamped ledger so any edit can be reverted or audited.

Run standalone:  ``python -m angerona.gui.sandbox_editor``
Embed in the app: ``launch_sandbox_editor(manager, bus, threat_callback=...)``.
"""
from __future__ import annotations

import ast
import contextlib
import importlib
import inspect
import io
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
    """Runs a module's ``self_test()`` on a decoupled thread with stdout/stderr
    captured, so a test can't touch the GUI thread or the live EventBus."""

    done = Signal(bool, str)   # (passed, captured_output)

    def __init__(self, module: BaseModule, parent=None) -> None:
        super().__init__(parent)
        self._module = module

    def run(self) -> None:
        buf = io.StringIO()
        passed = False
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                result = self._module.self_test()
            if isinstance(result, tuple):
                passed = bool(result[0])
                detail = str(result[1]) if len(result) > 1 else ""
            else:
                passed = bool(result)
                detail = ""
            if detail:
                buf.write(f"\n[self_test detail] {detail}")
        except Exception:
            buf.write("\n" + traceback.format_exc())
            passed = False
        self.done.emit(passed, buf.getvalue().strip() or "(no output)")


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
        close.clicked.connect(self.accept)
        lay.addWidget(close)


# ── Main sandbox window ───────────────────────────────────────────────────────
class SandboxEditor(QMainWindow):
    """Live-Fire Sandbox & Editor window."""

    def __init__(
        self,
        manager,
        bus,
        threat_callback: Optional[Callable[[str], None]] = None,
        parent=None,
        preselect: Optional[str] = None,
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.bus = bus
        self._threat_cb = threat_callback

        self.setWindowTitle("Angerona — Live-Fire Sandbox & Editor")
        self.resize(1180, 720)

        self._backups: Dict[str, List[str]] = {}   # name -> stack of prior sources
        self._history: Dict[str, List[dict]] = {}   # name -> ledger entries
        self._current: Optional[str] = None
        self._test_worker: Optional[IsolatedTestWorker] = None
        self._orig_publish = None

        self._build_ui()
        self._enter_isolation()
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

        banner = QLabel("⚠️  DIAGNOSTIC OVERRIDE: TESTING IN PROGRESS — live sensors are paused")
        banner.setStyleSheet(
            "background:#7f1d1d; color:#fee2e2; font-weight:800; padding:8px 12px;"
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
            ("Run Isolated Test", self._run_test),
            ("🤖 Ask AI", self._ask_ai),
            ("🔎 Find", self._show_find),
            ("Apply Changes", self._apply_changes),
            ("Revert to Previous", self._revert),
            ("View History", self._view_history),
        ):
            b = QPushButton(label)
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        btn_row.addStretch()
        close_btn = QPushButton("Exit Sandbox (restore sensors)")
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

    # ── Isolation lifecycle ─────────────────────────────────────────────────
    def _enter_isolation(self) -> None:
        # 1) stop all live daemon threads
        try:
            self.manager.stop_all()
        except Exception as exc:
            self._log(f"[!] could not stop modules: {exc}")
        # 2) suppress outbound bus traffic
        if self.bus is not None and hasattr(self.bus, "publish"):
            self._orig_publish = self.bus.publish
            self.bus.publish = lambda *a, **k: None   # type: ignore[assignment]
        # 3) override threat indicator
        if self._threat_cb:
            try:
                self._threat_cb("⚠️ DIAGNOSTIC OVERRIDE: TESTING IN PROGRESS")
            except Exception:
                pass
        self._log("Sandbox armed — all sensors paused, EventBus muted.")

    def _exit_isolation(self) -> None:
        if self._orig_publish is not None and self.bus is not None:
            self.bus.publish = self._orig_publish   # type: ignore[assignment]
            self._orig_publish = None
        if self._threat_cb:
            try:
                self._threat_cb("")   # clear override
            except Exception:
                pass

    def closeEvent(self, event) -> None:  # noqa: N802
        if QMessageBox.question(
            self, "Exit Sandbox",
            "Restore live sensors and leave the sandbox?\n\n"
            "Modules you edited will be (re)started with the applied code.",
        ) != QMessageBox.Yes:
            event.ignore()
            return
        self._exit_isolation()
        # Best-effort: bring previously-enabled modules back online.
        try:
            self.manager.start_enabled()
        except Exception as exc:
            self._log(f"[!] restart failed: {exc}")
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
        src = _module_source_file(mod)
        if not src or not src.exists():
            self._log(f"[!] could not resolve source file for {name}.")
            return
        try:
            self.editor.setPlainText(src.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log(f"[!] read failed: {exc}")
            return
        self._current = name
        self.path_lbl.setText(str(src))
        self._log(f"Opened {name}: {src}")

    def _run_test(self) -> None:
        name = self._selected_name() or self._current
        if not name:
            self._log("[!] select a module first.")
            return
        mod = self.manager.modules.get(name)
        if mod is None:
            self._log(f"[!] {name} not found.")
            return
        self._log(f"── Running isolated self_test() for {name} …")
        self._test_worker = IsolatedTestWorker(mod, self)
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
        if QMessageBox.warning(
            self, "Apply live code change",
            "CRITICAL: Modifying live sensor logic can impair system security or "
            "cause fatal deadlocks. Verify syntax before proceeding.\n\n"
            f"Write changes to {self._current} and hot-reload it now?",
            QMessageBox.Ok | QMessageBox.Cancel, QMessageBox.Cancel,
        ) != QMessageBox.Ok:
            return

        new_src = self.editor.toPlainText()
        # AST gate — never write code that won't parse.
        try:
            ast.parse(new_src)
        except SyntaxError as exc:
            self._log(f"[BLOCKED] Syntax error line {exc.lineno}: {exc.msg} — not saved.")
            self._highlight_error(exc.lineno)
            return

        mod = self.manager.modules.get(self._current)
        src = _module_source_file(mod)
        if not src:
            self._log("[!] cannot resolve target file — aborting.")
            return

        # Back up the current on-disk source for revert.
        try:
            prior = src.read_text(encoding="utf-8")
        except Exception:
            prior = ""
        self._backups.setdefault(self._current, []).append(prior)
        _write_temp_backup(self._current, prior)

        try:
            src.write_text(new_src, encoding="utf-8")
        except Exception as exc:
            self._log(f"[!] write failed: {exc}")
            return
        self._record_history(self._current, "apply", len(new_src.encode()),
                             f"wrote {src}")
        self._log(f"Saved {src}. Hot-reloading module…")
        self._reload_module(self._current)

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
        src = _module_source_file(mod)
        try:
            src.write_text(prior, encoding="utf-8")
            self.editor.setPlainText(prior)
        except Exception as exc:
            self._log(f"[!] revert write failed: {exc}")
            return
        self._record_history(self._current, "revert", len(prior.encode()),
                             "restored previous version")
        self._log(f"Reverted {self._current} to previous version. Reloading…")
        self._reload_module(self._current)

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
            "(Project Angerona) in a live-fire sandbox. Review the code and answer my "
            "questions / propose fixes. Keep changes minimal and preserve the BaseModule "
            "contract.\n\n--- current file ---\n" + code[:12000])
        AIConsultDialog(f"Sandbox Ask AI — {name}", prompt,
                        default_filename=f"{name}_ai_notes.md", parent=self).show()

    # ── Reload ────────────────────────────────────────────────────────────────
    def _reload_module(self, name: str) -> None:
        mod = self.manager.modules.get(name)
        if mod is None:
            self._log(f"[!] {name} vanished from manager.")
            return
        try:
            mod.stop()
        except Exception:
            pass
        pymod_name = type(mod).__module__
        pymod = sys.modules.get(pymod_name)
        try:
            if pymod is not None:
                importlib.reload(pymod)
        except Exception as exc:
            self._log(f"[!] reload FAILED: {exc}\n{traceback.format_exc()}")
            self._emit_module_alert(name, f"hot-reload failed: {exc}")
            return

        # Rebind a fresh instance of the same-named BaseModule subclass.
        new_cls = None
        for _, obj in inspect.getmembers(pymod, inspect.isclass):
            if (issubclass(obj, BaseModule) and obj is not BaseModule
                    and obj.__module__ == pymod.__name__
                    and getattr(obj, "name", None) == name):
                new_cls = obj
                break
        if new_cls is None:
            self._log(f"[!] reloaded module but couldn't find class named '{name}'. "
                      "Left stopped.")
            self._emit_module_alert(name, "reloaded but class not found; module stopped")
            return
        try:
            inst = new_cls()
            inst.bind(self.bus)
            if hasattr(inst, "bind_manager"):
                inst.bind_manager(self.manager)
            self.manager.modules[name] = inst
            inst.start()
            self._log(f"✓ {name} hot-reloaded and restarted.")
        except Exception as exc:
            self._log(f"[!] restart FAILED: {exc}\n{traceback.format_exc()}")
            self._emit_module_alert(name, f"restart failed after edit: {exc}")
        self._populate_modules()

    def _emit_module_alert(self, name: str, detail: str) -> None:
        """Surface a reload/restart failure onto the live alert feed (via the real
        publish, temporarily) so it lands in the user's module alert history."""
        if self._orig_publish is None or self.bus is None:
            return
        try:
            from angerona.core.eventbus import Event, Severity
            self._orig_publish(Event(name, f"SANDBOX: {detail}", Severity.HIGH,
                                     time.time(), {"sandbox": True}))
        except Exception:
            pass

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


def _write_temp_backup(name: str, source: str) -> None:
    try:
        import tempfile
        d = Path(tempfile.gettempdir()) / "angerona_sandbox_backups"
        d.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() else "_" for c in name)
        (d / f"{safe}_{int(time.time())}.py.bak").write_text(source, encoding="utf-8")
    except Exception:
        pass


def launch_sandbox_editor(manager, bus, threat_callback=None, parent=None,
                          preselect=None) -> SandboxEditor:
    """Embed entry point: build + show the sandbox over an existing app.
    `preselect` = a module name to auto-open its file immediately."""
    win = SandboxEditor(manager, bus, threat_callback=threat_callback, parent=parent,
                        preselect=preselect)
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
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(_standalone())
