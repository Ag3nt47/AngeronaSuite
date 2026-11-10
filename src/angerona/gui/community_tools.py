"""Suggested tools with worker-owned actions and inert editable source copies."""
from __future__ import annotations

import html
import json
import queue
import threading
import time
from urllib.parse import urlsplit

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QComboBox, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPlainTextEdit,
    QPushButton, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from angerona.core.community_tool_adapters import AdapterOperation
from angerona.gui.action_progress import ActionActivities, ActionProgressView
from angerona.gui.dashboard_sections import DashboardDisclosure
from angerona.gui.theme import set_function_role

_WORKERS = threading.BoundedSemaphore(2)
_BADGES = {"zero-breach": ("ZB", "#b83245"), "atomic-red-team": ("AR", "#ad4428"),
           "sigma": ("Σ", "#5e55bb"), "sysmon-modular": ("SY", "#276f94"),
           "yara-x": ("YX", "#26866b"), "caldera": ("CA", "#6e5494"),
           "velociraptor": ("VR", "#617b30"), "wazuh": ("W", "#317da8")}


def _status_summary(status):
    """Keep nested scanner holds visible even with its exact JSON collapsed."""
    scanner = status.get("scanner")
    scanner = scanner if isinstance(scanner, dict) else {}
    messages = []
    for value in (status.get("message"), scanner.get("message"),
                  scanner.get("execution_hold_reason"), scanner.get("storage_inventory_error")):
        if isinstance(value, str) and value.strip():
            message = value.strip()
            if not any(message in previous for previous in messages):
                messages.append(message if len(message) <= 512 else message[:512] + "… (full text in Technical record)")
    return "\n".join(messages) or "Refresh to inspect the installed state."


def tool_icon(tool_id):
    """Deterministic local badges; no logo fetches or unlicensed branding assets."""
    letters, color = _BADGES.get(tool_id, ("GH", "#34465b"))
    canvas = QPixmap(36, 36)
    canvas.fill(Qt.GlobalColor.transparent)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(color))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(0, 0, 36, 36, 8, 8)
    painter.setPen(QColor("white"))
    painter.drawText(canvas.rect(), Qt.AlignmentFlag.AlignCenter, letters)
    painter.end()
    return QIcon(canvas)


class CommunityToolsPanel(QWidget):
    """No filesystem/parser/native work runs on Qt; each tool has its own slot."""
    def __init__(self, service, parent=None, *, open_source_review=None):
        super().__init__(parent)
        self.service = service
        self._open_source_review = open_source_review
        self._specs = {row["id"]: row for row in service.tool_specs()}
        self._statuses = {}
        self._sources = []
        self._operations = {}
        self._threads = []
        self._queue = queue.Queue(maxsize=64)
        self._lifetime = {"closed": False, "operations": self._operations}
        self._selected = None
        self._sandbox = None
        self._path = None
        self._loaded = False
        self._activities = ActionActivities(self)
        layout = QVBoxLayout(self)
        layout.addWidget(ActionProgressView(self._activities, self))
        title = QLabel("Suggested GitHub tools")
        title.setObjectName("sectionTitle")
        set_function_role(title, "analysis")
        layout.addWidget(title)
        note = QLabel("Reviewed adapters · separate editable copies · imported scripts never run automatically.")
        note.setWordWrap(True)
        layout.addWidget(note)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tools = QListWidget()
        self.tools.setMinimumWidth(140)
        self.tools.setAccessibleName("Suggested community adapters")
        for key, spec in self._specs.items():
            item = QListWidgetItem(tool_icon(key), spec["name"])
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setToolTip("https://github.com/" + spec["repository"])
            self.tools.addItem(item)
        splitter.addWidget(self.tools)
        self.tabs = QTabWidget()
        overview = QWidget()
        overview_layout = QVBoxLayout(overview)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        overview_layout.addWidget(self.summary)
        self.sources = QComboBox()
        self.sources.setAccessibleName("Reviewed pinned source import")
        overview_layout.addWidget(self.sources)
        buttons = QGridLayout()
        self.install_button = QPushButton("Install selected")
        self.uninstall_button = QPushButton("Uninstall")
        self.check_button = QPushButton("Run self-check")
        self.refresh_button = QPushButton("Refresh")
        self.sandbox_button = QPushButton("Create editable copy")
        for column, button in enumerate((self.install_button, self.check_button, self.uninstall_button)):
            buttons.addWidget(button, 0, column)
        overview_layout.addLayout(buttons)
        source_content = QWidget()
        links = QGridLayout(source_content)
        links.setContentsMargins(0, 0, 0, 0)
        self.source_info = QLabel()
        self.source_info.setWordWrap(True)
        self.source_info.setTextFormat(Qt.TextFormat.PlainText)
        links.addWidget(self.source_info, 0, 0, 1, 2)
        self.upstream_button = QPushButton("Open upstream")
        self.credits_button = QPushButton("Credits / licenses")
        self.review_source_button = QPushButton("Source Library")
        self.review_source_button.setEnabled(callable(open_source_review))
        for index, button in enumerate((self.sandbox_button, self.review_source_button,
                                        self.upstream_button, self.credits_button, self.refresh_button)):
            links.addWidget(button, 1 + index // 2, index % 2)
        self.source_details = DashboardDisclosure(
            "Sources & editable copies", source_content, "Capabilities, credits and copy tools")
        overview_layout.addWidget(self.source_details)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setAccessibleName("Adapter status and exact action outcome")
        self.detail.document().setMaximumBlockCount(4000)
        self.technical_details = DashboardDisclosure(
            "Technical record", self.detail, "Exact installed state and action output")
        overview_layout.addWidget(self.technical_details, 1)
        # A folded record has a capped height. Absorb spare height below the
        # controls rather than stretching the summary and centering its text.
        rest_index = overview_layout.count()
        overview_layout.addStretch(1)
        self.technical_details.expanded_changed.connect(
            lambda expanded: overview_layout.setStretch(rest_index, 0 if expanded else 1))
        self.tabs.addTab(overview, "Overview / actions")
        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        self.copy_notice = QLabel("Working copies stay separate. Save, diff, revert and analysis cannot activate an edited tool.")
        self.copy_notice.setWordWrap(True)
        editor_layout.addWidget(self.copy_notice)
        self.sandboxes = QComboBox()
        self.sandboxes.setAccessibleName("Editable sandbox copy")
        editor_layout.addWidget(self.sandboxes)
        files_split = QSplitter(Qt.Orientation.Horizontal)
        self.files = QListWidget()
        self.files.setAccessibleName("Sandbox files")
        self.editor = QPlainTextEdit()
        self.editor.setAccessibleName("Editable community source working copy")
        self.editor.setReadOnly(True)
        files_split.addWidget(self.files)
        files_split.addWidget(self.editor)
        files_split.setStretchFactor(1, 3)
        editor_layout.addWidget(files_split, 1)
        edit_actions = QHBoxLayout()
        self.save_button = QPushButton("Save copy")
        self.diff_button = QPushButton("Show diff")
        self.revert_button = QPushButton("Revert selected copy")
        self.analyze_button = QPushButton("Validate / analyze data")
        for button in (self.save_button, self.diff_button, self.revert_button, self.analyze_button):
            edit_actions.addWidget(button)
        editor_layout.addLayout(edit_actions)
        self.tabs.addTab(editor, "Editable sandbox")
        self.credits = QTextBrowser()
        self.credits.setOpenExternalLinks(True)
        self.tabs.addTab(self.credits, "Credits / licenses")
        from angerona.gui.analysis_lab import AnalysisLabPanel
        self.analysis_lab = AnalysisLabPanel(root=service.root.parent / "analysis-lab")
        self.tabs.addTab(self.analysis_lab, "VM analysis")
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 4)
        layout.addWidget(splitter, 1)
        self.status = QLabel("Select a tool. Status and source-library reads run in background workers.")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self.cancel_button = QPushButton("Cancel this tool's action")
        layout.addWidget(self.cancel_button)
        for button in (self.check_button, self.refresh_button, self.upstream_button):
            set_function_role(button, "monitor")
        for button in (self.sandbox_button, self.analyze_button, self.diff_button,
                       self.review_source_button, self.credits_button):
            set_function_role(button, "analysis")
        for button in (self.install_button, self.uninstall_button, self.save_button, self.revert_button):
            set_function_role(button, "configure")
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll)
        self._timer.start()
        self.tools.currentItemChanged.connect(self._select)
        self.sandboxes.currentIndexChanged.connect(self._select_sandbox)
        self.files.currentItemChanged.connect(self._select_file)
        self.install_button.clicked.connect(self._install)
        self.uninstall_button.clicked.connect(lambda: self._action("uninstall"))
        self.check_button.clicked.connect(lambda: self._action("self_check"))
        self.refresh_button.clicked.connect(self.refresh)
        self.sandbox_button.clicked.connect(lambda: self._action("create_sandbox"))
        self.credits_button.clicked.connect(self._show_credits)
        self.upstream_button.clicked.connect(self._open_upstream)
        self.review_source_button.clicked.connect(lambda: self._open_source_review() if callable(self._open_source_review) else None)
        self.cancel_button.clicked.connect(self.cancel_selected)
        self.save_button.clicked.connect(self._save)
        self.diff_button.clicked.connect(lambda: self._sandbox_action("sandbox_diff"))
        self.revert_button.clicked.connect(lambda: self._sandbox_action("sandbox_revert"))
        self.analyze_button.clicked.connect(lambda: self._sandbox_action("sandbox_analysis"))
        lifetime = self._lifetime
        activities = self._activities
        def destroyed(*_args):
            lifetime["closed"] = True
            for entry in tuple(lifetime["operations"].values()):
                entry["operation"].cancel()
            activities.close()
        self.destroyed.connect(destroyed)
        self.tools.setCurrentRow(0)
        self._buttons()

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def _start(self, tool_id, kind, function):
        if self._lifetime["closed"] or tool_id in self._operations:
            return False
        if not _WORKERS.acquire(blocking=False):
            self.status.setText("Two community workers are active. Other completed tool views remain available.")
            return False
        operation = AdapterOperation(timeout=120)
        handle = self._activities.begin(tool_id + ":" + kind, self._specs[tool_id]["name"] + " · " + kind)
        entry = {"operation": operation, "kind": kind, "handle": handle}
        self._operations[tool_id] = entry
        target, lifetime = self._queue, self._lifetime
        def post(kind, value):
            if lifetime["closed"]:
                return
            try:
                target.put_nowait((tool_id, entry, kind, value))
            except queue.Full:
                if kind != "progress":
                    # One terminal slot is held in memory, never blocked by a slow Qt poll.
                    entry["terminal"] = (kind, value)
        def progress(value):
            post("progress", value)
        def work():
            try:
                result = function(operation, progress)
                operation.check()
                post("result", result)
            except Exception as exc:
                post("error", str(exc)[:1024])
            finally:
                entry["finished"] = True
                _WORKERS.release()
        thread = threading.Thread(target=work, name="CommunityTool-" + tool_id, daemon=True)
        self._threads.append(thread)
        try:
            thread.start()
        except (OSError, RuntimeError) as exc:
            if thread.ident is not None:
                operation.cancel()
                self.status.setText("Worker launch reported an error; waiting for its exact retirement.")
                return False
            self._threads.remove(thread)
            self._operations.pop(tool_id, None)
            self._activities.finish(handle)
            _WORKERS.release()
            self.status.setText("Worker could not start: " + str(exc)[:240])
            self._buttons()
            return False
        self._buttons()
        return True

    def _poll(self):
        for _ in range(32):
            try:
                tool_id, entry, kind, value = self._queue.get_nowait()
            except queue.Empty:
                break
            self._deliver(tool_id, entry, kind, value)
        for tool_id, entry in tuple(self._operations.items()):
            terminal = entry.pop("terminal", None)
            if terminal:
                self._deliver(tool_id, entry, *terminal)
        self._threads = [thread for thread in self._threads if thread.is_alive()]

    def _deliver(self, tool_id, entry, kind, value):
        if self._operations.get(tool_id) is not entry:
            return
        if kind == "progress":
            if isinstance(value, dict):
                self._activities.update(entry["handle"], label=str(value.get("phase", entry["kind"]))[:120],
                                        done=value.get("finished", 0), total=value.get("total", 0))
            return
        self._activities.finish(entry["handle"])
        self._operations.pop(tool_id, None)
        if kind == "result" and entry["kind"] == "refresh":
            self._statuses[tool_id], self._sources = value
            if tool_id == self._selected:
                self._paint()
        elif tool_id == self._selected:
            self.detail.setPlainText(json.dumps(value, indent=2, ensure_ascii=False) if kind == "result" else str(value))
            self.technical_details.set_expanded(True)
            self.status.setText("Action completed; review its exact coverage and result." if kind == "result" else str(value))
            if kind == "result":
                self._show_result(entry["kind"], value)
        self._buttons()

    def _select(self, item, _previous=None):
        self._selected = item.data(Qt.ItemDataRole.UserRole) if item else None
        self._sandbox = self._path = None
        self.editor.clear()
        self.files.clear()
        self._paint()

    def _paint(self):
        if not self._selected:
            return
        spec = self._specs[self._selected]
        status = self._statuses.get(self._selected, {})
        state = str(status.get("state", "Not checked"))
        message = _status_summary(status)
        self.summary.setText(spec["name"] + " · " + state + "\n" + spec["mode"] + "\n" + str(message))
        self.source_info.setText(spec["mode"] + " · " + spec["license"] + "\n" + ", ".join(spec["capabilities"]))
        old = self.sources.currentData()
        self.sources.blockSignals(True)
        self.sources.clear()
        self.sources.addItem("Choose a reviewed full-commit import…", None)
        for row in self._sources:
            if row.get("repository") == spec["repository"] and row.get("state") == "reviewed":
                self.sources.addItem(row["commit"][:12] + " · " + row["license"], row["id"])
        index = self.sources.findData(old)
        self.sources.setCurrentIndex(max(0, index))
        self.sources.blockSignals(False)
        self.sandboxes.blockSignals(True)
        self.sandboxes.clear()
        for row in status.get("sandboxes", []):
            self.sandboxes.addItem(row["sandbox_id"][:12] + (" · customized" if row["customized"] else " · original copy"), row["sandbox_id"])
        self.sandboxes.blockSignals(False)
        self.detail.setPlainText(json.dumps(status, indent=2, ensure_ascii=False))
        self._buttons()

    def _buttons(self):
        selected = bool(self._selected)
        busy = self._selected in self._operations
        for button in (self.install_button, self.uninstall_button, self.check_button, self.refresh_button, self.sandbox_button):
            button.setEnabled(selected and not busy)
        for button in (self.save_button, self.diff_button, self.revert_button, self.analyze_button):
            button.setEnabled(selected and bool(self._sandbox) and bool(self._path) and not busy)
        self.cancel_button.setEnabled(busy)
        self.files.setEnabled(not busy)
        self.sandboxes.setEnabled(not busy)
        self.editor.setReadOnly(not self._path or busy)

    def refresh(self):
        tool = self._selected
        if tool:
            self._start(tool, "refresh", lambda op, _progress: (self.service.status(tool), self.service.catalog.list_imports()))

    def _install(self):
        tool, source = self._selected, self.sources.currentData()
        if tool:
            self._start(tool, "install", lambda op, progress: self.service.install(tool, op, progress, source_id=source))

    def _action(self, name):
        tool = self._selected
        if tool:
            self._start(tool, name, lambda op, progress: getattr(self.service, name)(tool, op, progress))

    def _show_result(self, kind, value):
        if kind == "create_sandbox" and isinstance(value, dict) and value.get("sandbox_id"):
            self.sandboxes.addItem(value["sandbox_id"][:12], value["sandbox_id"])
            self.sandboxes.setCurrentIndex(self.sandboxes.count()-1)
            self._select_sandbox()
            self.tabs.setCurrentIndex(1)
            if isinstance(value.get("analysis_path"), str):
                self.analysis_lab.input_path.setText(value["analysis_path"])
        elif kind == "sandbox_files":
            self.files.clear()
            for row in value:
                item = QListWidgetItem(row["path"] + (" · customized" if row["customized"] else ""))
                item.setData(Qt.ItemDataRole.UserRole, row["path"])
                self.files.addItem(item)
        elif kind == "sandbox_read":
            self.editor.setPlainText(value["text"])
        elif kind == "sandbox_diff":
            self.detail.setPlainText(value["diff"])
            self.technical_details.set_expanded(True)
            self.tabs.setCurrentIndex(0)

    def _select_sandbox(self, *_args):
        tool, identity = self._selected, self.sandboxes.currentData()
        if tool and identity:
            self._sandbox, self._path = identity, None
            self._start(tool, "sandbox_files", lambda op, _progress: self.service.sandbox_files(tool, identity))

    def _select_file(self, item, _previous=None):
        tool, identity = self._selected, self._sandbox
        path = item.data(Qt.ItemDataRole.UserRole) if item else None
        self._path = path
        if tool and identity and path:
            self._start(tool, "sandbox_read", lambda op, _progress: self.service.sandbox_read(tool, identity, path))
        self._buttons()

    def _save(self):
        tool, identity, path, text = self._selected, self._sandbox, self._path, self.editor.toPlainText()
        if tool and identity and path:
            self._start(tool, "sandbox_write", lambda op, _progress: self.service.sandbox_write(tool, identity, path, text))

    def _sandbox_action(self, name):
        tool, identity, path = self._selected, self._sandbox, self._path
        if tool and identity and path:
            self._start(tool, name, lambda op, _progress: getattr(self.service, name)(tool, identity, paths=[path]) if name == "sandbox_revert" else getattr(self.service, name)(tool, identity, path))

    def _show_credits(self):
        if not self._selected:
            return
        rows = self.service.credits(self._selected)  # fixed catalog data only.
        blocks = []
        for row in rows:
            url = row.get("url", "")
            parsed = urlsplit(url)
            link = html.escape(url)
            if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password:
                link = '<a href="'+html.escape(url, quote=True)+'">'+link+'</a>'
            blocks.append("<p><b>"+html.escape(row["name"])+"</b><br>"+html.escape(row.get("license", ""))+"<br>"+link+"<br>"+html.escape(row.get("notice", ""))+"</p>")
        self.credits.setHtml("".join(blocks))
        self.tabs.setCurrentIndex(2)

    def _open_upstream(self):
        if self._selected:
            QDesktopServices.openUrl(QUrl("https://github.com/" + self._specs[self._selected]["repository"]))

    def cancel_selected(self):
        entry = self._operations.get(self._selected)
        if entry:
            entry["operation"].cancel()

    def shutdown(self, timeout=5):
        """Off Qt only: stop owned work and prove every worker returned."""
        self.request_shutdown()
        deadline = time.monotonic() + min(30, max(0, timeout))
        for thread in self.owned_workers():
            thread.join(max(0, deadline-time.monotonic()))
        return not any(thread.is_alive() for thread in self.owned_workers())

    def request_shutdown(self):
        self._lifetime["closed"] = True
        for entry in tuple(self._operations.values()):
            entry["operation"].cancel()
        self.analysis_lab._lifetime["closed"] = True
        self.analysis_lab.cancel_pending()

    def owned_workers(self):
        analysis = getattr(self.analysis_lab, "_worker", None)
        return (*self._threads, *((analysis,) if analysis is not None else ()))

    def custody_released(self):
        from angerona.core.community_tool_probe_worker import probe_custody_released
        from angerona.core.curated_tools import _HELD_CUSTODY
        return probe_custody_released() and not bool(_HELD_CUSTODY)
