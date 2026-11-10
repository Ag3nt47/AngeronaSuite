"""Dedicated rules/playbook catalog and draft editor; actions run off Qt."""
from __future__ import annotations

import json
import hashlib
import queue
import re
import threading
import time
from html import escape

from PySide6.QtCore import Qt, QTimer, QRectF
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFormLayout, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)

from angerona.core.community_tool_adapters import AdapterOperation
from angerona.gui.action_progress import ActionActivities, ActionProgressView
from angerona.gui.community_tools import _WORKERS
from angerona.gui.dashboard_sections import DashboardDisclosure
from angerona.gui.theme import set_function_role


class StrategyBoard(QWidget):
    """Responsive X/O planning diagram; colors never assert host protection."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(190)
        self.setAccessibleName("Planned tactic: input, verified event, trigger, policy gates, requested action")
        self.action = "notify"
        self.severity = "HIGH"

    def set_strategy(self, severity, action):
        self.severity, self.action = severity, action
        self.update()

    def paintEvent(self, _event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(6, 6, -6, -6)
        painter.setBrush(QColor("#10251e"))
        painter.setPen(QPen(QColor("#3a6354"), 1))
        painter.drawRoundedRect(rect, 10, 10)
        painter.setPen(QPen(QColor("#2b4c40"), 1, Qt.PenStyle.DashLine))
        for index in range(1, 5):
            x = rect.left() + rect.width()*index/5
            painter.drawLine(int(x), rect.top()+10, int(x), rect.bottom()-10)
        nodes = [("X", "Input", "Untrusted"), ("O", "Verify", "Native signal"),
                 ("O", self.severity, "Trigger filter"), ("O", "Gate", "Policy + identity"),
                 ("O", "Notify" if self.action == "notify" else "Request", "Existing broker")]
        y = rect.top()+67
        for index, (symbol, caption, definition) in enumerate(nodes):
            x = rect.left()+rect.width()*(index+.5)/5
            if index < 4:
                next_x = rect.left()+rect.width()*(index+1.5)/5
                painter.setPen(QPen(QColor("#9bbdaf"), 2))
                painter.drawLine(int(x+19), int(y), int(next_x-21), int(y))
                painter.drawLine(int(next_x-27), int(y-5), int(next_x-21), int(y))
                painter.drawLine(int(next_x-27), int(y+5), int(next_x-21), int(y))
            color = QColor("#fb7185") if symbol == "X" else QColor("#67e8f9")
            painter.setPen(QPen(color, 2))
            painter.setBrush(QColor("#10251e"))
            painter.drawEllipse(QRectF(x-17, y-17, 34, 34))
            painter.drawText(QRectF(x-17, y-17, 34, 34), Qt.AlignmentFlag.AlignCenter, symbol)
            painter.setPen(QColor("#e2e8f0"))
            painter.drawText(QRectF(x-rect.width()/10, y+28, rect.width()/5, 22), Qt.AlignmentFlag.AlignCenter, caption)
            painter.setPen(QColor("#b6cfc1"))
            painter.drawText(QRectF(x-rect.width()/10, y+51, rect.width()/5, 36), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, definition)
        painter.setPen(QColor("#c5dccf"))
        painter.drawText(rect.adjusted(12, 8, -12, -8), Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
                         "TACTICS BOARD · Planned path, not a coverage or enforcement receipt")
        painter.end()


class RulesPlaybooksPanel(QWidget):
    """A whole page for source discovery, batch import, validation and rollback."""
    def __init__(self, library, parent=None, *, open_forge=None, open_source_review=None, open_settings=None, cfg=None):
        super().__init__(parent)
        self.library = library
        self._open_forge = open_forge
        self._open_source_review = open_source_review
        self._open_settings = open_settings
        self.cfg = cfg
        self._queue = queue.Queue(maxsize=64)
        self._operation = None
        self._thread = None
        self._entry = None
        self._source_id = None
        self._item_id = None
        self._loaded = False
        self._rows = {}
        self._test_evidence = {}
        self._loaded_text = ""
        self._dirty = False
        self._lifetime = {"closed": False, "operation": None}
        self._activities = ActionActivities(self)
        layout = QVBoxLayout(self)
        layout.addWidget(ActionProgressView(self._activities, self))
        title = QLabel("Rules & Playbooks · YARA and SOAR")
        title.setObjectName("sectionTitle")
        set_function_role(title, "configure")
        layout.addWidget(title)
        note = QLabel("Validated data only · imported scripts stay inert · existing response permissions still apply.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.global_state = QLabel()
        self.global_state.setWordWrap(True)
        self.global_state.setTextFormat(Qt.TextFormat.PlainText)
        self._global_state()
        runtime_row = QHBoxLayout()
        runtime_row.addWidget(self.global_state, 1)
        self.runtime_settings_button = QPushButton("Runtime settings")
        self.runtime_settings_button.setObjectName("CommunityRuntimeSettingsShortcut")
        self.runtime_settings_button.setEnabled(callable(open_settings))
        if callable(open_settings):
            self.runtime_settings_button.clicked.connect(lambda _checked=False: open_settings())
        runtime_row.addWidget(self.runtime_settings_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(runtime_row)
        self.tabs = QTabWidget()
        catalog = QWidget()
        catalog_layout = QVBoxLayout(catalog)
        self.presets = QComboBox()
        self.presets.addItem("Choose a predefined source…", "")
        self.presets.setAccessibleName("Predefined rules and playbooks sources")
        catalog_layout.addWidget(self.presets)
        source_line = QGridLayout()
        self.url = QLineEdit()
        self.url.setMaxLength(256)
        self.url.setPlaceholderText("https://github.com/owner/repository")
        self.url.setAccessibleName("Rules source repository URL")
        self.kind = QComboBox()
        self.kind.addItem("YARA + SOAR", "all")
        self.kind.addItem("YARA rules", "yara")
        self.kind.addItem("SOAR playbooks", "soar")
        self.find_button = QPushButton("Fetch catalog")
        self.review_button = QPushButton("Review source")
        self.review_button.setEnabled(callable(open_source_review))
        source_line.addWidget(self.url, 0, 0, 1, 3)
        source_line.addWidget(self.kind, 1, 0)
        source_line.addWidget(self.find_button, 1, 1)
        source_line.addWidget(self.review_button, 1, 2)
        source_line.setColumnStretch(0, 1)
        catalog_layout.addLayout(source_line)
        self.query = QLineEdit()
        self.query.setMaxLength(128)
        self.query.setPlaceholderText("Search rule name, technique or path…")
        catalog_layout.addWidget(self.query)
        self.candidates = QListWidget()
        self.candidates.setAccessibleName("Available catalog entries; select using checkboxes")
        catalog_layout.addWidget(self.candidates, 1)
        choose = QHBoxLayout()
        self.select_all_button = QPushButton("Select compatible")
        self.clear_button = QPushButton("Clear selection")
        self.install_button = QPushButton("Install checked")
        for button in (self.select_all_button, self.clear_button, self.install_button):
            choose.addWidget(button)
        catalog_layout.addLayout(choose)
        self.catalog_info = QLabel("Fetching lists source and license metadata; it never executes repository content.")
        self.catalog_info.setWordWrap(True)
        self.catalog_info.setTextFormat(Qt.TextFormat.PlainText)
        catalog_layout.addWidget(self.catalog_info)
        self.tabs.addTab(catalog, "Sources")
        drafts = QWidget()
        drafts_layout = QVBoxLayout(drafts)
        new_row = QHBoxLayout()
        self.draft_name = QLineEdit()
        self.draft_name.setMaxLength(128)
        self.draft_name.setPlaceholderText("Name for a new rule/playbook draft")
        self.draft_kind = QComboBox()
        self.draft_kind.addItem("New YARA rule", "yara")
        self.draft_kind.addItem("New declarative SOAR", "soar")
        self.new_button = QPushButton("Create draft")
        for widget in (self.draft_name, self.draft_kind, self.new_button):
            new_row.addWidget(widget)
        drafts_layout.addLayout(new_row)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.items = QListWidget()
        self.items.setAccessibleName("Installed rule and playbook drafts")
        split.addWidget(self.items)
        editor_box = QWidget()
        editor_layout = QVBoxLayout(editor_box)
        self.item_info = QLabel("Select an imported entry to view its current state, provenance and draft.")
        self.item_info.setTextFormat(Qt.TextFormat.PlainText)
        self.item_info.setWordWrap(True)
        editor_layout.addWidget(self.item_info)
        self.item_provenance = QLabel()
        self.item_provenance.setTextFormat(Qt.TextFormat.PlainText)
        self.item_provenance.setWordWrap(True)
        self.item_details = DashboardDisclosure(
            "Source details", self.item_provenance, "License, path and pinned revision")
        editor_layout.addWidget(self.item_details)
        self.editor = QPlainTextEdit()
        self.editor.setAccessibleName("YARA rule or declarative SOAR playbook draft editor")
        self.editor.setReadOnly(True)
        editor_layout.addWidget(self.editor, 1)
        split.addWidget(editor_box)
        split.setStretchFactor(1, 4)
        drafts_layout.addWidget(split, 1)
        actions = QGridLayout()
        self.save_button = QPushButton("Save draft")
        self.validate_button = QPushButton("Validate")
        self.test_button = QPushButton("Sample test")
        self.diff_button = QPushButton("Diff")
        self.activate_button = QPushButton("Activate validated")
        self.disable_button = QPushButton("Disable")
        self.rollback_button = QPushButton("Rollback")
        for index, button in enumerate((self.save_button, self.validate_button, self.test_button, self.diff_button,
                                        self.activate_button, self.disable_button, self.rollback_button)):
            actions.addWidget(button, index // 4, index % 4)
        drafts_layout.addLayout(actions)
        self.tabs.addTab(drafts, "Drafts")
        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        self.results.setAccessibleName("Rule validation sample results and exact activation coverage")
        self.results.document().setMaximumBlockCount(6000)
        self.test_table = QTableWidget(0, 4)
        self.test_table.setHorizontalHeaderLabels(["Rule / playbook", "Revision test", "Data state", "Reason / limits"])
        self.test_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.test_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.test_table.horizontalHeader().setStretchLastSection(True)
        self.result_page = QWidget()
        result_layout = QVBoxLayout(self.result_page)
        result_layout.addWidget(self.test_table)
        result_layout.addWidget(self.results, 2)
        self.tabs.addTab(self.result_page, "Tests & records")
        self.builder_page = self._build_strategy()
        self.tabs.insertTab(2, self.builder_page, "Strategy")
        layout.addWidget(self.tabs, 1)
        bottom = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.credits_button = QPushButton("Credits / licenses")
        self.forge_button = QPushButton("DetectionForge")
        self.forge_button.setEnabled(callable(open_forge))
        self.cancel_button = QPushButton("Cancel action")
        for button in (self.refresh_button, self.credits_button, self.forge_button, self.cancel_button):
            bottom.addWidget(button)
        layout.addLayout(bottom)
        self.status = QLabel("Drafts do not grant process, network or administrator authority.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        workflow_help = QLabel(
            "Choose a pinned source and review its provenance. Import entries as drafts, validate their syntax, "
            "then run a known sample before activation. Activation selects data; the corresponding global switch "
            "must also be ON. SOAR requests still pass the existing scoped response broker.")
        workflow_help.setWordWrap(True)
        self.workflow_details = DashboardDisclosure("Workflow help", workflow_help)
        layout.addWidget(self.workflow_details)
        for button in (self.validate_button, self.test_button, self.diff_button,
                       self.review_button, self.credits_button, self.forge_button):
            set_function_role(button, "analysis")
        for button in (self.runtime_settings_button, self.install_button, self.save_button,
                       self.new_button, self.activate_button, self.disable_button, self.rollback_button):
            set_function_role(button, "configure")
        for button in (self.refresh_button, self.find_button):
            set_function_role(button, "monitor")
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll)
        self._timer.start()
        self.presets.currentIndexChanged.connect(self._preset)
        self.find_button.clicked.connect(self._discover)
        self.review_button.clicked.connect(lambda: self._open_source_review() if callable(self._open_source_review) else None)
        self.query.textChanged.connect(self._filter)
        self.select_all_button.clicked.connect(lambda: self._check_candidates(True))
        self.clear_button.clicked.connect(lambda: self._check_candidates(False))
        self.install_button.clicked.connect(self._install)
        self.items.currentItemChanged.connect(self._read)
        self.refresh_button.clicked.connect(self.refresh)
        self.save_button.clicked.connect(self._save)
        self.editor.textChanged.connect(self._edited)
        self.new_button.clicked.connect(self._create)
        for button, method in ((self.validate_button, "validate"), (self.test_button, "sample_test"), (self.diff_button, "diff"),
                               (self.activate_button, "activate"), (self.disable_button, "disable"), (self.rollback_button, "rollback")):
            button.clicked.connect(lambda _checked=False, method=method: self._item_action(method))
        self.credits_button.clicked.connect(lambda: self._start("credits", lambda _op, _progress: library.credits()))
        self.forge_button.clicked.connect(lambda: self._open_forge() if callable(self._open_forge) else None)
        self.cancel_button.clicked.connect(self.cancel)
        lifetime, activities = self._lifetime, self._activities
        def destroyed(*_args):
            lifetime["closed"] = True
            if lifetime["operation"]:
                lifetime["operation"].cancel()
            activities.close()
        self.destroyed.connect(destroyed)
        self._buttons()

    def _build_strategy(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.strategy_title = QLabel("Build a tactic · match a verified signal, then request a permitted response")
        self.strategy_title.setWordWrap(True)
        layout.addWidget(self.strategy_title)
        self.strategy_board = StrategyBoard()
        layout.addWidget(self.strategy_board)
        form = QFormLayout()
        self.strategy_name = QLineEdit("Review suspicious activity")
        self.strategy_name.setMaxLength(120)
        self.strategy_severity = QComboBox()
        self.strategy_severity.addItems(["HIGH", "CRITICAL"])
        self.strategy_modules = QLineEdit()
        self.strategy_modules.setMaxLength(1024)
        self.strategy_modules.setPlaceholderText("Optional exact module names, separated by commas")
        self.strategy_action = QComboBox()
        self.strategy_action.addItem("Notify and explain", "notify")
        self.strategy_action.addItem("Request verified containment", "request_containment")
        self.strategy_message = QLineEdit("Review the original detection, its evidence and coverage before responding.")
        self.strategy_message.setMaxLength(1024)
        form.addRow("Tactic name", self.strategy_name)
        form.addRow("Minimum alert severity", self.strategy_severity)
        form.addRow("Which detectors?", self.strategy_modules)
        form.addRow("Requested action", self.strategy_action)
        form.addRow("Plain-English notification", self.strategy_message)
        layout.addLayout(form)
        self.strategy_explanation = QLabel()
        self.strategy_explanation.setWordWrap(True)
        layout.addWidget(self.strategy_explanation)
        actions = QHBoxLayout()
        self.strategy_preview_button = QPushButton("Preview JSON in technical editor")
        self.strategy_create_button = QPushButton("Create guided SOAR draft")
        actions.addWidget(self.strategy_preview_button)
        actions.addWidget(self.strategy_create_button)
        layout.addLayout(actions)
        definitions = QToolButton()
        definitions.setText("Definitions · why these gates exist")
        definitions.setCheckable(True)
        self.definitions = QLabel("YARA matches content patterns in scanned bytes; a match alone is not a verified breach. "
            "SOAR is a response workflow. HIGH/CRITICAL filters choose which original detections qualify. "
            "Native source means an actual enrolled collector, not a message copied from a report. "
            "Policy, process birth, file identity and original receipts still control containment. "
            "The builder cannot insert a shell command, target override or administrator grant. "
            "A sample test checks a known inert example; it does not establish host-wide protection.")
        self.definitions.setWordWrap(True)
        self.definitions.hide()
        definitions.toggled.connect(self.definitions.setVisible)
        layout.addWidget(definitions)
        layout.addWidget(self.definitions)
        layout.addStretch()
        self.strategy_preview_button.clicked.connect(self._preview_strategy)
        self.strategy_create_button.clicked.connect(self._create_strategy)
        self.strategy_severity.currentIndexChanged.connect(self._strategy_changed)
        self.strategy_action.currentIndexChanged.connect(self._strategy_changed)
        self._strategy_changed()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(page)
        return scroll

    def _strategy_changed(self):
        severity, action = self.strategy_severity.currentText(), self.strategy_action.currentData()
        self.strategy_board.set_strategy(severity, action)
        self.strategy_message.setEnabled(action == "notify")
        self.strategy_explanation.setText("When an original active " + severity + " detection matches the selected modules, " +
            ("show your review message." if action == "notify" else "ask the existing response owner to contain its verified target. This request can be held by policy or missing evidence.") +
            " Saving this tactic creates data only. Validate, test, select it, and review the global SOAR switch separately.")

    def _strategy_document(self):
        name = self.strategy_name.text().strip()
        identifier = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")[:64] or "review-playbook"
        modules = [value.strip() for value in self.strategy_modules.text().split(",") if value.strip()]
        action = {"type": self.strategy_action.currentData()}
        if action["type"] == "notify":
            action["message"] = self.strategy_message.text()
        document = {"schema": "angerona-playbook/v1", "id": identifier, "name": name,
                    "description": "Guided operator tactic; all existing response authority and target identity checks remain required.",
                    "trigger": {"minimum_severity": self.strategy_severity.currentText(), "modules": modules}, "actions": [action]}
        return name, json.dumps(document, indent=2, ensure_ascii=False)

    def _preview_strategy(self):
        name, text = self._strategy_document()
        self.items.setCurrentRow(-1)
        self._item_id = None
        self.draft_name.setText(name)
        self.draft_kind.setCurrentIndex(self.draft_kind.findData("soar"))
        self.editor.setPlainText(text)
        self.tabs.setCurrentIndex(1)
        self._buttons()

    def _create_strategy(self):
        name, text = self._strategy_document()
        self._start("create_draft", lambda _op, _progress: self.library.create_draft("soar", text, name=name))

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def _buttons(self):
        busy = self._operation is not None
        for widget in (self.presets, self.url, self.kind, self.find_button, self.install_button, self.items,
                       self.refresh_button, self.candidates, self.select_all_button, self.clear_button,
                       self.draft_name, self.draft_kind, self.new_button, self.strategy_preview_button, self.strategy_create_button):
            widget.setEnabled(not busy)
        for button in (self.save_button, self.validate_button, self.test_button, self.diff_button,
                       self.activate_button, self.disable_button, self.rollback_button):
            button.setEnabled(bool(self._item_id) and not busy)
        self.editor.setReadOnly(busy)
        self.cancel_button.setEnabled(busy)
        for button in (self.validate_button, self.test_button, self.activate_button):
            button.setEnabled(bool(self._item_id) and not busy and not self._dirty)

    def _global_state(self):
        if self.cfg is None:
            text = "Runtime configuration unavailable; activation does not prove a live scanner or responder."
        else:
            rules = getattr(self.cfg, "community_rules_enabled", False) is True
            playbooks = getattr(self.cfg, "community_playbooks_enabled", False) is True
            text = "Community runtime · YARA: " + ("enabled" if rules else "OFF") + " · SOAR: " + ("enabled" if playbooks else "OFF") + ". OFF switches keep activated data inactive."
        if self.global_state.text() != text:
            self.global_state.setText(text)

    def _start(self, kind, work):
        if self._lifetime["closed"] or self._operation is not None:
            return False
        if self._thread is not None and self._thread.is_alive():
            self.status.setText("The previous action is finishing its worker retirement; retry after it exits.")
            return False
        if not _WORKERS.acquire(blocking=False):
            self.status.setText("Community workers are busy; existing results remain available.")
            return False
        operation = AdapterOperation()
        self._operation = self._lifetime["operation"] = operation
        entry = self._entry = {"operation": operation, "kind": kind, "handle": self._activities.begin(kind, kind)}
        target, lifetime = self._queue, self._lifetime
        def post(kind, value):
            if lifetime["closed"]:
                return
            try:
                target.put_nowait((entry, kind, value))
            except queue.Full:
                if kind != "progress":
                    entry["terminal"] = kind, value
        def progress(value):
            post("progress", value)
        def run():
            try:
                result = work(operation, progress)
                operation.check()
                post("result", result)
            except Exception as exc:
                post("error", str(exc)[:2048])
            finally:
                _WORKERS.release()
        self._thread = threading.Thread(target=run, name="RulesPlaybooks-"+kind, daemon=True)
        try:
            self._thread.start()
        except (OSError, RuntimeError) as exc:
            if self._thread.ident is not None:
                operation.cancel()
                self.status.setText("Worker launch reported an error; waiting for its exact retirement.")
                return False
            _WORKERS.release()
            self._activities.finish(entry["handle"])
            self._entry = self._operation = self._lifetime["operation"] = None
            self._thread = None
            self.status.setText("Worker could not start: " + str(exc)[:240])
            self._buttons()
            return False
        self._buttons()
        return True

    def _poll(self):
        self._global_state()
        for _ in range(32):
            try:
                entry, kind, value = self._queue.get_nowait()
            except queue.Empty:
                break
            self._deliver(entry, kind, value)
        if self._entry and "terminal" in self._entry:
            self._deliver(self._entry, *self._entry.pop("terminal"))

    def _deliver(self, entry, kind, value):
        if self._lifetime["closed"] or self._entry is not entry:
            return
        if kind == "progress":
            row = value if isinstance(value, dict) else {"phase": str(value)}
            self._activities.update(entry["handle"], label=str(row.get("phase", entry["kind"]))[:140], done=row.get("finished", 0), total=row.get("total", 0))
            return
        self._activities.finish(entry["handle"])
        self._entry = self._operation = self._lifetime["operation"] = None
        if kind == "error":
            self.status.setText(str(value))
            self.results.setPlainText(str(value))
            self.tabs.setCurrentWidget(self.result_page)
        else:
            self._result(entry["kind"], value)
        self._buttons()

    def _result(self, kind, value):
        self.results.setPlainText(value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False, default=str))
        self.status.setText("Completed; inspect exact compatibility, coverage and authority checks in Results.")
        self._global_state()
        if kind == "activate" and self.cfg is not None and not (getattr(self.cfg, "community_rules_enabled", False) is True and getattr(self.cfg, "community_playbooks_enabled", False) is True):
            self.status.setText("Activation result recorded. Check the global switches above: selected data stays inactive while its corresponding switch is OFF.")
        if kind == "refresh":
            sources, items = value
            self.presets.blockSignals(True)
            self.presets.clear()
            self.presets.addItem("Choose a predefined source…", "")
            for row in sources:
                self.presets.addItem(row.get("name", row.get("url", "Source")), row.get("url", ""))
            self.presets.blockSignals(False)
            self.items.blockSignals(True)
            self.items.clear()
            self._rows = {row["id"]: row for row in items}
            for row in items:
                item = QListWidgetItem()
                item.setData(Qt.ItemDataRole.UserRole, row["id"])
                self.items.addItem(item)
                self._paint_badge(item, row)
            self.items.blockSignals(False)
            self._item_id = None
            self._dirty = False
            self.editor.clear()
            self._test_rows()
        elif kind == "discover":
            self._source_id = value.get("source_id")
            self.candidates.clear()
            entries = value.get("entries", [])
            for row in entries[:500]:
                compatibility = str(row.get("compatibility", "review required"))
                item = QListWidgetItem(row.get("name", row["path"]) + " · " + compatibility)
                item.setData(Qt.ItemDataRole.UserRole, row)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                item.setToolTip("<qt>" + escape(row["path"] + "\n" + str(row.get("license", "License requires review"))).replace("\n", "<br>") + "</qt>")
                self.candidates.addItem(item)
            self.catalog_info.setText(str(value.get("commit", "Pinned source unavailable")) + " · " + str(len(entries)) + " catalog entries; " + str(min(500, len(entries))) + " shown. Review this exact source in Source Library before installation. Imported scripts remain inert.")
            self._filter()
        elif kind == "read":
            if self._item_id:
                self._rows[self._item_id] = value
            self.editor.blockSignals(True)
            self.editor.setPlainText(value["text"])
            self._loaded_text = self.editor.toPlainText()
            self._dirty = False
            self.editor.blockSignals(False)
            self.item_info.setText(str(value.get("name", "")) + " · " + str(value.get("kind", ""))
                                   + " · " + str(value.get("state", "")))
            self.item_provenance.setText("\n".join(str(value.get(key, "")) for key in ("license", "path", "commit")))
            if value.get("kind") == "soar":
                try:
                    document = json.loads(value["text"])
                    if document.get("schema") == "angerona-playbook/v1":
                        action = document["actions"][0]["type"]
                        self.strategy_board.set_strategy(document["trigger"]["minimum_severity"], action)
                        self.strategy_title.setText("Selected tactic: " + str(document["name"]) + " · planned data path; runtime and proof gates still apply")
                except (ValueError, TypeError, KeyError, IndexError):
                    pass
            self._test_rows()
        else:
            if self._item_id and isinstance(value, dict) and kind in {"save_draft", "validate", "sample_test", "activate", "disable", "rollback"}:
                row = self._rows.get(self._item_id, {})
                if kind == "save_draft":
                    row = dict(row, **value)
                    self._loaded_text, self._dirty = self.editor.toPlainText(), False
                    self._test_evidence.pop(self._item_id, None)
                elif kind in {"validate", "sample_test"}:
                    if value.get("sha256") == row.get("draft_sha256"):
                        self._test_evidence[self._item_id] = value
                elif kind in {"activate", "disable", "rollback"}:
                    row = dict(row, **value)
                self._rows[self._item_id] = row
                self._test_rows()
            self.tabs.setCurrentWidget(self.result_page)

    def _badge(self, row):
        identity = row.get("id")
        if identity == self._item_id and self._dirty:
            return "? edited", "Unsaved text differs from the tested revision. Save and test again.", "#fbbf24", ""
        validation = self._test_evidence.get(identity, row.get("validation", {}))
        if not isinstance(validation, dict) or not isinstance(validation.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", validation["sha256"]) or validation.get("sha256") != row.get("draft_sha256"):
            return "? untested", "No test evidence bound to this draft SHA.", "#94a3b8", ""
        digest = validation.get("sha256", "")
        if validation.get("state") in {"invalid", "failed"}:
            return "✕ failed", str(validation.get("message", "Validation failed"))[:220], "#fb7185", digest
        if validation.get("sample_passed") is True:
            return "✓ sample pass", "Known inert positive/negative checks passed; host coverage remains unverified.", "#34d399", digest
        if validation.get("sample_passed") is False:
            return "✕ sample fail", "The expected positive/negative fixture did not pass.", "#fb7185", digest
        return "• validated", "Syntax/native compilation or sample scan completed; expected accuracy is unproved.", "#fbbf24", digest

    def _paint_badge(self, item, row):
        badge, reason, color, digest = self._badge(row)
        item.setText(badge + " · " + row.get("name", row.get("path", row["id"])) + " · " + str(row.get("state", "draft")))
        item.setForeground(QColor(color))
        item.setToolTip("<qt>" + escape(reason + ("\nTested SHA-256: " + digest if digest else "")).replace("\n", "<br>") + "</qt>")

    def _test_rows(self):
        self.test_table.setRowCount(len(self._rows))
        for index, row in enumerate(self._rows.values()):
            badge, reason, color, digest = self._badge(row)
            for column, text in enumerate((row.get("name", row.get("path", row["id"])), badge, str(row.get("state", "draft")), reason)):
                cell = QTableWidgetItem(text)
                if column == 1:
                    cell.setForeground(QColor(color))
                cell.setToolTip("<qt>" + escape(reason + ("\nTested SHA-256: " + digest if digest else "")).replace("\n", "<br>") + "</qt>")
                self.test_table.setItem(index, column, cell)
        for index in range(self.items.count()):
            item = self.items.item(index)
            row = self._rows.get(item.data(Qt.ItemDataRole.UserRole))
            if row:
                self._paint_badge(item, row)

    def _edited(self):
        self._dirty = bool(self._item_id and self.editor.toPlainText() != self._loaded_text)
        # Editing one draft must not recreate the entire 256-row table per key.
        for index, row in enumerate(self._rows.values()):
            if row["id"] != self._item_id:
                continue
            badge, reason, color, digest = self._badge(row)
            for column, text in ((1, badge), (3, reason)):
                cell = self.test_table.item(index, column)
                if cell is not None:
                    cell.setText(text)
                    cell.setToolTip("<qt>" + escape(reason + ("\nTested SHA-256: "+digest if digest else "")).replace("\n", "<br>") + "</qt>")
                    if column == 1:
                        cell.setForeground(QColor(color))
            break
        for index in range(self.items.count()):
            item = self.items.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == self._item_id:
                self._paint_badge(item, self._rows[self._item_id])
                break
        self._buttons()

    def refresh(self):
        return self._start("refresh", lambda _op, _progress: (self.library.sources(), self.library.items()))

    def _preset(self):
        value = self.presets.currentData()
        if value:
            self.url.setText(value)

    def _discover(self):
        url, kind, query = self.url.text().strip(), self.kind.currentData(), self.query.text().strip()
        self._start("discover", lambda op, progress: self.library.discover(url, kind=kind, query=query, operation=op, progress=progress))

    def _filter(self):
        query = self.query.text().casefold()
        for index in range(self.candidates.count()):
            item = self.candidates.item(index)
            row = item.data(Qt.ItemDataRole.UserRole)
            item.setHidden(query not in (item.text()+" "+row["path"]).casefold())

    def _check_candidates(self, checked):
        for index in range(self.candidates.count()):
            item = self.candidates.item(index)
            row = item.data(Qt.ItemDataRole.UserRole)
            compatible = str(row.get("compatibility", "")).lower() in {"supported", "compatible", "native", "reviewed"}
            item.setCheckState(Qt.CheckState.Checked if checked and compatible and not item.isHidden() else Qt.CheckState.Unchecked)

    def _install(self):
        source = self._source_id
        paths = [self.candidates.item(index).data(Qt.ItemDataRole.UserRole)["path"] for index in range(self.candidates.count()) if self.candidates.item(index).checkState() == Qt.CheckState.Checked]
        if not source or not paths:
            self.status.setText("Fetch a pinned catalog and check the entries to import.")
            return
        self._start("install_batch", lambda op, progress: self.library.install_batch(source, paths, operation=op, progress=progress))

    def _read(self, item, _previous=None):
        self._item_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        if self._item_id:
            identity = self._item_id
            self._start("read", lambda _op, _progress: self.library.read(identity))

    def _save(self):
        identity, text = self._item_id, self.editor.toPlainText()
        if identity:
            self._start("save_draft", lambda _op, _progress: self.library.save_draft(identity, text))

    def _create(self):
        kind, name, text = self.draft_kind.currentData(), self.draft_name.text().strip(), self.editor.toPlainText()
        if not name or not text.strip():
            self.status.setText("Give the draft a name and enter its rule or declarative playbook text.")
            return
        self._start("create_draft", lambda _op, _progress: self.library.create_draft(kind, text, name=name))

    def _item_action(self, method):
        identity = self._item_id
        if identity:
            self._start(method, lambda op, _progress: getattr(self.library, method)(identity, operation=op)
                        if method in {"validate", "sample_test", "activate", "rollback"} else getattr(self.library, method)(identity))

    def cancel(self):
        if self._operation:
            self._operation.cancel()

    def shutdown(self, timeout=5):
        """Background shutdown; never joins a compiler or importer on Qt."""
        self._lifetime["closed"] = True
        self.cancel()
        if self._thread:
            self._thread.join(min(30, max(0, timeout)))
        return self._thread is None or not self._thread.is_alive()

    def request_shutdown(self):
        self._lifetime["closed"] = True
        self.cancel()

    def owned_workers(self):
        return (self._thread,) if self._thread is not None else ()

    def custody_released(self):
        from angerona.core.community_tool_probe_worker import probe_custody_released
        return probe_custody_released()


class RulesPlaybooksDialog(QDialog):
    """A modeless, independently resizable authoring window."""
    def __init__(self, library, parent=None, *, cfg=None, open_forge=None, open_source_review=None, open_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Angerona — Rules & Playbooks")
        self.setModal(False)
        self.resize(1180, 780)
        self.setMinimumSize(650, 440)
        layout = QVBoxLayout(self)
        self.panel = RulesPlaybooksPanel(library, self, cfg=cfg, open_forge=open_forge,
                                        open_source_review=open_source_review, open_settings=open_settings)
        layout.addWidget(self.panel)
        from angerona.gui.window_fit import install_window_fit
        self._window_fit = install_window_fit(self)

    def closeEvent(self, event):  # noqa: N802
        self.panel.cancel()
        super().closeEvent(event)

    def retire_view(self):
        self.panel.request_shutdown()
        self.close()

    def owned_workers(self):
        return self.panel.owned_workers()

    def custody_released(self):
        return self.panel.custody_released()
