import threading
import time
import json
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtWidgets import QApplication, QPushButton, QWidget

from angerona.core.community_tool_adapters import tool_specs
from angerona.gui.community_tools import CommunityToolsPanel
from angerona.gui.rules_playbooks import RulesPlaybooksPanel

_APP = None


def wait_until(predicate, timeout=5):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def app():
    global _APP
    _APP = QApplication.instance() or QApplication([])
    return _APP


class FakeTools:
    def __init__(self, tmp_path):
        self.root = tmp_path / "community"
        self.calls = []
        self.main = threading.get_ident()
        self.text = "inert original"
        self.catalog = SimpleNamespace(list_imports=lambda: self._record("sources") or [{"repository": "sigmahq/sigma", "state": "reviewed", "commit": "a"*40, "license": "DRL-1.1", "id": "b"*64}])
    def _record(self, *args):
        assert threading.get_ident() != self.main
        self.calls.append(args)
    tool_specs = staticmethod(tool_specs)
    def status(self, tool):
        self._record("status", tool)
        return {"tool_id": tool, "state": "not-installed", "sandboxes": []}
    def install(self, tool, operation, progress, *, source_id=None):
        self._record("install", tool, source_id)
        progress({"phase": "install", "finished": 1, "total": 1})
        return {"state": "ready-data"}
    def uninstall(self, tool, operation, progress):
        self._record("uninstall", tool)
        return {"state": "uninstalled"}
    def self_check(self, tool, operation, progress):
        self._record("self_check", tool)
        return {"state": "passed", "positive": True, "negative": True}
    def create_sandbox(self, tool, operation, progress):
        self._record("create_sandbox", tool)
        return {"sandbox_id": "a"*32, "tool_id": tool}
    def sandbox_files(self, tool, identity):
        self._record("files", tool, identity)
        return [{"path": "fixture.xml", "customized": False}]
    def sandbox_read(self, tool, identity, path):
        self._record("read", tool, identity, path)
        return {"path": path, "text": self.text}
    def sandbox_write(self, tool, identity, path, text):
        self._record("save", tool, identity, path, text)
        self.text = text
        return {"state": "saved-custom-copy", "activated": False}
    def sandbox_diff(self, tool, identity, path):
        self._record("diff", tool, identity, path)
        return {"diff": "-old\n+custom"}
    def sandbox_revert(self, tool, identity, *, paths):
        self._record("revert", tool, identity, paths)
        return {"state": "reverted"}
    def sandbox_analysis(self, tool, identity, path):
        self._record("analysis", tool, identity, path)
        return {"state": "parsed", "activated": False}
    def credits(self, _tool):
        return [{"name": "<inert author>", "url": "javascript:inert", "license": "MIT"}]


def retire(panel):
    if isinstance(panel, CommunityToolsPanel):
        for entry in panel._operations.values():
            entry["operation"].cancel()
        wait_until(lambda: not panel._operations)
        wait_until(lambda: not any(thread.is_alive() for thread in panel._threads))
    else:
        panel.cancel()
        wait_until(lambda: panel._operation is None)
        wait_until(lambda: panel._thread is None or not panel._thread.is_alive())
    panel.close()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_suggested_pinned_install_self_check_and_sandbox_actions_are_off_qt(app, tmp_path):
    service = FakeTools(tmp_path)
    panel = CommunityToolsPanel(service)
    panel.show()
    wait_until(lambda: not panel._operations)
    panel.tools.setCurrentRow(2)  # Sigma
    panel.refresh()
    wait_until(lambda: not panel._operations)
    assert panel.sources.count() == 2
    panel.sources.setCurrentIndex(1)
    panel.install_button.click()
    wait_until(lambda: not panel._operations)
    assert ("install", "sigma", "b"*64) in service.calls
    panel.check_button.click()
    wait_until(lambda: not panel._operations)
    assert ("self_check", "sigma") in service.calls
    panel.sandbox_button.click()
    wait_until(lambda: panel.files.count() == 1 and not panel._operations)
    panel.files.setCurrentRow(0)
    wait_until(lambda: not panel._operations and panel.editor.toPlainText() == "inert original")
    panel.editor.setPlainText("operator inert custom copy")
    panel.save_button.click()
    wait_until(lambda: not panel._operations)
    assert service.text == "operator inert custom copy"
    panel.diff_button.click()
    wait_until(lambda: not panel._operations)
    assert "+custom" in panel.detail.toPlainText()
    panel.credits_button.click()
    assert "<inert author>" in panel.credits.toPlainText()
    assert 'href="javascript:' not in panel.credits.toHtml()
    retire(panel)


def test_one_busy_adapter_does_not_block_another_or_qt(app, tmp_path):
    service = FakeTools(tmp_path)
    started = threading.Event()
    def blocked(tool, operation, progress):
        service._record("self_check", tool)
        if tool == "zero-breach":
            started.set()
            while not operation.cancelled.wait(.01):
                operation.check()
            operation.check()
        return {"state": "passed"}
    service.self_check = blocked
    panel = CommunityToolsPanel(service)
    panel.show()
    wait_until(lambda: not panel._operations)
    ticks = []
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start(5)
    panel.check_button.click()
    wait_until(started.is_set)
    panel.tools.setCurrentRow(2)
    panel.check_button.click()
    wait_until(lambda: ("self_check", "sigma") in service.calls and "sigma" not in panel._operations)
    assert ticks and "zero-breach" in panel._operations
    panel.tools.setCurrentRow(0)
    panel.cancel_button.click()
    wait_until(lambda: not panel._operations)
    timer.stop()
    retire(panel)


class FakeLibrary:
    def __init__(self):
        self.calls = []
        self.main = threading.get_ident()
    def record(self, *args):
        assert threading.get_ident() != self.main
        self.calls.append(args)
    def sources(self):
        self.record("sources")
        return [{"name": "Pinned fixture source", "url": "https://github.com/owner/rules"}]
    def items(self):
        self.record("items")
        return [{"id": "fixture-id", "name": "Inert YARA", "kind": "yara", "state": "draft"}]
    def discover(self, url, *, kind, query, operation, progress):
        self.record("discover", url, kind, query)
        return {"source_id": "b"*64, "commit": "a"*40, "entries": [{"id": "entry", "path": "rules/inert.yar", "name": "Inert rule", "kind": "yara", "compatibility": "supported", "license": "MIT"}, {"id": "foreign", "path": "foreign/script.py", "name": "Foreign script", "kind": "soar", "compatibility": "advisory-only"}]}
    def install_batch(self, source, paths, *, operation, progress):
        self.record("install_batch", source, paths)
        return [{"id": "fixture-id", "state": "draft"}]
    def read(self, identity):
        self.record("read", identity)
        return {"id": identity, "name": "Inert YARA", "text": "rule inert { condition: false }", "kind": "yara", "state": "draft"}
    def save_draft(self, identity, text):
        self.record("save_draft", identity, text)
        return {"state": "draft"}
    def create_draft(self, kind, text, *, name):
        self.record("create_draft", kind, text, name)
        return {"id": "new-fixture-id", "state": "draft"}
    def validate(self, identity, *, operation=None):
        self.record("validate", identity)
        return {"state": "valid"}
    def sample_test(self, identity, *, operation=None):
        self.record("sample_test", identity)
        return {"state": "passed", "positive": True, "negative": True}
    def diff(self, identity):
        self.record("diff", identity)
        return "-old\n+custom"
    def activate(self, identity, *, operation=None):
        self.record("activate", identity)
        return {"state": "held", "reason": "Exact runtime admission remains required"}
    def disable(self, identity):
        self.record("disable", identity)
        return {"state": "disabled"}
    def rollback(self, identity, *, operation=None):
        self.record("rollback", identity)
        return {"state": "rolled-back"}
    def credits(self):
        self.record("credits")
        return [{"name": "Inert fixture author", "license": "MIT"}]


def test_rules_page_catalog_batch_editor_and_exact_runtime_buttons(app):
    library = FakeLibrary()
    opened = []
    panel = RulesPlaybooksPanel(library, open_forge=lambda: opened.append(True), cfg=SimpleNamespace(community_rules_enabled=False, community_playbooks_enabled=False))
    panel.show()
    wait_until(lambda: panel._operation is None and panel.items.count() == 1)
    panel.presets.setCurrentIndex(1)
    panel.find_button.click()
    wait_until(lambda: panel._operation is None and panel.candidates.count() == 2)
    panel.select_all_button.click()
    assert panel.candidates.item(0).checkState() == Qt.CheckState.Checked
    assert panel.candidates.item(1).checkState() == Qt.CheckState.Unchecked
    panel.install_button.click()
    wait_until(lambda: panel._operation is None)
    assert ("install_batch", "b"*64, ["rules/inert.yar"]) in library.calls
    assert "YARA: OFF" in panel.global_state.text() and "SOAR: OFF" in panel.global_state.text()
    panel.tabs.setCurrentIndex(1)
    panel.items.setCurrentRow(0)
    wait_until(lambda: panel._operation is None and "condition: false" in panel.editor.toPlainText())
    panel.editor.setPlainText("rule inert { condition: true }")
    panel.save_button.click()
    wait_until(lambda: panel._operation is None)
    for button, method in ((panel.validate_button, "validate"), (panel.test_button, "sample_test"),
                           (panel.activate_button, "activate"), (panel.disable_button, "disable"), (panel.rollback_button, "rollback")):
        button.click()
        wait_until(lambda: panel._operation is None)
        assert (method, "fixture-id") in library.calls
    panel.forge_button.click()
    assert opened == [True]
    panel.draft_name.setText("New inert YARA")
    panel.new_button.click()
    wait_until(lambda: panel._operation is None)
    assert ("create_draft", "yara", "rule inert { condition: true }", "New inert YARA") in library.calls
    retire(panel)


def test_guided_strategy_emits_only_closed_declarative_actions_and_explains_gates(app):
    library = FakeLibrary()
    panel = RulesPlaybooksPanel(library)
    panel.strategy_name.setText("Verified review tactic")
    panel.strategy_severity.setCurrentText("CRITICAL")
    panel.strategy_modules.setText("YARA Scanner, SpywareGuard")
    panel.strategy_action.setCurrentIndex(panel.strategy_action.findData("request_containment"))
    name, text = panel._strategy_document()
    document = json.loads(text)
    from angerona.core.rule_playbook_library import validate_playbook
    assert validate_playbook(text.encode())["actions"] == [{"type": "request_containment"}]
    assert document["trigger"] == {"minimum_severity": "CRITICAL", "modules": ["YARA Scanner", "SpywareGuard"]}
    assert "can be held by policy" in panel.strategy_explanation.text()
    assert panel.strategy_board.action == "request_containment"
    panel.strategy_create_button.click()
    wait_until(lambda: panel._operation is None)
    assert ("create_draft", "soar", text, name) in library.calls
    retire(panel)


def test_test_badges_require_current_sha_and_expected_samples_and_stale_on_edit(app):
    panel = RulesPlaybooksPanel(FakeLibrary())
    row = {"id": "inert-id", "draft_sha256": "a"*64, "validation": {"state": "valid", "sha256": "a"*64}}
    assert panel._badge(row)[0] == "• validated"  # native compile is not an accuracy pass.
    row["validation"]["sample_passed"] = True
    assert panel._badge(row)[0] == "✓ sample pass"
    row["draft_sha256"] = "b"*64
    assert panel._badge(row)[0] == "? untested"
    row["draft_sha256"] = "a"*64
    panel._item_id, panel._dirty = "inert-id", True
    assert panel._badge(row)[0] == "? edited"
    panel._dirty = False
    row["validation"]["sample_passed"] = False
    assert panel._badge(row)[0] == "✕ sample fail"
    retire(panel)


def test_actual_hub_and_dedicated_window_reuse_bound_libraries_and_remain_modeless(app, tmp_path):
    from angerona.gui.curated_tools import GitHubToolsDialog
    from angerona.gui.main_window import MainWindow
    cfg = SimpleNamespace(data_dir=tmp_path, community_rules_enabled=False, community_playbooks_enabled=False)
    manager = SimpleNamespace(cfg=cfg, modules={}, ugcap_paused=False)
    hub = GitHubToolsDialog(manager)
    assert hub.community_service.root == tmp_path / "community-tools"
    assert hub.rule_library.root == tmp_path / "rule-playbook-library"
    assert hub.community_service.catalog.root == tmp_path / "github-source-library"
    titles = [hub.tabs.tabText(index) for index in range(hub.tabs.count())]
    assert "Suggested tools" in titles and "Rules & Playbooks" in titles
    hub.open_source_library()
    assert hub.tabs.currentWidget() is hub.source_scroll
    hub.open_analysis()
    assert hub.source_library.tabs.currentWidget() is hub.source_library.analysis_lab
    hub.scanner.controller.shutdown()
    wait_until(lambda: hub.scanner.controller._worker is None or not hub.scanner.controller._worker.is_alive())
    hub.retire_view()
    wait_until(lambda: not any(worker.is_alive() for worker in hub.owned_workers()))
    hub.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


    # Actual MainWindow route with only a QWidget owner; no Core is constructed.
    owner = QWidget()
    owner.manager, owner.config = manager, cfg
    owner._github_tools_ui_closed = False
    owner._rules_playbooks_dialog = None
    owner._github_tools_dialog = None
    owner._rules_playbooks_btn = QPushButton(owner)
    owner._qss = lambda: ""
    owner._open_community_forge = lambda: None
    owner._open_github_tools = lambda **_kwargs: None
    window = MainWindow._open_rules_playbooks(owner)
    wait_until(lambda: window.panel._operation is None)
    assert not window.isModal()
    assert window.windowFlags() & Qt.WindowType.WindowMinimizeButtonHint
    assert window.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
    assert window.panel.library.root == tmp_path / "rule-playbook-library"
    assert MainWindow._open_rules_playbooks(owner) is window
    MainWindow._close_github_tools_window(owner)
    assert window.panel._lifetime["closed"]
    wait_until(lambda: not any(worker.is_alive() for worker in window.owned_workers()))
    assert window.custody_released()
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_suggested_shutdown_cancels_and_retains_its_analysis_lab_worker(app, tmp_path):
    panel = CommunityToolsPanel(FakeTools(tmp_path))
    stopped = threading.Event()
    operation = SimpleNamespace(cancel=lambda: stopped.set())
    panel.analysis_lab._operation = operation
    worker = threading.Thread(target=lambda: stopped.wait(2), name="inert-analysis-owner")
    panel.analysis_lab._worker = worker
    worker.start()
    assert worker in panel.owned_workers()
    panel.request_shutdown()
    assert stopped.is_set() and panel.analysis_lab._lifetime["closed"]
    wait_until(lambda: not worker.is_alive())
    retire(panel)


@pytest.mark.parametrize("kind", ["source", "analysis"])
def test_existing_source_and_analysis_start_fence_closed_or_unsettled_generation(app, tmp_path, kind):
    if kind == "source":
        from angerona.gui.github_tools import GitHubToolsPanel
        panel = GitHubToolsPanel(root=tmp_path / "source")
        start = lambda work: panel._start("preview", lambda op: work(op), "Inert fixture")
    else:
        from angerona.gui.analysis_lab import AnalysisLabPanel
        panel = AnalysisLabPanel(root=tmp_path / "analysis")
        start = lambda work: panel._start("case", lambda op, _progress: work(op), "Inert fixture")
    calls = []
    panel._lifetime["closed"] = True
    start(lambda _op: calls.append("forbidden after close"))
    assert panel._worker is None and not calls
    panel._lifetime["closed"] = False
    entered, release = threading.Event(), threading.Event()
    def old(_op):
        entered.set()
        release.wait(3)
        return "old inert outcome"
    start(old)
    wait_until(entered.is_set)
    original = panel._worker
    panel._busy = False  # Reopened view state cannot replace a retained worker.
    start(lambda _op: calls.append("forbidden replacement"))
    assert panel._worker is original and not calls
    release.set()
    wait_until(lambda: panel._worker is None)
    assert not original.is_alive()
    start(lambda _op: calls.append("new after retirement") or "new inert outcome")
    wait_until(lambda: panel._worker is None)
    assert calls == ["new after retirement"]
    panel.close()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_rules_retains_previous_worker_until_actual_retirement(app):
    panel = RulesPlaybooksPanel(FakeLibrary())
    entered, release = threading.Event(), threading.Event()
    def old():
        entered.set()
        release.wait(3)
    previous = threading.Thread(target=old, name="inert-rule-retirement")
    panel._thread = previous
    previous.start()
    wait_until(entered.is_set)
    calls = []
    assert not panel._start("fixture", lambda *_: calls.append("forbidden replacement"))
    assert panel.owned_workers() == (previous,)
    assert not calls and "retirement" in panel.status.text()
    release.set()
    wait_until(lambda: not previous.is_alive())
    assert panel._start("fixture", lambda *_: calls.append("after retirement") or {})
    wait_until(lambda: panel._operation is None)
    assert calls == ["after retirement"]
    retire(panel)


@pytest.mark.parametrize("kind", ["rules", "tools"])
def test_community_thread_start_failure_releases_slot_and_preserves_next_action(app, tmp_path, monkeypatch, kind):
    from angerona.gui import rules_playbooks, community_tools
    target = rules_playbooks if kind == "rules" else community_tools
    panel = RulesPlaybooksPanel(FakeLibrary()) if kind == "rules" else CommunityToolsPanel(FakeTools(tmp_path))
    if kind == "tools":
        wait_until(lambda: not panel._operations and not any(thread.is_alive() for thread in panel._threads))
    class BrokenThread:
        def __init__(self, **_kwargs):
            self.ident = None
        def start(self):
            raise RuntimeError("inert launch failure")
        def is_alive(self):
            return False
    real_threading = target.threading
    monkeypatch.setattr(target, "threading", SimpleNamespace(Thread=BrokenThread))
    start = (lambda: panel._start("fixture", lambda *_: {})) if kind == "rules" else (lambda: panel._start("sigma", "fixture", lambda *_: {}))
    assert start() is False
    assert "could not start" in panel.status.text()
    assert not panel.owned_workers()
    assert panel._operation is None if kind == "rules" else not panel._operations
    # Both global permits are still available; a failed start consumed none.
    assert community_tools._WORKERS.acquire(blocking=False)
    assert community_tools._WORKERS.acquire(blocking=False)
    community_tools._WORKERS.release()
    community_tools._WORKERS.release()
    monkeypatch.setattr(target, "threading", real_threading)
    assert start() is True
    wait_until(lambda: panel._operation is None if kind == "rules" else not panel._operations)
    retire(panel)


def test_rules_runtime_settings_shortcut_and_closed_result_fence(app):
    opened = []
    panel = RulesPlaybooksPanel(FakeLibrary(), open_settings=lambda: opened.append(True))
    panel.runtime_settings_button.click()
    assert opened == [True]
    panel.request_shutdown()
    before = panel.results.toPlainText()
    panel._entry = entry = {"kind": "fixture"}
    panel._deliver(entry, "result", "late untrusted result")
    assert panel.results.toPlainText() == before
    panel._entry = None
    retire(panel)
