import gc
import json
import threading
import time
import weakref
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtGui import QKeyEvent
from shiboken6 import isValid

import blackbox_recorder as blackbox


def pump_until(app, predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate()


def test_log_burst_drains_bounded_chunks_without_losing_source(tmp_path):
    path = tmp_path / "burst.log"
    original = b"a" * (blackbox.MAX_LOG_READ_BYTES * 3 + 17)
    path.write_bytes(original)
    offset, chunks = 0, []
    while offset < len(original):
        chunk, following = blackbox.safe_tail_bytes(path, offset)
        assert 0 < len(chunk) <= blackbox.MAX_LOG_READ_BYTES
        assert following == offset + len(chunk)
        chunks.append(chunk)
        offset = following
    assert b"".join(chunks) == original == path.read_bytes()
    path.write_bytes(b"rotated")
    assert blackbox.safe_tail_bytes(path, offset) == (b"rotated", 7)


def test_process_discovery_does_not_query_unrelated_process_evidence(monkeypatch):
    class Unrelated:
        info = {"pid": 501, "name": "browser.exe"}
        def cmdline(self):
            raise AssertionError("unrelated command line queried")
        def memory_info(self):
            raise AssertionError("unrelated memory queried")
    core = SimpleNamespace(info={"pid": 502, "name": "python.exe"},
                           cmdline=lambda: ["python.exe", "-m", "angerona"],
                           memory_info=lambda: SimpleNamespace(rss=100), ppid=lambda: 1)
    attrs_seen = []
    monkeypatch.setattr(blackbox.psutil, "process_iter",
                        lambda attrs: attrs_seen.append(attrs) or [Unrelated(), core])
    assert blackbox.find_angerona_pid() == 502
    assert attrs_seen == [["pid", "name"]]


def test_log_chunks_preserve_utf8_and_split_critical_markers(monkeypatch, tmp_path):
    monkeypatch.setattr(blackbox, "MAX_LOG_READ_BYTES", 8)
    path = tmp_path / "burst.log"
    path.write_bytes("aaaaaCRITICAL ☃\n".encode())
    blocks, critical = [], []
    worker = blackbox.LogTailWorker()
    worker.block.connect(lambda text, severity, hints: blocks.append((text, severity)))
    worker.exception_at.connect(critical.append)
    for _ in range(4):
        worker._consume_tail(path, "test")
    rendered = "".join(text.partition("\n")[2] for text, _ in blocks)
    assert rendered == "aaaaaCRITICAL ☃"
    assert "\ufffd" not in rendered
    assert critical and any(severity == "critical" for _, severity in blocks)
    path.write_bytes(b"fine\n")
    worker._consume_tail(path, "test")
    assert blocks[-1][1] == "info"


def test_log_decoders_are_independent_per_file(monkeypatch, tmp_path):
    monkeypatch.setattr(blackbox, "MAX_LOG_READ_BYTES", 2)
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes("☃".encode())
    second.write_bytes(b"OK")
    worker = blackbox.LogTailWorker()
    blocks = []
    worker.block.connect(lambda text, severity, hints: blocks.append(text.partition("\n")[2]))
    worker._consume_tail(first, "first")
    worker._consume_tail(second, "second")
    worker._consume_tail(first, "first")
    assert blocks == ["OK", "☃"]


def test_firewall_refresh_keeps_qt_alive_and_coalesces_clicks(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    entered, release = threading.Event(), threading.Event()
    calls, beats = [], []

    def read():
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
        return [{"name": "same", "rule_id": "one", "direction": "Inbound",
                 "action": "Block", "proto": "", "port": ""}]

    monkeypatch.setattr(blackbox.FirewallTab, "_read_rules", staticmethod(read))
    tab = blackbox.FirewallTab()
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: beats.append(1))
    timer.start()
    try:
        tab.refresh()
        assert entered.wait(2)
        for _ in range(10):
            tab.refresh()
        pump_until(app, lambda: len(beats) >= 3)
        assert calls == [tab._reader.thread.ident]
        assert calls[0] != threading.get_ident()
        release.set()
        pump_until(app, lambda: not tab._reader.busy)
        assert tab.table.item(0, 0).data(Qt.UserRole)["rule_id"] == "one"
    finally:
        release.set()
        timer.stop()
        tab._reader.close()
        tab.close()


@pytest.mark.parametrize("completion, expected", [
    ("title_close", 0), ("close_button", 1), ("reject", 0),
    ("escape", 0), ("custom_done", 23),
])
def test_firewall_detail_completion_keeps_owner_until_native_exit(
        monkeypatch, completion, expected):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    entered, release = threading.Event(), threading.Event()
    completed, close_elapsed, beats, guard_fired = [], [], [], []

    class HeldDetailWorker(blackbox._FwDetailWorker):
        def run(self):
            entered.set()
            release.wait(5)
            self.done.emit({"description": "inert held detail"})

    monkeypatch.setattr(blackbox, "_FwDetailWorker", HeldDetailWorker)
    parent = blackbox.QWidget()
    dialog = blackbox.FirewallRuleDetailDialog({"rule_id": "inert-rule"}, parent)
    dialog.setAttribute(Qt.WA_DeleteOnClose)
    dialog.finished.connect(completed.append)
    worker = dialog._worker
    dialog_ref = weakref.ref(dialog)
    modal_guard = QTimer()
    modal_guard.setSingleShot(True)
    def guard_modal():
        guard_fired.append(True)
        current = dialog_ref()
        if current is not None and isValid(current):
            current.hide()
    modal_guard.timeout.connect(guard_modal)
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: beats.append(1))
    timer.start()

    def request_completion():
        current = dialog_ref()
        assert current is not None and isValid(current)
        started = time.monotonic()
        if completion == "title_close":
            current.close()
        elif completion == "close_button":
            next(button for button in current.findChildren(blackbox.QPushButton)
                 if button.text() == "Close").click()
        elif completion == "reject":
            current.reject()
        elif completion == "escape":
            QCoreApplication.sendEvent(
                current, QKeyEvent(QEvent.KeyPress, Qt.Key_Escape, Qt.NoModifier))
        else:
            current.done(23)
        close_elapsed.append(time.monotonic() - started)

    try:
        assert entered.wait(2)
        # Exercise exec()'s cached delete-on-close flag, not just QWidget.close().
        modal_guard.start(2000)
        QTimer.singleShot(0, request_completion)
        observed_result = dialog.exec()
        modal_guard.stop()
        assert not guard_fired and observed_result == expected
        assert close_elapsed and close_elapsed[0] < 0.5
        assert worker.isRunning() and not release.is_set()
        assert isValid(dialog) and not dialog.isVisible()
        assert dialog.parent() is None
        assert completed == []
        dialog.reject()  # A late second request must preserve the first result.
        assert dialog.result() == expected

        parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert not isValid(parent) and isValid(dialog)
        owner = weakref.ref(dialog)
        del dialog
        gc.collect()
        assert owner() is not None and isValid(owner())
        pump_until(app, lambda: len(beats) >= 3)
        assert worker.isRunning() and completed == []

        release.set()
        pump_until(app, lambda: not worker.isRunning())
        pump_until(app, lambda: completed == [expected])
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert owner() is None or not isValid(owner())
    finally:
        release.set()
        timer.stop()
        modal_guard.stop()
        assert worker.wait(2000)
        worker.deleteLater()
        if isValid(parent):
            parent.deleteLater()
        remaining = locals().get("dialog")
        if remaining is None and "owner" in locals():
            remaining = owner()
        if remaining is not None and isValid(remaining):
            remaining.close()
            remaining.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_firewall_detail_completed_query_preserves_result_display(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    program = "C:/inert/detail.exe"

    class ReadyDetailWorker(blackbox._FwDetailWorker):
        def run(self):
            self.done.emit({"description": "inert description", "program": program})

    monkeypatch.setattr(blackbox, "_FwDetailWorker", ReadyDetailWorker)
    dialog = blackbox.FirewallRuleDetailDialog({"rule_id": "inert-rule"})
    worker = dialog._worker
    completed = []
    dialog.finished.connect(completed.append)
    dialog.show()
    try:
        pump_until(app, lambda: not worker.isRunning() and dialog.btn_copy.isEnabled())
        assert dialog._program == program and dialog.btn_open.isEnabled()
        assert "inert description" in [label.text() for label in dialog.findChildren(blackbox.QLabel)]
        assert dialog._loading.isHidden() and dialog._prog_box.isVisible()
        dialog.accept()
        assert completed == [1] and dialog.result() == 1
    finally:
        assert worker.wait(2000)
        dialog.close()
        dialog.deleteLater()
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


@pytest.fixture
def firewall_detail_case(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    state = SimpleNamespace(
        app=app, entered=threading.Event(), release=threading.Event(),
        workers=[], dialogs=[], beats=[], close_ready_only=False, guard_fired=False,
    )

    class InertDetailWorker(blackbox._FwDetailWorker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            state.workers.append(self)

        def run(self):
            state.entered.set()
            state.release.wait(5)
            self.done.emit({"description": "inert detail", "program": "C:/inert/detail.exe"})

    class ShutdownOwner(blackbox.QMainWindow):
        stop_workers = blackbox.BlackBoxWindow.stop_workers

    inert_rules = [
        {"name": identity, "rule_id": identity, "direction": "Inbound",
         "action": "Block", "proto": "", "port": ""}
        for identity in ("one", "two")
    ]
    monkeypatch.setattr(blackbox.FirewallTab, "_read_rules",
                        staticmethod(lambda: [dict(rule) for rule in inert_rules]))
    monkeypatch.setattr(blackbox, "_FwDetailWorker", InertDetailWorker)
    state.window = ShutdownOwner()
    state.window._closing = False
    state.window._shutdown_threads = None
    state.tab = blackbox.FirewallTab()
    state.window.setCentralWidget(state.tab)
    state.tab._apply_rules(inert_rules)
    state.tab.table.sortItems(0, Qt.AscendingOrder)
    tab_ref = weakref.ref(state.tab)

    def dismiss_visible():
        state.beats.append(1)
        tab = tab_ref()
        if tab is None or not isValid(tab):
            return
        for dialog in tab.findChildren(blackbox.FirewallRuleDetailDialog):
            if not dialog.isVisible():
                continue
            if state.close_ready_only and (dialog._worker.isRunning() or
                                          not dialog.btn_copy.isEnabled()):
                continue
            state.dialogs.append(weakref.ref(dialog))
            dialog.reject()

    def retired():
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        return bool(state.dialogs) and all(
            ref() is None or not isValid(ref()) for ref in state.dialogs)

    def interrupt_modal():
        state.guard_fired = True
        tab = tab_ref()
        if tab is not None and isValid(tab):
            for dialog in tab.findChildren(blackbox.FirewallRuleDetailDialog):
                dialog.hide()

    state.guard = QTimer()
    state.guard.setInterval(2000)
    state.guard.timeout.connect(interrupt_modal)
    state.guard.start()
    state.timer = QTimer()
    state.timer.setInterval(5)
    state.timer.timeout.connect(dismiss_visible)
    state.retired = retired
    try:
        yield state
    finally:
        state.timer.stop()
        state.guard.stop()
        state.release.set()
        for worker in state.workers:
            assert worker.wait(2000)
        for ref in state.dialogs:
            dialog = ref()
            if dialog is not None and isValid(dialog):
                dialog.close()
        if isValid(state.tab):
            state.tab._reader.close()
        state.window.deleteLater()
        for worker in state.workers:
            worker.deleteLater()
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_firewall_detail_clicks_share_admission_until_retirement(firewall_detail_case):
    case = firewall_detail_case
    tab, reader = case.tab, case.tab._reader
    previous_status = tab.status.text()
    visible_requests = []

    def repeat_visible():
        case.timer.start()
        current = getattr(tab, "_detail_dialog", None)
        visible_requests.append(current is not None and current.isVisible())
        tab._on_rule_clicked(1, 0)

    # A request while the first dialog is visible must focus it, not recurse.
    QTimer.singleShot(0, repeat_visible)
    tab._on_rule_clicked(0, 0)
    assert not case.guard_fired and visible_requests == [True] and case.entered.wait(2)
    assert len(case.workers) == 1
    worker, dialog = case.workers[0], tab._detail_dialog
    assert worker.isRunning() and not case.release.is_set()
    assert isValid(dialog) and dialog.parent() is None and not dialog.isVisible()
    assert tab._worker is worker
    for _ in range(10):
        tab._on_rule_clicked(1, 0)
    assert len(case.workers) == 1 and tab.status.text() != previous_status
    beats = len(case.beats)
    pump_until(case.app, lambda: len(case.beats) >= beats + 3)
    assert worker.isRunning() and tab._reader is reader

    case.release.set()
    pump_until(case.app, case.retired)
    assert not isValid(dialog) and tab._detail_dialog is None and tab._worker is None
    tab._on_rule_clicked(1, 0)
    assert not case.guard_fired
    pump_until(case.app, case.retired)
    assert [worker._rule_id for worker in case.workers] == ["one", "two"]
    assert tab._detail_dialog is None and tab._worker is None and tab._reader is reader


def test_firewall_detail_detached_worker_remains_in_blackbox_shutdown(firewall_detail_case):
    case = firewall_detail_case
    case.timer.start()
    case.tab._on_rule_clicked(0, 0)
    assert not case.guard_fired and case.entered.wait(2)
    worker, dialog = case.workers[0], case.tab._detail_dialog
    assert dialog.parent() is None and worker.isRunning()
    assert dialog not in case.window.findChildren(blackbox.QWidget)
    assert not case.window.stop_workers(timeout_ms=0)
    assert worker in case.window._shutdown_threads

    # Parent destruction must not invalidate the detached draining owner, and
    # its eventual destroyed callback must tolerate the deleted tab wrapper.
    case.tab.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(case.tab) and isValid(dialog) and worker.isRunning()
    case.release.set()
    pump_until(case.app, case.retired)
    assert not isValid(dialog) and not worker.isRunning()
    assert case.window.stop_workers(timeout_ms=0)
    assert worker in case.window._shutdown_threads


def test_firewall_detail_completed_query_deletes_parent_owned_dialog(firewall_detail_case):
    case = firewall_detail_case
    case.release.set()
    case.close_ready_only = True
    case.timer.start()
    case.tab._on_rule_clicked(0, 0)
    assert not case.guard_fired
    pump_until(case.app, case.retired)
    assert len(case.workers) == 1 and not case.workers[0].isRunning()
    assert case.dialogs and case.tab.findChildren(blackbox.FirewallRuleDetailDialog) == []
    assert case.tab._detail_dialog is None and case.tab._worker is None


def test_firewall_failure_preserves_prior_snapshot(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    def failed():
        raise OSError("unavailable")
    monkeypatch.setattr(blackbox.FirewallTab, "_read_rules", staticmethod(failed))
    tab = blackbox.FirewallTab()
    tab._apply_rules([{"name": "retained", "rule_id": "one", "direction": "In",
                       "action": "Block", "proto": "", "port": ""}])
    try:
        tab.refresh()
        pump_until(app, lambda: not tab._reader.busy)
        assert tab.table.item(0, 0).text() == "retained"
        assert "previous snapshot retained" in tab.status.text()
    finally:
        tab._reader.close()
        tab.close()


def test_firewall_owner_deletion_during_read_is_safe(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    entered, release = threading.Event(), threading.Event()
    def read():
        entered.set()
        assert release.wait(5)
        return []
    monkeypatch.setattr(blackbox.FirewallTab, "_read_rules", staticmethod(read))
    tab = blackbox.FirewallTab()
    tab.refresh()
    assert entered.wait(2)
    reader = tab._reader
    try:
        tab.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert reader._closed
        release.set()
        reader.thread.join(2)
        assert not reader.thread.is_alive()
        app.processEvents()
    finally:
        release.set()


def test_firewall_accepts_string_enums_without_fallback(monkeypatch):
    calls = []
    def output(command, **kwargs):
        calls.append(command)
        return json.dumps([{"DisplayName": "rule", "Name": "id", "Direction": "Inbound",
                            "Action": "Block", "Enabled": "True"}])
    monkeypatch.setattr(blackbox, "_read_firewall_command", output)
    assert blackbox.FirewallTab._read_rules()[0]["direction"] == "Inbound"
    assert len(calls) == 1


def test_firewall_duplicate_names_keep_exact_identity_when_sorted(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    tab = blackbox.FirewallTab()
    shown = []
    class DetailDialog(blackbox.QDialog):
        def __init__(self, rule, parent):
            super().__init__(parent)
            self._worker = None
            self._rule_id = rule["rule_id"]

        def exec(self):
            shown.append(self._rule_id)
            self.deleteLater()
            return 0

    monkeypatch.setattr(blackbox, "FirewallRuleDetailDialog", DetailDialog)
    try:
        tab._apply_rules([{"name": "same", "rule_id": identity, "direction": "In",
                           "action": action, "proto": "", "port": ""}
                          for identity, action in [("first", "Block"), ("second", "Allow")]])
        tab.table.sortItems(2, Qt.AscendingOrder)
        tab._on_rule_clicked(0, 0)
        assert shown == ["second"]
    finally:
        tab._reader.close()
        tab.close()
        app.processEvents()


def test_soar_bounded_tail_tolerates_bad_records_and_preserves_distinct_messages(monkeypatch, tmp_path):
    monkeypatch.setattr(blackbox, "DATA_DIR", tmp_path)
    path = tmp_path / "shared_logs" / "soar_queue.json"
    path.parent.mkdir()
    rows = [{"ts": n + 1, "message": "x" * 70 + str(n), "origin_module": "m", "severity": "HIGH"}
            for n in range(220)]
    path.write_text("x" * (1024 * 1024 + 1) + "\n[]\nnull\n" +
                    "\n".join(json.dumps(row) for row in rows) + '\n{"ts":1e300}\n', encoding="utf-8")
    results = blackbox.SoarEventsTab._read_records()
    assert len(results) == 200
    assert results[0]["ts"] == 220 and results[-1]["ts"] == 21


def test_health_cpu_reuses_sample_only_for_same_process_identity(monkeypatch):
    created, samples = [], []
    birth = [123.0]
    def process(pid):
        index = len(created)
        instance = SimpleNamespace(
            oneshot=nullcontext, status=lambda: blackbox.psutil.STATUS_RUNNING,
            memory_info=lambda: SimpleNamespace(rss=10), create_time=lambda: birth[0],
            cpu_percent=lambda interval: samples.append(index) or float(samples.count(index) - 1),
        )
        created.append(instance)
        return instance
    monkeypatch.setattr(blackbox.psutil, "Process", process)
    monkeypatch.setattr(blackbox, "find_angerona_pid", lambda: 100)
    worker = blackbox.SuiteHealthWorker()
    monkeypatch.setattr(worker, "_read_status", lambda: {})
    assert worker._collect()["cpu"] == 0
    assert worker._collect()["cpu"] == 1
    birth[0] += 1
    assert worker._collect()["cpu"] == 0
    assert samples == [0, 0, 2]
