import json
import threading
import time
from contextlib import nullcontext
from types import SimpleNamespace

from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt

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
    monkeypatch.setattr(blackbox, "FirewallRuleDetailDialog",
                        lambda rule, parent: SimpleNamespace(exec=lambda: shown.append(rule["rule_id"])))
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
