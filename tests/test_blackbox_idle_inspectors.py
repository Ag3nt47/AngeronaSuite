"""Heavy diagnostic readers sleep when their views are unattended."""
import threading
import time

import pytest

import blackbox_recorder as blackbox


def pump(app, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate()


@pytest.mark.parametrize("worker_type,result", [
    (blackbox.ThreadStateWorker, ([], "fixture")),
    (blackbox.MemoryProfilerWorker, ([], "fixture")),
    (blackbox.ConfigDriftWorker, {}),
])
def test_inspector_sleeps_until_selected_and_wakes_on_stop(monkeypatch, worker_type, result):
    worker = worker_type()
    collected = threading.Event()
    calls = []

    def collect():
        calls.append(threading.get_ident())
        collected.set()
        return result

    monkeypatch.setattr(worker, "_collect", collect)
    monkeypatch.setattr(worker, "_poll_seconds", lambda: 60)
    worker.start()
    try:
        assert not collected.wait(0.1)
        worker.set_active(True)
        assert collected.wait(2)
        worker.set_active(False)
        time.sleep(0.1)
        assert len(calls) == 1
        assert calls[0] != threading.get_ident()
        collected.clear()
        worker.set_active(True)
        assert collected.wait(2)  # resume bypasses the 60-second interval
    finally:
        worker.stop()
        assert worker.wait(2000)


def test_hiding_during_native_read_does_not_block_or_start_another_read(monkeypatch):
    worker = blackbox.MemoryProfilerWorker()
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def collect():
        calls.append(1)
        entered.set()
        assert release.wait(3)
        completed.set()
        return [], "fixture"

    monkeypatch.setattr(worker, "_collect", collect)
    monkeypatch.setattr(worker, "_poll_seconds", lambda: 0.02)
    worker.set_active(True)
    worker.start()
    try:
        assert entered.wait(2)
        worker.set_active(False)
        assert not completed.is_set()  # the caller returned with the read in flight
        release.set()
        assert completed.wait(2)
        time.sleep(0.1)
        assert calls == [1]
    finally:
        release.set()
        worker.stop()
        assert worker.wait(2000)


def test_stop_between_loop_check_and_wake_clear_cannot_lose_wakeup(monkeypatch):
    worker = blackbox.MemoryProfilerWorker()
    original_clear = worker._wake.clear

    def stop_before_clear():
        worker.stop()
        original_clear()

    monkeypatch.setattr(worker._wake, "clear", stop_before_clear)
    worker.start()
    try:
        assert worker.wait(2000)
    finally:
        # Release the old implementation's lost-wakeup wait before teardown.
        worker.stop()
        assert worker.wait(2000)


def test_window_activates_only_selected_visible_inspector(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    # Keep real inspector QThreads/signals, replacing only their native inputs.
    monkeypatch.setattr(blackbox.LogTailWorker, "run", lambda self: None)
    monkeypatch.setattr(blackbox.HostTelemetryWorker, "run", lambda self: None)
    monkeypatch.setattr(blackbox.SuiteHealthWorker, "run", lambda self: None)
    monkeypatch.setattr(blackbox.SoarEventsTab, "_read_records", staticmethod(lambda: []))
    counts = {"threads": 0, "memory": 0, "config": 0}

    def reader(key, result):
        def collect(self):
            counts[key] += 1
            return result
        return collect

    for worker_type, key, result in [
        (blackbox.ThreadStateWorker, "threads", ([], "fixture")),
        (blackbox.MemoryProfilerWorker, "memory", ([], "fixture")),
        (blackbox.ConfigDriftWorker, "config", {"files": [], "pid": 1}),
    ]:
        monkeypatch.setattr(worker_type, "_collect", reader(key, result))
        monkeypatch.setattr(worker_type, "_poll_seconds", lambda self: 0.03)

    window = blackbox.BlackBoxWindow()
    try:
        time.sleep(0.1)
        assert counts == {"threads": 0, "memory": 0, "config": 0}
        window.show()
        app.processEvents()
        time.sleep(0.1)
        assert not any(counts.values())  # log tab is selected
        window.tabs.setCurrentWidget(window.tab_mem)
        pump(app, lambda: counts["memory"] >= 2)
        assert not counts["threads"] and not counts["config"]
        window.showMinimized()
        app.processEvents()
        time.sleep(0.1)  # allow the in-flight collection to finish
        paused = counts.copy()
        time.sleep(0.1)
        assert counts == paused
        window.showNormal()
        pump(app, lambda: counts["memory"] > paused["memory"])
        window.tabs.setCurrentWidget(window.tab_config)
        pump(app, lambda: counts["config"] >= 2)
        window.hide()
        app.processEvents()
        time.sleep(0.1)
        paused = counts.copy()
        time.sleep(0.1)
        assert counts == paused
    finally:
        window.stop_workers()
        window.tab_soar._reader.close()
        window.close()
        window.deleteLater()
        app.processEvents()


def test_exported_inspector_snapshots_identify_last_capture():
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    thread, memory, config = blackbox.ThreadTab(), blackbox.MemoryTab(), blackbox.ConfigTab()
    try:
        thread.on_threads([{"name": "fixture", "id": "1", "where": "idle", "state": "running"}], "fixture")
        memory.on_rows([{"label": "fixture", "size": 10, "count": 1}], "fixture")
        config.on_drift({"files": [], "sockets": [], "handles": []})
        for view in (thread, memory, config):
            assert view.snapshot_text().startswith("Last captured ")
            assert "updates while tab is visible" in view.snapshot_text()
    finally:
        for view in (thread, memory, config):
            view.close()
        app.processEvents()
