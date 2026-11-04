"""Result delivery and native/Python thread retirement remain separate."""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui.action_progress import ActionActivities
from angerona.gui.pages import ModuleInspector
from angerona.gui.shutdown_retirement import write_shutdown_diagnostic


def test_module_result_does_not_finish_activity_until_exact_worker_returns():
    app = QApplication.instance() or QApplication([])
    owner, release, labels = QWidget(), threading.Event(), []
    activities = ActionActivities(owner)
    handle = activities.begin("module-selftest", "Inert module test")
    generation = object()
    worker = threading.Thread(target=lambda: release.wait(3), daemon=True)
    worker.start()
    view = SimpleNamespace(_accept_async_results=True, _test_generation=generation,
        _test_worker=worker, _test_activity=handle, _test_activities=activities,
        _test_result_pending=None, test_lbl=SimpleNamespace(setText=labels.append),
        selftest_btn=SimpleNamespace(setEnabled=lambda _value: None))
    view._settle_test_activity = lambda: ModuleInspector._settle_test_activity(view)
    try:
        ModuleInspector._apply_test_result(view, generation, "PASS — inert completed result")
        assert activities.snapshot() and labels == [] and view._test_activity is handle
        ModuleInspector._apply_test_result(view, object(), "Stale FAIL must not replace new result")
        assert view._test_result_pending == "PASS — inert completed result"
        release.set()
        end = time.monotonic() + 3
        while worker.is_alive() and time.monotonic() < end:
            app.processEvents()
            time.sleep(.005)
        assert not worker.is_alive()
        view._settle_test_activity()
        assert activities.snapshot() == {} and labels == ["PASS — inert completed result"]
    finally:
        release.set()
        worker.join(3)  # Test cleanup outside any application GUI callback.
        assert not worker.is_alive()
        owner.close()


def test_shutdown_diagnostic_failure_keeps_previous_atomic_destination(tmp_path, monkeypatch):
    from angerona.gui import shutdown_retirement
    write_shutdown_diagnostic(tmp_path, {"schema": 1, "state": "stopping"})
    target = tmp_path / "diagnostics" / "operator-stop.json"
    original = target.read_bytes()
    def fail_replace(*_args):
        raise OSError("Inert atomic replacement failure")
    monkeypatch.setattr(shutdown_retirement.os, "replace", fail_replace)
    with pytest.raises(OSError):
        write_shutdown_diagnostic(tmp_path, {"schema": 1, "state": "forced-incomplete"})
    assert target.read_bytes() == original
    assert list(target.parent.glob(".operator-stop.*.tmp")) == []


def test_shutdown_diagnostic_refuses_multilink_destination(tmp_path):
    directory = tmp_path / "diagnostics"
    directory.mkdir()
    original = tmp_path / "retained-original.json"
    original.write_bytes(b"retained")
    os.link(original, directory / "operator-stop.json")
    with pytest.raises(ValueError, match="ordinary"):
        write_shutdown_diagnostic(tmp_path, {"schema": 1, "state": "stopping"})
    assert original.read_bytes() == b"retained"
