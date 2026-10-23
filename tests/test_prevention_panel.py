import threading
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from angerona.gui.prevention_panel import PreventionPanel


def drain(panel, timeout=3):
    deadline = time.monotonic() + timeout
    while panel._job is not None and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.002)
    assert panel._job is None


def test_panel_constructor_and_paint_never_inspect_or_provision_authority():
    calls = []
    panel = PreventionPanel(inspector=lambda: calls.append(True))
    panel.show()
    QApplication.instance().processEvents()
    assert not calls
    assert not panel.apply_button.isEnabled() and not panel.restore_button.isEnabled()
    assert "Deployment held" in panel.authority.text()
    for index in range(panel.catalog.count()):
        panel.catalog.setCurrentIndex(index)
    assert not calls
    panel.close()


def test_native_inspection_worker_is_single_bounded_and_qt_remains_responsive():
    entered, release = threading.Event(), threading.Event()
    threads = []
    main = threading.get_ident()

    def inspect():
        threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        return dict(state="partial", bits=0, event_collection="unknown")

    panel = PreventionPanel(inspector=inspect)
    panel.show()
    panel._refresh()
    assert entered.wait(1)
    for _ in range(5):
        panel._refresh()
    heartbeat = []
    QTimer.singleShot(0, lambda: heartbeat.append(True))
    QApplication.instance().processEvents()
    assert heartbeat and threads == [threads[0]] and threads[0] != main
    release.set()
    drain(panel)
    assert '"event_collection": "unknown"' in panel.details.toPlainText()
    panel.close()


def test_stage_default_is_preview_only_and_hiding_drops_plan():
    panel = PreventionPanel(inspector=lambda: dict(state="partial", bits=1))
    panel.show()
    panel._prepare()
    drain(panel)
    assert panel._plan.expected_bits == 1 and panel._plan.target_bits == 3
    assert panel.copy_button.isEnabled() and not panel.apply_button.isEnabled()
    panel.hide()
    assert panel._plan is None
    panel.show()
    assert not panel.apply_button.isEnabled()
    panel.close()


def test_close_cancels_waiting_installed_adapter_before_any_dispatch():
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    writes = []

    class Client:
        def prepare_logon(self, *, cancel):
            return None

        def apply_plan(self, plan, *, cancel):
            entered.set()
            assert release.wait(3)
            try:
                if not cancel.is_set():
                    writes.append(plan)
            finally:
                finished.set()
            return dict(state="cancelled")

    from angerona.core.windows_prevention import prepare_logon_plan
    panel = PreventionPanel(client=Client())
    panel.show()
    panel._plan = prepare_logon_plan(0)
    panel._apply()
    job = panel._job
    assert entered.wait(1)
    started = time.monotonic()
    panel.close()
    assert time.monotonic() - started < .1 and job.cancel.is_set()
    release.set()
    assert finished.wait(1) and job.done.wait(1)
    assert not writes


def test_malformed_backend_plan_cannot_enable_apply():
    class Client:
        def prepare_logon(self, *, cancel):
            return dict(plan={"plan_id": "untrusted"})

    panel = PreventionPanel(client=Client())
    panel.show()
    panel._prepare()
    drain(panel)
    assert panel._plan is None and not panel.apply_button.isEnabled()
    assert "Malformed" in panel.status.text()
    panel.close()


def test_oversized_result_is_rejected_on_worker_before_qt_render():
    panel = PreventionPanel(inspector=lambda: dict(reason="x" * 100000))
    panel.show()
    panel._refresh()
    drain(panel)
    assert panel._plan is None and not panel.apply_button.isEnabled()
    assert "Malformed or oversized" in panel.status.text()
    assert len(panel.details.toPlainText()) < 2000
    panel.close()
