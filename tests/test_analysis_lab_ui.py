import threading
import time

from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication

from angerona.gui import analysis_lab as ui


def wait(predicate):
    deadline=time.monotonic()+5
    while not predicate() and time.monotonic()<deadline:
        QApplication.instance().processEvents()
        time.sleep(.01)
    assert predicate()


def panel(tmp_path, monkeypatch):
    monkeypatch.setattr(ui.jobs,'readiness',lambda _root:(False,'Start VMware Authorization Service.'))
    widget=ui.AnalysisLabPanel(root=tmp_path)
    widget.show()
    wait(lambda:not widget._busy)
    return widget


def test_missing_service_is_actionable_and_signal_cannot_bypass_gate(tmp_path,monkeypatch):
    widget=panel(tmp_path,monkeypatch)
    try:
        assert 'Authorization Service' in widget.status.text()
        assert not widget.run_button.isEnabled()
        widget.input_path.setText(str(tmp_path))
        widget.run_button.clicked.emit()
        assert not widget._busy
        assert 'Check readiness' in widget.status.text()
    finally:widget.close()


def test_readiness_check_enables_only_selected_input(tmp_path,monkeypatch):
    widget=panel(tmp_path,monkeypatch)
    monkeypatch.setattr(ui.jobs,'check_runtime',lambda *_args:(True,'Verified'))
    try:
        widget.check_button.click()
        wait(lambda:not widget._busy)
        assert not widget.run_button.isEnabled()
        widget.input_path.setText(str(tmp_path))
        assert widget.run_button.isEnabled()
    finally:widget.close()


def test_cancellation_keeps_ui_responsive_and_discards_late_success(tmp_path,monkeypatch):
    widget=panel(tmp_path,monkeypatch)
    release=threading.Event()
    ticks=[]
    try:
        widget._start('check',lambda *_args:(release.wait(3),(True,'late'))[1],'Working')
        QTimer.singleShot(0,lambda:ticks.append(True))
        QApplication.instance().processEvents()
        assert ticks
        widget.cancel_button.click()
        release.set()
        wait(lambda:not widget._busy)
        assert not widget._ready
        assert 'cancelled' in widget.status.text()
    finally:
        release.set()
        widget.close()


def test_destroying_lab_cancels_without_worker_qt_callbacks(tmp_path,monkeypatch):
    widget=panel(tmp_path,monkeypatch)
    release=threading.Event()
    widget._start('check',lambda *_args:(release.wait(3),(True,'late'))[1],'Working')
    operation=widget._operation
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete)
    assert operation.cancelled.is_set()
    release.set()


def test_skipping_setup_refreshes_visible_readiness_and_restores_run(tmp_path, monkeypatch):
    from angerona.gui import analysis_qemu_setup as setup_ui

    skipped = threading.Event()
    release = threading.Event()

    class SkipDialog:
        def __init__(self, *_args, **_kwargs):
            pass

        def exec(self):
            skipped.set()
            return 0  # The operator chose Skip, without any native setup.

        def deleteLater(self):
            pass

    def readiness(_root):
        if skipped.is_set():
            assert release.wait(3)
            return True, 'Ready after skipped setup'
        return True, 'Initially ready'

    monkeypatch.setattr(setup_ui, 'QEMUSetupDialog', SkipDialog)
    monkeypatch.setattr(ui.jobs, 'readiness', readiness)
    monkeypatch.setattr(ui.jobs, 'history', lambda _root: [])
    widget = ui.AnalysisLabPanel(root=tmp_path)
    try:
        widget.input_path.setText(str(tmp_path))
        widget.show()
        wait(lambda: widget.status.text() == 'Initially ready')
        assert widget.run_button.isEnabled()

        widget.setup_button.click()
        assert widget.status.text() == 'Checking Analysis Lab…'
        assert not widget.run_button.isEnabled()
        ticks = []
        QTimer.singleShot(0, lambda: ticks.append(True))
        QApplication.instance().processEvents()
        assert ticks  # The refresh stays in the background while the panel remains visible.

        release.set()
        wait(lambda: widget.status.text() == 'Ready after skipped setup')
        assert widget.run_button.isEnabled()
        assert widget.setup_button.isEnabled()
        assert not widget.cancel_button.isEnabled()
    finally:
        release.set()
        widget.close()
        widget.deleteLater()
