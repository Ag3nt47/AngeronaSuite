"""Fresh executable authorization hashes must never run on the threat dialog's Qt thread."""
import threading
import time
from types import SimpleNamespace

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import Event, Severity
from angerona.gui import pages


def test_slow_threat_authorization_keeps_dialog_and_heartbeat_responsive(monkeypatch):
    app = QApplication.instance()
    entered, release = threading.Event(), threading.Event()
    readers = []

    def blocked(events):
        readers.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
        return events

    event = Event("Fixture detector", "Inert finding", Severity.HIGH)
    monkeypatch.setattr(pages, "active_threat_events", blocked)
    dialog = pages.ThreatWindow(SimpleNamespace(recent=lambda _: [event]), object(),
                                SimpleNamespace(modules={}))
    try:
        assert entered.wait(2)
        assert readers == [dialog._threat_reader.thread.ident]
        assert readers[0] != threading.get_ident()
        ticks = []
        timer = QTimer(dialog)
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(10)
        # A first native Qt dispatch can consume a scheduler slice under load.
        # Observe repeated heartbeats while the reader is still held, rather
        # than assuming that one 200-ms interval contains multiple dispatches.
        deadline = time.monotonic() + 2
        while len(ticks) < 3 and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.002)
        assert len(ticks) >= 3
        assert not release.is_set()
        assert dialog._threat_reader.thread.is_alive()
        assert dialog.table.rowCount() == 0
        assert "Reviewing" in dialog.status_lbl.text()
        release.set()
        deadline = time.monotonic() + 3
        while dialog.table.rowCount() == 0 and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.01)
        assert dialog.table.rowCount() == 1
        dialog.table.selectRow(0)
        assert dialog._selected_event() is event
        assert len(readers) == 1  # Selection uses the completed immutable view.
    finally:
        release.set()
        dialog.close()
        dialog.deleteLater()
        app.processEvents()
