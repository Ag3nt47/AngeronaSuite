"""Real authenticated alert preparation stays off Qt; paint batches stay on Qt."""
from dataclasses import FrozenInstanceError, replace
import threading
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt, QTimer
from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.gui import pages


class Storage:
    def __init__(self, events):
        self.events = list(events)
        self.number = 1

    def revision(self):
        return self.number

    def try_recent(self, limit):
        return self.events[:limit]


def signed_events(count):
    authority = BusAuthority(bytes(range(32)))
    bus = EventBus(ring_size=max(500, count))
    bus.arm(authority)
    for index in range(count):
        bus.publish(Event("Inert signed sensor", f"record {index}", Severity.HIGH,
                          ts=1000.0+index, details={"rule_id":f"rule-{index}",
                          "evidence":{"nested":[{"payload":"inert"*4096}]}}))
    return bus, bus.recent(count)


def wait_until(predicate, timeout=5):
    deadline = time.monotonic()+timeout
    while not predicate() and time.monotonic()<deadline:
        QApplication.processEvents()
        time.sleep(0.005)
    assert predicate()


def run_reader(panel):
    reader = panel._prepare_alert_snapshot()
    results, errors = [], []

    def read():
        try:
            results.append(reader())
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=read)
    worker.start()
    worker.join(5)
    assert not worker.is_alive() and not errors
    return results[0]


def dispose(panel):
    panel.close()
    worker = panel._events_reader.thread
    if worker is not None:
        worker.join(5)
        assert not worker.is_alive()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_real_signed_verification_and_formatting_do_not_block_qt(monkeypatch):
    bus, events = signed_events(3)
    panel = pages.AlertsPanel(Storage(events), bus=bus)
    gui = threading.get_ident()
    entered, release = threading.Event(), threading.Event()
    verify_threads, projection_threads, insert_threads = [], [], []
    verify, project, insert = bus.verify, pages._event_path_display, panel._insert_row

    def held_verify(event):
        verify_threads.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
        return verify(event)

    def project_row(event):
        projection_threads.append(threading.get_ident())
        return project(event)

    def insert_row(*args):
        insert_threads.append(threading.get_ident())
        return insert(*args)

    monkeypatch.setattr(bus, "verify", held_verify)
    monkeypatch.setattr(pages, "_event_path_display", project_row)
    monkeypatch.setattr(panel, "_insert_row", insert_row)
    try:
        panel.refresh()
        assert entered.wait(2)
        dispatched = []
        QTimer.singleShot(0, lambda: dispatched.append(threading.get_ident()))
        QApplication.processEvents()
        assert dispatched == [gui], "Qt must dispatch while the verifier is held"
        assert panel.table.rowCount() == 0
        release.set()
        wait_until(lambda: len(panel._rendered_event_ids)==3)
        assert len(verify_threads)==3 and all(t!=gui for t in verify_threads)
        assert projection_threads==verify_threads
        assert insert_threads and set(insert_threads)=={gui}
        assert all(identity.startswith("verified:") for identity in panel._rendered_event_ids)
        rows = panel._prepared_alert_rows
        assert isinstance(rows,tuple)
        with pytest.raises(FrozenInstanceError):
            rows[0].identity="forged"
        # Repainting a suppression change must reuse display evidence without
        # running bulk authentication on Qt. It grants no action authority.
        panel._refresh_alert_presentation(force=True)
        wait_until(lambda: panel._alert_render_job is None)
        assert len(verify_threads)==3
    finally:
        release.set()
        dispose(panel)


def test_bad_signature_and_duplicate_ordinals_are_not_promoted(monkeypatch):
    bus, (original,) = signed_events(1)
    altered = replace(original, details={"rule_id":"changed","payload":"inert tamper"})
    panel = pages.AlertsPanel(Storage([original,altered,original]), bus=bus)
    try:
        snapshot = run_reader(panel)
        panel._apply_loaded_events(*snapshot)
        wait_until(lambda: panel._alert_render_job is None)
        identities = panel._rendered_event_ids
        assert identities[0]==f"verified:{original.hmac_sig}:0"
        assert identities[1].startswith("record:")
        assert identities[2]==f"verified:{original.hmac_sig}:1"
        assert panel.table.rowCount()==3
        assert bus.verify(altered) is False
    finally:
        dispose(panel)


def test_paint_batches_yield_keep_latest_and_retire_on_close(monkeypatch):
    bus, events = signed_events(120)
    storage = Storage(events)
    panel = pages.AlertsPanel(storage, bus=bus)
    gui = threading.get_ident()
    inserted = []
    original_insert = panel._insert_row

    def insert(*args):
        inserted.append(threading.get_ident())
        return original_insert(*args)

    monkeypatch.setattr(panel,"_insert_row",insert)
    try:
        first = run_reader(panel)
        panel._apply_loaded_events(*first)
        panel._alert_render_timer.stop()
        generation = panel._alert_render_generation
        panel._advance_alert_render()
        panel._alert_render_timer.stop()
        assert 1<=len(inserted)<=8
        assert panel._alert_render_job is not None
        assert panel.table.updatesEnabled() and panel.table.isSortingEnabled()
        # A completed Qt turn can run between row batches.
        heartbeat=[]
        QTimer.singleShot(0,lambda:heartbeat.append(True))
        QApplication.processEvents()
        assert heartbeat==[True]
        storage.events=[events[-1],events[0]]
        storage.number=2
        panel._apply_loaded_events(*run_reader(panel))
        assert panel._alert_render_generation>generation
        wait_until(lambda:panel._alert_render_job is None)
        assert panel.table.rowCount()==2
        assert {panel.table.item(r,0).data(Qt.UserRole).message for r in range(2)}=={events[-1].message,events[0].message}
        assert panel._last_storage_revision==2
        assert set(inserted)=={gui}
        # Returning to the last completed identity set after a partial newer
        # job must reconcile actual rows rather than skip on the old cache.
        completed=tuple(panel._rendered_event_ids)
        storage.events=events
        storage.number=3
        panel._apply_loaded_events(*run_reader(panel))
        panel._alert_render_timer.stop()
        panel._advance_alert_render()
        panel._alert_render_timer.stop()
        storage.events=[events[-1],events[0]]
        storage.number=4
        panel._apply_loaded_events(*run_reader(panel))
        wait_until(lambda:panel._alert_render_job is None)
        assert panel._rendered_event_ids==completed and panel.table.rowCount()==2
        storage.events=events
        storage.number=5
        panel._apply_loaded_events(*run_reader(panel))
        assert panel._alert_render_job is not None
        panel.close()
        count=panel.table.rowCount()
        assert panel._alert_render_job is None and not panel._alert_render_timer.isActive()
        panel._advance_alert_render()
        QApplication.processEvents()
        assert panel.table.rowCount()==count
    finally:
        dispose(panel)


def test_close_during_authentication_discards_worker_completion(monkeypatch):
    bus, events = signed_events(1)
    panel = pages.AlertsPanel(Storage(events),bus=bus)
    entered,release=threading.Event(),threading.Event()
    original=bus.verify

    def held(event):
        entered.set()
        assert release.wait(5)
        return original(event)

    monkeypatch.setattr(bus,"verify",held)
    try:
        panel.refresh()
        assert entered.wait(2)
        panel.close()
        release.set()
        panel._events_reader.thread.join(5)
        assert not panel._events_reader.thread.is_alive()
        QApplication.processEvents()
        assert panel.table.rowCount()==0
        assert panel._alert_render_job is None and not panel._alert_render_timer.isActive()
    finally:
        release.set()
        dispose(panel)


def test_failed_paint_restores_qt_state_and_retries_authenticated_snapshot(monkeypatch):
    bus, events = signed_events(2)
    panel = pages.AlertsPanel(Storage(events), bus=bus)
    original = panel._insert_row

    def fail(*_args):
        raise RuntimeError("inert paint interruption")

    try:
        snapshot = run_reader(panel)
        monkeypatch.setattr(panel, "_insert_row", fail)
        panel._apply_loaded_events(*snapshot)
        panel._alert_render_timer.stop()
        panel._advance_alert_render()
        assert panel._alert_render_job is None
        assert panel.table.updatesEnabled() and panel.table.isSortingEnabled()
        assert panel._last_storage_revision == -1
        monkeypatch.setattr(panel, "_insert_row", original)
        panel.refresh()
        wait_until(lambda: len(panel._rendered_event_ids) == 2)
        assert all(identity.startswith("verified:") for identity in panel._rendered_event_ids)
    finally:
        dispose(panel)
