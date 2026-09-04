"""Offline regressions for the September dashboard stalls and sensor failures."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from angerona.core import capability_assurance as assurance
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.gui.pages import AlertsPanel, _module_assurance
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.av_telemetry_bridge import AVTelemetryBridgeModule
from angerona.modules.sysmon_listener import SysmonListenerModule
from angerona.modules import sysmon_listener
from angerona.modules import storage_hygiene


def test_slow_source_verification_never_blocks_gui_or_spawns_duplicate_workers(monkeypatch):
    cache = assurance._DisplayAnchorCache()
    entered, release = threading.Event(), threading.Event()
    calls = []
    anchor = assurance.SourceAnchor(source_provenance="test-snapshot")

    def slow_reader(module):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
        return anchor

    monkeypatch.setattr(assurance, "_DISPLAY_ANCHORS", cache)
    monkeypatch.setattr(assurance, "_read_declaration_anchor", slow_reader)
    module = SimpleNamespace(name="test", status="stopped")
    manager = SimpleNamespace(platform="windows", is_enabled=lambda _name: True)
    try:
        _module_assurance(manager, module, {"status": "stopped"})
        assert entered.wait(2)
        worker = cache._worker
        for _ in range(100):
            assert cache.get(module).source_provenance == "source-verification-pending"
            _module_assurance(manager, module, {"status": "stopped"})
        assert cache._worker is worker
        assert len(cache._pending) == 1
        assert calls == [worker.ident]
        assert worker.ident != threading.get_ident()
    finally:
        release.set()
        if cache._worker is not None:
            cache._worker.join(5)
    assert cache.get(module) is anchor


def test_expired_display_anchor_is_unavailable_until_verified_again(monkeypatch):
    cache = assurance._DisplayAnchorCache()
    module = object()
    now = [0.0]
    release = threading.Event()
    entered = threading.Event()
    monkeypatch.setattr(assurance, "time", SimpleNamespace(monotonic=lambda: now[0]))
    old = assurance.SourceAnchor(source_state="available", source_sha256="a" * 64)
    cache.remember(module, old)
    assert cache.get(module) is old

    def unavailable(_module):
        entered.set()
        assert release.wait(5)
        return assurance.SourceAnchor(source_provenance="source-read-failed")

    monkeypatch.setattr(assurance, "_read_declaration_anchor", unavailable)
    now[0] = 31.0
    try:
        assert cache.get(module).source_state == "unavailable"
        assert entered.wait(2)
        worker = cache._worker
    finally:
        release.set()
        if cache._worker is not None:
            cache._worker.join(5)
    assert not worker.is_alive()
    assert cache.get(module).source_provenance == "source-read-failed"


def test_alert_burst_retains_unchanged_items_and_caps_before_rendering(monkeypatch):
    app = QApplication.instance()
    panel = AlertsPanel(SimpleNamespace(revision=lambda: 0, try_recent=lambda _limit: []))
    original = [Event("test", str(i), Severity.INFO, ts=float(i)) for i in range(200, 80, -1)]
    try:
        panel._rebuild_event_rows(original)
        retained = panel.table.item(0, 0)
        calls = []
        insert = panel._insert_row

        def count_insert(*args):
            calls.append(args)
            return insert(*args)

        monkeypatch.setattr(panel, "_insert_row", count_insert)
        newest = Event("test", "new", Severity.HIGH, ts=201.0)
        panel._rebuild_event_rows([newest, *original])
        assert len(calls) == 1
        assert panel.table.rowCount() == 120
        assert panel.table.item(1, 0) is retained
        assert panel.table.item(0, 0).data(Qt.UserRole) is newest
        panel._rebuild_event_rows([newest, *original])
        assert len(calls) == 1
    finally:
        panel.close()
        panel.deleteLater()
        app.processEvents()


def test_alert_render_error_restores_painting_and_sorting(monkeypatch):
    panel = AlertsPanel(SimpleNamespace(revision=lambda: 0, try_recent=lambda _limit: []))

    def failed(*_args):
        raise RuntimeError("render interrupted")

    monkeypatch.setattr(panel, "_insert_row", failed)
    try:
        with pytest.raises(RuntimeError, match="render interrupted"):
            panel._rebuild_event_rows([Event("test", "test", Severity.INFO)])
        assert panel.table.updatesEnabled()
        assert panel.table.isSortingEnabled()
    finally:
        panel.close()
        panel.deleteLater()


def test_defender_repeated_gap_evidence_survives_counters_and_restart(tmp_path, monkeypatch):
    key = bytes(range(32))
    for delivered in (0, 10):
        module = AVTelemetryBridgeModule(tmp_path, continuity_key=key)
        module.bind(EventBus())
        assert module._open_continuity_state()
        monkeypatch.setattr(module, "_drain_outbox", lambda: None)
        module._delivered = delivered
        try:
            for _ in range(2):
                module._continuity_gap("retained log gap", reason_code="test.retention")
            rows = module._outbox._db.execute(
                "SELECT item_id, payload_json FROM durable_outbox WHERE item_id LIKE 'defender-gap-%'"
            ).fetchall()
            payloads = [json.loads(row[1]) for row in rows]
            assert len(rows) == (2 if delivered == 0 else 4)
            assert all(p["details"]["response_authorized"] is False for p in payloads)
            assert module.health < 100
        finally:
            module._close_continuity_state()


def _sysmon_fixture(tmp_path, monkeypatch):
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=bytes(range(32)))
    module._evtlog_handle = object()
    records = [SimpleNamespace(RecordNumber=i, EventID=1, TimeGenerated="fixed", StringInserts=[])
               for i in range(1, 601)]
    consumed = []
    monkeypatch.setattr(module, "_process_record", lambda record: consumed.append(record.RecordNumber))
    # A previously empty channel now contains retained history to replay.
    assert module._save_cursor(
        0, record_anchor=sysmon_listener._EMPTY_DIGEST,
        generation=module._generation("empty", 0, sysmon_listener._EMPTY_DIGEST),
    )

    class Backend:
        def GetOldestEventLogRecord(self, _handle):
            return 1

        def GetNumberOfEventLogRecords(self, _handle):
            return len(records)

        def ReadEventLog(self, _handle, flags, offset):
            if flags == sysmon_listener._EVTLOG_SEEK_FWD:
                return [r for r in records if r.RecordNumber >= offset]
            return []

    return module, Backend(), consumed


def test_sysmon_large_replay_is_bounded_and_resumes_without_skipping(tmp_path, monkeypatch):
    module, backend, consumed = _sysmon_fixture(tmp_path, monkeypatch)
    # Isolate the deterministic record bound from host disk speed.
    module._REPLAY_BUDGET_SECONDS = 60.0
    module._reseek_and_drain(backend)
    assert consumed == list(range(1, 257))
    assert module._load_cursor() == 256
    module._reseek_and_drain(backend)
    assert module._load_cursor() == 512
    module._reseek_and_drain(backend)
    assert module._load_cursor() == 600
    assert consumed == list(range(1, 601))


def test_sysmon_slow_batch_and_stop_preserve_only_consumed_prefix(tmp_path, monkeypatch):
    module, backend, consumed = _sysmon_fixture(tmp_path, monkeypatch)
    clock = [10.0]
    monkeypatch.setattr(sysmon_listener, "time", SimpleNamespace(
        monotonic=lambda: clock[0], time=lambda: 1000.0
    ))

    def process(record):
        consumed.append(record.RecordNumber)
        clock[0] += 2.0

    monkeypatch.setattr(module, "_process_record", process)
    module._reseek_and_drain(backend)
    assert consumed == [1]
    assert module._load_cursor() == 1
    assert module._continuity_state != "delivery-gap"
    module._stop.set()
    module._reseek_and_drain(backend)
    assert consumed == [1]
    assert module._load_cursor() == 1


def test_failed_combat_prerequisite_stays_blocked_without_restart_or_rearm(tmp_path, monkeypatch):
    module = AdversaryCombat(tmp_path)
    module.bind(EventBus())
    calls = []

    def failed_reconcile():
        calls.append("reconcile")
        module._journal_error = "journal custody unavailable"
        return False

    def stop_after_wait(seconds):
        calls.append(seconds)
        module._stop.set()

    monkeypatch.setattr(module, "_reconcile_state", failed_reconcile)
    monkeypatch.setattr(module, "sleep", stop_after_wait)
    module.run()
    assert calls == ["reconcile", 30.0]
    assert module._mutation_blocked
    assert not module.response_ready()
    assert module.health == 0
    assert "journal custody unavailable" in module.health_note


def test_storage_hygiene_recognizes_source_profile_without_migration(tmp_path, monkeypatch):
    source = tmp_path / "Angerona"
    dest = source / "SourceData"
    dest.mkdir(parents=True)
    evidence = dest / "evidence.txt"
    evidence.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(storage_hygiene, "default_c_location", lambda: source)
    monkeypatch.setattr(storage_hygiene, "canonical_root", lambda: dest)
    module = storage_hygiene.StorageHygieneModule()
    module._pass()
    assert module.health == 100
    assert "source profile" in module.health_note
    assert evidence.read_text(encoding="utf-8") == "preserve"
    # The generic mutation boundary must still reject every overlapping root.
    assert storage_hygiene.inspect_stray(source, dest)["status"] == "unsafe"
    monkeypatch.setattr(storage_hygiene, "canonical_root", lambda: source / "arbitrary-child")
    module._pass()
    assert module.health == 30
