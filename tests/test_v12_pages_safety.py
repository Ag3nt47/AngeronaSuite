from __future__ import annotations

import copy
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.config import Config
from angerona.gui import pages


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _event(message: str, *, ts: float = 10.0, module: str = "Process Monitor"):
    return Event(
        module,
        message,
        Severity.HIGH,
        ts=ts,
        details={"rule_id": message, "pid": 321},
    )


def test_settings_bridge_save_failure_restores_every_transaction_resource(
    tmp_path, monkeypatch,
) -> None:
    _app()
    from angerona.core import autostart, config as config_module, secure_store

    protected = {"ANGERONA_BRIDGE_KEY": "a" * 64, "PRESERVE": "value"}

    def read_map(_root=None, *, strict=False):
        return dict(protected)

    def write_map(updates):
        for name, value in updates.items():
            if value in (None, ""):
                protected.pop(name, None)
            else:
                protected[name] = str(value)
        return tmp_path / "secrets.dpapi"

    monkeypatch.setattr(secure_store, "read_secret_map", read_map)
    monkeypatch.setattr(config_module, "write_env_keys", write_map)
    autostart_state = {"enabled": False}
    monkeypatch.setattr(autostart, "is_enabled", lambda: autostart_state["enabled"])
    monkeypatch.setattr(
        autostart, "enable_autostart",
        lambda: autostart_state.__setitem__("enabled", True) or True,
    )
    monkeypatch.setattr(
        autostart, "disable_autostart",
        lambda: autostart_state.__setitem__("enabled", False) or True,
    )
    messages: list[tuple[str, str]] = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        lambda _parent, title, text, *_args: messages.append((title, text)),
    )
    monkeypatch.setattr(
        QMessageBox, "critical",
        lambda _parent, title, text, *_args: messages.append((title, text)),
    )

    config = Config(data_dir=tmp_path)
    config.autostart_enabled = False
    config.settings_path.write_bytes(b'{"original":true}\n')
    config_before = copy.deepcopy(vars(config))
    dialog = pages.SettingsDialog(config, lambda: None, lambda _theme: None)
    dialog._bridge_key.setText("b" * 64)
    environment_before = dict(os.environ)

    def fail_save(candidate):
        candidate.settings_path.write_bytes(b"partial")
        raise OSError("simulated settings write failure")

    monkeypatch.setattr(Config, "save", fail_save)
    dialog._save()

    assert vars(config) == config_before
    assert config.settings_path.read_bytes() == b'{"original":true}\n'
    assert protected == {"ANGERONA_BRIDGE_KEY": "a" * 64, "PRESERVE": "value"}
    assert dict(os.environ) == environment_before
    assert autostart_state == {"enabled": False}
    assert messages and messages[-1][0] == "Settings not saved"
    assert "were restored" in messages[-1][1]


def test_alert_reconcile_uses_identity_and_empty_ledger_clears_rows() -> None:
    _app()
    storage = SimpleNamespace()
    panel = pages.AlertsPanel(storage)
    first = _event("first", ts=20.0)
    second = _event("second", ts=20.0)

    panel._apply_loaded_events(1, [first])
    panel._apply_loaded_events(2, [second, first])
    assert panel.table.rowCount() == 2
    assert {
        panel.table.item(row, 0).data(pages.Qt.UserRole).message
        for row in range(panel.table.rowCount())
    } == {"first", "second"}

    panel._apply_loaded_events(3, [])
    assert panel.table.rowCount() == 0
    assert panel._rendered_event_ids == ()
    panel.close()


def test_analyze_dedupes_identity_and_bounds_global_queue() -> None:
    _app()
    panel = pages.AlertsPanel(SimpleNamespace())
    panel._analyze_workers[:] = [object(), object()]
    duplicate = _event("duplicate")
    panel._analyze_event(duplicate, None)
    panel._analyze_event(duplicate, None)
    assert len(panel._analyze_queue) == 1
    assert "already running or queued" in panel._status.text()

    for index in range(20):
        panel._analyze_event(_event(f"rule-{index}"), None)
    assert len(panel._analyze_queue) == panel._max_analyze_queue
    assert "queue is full" in panel._status.text()
    panel.close()


def test_allow_is_confirmed_scoped_expiring_audited_and_reversible(
    monkeypatch,
) -> None:
    _app()
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.Yes)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: None)
    bus = EventBus()
    target = _event("target")
    sibling = _event("sibling")
    integrity = _event("integrity", module="Self Integrity Sentinel")
    panel = pages.AlertsPanel(SimpleNamespace(), bus=bus)
    panel._events = [target, sibling, integrity]
    panel._rebuild_event_rows(panel._events)

    assert panel._allow_event(target) is True
    assert panel.table.rowCount() == 2
    assert any(
        event.module == "Operator Alert Suppression"
        for event in bus.recent(10)
    )
    assert panel._allow_event(integrity) is False
    assert panel._suppressions

    panel._undo_last_suppression()
    assert panel.table.rowCount() == 3
    assert not panel._suppressions
    panel.close()


def test_soar_clear_archives_atomically_and_can_restore(tmp_path, monkeypatch) -> None:
    _app()
    queue = tmp_path / "soar_queue.json"
    state = tmp_path / "soar_queue_state.json"
    queue.write_bytes(b'{"request_id":"' + b"a" * 32 + b'"}\n')
    state.write_bytes(b"{}")
    monkeypatch.setattr(pages, "_soar_queue_path", lambda: queue)
    monkeypatch.setattr(pages, "_soar_queue_state_path", lambda: state)

    archive = pages._archive_soar_history()
    assert archive is not None
    assert not queue.exists() and not state.exists()
    assert (archive / "archive_receipt.json").exists()
    pages._restore_soar_archive(archive)
    assert queue.exists() and state.exists()


def test_alert_detail_never_claims_unverified_record_is_signed() -> None:
    _app()
    unsigned = pages.AlertDetailDialog(_event("unsigned"))
    assert "not verified" in unsigned.findChild(
        pages.QLabel, "alertEvidenceAuthenticity"
    ).text().casefold()
    unsigned.close()

    bus = EventBus()
    bus.arm(BusAuthority(b"v" * 32))
    bus.publish(_event("verified"))
    panel = pages.AlertsPanel(SimpleNamespace(), bus=bus)
    verified = pages.AlertDetailDialog(bus.recent(1)[0], panel=panel)
    assert "verified" in verified.findChild(
        pages.QLabel, "alertEvidenceAuthenticity"
    ).text().casefold()
    verified.close()
    panel.close()
