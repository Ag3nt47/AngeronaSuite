"""Signing settings stay modeless and never promote candidate data to authority."""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog

from angerona.core.config import Config
from angerona.core.watchdog_signing import parse_inspection
from angerona.gui.component_heartbeat import ComponentHeartbeatStrip
from angerona.gui.main_window import MainWindow
from angerona.gui.watchdog_settings import WatchdogSettingsPanel
from test_watchdog_signing import CANDIDATE, PUBLISHER, diagnostic, status


def _retire_panel(panel):
    threads = panel.reader_threads
    panel.shutdown()
    for thread in threads:
        thread.join(3)
        assert not thread.is_alive()
    panel.close()
    panel.deleteLater()


def test_constructor_and_selection_never_inspect_or_execute_candidate(tmp_path):
    inspect = Mock(side_effect=AssertionError("No explicit verification requested"))
    panel = WatchdogSettingsPanel(Config(data_dir=tmp_path),
                                  status_supplier=lambda: {}, inspector=inspect)
    try:
        assert not panel.unsigned_enabled.isChecked()
        panel.select_candidate(CANDIDATE)
        assert panel.inspect_button.isEnabled()
        assert not panel.prepare_button.isEnabled() and not panel.export_button.isEnabled()
        assert panel.reader_threads == ()
        inspect.assert_not_called()
        assert "Activation held" in panel.activation_label.text()
    finally:
        _retire_panel(panel)


def test_explicit_verification_runs_off_gui_and_prepares_only_untrusted_data(tmp_path):
    threads = []

    def inspect(path):
        threads.append(threading.get_ident())
        return parse_inspection(path, diagnostic())

    panel = WatchdogSettingsPanel(Config(data_dir=tmp_path),
                                  status_supplier=lambda: {}, inspector=inspect)
    try:
        gui_thread = threading.get_ident()
        panel.select_candidate(CANDIDATE)
        panel._inspect_selected()
        deadline = time.monotonic() + 3
        while not panel.prepare_button.isEnabled() and time.monotonic() < deadline:
            QApplication.processEvents()
            QTest.qWait(5)
        assert panel.prepare_button.isEnabled()
        assert len(threads) == 1 and threads[0] != gui_thread
        assert panel.inspection_label.textFormat() == Qt.PlainText
        assert PUBLISHER in panel.inspection_label.text()
        assert "unverified" in panel.inspection_label.text()
        panel._prepare_update()
        request = json.loads(panel.request_preview.toPlainText())
        assert request["trusted"] is False and request["activation_allowed"] is False
        assert "UNTRUSTED" in panel.activation_label.text()
        assert panel.export_button.isEnabled()
        panel.select_candidate(r"C:\another\watchdog3.exe")
        assert not panel.prepare_button.isEnabled() and not panel.export_button.isEnabled()
        assert panel.request_preview.toPlainText() == ""
    finally:
        _retire_panel(panel)


def test_status_literal_signer_and_unverified_refresh_cannot_reuse_old_identity(tmp_path):
    current = [status(reason="Fresh native generation", recovery_reason="Recovery held: user-session lifetime")]
    panel = WatchdogSettingsPanel(Config(data_dir=tmp_path), status_supplier=lambda: current[0])
    try:
        assert panel.signature_label.text() == "Signature verified"
        assert panel.signer_label.textFormat() == Qt.PlainText
        assert panel.signer_label.text() == PUBLISHER
        assert "&lt;Literal&gt;" in panel.signature_label.toolTip()
        assert "Not enrolled" in panel.enrollment_label.text()
        assert "Recovery held" in panel.runtime_reason_label.text()
        current[0] = status(signature_verified=False, signature_state="unverified")
        panel.refresh_status()
        assert panel.signature_label.text() == "Signature unverified"
        assert panel.signer_label.text() == "Unavailable"
        assert panel.expiry_label.text() == "Unavailable"
        assert "Reduced protection" in panel.status_label.text()
    finally:
        _retire_panel(panel)


def test_signature_marker_click_opens_signing_not_heartbeat_details():
    strip = ComponentHeartbeatStrip(clock=lambda: 100)
    clicked, details = Mock(), Mock()
    strip.signing_settings_requested.connect(clicked)
    strip.details_requested.connect(details)
    try:
        strip.set_signing_source(lambda: status(state="stale", heartbeat_verified=False))
        strip.show()
        QApplication.processEvents()
        marker = strip._signature_marker
        assert marker.text() == "✓" and "#22c55e" in marker.styleSheet()
        assert "Not responding" in marker.toolTip()
        assert "&lt;Literal&gt;" in marker.toolTip()
        assert not any(row.fresh for row in strip.snapshot())
        QTest.mouseClick(marker, Qt.LeftButton)
        assert clicked.call_count == 1 and details.call_count == 0
        strip.set_signing_source(lambda: status(signature_verified=False))
        assert marker.text() == "✕" and "#f87171" in marker.styleSheet()
        assert "Signature unverified" in marker.accessibleName()
    finally:
        strip.close()
        strip.deleteLater()


def test_marker_settings_route_reuses_the_modeless_settings_owner():
    dialog = SimpleNamespace(focus_watchdog_signing=Mock())
    owner = SimpleNamespace(_show_settings=Mock(return_value=dialog))
    MainWindow._open_watchdog_signing_settings(owner)
    owner._show_settings.assert_called_once_with("Watchdog")
    dialog.focus_watchdog_signing.assert_called_once_with()
    owner._show_settings.return_value = None  # Previous exact worker still retiring.
    MainWindow._open_watchdog_signing_settings(owner)
    assert dialog.focus_watchdog_signing.call_count == 1


def test_real_settings_stages_opt_in_until_save_and_closes_owned_readers(tmp_path, monkeypatch):
    from test_settings_autostart_save_probe import _dialog
    dialog, config, probes, changes = _dialog(tmp_path, monkeypatch)
    try:
        panel = dialog._watchdog_settings
        dialog.focus_watchdog_signing()
        assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "Watchdog"
        assert config.watchdog3_unsigned_enabled is False
        panel.unsigned_enabled.setChecked(True)
        assert config.watchdog3_unsigned_enabled is False
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.watchdog3_unsigned_enabled is True
        assert json.loads(config.settings_path.read_text())["watchdog3_unsigned_enabled"] is True
        assert panel._closed
        assert panel._inspection_reader.thread is None and panel._export_reader.thread is None
        assert probes == ["query"] and changes == []
    finally:
        dialog.close()
