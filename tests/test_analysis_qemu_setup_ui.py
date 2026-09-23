from __future__ import annotations

import sys
import threading
import time
from types import SimpleNamespace

import pytest

pytest.importorskip('PySide6')
from PySide6.QtWidgets import QApplication
from angerona.gui import analysis_qemu_setup as ui


def test_opening_optional_setup_does_not_start_download_or_timer(tmp_path):
    dialog = ui.QEMUSetupDialog(root=tmp_path)
    try:
        assert not dialog._busy and not dialog._timer.isActive()
        assert dialog.close_button.isDefault()
        assert not dialog.install_button.autoDefault()
        assert 'optional' in ui.PURPOSE.lower()
        assert 'automatic defense' in ui.PURPOSE
        assert '197 MiB' in ui.SETUP_DETAILS
    finally:
        dialog.close()
        dialog.deleteLater()


def test_native_setup_keeps_dialog_open_and_delivers_completion(tmp_path, monkeypatch):
    entered, finish = threading.Event(), threading.Event()
    def install(root, _operation, progress):
        assert root == tmp_path
        entered.set()
        for _ in range(30):
            progress('Bounded progress')
        assert finish.wait(3)
        return 'Fixture setup completed'
    monkeypatch.setitem(sys.modules, 'angerona.core.analysis_qemu_setup',
                        SimpleNamespace(install_and_configure=install))
    dialog = ui.QEMUSetupDialog(root=tmp_path)
    try:
        dialog._install()
        assert entered.wait(1)
        assert dialog._busy and not dialog.close_button.isEnabled()
        dialog.reject()
        assert dialog._busy
        assert not dialog.vmware_button.isEnabled()
        finish.set()
        deadline = time.monotonic() + 3
        while dialog._busy and time.monotonic() < deadline:
            QApplication.processEvents()
            dialog._poll()
            time.sleep(.01)
        assert not dialog._busy
        assert dialog.status.text() == 'Fixture setup completed'
        assert dialog.close_button.isEnabled()
        assert not dialog._timer.isActive()
    finally:
        finish.set()
        dialog.close()
        dialog.deleteLater()


def test_nonwindows_user_can_skip_without_install_actions(tmp_path, monkeypatch):
    monkeypatch.setattr(ui.sys, 'platform', 'darwin')
    dialog = ui.QEMUSetupDialog(root=tmp_path)
    try:
        assert not dialog.install_button.isEnabled()
        assert not dialog.vmware_button.isEnabled()
        assert dialog.close_button.isEnabled()
    finally:
        dialog.close()
        dialog.deleteLater()
