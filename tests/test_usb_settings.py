from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QMessageBox

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


_QAPP: QApplication | None = None


def _app() -> QApplication:
    global _QAPP
    _QAPP = QApplication.instance() or QApplication([])
    return _QAPP


def _dialog(tmp_path, monkeypatch) -> SettingsDialog:
    _app()
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    return SettingsDialog(
        Config(data_dir=tmp_path), lambda: None, lambda _theme: None
    )


def test_usb_pin_editor_is_masked_and_explains_scope(tmp_path, monkeypatch) -> None:
    dialog = _dialog(tmp_path, monkeypatch)

    assert dialog._select_tab("System") is True
    assert dialog._usb_pin.echoMode() == QLineEdit.EchoMode.Password
    assert dialog._usb_pin_confirm.echoMode() == QLineEdit.EchoMode.Password
    assert dialog._usb_pin.maxLength() == 12
    assert dialog._usb_pin_confirm.maxLength() == 12
    copy = " ".join(label.text() for label in dialog.findChildren(QLabel))
    assert "One incorrect PIN locks USB approval" in copy
    assert "Resetting revokes trust and never approves" in copy
    assert "Approval grants only Angerona permission" in copy
    assert "AutoRun and AutoPlay remain disabled" in copy
    assert "never in settings.json" in copy

    dialog.close()


def test_usb_pin_uses_only_protected_credential_store(
    tmp_path, monkeypatch
) -> None:
    dialog = _dialog(tmp_path, monkeypatch)
    from angerona.core import config as config_module

    updates: list[dict[str, str]] = []
    monkeypatch.setattr(config_module, "write_env_keys", updates.append)
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.Yes)
    monkeypatch.setattr(QMessageBox, "information", lambda *_args: None)
    dialog._usb_pin.setText("004271")
    dialog._usb_pin_confirm.setText("004271")

    assert dialog._reset_usb_pin() is True
    assert updates == [{"ANGERONA_USB_PIN": "004271"}]
    assert dialog._usb_pin.text() == ""

    dialog._cfg.save()
    saved_text = dialog._cfg.settings_path.read_text(encoding="utf-8")
    saved = json.loads(saved_text)
    assert "ANGERONA_USB_PIN" not in saved
    assert "004271" not in saved_text
    dialog.close()


def test_invalid_usb_pin_stops_settings_save(tmp_path, monkeypatch) -> None:
    dialog = _dialog(tmp_path, monkeypatch)
    from angerona.core import config as config_module

    updates: list[dict[str, str]] = []
    warnings: list[tuple[str, str]] = []
    monkeypatch.setattr(config_module, "write_env_keys", updates.append)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda _parent, title, message: warnings.append((title, message)),
    )
    dialog._usb_pin.setText("123")
    dialog._usb_pin_confirm.setText("123")

    assert not dialog._reset_usb_pin()

    assert updates == []
    assert warnings == [
        (
            "USB PIN not reset",
            "The removable-media approval PIN must contain 4–12 digits.",
        )
    ]
    assert not dialog._cfg.settings_path.exists()
    assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "System"
    dialog.close()


def test_confirmed_reset_revokes_trust_without_approving_attached_media(
    tmp_path, monkeypatch
) -> None:
    from angerona.core import config as config_module
    from angerona.core.usb_policy import UsbApprovalPolicy

    configured = {"pin": "246810"}
    policy = UsbApprovalPolicy(pin_loader=lambda: configured["pin"])
    approval = policy.request("U:\\")
    assert policy.verify(approval.approval_id, "246810").approved

    dialog = _dialog(tmp_path, monkeypatch)

    def protected_write(updates: dict[str, str]) -> None:
        configured["pin"] = updates["ANGERONA_USB_PIN"]

    monkeypatch.setattr(config_module, "write_env_keys", protected_write)
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.Yes)
    monkeypatch.setattr(QMessageBox, "information", lambda *_args: None)
    dialog._usb_pin.setText("135790")
    dialog._usb_pin_confirm.setText("135790")

    assert dialog._reset_usb_pin()
    assert policy.trust_state("U:\\") == "pending"
    assert configured["pin"] == "135790"
    assert policy.verify(approval.approval_id, "135790").approved
    dialog.close()


def test_cancelled_reset_does_not_clear_session_lock(tmp_path, monkeypatch) -> None:
    from angerona.core import config as config_module
    from angerona.core.usb_policy import UsbApprovalPolicy

    writes: list[dict[str, str]] = []
    policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    approval = policy.request("T:\\")
    assert policy.verify(approval.approval_id, "000000").state == "locked"

    dialog = _dialog(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "write_env_keys", writes.append)
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.No)
    dialog._usb_pin.setText("135790")
    dialog._usb_pin_confirm.setText("135790")

    assert not dialog._reset_usb_pin()
    assert writes == []
    assert policy.pin_reset_required()
    assert policy.trust_state("T:\\") == "locked"
    dialog.close()
