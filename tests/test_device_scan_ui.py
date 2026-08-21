from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton

from angerona.core.device_security_lab import DeviceSecurityLab
from angerona.gui.pages import AlertsPanel
from angerona.gui.red_team_console import RedTeamConsole
from angerona.gui.scan_center import ScanCenterPanel


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_red_team_device_lab_creates_a_local_authorized_enrollment(
    tmp_path, monkeypatch
) -> None:
    app = _app()
    lab = DeviceSecurityLab(tmp_path / "lab", authority=b"A" * 32)
    monkeypatch.setattr(RedTeamConsole, "_device_lab_service", lambda _self: lab)
    dialog = RedTeamConsole(None, default_target=str(tmp_path))

    assert any(
        "Device Security Lab" in dialog._tabs.tabText(index)
        for index in range(dialog._tabs.count())
    )
    assert dialog.device_pairing_key.echoMode() == QLineEdit.EchoMode.Normal
    assert "public key" in dialog.device_pairing_key.placeholderText().lower()
    assert "private" in dialog.device_lab_log.toPlainText().lower() or not (
        dialog.device_lab_log.toPlainText()
    )

    dialog.device_label.setText("Owned test laptop")
    dialog.device_source.setCurrentIndex(dialog.device_source.findData("local"))
    dialog.device_owner_attested.setChecked(True)
    dialog._create_device_enrollment()
    app.processEvents()

    records = lab.list_enrollments()
    assert len(records) == 1
    assert records[0].status == "active"
    assert records[0].evidence_source == "local"
    assert records[0].public_key_fingerprint == ""
    assert dialog.device_enrollments.count() == 1
    dialog.close()


def test_scan_center_renders_redacted_findings_without_a_remote_target() -> None:
    app = _app()
    panel = ScanCenterPanel()
    panel._apply_result({
        "operation": "listening_exposure_audit",
        "status": "completed",
        "supported": True,
        "executed": True,
        "summary": "Reviewed one local listener; no packets were sent.",
        "findings": [{
            "finding_id": "listener.example",
            "severity": "medium",
            "category": "Listening exposure",
            "title": "Service is reachable beyond loopback",
            "evidence": ["Port: 8443", "Bind scope: all-interfaces"],
            "remediation": ["Restrict the bind and firewall scope."],
        }],
        "metrics": {"listeners_reviewed": 1},
        "errors": [],
        "privacy": "No IP, MAC, SSID, username, or path is returned.",
    })
    app.processEvents()

    assert panel.findings.rowCount() == 1
    assert panel.findings.item(0, 0).text() == "medium"
    assert "beyond loopback" in panel.findings.item(0, 1).text()
    assert "no packets" in panel.log.toPlainText().lower()
    assert not hasattr(panel, "target_host")
    panel.close()


def test_live_alerts_scan_center_button_emits_navigation_request() -> None:
    app = _app()
    panel = AlertsPanel(object())
    requested: list[bool] = []
    panel.scan_requested.connect(lambda: requested.append(True))
    button = next(
        item for item in panel.findChildren(QPushButton)
        if "Scan Center" in item.text()
    )
    button.click()
    app.processEvents()
    assert requested == [True]
    panel.close()
