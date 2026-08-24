from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLineEdit

from angerona.core.eventbus import Event, Severity
from angerona.gui.pages import (
    AlertDetailDialog,
    AlertsPanel,
    _event_artifact_paths,
    _event_evidence_context,
)
from angerona.resilience.scanner import _redact_command_line


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _process_event() -> Event:
    return Event(
        module="Telemetry Scanner",
        message="process_creation: conhost.exe (pid 9580)",
        severity=Severity.INFO,
        ts=1_785_372_208.35,
        details={
            "type": "process_creation",
            "pid": 9580,
            "ppid": 15520,
            "name": "conhost.exe",
            "exe": r"C:\Windows\System32\conhost.exe",
            "location_status": "resolved",
            "cmdline": r"C:\Windows\System32\conhost.exe 0xffffffff -ForceV1",
            "command_line_status": "resolved",
            "parent_name": "powershell.exe",
            "source": "scanner",
            "sensor": "process_creation",
        },
    )


def test_process_evidence_context_exposes_location_parent_and_command_line() -> None:
    context = _event_evidence_context(_process_event())
    assert context["event"] == "Process Creation"
    assert context["subject"] == "conhost.exe (PID 9580)"
    assert context["location"] == r"C:\Windows\System32\conhost.exe"
    assert context["parent"] == "powershell.exe (PID 15520)"
    assert "-ForceV1" in context["command_line"]
    assert context["source"] == "scanner · process_creation"


def test_scanner_command_line_keeps_context_but_redacts_inline_secrets() -> None:
    rendered = _redact_command_line(
        [
            "agent.exe",
            "--mode",
            "scan",
            "--api-key=private-value",
            "--token",
            "other-private-value",
        ]
    )
    assert "agent.exe" in rendered
    assert "--mode scan" in rendered
    assert "private-value" not in rendered
    assert "[REDACTED]" in rendered


def test_alert_detail_renders_read_only_observed_evidence_fields() -> None:
    app = _app()
    dialog = AlertDetailDialog(_process_event())
    dialog.show()
    app.processEvents()
    location = dialog.findChild(QLineEdit, "alertEvidenceLocation")
    parent = dialog.findChild(QLineEdit, "alertEvidenceParent")
    command = dialog.findChild(QLineEdit, "alertEvidenceCommandLine")
    assert location is not None and location.isReadOnly()
    assert location.text() == r"C:\Windows\System32\conhost.exe"
    assert parent is not None and parent.text() == "powershell.exe (PID 15520)"
    assert command is not None and "-ForceV1" in command.text()
    dialog.close()


def test_live_alerts_show_all_sensor_supplied_artifact_paths() -> None:
    app = _app()
    event = Event(
        module="AV Telemetry Bridge",
        message="Defender detected two related artifacts",
        severity=Severity.HIGH,
        details={
            "artifact_paths": [r"C:\Temp\dropper.exe", r"C:\Temp\payload.dll"],
            "artifact_path": r"C:\Temp\dropper.exe",
        },
    )
    assert _event_artifact_paths(event) == [
        r"C:\Temp\dropper.exe",
        r"C:\Temp\payload.dll",
    ]

    panel = AlertsPanel(object())
    panel._insert_row(0, event)
    path_item = panel.table.item(0, 4)
    assert path_item is not None
    assert r"C:\Temp\dropper.exe" in path_item.text()
    assert r"C:\Temp\payload.dll" in path_item.text()
    panel.close()
    panel.deleteLater()
    app.processEvents()


def test_live_alert_action_columns_still_route_after_path_expansion() -> None:
    app = _app()
    event = _process_event()
    panel = AlertsPanel(object())
    panel._insert_row(0, event)
    routed = []
    panel._allow_event = lambda selected: routed.append(("allow", selected))
    panel._block_event = lambda selected: routed.append(("block", selected))
    panel._analyze_event = lambda selected, _button: routed.append(("analyze", selected))

    panel._on_click(0, 5)
    panel._on_click(0, 6)
    panel._on_click(0, 7)
    assert routed == [("allow", event), ("block", event), ("analyze", event)]
    panel.close()
    panel.deleteLater()
    app.processEvents()


def test_alert_detail_evidence_and_record_boxes_remain_resizable() -> None:
    app = _app()
    dialog = AlertDetailDialog(_process_event())
    dialog.resize(900, 720)
    dialog.show()
    app.processEvents()
    sizes = dialog._details_splitter.sizes()
    assert len(sizes) == 2
    assert min(sizes) >= 96
    assert dialog._evidence_scroll.widgetResizable()
    assert dialog._record_body.minimumHeight() == 96
    dialog.close()
