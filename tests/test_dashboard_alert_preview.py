"""Inline alert inspection stays read-only and preserves guarded action routes."""
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import Event, Severity
from angerona.gui.alert_preview import AlertPreview
from angerona.gui.pages import AlertsPanel, StatCard
from angerona.gui.theme import build_qss


def make_panel(width=1300):
    panel = AlertsPanel(SimpleNamespace())
    panel.resize(width, 420)
    panel.show()
    events = [
        Event("Sensor A", "<b>Untrusted message</b>", Severity.HIGH, ts=101.0,
              details={"file_path": r"C:\sample\one.exe", "secret": "RAW_SECRET_MUST_NOT_APPEAR"}),
        Event("Sensor B", "Second event", Severity.INFO, ts=100.0),
    ]
    panel._rebuild_event_rows(events)
    QApplication.instance().processEvents()
    return panel, events


def test_inline_selection_previews_plain_evidence_without_opening_windows(monkeypatch):
    panel, events = make_panel()
    opened = []
    monkeypatch.setattr(panel, "_open_event_details", opened.append)
    try:
        panel._details_button.setChecked(True)
        panel.table.selectRow(0)
        panel._on_click(0, 3)
        assert opened == []
        assert panel._preview_event == events[0]
        assert panel._preview._source.text() == "Sensor A"
        assert panel._preview._source.textFormat() == Qt.PlainText
        evidence = panel._preview._evidence.toPlainText()
        assert "<b>Untrusted message</b>" in evidence
        assert r"C:\sample\one.exe" in evidence
        assert "RAW_SECRET_MUST_NOT_APPEAR" not in evidence
        assert panel.table.isColumnHidden(4)
        panel.table.selectRow(1)
        assert panel._preview._source.text() == "Sensor B"
        panel._preview._open.click()
        assert opened == [events[1]]
        panel._on_double_click(1, 3)
        assert opened == [events[1], events[1]]
        panel.table.clearSelection()
        assert panel._preview_event is None and not panel._preview._open.isEnabled()
    finally:
        panel.close()


def test_inspector_does_not_bypass_allow_block_or_analyze_routes(monkeypatch):
    panel, events = make_panel()
    actions = []
    monkeypatch.setattr(panel, "_allow_event", lambda event: actions.append(("allow", event)))
    monkeypatch.setattr(panel, "_block_event", lambda event: actions.append(("block", event)))
    monkeypatch.setattr(panel, "_analyze_event", lambda event, button: actions.append(("analyze", event)))
    try:
        panel._details_button.setChecked(True)
        panel.table.selectRow(0)
        for column in (5, 6, 7):
            panel._on_click(0, column)
            panel._on_double_click(0, column)
        assert actions == [(name, events[0]) for name in ("allow", "block", "analyze")]
        assert panel._preview._evidence.isReadOnly()
    finally:
        panel.close()


def test_narrow_layout_collapses_preview_and_preserves_full_detail_access(monkeypatch):
    panel, events = make_panel()
    opened = []
    monkeypatch.setattr(panel, "_open_event_details", opened.append)
    try:
        panel.table.selectRow(0)
        panel._details_button.setChecked(True)
        panel.resize(820, 420)
        QApplication.instance().processEvents()
        assert panel._preview.isHidden()
        assert not panel._details_button.isChecked()
        assert not panel.table.isColumnHidden(4)
        panel._details_button.click()
        assert opened == [events[0]]
        assert panel._preview.isHidden()
        panel._on_click(0, 3)
        assert opened == [events[0], events[0]]
    finally:
        panel.close()


def test_bounded_preview_retains_scroll_position_when_evidence_is_unchanged():
    preview = AlertPreview()
    payload = dict(module="Sensor", severity="Info", timestamp="12:00:00",
                   message="line\n" * 10000, paths="C:\\" + "x" * 10000)
    try:
        preview.show_evidence(**payload)
        document = preview._evidence.document()
        revision = document.revision()
        assert document.characterCount() < 21000
        assert "Open full details" in preview._evidence.toPlainText()
        preview.show_evidence(**payload)
        assert document.revision() == revision
        preview.clear()
        assert not preview._open.isEnabled()
    finally:
        preview.close()


def test_new_alerts_preserve_selected_preview_and_removal_clears_stale_evidence():
    panel, events = make_panel()
    try:
        panel._details_button.setChecked(True)
        panel.table.selectRow(1)
        added = Event("New sensor", "New incoming event", Severity.LOW, ts=102)
        panel._rebuild_event_rows([added, *events])
        assert panel._preview_event == events[1]
        assert panel._preview._source.text() == events[1].module
        panel._rebuild_event_rows([])
        assert panel._preview_event is None and not panel._preview._open.isEnabled()
    finally:
        panel.close()


@pytest.mark.parametrize("scale", [0.75, 1.0, 1.35])
def test_short_inspector_keeps_actual_evidence_visible_at_supported_scales(scale):
    preview = AlertPreview()
    preview.setStyleSheet(build_qss(scale=scale))
    preview.resize(330, 190)
    preview.show_evidence(module="Zero-Trust Local IPC Guard", severity="Info", timestamp="06:00:11",
                          message="Synthetic loopback authentication challenge verified", paths="Not provided")
    preview.show()
    QApplication.instance().processEvents()
    try:
        assert preview._evidence.viewport().height() >= 120
        assert preview._evidence.toPlainText().startswith("Synthetic loopback")
        assert preview._open.isVisible()
    finally:
        preview.close()


class _StyleEvents(QObject):
    def __init__(self, widget):
        super().__init__(widget)
        self.count = 0
        widget.installEventFilter(self)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.StyleChange:
            self.count += 1
        return False


def test_critical_cards_keep_exact_counts_without_restyling_unchanged_color():
    card = StatCard("Active critical")
    try:
        card.set("1", "#ef4444")
        observer = _StyleEvents(card.value)
        assert card.property("alert") is True
        card.set("2", "#ef4444")
        assert card.value.text() == "2" and observer.count == 0
        card.set("0", "#ffffff")
        assert card.property("alert") is False
    finally:
        card.close()
