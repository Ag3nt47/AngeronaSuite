from __future__ import annotations

import json
import os
import socket
import weakref
from html.parser import HTMLParser
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QMessageBox, QPushButton

from angerona.core import cve_fix_advisor, cve_ignore
from angerona.gui import cve_analysis_window, threat_intel_page, top_talkers, worldview_page


@pytest.fixture(scope="module", autouse=True)
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def no_network_or_browser(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("Untrusted text test attempted network or browser access")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)
    monkeypatch.setattr(QDesktopServices, "openUrl", refused)
    monkeypatch.setattr(cve_fix_advisor, "analyze", refused)
    monkeypatch.setattr(cve_fix_advisor, "safe_urlopen", refused)


class _Tags(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, _attrs):
        self.tags.append(tag)


def _payload(tmp_path):
    # A local nonexistent fixture resource keeps even a pre-fix failure inert.
    return f"<b>untrusted</b><img src='{(tmp_path / 'inert-missing.png').as_uri()}'>"


def test_cve_card_treats_feed_values_as_plain_text_and_keeps_canonical_nvd_link(tmp_path):
    payload = _payload(tmp_path)
    record = {"cve": "CVE-2026-12345", "name": payload, "vendor": payload,
              "product": payload, "mitre": payload, "date_added": payload,
              "due_date": payload, "remediation": payload}
    card = cve_analysis_window.CveCard(record)
    try:
        values = [label for label in card.findChildren(QLabel) if label.text() == payload]
        assert len(values) == 7
        assert all(label.textFormat() == Qt.TextFormat.PlainText for label in values)
        link = next(label for label in card.findChildren(QLabel) if label.openExternalLinks())
        assert link.textFormat() == Qt.TextFormat.RichText
        assert "https://nvd.nist.gov/vuln/detail/CVE-2026-12345" in link.text()
        assert _Tags(link.text()).tags == ["a"]
    finally:
        card.close()


@pytest.mark.parametrize("identifier", [
    "CVE-2026-1234' onclick='inert", "../CVE-2026-1234", "CVE-2026-1234\n",
    "CVE-2026-" + "1" * 33, "<b>CVE-2026-1234</b>",
])
def test_malformed_cve_has_no_automatic_external_link(identifier):
    assert cve_analysis_window._nvd_url(identifier) is None
    card = cve_analysis_window.CveCard({"cve": identifier})
    try:
        assert not any(label.openExternalLinks() for label in card.findChildren(QLabel))
        value = next(label for label in card.findChildren(QLabel) if label.text() == identifier)
        assert value.textFormat() == Qt.TextFormat.PlainText
    finally:
        card.close()


def test_top_talkers_result_uses_actual_plain_nonmodal_message_box(monkeypatch, tmp_path):
    payload = _payload(tmp_path)
    dialog = QDialog()
    button, status = QPushButton(dialog), QLabel(dialog)
    captured = []
    monkeypatch.setattr(QMessageBox, "show", lambda box: captured.append(box))
    subject = SimpleNamespace(_ai_context={"token": 7, "dialog": weakref.ref(dialog),
        "button": weakref.ref(button), "status": weakref.ref(status), "abandoned": False},
        _activities=SimpleNamespace(finish=lambda _activity: None), _ai_activity=None,
        _accept_results=True, _live_widget=top_talkers.TopTalkersDialog._live_widget)
    try:
        top_talkers.TopTalkersDialog._handle_ai_result(subject, 7, payload)
        assert len(captured) == 1
        assert captured[0].text() == payload
        assert captured[0].textFormat() == Qt.TextFormat.PlainText
        assert captured[0].windowModality() == Qt.WindowModality.NonModal
    finally:
        dialog.close()


def test_top_talkers_process_and_destination_cannot_add_rich_text_resources(monkeypatch, tmp_path):
    payload = _payload(tmp_path)
    dialogs = []
    monkeypatch.setattr(QDialog, "exec", lambda dialog: dialogs.append(dialog) or 0)
    parent = QDialog()
    try:
        top_talkers.TopTalkersDialog._process_actions(parent, 1234, payload, payload, {})
        head = next(label for label in dialogs[0].findChildren(QLabel) if "Top remote:" in label.text())
        assert "img" not in _Tags(head.text()).tags
        assert "&lt;img" in head.text()
    finally:
        parent.close()


def test_worldview_model_and_error_fields_are_plain_without_starting_workers(monkeypatch, tmp_path):
    payload = _payload(tmp_path)
    monkeypatch.setattr(worldview_page.PresentationTimer, "start", lambda *_args: None)
    engine = SimpleNamespace(host_vs_suite_matrix=lambda: {"available": False, "reason": payload},
        eps_gauge=lambda _count: {"alarm": True, "blinding_suspected": True,
            "internal_eps": 0, "host_ctx_switch_rate": 1, "host_active": True, "banner": payload})
    window = worldview_page.WorldViewDialog(engine=engine)
    try:
        window._on_ollama_result({"available": True, "model": payload})
        assert payload in window._ollama.text()
        assert window._ollama.textFormat() == Qt.TextFormat.PlainText
        window._on_ollama_result({"available": False, "reason": payload})
        assert payload in window._ollama.text()
        assert window._matrix.textFormat() == window._banner.textFormat() == Qt.TextFormat.PlainText
        assert window._eps.textFormat() == Qt.TextFormat.PlainText
        assert window._ollama_worker is None
    finally:
        window.close()


def test_threat_detail_escapes_feed_header_and_keeps_model_summary_plain(monkeypatch, tmp_path):
    payload = _payload(tmp_path)
    monkeypatch.setattr(threat_intel_page, "_load_threats", lambda: {"matches": []})
    monkeypatch.setattr(cve_ignore, "load", lambda: {})
    monkeypatch.setattr(cve_ignore, "is_ignored", lambda *_args: False)
    monkeypatch.setattr(cve_fix_advisor, "applied_state", lambda _cve: None)
    dialogs = []
    monkeypatch.setattr(QDialog, "exec", lambda dialog: dialogs.append(dialog) or 0)
    # Proposal previews intentionally use a modeless show, not exec. Capture
    # that actual path too; no proposal button or action worker is invoked.
    monkeypatch.setattr(QDialog, "show", lambda dialog: dialogs.append(dialog))
    dashboard = threat_intel_page.ThreatIntelDashboard()
    dashboard._timer.stop()
    analysis = {"fix_available": True, "confidence": 0.9, "summary": payload,
                "fix_script": "Write-Output 'inert'"}
    monkeypatch.setattr(dashboard, "_cached_analysis", lambda *_args: analysis)
    try:
        dashboard._stage_review("CVE-2026-1234", {"name": payload, "vendor": payload, "product": payload})
        head = next(label for label in dialogs[-1].findChildren(QLabel) if "<b>CVE:</b>" in label.text())
        assert head.textFormat() == Qt.TextFormat.RichText
        assert "img" not in _Tags(head.text()).tags
        summary = next(label for label in dialogs[-1].findChildren(QLabel) if "Potential fix available" in label.text())
        assert payload in summary.text() and summary.textFormat() == Qt.TextFormat.PlainText
        dashboard._apply_fix("CVE-2026-1234", analysis)
        summary = next(label for label in dialogs[-1].findChildren(QLabel) if label.text() == payload)
        assert summary.textFormat() == Qt.TextFormat.PlainText
    finally:
        dashboard.close()


def test_threat_notice_and_rollback_confirmation_are_plain(monkeypatch, tmp_path):
    payload = _payload(tmp_path)
    notices = []
    monkeypatch.setattr(QMessageBox, "show", lambda box: notices.append(box))
    parent = QDialog()
    try:
        notice = threat_intel_page._plain_notice(parent, "Inert", payload)
        assert notice.textFormat() == Qt.TextFormat.PlainText and notice.text() == payload
        confirmations = []
        monkeypatch.setattr(QMessageBox, "exec", lambda box: confirmations.append(box) or QMessageBox.StandardButton.No)
        threat_intel_page.ThreatIntelDashboard._revert_fix(parent, payload)
        assert confirmations[0].textFormat() == Qt.TextFormat.PlainText
        assert payload in confirmations[0].text()
    finally:
        parent.close()


def test_top_talkers_prompt_delimits_and_bounds_process_and_ptr_input(monkeypatch):
    captured = []

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _maximum):
            return b'{"response":"inert recommendation"}'

    def open_fake(request, **_kwargs):
        captured.append(json.loads(request.data))
        return Response()

    monkeypatch.setattr(top_talkers, "safe_urlopen", open_fake)
    name, destination = "untrusted-process " * 200, "untrusted-ptr " * 200
    result = top_talkers.TopTalkersDialog._ask_ai(None, name, 1234, destination)
    assert result == "inert recommendation"
    prompt = captured[0]["prompt"]
    assert prompt.count("<<<BEGIN_TELEMETRY>>>") == 2
    assert name not in prompt and destination not in prompt
    assert len(prompt) < 2000
