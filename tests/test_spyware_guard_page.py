"""Exercise real offscreen widgets against an inert, queue-only module."""
from __future__ import annotations

import copy
import time
from types import SimpleNamespace

from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication

from angerona.core.spyware_catalog import CATALOG_REVIEWED, SPYWARE_PROFILES
from angerona.gui.spyware_guard_page import SpywareGuardPage


class FakeModule:
    def __init__(self):
        self.calls = []
        self.reads = 0
        self.status = "running"
        self.snapshot = {
            "hits": [], "containments": [], "indicators": [], "sources": [],
            "coverage": {"memory": "disabled", "credential_interception": "not implemented"},
            "beacon": {"enabled": False, "delivery": "not attempted"},
            "settings": {
                "spyware_auto_contain": True,
                "spyware_network_enabled": False,
                "spyware_memory_enabled": False,
                "spyware_beacon_enabled": False,
                "spyware_beacon_channel": True,
                "spyware_beacon_signal": False,
            },
        }

    def dashboard_snapshot(self):
        self.reads += 1
        return copy.deepcopy(self.snapshot)

    def request_scan(self):
        self.calls.append(("scan",))
        return True

    def queue_report_url(self, url):
        self.calls.append(("url", url))
        return True

    def review_indicator(self, kind, value, approved=True):
        self.calls.append(("review", kind, value, approved))
        return True

    def run_sandbox(self, scenario):
        self.calls.append(("sandbox", scenario))
        return True

    def configure_settings(self, **kwargs):
        self.calls.append(("settings", kwargs))
        return {"queued": True}

    def request_news_refresh(self):
        self.calls.append(("news",))
        return True

    def queue_rule_export(self):
        self.calls.append(("rules",))
        return True


def make_page(*, show=False):
    module = FakeModule()
    config = SimpleNamespace(**module.snapshot["settings"])
    page = SpywareGuardPage(SimpleNamespace(modules={"SpywareGuard": module}), config, None)
    if show:
        page.show()
        QApplication.instance().processEvents()
    return page, module


def test_construction_and_opening_never_fetch_scan_or_change_policy():
    page, module = make_page()
    try:
        assert module.reads == 0
        assert module.calls == []
        assert not page._timer.isActive()
        page.show()
        QApplication.instance().processEvents()
        assert module.reads >= 1
        assert module.calls == []
        assert page._timer.interval() == 3000
        assert page._timer.isActive()
    finally:
        page.close()


def test_url_fetch_requires_explicit_click_and_basic_https_validation():
    page, module = make_page(show=True)
    try:
        for value in ("http://example.com/report", "https://u:p@example.com/report", "https://example.com/#token", "https://[bad"):
            page.report_url.setText(value)
            page.ingest_button.click()
        assert module.calls == []
        page.report_url.setText("https://citizenlab.ca/research/report/")
        QApplication.instance().processEvents()
        assert module.calls == []
        page.ingest_button.click()
        assert module.calls == [("url", "https://citizenlab.ca/research/report/")]
        assert page.report_url.text() == ""
        assert "queued" in page.status.text()
    finally:
        page.close()


def test_single_rule_policy_and_beacon_only_change_on_apply():
    page, module = make_page(show=True)
    try:
        assert page.setting_checks["spyware_auto_contain"].isChecked()
        page.setting_checks["spyware_beacon_enabled"].setChecked(True)
        page.setting_checks["spyware_beacon_signal"].setChecked(True)
        page.refresh()
        assert page.setting_checks["spyware_beacon_enabled"].isChecked()
        assert module.calls == []
        page.save_button.click()
        method, settings = module.calls[-1]
        assert method == "settings"
        assert settings["spyware_beacon_enabled"] is True
        assert settings["spyware_beacon_signal"] is True
        assert settings["spyware_auto_contain"] is True
        page.refresh()  # An older snapshot cannot undo an unconfirmed queued edit.
        assert page.setting_checks["spyware_beacon_enabled"].isChecked()
        module.snapshot["settings"].update(settings)
        page.refresh()
        assert not page._settings_dirty
        assert page._pending_settings is None
    finally:
        page.close()


def test_recent_evidence_is_bounded_plaintext_and_selection_is_stable():
    page, module = make_page(show=True)
    try:
        hostile = '<img src="https://example.com/track"><b>evidence</b>'
        module.snapshot["hits"] = [{"rule": hostile, "pid": index, "severity": "HIGH"} for index in reversed(range(250))]
        module.snapshot["containments"] = [{"target": hostile, "status": "failed", "error": "Denied"}]
        module.snapshot["beacon"] = {"status": hostile}
        page.refresh()
        assert page.hits_table.rowCount() == 200
        assert page.hits_table.item(0, 2).text() == "249"
        assert page.hits_table.item(0, 1).text() == hostile
        page.hits_table.selectRow(3)
        assert hostile.replace('"', '\\"') in page.evidence_detail.toPlainText()
        assert page.beacon_status.textFormat() == Qt.TextFormat.PlainText
        assert hostile.replace('"', '\\"') in page.beacon_status.text()
        module.snapshot["hits"].insert(0, {"rule": "new", "pid": 999})
        page.refresh()
        assert page.hits_table.currentRow() == 4
        assert page.containments_table.item(0, 2).text() == "failed"
    finally:
        page.close()


def test_indicator_review_uses_selected_exact_value_and_source_provenance():
    page, module = make_page(show=True)
    try:
        module.snapshot["indicators"] = [
            {"kind": "domain", "value": "example.invalid", "approved": False,
             "source_url": "https://research.example/report"},
        ]
        page.refresh()
        page.approve_button.click()
        assert module.calls == []
        page.indicators_table.selectRow(0)
        page.approve_button.click()
        page.reject_button.click()
        assert module.calls == [
            ("review", "domain", "example.invalid", True),
            ("review", "domain", "example.invalid", False),
        ]
        assert page.indicators_table.item(0, 3).text() == "https://research.example/report"
        assert "review required" in page.indicators_table.item(0, 2).text()
    finally:
        page.close()


def test_real_module_receipt_shape_is_visible_before_requested_rows():
    page, module = make_page(show=True)
    try:
        module.snapshot["stats"] = {"findings": 412}
        module.snapshot["containments"] = [
            {"created_at": 1_792_598_400.0, "target": "local-host", "status": "applied", "action": "isolate_host"},
        ] + [{"ts": index, "targets": {"pid": 123}, "status": "requested", "actions": ["suspend_process"]} for index in range(250)]
        page.refresh()
        assert page.containments_table.rowCount() == 200
        assert page.containments_table.item(0, 1).text() == "local-host"
        assert page.containments_table.item(0, 2).text() == "applied"
        assert page.containments_table.item(0, 3).text() == "isolate_host"
        assert "123" in page.containments_table.item(1, 1).text()
        assert "suspend_process" in page.containments_table.item(1, 3).text()
        assert "Hits: 412" in page.stats.text()
    finally:
        page.close()


def test_rehearsals_are_explicit_and_use_fixed_scenarios():
    page, module = make_page(show=True)
    try:
        assert module.calls == []
        for index in range(page.sandbox_scenario.count()):
            page.sandbox_scenario.setCurrentIndex(index)
            page.sandbox_button.click()
        assert module.calls == [
            ("sandbox", "dns_tunnel"), ("sandbox", "exfiltration"),
            ("sandbox", "renderer_escape"),
        ]
        module.snapshot["sandbox_results"] = [{"simulation": True, "scenario": "dns_tunnel", "outcome": "detected"}]
        page.refresh()
        assert '"simulation": true' in page.sandbox_results.toPlainText()
    finally:
        page.close()


def test_hidden_or_closed_page_does_not_poll_and_deletion_stops_timer():
    page, module = make_page(show=True)
    page.hide()
    QApplication.instance().processEvents()
    reads = module.reads
    assert not page._timer.isActive()
    page.refresh()
    assert module.reads == reads
    page.show()
    QApplication.instance().processEvents()
    assert page._timer.isActive()
    page.close()
    assert not page._timer.isActive()
    reads = module.reads
    page.refresh()
    assert module.reads == reads
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_missing_module_keeps_guide_available_and_commands_disabled():
    page = SpywareGuardPage(SimpleNamespace(modules={}), SimpleNamespace(), None)
    try:
        page.show()
        assert not page.scan_button.isEnabled()
        assert not page.ingest_button.isEnabled()
        assert page.guide_choice.count() == len(SPYWARE_PROFILES)
        assert "unavailable" in page.status.text()
        assert "2026-10-21" in page.guide_detail.toPlainText()
    finally:
        page.close()


def test_primary_source_navigation_requires_explicit_action(monkeypatch):
    from angerona.gui import spyware_guard_page as ui

    opened = []
    monkeypatch.setattr(ui.QDesktopServices, "openUrl", lambda url: opened.append(url.toString()))
    page, _module = make_page(show=True)
    try:
        page.guide_choice.setCurrentIndex(1)
        assert opened == []
        page.guide_source_button.click()
        assert opened == [SPYWARE_PROFILES[1].source_url]
        assert "local match" in ui.CATALOG_SCOPE
        assert CATALOG_REVIEWED in page.guide_detail.toPlainText()
    finally:
        page.close()


def test_settings_navigation_targets_existing_destination_setup():
    from PySide6.QtWidgets import QPushButton

    page, module = make_page(show=True)
    requested = []
    page.settings_requested.connect(requested.append)
    try:
        for button in page.findChildren(QPushButton):
            if button.text().startswith("Configure "):
                button.click()
        assert requested == ["Integrations", "Mobile Integration"]
        assert module.calls == []
    finally:
        page.close()


def news_rows(now):
    return [
        {"title": "New spyware exploit investigation " * 8,
         "url": "https://citizenlab.ca/research/new-analysis/", "source": "citizen_lab",
         "published": now - 86400, "verified_at": now - 100},
        {"title": "Browser zero-day and sandbox escape analysis",
         "url": "https://projectzero.google/2026/10/new-analysis.html", "source": "project_zero",
         "published": now - 2 * 86400, "verified_at": now - 100},
    ]


def test_news_strip_is_offline_until_opt_in_and_refresh_is_explicit(monkeypatch):
    page, module = make_page(show=True)
    try:
        assert "offline" in page.news_headline.text()
        assert not page.news_refresh_button.isEnabled()
        page._request_news_refresh()
        assert module.calls == []
        module.snapshot["settings"]["spyware_network_enabled"] = True
        page.refresh()
        assert page.news_refresh_button.isEnabled()
        assert module.calls == []
        page.news_refresh_button.click()
        assert module.calls == [("news",)]
        assert page._news_refreshing
        assert "queued" in page.news_headline.text()
    finally:
        page.close()


def test_news_rotation_marquee_pause_hidden_and_reduced_motion(monkeypatch):
    from angerona.gui import spyware_guard_page as ui
    monkeypatch.setattr(ui, "motion_allowed", lambda config: getattr(config, "ui_motion_enabled", True))
    page, module = make_page(show=True)
    try:
        page.resize(810, 460)
        module.snapshot["settings"]["spyware_network_enabled"] = True
        module.snapshot["news"] = news_rows(time.time())
        module.snapshot["news_status"] = {"state": "refreshing", "refreshing": True}
        page.refresh()
        QApplication.instance().processEvents()
        page._sync_news_motion()
        assert page._news_rotation_timer.isActive()
        assert page._news_scroll_timer.isActive()
        assert page.news_spinner._timer.isActive()
        bar = page.news_scroll.horizontalScrollBar()
        page._scroll_news()
        assert bar.value() > 0
        page.news_pause_button.click()
        assert not page._news_rotation_timer.isActive()
        assert not page._news_scroll_timer.isActive()
        assert not page.news_spinner._timer.isActive()
        page.news_pause_button.click()
        assert page._news_rotation_timer.isActive()
        page.hide()
        assert not page._news_rotation_timer.isActive()
        assert not page._news_scroll_timer.isActive()
        assert not page.news_spinner._timer.isActive()
        page.show()
        page.config.ui_motion_enabled = False
        page.refresh()
        assert not page._news_rotation_timer.isActive()
        assert not page._news_scroll_timer.isActive()
        assert not page.news_spinner._timer.isActive()
        assert page.news_headline.isEnabled()  # Static source links remain usable.
    finally:
        page.close()


def test_news_headline_and_source_date_link_map_to_current_validated_article(monkeypatch):
    from angerona.gui import spyware_guard_page as ui
    opened = []
    monkeypatch.setattr(ui.QDesktopServices, "openUrl", lambda url: opened.append(url.toString()))
    page, module = make_page(show=True)
    try:
        module.snapshot["settings"]["spyware_network_enabled"] = True
        rows = news_rows(time.time())
        module.snapshot["news"] = rows
        page.refresh()
        assert opened == []
        page.news_headline.click()
        page.news_source_button.click()
        page._rotate_news()
        page.news_source_button.click()
        assert opened == [rows[0]["url"], rows[0]["url"], rows[1]["url"]]
        assert "Project Zero" in page.news_source_button.text()
        assert module.calls == []
    finally:
        page.close()


def test_stale_future_unverified_and_unsafe_news_do_not_appear(monkeypatch):
    page, module = make_page(show=True)
    try:
        now = time.time()
        good = news_rows(now)[0]
        module.snapshot["settings"]["spyware_network_enabled"] = True
        module.snapshot["news"] = [dict(good, published=now - 31 * 86400),
                                   dict(good, published=now + 100),
                                   dict(good, verified_at=None),
                                   dict(good, url="https://127.0.0.1/admin")]
        page.refresh()
        assert not page._news_items
        assert "No verified" in page.news_headline.text()
        assert not page.news_source_button.isVisible()
        assert not page._news_rotation_timer.isActive()
        module.snapshot["news_status"] = {"state": "failed", "error": "source unavailable"}
        page.refresh()
        assert "failed" in page.news_headline.text()
    finally:
        page.close()


def test_rule_export_is_explicit_queue_only_action():
    page, module = make_page(show=True)
    try:
        assert module.calls == []
        page.export_rules_button.click()
        assert module.calls == [("rules",)]
        assert "Inactive rule candidates" in page.status.text()
    finally:
        page.close()
