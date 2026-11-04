from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import socket

import pytest

from angerona.core import spyware_news as news
from angerona.gui import spyware_guard_page as ui
from test_spyware_guard_page import make_page, news_rows
from test_spyware_news import citizen_index


NOW = datetime(2026, 11, 2, 15, tzinfo=timezone.utc).timestamp()


def news_card(*, title="Fixed publisher update", date="October 28, 2026",
              link="https://citizenlab.ca/fixed-publisher-update/", kind="post",
              summary="Publisher update discussing targeted advertising and zero-click spyware."):
    # The current official homepage shape, with synthetic article contents.
    return f'''<article class="content-card content-card--{kind} has-focus-area">
      <div class="content-card__content">
      <div class="content-card__content-type">News</div>
      <h2 class="content-card__title"><a href="{escape(link)}">{title}</a></h2>
      <div class="content-card__external-link"><a href="https://press.example/article/">External press</a></div>
      <div class="content-card__excerpt"><p>{summary}</p></div>
      <div class="content-card__date-focus-areas-wrapper">
      <div class="content-card__date">{date}</div></div></div></article>'''


def index(*cards):
    return "<!DOCTYPE html><html><body>" + "".join(cards) + "</body></html>"


def test_newer_publisher_updates_join_existing_research_without_external_link_selection(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("Parser attempted DNS"))
    rows = news.parse_citizen_lab_index(
        index(news_card(), citizen_index()), now=NOW)
    assert len(rows) == 2
    assert rows[0]["published"] == datetime(2026, 10, 28, tzinfo=timezone.utc).timestamp()
    assert rows[0]["url"] == "https://citizenlab.ca/fixed-publisher-update/"
    assert rows[0]["content_kind"] == "publisher-news"
    assert "content_kind" not in rows[1]
    assert all(row["verified_at"] == NOW and row["advisory_only"] is True for row in rows)
    assert not any("press.example" in row["url"] for row in rows)


@pytest.mark.parametrize("changes", [
    {"link": "https://press.example/spyware/"},
    {"link": "//citizenlab.ca/fixed-publisher-update/"},
    {"link": "https://citizenlab.ca/fixed-publisher-update/?next=external"},
    {"link": "https://citizenlab.ca/fixed-publisher-update/#fragment"},
    {"link": "https://citizenlab.ca/%2e%2e/spyware/"},
    {"date": "November 3, 2026"}, {"date": "September 1, 2026"},
    {"date": "October 99, 2026"}, {"kind": "event"},
])
def test_publisher_card_keeps_link_date_and_content_type_guards(changes):
    rows = news.parse_citizen_lab_index(index(news_card(**changes), citizen_index()), now=NOW)
    assert len(rows) == 1 and "content_kind" not in rows[0]


def test_unrecognized_homepage_is_unavailable_instead_of_successful_empty_refresh():
    with pytest.raises(ValueError, match="no recognized research or news cards"):
        news.parse_citizen_lab_index(index("<h1>Maintenance</h1>"), now=NOW)


def test_publisher_summary_is_bounded_plain_text_and_empty_eligible_result_is_still_valid():
    rows = news.parse_citizen_lab_index(index(news_card(
        summary="<b>Spyware update</b><script>never execute</script>\u202e" + "x" * 2000)), now=NOW)
    assert len(rows) == 1 and len(rows[0]["summary"]) <= news.MAX_NEWS_SUMMARY
    assert "never execute" not in rows[0]["summary"] and "\u202e" not in rows[0]["summary"]
    assert news.parse_citizen_lab_index(index(news_card(title="Publisher logistics", summary="Event schedule")), now=NOW) == []


def test_refresh_keeps_one_fixed_official_request_and_exact_network_opt_in(monkeypatch):
    calls = []

    def fetch(url, **kwargs):
        calls.append((url, kwargs))
        return index(news_card(), citizen_index()).encode(), "html"

    monkeypatch.setattr(news, "_fetch_https_report", fetch)
    for enabled in (False, None, 1, "true"):
        with pytest.raises(PermissionError):
            news.fetch_news_source("citizen_lab", network_enabled=enabled, now=NOW)
    assert not calls
    assert len(news.fetch_news_source("citizen_lab", network_enabled=True, now=NOW)) == 2
    assert calls == [("https://citizenlab.ca/", {"timeout": 15.0, "expected_format": "html"})]


def test_offline_news_settings_action_only_opens_existing_permission_controls():
    page, module = make_page(show=True)
    try:
        check = page.setting_checks["spyware_network_enabled"]
        assert not check.isChecked() and not page._settings_dirty
        page.news_settings_button.click()
        assert page.tabs.tabText(page.tabs.currentIndex()) == "Policy / Beacon"
        assert not check.isChecked() and not page._settings_dirty
        assert not page.config.spyware_network_enabled and not module.calls
        assert not page.news_refresh_button.isEnabled()
    finally:
        page.close()


def test_queued_check_never_advances_success_or_cache_dates_and_failures_remain_visible(monkeypatch):
    monkeypatch.setattr(ui.time, "time", lambda: NOW)
    page, module = make_page(show=True)
    try:
        module.snapshot["settings"]["spyware_network_enabled"] = True
        cached = news_rows(NOW)[0]
        module.snapshot.update(news=[cached], news_status={
            "state": "queued", "refreshing": True, "last_refresh": NOW - 3600,
            "queued_reason": "Waiting for module dispatch; priority scan is active.",
            "sources": {"citizen_lab": {"state": "available", "items": 1,
                                         "checked_at": NOW - 3600}}})
        page.refresh()
        assert "Refresh queued" in page.news_state.text()
        assert "Waiting for module dispatch" in page.news_checks.text()
        assert ui._news_checked_text(NOW - 3600, NOW) in page.news_checks.text()
        assert ui._news_checked_text(cached["verified_at"], NOW) in page.news_checks.text()
        assert not page.news_refresh_button.isEnabled()
        module.snapshot["news_status"] = {"state": "failed", "last_refresh": NOW - 3600,
            "last_attempt": NOW - 10, "error": "TimeoutError",
            "sources": {"citizen_lab": {"state": "failed", "checked_at": NOW - 10,
                                         "error": "TimeoutError"}}}
        page.refresh()
        assert page._news_items[0]["verified_at"] == cached["verified_at"]
        assert "Latest refresh error: TimeoutError" in page.news_checks.text()
        assert "Citizen Lab: failed" in page.news_sources.text()
        assert "attempt " + ui._news_checked_text(NOW - 10, NOW) in page.news_sources.text()
        assert page.news_refresh_button.isEnabled() and not module.calls
    finally:
        page.close()


def test_publisher_update_is_labelled_as_news_in_the_cached_brief(monkeypatch):
    monkeypatch.setattr(ui.time, "time", lambda: NOW)
    page, module = make_page(show=True)
    try:
        module.snapshot["settings"]["spyware_network_enabled"] = True
        module.snapshot["news"] = news.parse_citizen_lab_index(index(news_card()), now=NOW)
        page.refresh()
        assert "CACHED NEWS" in page.news_badge.text()
        page.news_headline.click()
        assert "publisher news/update, not a new technical research report" in page.news_detail.toPlainText()
        assert not module.calls
    finally:
        page.close()


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), NOW + 1,
                                   pytest.param(10**1000, id="overflow-sized-stamp")])
def test_invalid_check_timestamps_are_not_presented_as_recent_success(value):
    assert ui._news_checked_text(value, NOW) == "not recorded"
    assert ui._news_age_text(value, NOW) == "age unavailable"
