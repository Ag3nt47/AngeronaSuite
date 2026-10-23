from __future__ import annotations

import io
import socket
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import pytest

from angerona.core import spyware_intel as intel
from angerona.core import spyware_news as news


NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc).timestamp()
ARTICLE = "https://citizenlab.ca/research/spyware-analysis/"


def rss_item(*, title="Spyware exploit analysis", link=ARTICLE, stamp=NOW - 86400):
    date = format_datetime(datetime.fromtimestamp(stamp, timezone.utc)) if isinstance(stamp, (int, float)) else stamp
    return f"<item><title>{escape(title)}</title><link>{escape(link)}</link><pubDate>{escape(date)}</pubDate></item>"


def rss(*items):
    return "<rss version='2.0'><channel>" + "".join(items) + "</channel></rss>"


def project_zero_item(*, title="How to fix a bug in a fix", date="2026-Oct-06",
                      link="/2026/10/emergency-patching.html",
                      summary="Research on fast vendor fixes for urgent vulnerabilities."):
    # The official homepage uses visible day-precision metadata rather than a
    # time element; significant context can occur in the snippet, not title.
    return f"""<article class="grid">
      <div class="post-title"><a href="{escape(link, {'"': '&quot;'})}">{title}</a></div>
      <div class="post-meta"><a class="post-date" href="{escape(link, {'"': '&quot;'})}"
        title="Permalink to this post">{date}</a><span class="post-author">Researcher</span></div>
      <div class="top-space"><br></div><br>
      <section class="post-content-snippet"><p>{summary}</p>
        <div class="expand-post-link"><br><a class="more-link" href="/archive.html">read more</a></div>
      </section></article>"""


def project_zero_index(*items):
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<script>window.spyware = 'vulnerability';</script></head><body>"
            "<header><a href='/archive.html'>archive</a></header><main class='post-content'>"
            + "".join(items) + "</main></body></html>")


def citizen_index(*, title="Pegasus attacks on Serbian pro-democracy figures", date="October 19, 2026",
                  link="https://citizenlab.ca/research/pegasus-spyware-serbian-pro-democracy/",
                  summary="Research distinguishes Pegasus infection evidence from threat notifications."):
    return f'''<!DOCTYPE html><html><body><div class="nua-home-slider-mobile__slide">
      <h2 class="nua-home-slider-mobile__slide-title"><a href="{escape(link)}">Research</a></h2>
      <h3 class="nua-home-slider-mobile__slide-subtitle"><a href="{escape(link)}">{title}</a></h3>
      <p class="nua-home-slider-mobile__slide-excerpt">{summary}</p>
      <p class="nua-home-slider-mobile__slide-date">{date}</p></div></body></html>'''


def test_rss_filters_significance_deduplicates_links_and_orders_by_published():
    raw = rss(
        rss_item(title="Research event logistics", link="https://citizenlab.ca/research/event/"),
        rss_item(stamp=NOW - 5000),
        rss_item(title="Updated spyware exploit analysis", stamp=NOW - 1000),
        rss_item(title="Browser vulnerability investigation", link="https://citizenlab.ca/research/browser/", stamp=NOW - 2000),
    )
    rows = news.parse_news_feed(raw, source_name="citizen_lab", now=NOW)
    assert len(rows) == 2
    assert rows[0] == {"title": "Updated spyware exploit analysis", "url": ARTICLE,
                       "published": NOW - 1000, "source": "citizen_lab", "verified_at": NOW,
                       "summary": "", "advisory_only": True}
    assert rows[1]["title"] == "Browser vulnerability investigation"


def test_atom_uses_alternate_article_link_and_aware_published_date():
    raw = """<feed xmlns='http://www.w3.org/2005/Atom'><entry>
      <title>Zero-click exploitation &amp; sandbox escape</title>
      <link rel='self' href='https://projectzero.google/feed.xml'/>
      <link rel='alternate' type='text/html' href='https://projectzero.google/2026/10/analysis.html'/>
      <published>2026-10-20T12:00:00Z</published><updated>2026-10-21T10:00:00Z</updated>
    </entry></feed>"""
    rows = news.parse_news_feed(raw, source_name="project_zero", now=NOW)
    assert rows[0]["url"] == "https://projectzero.google/2026/10/analysis.html"
    assert rows[0]["published"] == NOW - 86400
    assert rows[0]["title"] == "Zero-click exploitation & sandbox escape"


@pytest.mark.parametrize("date", ["2026-10-22T00:00:00Z", "2026-08-01T00:00:00Z",
                                    "not a date", "2026-10-20T12:00:00", "Tue, 20 Oct 2026 12:00:00"])
def test_invalid_future_stale_or_unzoned_dates_cannot_be_fresh_news(date):
    assert not news.parse_news_feed(rss(rss_item(stamp=date)), source_name="citizen_lab", now=NOW)


def test_freshness_boundary_and_clock_are_strict():
    assert len(news.parse_news_feed(rss(rss_item(stamp=NOW - news.MAX_NEWS_AGE)), source_name="citizen_lab", now=NOW)) == 1
    assert not news.parse_news_feed(rss(rss_item(stamp=NOW - news.MAX_NEWS_AGE - 1)), source_name="citizen_lab", now=NOW)
    assert not news.parse_news_feed(rss(rss_item(stamp=NOW + 1)), source_name="citizen_lab", now=NOW)
    for clock in (True, float("nan"), float("inf"), -1, "now"):
        with pytest.raises(ValueError, match="timestamp"):
            news.parse_news_feed(rss(), source_name="citizen_lab", now=clock)


@pytest.mark.parametrize("unsafe", [
    "<!DOCTYPE rss><rss><channel/></rss>",
    "<!DOCTYPE rss [<!ENTITY leak SYSTEM 'file:///C:/secret'>]><rss><channel><title>&leak;</title></channel></rss>",
    "<!DOCTYPE rss [<!ENTITY x 'bomb'>]><rss><channel><title>&x;</title></channel></rss>",
    "<!DOCTYPE rss SYSTEM 'https://example.com/evil.dtd'><rss><channel/></rss>",
    "<rss><channel>",
])
def test_unsafe_or_malformed_xml_rejects_whole_feed_without_resolution(unsafe, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("XML attempted DNS"))
    with pytest.raises(ValueError, match="unsafe or malformed"):
        news.parse_news_feed(unsafe, source_name="citizen_lab", now=NOW)
    with pytest.raises(ValueError, match="unsafe or malformed"):
        news.parse_news_feed(unsafe.encode("utf-16"), source_name="citizen_lab", now=NOW)


@pytest.mark.parametrize("url", [
    "http://citizenlab.ca/research/article/", "https://example.com/research/article/",
    "https://evil.citizenlab.ca/research/article/", "https://127.0.0.1/research/article/",
    "https://citizenlab.ca@evil.example/research/article/", "https://u:p@citizenlab.ca/research/article/",
    "https://citizenlab.ca:444/research/article/", "https://citizenlab.ca/research/article/#token",
    "https://citizenlab.ca/research/article/?redirect=https://evil.example",
    "https://citizenlab.ca/research/../admin/", "https://citizenlab.ca/research/%2e%2e/admin/",
    "https://citizenlab.ca/research/%252e%252e%252fadmin/",
    "https://citizenlab.ca/research/article%5cother/", "https://citizenlab.ca/research/%00article/",
    "https://citizenlab.ca/feed/", "https://citizenlab.ca/wp-admin/", "//citizenlab.ca/research/article/",
])
def test_article_links_reject_traversal_external_or_noncanonical_urls(url):
    with pytest.raises(ValueError):
        news.safe_news_article_url(url, "citizen_lab")
    assert not news.parse_news_feed(rss(rss_item(link=url)), source_name="citizen_lab", now=NOW)


def test_article_syntax_validation_never_resolves_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("link validation resolved DNS"))
    assert news.safe_news_article_url("https://CITIZENLAB.ca:443/research/article/", "citizen_lab") == "https://citizenlab.ca/research/article/"
    assert news.safe_news_article_url("https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-example", "cisa")
    with pytest.raises(ValueError, match="unknown"):
        news.safe_news_article_url(ARTICLE, "untrusted")


@pytest.mark.parametrize("path", [
    "/news-events/alerts/2026/09/08/cisa-adds-four-known-exploited-vulnerabilities-catalog",
    "/news-events/alerts/2024/02/29/leap-day-vulnerability/",
    "/news-events/alerts/undated-vulnerability",
    "/news-events/cybersecurity-advisories/aa26-example/",
    "/news-events/analysis-reports/ar26-example",
])
def test_cisa_accepts_dated_alerts_and_existing_undated_categories_without_dns(path, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("link validation resolved DNS"))
    url = "https://www.cisa.gov" + path
    assert news.safe_news_article_url(url, "cisa") == url


@pytest.mark.parametrize("date", [
    "0000/01/01", "1900/02/29", "2025/02/29", "2026/02/30", "2026/00/01",
    "2026/13/01", "2026/09/00", "2026/09/31", "2026/9/08", "2026/09/8",
    "２０２６/09/08",
])
def test_cisa_dated_alert_requires_a_canonical_valid_calendar_date(date):
    url = f"https://www.cisa.gov/news-events/alerts/{date}/vulnerability"
    with pytest.raises(ValueError):
        news.safe_news_article_url(url, "cisa")
    assert not news.parse_news_feed(rss(rss_item(link=url)), source_name="cisa", now=NOW)


@pytest.mark.parametrize("url", [
    "https://www.cisa.gov/news-events/cybersecurity-advisories/2026/09/08/vulnerability",
    "https://www.cisa.gov/news-events/analysis-reports/2026/09/08/vulnerability",
    "https://www.cisa.gov/news-events/other/2026/09/08/vulnerability",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/",
    "https://www.cisa.gov/news-events/alerts/2026/09/08//vulnerability",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/vulnerability/extra",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/../vulnerability",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/%252e%252e/vulnerability",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/vulnerability%5cother",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/%00vulnerability",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/vulnerability?redirect=https://evil.example",
    "https://www.cisa.gov/news-events/alerts/2026/09/08/vulnerability#token",
    "http://www.cisa.gov/news-events/alerts/2026/09/08/vulnerability",
    "https://evil.cisa.gov/news-events/alerts/2026/09/08/vulnerability",
    "https://www.cisa.gov:444/news-events/alerts/2026/09/08/vulnerability",
])
def test_cisa_dated_alert_preserves_category_path_and_https_boundaries(url):
    with pytest.raises(ValueError):
        news.safe_news_article_url(url, "cisa")
    assert not news.parse_news_feed(rss(rss_item(link=url)), source_name="cisa", now=NOW)


def test_cisa_dated_alert_feed_keeps_publication_freshness_and_advisory_only(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("feed parser resolved DNS"))
    monkeypatch.setattr(news, "_fetch_https_report", lambda *_a, **_k: pytest.fail("feed parser fetched"))
    url = "https://www.cisa.gov/news-events/alerts/2026/09/08/cisa-adds-four-known-exploited-vulnerabilities-catalog"
    published = datetime(2026, 9, 8, 12, tzinfo=timezone.utc).timestamp()
    title = "CISA Adds Four Known Exploited Vulnerabilities to Catalog"
    raw = rss(rss_item(title=title, link=url, stamp=published))
    rows = news.parse_news_feed(raw, source_name="cisa", now=published + 86400)
    assert rows == [{"title": title, "url": url, "published": published, "source": "cisa",
                     "verified_at": published + 86400, "summary": "", "advisory_only": True}]
    assert news.parse_news_feed(raw, source_name="cisa", now=published + news.MAX_NEWS_AGE + 1) == []
    assert news.parse_news_feed(raw, source_name="cisa", now=published - 1) == []


def test_citizen_lab_current_root_slug_articles_are_accepted_without_navigation_endpoints(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("link validation resolved DNS"))
    article = "https://citizenlab.ca/the-secrets-of-a-us-spyware-king/"
    assert news.safe_news_article_url(article, "citizen_lab") == article
    rows = news.parse_news_feed(rss(rss_item(link=article, stamp="Thu, 08 Oct 2026 12:00:00 +0000")),
                                source_name="citizen_lab", now=NOW)
    assert len(rows) == 1 and rows[0]["url"] == article
    for path in ("feed", "feeds", "wp-admin", "wp-json", "wp-login.php", "wp-content",
                 "wp-includes", "about", "contact-us", "category", "author", "research",
                 "comments", "privacy-policy", "login", "admin", "sitemap.xml", "a/b"):
        with pytest.raises(ValueError):
            news.safe_news_article_url(f"https://citizenlab.ca/{path}/", "citizen_lab")


def test_project_zero_html_matches_real_homepage_structure_and_utc_day_metadata(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("HTML parsing resolved DNS"))
    raw = project_zero_index(project_zero_item())
    rows = news.parse_project_zero_index(raw, now=NOW)
    assert rows == [{"title": "How to fix a bug in a fix",
                     "url": "https://projectzero.google/2026/10/emergency-patching.html",
                     "published": datetime(2026, 10, 6, tzinfo=timezone.utc).timestamp(),
                     "source": "project_zero", "verified_at": NOW,
                     "summary": "Research on fast vendor fixes for urgent vulnerabilities.", "advisory_only": True}]
    assert news.parse_project_zero_index(raw.encode(), now=NOW) == rows


def test_project_zero_html_keeps_freshness_significance_dedupe_and_plain_title_filters():
    raw = project_zero_index(
        project_zero_item(title="<b>Updated</b> fix \u202eanalysis", date="2026-Oct-20"),
        project_zero_item(),
        project_zero_item(title="Spyware old analysis", date="2026-Sep-20", link="/2026/09/old.html"),
        project_zero_item(title="Spyware future analysis", date="2026-Oct-22", link="/2026/10/future.html"),
        project_zero_item(title="Research social event", summary="Venue and travel.", link="/2026/10/event.html"),
        project_zero_item(title="Research social event", summary="<script>spyware exploitation</script>",
                          link="/2026/10/script.html"),
        project_zero_item(title="Research social event", summary="<style>spyware vulnerability</style>",
                          link="/2026/10/style.html"),
    )
    rows = news.parse_project_zero_index(raw, now=NOW)
    assert len(rows) == 1 and rows[0]["title"] == "Updated fix analysis"
    assert rows[0]["published"] == datetime(2026, 10, 20, tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("link", [
    "https://evil.example/2026/10/analysis.html", "//evil.example/2026/10/analysis.html",
    "http://projectzero.google/2026/10/analysis.html", "/archive.html", "/feed.xml",
    "/2026/10/../09/analysis.html", "/2026/10/%2e%2e/09/analysis.html",
    "/2026/10/article.html?redirect=https://evil.example", "/2026/10/article.html#token",
    "https://projectzero.google:444/2026/10/analysis.html", "/2026/10/article%5cother.html",
])
def test_project_zero_html_links_use_the_same_article_policy_without_normalizing_traversal(link):
    assert not news.parse_project_zero_index(project_zero_index(project_zero_item(link=link)), now=NOW)


@pytest.mark.parametrize("date", ["not a date", "2026-10-20", "2026-Oct-32", "2026-Xxx-20", "2026-oct-20"])
def test_project_zero_html_invalid_dates_are_skipped(date):
    assert not news.parse_project_zero_index(project_zero_index(project_zero_item(date=date)), now=NOW)


def test_project_zero_html_parser_is_bounded_and_never_evaluates_declarations(monkeypatch):
    raw = project_zero_index(project_zero_item())
    monkeypatch.setattr(news, "MAX_NEWS_BYTES", len(raw.encode()) - 1)
    with pytest.raises(ValueError, match="byte bound"):
        news.parse_project_zero_index(raw, now=NOW)
    monkeypatch.setattr(news, "MAX_NEWS_BYTES", 100_000)
    monkeypatch.setattr(news, "MAX_XML_NODES", 5)
    with pytest.raises(ValueError, match="node bound"):
        news.parse_project_zero_index(raw, now=NOW)
    monkeypatch.setattr(news, "MAX_XML_NODES", 1000)
    with pytest.raises(ValueError, match="depth bound"):
        news.parse_project_zero_index("<div>" * (news.MAX_HTML_DEPTH + 1), now=NOW)
    with pytest.raises(ValueError, match="attribute bound"):
        news.parse_project_zero_index("<div title='" + "x" * 8193 + "'>", now=NOW)
    with pytest.raises(ValueError, match="unsupported"):
        news.parse_project_zero_index("<!DOCTYPE html [<!ENTITY x SYSTEM 'file:///secret'>]>", now=NOW)
    with pytest.raises(ValueError, match="malformed"):
        news.parse_project_zero_index(b"\xff", now=NOW)
    monkeypatch.setattr(news, "MAX_FEED_ENTRIES", 2)
    monkeypatch.setattr(news, "MAX_NEWS_ITEMS", 1)
    raw = project_zero_index(*(project_zero_item(link=f"/2026/10/item-{i}.html", date=f"2026-Oct-{10+i}")
                               for i in range(4)))
    rows = news.parse_project_zero_index(raw, now=NOW)
    assert len(rows) == 1 and rows[0]["url"].endswith("item-1.html")


def test_titles_are_plain_and_control_characters_are_removed():
    raw = rss(rss_item(title="<b>Spyware</b>\u202e exploit report"))
    rows = news.parse_news_feed(raw, source_name="citizen_lab", now=NOW)
    assert rows[0]["title"] == "Spyware exploit report"


def test_bytes_nodes_entry_and_output_counts_are_bounded(monkeypatch):
    monkeypatch.setattr(news, "MAX_NEWS_BYTES", 100)
    with pytest.raises(ValueError, match="byte bound"):
        news.parse_news_feed("x" * 101, source_name="citizen_lab", now=NOW)
    monkeypatch.setattr(news, "MAX_NEWS_BYTES", 100_000)
    monkeypatch.setattr(news, "MAX_XML_NODES", 5)
    with pytest.raises(ValueError, match="node bound"):
        news.parse_news_feed(rss(rss_item()), source_name="citizen_lab", now=NOW)
    monkeypatch.setattr(news, "MAX_XML_NODES", 1000)
    monkeypatch.setattr(news, "MAX_FEED_ENTRIES", 2)
    monkeypatch.setattr(news, "MAX_NEWS_ITEMS", 1)
    raw = rss(*(rss_item(link=f"https://citizenlab.ca/research/item-{i}/", stamp=NOW - 1000 + i) for i in range(5)))
    rows = news.parse_news_feed(raw, source_name="citizen_lab", now=NOW)
    assert len(rows) == 1 and rows[0]["url"].endswith("item-1/")


def test_news_fetch_requires_exact_opt_in_and_fixed_official_source(monkeypatch):
    calls = []
    def fetch(url, **kwargs):
        calls.append((url, kwargs))
        return citizen_index().encode(), "html"
    monkeypatch.setattr(news, "_fetch_https_report", fetch)
    for enabled in (False, None, 1, "true"):
        with pytest.raises(PermissionError):
            news.fetch_news_source("citizen_lab", network_enabled=enabled, now=NOW)
    with pytest.raises(ValueError, match="unknown"):
        news.fetch_news_source("https://evil.example/feed", network_enabled=True, now=NOW)
    assert calls == []
    rows = news.fetch_news_source("citizen_lab", network_enabled=True, now=NOW)
    assert len(rows) == 1
    assert calls == [("https://citizenlab.ca/", {"timeout": 15.0, "expected_format": "html"})]


def test_project_zero_fetch_uses_bounded_official_html_index_instead_of_archive(monkeypatch):
    calls = []
    def fetch(url, **kwargs):
        calls.append((url, kwargs))
        return project_zero_index(project_zero_item()).encode(), "html"
    monkeypatch.setattr(news, "_fetch_https_report", fetch)
    rows = news.fetch_news_source("project_zero", network_enabled=True, now=NOW)
    assert len(rows) == 1
    assert calls == [("https://projectzero.google/", {"timeout": 15.0, "expected_format": "html"})]


@pytest.mark.parametrize("mime", ["application/rss+xml", "application/atom+xml", "application/xml", "text/xml"])
def test_pinned_fetch_accepts_xml_only_when_explicitly_requested(monkeypatch, mime):
    requests = []
    class Response:
        status = 200
        def __init__(self):
            self.body = io.BytesIO(b"<rss><channel/></rss>")
        def getheader(self, name, default=None):
            return {"Content-Type": mime, "Content-Encoding": "identity"}.get(name, default)
        def read1(self, size):
            return self.body.read(size)
    class Connection:
        sock = None
        def __init__(self, *_args): pass
        def request(self, *args, **kwargs): requests.append((args, kwargs))
        def getresponse(self): return Response()
        def abort(self): pass
        def close(self): pass
    monkeypatch.setattr(intel, "_public_address", lambda *_args: "1.1.1.1")
    monkeypatch.setattr(intel, "_PinnedHTTPSConnection", Connection)
    assert intel._fetch_https_report(news.NEWS_SOURCES["citizen_lab"], timeout=1, expected_format="xml")[1] == "xml"
    assert "application/rss+xml" in requests[0][1]["headers"]["Accept"]
    with pytest.raises(ValueError, match="format"):
        intel._fetch_https_report(news.NEWS_SOURCES["citizen_lab"], timeout=1)
    with pytest.raises(ValueError, match="format"):
        intel._fetch_https_report(news.NEWS_SOURCES["citizen_lab"], timeout=1, expected_format="html")


def test_offline_selftest_never_fetches(monkeypatch):
    monkeypatch.setattr(news, "_fetch_https_report", lambda *_a, **_k: pytest.fail("self-test fetched"))
    assert news.self_test()[0]


def test_citizen_lab_research_card_uses_current_shape_dates_and_bounded_plain_summary(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("index parser attempted DNS"))
    raw = citizen_index(summary="<b>Pegasus evidence</b> &amp; context <script>secret script</script>\u202e " + "a" * 1800)
    rows = news.parse_citizen_lab_index(raw, now=NOW)
    assert len(rows) == 1
    row = rows[0]
    assert row["published"] == datetime(2026, 10, 19, tzinfo=timezone.utc).timestamp()
    assert row["title"] == "Pegasus attacks on Serbian pro-democracy figures"
    assert row["summary"].startswith("Pegasus evidence & context")
    assert "secret script" not in row["summary"] and "\u202e" not in row["summary"]
    assert len(row["summary"]) <= news.MAX_NEWS_SUMMARY
    assert row["advisory_only"] is True


@pytest.mark.parametrize("changes", [{"date": "October 23, 2026"}, {"date": "September 01, 2026"},
    {"date": "October 99, 2026"}, {"link": "https://evil.example/research/spyware/"},
    {"title": "Research logistics", "summary": "<script>spyware exploit</script>"}])
def test_citizen_lab_index_keeps_date_link_and_significance_guards(changes):
    assert news.parse_citizen_lab_index(citizen_index(**changes), now=NOW) == []


def test_offline_references_have_fixed_review_dates_no_io_and_detached_data(monkeypatch):
    monkeypatch.setattr(news, "_fetch_https_report", lambda *_a, **_k: pytest.fail("offline reference fetched"))
    now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc).timestamp()
    rows = news.reference_news(now=now)
    assert len(rows) == 3
    assert {row["origin"] for row in rows} == {"bundled-reference"}
    assert all(row["advisory_only"] and row["reviewed"] == "2026-10-22" for row in rows)
    assert all(row["published"] <= row["verified_at"] <= now for row in rows)
    assert all(news.safe_news_article_url(row["url"], row["source"]) for row in rows)
    rows[0]["title"] = "changed"
    assert news.reference_news(now=now)[0]["title"] != "changed"
    assert news.reference_news(now=NOW) == []  # Do not claim a future editorial review.
