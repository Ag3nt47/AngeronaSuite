"""Bounded official research headlines for presentation, never detection rules.

The fetch path shares SpywareGuard's pinned public HTTPS transport. RSS/Atom and
the bounded Citizen Lab/Project Zero indexes are untrusted data: stale dates, unrelated
items, and unsafe article links are rejected. Article links are checked without
resolving DNS; only an explicit operator click opens the browser.
"""
from __future__ import annotations

import math
import re
import time
import unicodedata
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from types import MappingProxyType
from urllib.parse import unquote, urlsplit, urlunsplit

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from angerona.core.spyware_intel import _fetch_https_report
from angerona.core.url_policy import UrlPolicy, validate_url


MAX_NEWS_BYTES = 2 * 1024 * 1024
MAX_NEWS_ITEMS = 30
MAX_FEED_ENTRIES = 300
MAX_XML_NODES = 20_000
MAX_HTML_DEPTH = 64
MAX_NEWS_AGE = 30 * 86400
MAX_CACHED_NEWS_AGE = 180 * 86400
MAX_NEWS_SUMMARY = 1200
REFERENCE_REVIEWED = "2026-10-22"
NEWS_SOURCES = MappingProxyType({
    # Its general RSS stream omits current research reports. The homepage's
    # dated research cards include the reports without crawling article pages.
    "citizen_lab": "https://citizenlab.ca/",
    # The Atom endpoint contains the complete archive and exceeds the shared
    # transport limit. Its official recent-post index is small and bounded.
    "project_zero": "https://projectzero.google/",
    "cisa": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
})
NEWS_SOURCE_LABELS = MappingProxyType({
    "citizen_lab": "Citizen Lab", "project_zero": "Project Zero", "cisa": "CISA",
})
_SIGNIFICANT = re.compile(
    r"\b(?:spyware|surveillance|pegasus|candiru|graphite|paragon|predator|adfection|"
    r"forcedentry|exploit\w*|vulnerabilit\w*|zero[\s-]?(?:day|click)|0[\s-]?day|"
    r"CVE-\d{4}-\d{4,}|sandbox[\s-]escape)\b", re.IGNORECASE,
)
_ATOM = "http://www.w3.org/2005/Atom"
_DC = "http://purl.org/dc/elements/1.1/"
_CITIZEN_NONARTICLES = frozenset({
    "feed", "feeds", "rss", "rss2", "atom", "comments", "research", "about",
    "contact", "contact-us", "category", "tag", "author", "page", "search",
    "news", "events", "people", "publications", "privacy", "privacy-policy",
    "terms", "terms-of-use", "sitemap", "robots", "login", "admin",
})
_MONTHS = {month: index for index, month in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_LONG_MONTHS = {month: index for index, month in enumerate((
    "January", "February", "March", "April", "May", "June", "July", "August", "September",
    "October", "November", "December"), 1)}

# Reviewed primary-source reference briefs, not a simulated feed or detection
# indicators. They remain useful offline; their dates never advance at runtime.
_REFERENCE_BRIEFS = (
    ("citizen_lab", "2026-10-19", "Pegasus attacks on Serbian pro-democracy figures",
     "https://citizenlab.ca/research/pegasus-spyware-serbian-pro-democracy/",
     "Citizen Lab and the SHARE Foundation reported evidence of Pegasus infection involving a Serbian university leader, "
     "and a separate Apple threat notification involving a prosecutor. The report distinguishes confirmed infection "
     "from notification-based targeting evidence; it does not establish infection on this computer."),
    ("citizen_lab", "2026-10-15", "AdFection: targeted advertising used to deliver spyware",
     "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/",
     "Citizen Lab describes targeted advertising infrastructure associated with Discover-Tech/Controlium and delivery "
     "of Candiru spyware to Al Jazeera devices. Advertising exposure and a local heuristic alone do not identify an actor; "
     "review the original technical evidence and the local detector's coverage separately."),
    ("project_zero", "2026-10-06", "Emergency patching and the limits of urgent vulnerability fixes",
     "https://projectzero.google/2026/10/emergency-patching.html",
     "Project Zero reviews mechanisms vendors use to deliver urgent security fixes outside normal update cycles. "
     "The article concerns response and patch delivery design; it is not an announcement that this device is vulnerable "
     "or that a new spyware infection has been detected."),
)


def reference_news(*, now=None) -> list[dict]:
    """Return detached, honestly dated offline references; never perform I/O."""
    timestamp = _timestamp(now)
    reviewed = datetime.fromisoformat(REFERENCE_REVIEWED).replace(tzinfo=timezone.utc).timestamp()
    if timestamp < reviewed:
        return []
    return [{"source": source, "published": datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp(),
             "title": title, "url": safe_news_article_url(url, source), "summary": summary,
             "verified_at": reviewed, "origin": "bundled-reference", "reviewed": REFERENCE_REVIEWED,
             "advisory_only": True}
            for source, day, title, url, summary in _REFERENCE_BRIEFS]


def _timestamp(value) -> float:
    stamp = time.time() if value is None else value
    if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp <= 0:
        raise ValueError("invalid news timestamp")
    return float(stamp)


def safe_news_article_url(url: str, source_name: str) -> str:
    """Validate an official article link without network or redirect traversal."""
    feed = NEWS_SOURCES.get(source_name)
    if feed is None:
        raise ValueError("unknown official news source")
    expected_host = urlsplit(feed).hostname
    policy = UrlPolicy("official news article", frozenset({"https"}),
                       frozenset({expected_host}), resolve_addresses=False,
                       max_url_chars=2048)
    host = validate_url(url, policy)
    parsed = urlsplit(url)
    if (parsed.port not in (None, 443) or parsed.query or parsed.fragment
            or not parsed.hostname.isascii()):
        raise ValueError("news article must use a canonical public HTTPS link")
    path = parsed.path
    # Reject direct and recursively encoded traversal, control characters, and
    # path-separator tricks before the link can reach a browser.
    decoded = path
    for _ in range(4):
        if ("\\" in decoded or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded)
                or any(part in {".", ".."} for part in decoded.split("/"))):
            raise ValueError("news article path contains traversal")
        expanded = unquote(decoded, errors="strict")
        if expanded == decoded:
            break
        decoded = expanded
    else:
        raise ValueError("news article path is overencoded")
    if source_name == "citizen_lab":
        article = re.fullmatch(r"/(?:research/[^/]+|\d{4}/\d{2}/[^/]+)/?", decoded)
        if article is None:
            # Citizen Lab now also publishes canonical root-level slugs. Keep
            # WordPress, feed and navigation endpoints out of article links.
            root_slug = decoded.strip("/")
            if (root_slug not in _CITIZEN_NONARTICLES and not root_slug.startswith("wp-")
                    and len(root_slug) <= 200):
                article = re.fullmatch(r"/[a-z0-9]+(?:-[a-z0-9]+)*/?", decoded)
    elif source_name == "project_zero":
        article = re.fullmatch(r"/\d{4}/\d{2}/[^/]+/?", decoded)
    else:
        article = re.fullmatch(r"/news-events/(?:cybersecurity-advisories|alerts|analysis-reports)/[^/]+/?", decoded)
        if article is None:
            article = re.fullmatch(
                r"/news-events/alerts/([0-9]{4})/([0-9]{2})/([0-9]{2})/[^/]+/?", decoded)
            if article is not None:
                try:
                    datetime(int(article[1]), int(article[2]), int(article[3]))
                except ValueError:
                    article = None
    if article is None:
        raise ValueError("news link is not an official article path")
    return urlunsplit(("https", host, path, "", ""))


def _date(value: str) -> float | None:
    value = value.strip()
    if not value or len(value) > 100:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        stamp = parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return None
    return stamp if math.isfinite(stamp) and stamp > 0 else None


class _PlainSummary(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template", "noscript"}:
            self.ignored += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template", "noscript"}:
            self.ignored = max(0, self.ignored - 1)

    def handle_data(self, data):
        if not self.ignored:
            self.text.append(data)


def _plain(value: str, limit=260) -> str:
    # Titles remain plain text; discard markup and invisible/bidi controls so
    # the displayed source cannot be visually swapped by a feed entry.
    parser = _PlainSummary()
    parser.feed(value[:4096])
    parser.close()
    text = " ".join(parser.text)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in {"Cc", "Cf"})
    return " ".join(text.split())[:limit]


def _element_text(element) -> str:
    if element is None:
        return ""
    pieces = []
    total = 0
    for value in element.itertext():
        pieces.append(value[:4096 - total])
        total += len(pieces[-1])
        if total >= 4096:
            break
    return " ".join(pieces)


def _news_entry(title, summary, stamp, link, *, source_name, timestamp):
    title = _plain(title)
    summary = _plain(summary, MAX_NEWS_SUMMARY)
    summary = re.sub(r"\s+read more(?:\s*→)?\s*$", "", summary, flags=re.IGNORECASE)
    if (not title or stamp is None or stamp > timestamp or timestamp - stamp > MAX_NEWS_AGE
            or not _SIGNIFICANT.search(title + " " + summary)):
        return None
    try:
        url = safe_news_article_url(link.strip(), source_name)
    except (ValueError, UnicodeError):
        return None
    return {"title": title, "url": url, "published": stamp,
            "source": source_name, "verified_at": timestamp, "summary": summary,
            "advisory_only": True}


class _ProjectZeroIndexParser(HTMLParser):
    """Read only the official index's article fields; never load HTML assets."""

    _VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input",
                       "link", "meta", "param", "source", "track", "wbr"})
    _IGNORE = frozenset({"script", "style", "template", "noscript"})

    def __init__(self, source_name="project_zero"):
        super().__init__(convert_charrefs=True)
        self._citizen = source_name == "citizen_lab"
        self.entries = []
        self._stack = []
        self._article = None
        self._article_depth = 0
        self._nodes = 0
        self._count = 0

    def handle_decl(self, decl):
        if decl.strip().casefold() != "doctype html":
            raise ValueError("news HTML declaration is unsupported")

    def unknown_decl(self, data):
        raise ValueError("news HTML declaration is unsupported")

    def handle_starttag(self, tag, attrs):
        self._nodes += 1
        if self._nodes > MAX_XML_NODES:
            raise ValueError("news index exceeds HTML node bound")
        if len(attrs) > 32 or any(len(key) > 100 or len(value or "") > 8192 for key, value in attrs):
            raise ValueError("news index exceeds HTML attribute bound")
        if len(self._stack) >= MAX_HTML_DEPTH:
            raise ValueError("news index exceeds HTML depth bound")
        attributes = dict(attrs)
        classes = (attributes.get("class") or "").split()
        inherited = self._stack[-1][1] if self._stack else 0
        ignored = (self._stack[-1][2] if self._stack else False) or tag in self._IGNORE
        entry = (tag == "div" and "nua-home-slider-mobile__slide" in classes if self._citizen
                 else tag == "article")
        if entry and not ignored:
            if self._article is not None:
                raise ValueError("news index contains nested articles")
            self._count += 1
            if (self._citizen or "grid" in classes) and self._count <= MAX_FEED_ENTRIES:
                self._article = {"title": "", "date": "", "summary": "", "link": ""}
                self._article_depth = len(self._stack) + 1
        flags = inherited
        if self._article is not None and not ignored:
            if self._citizen and any(name in classes for name in (
                    "nua-home-slider-mobile__slide-title", "nua-home-slider-mobile__slide-subtitle")):
                if "nua-home-slider-mobile__slide-subtitle" in classes:
                    self._article["title"] = ""
                    self._article["link"] = ""
                flags |= 1
            elif self._citizen and "nua-home-slider-mobile__slide-date" in classes:
                flags |= 2
            elif self._citizen and "nua-home-slider-mobile__slide-excerpt" in classes:
                flags |= 4
            elif tag == "div" and "post-title" in classes:
                flags |= 1
            elif tag == "a" and "post-date" in classes:
                flags |= 2
            elif tag == "section" and "post-content-snippet" in classes:
                flags |= 4
            if tag == "a" and flags & 1 and not self._article["link"]:
                self._article["link"] = (attributes.get("href") or "")[:2049]
        if tag not in self._VOID:
            self._stack.append((tag, flags, ignored))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] != tag:
                continue
            if self._article is not None and index < self._article_depth:
                self.entries.append(self._article)
                self._article = None
            del self._stack[index:]
            return

    def handle_data(self, data):
        if self._article is None or not self._stack or self._stack[-1][2]:
            return
        flags = self._stack[-1][1]
        for bit, field in ((1, "title"), (2, "date"), (4, "summary")):
            if flags & bit and len(self._article[field]) < 4096:
                self._article[field] += data[:4096 - len(self._article[field])]


def _parse_official_index(payload: bytes | str, *, source_name: str, now=None) -> list[dict]:
    """Parse the fixed official recent-post index, never arbitrary user HTML.

    Its visible YYYY-Mon-DD metadata has day precision. Treat that date as
    midnight UTC; this does not relax timezone checks for RSS/Atom timestamps.
    """
    timestamp = _timestamp(now)
    if not isinstance(payload, (bytes, str)):
        raise ValueError("news index must be HTML bytes or text")
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    if not raw or len(raw) > MAX_NEWS_BYTES:
        raise ValueError("news index exceeds byte bound")
    parser = _ProjectZeroIndexParser(source_name)
    try:
        parser.feed(raw.decode("utf-8", errors="strict"))
        parser.close()
    except (UnicodeError, AssertionError) as exc:
        raise ValueError("news index HTML is malformed") from exc
    results = {}
    for entry in parser.entries:
        if source_name == "citizen_lab":
            match = re.fullmatch(r"([A-Z][a-z]+) (\d{1,2}), (\d{4})", entry["date"].strip())
            if match is None or match[1] not in _LONG_MONTHS:
                continue
            year, month, day = int(match[3]), _LONG_MONTHS[match[1]], int(match[2])
        else:
            match = re.fullmatch(r"(\d{4})-([A-Z][a-z]{2})-(\d{2})", entry["date"].strip())
            if match is None or match[2] not in _MONTHS:
                continue
            year, month, day = int(match[1]), _MONTHS[match[2]], int(match[3])
        try:
            stamp = datetime(year, month, day, tzinfo=timezone.utc).timestamp()
        except (ValueError, OverflowError, OSError):
            continue
        link = entry["link"]
        if link.startswith("/") and not link.startswith("//"):
            # Prefix the fixed origin without normalizing traversal segments;
            # the article policy must see and reject the original path.
            link = NEWS_SOURCES[source_name].rstrip("/") + link
        row = _news_entry(entry["title"], entry["summary"], stamp, link,
                          source_name=source_name, timestamp=timestamp)
        if row is not None:
            existing = results.get(row["url"])
            if existing is None or stamp > existing["published"]:
                results[row["url"]] = row
    return sorted(results.values(), key=lambda row: (-row["published"], row["url"]))[:MAX_NEWS_ITEMS]


def parse_project_zero_index(payload: bytes | str, *, now=None) -> list[dict]:
    return _parse_official_index(payload, source_name="project_zero", now=now)


def parse_citizen_lab_index(payload: bytes | str, *, now=None) -> list[dict]:
    """Parse dated official research cards; do not fetch assets or follow links."""
    return _parse_official_index(payload, source_name="citizen_lab", now=now)


def parse_news_feed(payload: bytes | str, *, source_name: str, now=None) -> list[dict]:
    """Parse bounded RSS 2 / Atom entries into fresh, significant headlines.

    Invalid individual entries are skipped; malformed or unsafe XML rejects
    the feed as a whole. No returned data authorizes detection or response.
    """
    if source_name not in NEWS_SOURCES:
        raise ValueError("unknown official news source")
    timestamp = _timestamp(now)
    if not isinstance(payload, (bytes, str)):
        raise ValueError("news feed must be XML bytes or text")
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    if not raw or len(raw) > MAX_NEWS_BYTES:
        raise ValueError("news feed exceeds byte bound")
    try:
        root = ElementTree.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ElementTree.ParseError, ValueError) as exc:
        raise ValueError("news feed XML is unsafe or malformed") from exc
    for count, _ in enumerate(root.iter(), start=1):
        if count > MAX_XML_NODES:
            raise ValueError("news feed exceeds XML node bound")
    if root.tag == "rss":
        channel = root.find("channel")
        entries = [] if channel is None else channel.findall("item")
        atom = False
    elif root.tag == "{" + _ATOM + "}feed":
        entries = root.findall("{" + _ATOM + "}entry")
        atom = True
    else:
        raise ValueError("news feed must be RSS or Atom")
    results = {}
    for entry in entries[:MAX_FEED_ENTRIES]:
        if atom:
            title = _plain(_element_text(entry.find("{" + _ATOM + "}title")))
            summary = _element_text(entry.find("{" + _ATOM + "}summary"))
            if not summary:
                summary = _element_text(entry.find("{" + _ATOM + "}content"))
            published = entry.findtext("{" + _ATOM + "}published") or entry.findtext("{" + _ATOM + "}updated") or ""
            links = entry.findall("{" + _ATOM + "}link")
            link = next((item.get("href", "") for item in links
                         if item.get("rel", "alternate") == "alternate"
                         and item.get("type", "text/html") in {"text/html", "application/xhtml+xml"}), "")
        else:
            title = _plain(_element_text(entry.find("title")))
            summary = _element_text(entry.find("description"))
            published = entry.findtext("pubDate") or entry.findtext("{" + _DC + "}date") or ""
            link = entry.findtext("link") or ""
        row = _news_entry(title, summary, _date(published), link,
                          source_name=source_name, timestamp=timestamp)
        if row is None:
            continue
        url, stamp = row["url"], row["published"]
        existing = results.get(url)
        if existing is None or stamp > existing["published"]:
            results[url] = row
    return sorted(results.values(), key=lambda row: (-row["published"], row["url"]))[:MAX_NEWS_ITEMS]


def fetch_news_source(source_name: str, *, network_enabled: bool = False, now=None) -> list[dict]:
    """Fetch one fixed official feed/index after explicit network enablement."""
    if source_name not in NEWS_SOURCES:
        raise ValueError("unknown official news source")
    if network_enabled is not True:
        raise PermissionError("news downloads require explicit network enablement")
    timestamp = _timestamp(now)
    if source_name in {"project_zero", "citizen_lab"}:
        raw, _ = _fetch_https_report(NEWS_SOURCES[source_name], timeout=15.0, expected_format="html")
        return _parse_official_index(raw, source_name=source_name, now=timestamp)
    raw, _ = _fetch_https_report(NEWS_SOURCES[source_name], timeout=15.0, expected_format="xml")
    return parse_news_feed(raw, source_name=source_name, now=timestamp)


def self_test() -> tuple[bool, str]:
    now = datetime.fromisoformat("2026-10-21T12:00:00+00:00").timestamp()
    raw = ("<rss version='2.0'><channel><item><title>Spyware exploit analysis</title>"
           "<link>https://citizenlab.ca/research/example-analysis/</link>"
           "<pubDate>Tue, 20 Oct 2026 12:00:00 +0000</pubDate></item></channel></rss>")
    rows = parse_news_feed(raw, source_name="citizen_lab", now=now)
    assert len(rows) == 1 and rows[0]["source"] == "citizen_lab"
    assert not parse_news_feed(raw, source_name="citizen_lab", now=now + 31 * 86400)
    return True, "Offline RSS freshness, source link and headline parsing passed"
