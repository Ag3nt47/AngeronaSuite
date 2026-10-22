"""Bounded, advisory threat intelligence for SpywareGuard.

Reports are untrusted data: no report instructions, remote rules, or code run.
All indicators and generated rules require operator review; a match never
authorizes response. Network access defaults off and only the named, exact
official sources below may be refreshed automatically. An explicitly supplied
public HTTPS report URL may be fetched through the separately gated manual
import helper. No host telemetry leaves this module.

Source/format references (verified 2026-10-21):
* https://www.cisa.gov/known-exploited-vulnerabilities-catalog (KEV JSON)
* https://citizenlab.ca/reports/ (HTML research index)
* https://projectzero.google/ (current official Project Zero HTML index)
* https://oasis-open.github.io/cti-documentation/stix/examples.html (STIX 2.1)

Research indexes are fetched once, never crawled. Their literal observables
are candidates, not an assertion that referenced infrastructure is malicious.
KEV is vulnerability prioritization metadata, never a network-indicator feed.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import math
import os
import queue
import re
import socket
import ssl
import stat
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

from angerona.core.atomic_io import replace_with_retry
from angerona.core.url_policy import UrlPolicy, validate_url

MAX_BYTES = 4 * 1024 * 1024
MAX_ITEMS = 5000
DEFAULT_TTL = 12 * 3600
_MAX_TTL = 30 * 86400
_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
_CVE = re.compile(r"CVE-\d{4}-\d{4,19}\Z", re.I)
_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])\Z")
_TOKEN = re.compile(
    r"(?<![\w@-])(?:[a-fA-F0-9]{64}(?![a-fA-F0-9])|CVE-\d{4}-\d{4,19}"
    r"|(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(?:\[\.\]|\(\.\)|\.)){1,20}"
    r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62})(?![\w-])"
)
_IPV6 = re.compile(r"(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}(?![\w:])")
_STIX_LITERAL = re.compile(
    r"\[\s*(domain-name:value|ipv4-addr:value|ipv6-addr:value|file:hashes\.'SHA-256')"
    r"\s*=\s*'([^'\\\r\n]{1,253})'\s*\]"
)


@dataclass(frozen=True)
class FeedSource:
    url: str
    format: str


OFFICIAL_SOURCES = MappingProxyType({
    "cisa_kev": FeedSource(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev"
    ),
    "citizen_lab": FeedSource("https://citizenlab.ca/reports/", "html"),
    "project_zero": FeedSource("https://projectzero.google/", "html"),
})


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    source: str
    observed_at: float = 0.0
    expires_at: float = 0.0
    confidence: str = "candidate"
    evidence: str = ""
    source_sha256: str = ""

    def fresh(self, now: float | None = None) -> bool:
        timestamp = time.time() if now is None else _timestamp(now)
        return self.observed_at <= timestamp < self.expires_at


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    source: str
    vendor: str = ""
    product: str = ""
    description: str = ""
    required_action: str = ""
    observed_at: float = 0.0
    expires_at: float = 0.0


@dataclass(frozen=True)
class ParseResult:
    indicators: tuple[Indicator, ...] = ()
    vulnerabilities: tuple[Vulnerability, ...] = ()
    rejected_count: int = 0
    truncated: bool = False
    format: str = ""
    content_sha256: str = ""


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timestamp must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("timestamp must be finite and nonnegative")
    return result


def _text(value: object, maximum: int = 512) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:maximum]


def normalize_indicator(kind: str, value: object) -> str | None:
    """Accept only canonical literal values; never accept patterns or URLs."""
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        return None
    value = value.strip().replace("[.]", ".").replace("(.)", ".")
    if kind == "sha256":
        return value.lower() if _SHA256.fullmatch(value) else None
    if kind == "cve":
        return value.upper() if _CVE.fullmatch(value) else None
    if kind == "ip":
        if "%" in value:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if kind == "domain":
        value = value.lower().rstrip(".")
        # ASCII-only literals prevent ambiguous Unicode/IDN presentation.
        if len(value) <= 253 and _DOMAIN.fullmatch(value):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return value
    return None


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _wire_payload(payload: bytes | str | dict | list) -> bytes:
    try:
        if isinstance(payload, bytes):
            raw = payload
        elif isinstance(payload, str):
            if len(payload) > MAX_BYTES:
                raise ValueError("report exceeds byte bound")
            raw = payload.encode("utf-8")
        elif isinstance(payload, (dict, list)):
            raw = json.dumps(payload, allow_nan=False).encode("utf-8")
        else:
            raise ValueError("unsupported report type")
    except (RecursionError, TypeError, UnicodeError) as exc:
        raise ValueError("report cannot be represented safely") from exc
    if len(raw) > MAX_BYTES:
        raise ValueError("report exceeds byte bound")
    return raw


def _upstream_time(value: object, fallback: float) -> float:
    if value is None:
        return fallback
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid upstream timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("upstream timestamp requires timezone")
    return _timestamp(parsed.astimezone(timezone.utc).timestamp())


def parse_threat_report(
    payload: bytes | str | dict | list,
    source: str,
    *,
    format: str = "auto",
    now: float | None = None,
    ttl_seconds: int = DEFAULT_TTL,
    max_items: int = MAX_ITEMS,
) -> ParseResult:
    """Extract candidate literals from JSON, strict STIX equalities, or text.

    Simple JSON accepts ips/domains/hashes/cves arrays or an indicators array
    of {kind, value}. STIX supports observable literals and single equality
    indicators only. Compound, revoked, future, and expired patterns are skipped.
    """
    if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= MAX_ITEMS:
        raise ValueError("invalid item bound")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= _MAX_TTL:
        raise ValueError("invalid indicator lifetime")
    timestamp = time.time() if now is None else _timestamp(now)
    origin = _text(source, 4096)
    if not origin or not isinstance(source, str) or len(source) > 4096:
        raise ValueError("report requires source provenance")
    raw = _wire_payload(payload)
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise ValueError("report must be UTF-8") from exc
    if format == "auto":
        format = "json" if text.lstrip().startswith(("{", "[")) else "text"
    if format not in {"json", "stix", "kev", "text", "html"}:
        raise ValueError("unsupported report format")
    found: dict[tuple[str, str], Indicator] = {}
    vulnerabilities: dict[str, Vulnerability] = {}
    rejected = 0
    examined = 0
    truncated = False

    def budget() -> bool:
        nonlocal examined, truncated
        if examined >= max_items:
            truncated = True
            return False
        examined += 1
        return True

    def add(kind, value, evidence="", expires=None):
        nonlocal rejected
        normalized = normalize_indicator(kind, value)
        if normalized is None:
            rejected += 1
            return
        item = Indicator(kind, normalized, origin, timestamp,
                         min(timestamp + ttl_seconds, expires) if expires is not None else timestamp + ttl_seconds,
                         evidence=_text(evidence, 160), source_sha256=digest)
        if item.fresh(timestamp):
            found[(kind, normalized)] = item
        else:
            rejected += 1

    if format in {"text", "html"}:
        if format == "html":
            visible = _VisibleText()
            visible.feed(text)
            text = "\n".join(visible.parts)
        # Literal matches are untrusted candidates, including benign references.
        # No narrative label, vendor name, or exploit claim invents an IOC.
        for match in _TOKEN.finditer(text):
            if not budget():
                break
            value = match.group()
            kind = next((kind for kind in ("sha256", "cve", "ip", "domain")
                         if normalize_indicator(kind, value) is not None), "invalid")
            add(kind, value, value)
        if not truncated:
            for match in _IPV6.finditer(text):
                if not budget():
                    break
                add("ip", match.group(), match.group())
    else:
        try:
            document = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ValueError("invalid JSON report") from exc
        if isinstance(document, dict) and "vulnerabilities" in document:
            format = "kev"
        if format == "kev":
            records = document.get("vulnerabilities") if isinstance(document, dict) else None
            if not isinstance(records, list):
                raise ValueError("KEV requires a vulnerabilities array")
            for record in records:
                if not budget():
                    break
                cve = normalize_indicator("cve", record.get("cveID")) if isinstance(record, dict) else None
                if cve is None:
                    rejected += 1
                    continue
                vulnerabilities[cve] = Vulnerability(
                    cve, origin, _text(record.get("vendorProject")), _text(record.get("product")),
                    _text(record.get("shortDescription"), 2048), _text(record.get("requiredAction"), 2048),
                    timestamp, timestamp + ttl_seconds,
                )
        elif isinstance(document, dict) and (document.get("type") == "bundle" or format == "stix"):
            format = "stix"
            records = document.get("objects")
            if not isinstance(records, list):
                raise ValueError("STIX requires an objects array")
            for record in records:
                if not budget():
                    break
                if not isinstance(record, dict) or record.get("revoked", False):
                    rejected += 1
                    continue
                try:
                    if _upstream_time(record.get("valid_from"), timestamp) > timestamp:
                        raise ValueError("future indicator")
                    expiry = _upstream_time(record.get("valid_until"), timestamp + ttl_seconds)
                except (ValueError, OverflowError):
                    rejected += 1
                    continue
                record_type = record.get("type")
                if not isinstance(record_type, str):
                    rejected += 1
                    continue
                kind = {"domain-name": "domain", "ipv4-addr": "ip", "ipv6-addr": "ip"}.get(record_type)
                if kind:
                    add(kind, record.get("value"), record.get("id"), expiry)
                elif record.get("type") == "file":
                    hashes = record.get("hashes")
                    add("sha256", hashes.get("SHA-256") if isinstance(hashes, dict) else None, record.get("id"), expiry)
                elif record.get("type") == "indicator":
                    pattern = record.get("pattern")
                    literal = _STIX_LITERAL.fullmatch(pattern) if isinstance(pattern, str) and len(pattern) <= 512 else None
                    if record.get("pattern_type", "stix") != "stix" or literal is None:
                        rejected += 1
                        continue
                    field, value = literal.groups()
                    kind = "domain" if field.startswith("domain") else "sha256" if field.startswith("file") else "ip"
                    add(kind, value, record.get("id"), expiry)
        else:
            records = document if isinstance(document, list) else document.get("indicators", []) if isinstance(document, dict) else None
            if not isinstance(records, list):
                raise ValueError("JSON requires indicator arrays")
            exhausted = False
            for record in records:
                if not budget():
                    exhausted = True
                    break
                if isinstance(record, dict):
                    add(record.get("kind"), record.get("value"))
                else:
                    rejected += 1
            if isinstance(document, dict) and not exhausted:
                for field, kind in (("ips", "ip"), ("domains", "domain"), ("hashes", "sha256"), ("cves", "cve")):
                    values = document.get(field, [])
                    if not isinstance(values, list):
                        rejected += 1
                        continue
                    for value in values:
                        if not budget():
                            exhausted = True
                            break
                        add(kind, value)
                    if exhausted:
                        break
    return ParseResult(tuple(found[key] for key in sorted(found)),
                       tuple(vulnerabilities[key] for key in sorted(vulnerabilities)),
                       rejected, truncated, format, digest)


def _public_address(host: str, timeout: float) -> str:
    """Bound DNS waiting and pin the checked numeric destination for TLS."""
    results: queue.Queue = queue.Queue(maxsize=1)

    def resolve():
        try:
            results.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError as exc:
            results.put(exc)

    threading.Thread(target=resolve, name="spyware-intel-dns", daemon=True).start()
    try:
        records = results.get(timeout=timeout)
    except queue.Empty as exc:
        raise TimeoutError("threat source DNS timed out") from exc
    if isinstance(records, Exception):
        raise ValueError("threat source DNS failed") from records
    policy = UrlPolicy("official SpywareGuard source", frozenset({"https"}), frozenset({host}))
    validate_url("https://" + host + "/", policy, resolver=lambda *_a, **_k: records)
    return str(ipaddress.ip_address(records[0][4][0]))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address
        self._transport = None
        self._deadline = time.monotonic() + timeout

    def connect(self):
        # Numeric target cannot resolve again; original official host supplies
        # SNI and certificate validation. No inherited HTTP proxy is involved.
        raw = socket.create_connection((self._address, 443), self.timeout)
        self._transport = raw
        try:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("threat source deadline exceeded")
            raw.settimeout(remaining)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            self._transport = self.sock
            self.sock.do_handshake()
        except BaseException:
            raw.close()
            self.abort()
            raise

    def abort(self):
        # Interrupt slow header/body trickling even after http.client transfers
        # ownership of a connection-close response to its buffered file.
        transport = self._transport
        if transport is not None:
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            transport.close()


def fetch_official_source(name: str, *, network_enabled: bool = False, timeout: float = 15.0) -> bytes:
    if name not in OFFICIAL_SOURCES:
        raise ValueError("unknown official threat source")
    if network_enabled is not True:
        raise PermissionError("official threat downloads require explicit network enablement")
    return _fetch_https_report(OFFICIAL_SOURCES[name].url, timeout=timeout,
                              expected_format=OFFICIAL_SOURCES[name].format)[0]


def _fetch_https_report(url: str, *, timeout: float, expected_format: str | None = None) -> tuple[bytes, str]:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
        raise ValueError("invalid network time bound")
    # Syntax validation occurs before DNS; the public address check is repeated
    # against the exact records used to choose the pinned TLS destination.
    syntax_policy = UrlPolicy("manual SpywareGuard HTTPS report", frozenset({"https"}), resolve_addresses=False)
    validate_url(url, syntax_policy)
    parsed = urlsplit(url)
    if parsed.port not in (None, 443) or not parsed.hostname.isascii():
        raise ValueError("threat reports require an ASCII HTTPS hostname on port 443")
    deadline = time.monotonic() + timeout
    address = _public_address(parsed.hostname, timeout)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("threat source deadline exceeded")
    connection = _PinnedHTTPSConnection(parsed.hostname, address, remaining)
    watchdog = threading.Timer(remaining, connection.abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        connection.request("GET", target, headers={
            "User-Agent": "Angerona-SpywareGuard/1.0", "Accept-Encoding": "identity",
            "Accept": ("application/rss+xml, application/atom+xml, application/xml, text/xml"
                       if expected_format == "xml" else
                       "application/json, application/stix+json, text/html, text/plain"),
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("official source returned non-success status; redirects are forbidden")
        encoding = response.getheader("Content-Encoding", "identity").lower()
        if encoding != "identity":
            raise ValueError("compressed threat responses are forbidden")
        media_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        formats = {"application/json": "json", "application/stix+json": "stix",
                   "text/html": "html", "application/xhtml+xml": "html", "text/plain": "text"}
        allowed = ({"application/rss+xml", "application/atom+xml", "application/xml", "text/xml"}
                   if expected_format == "xml" else {"application/json"} if expected_format == "kev"
                   else {"text/html", "application/xhtml+xml"} if expected_format == "html" else set(formats))
        if media_type not in allowed:
            raise ValueError("official source response format is unexpected")
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError as exc:
                raise ValueError("invalid threat response size") from exc
            if not 0 <= length <= MAX_BYTES:
                raise ValueError("threat response exceeds byte bound")
        parts = []
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("threat source deadline exceeded")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            part = response.read1(min(65536, MAX_BYTES + 1 - total))
            if not part:
                break
            parts.append(part)
            total += len(part)
            if total > MAX_BYTES:
                raise ValueError("threat response exceeds byte bound")
        if time.monotonic() > deadline:
            raise TimeoutError("threat source deadline exceeded")
        return b"".join(parts), expected_format or formats[media_type]
    finally:
        watchdog.cancel()
        connection.close()


def fetch_report_url(url: str, *, network_enabled: bool = False, now=None,
                     timeout: float = 15.0, ttl_seconds: int = DEFAULT_TTL) -> ParseResult:
    """Fetch one operator-supplied public HTTPS report without following links.

    HTML, UTF-8 text, JSON and STIX are supported. PDFs and compressed/archive
    content are rejected. No URL fetched here becomes an automatic feed.
    """
    if network_enabled is not True:
        raise PermissionError("report URL imports require explicit network enablement")
    raw, format = _fetch_https_report(url, timeout=timeout)
    return parse_threat_report(raw, url, format=format, now=now, ttl_seconds=ttl_seconds)


def export_candidate_rules(indicators, *, now: float | None = None) -> dict:
    """Generate literal, inactive review artifacts; never import remote rules."""
    timestamp = time.time() if now is None else _timestamp(now)
    candidates = {}
    for index, item in enumerate(indicators):
        if index >= MAX_ITEMS:
            break
        if isinstance(item, Indicator) and item.fresh(timestamp) and normalize_indicator(item.kind, item.value) == item.value:
            candidates[(item.kind, item.value)] = item
    yara = []
    sigma = []
    ndr = []
    for (kind, value), item in sorted(candidates.items()):
        rule_id = hashlib.sha256((kind + ":" + value).encode()).hexdigest()[:24]
        if kind == "sha256":
            yara.append('import "hash"\nrule SpywareGuard_candidate_' + rule_id + ' {\n'
                        '  meta:\n    review_required = true\n'
                        '  condition:\n    hash.sha256(0, filesize) == "' + value + '"\n}\n')
        elif kind in {"domain", "ip"}:
            field = "DestinationHostname" if kind == "domain" else "DestinationIp"
            sigma.append({"title": "SpywareGuard candidate " + rule_id, "status": "experimental",
                          "logsource": {"category": "network_connection"},
                          "detection": {"selection": {field: value}, "condition": "selection"},
                          "falsepositives": ["Unreviewed research literal; requires corroboration"],
                          "level": "low", "review_required": True})
            ndr.append({"kind": kind, "value": value, "match": "exact", "action": "alert",
                        "source": item.source, "expires_at": item.expires_at, "review_required": True})
    return {"review_required": True, "active": False, "yara": yara, "sigma": sigma, "ndr": ndr}


class ThreatIntelStore:
    """Bounded candidate cache. Optional disk data never confers authority."""
    def __init__(self, path: str | Path | None = None, *, max_indicators: int = MAX_ITEMS,
                 network_enabled: bool = False):
        if isinstance(max_indicators, bool) or not isinstance(max_indicators, int) or not 1 <= max_indicators <= MAX_ITEMS:
            raise ValueError("invalid store item bound")
        self.path = Path(path).absolute() if path is not None else None
        self.max_indicators = max_indicators
        self.network_enabled = network_enabled is True
        self._lock = threading.RLock()
        self._items: dict[tuple[str, str, str], Indicator] = {}
        self._vulnerabilities: dict[tuple[str, str], Vulnerability] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def _check_path(self):
        for part in (self.path, *self.path.parents):
            try:
                info = part.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise ValueError("threat store path cannot traverse links or reparse points")

    def _persist(self, items, vulnerabilities):
        if self.path is None:
            return
        self._check_path()
        raw = json.dumps({"version": 1, "indicators": [asdict(x) for x in items.values()],
                          "vulnerabilities": [asdict(x) for x in vulnerabilities.values()]},
                         sort_keys=True, allow_nan=False).encode()
        if len(raw) > MAX_BYTES:
            raise ValueError("threat store exceeds byte bound")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._check_path()
        descriptor, temporary = tempfile.mkstemp(prefix=".spyware-intel-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            self._check_path()
            replace_with_retry(Path(temporary), self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _load(self):
        self._check_path()
        with self.path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("threat store exceeds byte bound")
        try:
            state = json.loads(raw)
            if not isinstance(state, dict) or state.get("version") != 1:
                raise ValueError("invalid threat store version")
            records = state.get("indicators", [])
            vulnerabilities = state.get("vulnerabilities", [])
            if not isinstance(records, list) or not isinstance(vulnerabilities, list) or len(records) + len(vulnerabilities) > self.max_indicators:
                raise ValueError("invalid threat store item count")
            for record in records:
                item = Indicator(**record)
                if (normalize_indicator(item.kind, item.value) != item.value or item.confidence != "candidate"
                        or not item.source or len(item.source) > 4096 or len(item.evidence) > 160
                        or not _SHA256.fullmatch(item.source_sha256)
                        or not 0 < _timestamp(item.expires_at) - _timestamp(item.observed_at) <= _MAX_TTL):
                    raise ValueError("invalid stored candidate")
                self._items[(item.kind, item.value, item.source)] = item
            for record in vulnerabilities:
                item = Vulnerability(**record)
                if (normalize_indicator("cve", item.cve_id) != item.cve_id
                        or not isinstance(item.source, str) or not 1 <= len(item.source) <= 4096
                        or any(not isinstance(value, str) or len(value) > maximum
                               for value, maximum in ((item.vendor, 512), (item.product, 512),
                                                      (item.description, 2048), (item.required_action, 2048)))
                        or not 0 < _timestamp(item.expires_at) - _timestamp(item.observed_at) <= _MAX_TTL):
                    raise ValueError("invalid stored vulnerability")
                self._vulnerabilities[(item.cve_id, item.source)] = item
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            self._items.clear()
            self._vulnerabilities.clear()
            raise ValueError("invalid threat store") from exc

    def ingest(self, payload, source: str, *, format="auto", now=None, ttl_seconds=DEFAULT_TTL) -> ParseResult:
        timestamp = time.time() if now is None else _timestamp(now)
        parsed = parse_threat_report(payload, source, format=format, now=timestamp,
                                    ttl_seconds=ttl_seconds, max_items=self.max_indicators)
        return self._merge_result(parsed, timestamp)

    def _merge_result(self, parsed: ParseResult, timestamp: float) -> ParseResult:
        with self._lock:
            items = {key: item for key, item in self._items.items() if item.fresh(timestamp)}
            vulnerabilities = {key: item for key, item in self._vulnerabilities.items() if item.observed_at <= timestamp < item.expires_at}
            for item in parsed.indicators:
                items[(item.kind, item.value, item.source)] = item
            for item in parsed.vulnerabilities:
                vulnerabilities[(item.cve_id, item.source)] = item
            # Prefer newest evidence while preserving bounded per-source provenance.
            combined = sorted([(x.observed_at, key, x, False) for key, x in items.items()]
                              + [(x.observed_at, key, x, True) for key, x in vulnerabilities.items()],
                              key=lambda row: (row[0], str(row[1])), reverse=True)[:self.max_indicators]
            items = {key: item for _when, key, item, is_vuln in combined if not is_vuln}
            vulnerabilities = {key: item for _when, key, item, is_vuln in combined if is_vuln}
            self._persist(items, vulnerabilities)
            self._items, self._vulnerabilities = items, vulnerabilities
        return parsed

    def indicators(self, *, now=None) -> tuple[Indicator, ...]:
        timestamp = time.time() if now is None else _timestamp(now)
        with self._lock:
            return tuple(item for _key, item in sorted(self._items.items()) if item.fresh(timestamp))

    def vulnerabilities(self, *, now=None) -> tuple[Vulnerability, ...]:
        timestamp = time.time() if now is None else _timestamp(now)
        with self._lock:
            return tuple(item for _key, item in sorted(self._vulnerabilities.items()) if item.observed_at <= timestamp < item.expires_at)

    def lookup(self, kind: str, value: object, *, now=None) -> tuple[Indicator, ...]:
        normalized = normalize_indicator(kind, value)
        if normalized is None:
            return ()
        return tuple(item for item in self.indicators(now=now) if item.kind == kind and item.value == normalized)

    def refresh(self, source_name: str, *, now=None, timeout=15.0) -> ParseResult:
        if not self.network_enabled:
            raise PermissionError("SpywareGuard threat downloads require explicit network enablement")
        if source_name not in OFFICIAL_SOURCES:
            raise ValueError("unknown official threat source")
        source = OFFICIAL_SOURCES[source_name]
        return self.ingest(fetch_official_source(source_name, network_enabled=True, timeout=timeout), source.url,
                           format=source.format, now=now)

    def refresh_url(self, url: str, *, now=None, timeout=15.0) -> ParseResult:
        timestamp = time.time() if now is None else _timestamp(now)
        parsed = fetch_report_url(url, network_enabled=self.network_enabled, now=timestamp, timeout=timeout)
        return self._merge_result(parsed, timestamp)

    def export_candidates(self, *, now=None) -> dict:
        return export_candidate_rules(self.indicators(now=now), now=now)


def self_test() -> bool:
    """Offline contract probe; never touches a live feed or runtime data."""
    store = ThreatIntelStore()
    parsed = store.ingest({"domains": ["fixture[.]example"], "hashes": ["a" * 64]},
                          "offline-self-test", now=100.0)
    return bool(len(parsed.indicators) == 2 and store.lookup("domain", "fixture.example", now=101)
                and store.export_candidates(now=101)["active"] is False
                and not store.indicators(now=100 + DEFAULT_TTL))
