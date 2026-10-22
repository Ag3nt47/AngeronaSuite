"""Bounded local telemetry heuristics for SpywareGuard.

This module consumes telemetry supplied by local collectors; it does not capture
traffic, hook APIs, inspect memory, or authorize a response. Heuristic findings
are review candidates and do not establish spyware identity or compromise.

Records use ``event_type`` and an optional Unix ``ts``. Process state requires
both ``pid`` and ``process_create_time``; counters are cumulative ``bytes_sent``.
Renderer correlation uses ``media_render`` with ``role=renderer|webview`` and a
``process_start`` with ``parent_pid``, ``parent_create_time``, ``process_name``.
Sensitive API/file telemetry requires the literal boolean ``authorized=False``.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit


_EVENTS = frozenset({
    "dns_query", "network_egress", "network_connection", "media_render",
    "process_start", "api_access", "file_read", "http_request",
})
_DDNS = ("duckdns.org", "no-ip.org", "ddns.net", "dynv6.net", "hopto.org", "dynu.net")
_COMMON_PORTS = frozenset({53, 80, 123, 443, 465, 587, 853, 993, 995})
_SHELLS = frozenset({
    "cmd", "powershell", "pwsh", "sh", "bash", "dash", "zsh", "csh",
    "wscript", "cscript", "mshta",
})
_APIS = {
    "bitblt": "screen_capture", "getasynckeystate": "keyboard_state",
    "camera": "camera", "microphone": "microphone",
}
_MULTIPART_SUFFIXES = frozenset({"co.uk", "com.au", "co.jp", "co.nz", "com.br"})
_MAX_AGE = 300.0
_MAX_FUTURE = 5.0


def _number(value: object, *, positive: bool = False) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(number) or (positive and number <= 0):
        return None
    return number


def _identity(record: dict, prefix: str = "") -> tuple[int, float] | None:
    pid = record.get(prefix + "pid")
    birth_key = "parent_create_time" if prefix else "process_create_time"
    birth = _number(record.get(birth_key), positive=True)
    if type(pid) is not int or not 0 < pid <= 2**32 - 1 or birth is None:
        return None
    return pid, birth


def _domain(value: object) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 254:
        return None
    domain = value.lower().rstrip(".")
    if len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", item)
        for item in labels
    ):
        return None
    return domain


def _domain_group(domain: str) -> str:
    labels = domain.split(".")
    count = 3 if ".".join(labels[-2:]) in _MULTIPART_SUFFIXES else 2
    return ".".join(labels[-count:])


def _high_entropy_label(domain: str, group: str) -> bool:
    for label in domain[: -(len(group) + 1)].split("."):
        if len(label) < 24 or label.startswith("xn--") or not label.isalnum():
            continue
        counts = Counter(label)
        entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in counts.values())
        if entropy >= 3.6:
            return True
    return False


def _bounded_payload(record: dict) -> str | None:
    """Validate a small JSON-shaped input before canonical hashing.

    No raw payload, URL, advertising identifier, file path, or field value is
    retained in deduplication state. Structural budgets also bound hash work.
    """
    pending = [(record, 0)]
    nodes = chars = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > 512 or depth > 4:
            return None
        if isinstance(value, str):
            chars += len(value)
            if len(value) > 4096 or chars > 16384:
                return None
        elif type(value) is dict:
            if len(value) > 64 or any(not isinstance(key, str) for key in value):
                return None
            pending.extend((part, depth + 1) for item in value.items() for part in item)
        elif type(value) in (list, tuple):
            if len(value) > 64:
                return None
            pending.extend((part, depth + 1) for part in value)
        elif value is not None and type(value) not in (bool, int, float):
            return None
        elif type(value) is int and value.bit_length() > 128:
            return None
        elif type(value) is float and not math.isfinite(value):
            return None
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass
class _Process:
    last_seen: float = 0.0
    egress_ts: float | None = None
    sent: int = 0
    intervals: int = 0
    rate: float = 0.0
    media_ts: float | None = None
    destinations: OrderedDict = field(default_factory=OrderedDict)


class SpywareBehaviorEngine:
    """Pure, bounded telemetry analysis with no I/O or response side effects.

    ``observe`` returns no findings for malformed, stale, duplicate, forwarded,
    or drill records. Only explicit local observations belong in this adapter;
    locality is a collector trust boundary, not authenticated by this engine.
    Methods are synchronized for collector threads. ``max_processes`` bounds
    process identities and DNS buckets; each bucket and replay cache is bounded.
    """

    def __init__(self, clock=time.time, max_processes: int = 256) -> None:
        if type(max_processes) is not int or not 1 <= max_processes <= 4096:
            raise ValueError("max_processes must be an integer from 1 to 4096")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._clock = clock
        self.max_processes = max_processes
        self._processes: OrderedDict[tuple[int, float], _Process] = OrderedDict()
        self._dns: OrderedDict[tuple[tuple[int, float] | None, str], deque] = OrderedDict()
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._alerts: OrderedDict[str, float] = OrderedDict()
        self._counts: Counter = Counter()
        self._lock = threading.RLock()

    def coverage(self) -> dict:
        return {
            "mode": "local_telemetry_heuristics",
            "supported_events": sorted(_EVENTS),
            "requires_collectors": True,
            "api_interception": False,
            "memory_inspection": False,
            "packet_capture": False,
            "automatic_response": False,
            "vendor_attribution": False,
            "dns_grouping": "suffix heuristic; no public suffix database",
            "encrypted_egress": "explicit encrypted=True and six warmup intervals",
        }

    def stats(self) -> dict:
        with self._lock:
            return {
                "accepted": self._counts["accepted"], "rejected": self._counts["rejected"],
                "duplicates": self._counts["duplicates"], "findings": self._counts["findings"],
                "processes": len(self._processes), "dns_buckets": len(self._dns),
                "replay_entries": len(self._seen), "alert_entries": len(self._alerts),
                "max_processes": self.max_processes,
            }

    def _trim(self, now: float) -> None:
        for mapping, ttl in ((self._seen, _MAX_AGE + _MAX_FUTURE), (self._alerts, 60.0)):
            for key in list(mapping):
                if now - mapping[key] > ttl:
                    del mapping[key]
        for key in list(self._processes):
            if now - self._processes[key].last_seen > _MAX_AGE:
                del self._processes[key]
        for key in list(self._dns):
            bucket = self._dns[key]
            while bucket and bucket[0][0] < now - 60:
                bucket.popleft()
            if not bucket:
                del self._dns[key]

    def _process(self, identity: tuple[int, float], ts: float) -> _Process:
        state = self._processes.setdefault(identity, _Process())
        state.last_seen = max(ts, state.last_seen)
        self._processes.move_to_end(identity)
        while len(self._processes) > self.max_processes:
            self._processes.popitem(last=False)
        return state

    def _finding(self, kind: str, summary: str, evidence: dict,
                 identity: tuple[int, float] | None, now: float, severity="Medium") -> list[dict]:
        key = hashlib.sha256(json.dumps([kind, identity, evidence], sort_keys=True).encode()).hexdigest()
        if key in self._alerts and now - self._alerts[key] < 60:
            return []
        self._alerts[key] = now
        while len(self._alerts) > self.max_processes * 8:
            self._alerts.popitem(last=False)
        finding = {"kind": kind, "severity": severity, "summary": summary,
                   "evidence": evidence, "response_authorized": False}
        if identity is not None:
            finding.update(pid=identity[0], process_create_time=identity[1])
        self._counts["findings"] += 1
        return [finding]

    def observe(self, record: dict) -> list[dict]:
        with self._lock:
            findings = self._observe(record)
            # A literal endpoint may support a separate caller's reviewed policy;
            # arbitrary report text and hostnames never become response targets.
            if findings and isinstance(record.get("remote_ip"), str):
                endpoint = self._ip_host(record["remote_ip"])
                if endpoint is not None:
                    for finding in findings:
                        finding["remote_ip"] = endpoint
            return findings

    def _observe(self, record: dict) -> list[dict]:
        now = _number(self._clock(), positive=True)
        payload = _bounded_payload(record) if type(record) is dict else None
        if now is None or payload is None:
            self._counts["rejected"] += 1
            return []
        ts = _number(record.get("ts", now), positive=True)
        event = record.get("event_type")
        identity = _identity(record)
        origin_flags = ("remote", "node_origin", "drill", "practice", "synthetic", "simulation")
        if (not isinstance(event, str) or event not in _EVENTS
                or ts is None or now - ts > _MAX_AGE
                or ts - now > _MAX_FUTURE
                or any(bool(record.get(key)) for key in origin_flags)
                or record.get("response_authority") == "remote-observe-only"
                or record.get("origin", "local") != "local"
                or record.get("source_host", "local") != "local"
                or (("pid" in record or "process_create_time" in record) and identity is None)
                or (identity is not None and identity[1] > ts)):
            self._counts["rejected"] += 1
            return []
        self._trim(now)
        event_id = record.get("event_id")
        if event_id is not None and (not isinstance(event_id, str) or not 1 <= len(event_id) <= 128):
            self._counts["rejected"] += 1
            return []
        # Even a producer that changes event_id cannot replay an identical body.
        body = dict(record)
        body.pop("event_id", None)
        body["ts"] = ts
        body_digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        digests = ["body:" + body_digest]
        if event_id is not None:
            digests.append("id:" + hashlib.sha256(event_id.encode()).hexdigest())
        if any(digest in self._seen for digest in digests):
            self._counts["duplicates"] += 1
            return []
        for digest in digests:
            self._seen[digest] = now
        while len(self._seen) > self.max_processes * 32:
            self._seen.popitem(last=False)
        self._counts["accepted"] += 1
        if event == "dns_query":
            return self._observe_dns(record, identity, ts, now)
        if event in {"network_egress", "network_connection"}:
            findings = self._observe_connection(record, identity, ts, now)
            if event == "network_egress":
                findings.extend(self._observe_egress(record, identity, ts, now))
            return findings
        if event == "media_render":
            if identity is not None and record.get("role") in ("renderer", "webview"):
                state = self._process(identity, ts)
                state.media_ts = max(ts, state.media_ts or ts)
            return []
        if event == "process_start":
            return self._observe_child(record, identity, ts, now)
        if event == "api_access" and record.get("authorized") is False:
            api = record.get("api")
            category = _APIS.get(api.lower()) if isinstance(api, str) else None
            if category:
                return self._finding("unauthorized_sensitive_api", "Collector reported an unauthorized sensitive API access.",
                                     {"api_category": category}, identity, now)
        if event == "file_read" and record.get("authorized") is False:
            category = self._sensitive_path(record.get("path"))
            if category:
                return self._finding("unauthorized_sensitive_file_read", "Collector reported an unauthorized credential or browser profile read.",
                                     {"target_category": category}, identity, now)
        if event == "http_request":
            return self._observe_http(record, identity, now)
        return []

    def _observe_dns(self, record, identity, ts, now):
        domain = _domain(record.get("domain"))
        if domain is None:
            return []
        group = _domain_group(domain)
        key = identity, group
        bucket = self._dns.setdefault(key, deque(maxlen=128))
        self._dns.move_to_end(key)
        while len(self._dns) > self.max_processes:
            self._dns.popitem(last=False)
        # Out-of-order samples cannot extend a live burst or revive older data.
        if bucket and ts < bucket[-1][0]:
            return []
        domain_hash = hashlib.sha256(domain.encode()).hexdigest()
        bucket.append((ts, domain_hash, _high_entropy_label(domain, group)))
        while bucket and bucket[0][0] < ts - 60:
            bucket.popleft()
        unique = {entry[1] for entry in bucket}
        high = {entry[1] for entry in bucket if entry[2]}
        if len(unique) >= 12 and len(high) >= 10:
            return self._finding("dns_tunneling_candidate", "Rapid unique DNS queries included many high entropy labels.",
                                 {"base_domain": group, "unique_queries": len(unique),
                                  "high_entropy_queries": len(high), "window_seconds": 60}, identity, now)
        return []

    def _observe_egress(self, record, identity, ts, now):
        sent = record.get("bytes_sent")
        if identity is None or type(sent) is not int or not 0 <= sent <= 2**63 - 1:
            return []
        state = self._process(identity, ts)
        if record.get("encrypted") is not True:
            state.egress_ts, state.intervals, state.rate = None, 0, 0.0
            return []
        if state.egress_ts is None:
            state.egress_ts, state.sent = ts, sent
            return []
        interval = ts - state.egress_ts
        if interval <= 0:
            return []
        delta = sent - state.sent
        state.egress_ts, state.sent = ts, sent
        if delta < 0 or interval > 120:
            state.intervals, state.rate = 0, 0.0
            return []
        if interval < 1:
            # Subsecond jitter cannot inflate the baseline or its warmup.
            return []
        rate = delta / interval
        findings = []
        if (state.intervals >= 6 and delta >= 5 * 1024 * 1024
                and rate >= 1024 * 1024 and rate > max(state.rate, 1024) * 8):
            findings = self._finding("encrypted_egress_spike", "Explicitly encrypted outbound telemetry exceeded the process baseline.",
                                     {"bytes_delta": delta, "interval_seconds": round(interval, 3),
                                      "rate_bytes_per_second": round(rate),
                                      "baseline_bytes_per_second": round(state.rate),
                                      "warmup_intervals": state.intervals}, identity, now, "High")
        else:
            state.rate = rate if state.intervals == 0 else state.rate * 0.8 + rate * 0.2
        state.intervals += 1
        return findings

    def _observe_connection(self, record, identity, ts, now):
        domain = _domain(record.get("domain"))
        port = record.get("remote_port")
        if (identity is None or domain is None or type(port) is not int
                or not 1 <= port <= 65535 or port in _COMMON_PORTS):
            return []
        provider = next((suffix for suffix in _DDNS if domain.endswith("." + suffix)), None)
        if provider is None:
            return []
        state = self._process(identity, ts)
        key = hashlib.sha256(domain.encode()).hexdigest(), port
        stamps = state.destinations.setdefault(key, deque(maxlen=8))
        state.destinations.move_to_end(key)
        while len(state.destinations) > 16:
            state.destinations.popitem(last=False)
        if stamps and ts <= stamps[-1]:
            return []
        stamps.append(ts)
        while stamps and stamps[0] < ts - 120:
            stamps.popleft()
        if len(stamps) >= 3 and stamps[-1] - stamps[0] >= 30:
            return self._finding("ddns_unusual_port", "Repeated dynamic DNS connections used an uncommon destination port.",
                                 {"provider": provider, "remote_port": port,
                                  "observations": len(stamps)}, identity, now)
        return []

    def _observe_child(self, record, identity, ts, now):
        parent = _identity(record, "parent_")
        name = record.get("process_name")
        if identity is None or parent is None or not isinstance(name, str):
            return []
        state = self._processes.get(parent)
        if state is None or state.media_ts is None or not 0 <= ts - state.media_ts <= 15:
            return []
        leaf = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        leaf = leaf[:-4] if leaf.endswith(".exe") else leaf
        if leaf in _SHELLS:
            return self._finding("renderer_shell_child", "A renderer or WebView spawned a shell shortly after media rendering.",
                                 {"parent_pid": parent[0], "parent_create_time": parent[1],
                                  "child_category": "shell", "delay_seconds": round(ts - state.media_ts, 3)},
                                 identity, now, "High")
        return []

    @staticmethod
    def _sensitive_path(value):
        if not isinstance(value, str):
            return None
        path = "/" + value.replace("\\", "/").lower().strip("/") + "/"
        browser = ("/google/chrome/user data/", "/microsoft/edge/user data/",
                   "/mozilla/firefox/profiles/", "/.mozilla/firefox/", "/.config/chromium/",
                   "/application support/google/chrome/", "/application support/firefox/profiles/")
        vaults = ("/microsoft/credentials/", "/microsoft/vault/", "/keychains/", "/.ssh/", "/.gnupg/")
        if any(marker in path for marker in browser):
            return "browser_profile"
        if any(marker in path for marker in vaults):
            return "credential_store"
        return None

    def _observe_http(self, record, identity, now):
        url = record.get("url", "")
        try:
            parts = urlsplit(url) if isinstance(url, str) else None
            scheme = parts.scheme.lower() if parts and parts.scheme else record.get("scheme")
            host = parts.hostname if parts and parts.hostname else record.get("host")
            names = [name for name, _value in parse_qsl(parts.query, max_num_fields=64)] if parts else []
        except (ValueError, TypeError):
            return []
        if scheme != "http" or not isinstance(host, str):
            return []
        host = _domain(host) or self._ip_host(host)
        if host is None:
            return []
        field_names = record.get("field_names", [])
        if isinstance(field_names, (list, tuple)):
            names.extend(name for name in field_names if isinstance(name, str))
        for key in ("fields", "query", "headers"):
            fields = record.get(key)
            if isinstance(fields, dict):
                names.extend(fields.keys())
        types = sorted({name.lower() for name in names if name.lower() in {"idfa", "gaid"}})
        if types:
            return self._finding("cleartext_advertising_identifier", "Advertising identifier fields were observed in cleartext HTTP telemetry.",
                                 {"identifier_types": types, "host": host}, identity, now)
        return []

    @staticmethod
    def _ip_host(host):
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None
