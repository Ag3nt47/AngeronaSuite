"""Entity-scoped fusion of independent, otherwise weak defensive signals.

Angerona already groups alerts by time and requires corroboration before SOAR
containment.  Evidence Lattice fills a narrower gap: it joins MEDIUM events
that name the *same structured entity* (PID, file hash/path, or remote address)
and promotes them only when three distinct modules spanning at least two sensor
domains agree inside a short window.

The engine is deliberately local, deterministic, bounded, and response-free.
It never polls the host, calls a model, sends data, or performs containment.
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule


_PID_KEYS = ("pid", "process_id", "target_pid", "child_pid")
_HASH_KEYS = ("sha256", "file_hash", "hash")
_PATH_KEYS = ("path", "file", "filepath", "image", "exe")
_NET_KEYS = ("dest_ip", "remote_ip", "raddr", "remote", "destination")

_DOMAIN_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("memory", ("memory", "amsi", "api patch", "inject")),
    ("network", ("network", "wfp", "packet", "beacon", "arp", "wlan", "dns")),
    ("file", ("file", "yara", "ransomware", "deception", "integrity")),
    ("identity", ("identity", "auth", "credential", "lsass", "persistence")),
    ("process", ("process", "etw", "sysmon", "telemetry")),
    ("defense", ("defender", "antivirus", "av telemetry", "soar")),
)


@dataclass(frozen=True)
class EvidenceFinding:
    entity_type: str
    entity: str
    modules: tuple[str, ...]
    domains: tuple[str, ...]
    confidence: int
    signal_count: int


@dataclass(frozen=True)
class _Signal:
    seen_at: float
    module: str
    domain: str


def _first(details: dict, keys: tuple[str, ...]):
    for key in keys:
        value = details.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _entity(details: dict) -> tuple[str, str] | None:
    """Return a conservative canonical entity from structured telemetry only."""
    raw_pid = _first(details, _PID_KEYS)
    if raw_pid is not None:
        try:
            pid = int(raw_pid)
            if 0 < pid <= 0xFFFFFFFF:
                return "pid", str(pid)
        except (TypeError, ValueError):
            pass

    raw_hash = _first(details, _HASH_KEYS)
    if raw_hash is not None:
        value = str(raw_hash).strip().lower()
        if len(value) >= 32 and all(ch in "0123456789abcdef" for ch in value):
            return "file_hash", value

    raw_path = _first(details, _PATH_KEYS)
    if raw_path is not None:
        value = os.path.normcase(os.path.normpath(str(raw_path).strip()))
        if value and value not in (".", os.path.sep):
            return "path", value

    raw_net = _first(details, _NET_KEYS)
    if raw_net is not None:
        value = str(raw_net).strip()
        # Accept a bare IP or a common ip:port form; do not correlate arbitrary
        # host-like strings that could collapse unrelated telemetry.
        host = value
        if value.count(":") == 1 and "." in value:
            host = value.rsplit(":", 1)[0]
        try:
            return "ip", str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            pass
    return None


def _domain(module: str, details: dict) -> str:
    name = (module or "").casefold()
    for domain, tokens in _DOMAIN_TOKENS:
        if any(token in name for token in tokens):
            return domain
    keys = {str(key).casefold() for key in details}
    if keys.intersection(_NET_KEYS):
        return "network"
    if keys.intersection(_HASH_KEYS + _PATH_KEYS):
        return "file"
    if keys.intersection(("user", "account", "sid", "logon_id")):
        return "identity"
    if keys.intersection(("address", "protection", "allocation_type")):
        return "memory"
    return "other"


class EvidenceLattice:
    """Bounded, thread-safe entity correlation engine."""

    def __init__(
        self,
        window_s: float = 90.0,
        min_modules: int = 3,
        min_domains: int = 2,
        max_entities: int = 512,
        max_signals_per_entity: int = 16,
        dedup_s: float = 180.0,
    ) -> None:
        self.window_s = max(1.0, float(window_s))
        self.min_modules = max(2, int(min_modules))
        self.min_domains = max(2, int(min_domains))
        self.max_entities = max(8, int(max_entities))
        self.max_signals = max(4, int(max_signals_per_entity))
        self.dedup_s = max(self.window_s, float(dedup_s))
        self._buckets: OrderedDict[tuple[str, str], deque[_Signal]] = OrderedDict()
        self._dedup_until: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = threading.Lock()

    def ingest(self, event: Event, now: float | None = None) -> EvidenceFinding | None:
        # Strong alerts already have their own incident/SOAR paths. The lattice
        # exists specifically to elevate independent weak evidence without
        # creating duplicate alerts for an already-HIGH detection.
        if event.module == EvidenceLatticeModule.name or event.severity != Severity.MEDIUM:
            return None
        entity = _entity(event.details or {})
        if entity is None:
            return None
        current = time.time() if now is None else float(now)
        signal = _Signal(current, str(event.module), _domain(event.module, event.details or {}))

        with self._lock:
            expiry = self._dedup_until.get(entity, 0.0)
            if current < expiry:
                return None
            if expiry:
                self._dedup_until.pop(entity, None)

            bucket = self._buckets.get(entity)
            if bucket is None:
                bucket = deque(maxlen=self.max_signals)
                self._buckets[entity] = bucket
            else:
                self._buckets.move_to_end(entity)

            cutoff = current - self.window_s
            while bucket and bucket[0].seen_at < cutoff:
                bucket.popleft()
            bucket.append(signal)

            while len(self._buckets) > self.max_entities:
                self._buckets.popitem(last=False)

            modules = sorted({item.module for item in bucket})
            domains = sorted({item.domain for item in bucket if item.domain != "other"})
            if len(modules) < self.min_modules or len(domains) < self.min_domains:
                return None

            finding = EvidenceFinding(
                entity_type=entity[0],
                entity=entity[1],
                modules=tuple(modules),
                domains=tuple(domains),
                confidence=min(95, 45 + len(modules) * 10 + len(domains) * 8),
                signal_count=len(bucket),
            )
            self._buckets.pop(entity, None)
            self._dedup_until[entity] = current + self.dedup_s
            self._dedup_until.move_to_end(entity)
            while len(self._dedup_until) > self.max_entities:
                self._dedup_until.popitem(last=False)
            return finding

    def counts(self) -> tuple[int, int]:
        with self._lock:
            return len(self._buckets), len(self._dedup_until)


class EvidenceLatticeModule(BaseModule):
    CODE = "ELAT"
    NAME = "Evidence Lattice Fusion"
    name = "Evidence Lattice Fusion"
    description = (
        "Fuses MEDIUM signals about the same PID, path/hash, or IP across three "
        "independent modules and two sensor domains; emits an explainable HIGH "
        "finding without polling, cloud access, or automatic response."
    )
    category = "Detection"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self.lattice = EvidenceLattice()
        self._findings = 0
        self._subscribed = False

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def _on_event(self, event: Event) -> None:
        if self.stopping:
            return
        finding = self.lattice.ingest(event)
        if finding is None:
            return
        self._findings += 1
        modules = ", ".join(finding.modules)
        self.emit(
            f"Evidence lattice: {finding.entity_type} {finding.entity} has "
            f"{finding.signal_count} MEDIUM signals from {len(finding.modules)} "
            f"modules across {len(finding.domains)} domains (confidence "
            f"{finding.confidence}%). Sources: {modules}",
            Severity.HIGH,
            entity_type=finding.entity_type,
            entity=finding.entity,
            modules=list(finding.modules),
            domains=list(finding.domains),
            confidence=finding.confidence,
            signal_count=finding.signal_count,
            correlation="entity_lattice",
        )

    def run(self) -> None:
        # EventBus subscriptions live for the process lifetime. Reuse the first
        # subscription across an operator stop/start instead of multiplying it.
        if self._bus is not None and not self._subscribed:
            self._bus.subscribe(self._on_event)
            self._subscribed = True
        self.emit(
            "ELAT online — correlating independent weak signals by structured entity.",
            Severity.INFO,
        )
        while not self.stopping:
            active, dedup = self.lattice.counts()
            self.set_health(100, f"{active} active entities / {self._findings} findings / {dedup} dedup")
            self.sleep(15.0)

    def self_test(self) -> tuple[bool, str]:
        def event(module: str, severity: Severity, pid: int) -> Event:
            return Event(module=module, message="synthetic suspicious signal",
                         severity=severity, ts=1.0, details={"pid": pid})

        # Malicious-looking case: three independent MEDIUM observations about
        # one process, spanning process/memory/network, must fuse exactly once.
        lattice = EvidenceLattice(window_s=10, dedup_s=20)
        a = lattice.ingest(event("Process Monitor", Severity.MEDIUM, 4242), now=1)
        b = lattice.ingest(event("Memory Injection Scanner", Severity.MEDIUM, 4242), now=2)
        hit = lattice.ingest(event("Network Monitor", Severity.MEDIUM, 4242), now=3)
        duplicate = lattice.ingest(event("AV Telemetry Bridge", Severity.MEDIUM, 4242), now=4)
        suspicious_ok = (
            a is None and b is None and hit is not None and duplicate is None
            and hit.entity == "4242" and len(hit.modules) == 3
            and set(hit.domains) == {"memory", "network", "process"}
        )

        # False-positive controls: repetitions from one sensor, low/INFO noise,
        # strong alerts (handled elsewhere), and unrelated entities never fuse.
        benign = EvidenceLattice(window_s=10)
        repeated = [benign.ingest(event("Process Monitor", Severity.MEDIUM, 5000), now=i)
                    for i in range(1, 6)]
        noise = [benign.ingest(event(name, sev, 6000), now=6 + i)
                 for i, (name, sev) in enumerate((
                     ("Process Monitor", Severity.INFO),
                     ("Memory Injection Scanner", Severity.LOW),
                     ("Network Monitor", Severity.HIGH),
                 ))]
        separate = [benign.ingest(event(name, Severity.MEDIUM, pid), now=9 + i)
                    for i, (name, pid) in enumerate((
                        ("Process Monitor", 7001),
                        ("Memory Injection Scanner", 7002),
                        ("Network Monitor", 7003),
                    ))]
        benign_ok = not any(repeated + noise + separate)

        # Expired evidence must not combine with a later signal.
        expiry = EvidenceLattice(window_s=5)
        expiry.ingest(event("Process Monitor", Severity.MEDIUM, 8000), now=1)
        expiry.ingest(event("Memory Injection Scanner", Severity.MEDIUM, 8000), now=2)
        expired_hit = expiry.ingest(event("Network Monitor", Severity.MEDIUM, 8000), now=9)
        expiry_ok = expired_hit is None

        ok = suspicious_ok and benign_ok and expiry_ok
        detail = (
            "entity fusion, dedup, time-window expiry, and false-positive controls passed"
            if ok else
            f"failed: suspicious={suspicious_ok} benign={benign_ok} expiry={expiry_ok}"
        )
        return ok, detail


def register() -> EvidenceLatticeModule:
    return EvidenceLatticeModule()
