"""Bounded read-only topology for the Suite Map; no native queries or control.

Module/drive facts come from existing cached owners. Event counts describe only
this viewer's observed publications, not subscriber delivery or attack proof.
Physical devices and cables invisible to the OS cannot be inventoried here.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import math
import queue
import threading
import time
import unicodedata

from angerona.core.eventbus import Event

MAX_MODULES = 192
MAX_PORTS = 48
MAX_DRIVES = 128
MAX_NODES = 400
MAX_EDGES = 512


def _text(value, limit=512):
    if type(value) is not str:
        return ""
    return "".join(char if char in "\n\t" or unicodedata.category(char)[0] != "C" else " " for char in value[:limit])


def _identity(kind, value):
    return kind + ":" + hashlib.sha256(value.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class TopologyNode:
    id: str
    label: str
    kind: str
    status: str
    health: int | None
    position: tuple[float, float, float]
    info: tuple[tuple[str, str], ...]
    route: str = ""
    target: str = ""


@dataclass(frozen=True)
class TopologyEdge:
    source: str
    target: str
    label: str
    observed: bool = False
    count: int = 0
    active: bool = False


@dataclass(frozen=True)
class TopologySnapshot:
    generation: int = 0
    nodes: tuple[TopologyNode, ...] = ()
    edges: tuple[TopologyEdge, ...] = ()
    events: int = 0
    dropped: int = 0
    omitted: int = 0
    state: str = "waiting"
    coverage: tuple[str, ...] = ()


class SuiteTopologyService:
    def __init__(self, manager, bus, *, clock=time.monotonic):
        self.manager, self.bus, self.clock = manager, bus, clock
        self._lock = threading.Lock()
        self._snapshot = TopologySnapshot()
        self._queue = queue.Queue(maxsize=512)
        self._stop = threading.Event()
        self._thread = None
        self._counts, self._recent = Counter(), {}
        self._ports = {}
        self._events = self._dropped = self._omitted = 0
        self._subscribed = False

    def _observe(self, event):
        if self._stop.is_set() or type(event) is not Event or type(event.module) is not str:
            return
        # Copy only bounded plain display fields. No event text, commands,
        # signatures, keys, files or response capabilities enter this model.
        details = event.details if type(event.details) is dict else {}
        port = details.get("remote_port", details.get("dport", details.get("dst_port")))
        address = details.get("remote_ip", details.get("dst_ip"))
        endpoint = details.get("raddr")
        if (type(port) is not int or type(address) is not str) and type(endpoint) is str and len(endpoint) <= 180:
            candidate, separator, raw_port = endpoint.rpartition(":")
            if separator and raw_port.isascii() and raw_port.isdecimal() and len(raw_port) <= 5:
                address, port = candidate.strip("[]"), int(raw_port)
        if type(port) is not int or not 1 <= port <= 65535:
            port = None
        address = _text(address, 128)
        try:
            self._queue.put_nowait((_text(event.module, 200), port, address))
        except queue.Full:
            self._dropped += 1

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return not self._stop.is_set()
        self._stop.clear()
        self.bus.subscribe(self._observe)
        self._subscribed = True
        self._thread = threading.Thread(target=self._run, name="SuiteMapSnapshot", daemon=True)
        self._thread.start()
        return True

    def request_shutdown(self):
        self._stop.set()

    def owned_workers(self):
        return (self._thread,) if self._thread is not None else ()

    def custody_released(self):
        return self._thread is None or not self._thread.is_alive()

    def snapshot(self):
        with self._lock:
            return self._snapshot

    def _build(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("Topology clock unavailable")
        for _ in range(512):
            try:
                module, port, address = self._queue.get_nowait()
            except queue.Empty:
                break
            self._events += 1
            if module in self._counts or len(self._counts) < MAX_MODULES:
                self._counts[module] += 1
                self._recent[module] = now
            else:
                self._omitted += 1
            if port is not None and address:
                key = (module, address, port)
                if key in self._ports or len(self._ports) < MAX_PORTS:
                    self._ports[key] = now
                else:
                    self._omitted += 1
        nodes = [
            TopologyNode("host", "Computer / server", "host", "local host", None, (0, 0, -4.2),
                (("Scope", "This host and cached host-visible devices; no remote probing"),), "worldview"),
            TopologyNode("core", "Angerona Core", "core", "viewer connected", None, (0, 1.4, 0),
                (("Role", "Module lifecycle and policy owner"), ("Boundary", "User-mode; presence is not proof of complete protection")), "health"),
            TopologyNode("bus", "EventBus", "bus", "publications observed", None, (0, 0, 0),
                (("Publications", str(self._events)), ("Coverage", "Observed while this viewer was active; hidden intervals are not observed. Not per-subscriber delivery proof")), "alerts"),
            TopologyNode("recorder", "Flight recorder", "storage", "architectural link", None, (-2.4, 0, 0),
                (("Role", "Retained event and audit evidence"), ("Coverage", "This map does not inspect SQL or verify durable commits")), "blackbox"),
            TopologyNode("dashboard", "Dashboard", "dashboard", "local UI", None, (2.4, 0, 0),
                (("Role", "Review alerts, coverage and operator controls"),), "dashboard"),
            TopologyNode("watchdog", "Watchdog", "watchdog", "see authenticated heartbeats", None, (0, 3.1, 0),
                (("Role", "Mutual recovery and authenticated peer-progress checks"), ("Coverage", "Open component health for fresh native-bound liveness; this node is a topology label")), "health"),
            TopologyNode("scanner", "Scanner service", "scanner", "see scan status", None, (-3.2, 1.8, 0),
                (("Role", "Owned scanning jobs and bounded reports"),), "spyware"),
            TopologyNode("blackbox", "Black Box", "storage", "see diagnostic status", None, (3.2, 1.8, 0),
                (("Role", "Independent diagnostic and recovery review interface"),), "blackbox"),
        ]
        edges = [TopologyEdge("core", "bus", "publishes and orchestrates"),
            TopologyEdge("bus", "recorder", "recorder subscription; delivery not measured"),
            TopologyEdge("bus", "dashboard", "dashboard subscription; delivery not measured"),
            TopologyEdge("core", "watchdog", "mutual supervision"),
            TopologyEdge("watchdog", "core", "verified recovery requests"),
            TopologyEdge("core", "scanner", "owned scan lifecycle"),
            TopologyEdge("core", "blackbox", "diagnostic peer lifecycle")]
        components = (
            ("processor", "CPU / processor", "Host execution resources; open World View for measured usage", "worldview"),
            ("memory", "Physical memory / RAM", "Host memory resources; this map does not read process memory", "worldview"),
            ("os", "Operating system", "OS/kernel boundary: Ring 3 observations do not attest kernel integrity", "worldview"),
            ("network", "Network stack", "Observed network paths and endpoints; no active port scan is started by this map", "network"),
            ("ai", "Local AI / Ollama", "Optional local context and triage; topology does not load a model or grant response authority", "worldview"),
            ("rules", "Rules & playbooks", "Reviewed data, explicit opt-ins, tests and rollback; imported code is not auto-executed", "rules"),
            ("tools", "Community tool library", "Pinned source review, managed tools, editable sandbox copies and credits", "tools"),
            ("recovery", "Recovery / startup", "Verified startup, bounded recovery storage and preserved settings", "settings"),
        )
        for index, (key, label, purpose, route) in enumerate(components):
            position = (4.8 * math.cos(index * math.tau / len(components)), 5.6,
                        4.8 * math.sin(index * math.tau / len(components)))
            nodes.append(TopologyNode(key, label, "component", "architectural component", None,
                position, (("Purpose", purpose), ("Status", "Open the owning view for current measured coverage")), route))
            edges.append(TopologyEdge("host" if index < 4 else "core", key, "architectural relationship"))
        modules = tuple(self.manager.modules.items())
        coverage, omitted = [], max(0, len(modules) - MAX_MODULES)
        for index, (name, module) in enumerate(modules[:MAX_MODULES]):
            if type(name) is not str:
                omitted += 1
                continue
            state = vars(module)
            health = state.get("health")
            health = health if type(health) is int and 0 <= health <= 100 else None
            status = _text(state.get("_status", "unavailable"), 80) or "unavailable"
            lifecycle, policy_reason = status, "Policy not supplied by this cached owner"
            config = getattr(self.manager, "config", None)
            if config is not None:
                try:
                    from angerona.core.module_usage import usage_for, chill_module_hold
                    usage = usage_for(module, config, getattr(self.manager, "platform", None),
                        kernel_installed=getattr(self.manager, "_kernel_installed", None))
                    hold = chill_module_hold(module, config)
                    policy_reason = hold or usage.reason
                    if hold:
                        status = "paused"
                    elif not usage.enabled:
                        status = usage.state
                except (AttributeError, KeyError, TypeError, ValueError):
                    policy_reason = "Policy unavailable; lifecycle health alone does not establish response authority"
            turn = index * math.pi * (3 - math.sqrt(5))
            height = 1 - 2 * (index + .5) / max(1, min(len(modules), MAX_MODULES))
            radius = math.sqrt(max(0, 1 - height * height))
            position = (5.4 * radius * math.cos(turn), 4.3 * height, 5.4 * radius * math.sin(turn))
            identifier = _identity("module", name)
            cls = type(module)
            capabilities = getattr(cls, "capability_outputs", ())
            caps = ", ".join(_text(value, 100) for value in capabilities[:16]) if type(capabilities) in (list, tuple) else ""
            info = (("Status", status), ("Worker lifecycle", lifecycle), ("Policy", _text(policy_reason, 512)),
                ("Health", str(health) + "%" if health is not None else "Unavailable"),
                ("Reason", _text(state.get("health_note"), 1024)),
                ("Purpose", _text(getattr(cls, "description", ""), 2048)),
                ("Capabilities", caps or "See module inspector"),
                ("Observed publications", str(self._counts.get(name, 0))))
            nodes.append(TopologyNode(identifier, _text(name, 200), "module", status, health, position, info, "module", name))
            count = self._counts.get(name, 0)
            active = count > 0 and 0 <= now - self._recent.get(name, now) <= 5
            edges.append(TopologyEdge(identifier, "bus", "observed publications" if count else "module publication path", bool(count), count, active))
            edges.append(TopologyEdge("host", identifier, "host observation / module role; not a measured delivery"))
        usb = self.manager.modules.get("Removable-Media / USB Monitor")
        drives, removable, local_drives, volume_metadata = (), frozenset(), frozenset(), {}
        if usb is not None:
            cached = vars(usb)
            drives = tuple(cached.get("_known_local_mounts", ()))
            local_drives = frozenset(drives)
            removable = frozenset(cached.get("_known", ()))
            inventory = cached.get("_cached_volume_inventory", ())
            if type(inventory) is tuple:
                for item in inventory[:256]:
                    if type(item) is tuple and len(item) == 3 and all(type(value) is str for value in item):
                        volume_metadata[item[0]] = item[1:]
            drives = tuple(sorted(set(drives) | set(removable)))
            drives = tuple(sorted(set(drives) | set(volume_metadata)))
        if not drives:
            coverage.append("Drive inventory unavailable: existing USB/volume owner has not supplied cached mounts")
        omitted += max(0, len(drives) - MAX_DRIVES)
        for index, drive in enumerate(drives[:MAX_DRIVES]):
            if type(drive) is not str:
                continue
            identifier = _identity("drive", drive)
            external = drive in removable or volume_metadata.get(drive, ("", ""))[0] == "removable"
            kind = "external_drive" if external else "internal_drive" if drive in local_drives else "volume"
            label = ("External / removable " if external else "Local volume " if drive in local_drives else "Mounted volume ") + _text(drive, 120)
            nodes.append(TopologyNode(identifier, label, kind, "cached volume observation", None,
                (-7.4, -3 + index % 8, -3 + index // 8),
                (("Mount", _text(drive, 512)), ("Classification", "Removable/USB" if external else "Known mounted volume; internal/network/physical bus not inferred"),
                 ("Filesystem", volume_metadata.get(drive, ("", "Unavailable"))[1]),
                 ("Scan / trust", "Presence does not imply approval, complete scan or safe contents; review device notifications")), "notifications"))
            edges.append(TopologyEdge("host", identifier, "cached attachment / volume"))
        peripheral = self.manager.modules.get("Peripheral and DMA Posture Guard")
        observations = vars(peripheral).get("_scan_observation") if peripheral is not None else None
        if type(observations) is tuple and len(observations) == 4:
            combinations = observations[2] if type(observations[2]) is tuple else ()
            for index, label in enumerate(combinations[:32]):
                label = _text(label, 256)
                identifier = _identity("accessory", label)
                nodes.append(TopologyNode(identifier, label, "accessory", "host-visible function combination", None,
                    (7.4, -3 + index % 8, -3 + index // 8),
                    (("Coverage", _text(observations[1], 100)), ("Meaning", "A host-visible USB function combination; not a physical inspection or proof of malicious hardware")), "devices"))
                edges.append(TopologyEdge("host", identifier, "cached peripheral observation"))
        else:
            coverage.append("Accessory inventory unavailable; invisible cable/firmware implants cannot be ruled out")
        network = self.manager.modules.get("Zero-Trust Network Path Monitor")
        paths = vars(network).get("_last_path_states", {}) if network is not None else {}
        if type(paths) is dict:
            for index, (token, state) in enumerate(tuple(paths.items())[:16]):
                if type(token) is not str or type(state) is not tuple or len(state) != 2:
                    continue
                identifier = _identity("network_path", token)
                nodes.append(TopologyNode(identifier, "Network path " + _text(token, 10), "network_path",
                    _text(state[0], 80), None, (7.5, 3.8 - index * .6, 2),
                    (("Trust", _text(state[0], 80)), ("Path token", _text(token, 128)),
                     ("Coverage", "Cached path observation; raw interface identifiers are deliberately omitted by its owner")), "network"))
                edges.append(TopologyEdge("network", identifier, "cached network-path observation"))
        for index, ((module, address, port), seen) in enumerate(self._ports.items()):
            identifier = _identity("port", f"{module}:{address}:{port}")
            nodes.append(TopologyNode(identifier, f"{address}:{port}", "port", "retained endpoint observation", None,
                (-4 + (index % 12) * .75, -6.1, -3 + (index // 12) * 1.2),
                (("Endpoint", f"{address}:{port}"), ("Observed by", module),
                 ("Age of last observation", f"{max(0, int(now - seen))} seconds; an observation does not prove a current connection"),
                 ("Meaning", "Published endpoint metadata, not a listening-port scan, ownership proof or geographic location")), "network"))
            edges.append(TopologyEdge("host", identifier, "observed endpoint metadata", True, 1, 0 <= now - seen <= 5))
        ids = {node.id for node in nodes[:MAX_NODES]}
        omitted += max(0, len(nodes) - MAX_NODES) + max(0, len(edges) - MAX_EDGES)
        edges = tuple(edge for edge in edges[:MAX_EDGES] if edge.source in ids and edge.target in ids)
        coverage.extend(("Solid bright links: publications/endpoints observed by this viewer; particles indicate recent activity",
                         "Dashed links: architectural relationships; not proof that every sensor, action or subscriber is working"))
        return TopologySnapshot(self._snapshot.generation + 1, tuple(nodes[:MAX_NODES]), edges,
            self._events, self._dropped, omitted + self._omitted, "live", tuple(coverage))

    def _run(self):
        try:
            while not self._stop.is_set():
                try:
                    snapshot = self._build()
                except (RuntimeError, TypeError, ValueError, AttributeError):
                    prior = self.snapshot()
                    snapshot = TopologySnapshot(prior.generation + 1, prior.nodes, prior.edges,
                        prior.events, self._dropped, prior.omitted, "stale",
                        ("A cached owner changed during this read; last available view retained",))
                with self._lock:
                    self._snapshot = snapshot
                self._stop.wait(1)
        finally:
            if self._subscribed:
                self.bus.unsubscribe(self._observe)
                self._subscribed = False
