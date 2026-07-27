"""Bounded, read-side causal incident graph for Angerona telemetry.

This builder consumes one immutable event snapshot. It never subscribes to the
EventBus, performs database I/O, calls AI, or changes the host. That keeps graph
work off the producer hot path while giving analysts an explainable structure:
each edge states its relation, evidence basis, and confidence.

Time proximity is represented as ``precedes`` and is never mislabeled as proof
of causation. Stronger relations require explicit process/file/network identity,
parentage, correlation identifiers, or a response event that names its trigger.
"""
from __future__ import annotations

import hashlib
import heapq
import json
from pathlib import PureWindowsPath
from typing import Any, Iterable


GRAPH_SCHEMA_VERSION = 1
DEFAULT_MAX_EVENTS = 1_000
DEFAULT_MAX_NODES = 2_500
DEFAULT_MAX_EDGES = 5_000
PROCESS_REUSE_GAP_S = 600.0

_PID_KEYS = ("pid", "process_id", "target_pid", "child_pid")
_PPID_KEYS = ("ppid", "parent_pid", "parentpid")
_START_KEYS = ("process_start_time", "create_time", "start_time", "process_instance_id")
_EXE_KEYS = ("process_path", "image", "exe", "executable", "process_name", "name")
_FILE_KEYS = ("path", "artifact_path", "file", "filepath", "target_path")
_NET_KEYS = (
    "remote_ip", "dest_ip", "destination", "remote", "raddr",
    "dest_hostname", "remote_addr",
)
_CORRELATION_KEYS = ("correlation_id", "run_id", "probe_id", "incident_id", "drill_id")
_MITRE_KEYS = ("mitre", "mitre_tags", "mitre_id", "technique", "technique_id")


def _first(details: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = details.get(key)
        if value not in (None, ""):
            return value
    return None


def _integer(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _canonical_digest(value: Any, length: int = 24) -> str:
    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()[:length]


def _event_fact(event: Any) -> dict[str, Any]:
    details = getattr(event, "details", None)
    if not isinstance(details, dict):
        details = {}
    try:
        severity = int(getattr(event, "severity", 0))
    except (TypeError, ValueError):
        severity = 0
    try:
        ts = float(getattr(event, "ts", 0.0) or 0.0)
    except (TypeError, ValueError):
        ts = 0.0
    module = str(getattr(event, "module", "Unknown"))[:160]
    message = str(getattr(event, "message", ""))[:512]
    signature = str(getattr(event, "hmac_sig", "") or "")
    identity = signature if signature else _canonical_digest({
        "module": module,
        "message": message,
        "severity": severity,
        "ts": ts,
        "details": details,
    }, 64)
    return {
        "event_id": f"EV:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}",
        "module": module,
        "message": message,
        "severity": severity,
        "ts": ts,
        "details": details,
    }


def _mitre_values(details: dict) -> list[str]:
    values: list[str] = []
    for key in _MITRE_KEYS:
        raw = details.get(key)
        if raw in (None, ""):
            continue
        items = raw if isinstance(raw, (list, tuple, set)) else str(raw).replace(",", "/").split("/")
        for item in items:
            value = str(item).strip().upper()
            if value.startswith("T") and value not in values:
                values.append(value[:16])
    return values[:32]


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, value: str) -> None:
        self.parent.setdefault(value, value)

    def find(self, value: str) -> str:
        self.add(value)
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def union(self, left: str, right: str) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


class _Builder:
    def __init__(self, max_nodes: int, max_edges: int) -> None:
        self.max_nodes = max(32, int(max_nodes))
        self.max_edges = max(32, int(max_edges))
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.uf = _UnionFind()
        self.dropped_nodes = 0
        self.dropped_edges = 0
        self.active_processes: dict[
            tuple[str, str, int], tuple[str, float, str]
        ] = {}
        self.last_event_for_process: dict[str, str] = {}
        self.events_by_module_time: list[tuple[float, str, str]] = []

    def node(
        self,
        node_id: str,
        kind: str,
        label: str,
        ts: float,
        **metadata: Any,
    ) -> str | None:
        if node_id in self.nodes:
            row = self.nodes[node_id]
            row["last_ts"] = max(float(row["last_ts"]), float(ts))
            return node_id
        if len(self.nodes) >= self.max_nodes:
            self.dropped_nodes += 1
            return None
        self.nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "label": str(label)[:256],
            "first_ts": float(ts),
            "last_ts": float(ts),
            **metadata,
        }
        self.uf.add(node_id)
        return node_id

    def edge(
        self,
        source: str | None,
        target: str | None,
        relation: str,
        *,
        basis: str,
        confidence: float,
        evidence: list[str],
        structural: bool = True,
    ) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, relation)
        if key in self.edges:
            existing = self.edges[key]
            merged = list(dict.fromkeys(existing["evidence"] + evidence))[:16]
            existing["evidence"] = merged
            existing["confidence"] = max(existing["confidence"], float(confidence))
            return
        if len(self.edges) >= self.max_edges:
            self.dropped_edges += 1
            return
        self.edges[key] = {
            "source": source,
            "target": target,
            "relation": relation,
            "basis": basis,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "evidence": list(dict.fromkeys(evidence))[:16],
        }
        if structural:
            self.uf.union(source, target)

    def process_identity(
        self,
        *,
        details: dict,
        ts: float,
        pid: int,
        exe: str,
        host: str,
        boot: str,
    ) -> str:
        explicit = _first(details, _START_KEYS)
        base = (host, boot, pid)
        exe_norm = exe.casefold()
        if explicit not in (None, ""):
            instance = str(explicit)[:96]
        else:
            current = self.active_processes.get(base)
            if (
                current is not None
                and current[2] == exe_norm
                and 0.0 <= ts - current[1] <= PROCESS_REUSE_GAP_S
            ):
                self.active_processes[base] = (current[0], ts, exe_norm)
                return current[0]
            instance = f"observed-{ts:.6f}"
        identity_fact = {
            "host": host,
            "boot": boot,
            "pid": pid,
            "instance": instance,
            "exe": exe_norm,
        }
        node_id = f"PROC:{_canonical_digest(identity_fact)}"
        self.active_processes[base] = (node_id, ts, exe_norm)
        return node_id

    def add_event(self, fact: dict[str, Any]) -> None:
        event_id = fact["event_id"]
        ts = fact["ts"]
        details = fact["details"]
        event_node = self.node(
            event_id,
            "event",
            f"{fact['module']}: {fact['message']}",
            ts,
            module=fact["module"],
            severity=fact["severity"],
            mitre=_mitre_values(details),
        )
        if event_node is None:
            return

        host = str(details.get("host_id") or details.get("hostname") or "local")[:128]
        boot = str(details.get("boot_id") or "current")[:128]
        pid = _integer(_first(details, _PID_KEYS))
        exe = str(_first(details, _EXE_KEYS) or "unknown")[:512]
        process_node: str | None = None
        if pid is not None:
            process_id = self.process_identity(
                details=details,
                ts=ts,
                pid=pid,
                exe=exe,
                host=host,
                boot=boot,
            )
            process_node = self.node(
                process_id,
                "process",
                f"{PureWindowsPath(exe).name or exe} (PID {pid})",
                ts,
                pid=pid,
                executable=exe[:256],
                host=host,
                boot_id=boot,
            )
            self.edge(
                event_node,
                process_node,
                "detector-evidence",
                basis="event carries process identity",
                confidence=0.95,
                evidence=[event_id],
            )
            previous = self.last_event_for_process.get(process_id)
            if previous:
                self.edge(
                    previous,
                    event_node,
                    "precedes",
                    basis="shared process identity and event time",
                    confidence=0.70,
                    evidence=[previous, event_id],
                    structural=False,
                )
            self.last_event_for_process[process_id] = event_node

            ppid = _integer(_first(details, _PPID_KEYS))
            if ppid is not None and ppid != pid:
                parent_base = (host, boot, ppid)
                partial_parent = {
                    "host": host,
                    "boot": boot,
                    "pid": ppid,
                    "instance": "unknown",
                }
                parent_id = (
                    self.active_processes.get(parent_base, ("", 0.0, ""))[0]
                    or f"PROC:{_canonical_digest(partial_parent)}"
                )
                parent_node = self.node(
                    parent_id,
                    "process",
                    f"PID {ppid}",
                    ts,
                    pid=ppid,
                    host=host,
                    boot_id=boot,
                    identity_quality="partial",
                )
                self.edge(
                    parent_node,
                    process_node,
                    "parent-process",
                    basis="explicit parent PID telemetry",
                    confidence=0.90,
                    evidence=[event_id],
                )

        file_value = _first(details, _FILE_KEYS)
        if file_value not in (None, ""):
            raw_path = str(file_value)[:1024]
            normalized = raw_path.replace("/", "\\").casefold()
            file_id = f"FILE:{_canonical_digest(normalized)}"
            file_node = self.node(
                file_id,
                "file",
                PureWindowsPath(raw_path).name or "[file]",
                ts,
            )
            self.edge(
                process_node or event_node,
                file_node,
                "process-file" if process_node else "event-file",
                basis="explicit file field in telemetry",
                confidence=0.90,
                evidence=[event_id],
            )

        network_value = _first(details, _NET_KEYS)
        if network_value not in (None, ""):
            remote = str(network_value)[:512]
            network_id = f"NET:{_canonical_digest(remote.casefold())}"
            network_node = self.node(
                network_id,
                "network",
                remote,
                ts,
            )
            self.edge(
                process_node or event_node,
                network_node,
                "process-network" if process_node else "event-network",
                basis="explicit remote endpoint field in telemetry",
                confidence=0.90,
                evidence=[event_id],
            )

        correlation = _first(details, _CORRELATION_KEYS)
        if correlation not in (None, ""):
            corr_text = str(correlation)[:256]
            correlation_id = f"CORR:{_canonical_digest(corr_text)}"
            correlation_node = self.node(
                correlation_id,
                "correlation",
                "Explicit correlation",
                ts,
            )
            self.edge(
                event_node,
                correlation_node,
                "explicit-correlation",
                basis="producer-supplied correlation identifier",
                confidence=1.0,
                evidence=[event_id],
            )

        receipt_id = details.get("receipt_id")
        if receipt_id:
            receipt_text = str(receipt_id)[:128]
            proof_id = f"PROOF:{_canonical_digest(receipt_text)}"
            proof_node = self.node(
                proof_id,
                "proof",
                receipt_text,
                ts,
                receipt_hash=str(details.get("receipt_hash") or "")[:64],
                verification=bool(details.get("verified")),
            )
            self.edge(
                event_node,
                proof_node,
                "verification-proof",
                basis="event names a signed remediation receipt",
                confidence=1.0,
                evidence=[event_id],
            )

        trigger_module = str(details.get("trigger_module") or "")
        trigger_ts = details.get("trigger_ts")
        if trigger_module and trigger_ts not in (None, ""):
            try:
                wanted_ts = float(trigger_ts)
            except (TypeError, ValueError):
                wanted_ts = -1.0
            candidates = [
                (abs(seen_ts - wanted_ts), seen_event)
                for seen_ts, seen_module, seen_event in self.events_by_module_time
                if seen_module == trigger_module and abs(seen_ts - wanted_ts) <= 2.0
            ]
            if candidates:
                _, trigger_event = min(candidates)
                self.edge(
                    event_node,
                    trigger_event,
                    "response-target",
                    basis="response names trigger module and timestamp",
                    confidence=1.0,
                    evidence=[event_id, trigger_event],
                )

        self.events_by_module_time.append((ts, fact["module"], event_node))

    def result(self, *, input_events: int, retained_events: int) -> dict[str, Any]:
        components: dict[str, list[str]] = {}
        for node_id in self.nodes:
            root = self.uf.find(node_id)
            components.setdefault(root, []).append(node_id)

        incidents: list[dict[str, Any]] = []
        for node_ids in components.values():
            event_ids = [
                node_id for node_id in node_ids
                if self.nodes[node_id]["kind"] == "event"
            ]
            if not event_ids:
                continue
            event_rows = [self.nodes[node_id] for node_id in event_ids]
            incident_id = f"CINC-{_canonical_digest(sorted(node_ids), 16).upper()}"
            incidents.append({
                "id": incident_id,
                "first_ts": min(row["first_ts"] for row in event_rows),
                "last_ts": max(row["last_ts"] for row in event_rows),
                "max_severity": max(int(row.get("severity", 0)) for row in event_rows),
                "event_count": len(event_ids),
                "entity_count": len(node_ids) - len(event_ids),
                "modules": sorted({
                    str(row.get("module", "Unknown")) for row in event_rows
                }),
                "evidence": sorted(event_ids),
            })
        incidents.sort(key=lambda row: (-row["max_severity"], -row["last_ts"], row["id"]))

        nodes = sorted(
            self.nodes.values(),
            key=lambda row: (row["first_ts"], row["kind"], row["id"]),
        )
        edges = sorted(
            self.edges.values(),
            key=lambda row: (row["source"], row["target"], row["relation"]),
        )
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "as_of": max((row["last_ts"] for row in nodes), default=0.0),
            "incidents": incidents,
            "nodes": nodes,
            "edges": edges,
            "limits": {
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
            },
            "stats": {
                "input_events": input_events,
                "retained_events": retained_events,
                "nodes": len(nodes),
                "edges": len(edges),
                "incidents": len(incidents),
                "dropped_events": max(0, input_events - retained_events),
                "dropped_nodes": self.dropped_nodes,
                "dropped_edges": self.dropped_edges,
            },
        }


def build_graph(
    events: Iterable[Any],
    *,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> dict[str, Any]:
    """Build a deterministic, bounded graph from an event iterable."""
    bounded_events = max(1, min(100_000, int(max_events)))
    # Keep the newest facts by event time, independent of input iteration order,
    # while retaining O(max_events) memory for very large snapshots.
    retained: list[tuple[float, str, int, dict[str, Any]]] = []
    input_count = 0
    for event in events:
        input_count += 1
        fact = _event_fact(event)
        item = (fact["ts"], fact["event_id"], input_count, fact)
        if len(retained) < bounded_events:
            heapq.heappush(retained, item)
        elif item[:2] > retained[0][:2]:
            heapq.heapreplace(retained, item)
    facts = [item[3] for item in retained]
    facts.sort(key=lambda row: (row["ts"], row["event_id"]))
    builder = _Builder(max_nodes=max_nodes, max_edges=max_edges)
    for fact in facts:
        builder.add_event(fact)
    return builder.result(input_events=input_count, retained_events=len(facts))
