"""provenance_graph.py — Data Provenance Graph Engine (Code: PROV).

Purpose
    Turn the flat event ledger into a relational Directed Acyclic Graph (DAG) so
    the suite can visualise an incident's *blast radius*: who spawned what, which
    files a process touched, and where it called out to.

Model
    Nodes are typed: ``PROC`` (process spawn), ``FIM`` (file invocation),
    ``NET`` (network connection). Edges are directed parent→child /
    process→artifact. Built from the flight-recorder SQLite ledger
    (``flight-recorder.db``, the live ``events`` table) and kept current by
    subscribing to the EventBus.

API
    ``ancestry(pid)``  — crawl UPSTREAM to the root cause / true parent threat.
    ``subtree(pid)``   — cascade DOWNSTREAM to every child, file and connection
                          the (possibly compromised) process mutated.
    ``blast_radius(pid)`` — combined node/edge arrays for the visual panel.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

_PID_RE = re.compile(r"\b(?:pid|PID)[\s=:#]*?(\d{2,7})\b")
_PPID_KEYS = ("ppid", "parent_pid", "parentpid", "parent")
_PID_KEYS = ("pid", "process_id", "target_pid", "child_pid")
# "image" is excluded from path keys — it's the exe path used as a PROC label,
# not a file artifact.  File artifacts come from "path", "filepath", etc.
_PATH_KEYS = ("path", "file", "filepath", "target", "artifact")
# G2 sysmon EID 3 emits dest_hostname + dest_ip; prefer hostname for readability.
_NET_KEYS = ("dest_hostname", "dest_ip", "raddr", "remote", "remote_addr", "dst", "destination")


class ProvenanceGraph:
    """In-memory typed DAG. Thread-safe via a single lock (state_lock)."""

    def __init__(self) -> None:
        self.state_lock = threading.Lock()
        self.nodes: dict[str, dict] = {}          # id -> {kind, label, ts, meta}
        self.edges: dict[str, set[str]] = {}      # parent id -> {child ids}
        self.parents: dict[str, set[str]] = {}    # child id -> {parent ids}

    @staticmethod
    def _safe_int(val) -> int | None:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _pid_id(pid) -> str:
        return f"PROC:{int(pid)}"

    def add_node(self, node_id: str, kind: str, label: str, ts: float, **meta) -> None:
        n = self.nodes.get(node_id)
        if n is None:
            self.nodes[node_id] = {"id": node_id, "kind": kind, "label": label,
                                   "ts": ts, "meta": meta}
        else:
            n["ts"] = max(n["ts"], ts)

    def add_edge(self, parent: str, child: str) -> None:
        if parent == child:
            return
        # keep it acyclic: skip an edge that would close a cycle (child already
        # an ancestor of parent).
        if parent in self._ancestor_ids(child):
            return
        self.edges.setdefault(parent, set()).add(child)
        self.parents.setdefault(child, set()).add(parent)

    def _ancestor_ids(self, node_id: str) -> set[str]:
        seen: set[str] = set()
        stack = list(self.parents.get(node_id, ()))
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self.parents.get(cur, ()))
        return seen

    # ── ingestion ────────────────────────────────────────────────────────────
    def ingest(self, module: str, message: str, details: dict, ts: float) -> None:
        with self.state_lock:
            # Parse pid safely in case of dirty string data like 'unknown'
            pid = self._safe_int(self._first(details, _PID_KEYS))
            if pid is None:
                m = _PID_RE.search(message or "")
                pid = int(m.group(1)) if m else None
            
            # Parse ppid safely as well
            ppid = self._safe_int(self._first(details, _PPID_KEYS))
            
            if pid is not None:
                pnode = self._pid_id(pid)
                # G2: sysmon EID 1 supplies "image" (full exe path); use basename
                # as label so the graph shows "cmd.exe" not just "pid 4812".
                raw_image = details.get("image", "")
                proc_label = (
                    raw_image.split("\\")[-1] if raw_image
                    else details.get("name", f"pid {pid}")
                )
                self.add_node(pnode, "PROC", proc_label, ts, module=module)
                if ppid is not None:
                    parent = self._pid_id(ppid)
                    raw_parent_image = details.get("parent_image", "")
                    parent_label = (
                        raw_parent_image.split("\\")[-1] if raw_parent_image
                        else details.get("parent_name", f"pid {ppid}")
                    )
                    self.add_node(parent, "PROC", parent_label, ts)
                    self.add_edge(parent, pnode)
                # file artifacts
                path = self._first(details, _PATH_KEYS)
                if path:
                    fid = f"FIM:{path}"
                    self.add_node(fid, "FIM", str(path), ts)
                    self.add_edge(pnode, fid)
                # network endpoints
                net = self._first(details, _NET_KEYS)
                if net:
                    nid = f"NET:{net}"
                    self.add_node(nid, "NET", str(net), ts)
                    self.add_edge(pnode, nid)

    @staticmethod
    def _first(d: dict, keys) -> object | None:
        for k in keys:
            if k in d and d[k] not in (None, "", []):
                return d[k]
        return None

    # ── analytical API ───────────────────────────────────────────────────────
    def ancestry(self, pid: int) -> list[dict]:
        """Upstream chain from `pid` to its root cause (nearest-first)."""
        with self.state_lock:
            start = self._pid_id(pid)
            chain, seen, frontier = [], set(), [start]
            while frontier:
                nxt = []
                for node in frontier:
                    for parent in sorted(self.parents.get(node, ())):
                        if parent in seen:
                            continue
                        seen.add(parent)
                        if parent in self.nodes:
                            chain.append(self.nodes[parent])
                        nxt.append(parent)
                frontier = nxt
            return chain

    def subtree(self, pid: int) -> list[dict]:
        """Downstream blast radius: every process/file/net reachable from `pid`."""
        with self.state_lock:
            start = self._pid_id(pid)
            out, seen, frontier = [], {start}, [start]
            while frontier:
                nxt = []
                for node in frontier:
                    for child in sorted(self.edges.get(node, ())):
                        if child in seen:
                            continue
                        seen.add(child)
                        if child in self.nodes:
                            out.append(self.nodes[child])
                        nxt.append(child)
                frontier = nxt
            return out

    def blast_radius(self, pid: int) -> dict:
        """Node + edge arrays for the real-time Blast Radius panel."""
        with self.state_lock:
            root = self._pid_id(pid)
        up = self.ancestry(pid)
        down = self.subtree(pid)
        ids = {root} | {n["id"] for n in up} | {n["id"] for n in down}
        with self.state_lock:
            nodes = [self.nodes[i] for i in ids if i in self.nodes]
            edges = [{"from": p, "to": c} for p in ids
                     for c in self.edges.get(p, ()) if c in ids]
        return {"root": root, "upstream": up, "downstream": down,
                "nodes": nodes, "edges": edges,
                "counts": {"nodes": len(nodes), "edges": len(edges)}}


class ProvenanceGraphModule(BaseModule):
    CODE = "PROV"
    NAME = "Data Provenance Graph"
    name = "Data Provenance Graph"
    description = ("Builds a PROC/FIM/NET provenance DAG from the flight recorder + "
                   "live events; exposes ancestry()/subtree() for blast-radius views.")
    category = "Forensics"
    version = "1.0.0"

    _REBUILD_INTERVAL = 20.0

    def __init__(self) -> None:
        super().__init__()
        self.graph = ProvenanceGraph()
        self._db_path: Path | None = None

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # public passthroughs
    def ancestry(self, pid: int) -> list[dict]:
        return self.graph.ancestry(pid)

    def subtree(self, pid: int) -> list[dict]:
        return self.graph.subtree(pid)

    def blast_radius(self, pid: int) -> dict:
        return self.graph.blast_radius(pid)

    # ── sources ──────────────────────────────────────────────────────────────
    def _rebuild_from_db(self) -> int:
        if self._db_path is None or not self._db_path.exists():
            return 0
        try:
            db = sqlite3.connect(str(self._db_path))
            rows = db.execute(
                "SELECT ts, module, message, details FROM events ORDER BY id ASC"
            ).fetchall()
            db.close()
        except Exception as exc:
            self.last_error = str(exc)
            return 0
        for ts, module, message, details in rows:
            try:
                d = json.loads(details) if details else {}
            except Exception:
                d = {}
            self.graph.ingest(module, message, d, ts or time.time())
        return len(rows)

    def _on_event(self, event) -> None:
        try:
            self.graph.ingest(event.module, event.message, event.details or {}, event.ts)
        except Exception:
            pass

    def run(self) -> None:
        from angerona.core.config import Config
        self._db_path = Config().db_path
        if self._bus is not None:
            try:
                self._bus.subscribe(self._on_event)      # live edges
            except Exception:
                pass
        self.emit("PROV online — mapping process/file/network provenance DAG.", Severity.INFO)
        while not self.stopping:
            n = self._rebuild_from_db()
            self.set_health(100, f"{len(self.graph.nodes)} nodes / {n} events")
            self.sleep(self._REBUILD_INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Build a synthetic PROC→PROC→FIM chain and verify ancestry/subtree."""
        g = ProvenanceGraph()
        g.ingest("t", "spawn", {"pid": 100, "ppid": 4}, time.time())
        g.ingest("t", "spawn", {"pid": 200, "ppid": 100}, time.time())
        g.ingest("t", "file", {"pid": 200, "path": "C:/temp/evil.exe"}, time.time())
        g.ingest("t", "net", {"pid": 200, "raddr": "10.0.0.5:443"}, time.time())
        anc = {n["id"] for n in g.ancestry(200)}
        sub = {n["id"] for n in g.subtree(100)}
        ok = "PROC:100" in anc and "PROC:4" in anc and "FIM:C:/temp/evil.exe" in sub \
            and "NET:10.0.0.5:443" in sub
        return (ok, "ancestry/subtree verified on synthetic DAG" if ok
                else f"graph walk failed (anc={anc}, sub={sub})")


def register() -> ProvenanceGraphModule:
    return ProvenanceGraphModule()