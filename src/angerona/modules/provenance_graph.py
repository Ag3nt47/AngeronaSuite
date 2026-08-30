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

import hashlib
import json
import re
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
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
    """Bounded in-memory typed DAG.

    The graph is fed for the lifetime of the process, so its node and edge
    stores must not grow with host uptime.  Ordered dictionaries give us O(1)
    recency refresh and eviction while preserving normal ``dict`` behavior for
    existing callers.
    """

    def __init__(self, max_nodes: int = 20_000, max_edges: int = 40_000) -> None:
        self.state_lock = threading.Lock()
        self.max_nodes = max(1, int(max_nodes))
        self.max_edges = max(1, int(max_edges))
        self.nodes: OrderedDict[str, dict] = OrderedDict()
        self.edges: dict[str, set[str]] = {}      # parent id -> {child ids}
        self.parents: dict[str, set[str]] = {}    # child id -> {parent ids}
        self._edge_order: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._latest_pid_node: dict[int, str] = {}

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
        # Total by construction: callers (GUI blast-radius, forensics) may pass a
        # pid that is None or dirty string data like 'unknown'. Returning a
        # sentinel that matches no real PROC node yields empty ancestry/subtree
        # instead of crashing the whole module into quarantine.
        try:
            return f"PROC:{int(pid)}"
        except (ValueError, TypeError):
            return "PROC:?"

    def add_node(self, node_id: str, kind: str, label: str, ts: float, **meta) -> None:
        source_event = str(meta.pop("source_event", "") or "")[:128]
        n = self.nodes.get(node_id)
        if n is None:
            if source_event:
                meta["source_events"] = [source_event]
            self.nodes[node_id] = {"id": node_id, "kind": kind, "label": label,
                                   "ts": ts, "meta": meta}
        else:
            n["ts"] = max(n["ts"], ts)
            if label and str(label) != f"pid {meta.get('pid', '')}":
                n["label"] = label
            n["meta"].update({key: value for key, value in meta.items() if value})
            if source_event:
                sources = n["meta"].setdefault("source_events", [])
                if source_event not in sources:
                    sources.append(source_event)
                    del sources[:-16]
            self.nodes.move_to_end(node_id)
        while len(self.nodes) > self.max_nodes:
            retired, _ = self.nodes.popitem(last=False)
            self._drop_node_links(retired)

    def add_edge(self, parent: str, child: str) -> None:
        if parent == child or parent not in self.nodes or child not in self.nodes:
            return
        edge = (parent, child)
        children = self.edges.get(parent)
        if children is not None and child in children:
            # Ledger catch-up can replay an edge already received live. Avoid
            # the ancestry walk: on a long process chain it made every periodic
            # rebuild superlinear even though no graph state changed.
            if edge in self._edge_order:
                self._edge_order.move_to_end(edge)
            else:
                self._edge_order[edge] = None
            return
        # keep it acyclic: skip an edge that would close a cycle (child already
        # an ancestor of parent).
        if parent in self._ancestor_ids(child):
            return
        self.edges.setdefault(parent, set()).add(child)
        self.parents.setdefault(child, set()).add(parent)
        self._edge_order[edge] = None
        while len(self._edge_order) > self.max_edges:
            (old_parent, old_child), _ = self._edge_order.popitem(last=False)
            self._discard_edge(old_parent, old_child, remove_order=False)

    def _discard_edge(self, parent: str, child: str, *, remove_order: bool = True) -> None:
        children = self.edges.get(parent)
        if children is not None:
            children.discard(child)
            if not children:
                self.edges.pop(parent, None)
        ancestors = self.parents.get(child)
        if ancestors is not None:
            ancestors.discard(parent)
            if not ancestors:
                self.parents.pop(child, None)
        if remove_order:
            self._edge_order.pop((parent, child), None)

    def _drop_node_links(self, node_id: str) -> None:
        for child in tuple(self.edges.get(node_id, ())):
            self._discard_edge(node_id, child)
        for parent in tuple(self.parents.get(node_id, ())):
            self._discard_edge(parent, node_id)
        for pid, current in tuple(self._latest_pid_node.items()):
            if current != node_id:
                continue
            candidates = [
                (float(node.get("ts", 0.0)), candidate)
                for candidate, node in self.nodes.items()
                if node.get("kind") == "PROC"
                and (node.get("meta") or {}).get("pid") == pid
            ]
            if candidates:
                self._latest_pid_node[pid] = max(candidates)[1]
            else:
                self._latest_pid_node.pop(pid, None)

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
    def _process_node_id(
        self,
        pid: int,
        details: dict,
        ts: float,
        *,
        parent: bool = False,
    ) -> tuple[str, str]:
        prefix = "parent_" if parent else ""
        raw_identity = self._first(
            details,
            (
                f"{prefix}process_guid",
                f"{prefix}process_create_time",
                f"{prefix}create_time",
                f"{prefix}birth_time",
            ),
        )
        if raw_identity is None and not parent:
            event_type = str(details.get("event_type") or details.get("kind") or "")
            if event_type in {"process_creation", "process_created"} or details.get("eid") == 4688:
                raw_identity = f"event:{float(ts):.6f}"
        if raw_identity is None:
            current = self._latest_pid_node.get(pid)
            return (current or self._pid_id(pid), "unknown")
        rendered = str(raw_identity).strip()[:512]
        token = hashlib.sha256(rendered.encode("utf-8", "replace")).hexdigest()[:20]
        node_id = f"PROC:{pid}@{token}"
        self._latest_pid_node[pid] = node_id
        return node_id, rendered

    def _resolve_pid_id(self, pid: object) -> str:
        parsed = self._safe_int(pid)
        if parsed is None:
            return "PROC:?"
        return self._latest_pid_node.get(parsed, self._pid_id(parsed))

    def ingest(self, module: str, message: str, details: dict, ts: float) -> None:
        with self.state_lock:
            source_event = hashlib.sha256(
                json.dumps(
                    {
                        "module": module,
                        "message": message,
                        "details": details,
                        "ts": float(ts),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8", "replace")
            ).hexdigest()
            # Parse pid safely in case of dirty string data like 'unknown'
            pid = self._safe_int(self._first(details, _PID_KEYS))
            if pid is None:
                m = _PID_RE.search(message or "")
                pid = int(m.group(1)) if m else None
            
            # Parse ppid safely as well
            ppid = self._safe_int(self._first(details, _PPID_KEYS))
            
            if pid is not None:
                pnode, process_identity = self._process_node_id(pid, details, ts)
                # G2: sysmon EID 1 supplies "image" (full exe path); use basename
                # as label so the graph shows "cmd.exe" not just "pid 4812".
                raw_image = details.get("image", "")
                proc_label = (
                    raw_image.split("\\")[-1] if raw_image
                    else details.get("name", f"pid {pid}")
                )
                self.add_node(
                    pnode,
                    "PROC",
                    proc_label,
                    ts,
                    module=module,
                    pid=pid,
                    process_identity=process_identity,
                    source_event=source_event,
                )
                if ppid is not None:
                    parent, parent_identity = self._process_node_id(
                        ppid, details, ts, parent=True
                    )
                    raw_parent_image = details.get("parent_image", "")
                    parent_label = (
                        raw_parent_image.split("\\")[-1] if raw_parent_image
                        else details.get("parent_name", f"pid {ppid}")
                    )
                    self.add_node(
                        parent,
                        "PROC",
                        parent_label,
                        ts,
                        pid=ppid,
                        process_identity=parent_identity,
                        source_event=source_event,
                    )
                    self.add_edge(parent, pnode)
                # file artifacts
                path = self._first(details, _PATH_KEYS)
                if path:
                    fid = f"FIM:{path}"
                    self.add_node(fid, "FIM", str(path), ts, source_event=source_event)
                    self.add_edge(pnode, fid)
                # network endpoints
                net = self._first(details, _NET_KEYS)
                if net:
                    nid = f"NET:{net}"
                    self.add_node(nid, "NET", str(net), ts, source_event=source_event)
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
            start = self._resolve_pid_id(pid)
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
            start = self._resolve_pid_id(pid)
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
            root = self._resolve_pid_id(pid)
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
    version = "1.12.1"

    _REBUILD_INTERVAL = 20.0
    _DB_PAGE = 1_000

    def __init__(self) -> None:
        super().__init__()
        self.graph = ProvenanceGraph()
        self._db_path: Path | None = None
        self._last_db_id = 0
        self._subscribed = False
        self._db_identity: tuple[int, int] | None = None
        self._last_db_error = ""
        self._db_rejected = 0
        self._db_gaps = 0
        self._db_source_resets = 0
        self._live_rejected = 0
        self._subscription_error = ""

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
            self._last_db_error = "flight-recorder database is unavailable"
            return 0
        db = None
        total = 0
        try:
            before = self._db_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or bool(
                getattr(before, "st_file_attributes", 0) & 0x400
            ):
                raise OSError("flight-recorder database is not an exact regular file")
            identity = (int(before.st_dev), int(before.st_ino))
            if self._db_identity is not None and identity != self._db_identity:
                self._last_db_id = 0
                self._db_source_resets += 1
            self._db_identity = identity
            db = sqlite3.connect(
                f"file:{self._db_path}?mode=ro", uri=True, timeout=0.5,
            )
            db.execute("PRAGMA query_only=ON")
            maximum = int(db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])
            if maximum < self._last_db_id:
                self._last_db_id = 0
                self._db_source_resets += 1
            while True:
                rows = db.execute(
                    "SELECT id, ts, module, message, details FROM events "
                    "WHERE id > ? ORDER BY id ASC LIMIT ?",
                    (self._last_db_id, self._DB_PAGE),
                ).fetchall()
                if not rows:
                    break
                for record_id, ts, module, message, details in rows:
                    # Advance across malformed rows too, otherwise one bad row
                    # would be reparsed on every refresh forever.
                    parsed_id = int(record_id)
                    if parsed_id > self._last_db_id + 1:
                        self._db_gaps += parsed_id - self._last_db_id - 1
                    self._last_db_id = max(self._last_db_id, parsed_id)
                    try:
                        d = json.loads(details) if details else {}
                        if not isinstance(d, dict):
                            raise ValueError("event details are not an object")
                    except Exception:
                        self._db_rejected += 1
                        continue
                    try:
                        self.graph.ingest(module, message, d, ts or time.time())
                    except Exception:
                        self._db_rejected += 1
                        continue
                total += len(rows)
                if len(rows) < self._DB_PAGE:
                    break
            after = self._db_path.stat(follow_symlinks=False)
            after_identity = (
                int(after.st_dev),
                int(after.st_ino),
            )
            if after_identity != identity:
                raise OSError("flight-recorder identity changed during provenance catch-up")
            self._last_db_error = ""
        except Exception as exc:
            self.last_error = str(exc)
            self._last_db_error = str(exc)[:1000]
        finally:
            try:
                if db is not None:
                    db.close()
            except Exception:
                pass
        return total

    def _on_event(self, event) -> None:
        try:
            details = event.details or {}
            if not isinstance(details, dict):
                raise ValueError("live event details are not an object")
            self.graph.ingest(event.module, event.message, details, event.ts)
        except Exception:
            self._live_rejected += 1

    def _update_source_health(self, new_events: int) -> None:
        db_available = bool(self._db_path is not None and self._db_path.exists())
        if self._subscription_error and not db_available:
            self.set_health(
                25,
                f"both provenance sources unavailable: {self._subscription_error}; "
                f"{self._last_db_error}",
            )
        elif self._last_db_error:
            self.set_health(
                55,
                f"persistent provenance source incomplete: {self._last_db_error}; "
                "live events remain active",
            )
        elif self._subscription_error:
            self.set_health(
                70,
                f"live provenance source unavailable: {self._subscription_error}; "
                "ledger catch-up remains active",
            )
        elif self._db_rejected or self._live_rejected or self._db_gaps or self._db_source_resets:
            self.set_health(
                75,
                f"provenance incomplete: {self._db_rejected} ledger reject(s), "
                f"{self._live_rejected} live reject(s), {self._db_gaps} ledger gap(s), "
                f"{self._db_source_resets} source reset(s)",
            )
        else:
            self.set_health(
                100,
                f"{len(self.graph.nodes)}/{self.graph.max_nodes} nodes / "
                f"{len(self.graph._edge_order)}/{self.graph.max_edges} edges / "
                f"{new_events} new ledger events; live + persistent sources complete",
            )

    def run(self) -> None:
        from angerona.core.config import Config
        self._db_path = Config().db_path
        if self._bus is not None and not self._subscribed:
            try:
                self._bus.subscribe(self._on_event)      # live edges
                self._subscribed = True
                self._subscription_error = ""
            except Exception as exc:
                self._subscription_error = str(exc)[:1000]
        self.emit("PROV online — mapping process/file/network provenance DAG.", Severity.INFO)
        while not self.stopping:
            n = self._rebuild_from_db()
            self._update_source_health(n)
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
