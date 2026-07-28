from __future__ import annotations

import json
import queue
import sqlite3
from types import SimpleNamespace


def test_provenance_duplicate_edge_skips_ancestry_walk() -> None:
    from angerona.modules.provenance_graph import ProvenanceGraph

    graph = ProvenanceGraph()
    graph.add_node("PROC:1", "PROC", "one", 1.0)
    graph.add_node("PROC:2", "PROC", "two", 2.0)
    graph.add_edge("PROC:1", "PROC:2")

    def unexpected_walk(_node_id):
        raise AssertionError("duplicate edge performed an ancestry walk")

    graph._ancestor_ids = unexpected_walk
    graph.add_edge("PROC:1", "PROC:2")
    assert graph.edges == {"PROC:1": {"PROC:2"}}


def test_provenance_state_caps_leave_no_dangling_edges() -> None:
    from angerona.modules.provenance_graph import ProvenanceGraph

    graph = ProvenanceGraph(max_nodes=12, max_edges=8)
    for pid in range(2, 80):
        graph.ingest(
            "ETW",
            "spawn",
            {"pid": pid, "ppid": pid - 1, "path": f"C:/tmp/{pid}.bin"},
            float(pid),
        )

    assert len(graph.nodes) <= 12
    assert len(graph._edge_order) <= 8
    assert all(parent in graph.nodes for parent in graph.edges)
    assert all(child in graph.nodes for children in graph.edges.values() for child in children)
    assert all(child in graph.nodes for child in graph.parents)
    assert all(parent in graph.nodes for parents in graph.parents.values() for parent in parents)


def test_provenance_db_catchup_is_incremental(tmp_path) -> None:
    from angerona.modules.provenance_graph import ProvenanceGraphModule

    path = tmp_path / "events.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE events ("
        "id INTEGER PRIMARY KEY, ts REAL, module TEXT, message TEXT, details TEXT)"
    )
    for record_id in range(1, 4):
        db.execute(
            "INSERT INTO events VALUES (?,?,?,?,?)",
            (
                record_id,
                float(record_id),
                "ETW",
                "spawn",
                json.dumps({"pid": record_id + 10, "ppid": record_id + 9}),
            ),
        )
    db.commit()

    module = ProvenanceGraphModule()
    module._db_path = path
    assert module._rebuild_from_db() == 3
    assert module._rebuild_from_db() == 0

    db.execute(
        "INSERT INTO events VALUES (?,?,?,?,?)",
        (4, 4.0, "ETW", "file", json.dumps({"pid": 14, "path": "C:/new.bin"})),
    )
    db.commit()
    db.close()
    assert module._rebuild_from_db() == 1
    assert module._last_db_id == 4
    assert "FIM:C:/new.bin" in module.graph.nodes


def test_reverse_feed_reader_preserves_newest_match_across_small_blocks(tmp_path) -> None:
    from angerona.modules.evolution_engine import EvolutionEngine, _reverse_lines

    feed = tmp_path / "attack_feed.log"
    records = [
        {"technique": "T1234", "seq": 1, "text": "old-\N{SNOWMAN}"},
        {"technique": "T9999", "seq": 2, "text": "noise"},
        {"technique": "T1234", "seq": 3, "text": "new-\N{SNOWMAN}"},
    ]
    feed.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )

    reversed_records = [
        json.loads(line) for line in _reverse_lines(feed, block_size=7) if line
    ]
    assert [record["seq"] for record in reversed_records] == [3, 2, 1]

    module = object.__new__(EvolutionEngine)
    module.attack_feed = feed
    assert module._latest_footprint("T1234")["seq"] == 3


def test_network_detectors_use_shared_connection_snapshot(monkeypatch) -> None:
    from angerona.modules import beacon_detector, counter_agentic

    rows = [
        {
            "pid": 42,
            "status": "ESTABLISHED",
            "laddr": "127.0.0.1:11434",
            "raddr": "8.8.8.8:443",
        }
    ]
    calls = {"beacon": 0, "counter": 0}

    def beacon_snapshot():
        calls["beacon"] += 1
        return rows

    def counter_snapshot():
        calls["counter"] += 1
        return rows

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def name():
            return "unexpected.exe"

    monkeypatch.setattr(beacon_detector, "list_connections", beacon_snapshot)
    monkeypatch.setattr(counter_agentic, "list_connections", counter_snapshot)
    monkeypatch.setattr(beacon_detector.psutil, "Process", Process)
    monkeypatch.setattr(counter_agentic.psutil, "Process", Process)

    beacon = beacon_detector.BeaconDetectorModule()
    beacon._poll_once()
    assert beacon._seen_last == {(42, "8.8.8.8")}

    findings = []
    counter = counter_agentic.CounterAgenticModule()
    counter.emit = lambda *args, **kwargs: findings.append((args, kwargs))
    counter._watch_ollama_port()
    assert findings and findings[0][1]["pid"] == 42
    assert calls == {"beacon": 1, "counter": 1}


def test_mobile_digest_keeps_only_rendered_samples_and_exact_total(monkeypatch) -> None:
    from angerona.core.eventbus import Severity
    from angerona.modules import mobile_bridge

    now = 1_000.0
    monkeypatch.setattr(mobile_bridge.time, "time", lambda: now)
    module = mobile_bridge.MobileResponseBridge()
    module._alert_times = [now] * (mobile_bridge._FLOOD_MAX + 1)
    sent = []
    module._send = sent.append
    event = SimpleNamespace(
        details={"pid": None},
        module="TEST",
        message="bounded flood sample",
        severity=Severity.HIGH,
    )

    for _ in range(1_000):
        module._gate_alert(event)

    assert len(module._digest) == 15
    assert module._digest_count == 1_000
    module._flush_digest()
    assert "1000 alert(s)" in sent[-1]
    assert module._digest == []
    assert module._digest_count == 0


def test_flight_cache_batches_commits_without_delaying_reads() -> None:
    from angerona.modules.flight_cache import FlightCache

    cache = FlightCache(cap=64)
    commits = []
    cache._db.set_trace_callback(
        lambda sql: commits.append(sql)
        if sql.strip().upper().startswith("COMMIT")
        else None
    )
    try:
        for index in range(cache._COMMIT_EVERY + 5):
            cache.put(float(index), "TEST", 1, f"event-{index}", {"index": index})

        assert len(commits) == 1
        assert cache.count() == 64
        assert cache.recent(1)[0]["message"] == f"event-{cache._COMMIT_EVERY + 4}"
        assert cache.query("SELECT COUNT(*) AS n FROM events")[0]["n"] == 64
    finally:
        cache.close()

    assert len(commits) == 2


def test_mcp_stop_closes_even_a_full_session_queue() -> None:
    from angerona.engines.mcp_server import AngeronaMCPServer

    server = AngeronaMCPServer(None, None, None, SimpleNamespace(mcp_port=0))
    responses = queue.Queue(maxsize=2)
    responses.put_nowait({"id": 1})
    responses.put_nowait({"id": 2})
    server._sessions["session"] = responses

    server.stop()

    assert server._sessions == {}
    assert responses.get_nowait() is None


def test_mcp_start_is_idempotent_and_thread_stops() -> None:
    from angerona.engines.mcp_server import AngeronaMCPServer

    config = SimpleNamespace(mcp_port=0, mcp_token=None)
    server = AngeronaMCPServer(None, None, None, config)
    try:
        first_port = server.start()
        thread = server._thread
        assert first_port > 0
        assert server.start() == first_port
        assert server._thread is thread
    finally:
        server.stop()
    assert not server.is_running
    assert thread is not None and not thread.is_alive()
