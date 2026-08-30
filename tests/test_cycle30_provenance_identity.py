from __future__ import annotations

import json
import sqlite3

from angerona.modules.provenance_graph import ProvenanceGraph, ProvenanceGraphModule


def test_pid_reuse_creates_distinct_process_lifetimes() -> None:
    graph = ProvenanceGraph()
    graph.ingest(
        "Process Monitor",
        "first process",
        {
            "event_type": "process_creation",
            "pid": 123,
            "process_create_time": 10.0,
            "name": "first.exe",
            "path": "C:/first.bin",
        },
        10.0,
    )
    first_node = graph._latest_pid_node[123]
    graph.ingest(
        "Process Monitor",
        "reused pid",
        {
            "event_type": "process_creation",
            "pid": 123,
            "process_create_time": 20.0,
            "name": "second.exe",
            "path": "C:/second.bin",
        },
        20.0,
    )
    second_node = graph._latest_pid_node[123]
    graph.ingest(
        "Network Monitor",
        "later connection",
        {"pid": 123, "raddr": "8.8.8.8:443"},
        21.0,
    )

    assert first_node != second_node
    assert graph.nodes[first_node]["label"] == "first.exe"
    assert graph.nodes[second_node]["label"] == "second.exe"
    latest = {node["id"] for node in graph.subtree(123)}
    assert "FIM:C:/second.bin" in latest
    assert "NET:8.8.8.8:443" in latest
    assert "FIM:C:/first.bin" not in latest


def test_process_node_retains_bounded_source_event_links() -> None:
    graph = ProvenanceGraph()
    for index in range(30):
        graph.ingest(
            "sensor",
            f"event-{index}",
            {"pid": 99, "process_create_time": 1.0},
            float(index),
        )
    node = graph.nodes[graph._latest_pid_node[99]]

    assert len(node["meta"]["source_events"]) == 16
    assert len(set(node["meta"]["source_events"])) == 16


def test_ledger_gap_and_malformed_row_degrade_health(tmp_path) -> None:
    path = tmp_path / "events.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE events ("
        "id INTEGER PRIMARY KEY, ts REAL, module TEXT, message TEXT, details TEXT)"
    )
    connection.execute(
        "INSERT INTO events VALUES (?,?,?,?,?)",
        (2, 2.0, "sensor", "valid", json.dumps({"pid": 2})),
    )
    connection.execute(
        "INSERT INTO events VALUES (?,?,?,?,?)",
        (3, 3.0, "sensor", "malformed", "not-json"),
    )
    connection.commit()
    connection.close()
    module = ProvenanceGraphModule()
    module._db_path = path
    module._subscribed = True

    assert module._rebuild_from_db() == 2
    module._update_source_health(2)

    assert module._db_gaps == 1
    assert module._db_rejected == 1
    assert module.health == 75
    assert "1 ledger reject" in module.health_note
    assert "1 ledger gap" in module.health_note


def test_missing_persistent_source_cannot_report_green(tmp_path) -> None:
    module = ProvenanceGraphModule()
    module._db_path = tmp_path / "missing.db"
    module._subscribed = True

    assert module._rebuild_from_db() == 0
    module._update_source_health(0)

    assert module.health == 55
    assert "persistent provenance source incomplete" in module.health_note
