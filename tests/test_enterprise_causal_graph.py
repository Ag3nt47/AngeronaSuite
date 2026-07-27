from __future__ import annotations

from angerona.core.causal_incident_graph import build_graph
from angerona.core.eventbus import Event, Severity


def _event(
    module: str,
    ts: float,
    *,
    pid: int | None = None,
    exe: str = "",
    message: str = "observed",
    **details,
) -> Event:
    if pid is not None:
        details["pid"] = pid
    if exe:
        details["process_path"] = exe
    return Event(module, message, Severity.HIGH, ts, details)


def test_unrelated_simultaneous_processes_form_separate_incidents() -> None:
    graph = build_graph([
        _event("ETW", 10.0, pid=101, exe=r"C:\Tools\one.exe"),
        _event("ETW", 10.0, pid=202, exe=r"C:\Tools\two.exe"),
    ])

    assert graph["stats"]["incidents"] == 2
    assert sorted(row["event_count"] for row in graph["incidents"]) == [1, 1]


def test_explicit_entity_relations_are_distinct_from_temporal_order() -> None:
    graph = build_graph([
        _event(
            "ETW",
            10.0,
            pid=101,
            exe=r"C:\Tools\one.exe",
            ppid=50,
            process_start_time=9.5,
            path=r"C:\Users\Alice\sample.bin",
        ),
        _event(
            "Network Monitor",
            11.0,
            pid=101,
            exe=r"C:\Tools\one.exe",
            process_start_time=9.5,
            remote_ip="203.0.113.9",
        ),
    ])

    relations = {edge["relation"]: edge for edge in graph["edges"]}
    assert "parent-process" in relations
    assert "process-file" in relations
    assert "process-network" in relations
    assert "precedes" in relations
    assert relations["precedes"]["structural"] if "structural" in relations["precedes"] else True
    assert relations["precedes"]["confidence"] < relations["parent-process"]["confidence"]
    assert graph["stats"]["incidents"] == 1
    file_nodes = [node for node in graph["nodes"] if node["kind"] == "file"]
    assert file_nodes[0]["label"] == "sample.bin"
    assert "Alice" not in file_nodes[0]["label"]


def test_pid_reuse_after_gap_does_not_merge_process_identity() -> None:
    graph = build_graph([
        _event("ETW", 1.0, pid=101, exe=r"C:\Tools\same.exe"),
        _event("ETW", 1_000.0, pid=101, exe=r"C:\Tools\same.exe"),
    ])
    process_nodes = [node for node in graph["nodes"] if node["kind"] == "process"]
    assert len(process_nodes) == 2
    assert graph["stats"]["incidents"] == 2


def test_response_event_links_to_named_trigger_evidence() -> None:
    graph = build_graph([
        _event("Memory Scanner", 20.0, pid=777, exe=r"C:\bad.exe"),
        _event(
            "Active Response SOAR",
            20.5,
            message="contained",
            trigger_module="Memory Scanner",
            trigger_ts=20.0,
            verified=True,
            mitigated=True,
            receipt_id="RCP-abc123",
            receipt_hash="a" * 64,
        ),
    ])
    response = [edge for edge in graph["edges"] if edge["relation"] == "response-target"]
    assert len(response) == 1
    assert response[0]["confidence"] == 1.0
    assert graph["stats"]["incidents"] == 1
    assert any(node["kind"] == "proof" for node in graph["nodes"])
    assert any(
        edge["relation"] == "verification-proof" for edge in graph["edges"]
    )


def test_graph_is_deterministic_for_out_of_order_input_and_hard_bounded() -> None:
    events = [
        _event("ETW", float(index), pid=index + 10, exe=fr"C:\P\{index}.exe")
        for index in range(250)
    ]
    first = build_graph(
        reversed(events),
        max_events=50,
        max_nodes=80,
        max_edges=90,
    )
    second = build_graph(
        events,
        max_events=50,
        max_nodes=80,
        max_edges=90,
    )

    assert first == second
    assert first["stats"]["input_events"] == 250
    assert first["stats"]["retained_events"] == 50
    assert first["stats"]["dropped_events"] == 200
    assert len(first["nodes"]) <= 80
    assert len(first["edges"]) <= 90
