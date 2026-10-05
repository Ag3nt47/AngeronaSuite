"""Inert process identity, graph, and bounded response-delivery regressions."""
from __future__ import annotations

import pytest
import threading
import time

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.modules.provenance_graph import ProvenanceGraph
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.modules.smart_deception import SmartDeception


@pytest.mark.parametrize("previous,current,expected", [
    ("notepad.exe", "winword.exe", True),
    ("winword.exe", "notepad.exe", False),
])
def test_current_parent_snapshot_wins_after_pid_reuse(previous, current, expected):
    module = ProcessMonitorModule()
    module._names = {71: previous}
    events = []
    module.emit = lambda *args, **kwargs: events.append((args, kwargs))
    module._evaluate({
        "pid": 72, "ppid": 71, "name": "powershell.exe",
        "exe": "C:/Windows/System32/powershell.exe", "create_time": 123.0,
    }, {71: current, 72: "powershell.exe"})
    assert bool(events) is expected
    if expected:
        assert events[0][1]["parent"] == current
        assert events[0][0][1] == Severity.CRITICAL


def _graph():
    graph = ProvenanceGraph()
    for node in "ABC":
        graph.add_node(node, "PROC", node, 1.0, pid=ord(node))
    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    return graph


def test_provenance_rejects_cycle_without_losing_existing_links():
    graph = _graph()
    graph.add_edge("C", "A")
    assert graph.edges == {"A": {"B"}, "B": {"C"}}
    assert graph.parents == {"B": {"A"}, "C": {"B"}}
    assert len(graph._edge_order) == 2


def test_provenance_retains_valid_transitive_evidence():
    graph = _graph()
    graph.add_edge("A", "C")
    assert graph.edges == {"A": {"B", "C"}, "B": {"C"}}
    assert graph.parents["C"] == {"A", "B"}
    assert len(graph._edge_order) == 3


def _failing_module(factory, monkeypatch):
    module = factory()
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: None)
    if factory is ActiveResponseSOAR:
        monkeypatch.setattr(module, "_armed", lambda: True)

    def fail(*args):
        raise RuntimeError("inert delivery failure")

    monkeypatch.setattr(module, "_process_one_event", fail)
    bus = EventBus(ring_size=1, priority_ring_size=1)
    bus.arm(BusAuthority(b"c" * 32))
    module.bind(bus)
    return module, bus


@pytest.mark.parametrize("factory", [SOARModule, ActiveResponseSOAR])
def test_delivery_failures_are_bounded_when_evidence_is_evicted(factory, monkeypatch):
    module, bus = _failing_module(factory, monkeypatch)
    for index in range(100):
        bus.publish(Event("fixture", str(index), Severity.HIGH))
        module.process_pending_once()
        assert len(module._delivery_failures) == 1
        assert set(module._delivery_failures.values()) == {1}
    assert module._dead_lettered == 0


@pytest.mark.parametrize("factory", [SOARModule, ActiveResponseSOAR])
def test_retained_failure_keeps_retry_budget_and_commits_on_third_failure(factory, monkeypatch):
    module, bus = _failing_module(factory, monkeypatch)
    bus.publish(Event("fixture", "retained", Severity.HIGH))
    for attempt in (1, 2):
        module.process_pending_once()
        assert list(module._delivery_failures.values()) == [attempt]
    module.process_pending_once()
    assert module._delivery_failures == {}
    assert module._dead_lettered == 1
    assert module._priority_cursor == 1


@pytest.mark.parametrize("factory", [SOARModule, ActiveResponseSOAR])
def test_replacement_bus_does_not_inherit_matching_evidence_retry_debt(factory, monkeypatch):
    module, bus = _failing_module(factory, monkeypatch)
    event = Event("fixture", "same authenticated evidence", Severity.HIGH, ts=1.0)
    bus.publish(event)
    module.process_pending_once()
    original_key = next(iter(module._delivery_failures))
    replacement = EventBus(ring_size=1, priority_ring_size=1)
    replacement.arm(BusAuthority(b"c" * 32))
    replacement.publish(event)
    module.bind(replacement)
    module.process_pending_once()
    assert module._delivery_failures == {original_key: 1}


def _inert_deception(tmp_path, monkeypatch):
    module = SmartDeception()
    module._targets = (tmp_path / "decoys",)
    module._runtime_root = module._targets[0]
    module._manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_refresh_quarantine_limits", lambda: None)
    monkeypatch.setattr(module, "_update_health", lambda: None)
    monkeypatch.setattr(module, "_check_decoy", lambda path: None)
    return module


def test_deception_stop_during_name_generation_never_deploys_and_cleanup_is_worker_owned(
    tmp_path, monkeypatch,
):
    module = _inert_deception(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    cleanup_threads, deployments = [], []

    def generate():
        entered.set()
        assert release.wait(5)
        return ["inert.txt"]

    monkeypatch.setattr(module, "_generate_names", generate)
    monkeypatch.setattr(module, "_deploy", lambda names: deployments.append(names))
    monkeypatch.setattr(module, "_cleanup_deployed_decoys",
                        lambda: cleanup_threads.append(threading.get_ident()))
    module.start()
    worker = module._thread
    try:
        assert entered.wait(2)
        started = time.monotonic()
        module.stop()
        assert time.monotonic() - started < 0.5
        assert module.stopping
        assert cleanup_threads == []
    finally:
        release.set()
        worker.join(3)
        module.stop()
    assert not worker.is_alive()
    assert deployments == []
    assert cleanup_threads == [worker.ident]


def test_deception_stop_during_creation_retires_exact_inflight_artifact(tmp_path, monkeypatch):
    module = _inert_deception(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(module, "_generate_names", lambda: ["one.txt", "two.txt", "three.txt"])
    original_write = module._write_decoy
    written = []

    def create_then_wait(path):
        result = original_write(path)
        written.append((path, result))
        entered.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(module, "_write_decoy", create_then_wait)
    module.start()
    worker = module._thread
    try:
        assert entered.wait(2)
        assert written[0][1] is True
        module.stop()
        assert worker.is_alive()  # in-flight creation remains owned until retirement
    finally:
        release.set()
        worker.join(3)
        module.stop()
    assert not worker.is_alive()
    assert len(written) == 1
    assert module._decoys == []
    assert list(module._targets[0].iterdir()) == []
    assert not module._manifest.exists()


def test_stale_deception_generation_cannot_clean_replacement_artifacts(tmp_path, monkeypatch):
    module = _inert_deception(tmp_path, monkeypatch)
    old_stop = module.generation_stop_event()
    module._run_context.stop_event = old_stop
    old_stop.set()
    module._stop = threading.Event()
    cleanup = []
    monkeypatch.setattr(module, "_cleanup_deployed_decoys", lambda: cleanup.append(True))
    monkeypatch.setattr(module, "_generate_names", lambda: pytest.fail("stale worker generated names"))
    module.run()
    assert cleanup == []
