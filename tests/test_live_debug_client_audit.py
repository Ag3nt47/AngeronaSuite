"""PW25 advisory client attribution; fake pipes only, no native handles/queries."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from angerona.core import live_debug as debug


class Bus:
    integrity_enabled = False

    def __init__(self):
        self.events, self.owner = [], None
        self.fail = False

    def publish(self, event):
        if self.fail:
            raise OSError("inert audit sink unavailable")
        self.events.append(event)
        if self.owner is not None:
            self.owner.submit(event)


@pytest.fixture
def audit(monkeypatch, tmp_path):
    clock, queries, disconnects = [100.0], [], []
    result = [731]

    def client_pid(handle):
        queries.append(handle)
        value = result[0]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setitem(sys.modules, "win32pipe", SimpleNamespace(
        GetNamedPipeClientProcessId=client_pid, DisconnectNamedPipe=lambda handle: disconnects.append(handle)))
    monkeypatch.setattr(debug, "_birth", lambda _pid: 123.0)
    monkeypatch.setattr(debug, "time", SimpleNamespace(monotonic=lambda: clock[0], time=lambda: 1000.0))
    bus = Bus()
    service = debug.LiveDebugService(bus, tmp_path, enabled=True, export_logs=False)
    return SimpleNamespace(service=service, bus=bus, clock=clock, queries=queries,
                           result=result, disconnects=disconnects)


@pytest.mark.parametrize("pid", [1, 731, 0xFFFFFFFF])
def test_pid_observation_passes_original_pointer_sized_handle_without_process_claim(audit, pid):
    audit.result[0] = pid
    handle = 0x10000000123
    token = audit.service._client_connected(handle)
    assert audit.queries == [handle]
    view = audit.service.client_audit_snapshot()
    assert len(view["active"]) == 1 and view["active"][0]["pid"] == pid
    assert view["active"][0]["pid_status"] == "observed"
    assert view["active"][0]["identity_complete"] is False
    assert view["response_authorized"] is False
    assert "birth/image/trust not verified" in view["identity_scope"]
    assert audit.service._client_disconnected(token)
    assert audit.service.client_audit_snapshot()["active"] == []


@pytest.mark.parametrize("value", [None, True, 0, -1, 1 << 32, "731", PermissionError("inert unavailable")])
def test_invalid_or_unavailable_client_pid_remains_explicit_unknown_without_admission_gate(audit, value):
    audit.result[0] = value
    token = audit.service._client_connected(object())
    view = audit.service.client_audit_snapshot()
    assert view["active"][0]["pid"] is None
    assert view["active"][0]["pid_status"] == "unavailable"
    assert view["attribution_unavailable"] == 1 and view["response_authorized"] is False
    assert view["active"][0]["error_type"]
    assert audit.service._client_disconnected(token)


def test_missing_pid_api_is_a_visible_unavailable_observation(audit, monkeypatch):
    monkeypatch.setitem(sys.modules, "win32pipe", SimpleNamespace())
    token = audit.service._client_connected(object())
    row = audit.service.client_audit_snapshot()["active"][0]
    assert row["pid"] is None and row["pid_status"] == "unavailable"
    assert row["error_type"] == "AttributeError"
    assert audit.service._client_disconnected(token)


def test_stale_disconnect_cannot_clear_replacement_slot_or_mutate_original(audit):
    first = audit.service._client_connected(object())
    original = audit.service.client_audit_snapshot()["recent"][0]
    assert audit.service._client_disconnected(first)
    second = audit.service._client_connected(object())
    assert audit.service._client_disconnected(first) is False
    current = audit.service.client_audit_snapshot()
    assert len(current["active"]) == 1 and current["active"][0]["connection_number"] == 2
    assert current["recent"][0] == original and original["phase"] == "connected"
    current["active"][0]["pid"] = 999  # Caller cannot mutate retained attribution.
    assert audit.service.client_audit_snapshot()["active"][0]["pid"] == 731
    assert audit.service._client_disconnected(second)


def test_active_and_recent_tables_are_bounded_with_explicit_capacity_and_eviction_counts(audit):
    tokens = [audit.service._client_connected(object()) for _index in range(100)]
    view = audit.service.client_audit_snapshot(limit=10_000)
    assert len(view["active"]) == debug.MAX_CLIENTS == 4
    assert len(view["recent"]) == debug.CLIENT_AUDIT_HISTORY == 64
    assert view["active_capacity_gaps"] == 96 and view["recent_records_evicted"] == 36
    assert view["connections_observed"] == 100
    assert len(audit.bus.events) == 1 and view["audit_publications_suppressed"] == 99
    assert all(audit.service._client_disconnected(token) for token in tokens[:4])
    assert audit.service.client_audit_snapshot()["active"] == []
    # Wire status intentionally exports only4 recent rows, remaining bounded
    # within the existing frame and decoder-node budgets even after churn.
    hello = audit.service._hello()
    assert len(hello["status"]["client_audit"]["recent"]) == 4
    assert debug._decode(debug._encode(hello)) == hello


def test_audit_publication_is_rate_bounded_nonrecursive_and_response_neutral(audit):
    audit.service._running = True
    audit.bus.owner = audit.service
    for _index in range(12):
        token = audit.service._client_connected(object())
        audit.service._client_disconnected(token)
    assert len(audit.bus.events) == 1 and audit.service._queue.qsize() == 1
    kind, event = audit.service._queue.get_nowait()
    assert kind == "event"
    audit.service._append(audit.service._event_view(event))
    assert len(audit.bus.events) == 1  # An exporter copy never republishes audit.
    assert audit.service._queue.empty()
    audit.clock[0] += debug.CLIENT_AUDIT_INTERVAL_SECONDS
    audit.service._client_connected(object())
    assert len(audit.bus.events) == 2
    details = audit.bus.events[-1].details
    assert details["suppressed_connections"] == 11 and details["count_unit"] == "accepted connections"
    assert details["client_identity_complete"] is False
    assert details["response_authorized"] is False and details["active_attack"] is False
    assert details["disposition"] == "observation"


def test_publication_failure_is_explicit_and_counters_saturate(audit):
    maximum = debug.CLIENT_AUDIT_COUNT_MAX
    audit.bus.fail = True
    audit.service._client_audit_connections = maximum - 1
    audit.service._client_audit_unavailable = maximum - 1
    audit.result[0] = None
    for _index in range(3):
        audit.service._client_connected(object())
    view = audit.service.client_audit_snapshot()
    assert view["connections_observed"] == view["attribution_unavailable"] == maximum
    assert view["count_capped"] is True and view["audit_publication_failures"] == 1
    assert len(view["active"]) == 3 and view["response_authorized"] is False


@pytest.mark.parametrize("attribution", [731, PermissionError("inert denied attribution")])
def test_connect_audits_before_export_and_existing_heartbeat_timeout_reuses_slot(audit, attribution):
    audit.result[0] = attribution
    server = debug._NamedPipeServer(audit.service)
    order, writes = [], []

    class Stop:
        stopped = False

        def is_set(self):
            return self.stopped

        def set(self):
            self.stopped = True

        def wait(self, timeout):
            assert timeout == 0.05
            audit.clock[0] += 2.0

    server.stop_event = Stop()
    observe = audit.service._client_connected

    def connected(handle):
        order.append("audit")
        return observe(handle)

    audit.service._client_connected = connected

    class Pipe:
        handle = object()
        connections = 0

        def connect_server(self, timeout):
            assert timeout == 1.0
            self.connections += 1
            if self.connections == 2:
                assert audit.service.client_audit_snapshot()["active"] == []
                assert audit.service.status()["client_count"] == 0
                server.stop_event.set()
                raise TimeoutError("end inert listener after proving slot reuse")

        def write(self, raw, timeout=3.0):
            assert timeout == 3.0
            order.append("write")
            if len(writes) == 3:
                raise TimeoutError("inert nonreading client filled fake output buffer")
            writes.extend(debug._decode(line) for line in raw.splitlines())

    pipe = Pipe()
    server._serve_client_loop(pipe)
    assert order[0:2] == ["audit", "write"]
    assert [record["kind"] for record in writes] == ["hello", "heartbeat", "heartbeat"]
    assert pipe.connections == 2 and audit.disconnects == [pipe.handle]
    view = audit.service.client_audit_snapshot()
    assert view["active"] == [] and [row["phase"] for row in view["recent"]] == ["connected", "disconnected"]
    assert view["connections_observed"] == 1
    assert view["attribution_unavailable"] == int(isinstance(attribution, Exception))
    assert writes[0]["status"]["client_audit"]["active"][0]["identity_complete"] is False
