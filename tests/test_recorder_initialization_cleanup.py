"""Failed recorder constructors retain or close their actual SQLite owners."""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from angerona.core import headless, storage
from angerona.core.eventbus import BusAuthority


class InitializationFailure(RuntimeError):
    pass


def test_key_admission_failure_closes_native_sqlite_while_traceback_is_retained(tmp_path, monkeypatch):
    connections = []
    connect = sqlite3.connect
    def capture(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection
    def rejected(_cls):
        raise InitializationFailure("fixture rejected key")
    monkeypatch.setattr(storage.sqlite3, "connect", capture)
    monkeypatch.setattr(storage.BusAuthority, "load", classmethod(rejected))
    path = tmp_path / "events.sqlite"
    with pytest.raises(InitializationFailure) as retained_error:
        storage.FlightRecorder(path)
    assert retained_error.value.__traceback__ is not None
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")
    path.rename(tmp_path / "retired.sqlite")


@pytest.mark.parametrize("stage", ["schema", "ui-open", "ui-configure"])
def test_partial_schema_or_ui_failure_closes_every_returned_connection(tmp_path, monkeypatch, stage):
    connections = []
    connect = sqlite3.connect
    class UI(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if stage == "ui-configure" and statement == "PRAGMA query_only=ON":
                raise InitializationFailure("fixture UI setup")
            return super().execute(statement, *args, **kwargs)
    def capture(*args, **kwargs):
        if len(connections) == 1 and stage == "ui-open":
            raise InitializationFailure("fixture second connect")
        if len(connections) == 1:
            kwargs["factory"] = UI
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection
    monkeypatch.setattr(storage.sqlite3, "connect", capture)
    monkeypatch.setattr(storage.BusAuthority, "load", classmethod(lambda _cls: BusAuthority(b"t" * 32)))
    if stage == "schema":
        def failed_schema(_self):
            raise InitializationFailure("fixture schema")
        monkeypatch.setattr(storage.FlightRecorder, "_init_schema", failed_schema)
    with pytest.raises(InitializationFailure) as retained_error:
        storage.FlightRecorder(tmp_path / "events.sqlite")
    assert retained_error.value.__traceback__ is not None
    assert len(connections) == (2 if stage == "ui-configure" else 1)
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_headless_retains_failed_constructor_owner_when_native_close_is_uncertain(tmp_path, monkeypatch):
    connections, close_attempts = [], []
    connect = sqlite3.connect
    class Uncertain(sqlite3.Connection):
        def close(self):
            close_attempts.append(self)
            raise OSError("fixture connection close uncertainty")
    def capture(*args, **kwargs):
        kwargs["factory"] = Uncertain
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection
    def rejected(_cls):
        raise InitializationFailure("fixture rejected key")
    monkeypatch.setattr(storage.sqlite3, "connect", capture)
    monkeypatch.setattr(storage.BusAuthority, "load", classmethod(rejected))
    monkeypatch.setattr(headless, "_HEADLESS_RETIREMENT_HOLD", None)
    def graph(**_kwargs):
        storage.FlightRecorder(tmp_path / "events.sqlite")
    monkeypatch.setattr(headless, "_run_headless_graph", graph)
    control = SimpleNamespace(graph_retirement_pending=False)
    try:
        with pytest.raises(headless.HeadlessRetirementPending):
            headless.run_headless(runtime_control=control)
        resources = headless._HEADLESS_RETIREMENT_HOLD
        assert resources is not None and control.graph_retirement_pending is True
        assert resources.partial_storage._failed_initialization_connections == tuple(connections)
        assert len(close_attempts) == 1
        with pytest.raises(headless.HeadlessRetirementPending):
            resources.close()
        assert len(close_attempts) == 1
        assert connections[0].execute("SELECT 1").fetchone() == (1,)
    finally:
        for connection in connections:
            # Fixture owns this actual SQLite subclass and deliberately bypasses
            # its injected failure for cleanup; production never retries it.
            sqlite3.Connection.close(connection)
