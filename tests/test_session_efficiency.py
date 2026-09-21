"""Long-session growth and retry behavior using inert local fixtures."""
from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import flow_metrics
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import network_protocol_decoder as dns


def test_dns_cooldown_is_bounded_and_does_not_rescan_live_names(monkeypatch):
    class NoScan(OrderedDict):
        def items(self):
            raise AssertionError("a new name must not scan existing cooldowns")

    monkeypatch.setattr(dns.time, "monotonic", lambda: 1000.0)
    module = dns.NetworkProtocolDecoderModule()
    module._last_emit = NoScan()
    for index in range(50_000):
        assert module._should_emit(f"{index}.example.com")
        assert len(module._last_emit) <= dns._MAX_EMIT_COOLDOWNS
    assert not module._should_emit("49999.example.com")
    # Capacity retires suppression only: it must not suppress new observations.
    assert module._should_emit("0.example.com")
    assert len(module._last_emit) == dns._MAX_EMIT_COOLDOWNS


def test_dns_first_minute_and_exact_expiry_keep_cooldown_order(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(dns.time, "monotonic", lambda: now[0])
    module = dns.NetworkProtocolDecoderModule()
    assert module._should_emit("a.example")
    assert not module._should_emit("a.example")
    now[0] = 10.0
    assert module._should_emit("b.example")
    now[0] = 59.99
    assert not module._should_emit("a.example")
    now[0] = 60.0
    assert module._should_emit("a.example")
    assert list(module._last_emit) == ["b.example", "a.example"]
    now[0] = 70.0
    assert not module._should_emit("a.example")
    assert module._should_emit("c.example")
    assert list(module._last_emit) == ["a.example", "c.example"]


def test_dns_concurrent_duplicate_has_one_observation(monkeypatch):
    monkeypatch.setattr(dns.time, "monotonic", lambda: 1000.0)
    module = dns.NetworkProtocolDecoderModule()
    with ThreadPoolExecutor(max_workers=8) as workers:
        emitted = list(workers.map(module._should_emit, ["same.example"] * 1000))
    assert sum(emitted) == 1


def test_dns_capacity_keeps_analysis_and_observation_semantics(monkeypatch):
    monkeypatch.setattr(dns, "_MAX_EMIT_COOLDOWNS", 4)
    monkeypatch.setattr(dns.time, "monotonic", lambda: 1000.0)
    monkeypatch.setattr(dns.self_ioc, "is_self_ioc", lambda _: False)
    module, bus = dns.NetworkProtocolDecoderModule(), EventBus()
    module.bind(bus)
    for index in range(30):
        module._on_event(Event("fixture", "DNS", details={
            "protocol": "dns", "qname": f"xkvhbrtplmqnzwcf{index}.example.net",
        }))
    assert module.stats()["dns_seen"] == 30
    assert len(bus.recent(100)) == 30
    assert len(module._last_emit) == 4
    for event in bus.recent(100):
        assert event.severity == Severity.MEDIUM
        assert event.details["active_attack"] is False
        assert event.details["disposition"] == "observation"
        assert "response_contract" not in event.details


@pytest.mark.parametrize("initial,appends", [
    (b"", [b"a", b"b", b"\n", b"\n", b"c\nd"]),
    (b"a\r\n", [b"b\r", b"\n", b"c\r\n"]),
    (b"a" * 131_073, [b"\n", b"\nlast", b"\n"]),
], ids=["partial-lines", "crlf", "multi-chunk-line"])
def test_audit_incremental_count_matches_binary_lines(tmp_path, monkeypatch, initial, appends):
    monkeypatch.setattr(flow_metrics, "_audit_cache", None)
    path = tmp_path / "audit.log"
    path.write_bytes(initial)
    for addition in [b"", *appends]:
        with path.open("ab") as stream:
            stream.write(addition)
        with path.open("rb") as stream:
            expected = sum(1 for _ in stream)
        assert flow_metrics._audit_line_count(path) == expected


def test_audit_append_reads_only_delta_and_small_guards(tmp_path, monkeypatch):
    monkeypatch.setattr(flow_metrics, "_audit_cache", None)
    path = tmp_path / "audit.log"
    path.write_bytes(b"x\n" * 524_288)
    assert flow_metrics._audit_line_count(path) == 524_288
    with path.open("ab") as stream:
        stream.write(b"new\n")
    original = Path.open
    reads = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.stream.close()

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def read(self, size=-1):
            assert 0 <= size <= flow_metrics._AUDIT_READ_CHUNK
            data = self.stream.read(size)
            reads.append(len(data))
            return data

    monkeypatch.setattr(Path, "open", lambda self, *a, **kw: Reader(original(self, *a, **kw)))
    assert flow_metrics._audit_line_count(path) == 524_289
    assert sum(reads) <= 4 + 4 * flow_metrics._AUDIT_GUARD_BYTES
    reads.clear()
    assert flow_metrics._audit_line_count(path) == 524_289
    assert reads == []


def test_audit_rotation_rewrites_truncation_and_path_switch(tmp_path, monkeypatch):
    monkeypatch.setattr(flow_metrics, "_audit_cache", None)
    path = tmp_path / "audit.log"
    path.write_bytes(b"a\nb\n")
    assert flow_metrics._audit_line_count(path) == 2
    stamp = path.stat().st_mtime_ns
    replacement = tmp_path / "replacement.log"
    replacement.write_bytes(b"abcd")
    os.utime(replacement, ns=(stamp, stamp))
    replacement.replace(path)
    assert flow_metrics._audit_line_count(path) == 1
    path.write_bytes(b"\n\n\n\n")
    os.utime(path, ns=(stamp + 1_000_000_000, stamp + 1_000_000_000))
    assert flow_metrics._audit_line_count(path) == 4
    path.write_bytes(b"one longer rewritten line\n")
    assert flow_metrics._audit_line_count(path) == 1
    path.write_bytes(b"a")
    assert flow_metrics._audit_line_count(path) == 1
    other = tmp_path / "other.log"
    other.write_bytes(b"\n\n")
    assert flow_metrics._audit_line_count(other) == 2
    assert flow_metrics._audit_line_count(path) == 1
    path.unlink()
    assert flow_metrics._audit_line_count(path) == 0


def test_audit_read_failure_retries_unchanged_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(flow_metrics, "_audit_cache", None)
    path = tmp_path / "audit.log"
    path.write_bytes(b"one\n")
    assert flow_metrics._audit_line_count(path) == 1
    with path.open("ab") as stream:
        stream.write(b"two\n")
    original = Path.open

    def denied(*_, **__):
        raise PermissionError("inert read failure")

    monkeypatch.setattr(Path, "open", denied)
    assert flow_metrics._audit_line_count(path) == 1
    monkeypatch.setattr(Path, "open", original)
    assert flow_metrics._audit_line_count(path) == 2


def test_audit_changed_during_read_is_not_cached_as_complete(tmp_path, monkeypatch):
    monkeypatch.setattr(flow_metrics, "_audit_cache", None)
    path = tmp_path / "audit.log"
    path.write_bytes(b"one\n")
    original = flow_metrics.os.fstat
    calls = []

    def mutate_after_read(descriptor):
        calls.append(1)
        if len(calls) == 2:
            with path.open("ab") as stream:
                stream.write(b"two\n")
        return original(descriptor)

    monkeypatch.setattr(flow_metrics.os, "fstat", mutate_after_read)
    assert flow_metrics._audit_line_count(path) == 0
    assert flow_metrics._audit_cache is None
    monkeypatch.setattr(flow_metrics.os, "fstat", original)
    assert flow_metrics._audit_line_count(path) == 2


def test_flow_writer_reuses_worker_coalesces_and_recovers(monkeypatch):
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QWidget
    from angerona.gui.async_snapshot import AsyncSnapshot
    from angerona.gui.main_window import MainWindow

    class Harness(QWidget):
        _prepare_flow_write = MainWindow._prepare_flow_write
        _write_flow_metrics_async = MainWindow._write_flow_metrics_async

        def __init__(self):
            super().__init__()
            self.manager = self.bus = self.config = SimpleNamespace()
            self._flow_writer = AsyncSnapshot(
                self, self._prepare_flow_write, lambda _: None, name="FlowMetricsWriter",
            )

    entered, release = threading.Event(), threading.Event()
    calls = []

    def write(*_):
        calls.append(threading.get_ident())
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
            raise OSError("inert write failure")

    monkeypatch.setattr(flow_metrics, "write", write)
    owner = Harness()
    reader = owner._flow_writer

    def settle():
        deadline = time.monotonic() + 5
        while reader.busy and time.monotonic() < deadline:
            reader._poll()
            time.sleep(0.001)
        assert not reader.busy

    try:
        owner._write_flow_metrics_async()
        assert entered.wait(2)
        worker = reader.thread
        for _ in range(100):
            owner._write_flow_metrics_async()
        assert len(calls) == 1
        release.set()
        settle()
        assert len(calls) == 2  # one coalesced retry after the failed write
        for _ in range(30):
            owner._write_flow_metrics_async()
            settle()
            assert reader.thread is worker
        assert len(set(calls)) == 1
        assert calls[0] != threading.get_ident()
    finally:
        release.set()
        reader.close()
        if reader.thread:
            reader.thread.join(2)
            assert not reader.thread.is_alive()
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_flow_writer_can_retry_after_thread_start_failure(monkeypatch):
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QWidget
    from angerona.gui.async_snapshot import AsyncSnapshot
    from angerona.gui.main_window import MainWindow

    owner = QWidget()
    owner.manager = owner.bus = owner.config = SimpleNamespace()
    completed = threading.Event()
    monkeypatch.setattr(flow_metrics, "write", lambda *_: completed.set())
    reader = AsyncSnapshot(
        owner, lambda: MainWindow._prepare_flow_write(owner), lambda _: None,
        name="FlowMetricsWriter",
    )
    original = threading.Thread.start

    def fail(_):
        raise RuntimeError("inert start failure")

    try:
        monkeypatch.setattr(threading.Thread, "start", fail)
        reader.request()
        assert not reader.busy
        monkeypatch.setattr(threading.Thread, "start", original)
        reader.request()
        assert completed.wait(2)
    finally:
        reader.close()
        if reader.thread:
            reader.thread.join(2)
            assert not reader.thread.is_alive()
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
