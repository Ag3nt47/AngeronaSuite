"""Inert benchmark contracts; no live collectors, children or sockets."""
from __future__ import annotations

import builtins
import math
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import ModuleType

import pytest

from angerona.telemetry import sensors


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "benchmark_module_poll_efficiency.py"
SOURCE = ROOT / "src" / "angerona" / "modules" / "process_monitor.py"


@pytest.fixture
def tool():
    # Compile the actual tool bytes; do not admit a cached sibling .pyc.
    namespace = ModuleType("angerona_poll_benchmark_test")
    namespace.__file__ = str(TOOL)
    exec(compile(TOOL.read_bytes(), str(TOOL), "exec"), namespace.__dict__)
    return namespace


def _source():
    return SOURCE.read_text(encoding="utf-8")


@pytest.mark.parametrize("processes,polls,arguments", [(1, 1, 0), (7, 3, 4)])
def test_current_loop_uses_every_supplied_typed_snapshot(tool, processes, polls, arguments):
    result = tool.benchmark(_source(), processes=processes, polls=polls, arguments=arguments)
    assert result["processes"] == processes
    assert result["polls"] == polls
    assert result["arguments"] == arguments
    assert result["fixture_snapshot_calls"] == [polls] * 5
    assert math.isfinite(result["median_ms_per_poll"])
    assert result["median_ms_per_poll"] >= 0


@pytest.mark.parametrize("operation,expression", [
    ("sensors.process_snapshot", "__import__('angerona.telemetry.sensors', fromlist=['x']).process_snapshot()"),
    ("sensors.list_processes", "__import__('angerona.telemetry.sensors', fromlist=['x']).list_processes()"),
    ("sensors.connection_snapshot", "__import__('angerona.telemetry.sensors', fromlist=['x']).connection_snapshot()"),
    ("sensors.list_connections", "__import__('angerona.telemetry.sensors', fromlist=['x']).list_connections()"),
    ("psutil.Process", "__import__('psutil').Process(900001)"),
    ("psutil.process_iter", "__import__('psutil').process_iter()"),
    ("psutil.net_connections", "__import__('psutil').net_connections()"),
    ("psutil._ppid_map", "__import__('psutil')._ppid_map()"),
    ("psutil.cpu_percent", "__import__('psutil').cpu_percent()"),
    ("subprocess.Popen", "__import__('subprocess').Popen(['inert-never-launched'])"),
    ("threading.Thread.start", "__import__('threading').Thread(target=lambda: None).start()"),
    ("socket.socket", "__import__('socket').socket()"),
    ("socket.create_connection", "__import__('socket').create_connection(('127.0.0.1', 1))"),
    ("os.system", "__import__('os').system('inert-never-executed')"),
    ("os.popen", "__import__('os').popen('inert-never-executed')"),
])
def test_swallowed_host_access_attempt_still_refuses_benchmark(tool, operation, expression):
    source = _source() + f"""
_original_run = ProcessMonitorModule.run
def _attempt_host_access(self):
    try:
        {expression}
    except Exception:
        pass
    return _original_run(self)
ProcessMonitorModule.run = _attempt_host_access
"""
    with pytest.raises(tool.InertBenchmarkViolation, match=rf"blocked {re.escape(operation)}$"):
        tool.benchmark(source, processes=2, polls=2, arguments=1)


def test_guard_is_active_while_reviewed_source_loads(tool):
    source = _source() + """
try:
    __import__('psutil').Process(900001)
except Exception:
    pass
"""
    with pytest.raises(tool.InertBenchmarkViolation, match=r"blocked psutil\.Process$"):
        tool.benchmark(source, processes=2, polls=2, arguments=1)


def test_captured_original_collector_cannot_return_cached_host_rows(tool, monkeypatch):
    saved = sensors.process_snapshot
    sentinel = sensors.ProcessSnapshot((), 123.0, True, 0, 0)
    original_cache = (time.monotonic(), sentinel)
    monkeypatch.setattr(sensors, "_proc_cache", original_cache)
    monkeypatch.setattr(builtins, "_angerona_saved_benchmark_collector", saved, raising=False)
    source = _source() + """
_original_run = ProcessMonitorModule.run
def _attempt_saved_collector(self):
    try:
        __import__('builtins')._angerona_saved_benchmark_collector(max_age=3600)
    except Exception:
        pass
    return _original_run(self)
ProcessMonitorModule.run = _attempt_saved_collector
"""
    with pytest.raises(tool.InertBenchmarkViolation, match=r"blocked psutil\.Process$"):
        tool.benchmark(source, processes=2, polls=2, arguments=1)
    assert sensors._proc_cache is original_cache


@pytest.mark.parametrize("replacement", [
    "def _ignored_snapshot(*args, **kwargs):\n    return None\nProcessMonitorModule.run = lambda self: None\n",
    "_original_run = ProcessMonitorModule.run\ndef _drop_rows(self):\n    _original_run(self)\n    self._seen.clear()\nProcessMonitorModule.run = _drop_rows\n",
])
def test_missing_fixture_reads_or_incomplete_cohort_cannot_report_timings(tool, replacement):
    with pytest.raises(tool.InertBenchmarkViolation, match="complete supplied cohort"):
        tool.benchmark(_source() + "\n" + replacement, processes=2, polls=2, arguments=1)


@pytest.mark.parametrize("outcome", ["return", "source-error", "blocked-access"])
def test_guard_restores_entry_points_and_caches_after_return_or_refusal(tool, outcome):
    owners = (
        (sensors, "process_snapshot"), (sensors, "list_processes"),
        (sensors, "connection_snapshot"), (sensors, "list_connections"),
        (sensors, "_proc_cache"), (sensors, "_conn_cache"),
        (subprocess, "Popen"), (threading.Thread, "start"),
        (socket, "socket"), (socket, "create_connection"),
        (os, "system"), (os, "popen"),
    )
    original = [getattr(owner, name) for owner, name in owners]
    absent = object()
    previous_psutil = sys.modules.get("psutil", absent)
    source = _source()
    if outcome == "source-error":
        source += "\nraise RuntimeError('inert load refusal')\n"
        with pytest.raises(RuntimeError, match="inert load refusal"):
            tool.benchmark(source, processes=2, polls=2, arguments=1)
    elif outcome == "blocked-access":
        source += "\n__import__('psutil').Process(900001)\n"
        with pytest.raises(tool.InertBenchmarkViolation, match=r"blocked psutil\.Process$"):
            tool.benchmark(source, processes=2, polls=2, arguments=1)
    else:
        tool.benchmark(source, processes=2, polls=2, arguments=1)
    assert all(getattr(owner, name) is value for (owner, name), value in zip(owners, original))
    assert sys.modules.get("psutil", absent) is previous_psutil


@pytest.mark.parametrize("dimensions", [
    {"processes": 0, "polls": 1, "arguments": 0},
    {"processes": 1, "polls": 0, "arguments": 0},
    {"processes": True, "polls": 1, "arguments": 0},
    {"processes": 1, "polls": 1, "arguments": -1},
])
def test_invalid_dimensions_refused_before_source_execution(tool, dimensions):
    with pytest.raises(ValueError, match="benchmark dimensions"):
        tool.benchmark("raise AssertionError('source must not execute')", **dimensions)
