"""Opt-in, bounded runtime evidence with real queue and GUI measurements.

Publishing is disabled unless ANGERONA_RUNTIME_METRICS=1. The GUI records only
small in-memory timing samples; one worker writes at ten-second intervals.
Headless instances expose GUI measurements as not applicable, never zero.
"""
from __future__ import annotations

from collections import deque
import math
import os
from pathlib import Path
import threading
import time
from typing import Callable

from .engine_transport import canonical

SCHEMA = "angerona.runtime-metrics/v1"
MAX_BYTES = 64 * 1024
MAX_AGE_SECONDS = 35.0


def _integer(value, name, *, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        raise ValueError(f"Invalid runtime counter: {name}")
    return value


def _number(value, name, *, minimum=0):
    if type(value) not in (float, int) or not math.isfinite(value) or value < minimum:
        raise ValueError(f"Invalid runtime measurement: {name}")
    return float(value)


class RuntimeMetrics:
    def __init__(self, *, gui: bool, recorder=None, evidence=None, retention=None,
                 extra_queues: dict[str, Callable[[], dict]] | None = None,
                 clock=time.monotonic, wall_clock=time.time):
        import psutil
        self.pid = os.getpid()
        self.process_started_at = psutil.Process(self.pid).create_time()
        self.gui = gui
        self.recorder, self.evidence, self.retention = recorder, evidence, retention
        self.extra_queues = extra_queues or {}
        if len(self.extra_queues) > 8:
            raise ValueError("Too many runtime queue producers")
        self.clock, self.wall_clock = clock, wall_clock
        self._lock = threading.Lock()
        self._ticks = deque(maxlen=128)
        self._beats = deque(maxlen=128)
        self._last_beat = None
        self._beat_interval = 1.0

    def heartbeat(self, *, expected_seconds: float = 1.0) -> None:
        now = self.clock()
        with self._lock:
            if self._last_beat is not None:
                lag = max(0.0, now - self._last_beat - self._beat_interval) * 1000
                self._beats.append((now, lag))
            self._last_beat = now
            self._beat_interval = max(0.1, min(60.0, expected_seconds))

    def record_tick(self, duration_ms: float) -> None:
        value = _number(duration_ms, "GUI tick duration")
        with self._lock:
            self._ticks.append((self.clock(), value))

    @staticmethod
    def _queue(name, depth, capacity, drops):
        depth = _integer(depth, "queue depth")
        capacity = _integer(capacity, "queue capacity", minimum=1)
        if depth > capacity:
            raise ValueError("Runtime queue exceeds its declared capacity")
        return {"name": name, "depth": depth, "capacity": capacity,
                "dropped": _integer(drops, "queue drops")}

    def snapshot(self) -> dict:
        queues = []
        # AsyncFlightRecorder.metrics() also enumerates its on-disk spool. This
        # read side deliberately samples the producer's actual memory counters
        # under its existing lock, without adding filesystem work to polling.
        if self.recorder is not None:
            recorder = self.recorder
            with recorder._metrics_lock:
                queues.append(self._queue("flight_recorder", recorder._queue.qsize(),
                                          recorder._queue.maxsize, recorder._dlq_failures))
                queues.append(self._queue("flight_recorder_overflow", recorder._overflow_queue.qsize(),
                                          recorder._overflow_queue.maxsize, 0))
        if self.evidence is not None:
            metrics = self.evidence.metrics()
            queues.append(self._queue("evidence_read_model", metrics.queue_depth,
                                      metrics.queue_capacity, metrics.dropped_full + metrics.failed))
        if self.retention is not None:
            metrics = self.retention.snapshot()
            queues.append(self._queue("alert_diagnostics", metrics["queued"],
                                      self.retention._queue.maxsize, metrics["dropped"] + metrics["writer_errors"]))
        for name, callback in self.extra_queues.items():
            metrics = callback()
            queues.append(self._queue(name, metrics["depth"], metrics["capacity"], metrics["dropped"]))
        if not queues:
            raise ValueError("No real runtime queue producer is configured")
        worst = max(queues, key=lambda item: item["depth"] / item["capacity"])
        now = self.clock()
        with self._lock:
            ticks = [value for observed, value in self._ticks if now - observed <= 15]
            beats = [value for observed, value in self._beats if now - observed <= 15]
            age = None if self._last_beat is None else max(0.0, now - self._last_beat)
            lag = None if age is None else max(0.0, age - self._beat_interval) * 1000
            if beats and lag is not None:
                lag = max(lag, max(beats))
        duration = max(ticks) if ticks else None
        tick_ms = max(duration or 0, lag or 0) if self.gui and age is not None else None
        result = {"schema": SCHEMA, "pid": self.pid,
                  "process_started_at": self.process_started_at, "sampled_at": self.wall_clock(),
                  "queue_depth": worst["depth"], "queue_capacity": worst["capacity"],
                  "queue_scope": "worst observed queue", "queues": queues,
                  "dropped_events": sum(item["dropped"] for item in queues),
                  "drop_scope": "observed recorder, read-model and diagnostic delivery failures",
                  "gui_applicable": self.gui, "tick_ms": tick_ms,
                  "gui_heartbeat_age_seconds": age if self.gui else None,
                  "gui_heartbeat_lag_ms": lag if self.gui else None,
                  "gui_tick_duration_ms": duration if self.gui else None}
        if len(canonical(result)) > MAX_BYTES:
            raise ValueError("Runtime metrics exceeded byte bound")
        return result


def validate_metrics(value: dict, *, pid: int, process_started_at: float,
                     now: float | None = None) -> dict:
    """Bind complete, fresh evidence to the exact measured process lifetime."""
    required = {"schema", "pid", "process_started_at", "sampled_at", "queue_depth",
                "queue_capacity", "queue_scope", "queues", "dropped_events", "drop_scope",
                "gui_applicable", "tick_ms", "gui_heartbeat_age_seconds",
                "gui_heartbeat_lag_ms", "gui_tick_duration_ms"}
    if not isinstance(value, dict) or set(value) != required or value["schema"] != SCHEMA:
        raise ValueError("Runtime metrics schema is incomplete or unsupported")
    if _integer(value["pid"], "PID", minimum=1) != pid:
        raise ValueError("Runtime metrics belong to a different PID")
    birth = _number(value["process_started_at"], "process birth")
    if abs(birth - process_started_at) > 0.01:
        raise ValueError("Runtime metrics belong to a different process lifetime")
    sampled = _number(value["sampled_at"], "sample timestamp")
    age = (time.time() if now is None else now) - sampled
    if not -2 <= age <= MAX_AGE_SECONDS:
        raise ValueError("Runtime metrics are stale or future-dated")
    if type(value["gui_applicable"]) is not bool:
        raise ValueError("Runtime GUI applicability is unknown")
    names = set()
    queues = value["queues"]
    if not isinstance(queues, list) or not 1 <= len(queues) <= 16:
        raise ValueError("Runtime metrics have no bounded queue observations")
    for item in queues:
        if (not isinstance(item, dict) or set(item) != {"name", "depth", "capacity", "dropped"}
                or not isinstance(item["name"], str) or not 1 <= len(item["name"]) <= 80
                or item["name"] in names):
            raise ValueError("Runtime queue record is invalid")
        RuntimeMetrics._queue(item["name"], item["depth"], item["capacity"], item["dropped"])
        names.add(item["name"])
    worst = max(queues, key=lambda item: item["depth"] / item["capacity"])
    if (value["queue_depth"] != worst["depth"] or value["queue_capacity"] != worst["capacity"]
            or value["dropped_events"] != sum(item["dropped"] for item in queues)):
        raise ValueError("Runtime aggregate counters do not match their producers")
    for name in ("queue_depth", "queue_capacity", "dropped_events"):
        _integer(value[name], name, minimum=1 if name == "queue_capacity" else 0)
    for name in ("tick_ms", "gui_heartbeat_age_seconds", "gui_heartbeat_lag_ms"):
        if value["gui_applicable"]:
            _number(value[name], name)
        elif value[name] is not None:
            raise ValueError("Headless GUI timing must be explicitly not applicable")
    if value["gui_tick_duration_ms"] is not None:
        _number(value["gui_tick_duration_ms"], "GUI tick duration")
    if not value["gui_applicable"] and value["gui_tick_duration_ms"] is not None:
        raise ValueError("Headless GUI timing must be explicitly not applicable")
    return value


class MetricsPublisher:
    def __init__(self, metrics: RuntimeMetrics, root: Path, *, interval: float = 10.0):
        if interval < 10:
            raise ValueError("Runtime metrics cadence must be at least ten seconds")
        self.metrics = metrics
        self.path = root / "diagnostics" / f"runtime-metrics-{metrics.pid}.json"
        self.interval = interval
        self.stop_event = threading.Event()
        self.last_error = ""
        self.thread = threading.Thread(target=self._run, name="RuntimeMetricsPublisher", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self, timeout=1.0):
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join(timeout)

    def publish(self):
        from .source_sandbox import _atomic_bytes_write, _ensure_directory
        _ensure_directory(self.path.parent)
        _atomic_bytes_write(self.path, canonical(self.metrics.snapshot()), root=self.path.parent)
        self.last_error = ""

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.publish()
            except Exception as exc:
                self.last_error = type(exc).__name__
            self.stop_event.wait(self.interval)


def optional_publisher(metrics: RuntimeMetrics, root: Path) -> MetricsPublisher | None:
    if os.environ.get("ANGERONA_RUNTIME_METRICS") != "1":
        return None
    publisher = MetricsPublisher(metrics, root)
    publisher.start()
    return publisher
