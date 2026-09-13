"""Bounded recovery of application-owned diagnostic and recorder workers.

Decisions use live service objects, never commands or diagnoses from log text.
Module/process restarts remain owned by their existing watchdogs. This worker
does not edit code, enroll trust, clear evidence, or interrupt a live thread.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import threading
import time


@dataclass
class _Rule:
    service: object
    failures: int = 0
    attempts: int = 0
    next_attempt: float = 0.0
    stable_since: float | None = None
    state: str = "observing"
    last_result: str = "not_attempted"
    error_type: str = ""
    evidence: dict = field(default_factory=dict)


class RuntimeHealer:
    """Confirm, repair, then independently observe each worker's recovery.

    Three attempts per incident, monotonic backoff, and five minutes of proven
    stability prevent restart storms. Budgets are process-local because these
    rules repair only this process's threads and diagnostic snapshots.
    """

    INTERVAL_SECONDS = 15.0
    CHILL_INTERVAL_SECONDS = 60.0
    BACKOFF_SECONDS = (15.0, 60.0, 300.0)
    STABILITY_SECONDS = 300.0
    CONFIRMATIONS = 2

    def __init__(self, reporter, recorder, bus, config, *, clock=time.monotonic):
        self._rules = {
            "status_reporter": _Rule(reporter),
            "flight_recorder": _Rule(recorder),
        }
        self._bus = bus
        self._config = config
        self._clock = clock
        self._stop = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._sweep_lock = threading.Lock()
        self._snapshot_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._history: deque[dict] = deque(maxlen=32)
        self._view: dict = {
            "components": {}, "recent_actions": [], "bus_advisory": {},
        }

    def start(self) -> bool:
        with self._lifecycle_lock:
            if self._stop.is_set() or (self._thread and self._thread.is_alive()):
                return False
            self._thread = threading.Thread(
                target=self._loop, name="RuntimeHealer", daemon=True,
            )
            try:
                self._thread.start()
            except Exception:
                self._thread = None
                raise
            return True

    def stop(self, timeout: float = 2.0) -> bool:
        # Serialize with action admission so teardown cannot revive a service.
        with self._lifecycle_lock:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, timeout))
        return thread is None or not thread.is_alive()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            chill = bool(getattr(self._config, "runtime_chill_active", False))
            self._stop.wait(
                self.CHILL_INTERVAL_SECONDS if chill else self.INTERVAL_SECONDS
            )

    def run_once(self) -> None:
        """One bounded sweep; concurrent callers cannot multiply attempts."""
        if self._stop.is_set() or not self._sweep_lock.acquire(blocking=False):
            return
        try:
            now = self._clock()
            for name, rule in self._rules.items():
                if self._stop.is_set():
                    break
                self._observe(name, rule, now)
            self._refresh_view()
        finally:
            self._sweep_lock.release()

    def _observe(self, name: str, rule: _Rule, now: float) -> None:
        try:
            health = rule.service.recovery_snapshot()
            if not isinstance(health, dict) or type(health.get("healthy")) is not bool:
                raise ValueError("invalid service health probe")
        except Exception as exc:
            # Unavailable evidence never authorizes a restart.
            rule.state = "unknown"
            rule.error_type = type(exc).__name__[:80]
            rule.failures = 0
            rule.stable_since = None
            return
        error_type = health.get("last_error_type", "")
        rule.error_type = (
            error_type if isinstance(error_type, str) and error_type.isidentifier()
            and len(error_type) <= 80 else ""
        )
        rule.evidence = {
            key: value for key in (
                "worker_alive", "dlq_worker_alive", "write_failures",
                "dlq_failures", "replay_failures", "replay_quarantined",
            )
            if type(value := health.get(key)) in (bool, int)
            and (isinstance(value, bool) or value >= 0)
        }
        if health.get("stopping") is True:
            rule.state = "stopped"
            rule.failures = 0
            rule.stable_since = None
            return
        if health["healthy"]:
            rule.failures = 0
            if rule.attempts:
                if rule.stable_since is None:
                    rule.stable_since = now
                    self._record(name, "recovery_observed", rule.attempts)
                if now - rule.stable_since >= self.STABILITY_SECONDS:
                    rule.attempts = 0
                    rule.next_attempt = 0.0
                    rule.last_result = "stable"
                    rule.state = "healthy"
                else:
                    rule.state = "stabilizing"
            else:
                rule.state = "healthy"
            return
        rule.stable_since = None
        rule.failures = min(self.CONFIRMATIONS, rule.failures + 1)
        if rule.failures < self.CONFIRMATIONS:
            rule.state = "confirming"
            return
        if rule.attempts >= len(self.BACKOFF_SECONDS):
            rule.state = "attention_required"
            return
        if now < rule.next_attempt:
            rule.state = "cooldown"
            return
        with self._lifecycle_lock:
            if self._stop.is_set():
                return
            # Charge before invoking code, including exceptions and refusals.
            rule.attempts += 1
            rule.next_attempt = now + self.BACKOFF_SECONDS[rule.attempts - 1]
            try:
                accepted = rule.service.recover() is True
                rule.last_result = "requested" if accepted else "declined"
            except Exception as exc:
                rule.last_result = "failed"
                rule.error_type = type(exc).__name__[:80]
            rule.state = "verifying"
            self._record(name, rule.last_result, rule.attempts)

    def _record(self, name: str, result: str, attempt: int) -> None:
        self._history.append({
            "component": name, "result": result, "attempt": attempt,
            "observed_at": time.time(),
        })

    def _refresh_view(self) -> None:
        try:
            rows = self._bus.subscriber_metrics()
            advisory = {
                "failures": sum(row.failures for row in rows),
                "budget_violations": sum(row.budget_violations for row in rows),
                "action": "diagnostic_only",
            }
        except Exception:
            advisory = {"action": "diagnostic_unavailable"}
        view = {
            "components": {
                name: {
                    "state": rule.state, "attempts": rule.attempts,
                    "last_result": rule.last_result, "error_type": rule.error_type,
                    "evidence": dict(rule.evidence),
                }
                for name, rule in self._rules.items()
            },
            "recent_actions": list(self._history),
            "bus_advisory": advisory,
        }
        with self._snapshot_lock:
            self._view = view

    def snapshot(self) -> dict:
        """A small status-only copy; never live service objects or raw errors."""
        with self._snapshot_lock:
            return {
                "enabled": not self._stop.is_set(),
                "worker_alive": bool(self._thread and self._thread.is_alive()),
                "components": {
                    name: {**row, "evidence": dict(row["evidence"])}
                    for name, row in self._view["components"].items()
                },
                "recent_actions": [dict(row) for row in self._view["recent_actions"]],
                "bus_advisory": dict(self._view["bus_advisory"]),
                "scope": "worker availability; evidence continuity is not certified",
            }
