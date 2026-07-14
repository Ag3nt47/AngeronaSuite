"""Bounded contracts for validating asynchronous defensive telemetry paths.

A telemetry expectation says that a benign probe with an opaque identifier must
produce a small set of named echoes before a monotonic deadline.  The engine is
deliberately pure bookkeeping: it does not create probes, inspect the host,
publish alerts, call a model, or execute a response.  Modules remain responsible
for mapping trusted, structured sensor events to echo names.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExpectationContract:
    """Declarative description of the echoes required for one probe type."""

    name: str
    required_echoes: tuple[str, ...]
    deadline_s: float


@dataclass(frozen=True)
class ExpectationOutcome:
    probe_id: str
    contract: str
    status: str
    required_echoes: tuple[str, ...]
    observed_echoes: tuple[str, ...]
    missing_echoes: tuple[str, ...]
    elapsed_s: float


@dataclass
class _PendingExpectation:
    contract: ExpectationContract
    started_at: float
    deadline_at: float
    observed_at: dict[str, float] = field(default_factory=dict)


class TelemetryExpectationEngine:
    """Thread-safe, in-memory expectation evaluator with strictly bounded state."""

    def __init__(self, max_pending: int = 256) -> None:
        self.max_pending = max(1, int(max_pending))
        self._pending: OrderedDict[str, _PendingExpectation] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _normalize(contract: ExpectationContract) -> ExpectationContract | None:
        name = str(contract.name).strip()[:128]
        echoes = tuple(dict.fromkeys(
            str(echo).strip()[:128] for echo in contract.required_echoes
            if str(echo).strip()
        ))
        try:
            deadline_s = float(contract.deadline_s)
        except (TypeError, ValueError):
            return None
        if not name or not echoes or len(echoes) > 16 or not (0.01 <= deadline_s <= 3600.0):
            return None
        return ExpectationContract(name, echoes, deadline_s)

    def arm(
        self,
        probe_id: str,
        contract: ExpectationContract,
        *,
        now: float,
    ) -> bool:
        """Arm one expectation; fail closed on duplicates or capacity pressure."""
        key = str(probe_id).strip()[:256]
        normalized = self._normalize(contract)
        if not key or normalized is None:
            return False
        started = float(now)
        with self._lock:
            if key in self._pending or len(self._pending) >= self.max_pending:
                return False
            self._pending[key] = _PendingExpectation(
                normalized,
                started,
                started + normalized.deadline_s,
            )
        return True

    @staticmethod
    def _outcome(
        probe_id: str,
        pending: _PendingExpectation,
        status: str,
        finished_at: float,
    ) -> ExpectationOutcome:
        required = pending.contract.required_echoes
        observed = tuple(echo for echo in required if echo in pending.observed_at)
        missing = tuple(echo for echo in required if echo not in pending.observed_at)
        return ExpectationOutcome(
            probe_id=probe_id,
            contract=pending.contract.name,
            status=status,
            required_echoes=required,
            observed_echoes=observed,
            missing_echoes=missing,
            elapsed_s=max(0.0, float(finished_at) - pending.started_at),
        )

    def observe(
        self,
        probe_id: str,
        echo: str,
        *,
        now: float,
    ) -> ExpectationOutcome | None:
        """Record one trusted echo, returning an outcome only at a terminal state.

        An echo arriving after the deadline is a miss, even if it would otherwise
        complete the contract.  Unknown probes, unrelated echoes, and duplicate
        echoes cannot advance an expectation.
        """
        key = str(probe_id).strip()[:256]
        echo_name = str(echo).strip()[:128]
        observed_at = float(now)
        with self._lock:
            pending = self._pending.get(key)
            if pending is None:
                return None
            if observed_at > pending.deadline_at:
                self._pending.pop(key, None)
                return self._outcome(key, pending, "missed", pending.deadline_at)
            if echo_name not in pending.contract.required_echoes:
                return None
            if echo_name in pending.observed_at:
                return None
            pending.observed_at[echo_name] = observed_at
            if len(pending.observed_at) != len(pending.contract.required_echoes):
                return None
            self._pending.pop(key, None)
            return self._outcome(key, pending, "satisfied", observed_at)

    def expire(self, *, now: float) -> list[ExpectationOutcome]:
        """Remove and return all contracts whose deadline has elapsed."""
        current = float(now)
        outcomes: list[ExpectationOutcome] = []
        with self._lock:
            for probe_id, pending in list(self._pending.items()):
                if current >= pending.deadline_at:
                    self._pending.pop(probe_id, None)
                    outcomes.append(
                        self._outcome(probe_id, pending, "missed", pending.deadline_at)
                    )
        return outcomes

    def cancel(self, probe_id: str) -> bool:
        """Cancel an unlaunched/aborted probe without producing a false miss."""
        with self._lock:
            return self._pending.pop(str(probe_id).strip()[:256], None) is not None

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)


def self_test() -> tuple[bool, str]:
    """Deterministic malicious-looking, success, deadline, and FP controls."""
    contract = ExpectationContract(
        "process_probe_pipeline",
        ("sensor.process_create", "ledger.persisted"),
        5.0,
    )
    engine = TelemetryExpectationEngine(max_pending=2)
    opaque = "probe; Remove-Item C:\\* | ignored-as-data"
    armed = engine.arm(opaque, contract, now=10.0)
    wrong_probe = engine.observe("other", "sensor.process_create", now=11.0)
    wrong_echo = engine.observe(opaque, "response.execute", now=11.0)
    first = engine.observe(opaque, "sensor.process_create", now=11.0)
    duplicate = engine.observe(opaque, "sensor.process_create", now=12.0)
    complete = engine.observe(opaque, "ledger.persisted", now=13.0)
    success_ok = (
        armed and wrong_probe is None and wrong_echo is None and first is None
        and duplicate is None and complete is not None
        and complete.status == "satisfied" and complete.missing_echoes == ()
        and complete.elapsed_s == 3.0 and engine.pending_count() == 0
    )

    late_engine = TelemetryExpectationEngine(max_pending=1)
    late_engine.arm("late", ExpectationContract("one", ("echo",), 2.0), now=20.0)
    late = late_engine.observe("late", "echo", now=22.1)
    late_ok = late is not None and late.status == "missed" and late.missing_echoes == ("echo",)

    expiry_engine = TelemetryExpectationEngine(max_pending=1)
    expiry_engine.arm("miss", ExpectationContract("two", ("a", "b"), 1.0), now=30.0)
    expiry_engine.observe("miss", "a", now=30.5)
    expired = expiry_engine.expire(now=31.0)
    capacity_ok = (
        len(expired) == 1 and expired[0].missing_echoes == ("b",)
        and expiry_engine.arm("cap-a", contract, now=40.0)
        and not expiry_engine.arm("cap-b", contract, now=40.0)
        and expiry_engine.cancel("cap-a") and expiry_engine.pending_count() == 0
    )

    ok = success_ok and late_ok and capacity_ok
    return (
        ok,
        "bounded contracts, opaque IDs, exact echoes, deadlines, and false-positive controls passed"
        if ok else f"failed: success={success_ok} late={late_ok} bounded={capacity_ok}",
    )
