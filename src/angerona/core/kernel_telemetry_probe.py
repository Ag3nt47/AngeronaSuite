"""Provider-specific benign telemetry loops and exact custody of their own child.

An echo demonstrates one observed collection path. It cannot attest intact
kernel callbacks, exclude Ring 0 tampering or grant response authority. Polling
and synthetic events never satisfy either native provider's expectation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import sys
import threading
import time

PROVIDERS = {"kernel-etw": "ETW Real-Time Process Sensor", "sysmon-native": "Sysmon Event Bridge"}
MAX_PENDING = 8
RECEIPT_MAX_AGE = 15.0
_TAG = re.compile(r"DRILLCANARY_[0-9A-F]{16}\Z")
_GENERATION = re.compile(r"[0-9a-f]{32}(?:[0-9a-f]{32})?\Z")
_HMAC = re.compile(r"[0-9a-f]{64}\Z")
_EPOCH = 116444736000000000


def _finite(value):
    return type(value) in (int, float) and 0 <= value <= 253402300799 and math.isfinite(value)


@dataclass(frozen=True)
class ProviderReceipt:
    provider: str
    generation: str
    available: bool
    sampled_monotonic: float
    reason: str

    @classmethod
    def from_snapshot(cls, provider: str, value: object, *, now: float):
        if provider not in PROVIDERS or not _finite(now):
            raise ValueError("Unknown native provider or clock")
        unavailable = cls(provider, "", False, now, "native collector unavailable or cached receipt stale")
        if type(value) is not dict or value.get("source_module") != PROVIDERS[provider]:
            return unavailable
        generation, sampled = value.get("generation"), value.get("sampled_monotonic")
        if (type(generation) is not str or not _GENERATION.fullmatch(generation)
                or not _finite(sampled) or not 0 <= now - sampled <= RECEIPT_MAX_AGE):
            return unavailable
        available = (value.get("mode") == "native" and value.get("live") is True
                     and type(value.get("loss_count")) is int and value["loss_count"] == 0)
        return cls(provider, generation, available, sampled,
                   "cached native collector receipt" if available else "native collector is unavailable, lossy or using fallback")


@dataclass(frozen=True)
class KernelEcho:
    tag: str
    provider: str
    generation: str
    pid: int
    event_ts: float
    hmac: str
    observed_monotonic: float
    live_enrolled_observed: bool
    correlation_basis: str = "command-line-nonce"

    def __post_init__(self):
        if (type(self.tag) is not str or not _TAG.fullmatch(self.tag)
                or type(self.provider) is not str or self.provider not in PROVIDERS
                or type(self.generation) is not str or not _GENERATION.fullmatch(self.generation)
                or type(self.pid) is not int or not 1 <= self.pid <= 0xFFFFFFFF
                or not _finite(self.event_ts) or self.event_ts <= 0
                or type(self.hmac) is not str or not _HMAC.fullmatch(self.hmac)
                or not _finite(self.observed_monotonic) or type(self.live_enrolled_observed) is not bool
                or self.correlation_basis not in {"command-line-nonce", "native-pid-birth"}):
            raise ValueError("Native echo metadata is malformed")


@dataclass(frozen=True)
class KernelIdentityCandidate:
    """Only a worker holding the probe identity may bind this to a local nonce."""

    provider: str
    generation: str
    pid: int
    birth_ticks: str
    event_ts: float
    hmac: str
    observed_monotonic: float
    live_enrolled_observed: bool


@dataclass(frozen=True)
class KernelProbeOutcome:
    tag: str
    provider: str
    generation: str
    state: str
    reason: str
    prior_path_observed: bool
    consecutive_misses: int
    live_enrolled_observed: bool = False
    event_hmac: str = ""
    event_ts: float | None = None
    correlation_basis: str = ""

    def event_details(self):
        result = dict(canary_tag=self.tag, source=self.provider, collection_generation=self.generation,
                    coverage_state=self.state, coverage_reason=self.reason,
                    prior_path_observed=self.prior_path_observed,
                    probe_correlation=self.correlation_basis,
                    consecutive_misses=self.consecutive_misses,
                    live_enrolled_observed=self.live_enrolled_observed,
                    kernel_integrity_verified=False, disposition="health", active_attack=False,
                    response_authorized=False, cause_unconfirmed=True, advisory_only=True)
        if _HMAC.fullmatch(self.event_hmac) and _finite(self.event_ts):
            result.update(trigger_hmac=self.event_hmac, trigger_ts=self.event_ts)
        return result


@dataclass
class _Pending:
    pid: int
    birth_ticks: str
    started_wall: float
    started_monotonic: float
    deadline: float
    providers: dict[str, ProviderReceipt]
    echoes: dict[str, KernelEcho] = field(default_factory=dict)


class KernelProbeTracker:
    """Worker-owned, bounded per-provider sensor AND durable-record contracts."""

    def __init__(self):
        self._pending: dict[str, _Pending] = {}
        self._generations: dict[str, str] = {}
        self._receipts: dict[str, ProviderReceipt] = {}
        self._observed: set[str] = set()
        self._misses: dict[str, int] = {}
        self._latest: dict[str, KernelProbeOutcome] = {}

    def arm(self, tag: str, *, pid: int, birth_ticks: str, started_wall: float,
            now: float, receipts: tuple[ProviderReceipt, ...], timeout: float = 6.0) -> tuple[KernelProbeOutcome, ...]:
        if (type(tag) is not str or not _TAG.fullmatch(tag) or type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF
                or type(birth_ticks) is not str or not birth_ticks.isascii() or not birth_ticks.isdecimal()
                or not 1 <= len(birth_ticks) <= 20 or not _EPOCH < int(birth_ticks) <= 0xFFFFFFFFFFFFFFFF
                or birth_ticks != str(int(birth_ticks))
                or not _finite(started_wall) or not _finite(now) or not _finite(timeout)
                or not 0.1 <= timeout <= 30 or type(receipts) is not tuple
                or len(receipts) != len(PROVIDERS)
                or any(type(row) is not ProviderReceipt for row in receipts)
                or {row.provider for row in receipts} != set(PROVIDERS)
                or any(type(row.available) is not bool or not _finite(row.sampled_monotonic)
                       or type(row.reason) is not str or len(row.reason) > 240
                       or (row.available and (type(row.generation) is not str
                                             or not _GENERATION.fullmatch(row.generation))) for row in receipts)):
            raise ValueError("Native probe contract is malformed")
        if tag in self._pending or len(self._pending) >= MAX_PENDING:
            raise ValueError("Native probe capacity is unavailable")
        available, initial = {}, []
        self.refresh_receipts(receipts)
        for receipt in receipts:
            if receipt.available and 0 <= now - receipt.sampled_monotonic <= RECEIPT_MAX_AGE:
                available[receipt.provider] = receipt
            else:
                result = self._outcome(tag, receipt.provider, receipt.generation, "unavailable", receipt.reason)
                initial.append(result)
        if available:
            self._pending[tag] = _Pending(pid, birth_ticks, started_wall, now, now + timeout, available)
        return tuple(initial)

    def refresh_receipts(self, receipts: tuple[ProviderReceipt, ...]) -> None:
        """Invalidate an in-flight old generation before a later probe is fired."""
        for receipt in receipts:
            if type(receipt) is not ProviderReceipt or receipt.provider not in PROVIDERS:
                continue
            self._receipts[receipt.provider] = receipt
            latest = self._latest.get(receipt.provider)
            if receipt.generation != self._generations.get(receipt.provider):
                self._generations[receipt.provider] = receipt.generation
                self._observed.discard(receipt.provider)
                self._misses[receipt.provider] = 0
                if latest is not None:
                    self._outcome(latest.tag, receipt.provider, receipt.generation, "unavailable",
                                  "native collector generation changed; fresh scoped probe required")
            elif not receipt.available and latest is not None and latest.state == "observed":
                self._outcome(latest.tag, receipt.provider, receipt.generation, "unavailable", receipt.reason)

    def unavailable(self, tag: str, receipts: tuple[ProviderReceipt, ...], *, now: float) -> tuple[KernelProbeOutcome, ...]:
        """Report an unlaunched attempt without inventing a process identity."""
        if (type(tag) is not str or not _TAG.fullmatch(tag) or not _finite(now)
                or type(receipts) is not tuple or len(receipts) != len(PROVIDERS)
                or any(type(row) is not ProviderReceipt for row in receipts)
                or {row.provider for row in receipts} != set(PROVIDERS)
                or any(row.available is not False or not _finite(row.sampled_monotonic)
                       or not 0 <= now - row.sampled_monotonic <= RECEIPT_MAX_AGE
                       or type(row.reason) is not str or len(row.reason) > 240 for row in receipts)):
            raise ValueError("Unavailable native collector receipts are malformed")
        self.refresh_receipts(receipts)
        return tuple(self._outcome(tag, row.provider, row.generation, "unavailable",
                                   "no probe launched: " + row.reason) for row in receipts)

    def observe(self, echo: KernelEcho) -> bool:
        if type(echo) is not KernelEcho:
            return False
        pending = self._pending.get(echo.tag)
        if pending is None:
            return False
        receipt = pending.providers.get(echo.provider)
        if (receipt is None or echo.provider in pending.echoes or echo.generation != receipt.generation
                or echo.generation != self._generations.get(echo.provider)
                or echo.pid != pending.pid or not _finite(echo.observed_monotonic)
                or not pending.started_monotonic <= echo.observed_monotonic <= pending.deadline
                or not _finite(echo.event_ts) or echo.event_ts < (int(pending.birth_ticks) - _EPOCH) / 10_000_000 - 0.001
                or type(echo.hmac) is not str or not _HMAC.fullmatch(echo.hmac)
                or type(echo.live_enrolled_observed) is not bool):
            return False
        pending.echoes[echo.provider] = echo
        return True

    def awaiting_durable(self) -> tuple[KernelEcho, ...]:
        return tuple(echo for pending in self._pending.values() for echo in pending.echoes.values())

    def persisted(self, echo: KernelEcho, *, now: float) -> KernelProbeOutcome | None:
        pending = self._pending.get(echo.tag)
        current = self._receipts.get(echo.provider)
        if (pending is None or not _finite(now) or not pending.started_monotonic <= echo.observed_monotonic <= now <= pending.deadline
                or pending.echoes.get(echo.provider) != echo
                or self._generations.get(echo.provider) != echo.generation
                or current is None or not current.available
                or not 0 <= now - current.sampled_monotonic <= RECEIPT_MAX_AGE):
            return None
        pending.providers.pop(echo.provider, None)
        pending.echoes.pop(echo.provider, None)
        prior = echo.provider in self._observed
        self._observed.add(echo.provider)
        self._misses[echo.provider] = 0
        outcome = KernelProbeOutcome(echo.tag, echo.provider, echo.generation, "observed",
                                     "nonce echo and exact authenticated durable event observed for this path",
                                     prior, 0, echo.live_enrolled_observed, echo.hmac, echo.event_ts, echo.correlation_basis)
        self._latest[echo.provider] = outcome
        if not pending.providers:
            self._pending.pop(echo.tag, None)
        return outcome

    def expire(self, *, now: float) -> tuple[KernelProbeOutcome, ...]:
        if not _finite(now):
            raise ValueError("Native probe clock is invalid")
        results = []
        for tag, pending in tuple(self._pending.items()):
            if now < pending.deadline:
                continue
            self._pending.pop(tag)
            for provider, receipt in pending.providers.items():
                if receipt.generation != self._generations.get(provider):
                    results.append(self._outcome(tag, provider, receipt.generation, "unavailable",
                                                 "native collector generation changed during probe"))
                    continue
                current = self._receipts.get(provider)
                if (current is None or not current.available
                        or not 0 <= now - current.sampled_monotonic <= RECEIPT_MAX_AGE):
                    results.append(self._outcome(tag, provider, receipt.generation, "unavailable",
                                                 "native collector receipt became unavailable during probe"))
                    continue
                self._misses[provider] = min(1_000_000, self._misses.get(provider, 0) + 1)
                reason = ("exact sensor echo not durable before deadline" if provider in pending.echoes
                          else "native provider nonce echo missed its deadline; cause unconfirmed")
                results.append(self._outcome(tag, provider, receipt.generation, "missed", reason))
        return tuple(results)

    def _outcome(self, tag, provider, generation, state, reason):
        outcome = KernelProbeOutcome(tag, provider, generation, state, reason,
                                     provider in self._observed, self._misses.get(provider, 0))
        if generation == self._generations.get(provider):
            self._latest[provider] = outcome
        return outcome

    def snapshot(self):
        return tuple(self._latest.values())


class OwnedCanaryProcess:
    """Only our fixed inert child is launched, retained and retired in its Job."""

    def __init__(self, tag: str, *, _launch=None, _native=None):
        if type(tag) is not str or not _TAG.fullmatch(tag) or os.name != "nt":
            raise ValueError("Owned native canary requires Windows and a valid nonce")
        from angerona.core.windows_child_job import launch_windows_child
        from angerona.core.windows_process_lease import _Native
        executable = Path(sys.executable)
        if not executable.is_absolute():
            raise ValueError("The actual interpreter path is unavailable")
        self._lock = threading.Lock()
        self._child = None
        self.identity = None
        self._birth_ticks = ""
        self._native = _Native() if _native is None else _native
        command = ([str(executable), "--kernel-telemetry-canary", tag] if bool(getattr(sys, "frozen", False)) else
                   [str(executable), "-I", "-S", "-B", "-c", "import time;time.sleep(2)", "--angerona-canary=" + tag])
        child = (_launch or launch_windows_child)(command, dict(os.environ),
                                                  cwd=str(executable.parent), deadline=time.monotonic() + 5.0)
        self._child = child
        try:
            with child._handle_lock:
                pid, birth = self._native.object_identity(int(child._process))
                self._birth_ticks = str(birth)
                self.identity = self._native.identity(int(child._process))
            if self.identity.pid != child.pid or self.identity.pid != pid or str(self.identity.birth_ticks) != self._birth_ticks:
                raise ValueError("Owned canary native PID differs")
        except BaseException:
            self.retire(cancel=True)
            raise

    def retire(self, *, cancel=False) -> dict | None:
        with self._lock:
            child = self._child
            if child is None:
                return None
            if child.poll() is None:
                if not cancel:
                    return None
                child.terminate()  # Exact own Job only; never a process-name lookup.
            code = child.wait(timeout=2.0)
            child.wait_tree(timeout=2.0)
            child.close()
            self._child = None
            return dict(pid=self.identity.pid if self.identity else child.pid,
                        birth_ticks=self._birth_ticks,
                        exit_code=code, native_wait_signaled=True, owned_tree_empty=True,
                        cancellation_requested=cancel)
