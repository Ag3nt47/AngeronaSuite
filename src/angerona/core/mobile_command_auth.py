"""Protected, cumulative PIN admission for Mobile Response Bridge mutations.

Only an explicit local rearm initializes or resets this state. Cooperating
processes serialize the complete reservation/compare/completion sequence through
the existing protected-store transaction. An unresolved reservation counts as a
failed attempt, including after process termination. Store readback establishes
the observed publication, not immunity to power loss, whole-store rollback or
hostile code running inside the same OS credential/account boundary. No external
freshness witness or hardware monotonic counter is claimed here.

Keep the helper for one unchanged scope to retain its session monotonic deadline;
authorization results must never be cached. Every call rereads protected state.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from angerona.core.secure_store import (
    read_secret_values,
    secret_transaction,
    write_secret_map,
)

MOBILE_PIN_SECRET = "ANGERONA_MOBILE_PIN"
LEGACY_MOBILE_PIN_SECRET = "ANGERONA_MOBILE_PIN_DPAPI"
MOBILE_AUTH_STATE_SECRET = "ANGERONA_MOBILE_AUTH_STATE"
MOBILE_AUTH_SECRET_NAMES = (
    MOBILE_PIN_SECRET, LEGACY_MOBILE_PIN_SECRET, MOBILE_AUTH_STATE_SECRET,
)

_PIN = re.compile(r"[0-9]{6,12}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_PHONE = re.compile(r"\+[1-9][0-9]{6,14}\Z")
_SCOPE_LIMITS = {"cli": 32767, "host": 32, "dest": 32, "sha256": 64, "publisher": 512}
_STATE_FIELDS = frozenset({
    "schema", "generation", "scope_digest", "pin_tag", "failures",
    "wall_high_water_ms", "next_attempt_ms", "reservation", "held_reason",
})
_MAX_STATE_BYTES = 8192
_FAILURE_LIMIT = 10
_MAX_BACKOFF_MS = 900_000
_MAX_WALL_MS = 253_402_300_799_999
_PIN_CONTEXT = b"Angerona/mobile-command-auth/PIN-binding/v1\0"


@dataclass(frozen=True, slots=True)
class MobileCommandStatus:
    ready: bool = False
    reason: str = "authorization-state-unavailable-local-rearm-required"
    generation: str = ""
    scope_digest: str = ""
    failures: int = 0
    retry_after_s: float = 0.0
    locked: bool = False


@dataclass(frozen=True, slots=True)
class MobileCommandResult:
    authorized: bool = False
    reason: str = "authorization-state-unavailable-local-rearm-required"
    generation: str = ""
    scope_digest: str = ""
    failures: int = 0
    retry_after_s: float = 0.0


Status = MobileCommandStatus
Result = MobileCommandResult


class _Held(Exception):
    def __init__(self, reason: str, state: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.state = state


def _valid_pin(value: object) -> bool:
    return type(value) is str and _PIN.fullmatch(value) is not None


def _scope_digest(scope: dict[str, str]) -> str:
    if type(scope) is not dict or set(scope) != set(_SCOPE_LIMITS):
        raise ValueError("Mobile authorization requires one complete configured scope")
    normalized: dict[str, str] = {}
    for name, limit in _SCOPE_LIMITS.items():
        value = scope[name]
        if type(value) is not str or not value or len(value) > limit:
            raise ValueError("Mobile authorization scope contains invalid text")
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Mobile authorization scope contains invalid text")
        normalized[name] = value.casefold() if name == "sha256" else value
    if not _HEX64.fullmatch(normalized["sha256"]):
        raise ValueError("Mobile authorization requires an exact CLI digest")
    if any(not _PHONE.fullmatch(normalized[name]) for name in ("host", "dest")):
        raise ValueError("Mobile authorization requires canonical Signal phone identities")
    if normalized["host"] == normalized["dest"]:
        raise ValueError("Mobile authorization host and destination must differ")
    try:
        raw = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode("ascii")).hexdigest()
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("Mobile authorization scope cannot be encoded") from exc


def _pin_tag(pin: str, generation: str, scope_digest: str) -> str:
    message = _PIN_CONTEXT + generation.encode("ascii") + b"\0" + scope_digest.encode("ascii")
    return hmac.new(pin.encode("ascii"), message, hashlib.sha256).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate mobile authorization field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("nonfinite mobile authorization value")


def _decode_state(raw: object) -> dict:
    try:
        if type(raw) is not str or not 1 <= len(raw.encode("utf-8")) <= _MAX_STATE_BYTES:
            raise ValueError("invalid mobile authorization size")
        state = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if type(state) is not dict or set(state) != _STATE_FIELDS:
            raise ValueError("invalid mobile authorization shape")
        if type(state["schema"]) is not int or state["schema"] != 1:
            raise ValueError("unsupported mobile authorization schema")
        for name in ("generation", "scope_digest", "pin_tag"):
            if type(state[name]) is not str or not _HEX64.fullmatch(state[name]):
                raise ValueError("invalid mobile authorization identity")
        if type(state["failures"]) is not int or not 0 <= state["failures"] <= _FAILURE_LIMIT:
            raise ValueError("invalid mobile authorization budget")
        for name in ("wall_high_water_ms", "next_attempt_ms"):
            if type(state[name]) is not int or not 0 <= state[name] <= _MAX_WALL_MS:
                raise ValueError("invalid mobile authorization time")
        if state["next_attempt_ms"] > state["wall_high_water_ms"] + _MAX_BACKOFF_MS:
            raise ValueError("invalid mobile authorization deadline")
        if type(state["held_reason"]) is not str or state["held_reason"] not in {"", "clock-rollback"}:
            raise ValueError("invalid mobile authorization hold")
        reservation = state["reservation"]
        if reservation is not None:
            if type(reservation) is not dict or set(reservation) != {"id", "generation", "prior_failures"}:
                raise ValueError("invalid mobile authorization reservation")
            if type(reservation["id"]) is not str or not _HEX32.fullmatch(reservation["id"]):
                raise ValueError("invalid mobile authorization reservation identity")
            if reservation["generation"] != state["generation"]:
                raise ValueError("mobile authorization reservation changed generation")
            if (type(reservation["prior_failures"]) is not int
                    or reservation["prior_failures"] != state["failures"] - 1
                    or not 0 <= reservation["prior_failures"] < _FAILURE_LIMIT):
                raise ValueError("invalid mobile authorization reservation floor")
        return state
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise _Held("malformed-authorization-state-local-rearm-required") from exc


def read_pin(data_root: Path | None = None) -> str | None:
    """Read only a valid new-format protected PIN; this grants no authorization."""
    try:
        with secret_transaction(data_root):
            value = read_secret_values((MOBILE_PIN_SECRET,), data_root, strict=True).get(MOBILE_PIN_SECRET)
            result = value if _valid_pin(value) else None
        return result
    except Exception:
        return None


class MobileCommandAuthorization:
    def __init__(
        self,
        data_root: Path | None = None,
        *,
        scope: dict[str, str],
        clock: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
    ):
        self.data_root = data_root
        self.scope_digest = _scope_digest(scope)
        self._clock = time.time if clock is None else clock
        self._monotonic = time.monotonic if monotonic is None else monotonic
        self._lock = threading.RLock()
        self._generation = ""
        self._last_wall_ms = 0
        self._last_monotonic: float | None = None
        self._deadline = 0.0
        self._fault = ""
        self._writes_started = 0

    def read_pin(self) -> str | None:
        return read_pin(self.data_root)

    def _times(self) -> tuple[int, float]:
        wall, monotonic = self._clock(), self._monotonic()
        if (type(wall) not in (int, float) or type(monotonic) not in (int, float)
                or not math.isfinite(wall) or not math.isfinite(monotonic)
                or not 0 <= wall <= (_MAX_WALL_MS - _MAX_BACKOFF_MS) / 1000
                or not 0 <= monotonic <= 2 ** 53):
            raise _Held("clock-unavailable-local-rearm-required")
        return int(wall * 1000), float(monotonic)

    def _load(self) -> tuple[dict, str]:
        values = read_secret_values(
            (MOBILE_PIN_SECRET, MOBILE_AUTH_STATE_SECRET), self.data_root, strict=True,
        )
        if type(values) is not dict or not values.get(MOBILE_AUTH_STATE_SECRET):
            raise _Held("not-armed-local-rearm-required")
        state = _decode_state(values[MOBILE_AUTH_STATE_SECRET])
        pin = values.get(MOBILE_PIN_SECRET)
        if not _valid_pin(pin):
            raise _Held("protected-pin-unavailable-local-rearm-required", state)
        if not hmac.compare_digest(state["scope_digest"], self.scope_digest):
            raise _Held("scope-changed-local-rearm-required", state)
        if not hmac.compare_digest(state["pin_tag"], _pin_tag(pin, state["generation"], self.scope_digest)):
            raise _Held("pin-changed-local-rearm-required", state)
        return state, pin

    def _persist(self, state: dict, pin: str, *, replace_pin: bool = False) -> None:
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        _decode_state(raw)
        updates = {MOBILE_AUTH_STATE_SECRET: raw}
        if replace_pin:
            updates.update({MOBILE_PIN_SECRET: pin, LEGACY_MOBILE_PIN_SECRET: ""})
        self._writes_started += 1
        write_secret_map(updates, self.data_root)
        values = read_secret_values(
            (MOBILE_PIN_SECRET, MOBILE_AUTH_STATE_SECRET), self.data_root, strict=True,
        )
        if (type(values) is not dict or values.get(MOBILE_AUTH_STATE_SECRET) != raw
                or not _valid_pin(values.get(MOBILE_PIN_SECRET))
                or not hmac.compare_digest(values[MOBILE_PIN_SECRET], pin)):
            raise RuntimeError("Mobile authorization publication did not survive readback")

    def _status(self, reason: str, state: dict | None = None, *, ready: bool = False,
                retry: float = 0.0) -> MobileCommandStatus:
        return MobileCommandStatus(
            ready=ready, reason=reason,
            generation=state["generation"] if state is not None else "",
            scope_digest=self.scope_digest,
            failures=state["failures"] if state is not None else 0,
            retry_after_s=max(0.0, retry),
            locked=bool(state is not None and state["failures"] >= _FAILURE_LIMIT),
        )

    @staticmethod
    def _result(status: MobileCommandStatus, *, authorized: bool = False) -> MobileCommandResult:
        return MobileCommandResult(
            authorized, status.reason, status.generation, status.scope_digest,
            status.failures, status.retry_after_s,
        )

    def _evaluate(self, state: dict, pin: str) -> tuple[MobileCommandStatus, int, float]:
        if state["held_reason"]:
            raise _Held("clock-rollback-local-rearm-required", state)
        wall, monotonic = self._times()
        if self._generation != state["generation"]:
            self._generation = state["generation"]
            self._last_wall_ms = state["wall_high_water_ms"]
            self._last_monotonic = None
            self._deadline = 0.0
        if (wall < max(self._last_wall_ms, state["wall_high_water_ms"])
                or (self._last_monotonic is not None and monotonic < self._last_monotonic)):
            held = dict(state, held_reason="clock-rollback")
            self._persist(held, pin)
            raise _Held("clock-rollback-local-rearm-required", held)
        self._last_wall_ms = wall
        self._last_monotonic = monotonic
        remaining = max(0.0, (state["next_attempt_ms"] - wall) / 1000)
        self._deadline = max(self._deadline, monotonic + remaining)
        retry = max(remaining, self._deadline - monotonic, 0.0)
        if state["failures"] >= _FAILURE_LIMIT:
            return self._status("attempt-budget-exhausted-local-rearm-required", state), wall, monotonic
        if retry > 0:
            return self._status("retry-backoff", state, retry=retry), wall, monotonic
        return self._status("ready", state, ready=True), wall, monotonic

    def _unavailable(self, before_writes: int, state: dict | None, exc: Exception) -> MobileCommandStatus:
        if self._writes_started != before_writes:
            self._fault = "authorization-publication-uncertain-local-rearm-required"
        reason = self._fault or (
            "authorization-store-busy" if isinstance(exc, TimeoutError)
            else "authorization-state-unavailable-local-rearm-required"
        )
        return self._status(reason, state)

    def status(self) -> MobileCommandStatus:
        if not self._lock.acquire(timeout=1.0):
            return self._status("authorization-store-busy")
        try:
            if self._fault:
                return self._status(self._fault)
            before, state = self._writes_started, None
            try:
                with secret_transaction(self.data_root):
                    state, pin = self._load()
                    result, _wall, _monotonic = self._evaluate(state, pin)
                return result
            except _Held as held:
                return self._status(held.reason, held.state)
            except Exception as exc:
                return self._unavailable(before, state, exc)
        finally:
            self._lock.release()

    def verify_pin(self, given: str, *, expected_generation: str) -> MobileCommandResult:
        if not self._lock.acquire(timeout=1.0):
            return self._result(self._status("authorization-store-busy"))
        try:
            if self._fault:
                return self._result(self._status(self._fault))
            if type(expected_generation) is not str or not _HEX64.fullmatch(expected_generation):
                return self._result(self._status("authorization-generation-required"))
            before, state = self._writes_started, None
            try:
                with secret_transaction(self.data_root):
                    state, pin = self._load()
                    if not hmac.compare_digest(state["generation"], expected_generation):
                        result = self._result(self._status("authorization-generation-changed", state))
                    else:
                        status, wall, monotonic = self._evaluate(state, pin)
                        if not status.ready:
                            result = self._result(status)
                        else:
                            prior_deadline = self._deadline
                            delay_ms = min(_MAX_BACKOFF_MS, 5_000 * 2 ** state["failures"])
                            reservation = {
                                "id": secrets.token_hex(16), "generation": state["generation"],
                                "prior_failures": state["failures"],
                            }
                            reserved = dict(
                                state, failures=state["failures"] + 1,
                                wall_high_water_ms=wall, next_attempt_ms=wall + delay_ms,
                                reservation=reservation,
                            )
                            self._persist(reserved, pin)
                            # No PIN comparison occurs until its failure charge is read back.
                            candidate = given.encode("ascii") if _valid_pin(given) else b""
                            matched = hmac.compare_digest(candidate, pin.encode("ascii"))
                            observed, _wall, _monotonic = self._evaluate(reserved, pin)
                            if matched:
                                # Verify that only this live reservation can release its charge.
                                current, current_pin = self._load()
                                if (current != reserved or current["reservation"] != reservation
                                        or not hmac.compare_digest(current_pin, pin)):
                                    raise RuntimeError("Mobile authorization reservation changed")
                                completed = dict(
                                    state, reservation=None,
                                    wall_high_water_ms=self._last_wall_ms,
                                )
                                self._persist(completed, pin)
                                self._deadline = prior_deadline
                                result = self._result(self._status("authorized", completed), authorized=True)
                            else:
                                self._deadline = max(self._deadline, monotonic + delay_ms / 1000)
                                result = self._result(self._status(
                                    "attempt-budget-exhausted-local-rearm-required"
                                    if observed.locked else "incorrect-pin",
                                    reserved, retry=max(0.0, self._deadline - _monotonic),
                                ))
                # Transaction/lease retirement is part of admission, not a later cleanup.
                return result
            except _Held as held:
                return self._result(self._status(held.reason, held.state))
            except Exception as exc:
                return self._result(self._unavailable(before, state, exc))
        finally:
            self._lock.release()

    def rearm_local(self, pin: str, confirmation: str) -> MobileCommandStatus:
        """Explicit host action: replace the protected PIN and revoke older generations."""
        if not self._lock.acquire(timeout=1.0):
            return self._status("authorization-store-busy")
        try:
            if not _valid_pin(pin) or not _valid_pin(confirmation):
                return self._status("local-rearm-requires-6-to-12-ascii-digits")
            if not hmac.compare_digest(pin, confirmation):
                return self._status("local-rearm-pin-confirmation-mismatch")
            before, state = self._writes_started, None
            try:
                with secret_transaction(self.data_root):
                    wall, monotonic = self._times()
                    generation = secrets.token_hex(32)
                    state = {
                        "schema": 1, "generation": generation,
                        "scope_digest": self.scope_digest,
                        "pin_tag": _pin_tag(pin, generation, self.scope_digest),
                        "failures": 0, "wall_high_water_ms": wall,
                        "next_attempt_ms": 0, "reservation": None, "held_reason": "",
                    }
                    self._persist(state, pin, replace_pin=True)
                self._fault = ""
                self._generation, self._last_wall_ms = generation, wall
                self._last_monotonic, self._deadline = monotonic, 0.0
                return self._status("ready", state, ready=True)
            except _Held as held:
                return self._status(held.reason, held.state)
            except Exception as exc:
                return self._unavailable(before, state, exc)
        finally:
            self._lock.release()
