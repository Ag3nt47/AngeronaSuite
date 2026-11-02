"""Bounded private test observations; this helper grants no response authority."""
from __future__ import annotations

from contextlib import contextmanager
import json
import math
import threading
import time


class ResponseHoldDiagnostic:
    """Share an existing 64-row/64-KiB stream without crowding out late holds."""

    NONHOLD_ROWS = 56
    NONHOLD_BYTES = 48 * 1024
    HOLD_ROWS = 8
    HOLD_BYTES = 16 * 1024
    HOLD_ROW_BYTES = 2 * 1024

    def __init__(self, stream, *, lock=None, wall_clock=time.time):
        self._stream = stream
        self._lock = threading.Lock() if lock is None else lock
        self._wall_clock = wall_clock
        self._local = threading.local()
        self._stats = {name: 0 for name in (
            "nonhold_rows_reserved", "nonhold_bytes_reserved", "nonhold_rows_written",
            "nonhold_budget_drops", "nonhold_write_errors", "nonhold_partial_writes",
            "holds_observed", "hold_rows_reserved", "hold_bytes_reserved", "hold_rows_written",
            "hold_unavailable_drops", "hold_busy_drops", "hold_budget_drops",
            "hold_capture_errors", "hold_oversize_drops", "hold_write_errors", "hold_partial_writes",
        )}

    def nonhold_full_locked(self):
        """Called only while the fixture already holds the shared stream lock."""
        full = (self._stats["nonhold_rows_reserved"] >= self.NONHOLD_ROWS
                or self._stats["nonhold_bytes_reserved"] >= self.NONHOLD_BYTES)
        if full:
            self._stats["nonhold_budget_drops"] += 1
        return full

    def _write_locked(self, raw, *, hold):
        prefix = "hold" if hold else "nonhold"
        row_limit = self.HOLD_ROWS if hold else self.NONHOLD_ROWS
        byte_limit = self.HOLD_BYTES if hold else self.NONHOLD_BYTES
        if (self._stats[f"{prefix}_rows_reserved"] >= row_limit
                or self._stats[f"{prefix}_bytes_reserved"] + len(raw) > byte_limit):
            self._stats[f"{prefix}_budget_drops"] += 1
            return False
        # Reserve complete attempts first. Failed/partial writes never return
        # row or byte capacity, and cannot be reported as captured records.
        self._stats[f"{prefix}_rows_reserved"] += 1
        self._stats[f"{prefix}_bytes_reserved"] += len(raw)
        try:
            written = self._stream.write(raw)
        except Exception:
            self._stats[f"{prefix}_write_errors"] += 1
            return False
        if type(written) is not int or written != len(raw):
            self._stats[f"{prefix}_partial_writes"] += 1
            return False
        self._stats[f"{prefix}_rows_written"] += 1
        return True

    def write_nonhold_locked(self, raw):
        """Keep the existing fixture's payload and lock ownership unchanged."""
        return self._write_locked(raw, hold=False)

    @contextmanager
    def action_scope(self, name):
        previous = getattr(self._local, "action", None)
        self._local.action = name if name in {"_quarantine_file", "_act_on_process"} else "other"
        try:
            yield
        finally:
            self._local.action = previous

    @staticmethod
    def _identity(value, *, limit):
        if type(value) is not str:
            return None, "unavailable"
        if len(value) > limit:
            return None, "oversized"
        if not value.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in value):
            return None, "non_plain"
        return value, "cached"

    @staticmethod
    def _number(value):
        if type(value) not in (int, float):
            return None
        try:
            return value if math.isfinite(value) and -1e20 <= value <= 1e20 else None
        except (OverflowError, ValueError):
            return None

    def _hold_row(self, event, held, kwargs, *, event_type, dispatch_context):
        observed_wall = self._number(self._wall_clock())  # Once, only after the original hold.
        cached = object.__getattribute__(event, "__dict__") if type(event) is event_type else {}
        details = cached.get("details")
        details = details if type(details) is dict else {}
        signature, signature_state = self._identity(cached.get("hmac_sig"), limit=128)
        run_id, run_state = self._identity(details.get("run_id"), limit=128)
        step_id, step_state = self._identity(details.get("step_id"), limit=128)
        timestamp = self._number(cached.get("ts"))
        context = dispatch_context()
        context_tuple = type(context) is tuple and len(context) == 4
        reason = held.args[0] if len(held.args) == 1 and type(held.args[0]) is str else None
        exception_type, _state = self._identity(type(held).__name__, limit=96)
        return {
            "schema": "angerona.gui-live-response-proof-hold.v1",
            "diagnostic_only": True, "cached_only": True, "cause_established": False,
            "exception_type": exception_type,
            "reason": reason[:128] if reason is not None else None,
            "reason_truncated": reason is not None and len(reason) > 128,
            "event": {"hmac_sig": signature, "run_id": run_id, "step_id": step_id,
                      "ts": timestamp, "identity_states": {"hmac_sig": signature_state,
                                                             "run_id": run_state, "step_id": step_state}},
            "observed_after_hold_wall_time": observed_wall,
            "age_observed_after_hold_seconds": (
                observed_wall - timestamp if observed_wall is not None and timestamp is not None else None
            ),
            "age_is_original_guard_sample": False,
            "phase_facts": {
                "admission": kwargs.get("admission") is True,
                "outer_action_scope": getattr(self._local, "action", None),
                "action_argument_present": kwargs.get("action") is not None,
                "pinned_argument_present": kwargs.get("pinned") is not None,
                "retained_dispatch_context_present": context_tuple,
                "retained_context_event_is_argument": context_tuple and context[0] is event,
            },
        }

    def _record_hold(self, event, held, kwargs, *, event_type, dispatch_context):
        self._stats["holds_observed"] += 1
        if self._stream is None:
            self._stats["hold_unavailable_drops"] += 1
            return
        if not self._lock.acquire(blocking=False):
            self._stats["hold_busy_drops"] += 1
            return
        try:
            if (self._stats["hold_rows_reserved"] >= self.HOLD_ROWS
                    or self._stats["hold_bytes_reserved"] >= self.HOLD_BYTES):
                self._stats["hold_budget_drops"] += 1
                return
            row = self._hold_row(event, held, kwargs, event_type=event_type,
                                 dispatch_context=dispatch_context)
            raw = (json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
            if len(raw) > self.HOLD_ROW_BYTES:
                self._stats["hold_oversize_drops"] += 1
                return
            self._write_locked(raw, hold=True)
        finally:
            self._lock.release()

    def wrap_guard(self, original, *, hold_type, event_type, dispatch_context):
        def observed(*args, **kwargs):
            try:
                return original(*args, **kwargs)
            except hold_type as held:
                try:
                    event = args[0] if args else kwargs.get("event")
                    self._record_hold(event, held, kwargs, event_type=event_type,
                                      dispatch_context=dispatch_context)
                except Exception:
                    self._stats["hold_capture_errors"] += 1
                raise
        return observed

    def coverage(self):
        """A bounded cached summary remains available after stream exhaustion."""
        result = {
            "schema": "angerona.gui-live-response-proof-coverage.v1",
            "diagnostic_only": True, "cached_only": True,
            "limits": {"rows": 64, "bytes": 64 * 1024, "hold_rows": self.HOLD_ROWS,
                       "hold_bytes": self.HOLD_BYTES},
            "state": "busy_or_unavailable", "hold_coverage_complete": False,
        }
        try:
            if not self._lock.acquire(blocking=False):
                return result
            try:
                result.update(self._stats)
                observed, written = self._stats["holds_observed"], self._stats["hold_rows_written"]
                result["state"] = "none_observed" if observed == 0 else "cached_observations"
                result["hold_coverage_complete"] = observed > 0 and observed == written
            finally:
                self._lock.release()
        except Exception:
            pass
        return result
