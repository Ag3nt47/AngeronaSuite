"""Bounded passive timing for the native GUI test; no authority or hot-path I/O."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
import time
from types import CodeType


class ResponseCostDiagnostic:
    STAGES = frozenset({
        "combat.handle", "combat.file_action", "combat.process_action",
        "combat.practice_binding", "combat.canary_proof", "combat.host_authority",
        "combat.current_event", "combat.owned_inventory", "combat.process_identity",
        "journal.append", "journal.append_bytes", "journal.cache_verify",
        "journal.graph_digest", "journal.commit", "anchor.read", "anchor.write",
        "anchor.advance", "witness.read", "witness.write",
        "issuer.scope", "issuer.marker_scope", "issuer.marker_identity",
        "issuer.target_identity", "issuer.policy_identity", "issuer.recorder",
        "issuer.artifact_identity", "credential.read", "credential.write",
        "credential.protect", "credential.unprotect", "native.file_pin",
        "credential.replace", "credential.file_state", "credential.security_state",
        "credential.parent_security", "credential.private_acl", "credential.native_acl",
        "credential.transaction_assert", "credential.store_identity",
        "credential.fsync", "credential.os_replace", "journal.fsync",
        "witness.fsync", "witness.replace",
        "native.file_hash", "native.file_links", "native.file_descriptor",
        "native.file_rename", "native.process_pin", "native.process_validate",
        "native.process_terminate", "native.process_wait", "native.process_proof",
    })
    PHASES = frozenset({"setup", "run1", "between", "run2", "cleanup"})
    ROLES = frozenset({"response-worker", "other-thread"})
    MAX_CALLS, MAX_ROWS, MAX_DEPTH = 250_000, 512, 64
    MAX_JSON_BYTES = 512 * 1024
    _DROP_NAMES = ("busy_enter", "busy_exit", "busy_flag", "budget", "depth",
                   "clock", "observer", "stack", "role", "flag")

    def __init__(self, *, clock=time.monotonic_ns):
        self._clock, self._lock, self._local = clock, threading.Lock(), threading.local()
        self._phase, self._role = "setup", lambda: "other-thread"
        self._rows, self._flags = {}, {}
        self._accepted = self._completed = self._filtered = 0
        self._gap = False
        self._drops = {name: 0 for name in self._DROP_NAMES}

    def _gap_at(self, reason):
        # No waiting in a producer. These best-effort counters are lower bounds
        # under contention; the sticky gap bit always withholds complete coverage.
        self._gap = True
        self._drops[reason] += 1

    def set_phase(self, phase):
        if phase not in self.PHASES:
            raise ValueError("Unknown fixed timing phase")
        self._phase = phase

    def set_response_thread(self, supplier):
        def role():
            return "response-worker" if threading.current_thread() is supplier() else "other-thread"
        self._role = role

    def _enter(self, stage, *, child_only, gate, args, kwargs):
        try:
            stack = getattr(self._local, "stack", None)
            if stack is None:
                stack = self._local.stack = []
            if (child_only and not stack) or gate is not None and gate(args, kwargs) is not True:
                self._filtered += 1
                return None
            if len(stack) >= self.MAX_DEPTH:
                self._gap_at("depth")
                return None
            role = self._role()
            if role not in self.ROLES:
                self._gap_at("role")
                return None
            started = self._clock()
            if type(started) is not int or not 0 <= started < 2**63:
                self._gap_at("clock")
                return None
            key = self._phase, role, stage
            if not self._lock.acquire(blocking=False):
                self._gap_at("busy_enter")
                return None
            try:
                if (self._accepted >= self.MAX_CALLS
                        or key not in self._rows and len(self._rows) >= self.MAX_ROWS):
                    self._gap_at("budget")
                    return None
                row = self._rows.setdefault(key, {
                    "entered": 0, "completed": 0, "raised": 0, "inflight_observations": 0,
                    "inclusive_ns": 0, "exclusive_ns": 0, "max_inclusive_ns": 0,
                    "true_returns": 0, "false_returns": 0,
                })
                row["entered"] += 1
                row["inflight_observations"] += 1
                self._accepted += 1
            finally:
                self._lock.release()
            token = [key, started, 0]
            stack.append(token)
            return token
        except Exception:
            self._gap_at("observer")
            return None

    def _actual_flag(self, token, host_code):
        cursor = None
        try:
            cursor = sys._getframe(1)
            classification = "outside_host"
            for _ in range(8):
                if cursor is None:
                    break
                if cursor.f_code is host_code:
                    flag = cursor.f_locals.get("deferred_canary")
                    classification = ("actual_true" if flag is True else
                                      "actual_false" if flag is False else "flag_unavailable")
                    break
                cursor = cursor.f_back
            else:
                classification = "frame_depth_limit"
            if not self._lock.acquire(blocking=False):
                self._gap_at("busy_flag")
                return
            try:
                key = token[0][:2]
                counts = self._flags.setdefault(key, {name: 0 for name in (
                    "actual_true", "actual_false", "flag_unavailable",
                    "outside_host", "frame_depth_limit")})
                counts[classification] += 1
            finally:
                self._lock.release()
        except Exception:
            self._gap_at("flag")
        finally:
            # Never retain a host frame, its arguments, native pins or secrets.
            del cursor

    def _finish(self, token, *, raised, result, boolean_result):
        if token is None:
            return
        try:
            finished = self._clock()
            stack = self._local.stack
            if not stack or stack[-1] is not token:
                self._gap_at("stack")
                return
            stack.pop()
            elapsed = finished - token[1]
            if type(finished) is not int or not 0 <= elapsed < 2**63:
                self._gap_at("clock")
                return
            if stack:
                stack[-1][2] += elapsed
            exclusive = elapsed - token[2]
            if exclusive < 0:
                self._gap_at("clock")
                exclusive = 0
            if not self._lock.acquire(blocking=False):
                self._gap_at("busy_exit")
                return
            try:
                row = self._rows[token[0]]
                row["completed"] += 1
                row["raised"] += int(raised)
                row["inflight_observations"] -= 1
                row["inclusive_ns"] += elapsed
                row["exclusive_ns"] += exclusive
                row["max_inclusive_ns"] = max(row["max_inclusive_ns"], elapsed)
                if boolean_result:
                    row["true_returns"] += int(result is True)
                    row["false_returns"] += int(result is False)
                self._completed += 1
            finally:
                self._lock.release()
        except Exception:
            self._gap_at("observer")

    def wrap(self, original, stage, *, child_only=False, gate=None,
             host_code=None, boolean_result=False):
        if stage not in self.STAGES or host_code is not None and type(host_code) is not CodeType:
            raise ValueError("Unknown timing stage or original host code")
        def observed(*args, **kwargs):
            token = self._enter(stage, child_only=child_only, gate=gate, args=args, kwargs=kwargs)
            if token is not None and host_code is not None:
                self._actual_flag(token, host_code)
            raised, result = False, None
            try:
                result = original(*args, **kwargs)
                return result
            except BaseException:
                raised = True
                raise
            finally:
                self._finish(token, raised=raised, result=result, boolean_result=boolean_result)
        return observed

    def wrap_scoped(self, original, scopes):
        """Time one original call only below a fixed observed parent stage.

        Selection reads bounded diagnostic tokens, never caller frames, file
        descriptors, paths, function arguments, return values or exceptions.
        The original is always called exactly once, outside observer handling.
        """
        if type(scopes) is not tuple or not 1 <= len(scopes) <= 8:
            raise ValueError("Bounded fixed timing scopes are required")
        selected = {}
        for pair in scopes:
            if (type(pair) is not tuple or len(pair) != 2
                    or type(pair[0]) is not str or type(pair[1]) is not str
                    or pair[0] not in self.STAGES or pair[1] not in self.STAGES
                    or pair[0] in selected):
                raise ValueError("Unknown or duplicate fixed timing scope")
            selected[pair[0]] = self.wrap(original, pair[1], child_only=True)

        def observed(*args, **kwargs):
            delegate = original
            try:
                stack = getattr(self._local, "stack", ())
                if len(stack) > self.MAX_DEPTH:
                    self._gap_at("depth")
                else:
                    for token in reversed(stack):
                        match = selected.get(token[0][2])
                        if match is not None:
                            delegate = match
                            break
                if delegate is original:
                    self._filtered += 1
            except Exception:
                self._gap_at("observer")
            # Do not catch a delegated original exception and then call it again.
            return delegate(*args, **kwargs)

        return observed

    def os_view(self, source, *, fsync_scopes=(), replace_scopes=()):
        """Read-through module-local view; the shared stdlib module is untouched."""
        class View:
            def __getattr__(self, name):
                return getattr(source, name)

        view = View()
        if fsync_scopes:
            view.fsync = self.wrap_scoped(source.fsync, fsync_scopes)
        if replace_scopes:
            view.replace = self.wrap_scoped(source.replace, replace_scopes)
        return view

    def snapshot(self):
        if not self._lock.acquire(blocking=False):
            return {"schema": "angerona.gui-live-response-cost.v1", "diagnostic_only": True,
                    "coverage_complete": False, "state": "snapshot-busy"}
        try:
            rows = [{"phase": phase, "role": role, "stage": stage, **values}
                    for (phase, role, stage), values in sorted(self._rows.items())]
            flags = [{"phase": phase, "role": role, **counts}
                     for (phase, role), counts in sorted(self._flags.items())]
            return {"schema": "angerona.gui-live-response-cost.v1", "diagnostic_only": True,
                "state": "bounded-passive-observations", "clock": "monotonic_ns",
                "coverage_complete": not self._gap and self._accepted == self._completed,
                "calls_accepted": self._accepted, "calls_completed": self._completed,
                "intentional_filtered_calls_lower_bound": self._filtered,
                "drop_counts_lower_bounds": dict(self._drops), "stages": rows,
                "actual_deferred_flags_at_current_guard": flags,
                "limits": {"calls": self.MAX_CALLS, "rows": self.MAX_ROWS,
                           "depth": self.MAX_DEPTH, "json_bytes": self.MAX_JSON_BYTES},
                "interpretation": (
                    "Inclusive times overlap nested stages and threads; do not sum them. "
                    "Exclusive time subtracts only observed nested stages on that thread. "
                    "Phases are assigned at entry. Flags are actual booleans from the exact original host frame, "
                    "not recomputed eligibility; host calls ending before current-event cannot be classified. "
                    "Scoped fsync/credential os.replace labels time the unchanged original call; "
                    "witness.replace includes the atomic helper's original retries, sleeps and callback. "
                    "These wall times include scheduling and do not isolate physical disk or antivirus latency. "
                    "Counters and timing grant no authority, containment or runtime-retirement proof.")}
        finally:
            self._lock.release()

    def write_after_retirement(self, path, *, producers_retired, recorder_retired):
        if producers_retired is not True or recorder_retired is not True:
            raise ValueError("Exact producer and recorder retirement is required before diagnostic output")
        result = self.snapshot()
        result["fixture_retirement_gate"] = {"producers_retired": True, "recorder_retired": True}
        raw = (json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
        if len(raw) > self.MAX_JSON_BYTES:
            raise ValueError("Timing diagnostic exceeds bounded output")
        with Path(path).open("xb") as stream:
            if stream.write(raw) != len(raw):
                raise OSError("Timing diagnostic write was incomplete")
        return True
