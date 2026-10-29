"""Bounded advisory progress for the pinned scanner's owned worker.

The engine and its reports retain their existing integrity/authority boundary.
This module observes selected reader calls and file reads; it cannot authorize
a response or turn unavailable collection into completed coverage.
"""
from __future__ import annotations

import copy
import json
import math
import os
from pathlib import Path
import re
import threading
import time

MAX_PROGRESS_BYTES = 48 * 1024
MAX_STEPS = 32
MAX_RUN_SECONDS = 4 * 60 * 60
MAX_PROGRESS_ELAPSED_SECONDS = 24 * 60 * 60
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_UUID = re.compile(r"[0-9a-f]{32}")
_STATES = {"queued", "running", "completed", "incomplete", "cancelled", "timed-out", "failed", "skipped"}
_SNAPSHOT_FIELDS = {"schema", "operation_id", "job_id", "nonce", "birth", "sequence", "state",
                    "elapsed_s", "timeout_seconds", "remaining_budget_s", "current_step", "current_task",
                    "current_file", "steps", "completed_steps", "total_steps", "overall_percent",
                    "remaining_s", "estimate_basis", "item_completed", "item_total", "item_percent",
                    "item_unit", "item_remaining_s"}
_STEP_FIELDS = {"id", "label", "state", "completed", "total", "unit", "percent", "checked",
                "skipped", "elapsed_s", "remaining_s"}
_LABELS = {
    "browser": "Browser and application traces", "hash": "File fingerprints",
    "host": "Host configuration and DNS", "traces": "Windows activity traces",
    "windows-execution": "Windows execution records", "unix-host": "Unix host configuration",
    "android-intrusion": "Android intrusion records", "android": "Android collection",
    "ios": "iPhone evidence", "patterns": "Optional pattern checks",
}


def _text(value, maximum=4096):
    if type(value) is not str:
        return ""
    return "".join(c if 32 <= ord(c) and not 127 <= ord(c) <= 159
                   and c not in "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
                   else "\ufffd" for c in value[:maximum])


def _number(value, maximum=10**12):
    return type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value)


def validate_snapshot(raw, *, job_id, nonce, birth, operation_id, previous_sequence=0):
    """Reject foreign, malformed, stale or oversized publications; no I/O."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_PROGRESS_BYTES:
        raise ValueError("Scanner progress exceeds its byte bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate scanner progress field")
            result[key] = value
        return result
    try:
        document = json.loads(raw, object_pairs_hook=unique,
                              parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("Non-finite progress")))
    except (RecursionError, OverflowError) as error:
        raise ValueError("Malformed scanner progress nesting/number") from error
    if (type(document) is not dict or type(document.get("schema")) is not int or document.get("schema") != 1
            or not set(document) <= _SNAPSHOT_FIELDS
            or document.get("job_id") != job_id or document.get("nonce") != nonce
            or document.get("birth") != birth or document.get("operation_id") != operation_id
            or not _UUID.fullmatch(str(operation_id))
            or type(document.get("sequence")) is not int
            or not previous_sequence < document["sequence"] <= 10**9
            or document.get("state") not in _STATES):
        raise ValueError("Scanner progress does not match its owned generation")
    for name in ("elapsed_s", "timeout_seconds", "remaining_budget_s"):
        ceiling = MAX_PROGRESS_ELAPSED_SECONDS if name == "elapsed_s" else MAX_RUN_SECONDS
        if not _number(document.get(name), ceiling):
            raise ValueError("Invalid scanner progress timing")
    for name, limit in (("current_step", 64), ("current_task", 1000), ("current_file", 4096), ("estimate_basis", 300)):
        if type(document.get(name)) is not str or len(document[name]) > limit:
            raise ValueError("Invalid scanner progress text")
    steps = document.get("steps")
    if type(steps) is not list or len(steps) > MAX_STEPS:
        raise ValueError("Invalid scanner progress plan")
    identifiers = set()
    for row in steps:
        if (type(row) is not dict or type(row.get("id")) is not str
                or not set(row) <= _STEP_FIELDS
                or not _ID.fullmatch(row["id"]) or row["id"] in identifiers
                or row.get("state") not in _STATES
                or type(row.get("label")) is not str or len(row["label"]) > 200
                or type(row.get("unit")) is not str or len(row["unit"]) > 60):
            raise ValueError("Invalid scanner progress step")
        identifiers.add(row["id"])
        for name in ("completed", "checked", "skipped"):
            if type(row.get(name)) is not int or not 0 <= row[name] <= 10**12:
                raise ValueError("Invalid scanner progress counter")
        if row.get("total") is not None and (type(row["total"]) is not int or not row["completed"] <= row["total"] <= 10**12):
            raise ValueError("Invalid scanner progress denominator")
        for name, ceiling in (("percent", 100), ("remaining_s", 10**9)):
            if row.get(name) is not None and not _number(row[name], ceiling):
                raise ValueError("Invalid scanner progress estimate")
        if row.get("percent") is not None:
            total = row.get("total")
            if total is None or total <= 0 or abs(row["percent"] - 100 * row["completed"] / total) > .11:
                raise ValueError("Scanner percentage lacks a measured denominator")
        if not _number(row.get("elapsed_s"), MAX_PROGRESS_ELAPSED_SECONDS):
            raise ValueError("Invalid scanner step duration")
    if (type(document.get("completed_steps")) is not int or type(document.get("total_steps")) is not int
            or document.get("total_steps") != len(steps)
            or document["completed_steps"] != sum(row["state"] in {"completed", "incomplete", "skipped", "failed"} for row in steps)):
        raise ValueError("Invalid scanner progress rollup")
    if document["current_step"] and document["current_step"] not in identifiers:
        raise ValueError("Scanner current step is outside its selected plan")
    for name, ceiling in (("overall_percent", 100), ("remaining_s", 10**9),
                          ("item_percent", 100), ("item_remaining_s", 10**9),
                          ("item_completed", 10**12), ("item_total", 10**12)):
        if document.get(name) is not None and not _number(document[name], ceiling):
            raise ValueError("Invalid scanner item/overall estimate")
    if type(document.get("item_unit", "")) is not str or len(document.get("item_unit", "")) > 60:
        raise ValueError("Invalid scanner item unit")
    completed, total, percent = (document.get(name) for name in ("item_completed", "item_total", "item_percent"))
    if completed is not None and type(completed) is not int:
        raise ValueError("Scanner item count must be an integer")
    if total is not None and (type(total) is not int or completed is None or completed > total):
        raise ValueError("Scanner item denominator is inconsistent")
    if percent is not None and (not total or completed is None or abs(percent - 100 * completed / total) > .11):
        raise ValueError("Scanner item percentage lacks its counted denominator")
    fraction = sum((row["percent"] or 0) / 100 if row["state"] == "running" else
                   1 if row["state"] in {"completed", "incomplete", "skipped", "failed"} else 0 for row in steps)
    expected = round(100 * fraction / len(steps), 1) if steps else None
    if expected is not None and document["state"] == "running":
        expected = min(99, expected)
    if document.get("overall_percent") != expected:
        raise ValueError("Scanner overall progress does not match its steps")
    # The launch nonce never enters the GUI's copied presentation state.
    result = {key: value for key, value in document.items() if key not in {"nonce", "birth"}}
    for name, maximum in (("current_task", 1000), ("current_file", 4096)):
        result[name] = _text(result[name], maximum)
    return copy.deepcopy(result)


class ScannerProgress:
    """Observe pinned reader calls; unknown work totals remain unknown."""
    def __init__(self, document, job, birth, writer, *, clock=time.monotonic):
        self.document, self.job, self.birth, self.writer = document, Path(job), birth, writer
        self.clock, self.started = clock, clock()
        self.timeout = float(document["limits"].get("runtime_seconds", document["limits"].get("cpu_seconds", 300)))
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.sequence = 0
        self.state, self.current_step, self.current_task, self.current_file = "running", "", "Preparing supported checks", ""
        self.steps, self.ctx, self.step_started = [], None, None
        self.item_completed = self.item_total = self.item_percent = None
        self.item_remaining_s = None
        self.item_unit = ""
        self._file_token, self._thread = 0, None
        self._last_publication = -1.0

    def start(self):
        self.publish(force=True)
        self._thread = threading.Thread(target=self._sample, name="Angerona scanner progress", daemon=True)
        self._thread.start()

    def _sample(self):
        while not self.stopped.wait(.5):
            self.publish()

    def publish(self, *, force=False):
        with self.lock:
            now = self.clock()
            if not force and now - self._last_publication < .45:
                return
            self._last_publication = now
            self.sequence += 1
            for row in self.steps:
                if row["state"] == "running" and self.step_started is not None:
                    row["elapsed_s"] = round(max(0, now - self.step_started), 3)
                    partial = getattr(self.ctx, "partial", None)
                    if getattr(partial, "name", None) == row["id"]:
                        for name in ("checked", "skipped"):
                            value = getattr(partial, name, 0)
                            if type(value) is int and 0 <= value <= 10**12:
                                row[name] = value
            finished = sum(row["state"] in {"completed", "incomplete", "skipped", "failed"} for row in self.steps)
            fraction = sum((row["percent"] or 0) / 100 if row["state"] == "running" else
                           1 if row["state"] in {"completed", "incomplete", "skipped", "failed"} else 0 for row in self.steps)
            percent = round(100 * fraction / len(self.steps), 1) if self.steps else None
            if percent is not None and self.state == "running":
                percent = min(99, percent)
            remaining = None
            active = next((row for row in self.steps if row["state"] == "running"), None)
            if active and active.get("remaining_s") is not None and all(row["state"] != "queued" for row in self.steps):
                remaining = active["remaining_s"]
            snapshot = dict(schema=1, operation_id=self.document["operation_id"], job_id=self.job.name,
                            nonce=self.document["nonce"], birth=self.birth, sequence=self.sequence,
                            state=self.state, elapsed_s=round(max(0, now - self.started), 3),
                            timeout_seconds=self.timeout, remaining_budget_s=round(max(0, self.timeout - (now - self.started)), 3),
                            current_step=self.current_step, current_task=_text(self.current_task, 1000),
                            current_file=_text(self.current_file), steps=copy.deepcopy(self.steps),
                            completed_steps=finished, total_steps=len(self.steps), overall_percent=percent,
                            remaining_s=remaining, estimate_basis="Measured completed units and current pace" if remaining is not None else "Calculating; remaining work has no measured denominator",
                            item_completed=self.item_completed, item_total=self.item_total,
                            item_percent=self.item_percent, item_unit=self.item_unit,
                            item_remaining_s=self.item_remaining_s)
        try:
            raw = json.dumps(snapshot, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
            if len(raw) <= MAX_PROGRESS_BYTES:
                self.writer(raw)
        except (OSError, ValueError):
            # Optional telemetry failure never interrupts evidence collection.
            pass

    def observe_file(self, path, size=None):
        with self.lock:
            if not self.current_step or isinstance(path, int):
                return None
            try:
                selected = Path(os.path.abspath(os.fspath(path)))
            except (TypeError, ValueError, OSError):
                return None
            if selected.is_relative_to(self.job):
                return None
            self._file_token += 1
            self.current_file = str(selected)
            self.current_task = "Reading evidence file"
            self.item_completed, self.item_total, self.item_percent = (0, size, 0.0) if type(size) is int and size > 0 else (None, None, None)
            self.item_unit = "bytes read" if size else ""
            self.item_remaining_s = None
            return self._file_token

    def read_position(self, token, position):
        with self.lock:
            if token != self._file_token or not _number(position) or not self.item_total:
                return
            self.item_completed = min(self.item_total, int(position))
            self.item_percent = round(100 * self.item_completed / self.item_total, 1)

    def install(self, namespace):
        original_run = namespace["reader_run"]
        selected = namespace["reader_select"]
        original_report = namespace.get("finalize_report")
        def run(ctx, resolver=None):
            plan = selected(ctx)
            if len(plan) + int(callable(original_report)) > MAX_STEPS or any(not _ID.fullmatch(spec.name) for spec in plan):
                raise ValueError("Pinned scanner reader plan exceeded its managed bounds")
            with self.lock:
                self.ctx = ctx
                self.steps = [dict(id=spec.name, label=_LABELS.get(spec.name, spec.name), state="queued",
                                   completed=0, total=None, unit="checks", percent=None, checked=0, skipped=0,
                                   elapsed_s=0.0, remaining_s=None) for spec in plan]
                if callable(original_report):
                    self.steps.append(dict(id="report", label="Writing scanner reports", state="queued", completed=0,
                                           total=1, unit="report task", percent=0.0, checked=0, skipped=0,
                                           elapsed_s=0.0, remaining_s=None))
            self.publish(force=True)
            base_resolver = resolver or namespace["reader_resolve"]
            def resolve(spec):
                callback = base_resolver(spec)
                def check(current):
                    row = next(item for item in self.steps if item["id"] == spec.name)
                    with self.lock:
                        self.current_step, self.current_task = spec.name, "Checking " + row["label"].lower()
                        self.current_file = ""
                        self.step_started = self.clock()
                        row["state"] = "running"
                    self.publish(force=True)
                    try:
                        result = callback(current)
                    except BaseException:
                        with self.lock:
                            row["state"] = "incomplete"
                        raise
                    with self.lock:
                        row.update(state="incomplete" if getattr(result, "skipped", 0) or any(not getattr(c, "ran", False) for c in getattr(result, "checks", ())) else "completed",
                                   completed=1, total=1, unit="reader", percent=100.0,
                                   checked=max(0, int(getattr(result, "checked", 0))),
                                   skipped=max(0, int(getattr(result, "skipped", 0))),
                                   elapsed_s=round(max(0, self.clock() - self.step_started), 3), remaining_s=0.0)
                    self.publish(force=True)
                    return result
                return check
            return original_run(ctx, resolve)
        namespace["reader_run"] = run

        if callable(original_report):
            def report(*args, **kwargs):
                row = next((row for row in self.steps if row["id"] == "report"), None)
                if row is None:
                    return original_report(*args, **kwargs)
                with self.lock:
                    self.current_step, self.current_task = "report", "Writing private scanner reports"
                    self.current_file, self.step_started = str(self.job / "report.json"), self.clock()
                    self.item_completed = self.item_total = self.item_percent = self.item_remaining_s = None
                    self.item_unit, row["state"] = "", "running"
                self.publish(force=True)
                try:
                    code = original_report(*args, **kwargs)
                except BaseException:
                    with self.lock:
                        row["state"] = "incomplete"
                    raise
                with self.lock:
                    row.update(state="completed" if code in {0, 2, 3} else "incomplete", completed=1,
                               percent=100.0, elapsed_s=round(max(0, self.clock() - self.step_started), 3), remaining_s=0.0)
                self.publish(force=True)
                return code
            namespace["finalize_report"] = report

        if callable(namespace.get("open_evidence_db")):
            original_db = namespace["open_evidence_db"]
            def database(path, *args, **kwargs):
                self.observe_file(path)
                with self.lock:
                    self.current_task = "Reading a supported evidence database"
                connection = original_db(path, *args, **kwargs)
                return ObservedConnection(connection, self) if self.current_step == "browser" else connection
            namespace["open_evidence_db"] = database
        indicator_type = namespace.get("IocSet")
        if indicator_type is not None:
            for method_name in ("search", "search_bytes"):
                original = getattr(indicator_type, method_name, None)
                if callable(original):
                    def matching(indicators, value, _original=original):
                        with self.lock:
                            if self.current_step:
                                self.current_task = "Matching indicators in the current artifact"
                        return _original(indicators, value)
                    setattr(indicator_type, method_name, matching)
        if callable(namespace.get("_hash_outcomes")):
            original_hashes = namespace["_hash_outcomes"]
            def hashes(candidates, ctx):
                total, finished, began = len(candidates), 0, self.clock()
                for result in original_hashes(candidates, ctx):
                    finished += 1
                    with self.lock:
                        self._file_token += 1
                        self.current_file, self.current_task = str(result[0]), "Comparing file fingerprints"
                        self.item_completed, self.item_total = finished, total
                        self.item_unit = "current batch files"
                        self.item_remaining_s = round((self.clock() - began) * (total - finished) / finished, 1) if finished and self.clock() - began >= .5 else None
                        self.item_percent = round(100 * finished / total, 1) if total else None
                        row = next((row for row in self.steps if row["id"] == "hash"), None)
                        if row is not None and len(ctx.targets) == 1:
                            row.update(completed=finished, total=total, unit="candidate files", percent=self.item_percent)
                            row["remaining_s"] = round((self.clock() - began) * (total - finished) / finished, 1) if finished and self.clock() - began >= .5 else None
                    yield result
            namespace["_hash_outcomes"] = hashes

    def finish(self, state):
        self.stopped.set()
        if self._thread is not None:
            self._thread.join(2)
            if self._thread.is_alive():
                raise RuntimeError("Scanner telemetry thread did not retire")
        with self.lock:
            self.state = state
            for row in self.steps:
                if row["state"] == "running":
                    row["state"] = "incomplete" if state == "completed" else state
                elif row["state"] == "queued" and getattr(self.ctx, "quick", False) and row["id"] == "hash":
                    row.update(state="skipped", completed=1, total=1, unit="reader", percent=100.0)
            self.current_task = "Scan ended; review findings and coverage" if state == "completed" else "Scan stopped; partial coverage is preserved"
        self.publish(force=True)


class ObservedReader:
    """Report bytes actually read from the current binary evidence file."""
    def __init__(self, real, observer, path, *, binary=False):
        self.real, self.observer = real, observer
        self.binary, self.sequential, self.completed = binary, True, 0
        size = None
        if binary:
            try:
                size = os.fstat(real.fileno()).st_size
            except (OSError, AttributeError):
                pass
        self.token = observer.observe_file(path, size)

    def __getattr__(self, name):
        return getattr(self.real, name)

    def read(self, *args):
        try:
            before = self.real.tell()
        except (OSError, AttributeError):
            before = None
        value = self.real.read(*args)
        if self.binary and type(value) is bytes:
            self.sequential = self.sequential and before == self.completed
            self.completed += len(value)
            if self.sequential:
                self.observer.read_position(self.token, self.completed)
            else:
                with self.observer.lock:
                    if self.token == self.observer._file_token:
                        self.observer.item_completed = self.completed
                        self.observer.item_total = self.observer.item_percent = self.observer.item_remaining_s = None
                        self.observer.item_unit = "file bytes accessed; non-sequential"
        return value

    def __iter__(self):
        return iter(self.real)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.real.__exit__(*args)


class ObservedRows:
    """Count existing fetched rows as consumed; issue no additional SQL."""
    def __init__(self, rows, observer):
        self.rows, self.observer = rows, observer

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, index):
        return self.rows[index]

    def __iter__(self):
        token = _begin_rows(self.observer, len(self.rows))
        began = self.observer.clock()
        for number, row in enumerate(self.rows, 1):
            yield row
            _rows_visited(self.observer, token, number, len(self.rows), began)


def _begin_rows(observer, total):
    with observer.lock:
        observer._file_token += 1
        observer.current_task = "Comparing supported browser database records"
        observer.item_completed, observer.item_total = 0, total
        observer.item_percent = 0.0 if total else None
        observer.item_remaining_s = None
        observer.item_unit = "database rows processed"
        return observer._file_token


def _rows_visited(observer, token, completed, total, began):
    with observer.lock:
        if token != observer._file_token:
            return
        observer.item_completed = completed
        observer.item_percent = round(100 * completed / total, 1) if total else None
        elapsed = observer.clock() - began
        observer.item_remaining_s = round(elapsed * (total - completed) / completed, 1) if total and completed >= 3 and elapsed >= .5 else None


class ObservedCursor:
    def __init__(self, real, observer):
        self.real, self.observer = real, observer

    def __getattr__(self, name):
        return getattr(self.real, name)

    def fetchall(self):
        return ObservedRows(self.real.fetchall(), self.observer)

    def __iter__(self):
        token = _begin_rows(self.observer, None)
        began = self.observer.clock()
        for number, row in enumerate(self.real, 1):
            yield row
            _rows_visited(self.observer, token, number, None, began)


class ObservedConnection:
    def __init__(self, real, observer):
        object.__setattr__(self, "real", real)
        object.__setattr__(self, "observer", observer)

    def __getattr__(self, name):
        return getattr(self.real, name)

    def __setattr__(self, name, value):
        setattr(self.real, name, value)

    def execute(self, query, *args, **kwargs):
        cursor = self.real.execute(query, *args, **kwargs)
        # Observe only queries the pinned reader already executes. In
        # particular do not COUNT, interpolate table names, change handlers,
        # materialize streamed results or widen evidence collection.
        if type(query) is str and query.lstrip().upper().startswith("SELECT "):
            return ObservedCursor(cursor, self.observer)
        return cursor
