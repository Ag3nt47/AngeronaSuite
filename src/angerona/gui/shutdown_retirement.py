"""Nonblocking custody of exact GUI workers during an operator STOP.

No process discovery, PID selection, thread termination or arbitrary join. A
bounded fallback is explicitly incomplete and skips Qt object teardown while
native QThreads may still be running.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import re
import stat
import threading
import time

from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThread, QTimer
from shiboken6 import isValid


MAX_RETAINED_WORKERS = 256
MAX_RETAINED_CUSTODY = 16


@dataclass(frozen=True)
class RetainedWorker:
    label: str
    worker: object
    before_cleanup: bool = False
    retirement_proof: object = None


@dataclass(frozen=True)
class RetainedCustody:
    """Exact owner and memory-only predicate, separate from worker existence."""
    label: str
    owner: object
    released: object


def worker_retired(worker):
    """Inspect exact native/Python worker custody, never cosmetic busy flags."""
    if isinstance(worker, threading.Thread):
        return not worker.is_alive()
    if isinstance(worker, QThread):
        # wait(0) is a nonblocking native retirement poll. A shadowed custom
        # finished signal or early result cannot stand in for OS-thread exit.
        return bool(isValid(worker) and worker.isFinished() and not worker.isRunning() and worker.wait(0))
    raise TypeError("An exact retained Python Thread or native QThread is required")


def write_shutdown_diagnostic(root, payload):
    """One bounded private atomic projection; original action journals remain."""
    directory = Path(root) / "diagnostics"
    for path in (*reversed(directory.parents), directory):
        if os.path.lexists(path):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Shutdown diagnostic directory is redirected")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "operator-stop.json"
    if os.path.lexists(target):
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Shutdown diagnostic destination is not ordinary")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > 64 * 1024:
        raise ValueError("Shutdown diagnostic exceeds its budget")
    temporary = directory / (".operator-stop." + secrets.token_hex(12) + ".tmp")
    created = False
    try:
        with temporary.open("xb") as stream:
            created = True
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        created = False
    finally:
        if created:
            temporary.unlink(missing_ok=True)



def _activation_binding(value):
    """Detach only exact launch/request identity; this grants no STOP proof."""
    if value is None:
        return None
    keys = {"launch_id", "activation_id", "request_sha256", "core_pid", "core_birth"}
    if type(value) is not dict or set(value) != keys:
        raise ValueError("Source activation STOP binding is outside its closed schema")
    for key, length in (("launch_id", 32), ("activation_id", 32), ("request_sha256", 64)):
        if type(value[key]) is not str or re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value[key]) is None:
            raise ValueError("Source activation STOP digest binding is invalid")
    if (type(value["core_pid"]) is not int or not 0 < value["core_pid"] <= 0xffffffff
            or type(value["core_birth"]) is not str
            or re.fullmatch(r"[1-9][0-9]{0,19}", value["core_birth"]) is None
            or int(value["core_birth"]) > 0xffffffffffffffff):
        raise ValueError("Source activation STOP native generation is invalid")
    return tuple((key, value[key]) for key in sorted(keys))

class ShutdownRetirement(QObject):
    """Let admitted mutations settle before stores close; then drain readers."""

    def __init__(self, owner, *, workers, cleanup, finish, data_root,
                 timeout=30.0, diagnostic_timeout=2.0, clock=time.monotonic,
                 diagnostic_writer=write_shutdown_diagnostic, status=None, critical=None,
                 custody=None, activation_binding=None):
        super().__init__(owner)
        self._activation_binding = _activation_binding(activation_binding)
        self._workers, self._cleanup, self._finish = workers, cleanup, finish
        self._root, self._clock, self._writer = Path(data_root), clock, diagnostic_writer
        self._timeout = max(.05, min(float(timeout), 60.0))
        self._diagnostic_timeout = max(.05, min(float(diagnostic_timeout), 3.0))
        self._status = status
        self._critical = critical
        self._retained = {}
        self._custody, self._retained_custody = custody, {}
        self._native_proven = set()
        self._deferred_native_delete = {}
        self._deferred_delete_posted = set()
        self._deferred_delete_holds = {}
        self._cleanup_thread = None
        self._cleanup_error = ""
        self._discovery_error = ""
        self._started = False
        self._done = False
        self._final = None
        self._diagnostic_thread = None
        self._diagnostic_error = ""
        self._diagnostic_written = None
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self.poll)

    def start(self):
        if self._started:
            return False
        self._started = True
        self._deadline = self._clock() + self._timeout
        self._collect()
        if self._critical is not None:
            def critical():
                try:
                    self._critical()
                except Exception as exc:
                    self._cleanup_error = type(exc).__name__
            thread = threading.Thread(target=critical, name="OperatorStopCritical", daemon=True)
            self._retained[id(thread)] = RetainedWorker("owned-companion-and-AI-cleanup", thread, True)
            try:
                thread.start()
            except Exception as exc:
                self._cleanup_error = type(exc).__name__
        self._write_async(self._payload("stopping"))
        self._timer.start()
        self.poll()
        return True

    def _collect(self):
        try:
            rows = self._workers()
            for index, row in enumerate(rows):
                if index >= MAX_RETAINED_WORKERS or type(row) is not RetainedWorker:
                    raise ValueError("Worker discovery is outside its bounded contract")
                identity = id(row.worker)
                previous = self._retained.get(identity)
                if previous is None:
                    if len(self._retained) >= MAX_RETAINED_WORKERS:
                        raise ValueError("Worker custody admission is full")
                    # Keep a strong reference even if a UI result handler drops
                    # its old attribute before the actual thread exits.
                    self._retained[identity] = row
                    if isinstance(row.worker, QThread) and isValid(row.worker):
                        if row.worker.thread() != self.thread():
                            raise ValueError("Native worker QObject affinity is outside the GUI retirement owner")
                        row.worker.installEventFilter(self)
                elif row.before_cleanup and not previous.before_cleanup:
                    self._retained[identity] = RetainedWorker(previous.label, previous.worker, True,
                        row.retirement_proof or previous.retirement_proof)
                elif row.retirement_proof is not None and previous.retirement_proof is None:
                    self._retained[identity] = RetainedWorker(previous.label, previous.worker,
                        previous.before_cleanup, row.retirement_proof)
        except Exception as exc:
            self._discovery_error = type(exc).__name__
        if self._custody is not None:
            try:
                for index, hold in enumerate(self._custody()):
                    if (index >= MAX_RETAINED_CUSTODY or type(hold) is not RetainedCustody
                            or not callable(hold.released)):
                        raise ValueError("Custody discovery is outside its bounded contract")
                    identity = id(hold.owner)
                    if identity not in self._retained_custody:
                        if len(self._retained_custody) >= MAX_RETAINED_CUSTODY:
                            raise ValueError("Exact owner custody admission is full")
                        self._retained_custody[identity] = hold
            except Exception as exc:
                self._discovery_error = type(exc).__name__

    def _pending_custody(self):
        pending = []
        for hold in self._retained_custody.values():
            try:
                released = hold.released() is True
            except Exception:
                released = False
            if not released:
                pending.append(hold)
        return pending

    def _pending(self):
        pending = []
        for row in self._retained.values():
            identity = id(row.worker)
            try:
                retired = self._retirement_proven(row)
            except Exception:
                retired = False
            if retired and isinstance(row.worker, QThread):
                self._native_proven.add(identity)
                if isValid(row.worker):
                    event = self._deferred_native_delete.get(identity)
                    if event is not None and identity not in self._deferred_delete_posted:
                        self._deferred_native_delete.pop(identity)
                        # Qt debounces deleteLater forever after the first post.
                        # Replay its actual native clone, preserving loop/scope
                        # payload. Keep the filter until delivery rechecks proof.
                        self._deferred_delete_posted.add(identity)
                        try:
                            QCoreApplication.postEvent(row.worker, event)
                        except BaseException:
                            # Ownership transfer may have happened; never retry.
                            self._deferred_delete_holds[identity] = (row.worker, event)
                            self._discovery_error = "DeferredDeleteReplayError"
            if not retired:
                pending.append(row)
        return pending

    def _has_native_proof(self, worker):
        identity = id(worker)
        if identity not in self._native_proven:
            return False
        if isValid(worker) and not worker_retired(worker):
            # A restarted live QThread is a new native generation even if its
            # Python wrapper identity was retained. Never reuse its old proof.
            self._native_proven.discard(identity)
            worker.installEventFilter(self)
            return False
        return True

    def _retirement_proven(self, row):
        worker = row.worker
        if isinstance(worker, QThread) and isValid(worker) and (worker.isRunning() or not worker.isFinished()):
            self._native_proven.discard(id(worker))
            return False  # Never-started is not completed; no guessed witness.
        if row.retirement_proof is not None:
            # Only a known producer's exact-object proof API is supplied by
            # MainWindow. It must record native retirement before removal or
            # deletion. A bare invalid wrapper is never that evidence.
            if (isValid(worker) and not worker_retired(worker)) or not callable(row.retirement_proof) or row.retirement_proof(worker) is not True:
                return False
            self._native_proven.add(id(worker))
            return True
        return self._has_native_proof(worker) or worker_retired(worker)

    def eventFilter(self, watched, event):  # noqa: N802 - Qt callback
        if event.type() == QEvent.Type.DeferredDelete and isinstance(watched, QThread):
            identity = id(watched)
            if identity in self._retained:
                try:
                    retired = self._retirement_proven(self._retained[identity])
                except Exception:
                    retired = False
                if retired:
                    self._native_proven.add(identity)
                    self._deferred_native_delete.pop(identity, None)
                    watched.removeEventFilter(self)
                    return False
                # Preserve one actual native event, not a generic fabricated
                # DeferredDelete (Qt requires its private loop/scope payload).
                if identity not in self._deferred_native_delete:
                    try:
                        retained = event.clone()
                        if retained is event or retained.type() != QEvent.Type.DeferredDelete:
                            raise ValueError("Native deferred-delete clone is invalid")
                        self._deferred_native_delete[identity] = retained
                    except BaseException:
                        self._discovery_error = "DeferredDeleteCloneError"
                if identity in self._deferred_delete_posted:
                    # A new live generation cannot consume a prior replay/proof.
                    self._discovery_error = "DeferredDeleteGenerationChanged"
                return True
        return super().eventFilter(watched, event)

    def _payload(self, state):
        pending = self._pending()
        custody = self._pending_custody()
        payload = {"schema": 1, "state": state, "operator_stop_recorded": True,
            "pending_workers": [str(row.label)[:80] for row in pending],
            "pending_custody": [str(row.label)[:80] for row in custody],
            "before_cleanup_pending": sum(row.before_cleanup for row in pending) + len(custody),
            "tracked_workers": len(self._retained), "cleanup_error": self._cleanup_error,
            "discovery_error": self._discovery_error,
            "scope": "Exact GUI workers and explicit memory-only owner custody; companion retirement remains in its existing owner",
            "forced": state == "forced-incomplete", "epoch": int(time.time())}
        if self._activation_binding is not None:
            payload["source_activation"] = dict(self._activation_binding)
        return payload

    def _write_async(self, payload):
        if self._diagnostic_thread is not None and self._diagnostic_thread.is_alive():
            return False
        detached = json.loads(json.dumps(payload, allow_nan=False))
        def write():
            try:
                self._writer(self._root, detached)
                self._diagnostic_written = detached["state"]
            except Exception as exc:
                self._diagnostic_error = type(exc).__name__
        self._diagnostic_thread = threading.Thread(target=write, name="OperatorStopDiagnostic", daemon=True)
        try:
            self._diagnostic_thread.start()
        except Exception as exc:
            self._diagnostic_error = type(exc).__name__
        return True

    def _begin_cleanup(self):
        def cleanup():
            try:
                self._cleanup()
            except Exception as exc:
                self._cleanup_error = type(exc).__name__
        self._cleanup_thread = threading.Thread(target=cleanup, name="OperatorStopCleanup", daemon=True)
        self._retained[id(self._cleanup_thread)] = RetainedWorker("owned-runtime-cleanup", self._cleanup_thread)
        try:
            self._cleanup_thread.start()
        except Exception as exc:
            self._cleanup_error = type(exc).__name__

    def poll(self):
        if not self._started or self._done:
            return
        self._collect()
        pending = self._pending()
        custody = self._pending_custody()
        if self._final is None:
            if (self._cleanup_thread is None and not custody
                    and not any(row.before_cleanup for row in pending) and not self._discovery_error):
                self._begin_cleanup()
                pending = self._pending()
            settled = (self._cleanup_thread is not None and not pending
                       and not custody and not self._cleanup_error and not self._discovery_error)
            timed_out = self._clock() >= self._deadline
            if settled or timed_out or self._cleanup_error:
                self._final = self._payload("retired" if settled else "forced-incomplete")
                self._final_deadline = self._clock() + self._diagnostic_timeout
                self._final_write_started = self._write_async(self._final)
            if callable(self._status):
                try:
                    self._status(len(pending) + len(custody), bool(custody) or any(row.before_cleanup for row in pending))
                except Exception:
                    pass  # Cosmetic delivery cannot prevent owned teardown.
        if self._final is not None:
            late = self._pending()
            late_custody = self._pending_custody()
            if (late or late_custody) and self._final["state"] == "retired":
                self._final.update(state="forced-incomplete", forced=True,
                    pending_workers=[str(row.label)[:80] for row in late],
                    pending_custody=[str(row.label)[:80] for row in late_custody])
                self._final_write_started = False
            if not self._final_write_started:
                self._final_write_started = self._write_async(self._final)
            written = (self._final_write_started and self._diagnostic_thread is not None
                       and not self._diagnostic_thread.is_alive())
            if written or self._clock() >= self._final_deadline:
                # A genuinely late worker still blocks normal Qt teardown even
                # if an earlier discovery was clear before final diagnostics.
                late = self._pending()
                late_custody = self._pending_custody()
                diagnostic_pending = self._diagnostic_thread is not None and self._diagnostic_thread.is_alive()
                if late or late_custody or self._discovery_error or diagnostic_pending:
                    self._final.update(state="forced-incomplete", forced=True,
                        pending_workers=[str(row.label)[:80] for row in late]
                            + (["shutdown-diagnostic-writer"] if diagnostic_pending else []),
                        pending_custody=[str(row.label)[:80] for row in late_custody])
                self._done = True
                self._timer.stop()
                self._final["diagnostic_persisted"] = self._diagnostic_written == self._final["state"]
                self._final["diagnostic_error"] = self._diagnostic_error
                self._finish(dict(self._final))
