"""SpywareGuard: bounded evidence, intelligence and verified native-hash response.

Research prose is advisory. Only a local detector finding can request an exact
target response; Adversary Combat independently enforces its own host policy.
No country, vendor name, CVE, feed mention or sandbox probe is response authority.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import stat
import threading
import time
from urllib.parse import urlsplit

from angerona.core.eventbus import Event, is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity
from angerona.core.response_contract import authorize_response
from angerona.core.response_proof import ProducerResponseProofs
from angerona.core.spyware_artifact_scan import (
    scan_chromium_hsts, scan_hosts_overrides, scan_selected_paths, scan_windows_user_temp,
)
from angerona.core.spyware_behavior import SpywareBehaviorEngine
from angerona.core.spyware_definitions import DefinitionError, DefinitionStore, parse_definition_review
from angerona.core.spyware_intel import (
    OFFICIAL_SOURCES, IndicatorReviewIdentity, ThreatIntelStore, normalize_indicator,
    parse_indicator_review_identity,
)
from angerona.core.spyware_native_windows import scan_windows_launch_configuration
from angerona.core.spyware_sensors import collect_persistence, inspect_process_memory, parse_memory_identity
from angerona.telemetry.sensors import connection_snapshot, process_snapshot


_SETTINGS = {
    "spyware_auto_contain": True,
    "spyware_network_enabled": False,
    "spyware_memory_enabled": False,
    "spyware_beacon_enabled": False,
    "spyware_beacon_channel": True,
    "spyware_beacon_signal": False,
}
_LOCAL_PRODUCERS = frozenset({
    "Persistence Sweep", "Memory Injection Scanner", "API Patch / Anti-Blinding Detector",
    "LSASS Credential-Access Guard", "Network Monitor", "C2 Beacon Detector", "Network Protocol Deep Decoder",
    "Process Monitor", "Packet Sniffer", "ETW Core Listener", "Sysmon Event Bridge",
    "ETW Real-Time Process Sensor", "Linux Observe Sensor", "macOS Observe Sensor",
})
_TELEMETRY = frozenset({
    "dns_query", "network_egress", "network_connection", "media_render",
    "process_start", "api_access", "file_read", "http_request",
})
_PRIORITY_STEPS = (
    ("persistence", "Persistence sources"),
    ("processes", "Process inventory"),
    ("hashes", "Bounded file hashes"),
    ("memory", "Bounded process memory"),
    ("connections", "Connections"),
)


def _progress_text(value, limit=512):
    """Observed paths and names remain bounded display data, never commands."""
    if type(value) is not str:
        return ""
    return "".join(character for character in value[:limit] if ord(character) >= 32)


def _priority_progress(request_id, generation, steps=_PRIORITY_STEPS):
    return {"schema": 1, "request_id": request_id, "operation_id": request_id,
            "lifecycle_generation": generation, "sequence": 0, "state": "queued",
            "elapsed_s": 0.0, "current_step": "", "current_task": "Waiting for the native worker",
            "current_file": "", "completed_steps": 0, "total_steps": len(steps),
            "overall_percent": 0.0, "remaining_s": None, "estimate_basis": "unavailable",
            "steps": [{"id": key, "label": label, "state": "pending", "completed": 0,
                       "total": None, "unit": "items", "percent": None, "checked": 0,
                       "skipped": 0, "elapsed_s": 0.0, "remaining_s": None}
                      for key, label in steps]}


@contextmanager
def _priority_worker_thread(level: str):
    """Boost only this worker thread and restore its actual previous priority."""
    info = {"thread_id": threading.get_native_id(), "pid": os.getpid(),
            "requested": level, "active": "unchanged", "restored": None,
            "scope": "native worker thread; not process or realtime scheduling"}
    if os.name != "nt":
        info["reason"] = "Native thread priority is unavailable on this platform."
        yield info
        return
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentThread.restype = wintypes.HANDLE
    kernel.GetThreadPriority.argtypes = (wintypes.HANDLE,)
    kernel.GetThreadPriority.restype = ctypes.c_int
    kernel.SetThreadPriority.argtypes = (wintypes.HANDLE, ctypes.c_int)
    kernel.SetThreadPriority.restype = wintypes.BOOL
    thread = kernel.GetCurrentThread()
    previous = kernel.GetThreadPriority(thread)
    changed = False
    if previous == 0x7FFFFFFF:
        info["reason"] = "Native worker priority could not be read."
    else:
        info["previous"] = previous
        requested = 2 if level == "high" else 1
        if kernel.SetThreadPriority(thread, requested):
            changed = True
            info["active"] = "highest" if requested == 2 else "above-normal"
        else:
            info["reason"] = "Native worker priority could not be changed."
    try:
        yield info
    finally:
        if changed:
            info["restored"] = bool(kernel.SetThreadPriority(thread, previous))
            if not info["restored"]:
                info["reason"] = "Native worker priority restoration failed."


class SpywareGuardModule(BaseModule):
    CODE = "SPYG"
    NAME = "SpywareGuard"
    name = NAME
    description = (
        "Advanced surveillanceware evidence, persistence and memory audits, NDR heuristics, "
        "reviewed intelligence, exact-target single-rule containment and emergency beacons."
    )
    category = "Spyware Defense"
    version = "1.14.1"
    supported_platforms = ("windows", "macos", "linux")
    capability_mode = "detect"
    maturity_channel = "preview"
    capability_inputs = ("local-host-evidence", "local-ndr-telemetry", "untrusted-research-report")
    capability_outputs = ("spyware-finding", "exact-target-response-request", "coverage-status")
    capability_permissions = (
        "host-persistence-read", "process-metadata-read", "event.emit",
        "opt-in-report-network-read", "typed-response-proposal",
    )
    high_risk_permissions = ("opt-in-report-network-read", "typed-response-proposal")
    data_classes = ("process-identity", "persistence-metadata", "network-indicator", "research-url")
    egress = "optional"
    retention = "bounded-memory-findings-and-indicators; private-config; optional-encrypted-evidence"
    response_authority = "typed-response"
    platform_requirements = (
        "Persistence and process permissions; memory metadata supports Windows/Linux",
        "Trusted local adapters for API/file/HTTP/per-process-byte telemetry",
        "Adversary Combat independently gates process and connection containment",
    )
    source_health_semantics = ("partial-is-unknown", "unsupported-is-not-clean", "event-loss-is-visible")
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = "report-coverage-loss-without-inferring-cleanliness"
    resource_budget = {
        "worker_model": "single-lifecycle-worker-with-bounded-commands-and-state",
        "event_delivery": "bounded-cursor-delta",
        "startup_cycle_timeout_seconds": 60.0,
    }
    settings_schema = {
        "type": "object",
        "properties": {key: {"type": "boolean", "default": value} for key, value in _SETTINGS.items()},
        "additionalProperties": False,
    }

    def __init__(self, *, clock=time.time, intel_store=None, persistence_collector=None,
                 memory_collector=None, process_observer=None, connection_observer=None,
                 beacon_factory=None, vault=None, definition_store=None) -> None:
        super().__init__()
        self._clock = clock
        self._response_proofs = ProducerResponseProofs()
        self._native_hash_samples = {}
        self._intel = intel_store or ThreatIntelStore()
        self._definitions = definition_store
        self._definitions_initialized = False
        self._definition_pending = 0
        self._definition_state = {"state": "not-loaded", "busy": False, "error": "",
                                  "generation": 0, "active": None, "previous": None, "staged": None}
        self._persistence = persistence_collector or collect_persistence
        self._memory = memory_collector or inspect_process_memory
        self._processes = process_observer or process_snapshot
        self._connections = connection_observer or connection_snapshot
        self._beacon_factory = beacon_factory
        self._beacon = None
        self._beacon_sender = None
        self._vault = vault
        self._manager = None
        self._config = None
        self._settings = dict(_SETTINGS)
        self._lock = threading.RLock()
        self._commands: queue.Queue = queue.Queue(maxsize=32)
        self._reports: queue.Queue = queue.Queue(maxsize=8)
        self._report_thread = None
        self._report_stop = threading.Event()
        self._hits = deque(maxlen=200)
        self._containments = deque(maxlen=200)
        self._sources = deque(maxlen=32)
        self._news: list[dict] = []
        self._news_pending: set[str] = set()
        self._news_jobs: dict[str, tuple[int, str]] = {}
        self._news_command_pending: tuple[int, str] | None = None
        self._news_status: dict = {"state": "disabled", "refreshing": False, "sources": {}}
        self._last_news = None
        self._review_session = secrets.token_hex(16)
        self._approved: OrderedDict[
            tuple[str, str], tuple[str, int, IndicatorReviewIdentity]
        ] = OrderedDict()
        self._dedup: OrderedDict[str, float] = OrderedDict()
        self._coverage: dict = {"host": "not-yet-scanned", "memory": "disabled",
                                "responses": {"status": "not-collected", "current": False,
                                              "last_verified_at": None, "retained_rows": 0}}
        self._engine = SpywareBehaviorEngine(clock=clock)
        self._advisory_engine = SpywareBehaviorEngine(clock=clock)
        self._last_scan = None
        self._last_refresh = None
        self._memory_cursor = 0
        self._hash_cursor = 0
        self._scan_requested = True
        self._priority_scan_wake = threading.Event()
        self._startup_wake_event = self._priority_scan_wake
        self._priority_scan_job = None
        self._priority_progress_clock = time.monotonic
        self._priority_step_durations = {}
        self._priority_scan_status = {"request_id": "", "state": "idle", "started_at": None,
                                      "finished_at": None, "coverage": {}, "error": ""}
        self._counts = {"findings": 0, "response_requests": 0, "reports": 0, "sandbox_runs": 0,
                        "queue_dropped": 0}
        self._receipt_ids: OrderedDict[str, float | None] = OrderedDict()
        self._response_rows: list[dict] = []
        self._upstream_events: OrderedDict[tuple[str, float], None] = OrderedDict()
        self._memory_receipts: OrderedDict[str, None] = OrderedDict()
        self._vault_state: dict = {"status": "not-used", "plaintext_quarantine_remains": True}

    def bind_manager(self, manager) -> None:
        self._manager = manager
        self._config = getattr(manager, "config", None)
        for name, default in _SETTINGS.items():
            value = getattr(self._config, name, default)
            self._settings[name] = value if type(value) is bool else default
        self._intel.network_enabled = self._settings["spyware_network_enabled"]
        with self._lock:
            self._news_status.update(state="awaiting-refresh" if self._settings["spyware_network_enabled"]
                                     else "disabled", refreshing=False)

    def _enqueue(self, command: str, payload=None) -> bool:
        try:
            self._commands.put_nowait((command, payload))
            return True
        except queue.Full:
            with self._lock:
                self._counts["queue_dropped"] += 1
            return False

    def request_scan(self) -> bool:
        return self._enqueue("scan")

    def request_priority_scan(self, request_id: str) -> bool:
        """Wake the existing generation; never create an overlapping scanner."""
        return self._queue_priority_scan(request_id, None, (), False)

    def request_scoped_priority_scan(self, request_id: str, *, mode: str, targets: tuple = (),
                                     background: bool = False) -> bool:
        """Admit a closed operator scope on the same native worker."""
        if (type(mode) is not str or mode not in {"default", "full", "browser", "targeted"}
                or type(background) is not bool or type(targets) is not tuple
                or len(targets) > 16 or bool(targets) != (mode == "targeted")
                or any(type(path) is not str or not 1 <= len(path) <= 4096 or "\x00" in path
                       or not Path(path).is_absolute() or Path(path).anchor.startswith(("\\\\", "//"))
                       or ".." in Path(path).parts for path in targets)):
            return False
        return self._queue_priority_scan(request_id, mode, targets, background)

    def _queue_priority_scan(self, request_id, mode, targets, background):
        if type(request_id) is not str or re.fullmatch(r"[a-f0-9]{32}", request_id) is None:
            return False
        with self._lifecycle_lock:
            thread = self._thread
            if (thread is None or not thread.is_alive() or self._stop.is_set()
                    or self.lifecycle_generation <= 0):
                return False
            generation = self.lifecycle_generation
            with self._lock:
                if (self._priority_scan_status["state"] in {"queued", "running"}
                        or self._priority_scan_status["request_id"] == request_id):
                    return False
                level = getattr(self._config, "spyware_scan_priority", "above-normal")
                level = level if type(level) is str and level in {"above-normal", "high"} else "above-normal"
                steps = _PRIORITY_STEPS if mode not in {"browser", "targeted"} else ()
                if mode in {"full", "browser"}:
                    steps += (("browser", "Browser contact evidence"),)
                if mode == "full":
                    steps += (("hosts", "Local name overrides"),)
                    if os.name == "nt":
                        steps += (("windows-launch", "Windows launch configuration"),
                                  ("windows-temp", "Configured Windows Temp files"))
                if mode == "targeted":
                    steps += (("selected", "Selected file evidence"),)
                self._priority_scan_job = {"request_id": request_id, "generation": generation,
                                           "cancel": threading.Event(), "priority": level, "worker": thread,
                                           "scope": mode, "targets": targets, "background": background}
                self._priority_scan_status = {
                    "request_id": request_id, "state": "queued", "started_at": None,
                    "finished_at": None, "coverage": {}, "error": "",
                    "lifecycle_generation": generation,
                    "request_finished": False, "collector_finished": False,
                    "cancellation_requested": False,
                    "progress": _priority_progress(request_id, generation, steps),
                }
                self._priority_scan_wake.set()
                return True

    def cancel_priority_scan(self, request_id: str) -> None:
        with self._lock:
            job = self._priority_scan_job
            if job is not None and job["request_id"] == request_id:
                job["cancel"].set()
                if self._priority_scan_status.get("state") in {"queued", "running"}:
                    self._priority_scan_status["cancellation_requested"] = True
                    progress = self._priority_scan_status.get("progress")
                    if type(progress) is dict:
                        progress.update(state="cancelling", current_task="Waiting for the current native check to stop")
                        progress["sequence"] += 1
                    if self._priority_scan_status["state"] == "queued":
                        # No priority collector was admitted. This does not
                        # claim that the continual worker's ordinary scan ends.
                        self._priority_scan_status.update(state="cancelled", finished_at=self._clock(),
                                                         request_finished=True, collector_finished=True)
                        self._finish_scan_progress(job, "cancelled")
                self._priority_scan_wake.set()

    def priority_scan_snapshot(self) -> dict:
        """Return detached memory state; no filesystem or process inspection."""
        with self._lock:
            job = self._priority_scan_job
            if (job is not None and self._priority_scan_status.get("state") in {"queued", "running"}
                    and not job["worker"].is_alive()):
                state = "cancelled" if job["cancel"].is_set() or self.stopping else "failed"
                error = "" if state == "cancelled" else "native-worker-exited-before-request-finished"
                self._priority_scan_status.update(state=state, error=error, finished_at=self._clock(),
                                                  request_finished=True, collector_finished=True)
                self._finish_scan_progress(job, state, error)
            snapshot = json.loads(json.dumps(self._priority_scan_status, default=str))
            worker = self._thread
            snapshot["module_worker_alive"] = bool(worker is not None and worker.is_alive())
            if (job is not None and snapshot.get("state") in {"queued", "running"}
                    and job.get("progress_started") is not None):
                progress = snapshot.get("progress")
                if type(progress) is dict:
                    now = self._priority_progress_clock()
                    progress["elapsed_s"] = max(0.0, now - job["progress_started"])
                    current = progress.get("current_step")
                    for step in progress["steps"]:
                        if step["id"] == current and step["state"] == "running":
                            step["elapsed_s"] = max(0.0, now - job["step_started"].get(current, now))
            return snapshot

    def _scan_progress(self, key, *, state="running", completed=0, total=None,
                       unit="items", task="", path="", checked=None, skipped=0,
                       item_completed=None, item_total=None):
        """Publish only this request's existing worker; routine scans cannot write it."""
        with self._lock:
            job = self._priority_scan_job
            if (job is None or self._thread is not threading.current_thread()
                    or job["generation"] != self.lifecycle_generation
                    or self._priority_scan_status.get("state") != "running"):
                return
            progress = self._priority_scan_status.get("progress")
            if type(progress) is not dict:
                return
            step = next((row for row in progress["steps"] if row["id"] == key), None)
            if step is None:
                return
            now = self._priority_progress_clock()
            started = job["step_started"].setdefault(key, now)
            elapsed = max(0.0, now - started)
            known = type(total) is int and total >= 0 and type(completed) is int and 0 <= completed <= total
            has_item = (type(item_completed) is int and type(item_total) is int
                        and 0 <= item_completed <= item_total and item_total > 0)
            fraction = item_completed / item_total if has_item and state == "running" else 0.0
            percent = (100.0 if total == 0 and state == "completed" else
                       min(total, completed + fraction) * 100.0 / total if known and total else None)
            if state == "running" and percent is not None:
                percent = min(99.0, percent)
            remaining = None
            basis = "unavailable"
            if known and total and completed >= 2 and elapsed >= 1 and completed < total:
                remaining = elapsed * (total - completed) / completed
                basis = "observed item rate; approximate"
            elif state == "running" and key in self._priority_step_durations:
                remaining = max(0.0, self._priority_step_durations[key] - elapsed)
                basis = "previous completed native step; approximate"
            step.update(state=state, completed=max(0, completed), total=total if known else None,
                        unit=unit, percent=percent, checked=max(0, completed if checked is None else checked),
                        skipped=max(0, skipped), elapsed_s=elapsed, remaining_s=remaining,
                        current_task=_progress_text(task), current_file=_progress_text(path))
            if has_item:
                step.update(item_completed=item_completed, item_total=item_total, item_unit="bytes",
                            item_percent=min(100.0, item_completed * 100.0 / item_total))
            else:
                for field in ("item_completed", "item_total", "item_unit", "item_percent"):
                    step.pop(field, None)
            step["percent_basis"] = ("completed candidate slots plus current file byte fraction" if has_item
                                     else "completed workflow items")
            if state == "completed":
                self._priority_step_durations[key] = elapsed
            settled = {"completed", "skipped"}
            progress.update(state="cancelling" if job["cancel"].is_set() else "running",
                            elapsed_s=max(0.0, now - job["progress_started"]), current_step=key,
                            current_task=_progress_text(task), current_file=_progress_text(path),
                            completed_steps=sum(row["state"] in settled for row in progress["steps"]),
                            overall_percent=min(99.0, 100.0 * sum(
                                1.0 if row["state"] in settled else (row["percent"] or 0) / 100.0
                                for row in progress["steps"]) / len(progress["steps"])),
                            remaining_s=None, estimate_basis="unavailable")
            unfinished = [row for row in progress["steps"] if row["state"] not in settled]
            if (remaining is not None and state == "running"
                    and all(row["id"] == key or row["id"] in self._priority_step_durations for row in unfinished)):
                progress["remaining_s"] = remaining + sum(self._priority_step_durations[row["id"]]
                    for row in unfinished if row["id"] != key)
                progress["estimate_basis"] = basis
            progress["sequence"] += 1

    def _finish_scan_progress(self, job, state, error=""):
        progress = self._priority_scan_status.get("progress")
        if type(progress) is not dict:
            return
        now = self._priority_progress_clock()
        progress.update(state=state, elapsed_s=max(0.0, now - job.get("progress_started", now)),
                        remaining_s=0.0 if state == "completed" else None,
                        estimate_basis="completed" if state == "completed" else "unavailable",
                        current_task=("Native request finished; review source coverage" if state == "completed" else
                                      "Native request stopped with partial coverage" if state == "cancelled" else
                                      "Native request failed: " + _progress_text(error, 120)))
        for step in progress["steps"]:
            if step["state"] == "running":
                step.update(state=state if state != "completed" else "incomplete", remaining_s=None)
        if state == "completed" and all(row["state"] in {"completed", "skipped"} for row in progress["steps"]):
            progress["overall_percent"] = 100.0
        elif state == "completed":
            progress["overall_percent"] = None
            progress["current_task"] = "Native request finished; detailed counters were not supplied"
        progress["sequence"] += 1

    def _run_priority_scan(self) -> bool:
        if self._thread is not threading.current_thread():
            return False
        with self._lock:
            job = self._priority_scan_job
            if job is None or self._priority_scan_status["state"] != "queued":
                if job is not None and self._priority_scan_status["state"] not in {"queued", "running"}:
                    self._priority_scan_wake.clear()
                return False
            self._priority_scan_wake.clear()
            if job["generation"] != self.lifecycle_generation or job["cancel"].is_set() or self.stopping:
                self._priority_scan_status.update(state="cancelled", finished_at=self._clock(),
                                                 request_finished=True, collector_finished=True)
                self._finish_scan_progress(job, "cancelled")
                return True
            job["progress_started"] = self._priority_progress_clock()
            job["step_started"] = {}
            self._priority_scan_status.update(state="running", started_at=self._clock(),
                                               worker_thread_id=threading.get_native_id())
            self._scan_requested = False
        stopped = self.generation_stop_event()

        def cancelled():
            return (stopped.is_set() or stopped is not self._stop or job["cancel"].is_set()
                    or job["generation"] != self.lifecycle_generation)

        state, error, native = "completed", "", {}
        artifact_checks, findings, advisory_total = {}, [], 0
        host_scope = job.get("scope") not in {"browser", "targeted"}
        priority = nullcontext({}) if job.get("background") else _priority_worker_thread(job["priority"])
        try:
            with priority as native:
                with self._lock:
                    self._priority_scan_status["native_priority"] = dict(native)
                completed = self._scan_once(cancelled=cancelled) if host_scope else True
                if not cancelled() and completed is not False:
                    artifact_checks, findings, advisory_total = self._scan_priority_artifacts(job, cancelled)
                if cancelled() or completed is False:
                    state = "cancelled"
        except Exception as exc:
            state, error = ("cancelled" if cancelled() else "failed"), type(exc).__name__
        finally:
            if native.get("restored") is False:
                state, error = "failed", "native-thread-priority-restore-failed"
                # Retiring this exact worker also retires a priority level the
                # OS refused to restore. Never boost the remaining core.
                stopped.set()
                self.status = "error"
                self.set_health(0, "Native worker priority restoration failed; worker retired.")
            with self._lock:
                if self._priority_scan_job is job:
                    coverage = json.loads(json.dumps(self._coverage, default=str)) if host_scope else {}
                    if artifact_checks:
                        coverage["artifact_checks"] = artifact_checks
                    self._priority_scan_status.update(
                        state=state, error=error, finished_at=self._clock(),
                        request_finished=True, collector_finished=True,
                        native_priority=dict(native), coverage=coverage,
                    )
                    if job.get("scope") is not None:
                        self._priority_scan_status.update(
                            findings=findings,
                            finding_counts={"advisory": advisory_total, "omitted": advisory_total - len(findings)},
                            coverage_incomplete=state != "completed" or any(
                                result["state"] != "completed" for result in artifact_checks.values()),
                        )
                    self._finish_scan_progress(job, state, error)
        return True

    def _scan_priority_artifacts(self, job, cancelled):
        mode = job.get("scope")
        readers = []
        if mode in {"full", "browser"}:
            readers.append(("browser", "Reading browser contact evidence", scan_chromium_hsts))
        if mode == "full":
            readers.append(("hosts", "Reading local name overrides", scan_hosts_overrides))
            if os.name == "nt":
                readers.extend((
                    ("windows-launch", "Checking Windows launch configuration", scan_windows_launch_configuration),
                    ("windows-temp", "Sampling configured Windows Temp files", scan_windows_user_temp),
                ))
        if mode == "targeted":
            readers.append(("selected", "Checking selected evidence files",
                            lambda **options: scan_selected_paths(job["targets"], **options)))
        coverage, findings, total_hits = {}, [], 0
        for key, task, reader in readers:
            if cancelled():
                break
            self._scan_progress(key, total=1, unit="collectors", task=task)
            outcome = reader(cancelled=cancelled)
            rows = outcome.pop("findings")
            total_hits += len(rows)
            findings.extend(rows[:max(0, 128 - len(findings))])
            coverage[key] = outcome
            self._scan_progress(
                key, state="completed" if outcome["state"] == "completed" else "incomplete",
                completed=1, total=1, unit="collectors", task=task,
                checked=outcome["checked"], skipped=outcome["skipped"],
            )
        return coverage, findings, total_hits

    def _queue_definition_command(self, command, value, *, module_session=None, module_generation=None):
        payload = {"module_session": self._review_session if module_session is None else module_session,
                   "module_generation": self.lifecycle_generation if module_generation is None else module_generation,
                   "value": value}
        with self._lock:
            if not self._enqueue(command, payload):
                return False
            self._definition_pending += 1
            self._definition_state.update(busy=True, error="")
        return True

    def queue_definition_import(self, path) -> bool:
        # Syntax only on the caller/Qt thread. The worker owns opening the file.
        if type(path) is not str or not 1 <= len(path) <= 4096 or "\x00" in path:
            return False
        return self._queue_definition_command("definition_import", path)

    def _queue_definition_review(self, expected, action):
        if type(expected) is not dict:
            return False
        module_fields = {"module_session", "module_generation"}
        review = {key: value for key, value in expected.items() if key not in module_fields}
        if (set(expected) != set(review) | module_fields or parse_definition_review(review) is None
                or review["action"] != action
                or type(expected.get("module_generation")) is not int
                or expected["module_generation"] != self.lifecycle_generation
                or expected.get("module_session") != self._review_session):
            return False
        # Preserve the displayed generation through queue admission; a restart
        # between the check above and enqueue must not rebind an old click.
        return self._queue_definition_command("definition_" + action, dict(review),
            module_session=expected["module_session"], module_generation=expected["module_generation"])

    def activate_definitions(self, *, expected) -> bool:
        return self._queue_definition_review(expected, "activate")

    def rollback_definitions(self, *, expected) -> bool:
        return self._queue_definition_review(expected, "rollback")

    @contextmanager
    def _definition_commit_guard(self, payload):
        with self._lifecycle_lock:
            if (self.stopping or payload["module_session"] != self._review_session
                    or payload["module_generation"] != self.lifecycle_generation):
                raise DefinitionError("Definition operation belongs to a retired module generation")
            yield

    def _cache_definition_snapshot(self, *, error=""):
        # The store snapshot is a small memory-only view. Never take the module
        # paint lock during parsing, authentication, filesystem I/O or replace.
        snapshot = self._definitions.snapshot() if self._definitions is not None else {
            "state": "unavailable", "generation": 0, "active": None,
            "previous": None, "staged": None,
        }
        for key in ("staged", "previous"):
            if snapshot.get(key) is not None:
                snapshot[key]["review_identity"].update(
                    module_session=self._review_session, module_generation=self.lifecycle_generation)
        with self._lock:
            snapshot.update(busy=self._definition_pending > 0, error=error)
            self._definition_state = snapshot
            self._coverage["definitions"] = {"state": snapshot["state"], "error": error,
                "generation": snapshot["generation"]}

    def _ensure_definitions(self):
        if self._definitions is None:
            root = getattr(self._config, "data_dir", None)
            if root is None:
                raise DefinitionError("Definition storage is unavailable without a configured data root")
            self._definitions = DefinitionStore(Path(root), clock=self._clock)
        self._definitions_initialized = True

    def _process_definition_command(self, command, payload):
        error = ""
        try:
            with self._definition_commit_guard(payload):
                pass
            self._ensure_definitions()
            if command == "definition_import":
                self._definitions.stage(payload["value"])
            else:
                self._definitions.apply(payload["value"], action=command.removeprefix("definition_"),
                    commit_guard=lambda: self._definition_commit_guard(payload))
            with self._definition_commit_guard(payload):
                self._scan_requested = True
        except (ValueError, OSError, RuntimeError) as exc:
            # Do not expose arbitrary file paths or imported content in errors.
            error = f"Definition operation refused ({type(exc).__name__}); inspect definition state before retrying."
            self.emit("SpywareGuard definition operation could not complete.", Severity.LOW,
                      operation=command, error_type=type(exc).__name__, response_authorized=False)
        finally:
            with self._lock:
                self._definition_pending = max(0, self._definition_pending - 1)
            self._cache_definition_snapshot(error=error)

    def queue_report_url(self, url: str) -> bool:
        if not isinstance(url, str) or len(url) > 2048:
            return False
        try:
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment):
                return False
        except ValueError:
            return False
        return self._enqueue("report", url)

    def _indicator_review_state(self, state, reason, review=None):
        with self._lock:
            self._coverage["indicator_review"] = {"state": state, "reason": reason}
            if review is not None:
                self._coverage["indicator_review"]["candidate"] = asdict(review[2])

    def review_indicator(self, kind: str, value: str, approved: bool = True, *, expected=None) -> bool:
        """Queue only the exact displayed evidence; legacy requests grant nothing."""
        normalized = (normalize_indicator(kind, value)
                      if type(kind) is str and type(value) is str else None)
        if (normalized is None or type(approved) is not bool or type(expected) is not dict
                or any(type(key) is not str for key in expected)
                or set(expected) != {"session", "generation", "candidate"}
                or type(expected["session"]) is not str
                or expected["session"] != self._review_session
                or type(expected["generation"]) is not int
                or expected["generation"] != self.lifecycle_generation):
            self._indicator_review_state("stale-review", "missing-or-invalid-evidence")
            return False
        identity = parse_indicator_review_identity(expected["candidate"])
        if identity is None or (identity.kind, identity.value) != (kind, normalized):
            self._indicator_review_state("stale-review", "missing-or-invalid-evidence")
            return False
        # Keep no caller-owned dictionaries or objects in the queued command.
        review = (expected["session"], expected["generation"], identity)
        self._indicator_review_state("queued", "awaiting-evidence-comparison", review)
        if not self._enqueue("review", (review, approved)):
            self._indicator_review_state("not-queued", "queue-full", review)
            return False
        return True

    def configure_settings(self, **kwargs) -> dict:
        if not kwargs or any(key not in _SETTINGS or type(value) is not bool
                             for key, value in kwargs.items()):
            return {"queued": False, "reason": "invalid-settings"}
        return {"queued": self._enqueue("settings", dict(kwargs))}

    def run_sandbox(self, scenario: str) -> bool:
        if scenario not in {"dns_tunnel", "exfiltration", "renderer_escape"}:
            return False
        return self._enqueue("sandbox", scenario)

    def queue_rule_export(self) -> bool:
        return self._enqueue("export_rules")

    def request_news_refresh(self) -> bool:
        # Admission records only queued work. It never refreshes a cache date
        # or performs network I/O on the requesting (possibly GUI) thread.
        with self._lifecycle_lock:
            thread = self._thread
            if self.stopping or thread is None or not thread.is_alive():
                return False
            with self._lock:
                if not self._settings["spyware_network_enabled"]:
                    return False
                if self._news_command_pending is not None or self._news_pending:
                    return True  # Coalesce with already admitted research work.
                request = (self.lifecycle_generation, secrets.token_hex(16))
                if not self._enqueue("news", request):
                    self._news_status.update(state="retry-required", refreshing=False,
                                             error="QueueFull", queued_reason="")
                    return False
                self._news_command_pending = request
                self._news_status.update(state="queued", refreshing=True, error="",
                    queued_reason="Waiting for module dispatch; a priority Spyware Scan can delay research work.")
                return True

    def submit_telemetry(self, record: dict) -> bool:
        """Adapter inputs are advisory until an authenticated EventBus producer supplies them."""
        if not isinstance(record, dict):
            return False
        try:
            payload = json.dumps(record, allow_nan=False)
            if len(payload) > 16384:
                return False
            copied = json.loads(payload)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False
        return self._enqueue("telemetry", copied)

    def _ensure_beacon(self):
        if self._beacon is None and not self._settings["spyware_beacon_enabled"]:
            return None
        if self._beacon is None and self._config is not None:
            if self._beacon_factory is None:
                from angerona.core.spyware_beacon import EmergencyBeacon
                self._beacon_factory = EmergencyBeacon
            self._beacon = self._beacon_factory(self._config, clock=self._clock)
        return self._beacon

    def _process_commands(self) -> None:
        for _ in range(8):
            try:
                command, payload = self._commands.get_nowait()
            except queue.Empty:
                return
            try:
                if command.startswith("definition_"):
                    self._process_definition_command(command, payload)
                elif command == "scan":
                    self._scan_requested = True
                elif command == "settings":
                    if self._config is not None:
                        before = {key: getattr(self._config, key, _SETTINGS[key]) for key in payload}
                        try:
                            for key, value in payload.items():
                                setattr(self._config, key, value)
                            self._config.save()
                        except Exception:
                            for key, value in before.items():
                                setattr(self._config, key, value)
                            raise
                    with self._lock:
                        self._settings.update(payload)
                        if not self._settings["spyware_network_enabled"]:
                            self._news_command_pending = None
                            for source in self._news_jobs:
                                self._news_status.setdefault("sources", {})[source] = {
                                    "state": "cancelled", "reason": "Research permission disabled; late results are held"}
                            self._news_jobs.clear()
                            self._news_pending.clear()
                            self._news_status.update(state="disabled", refreshing=False, queued_reason="")
                    self._intel.network_enabled = self._settings["spyware_network_enabled"]
                elif command == "report":
                    if not self._settings["spyware_network_enabled"]:
                        raise ValueError("report-network-disabled")
                    self._schedule_report("url", payload)
                elif command == "remember_url" and self._config is not None:
                    urls = list(getattr(self._config, "spyware_research_urls", []))
                    self._config.spyware_research_urls = list(dict.fromkeys([payload] + urls))[:32]
                    self._config.save()
                elif command == "review":
                    if (type(payload) is not tuple or len(payload) != 2
                            or type(payload[0]) is not tuple or len(payload[0]) != 3
                            or type(payload[0][0]) is not str or type(payload[0][1]) is not int
                            or type(payload[0][2]) is not IndicatorReviewIdentity
                            or type(payload[1]) is not bool):
                        self._indicator_review_state("stale-review", "invalid-queued-evidence")
                        continue
                    review, approve = payload
                    session, generation, expected = review
                    key = (expected.kind, expected.value)
                    # Candidate replacement and receipt assignment share store -> module order.
                    with self._intel.review_candidates(*key, clock=self._clock) as candidates:
                        with self._lock:
                            now = self._clock()
                            current = next((item for item, identity in candidates
                                            if identity == expected and item.fresh(now)), None)
                            if session != self._review_session or generation != self.lifecycle_generation:
                                self._indicator_review_state("stale-review", "module-session-changed", review)
                            elif approve and current is None:
                                self._indicator_review_state("stale-review", "evidence-changed-or-expired", review)
                            elif approve:
                                self._approved[key] = review
                                while len(self._approved) > 5000:
                                    self._approved.popitem(last=False)
                                self._indicator_review_state("approved", "exact-evidence-reviewed", review)
                            elif self._approved.get(key) in (None, review):
                                self._approved.pop(key, None)
                                self._indicator_review_state("revoked", "selected-evidence-revoked", review)
                            else:
                                self._indicator_review_state("stale-review", "different-evidence-approved", review)
                elif command == "sandbox":
                    self._sandbox(payload)
                elif command == "telemetry":
                    for finding in self._advisory_engine.observe(payload):
                        self._publish(finding, local_authority=False)
                elif command == "export_rules":
                    self._export_rules()
                elif command == "news":
                    self._schedule_news(request=payload)
            except Exception as exc:
                with self._lock:
                    self._coverage["last_command_error"] = type(exc).__name__
                    if command == "report":
                        self._sources.appendleft({"url": payload, "status": "failed",
                            "error": type(exc).__name__, "ts": self._clock()})
                    elif command == "news" and self._news_command_pending == payload:
                        self._news_command_pending = None
                        self._news_status.update(state="failed", refreshing=False,
                            error=type(exc).__name__, queued_reason="")
                self.emit("SpywareGuard operation could not complete.", Severity.LOW,
                          operation=command, error_type=type(exc).__name__, response_authorized=False)
            finally:
                self._commands.task_done()

    def _schedule_report(self, kind: str, value: str) -> bool:
        try:
            self._reports.put_nowait((kind, value))
        except queue.Full:
            with self._lock:
                self._counts["queue_dropped"] += 1
            return False
        self._ensure_report_worker()
        return True

    def _ensure_report_worker(self) -> None:
        if (not self._reports.empty() and not self.stopping
                and (self._report_thread is None or not self._report_thread.is_alive())):
            self._report_stop = threading.Event()
            self._report_thread = threading.Thread(target=self._report_worker, args=(self._report_stop,),
                name="SpywareGuardResearch", daemon=True)
            self._report_thread.start()

    def _schedule_news(self, *, request=None) -> None:
        from angerona.core.spyware_news import NEWS_SOURCES
        with self._lock:
            if request is not None:
                if request != self._news_command_pending or request[0] != self.lifecycle_generation:
                    return  # An old command cannot consume a newer admission.
                self._news_command_pending = None
            if not self._settings["spyware_network_enabled"] or self.stopping:
                self._news_command_pending = None
                for source in self._news_jobs:
                    self._news_status.setdefault("sources", {})[source] = {
                        "state": "cancelled", "reason": "Research request retired; late results are held"}
                self._news_jobs.clear()
                self._news_pending.clear()
                self._news_status.update(state="disabled" if not self._settings["spyware_network_enabled"]
                                         else "stopped", refreshing=False, queued_reason="")
                return
            sources = [source for source in NEWS_SOURCES if source not in self._news_pending]
            if not sources:
                self._finish_news_status()
                return
            self._last_news = self._clock()
            job = (self.lifecycle_generation, secrets.token_hex(16))
            self._news_pending.update(sources)
            self._news_jobs.update({source: job for source in sources})
            self._news_status.update(state="refreshing", refreshing=True, last_attempt=self._clock(),
                                     error="", queued_reason="")
            statuses = self._news_status.setdefault("sources", {})
            for source in sources:
                statuses[source] = {"state": "queued"}
        for source in sources:
            error = "QueueFull"
            try:
                accepted = self._schedule_report("news", (source, *job))
            except Exception as exc:
                # A failed worker start can occur after its queue put. Revoke
                # that exact token so a later worker cannot install its result.
                accepted, error = False, type(exc).__name__
            if not accepted:
                with self._lock:
                    if self._news_jobs.get(source) == job:
                        self._news_jobs.pop(source, None)
                        self._news_pending.discard(source)
                        self._news_status["error"] = error
                        self._news_status["sources"][source] = {"state": "failed", "error": error}
        with self._lock:
            self._finish_news_status()

    def _finish_news_status(self) -> None:
        """Called under the state lock; failures never promote old cache to live."""
        statuses = list(self._news_status.get("sources", {}).values())
        failed = [row for row in statuses if row.get("state") == "failed"]
        successful = [row for row in statuses if row.get("state") == "available"]
        state = ("disabled" if not self._settings["spyware_network_enabled"] else
                 "stopped" if self.stopping else
                 "queued" if self._news_command_pending is not None else
                 "refreshing" if self._news_pending else
                 "partial" if failed and successful else
                 "retry-required" if failed and all(row.get("error") == "QueueFull" for row in failed) else
                 "failed" if failed else
                 "current" if any(row.get("items", 0) for row in successful) else "empty")
        self._news_status.update(state=state, refreshing=bool(self._news_pending or self._news_command_pending)
                                 and not self.stopping
                                 and self._settings["spyware_network_enabled"])
        if self._news_command_pending is None:
            self._news_status["queued_reason"] = ""

    def _report_worker(self, stopped) -> None:
        # A slow research publisher must not delay single-rule host containment
        # or the independent watcher's heartbeat.
        while not stopped.is_set():
            try:
                kind, value = self._reports.get(timeout=0.5)
            except queue.Empty:
                continue
            url = OFFICIAL_SOURCES[value].url if kind == "source" else value
            news_source, news_job = None, None
            try:
                if kind == "news":
                    if (type(value) is not tuple or len(value) != 3
                            or type(value[0]) is not str or type(value[1]) is not int
                            or type(value[2]) is not str):
                        continue
                    news_source, news_job = value[0], value[1:]
                    url = news_source
                if not self._settings["spyware_network_enabled"]:
                    continue
                if kind == "news":
                    with self._lock:
                        if (news_job[0] != self.lifecycle_generation
                                or self._news_jobs.get(news_source) != news_job
                                or stopped.is_set() or self.stopping
                                or not self._settings["spyware_network_enabled"]):
                            continue
                        self._news_status.setdefault("sources", {})[news_source] = {"state": "fetching"}
                    from angerona.core.spyware_news import fetch_news_source
                    items = fetch_news_source(news_source, network_enabled=True, now=self._clock())
                    if not stopped.is_set() and self._settings["spyware_network_enabled"]:
                        with self._lock:
                            if (news_job[0] == self.lifecycle_generation
                                    and self._news_jobs.get(news_source) == news_job
                                    and not stopped.is_set() and not self.stopping
                                    and self._settings["spyware_network_enabled"]):
                                merged = {item["url"]: item for item in self._news + items}
                                self._news = sorted(merged.values(), key=lambda row: row["published"], reverse=True)[:30]
                                self._news_status.update(last_refresh=self._clock())
                                self._news_status.setdefault("sources", {})[news_source] = {
                                    "state": "available", "items": len(items), "checked_at": self._clock()}
                    continue
                result = (self._intel.refresh(value, now=self._clock()) if kind == "source"
                          else self._intel.refresh_url(value, now=self._clock()))
                if stopped.is_set():
                    continue
                with self._lock:
                    self._sources.appendleft({"url": url, "status": "ingested",
                        "indicators": len(result.indicators), "ts": self._clock(),
                        "content_sha256": result.content_sha256})
                    self._counts["reports"] += 1
                if kind == "url":
                    self._enqueue("remember_url", value)
            except Exception as exc:
                if not stopped.is_set():
                    with self._lock:
                        if kind == "news":
                            if (news_job is not None and news_job[0] == self.lifecycle_generation
                                    and self._news_jobs.get(news_source) == news_job):
                                self._news_status["error"] = type(exc).__name__
                                self._news_status.setdefault("sources", {})[news_source] = {
                                    "state": "failed", "error": type(exc).__name__, "checked_at": self._clock()}
                        self._sources.appendleft({"url": url, "status": "failed",
                            "error": type(exc).__name__, "ts": self._clock()})
            finally:
                if kind == "news":
                    with self._lock:
                        if news_job is not None and self._news_jobs.get(news_source) == news_job:
                            self._news_jobs.pop(news_source, None)
                            self._news_pending.discard(news_source)
                        self._finish_news_status()
                self._reports.task_done()

    @staticmethod
    def _memory_observation_only(finding: dict) -> bool:
        # A process identity binds the observation to its target. It does not
        # turn private executable/JIT permissions into proof of injection.
        return finding.get("kind") == "private_executable_memory" or (
            finding.get("kind") == "sensor_memory_injection_scanner"
            and finding.get("detector_policy") == "rwx-memory-indicator-alert-only"
            and finding.get("active_attack") is False
            and finding.get("disposition") == "observation"
        )

    @staticmethod
    def _startup_configuration_only(finding: dict) -> bool:
        # A Run entry records configured startup, not payload existence or
        # execution. Even an attached identity cannot corroborate this rule.
        return (finding.get("source") == "windows.run"
                and finding.get("kind") == "persistence_transient_payload")

    @staticmethod
    def _cadence_observation_only(finding: dict) -> bool:
        # A locally authenticated cadence observation remains an observation.
        # Only this producer's explicit corroborated policy can justify its
        # existing direct sensor response; origin authentication alone cannot.
        return (finding.get("kind") == "sensor_c2_beacon_detector"
                and not (finding.get("detector_policy") == "cadence-plus-threat-intel"
                         and finding.get("threat_intel_corroborated") is True))

    def _current_hash_review(self, digest):
        """Current private review state, never an imported finding's flags."""
        definition = self._definitions.lookup("sha256", digest) if self._definitions is not None else None
        if definition is not None:
            return definition
        with self._intel.review_candidates("sha256", digest, clock=self._clock) as candidates:
            with self._lock:
                review = self._approved.get(("sha256", digest))
                approved = next((item for item, identity in candidates
                    if review == (self._review_session, self.lifecycle_generation, identity)
                    and item.fresh(self._clock())), None)
        if approved is None:
            return None
        return {"indicator_kind": "sha256", "indicator": digest,
                "source": approved.source, "source_sha256": approved.source_sha256,
                "review_identity": {"session": review[0], "generation": review[1],
                                    "candidate": asdict(review[2])}, "reviewed": True}

    def _native_hash_response_allowed(self, finding, native_sample) -> bool:
        if type(native_sample) is not object:
            return False
        with self._lock:
            sample = self._native_hash_samples.get(native_sample)
        if sample is None or self.stopping:
            return False
        generation, sample_stop, observed, path, digest, pid, birth = sample
        now = time.monotonic()
        return bool(generation == self.lifecycle_generation and sample_stop is self._stop
                    and not sample_stop.is_set() and observed <= now < observed + 30
                    and finding.get("path") == path and finding.get("observed_content_sha256") == digest
                    and finding.get("pid") == pid and finding.get("process_create_time") == birth
                    and finding.get("evidence") == self._current_hash_review(digest))

    def _retain_native_hash_response(self, event, finding, native_sample):
        # Close the earlier validation/retention restart race. Never bind an old
        # sample to the new current generation or renew its original deadline.
        with self._lifecycle_lock:
            with self._lock:
                sample = self._native_hash_samples.get(native_sample)
                if sample is None:
                    raise ValueError("native-sample-missing")
                generation, sample_stop, observed, path, digest, pid, birth = sample
                now = time.monotonic()
                if (generation != self.lifecycle_generation or sample_stop is not self._stop
                        or sample_stop.is_set() or not observed <= now < observed + 30
                        or event.details.get("path") != path
                        or event.details.get("observed_content_sha256") != digest
                        or event.details.get("pid") != pid
                        or event.details.get("process_create_time") != birth):
                    raise ValueError("native-sample-retired-or-expired")
                self._response_proofs.retain(event, generation=generation,
                                            now=observed, review=finding["evidence"])

    def verify_response_admission(self, event: Event) -> bool:
        """Publisher-safe cached receipt check; no intel/definition lock or sort."""
        if type(event) is not Event or event.module != self.name or self.stopping:
            return False
        try:
            with self._lock:
                return self._response_proofs.verify(event, generation=self.lifecycle_generation,
                    now=time.monotonic(), review=event.details.get("evidence"))
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            return False

    def verify_response_event(self, event: Event) -> bool:
        """Exact current native sample + current reviewed hash, not bus flags."""
        if type(event) is not Event or event.module != self.name or self.stopping:
            return False
        try:
            digest = event.details.get("observed_content_sha256")
            if normalize_indicator("sha256", digest) != digest:
                return False
            review = self._current_hash_review(digest)
            if review is None or event.details.get("evidence") != review:
                return False
            with self._lock:
                return self._response_proofs.verify(event, generation=self.lifecycle_generation,
                                                    now=time.monotonic(), review=review)
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            return False

    def _response(self, finding: dict, local_authority: bool, *, native_sample=None) -> dict:
        if (not local_authority or not self._native_hash_response_allowed(finding, native_sample)
                or not self._settings["spyware_auto_contain"]
                or finding.get("response_eligible") is False
                or self._memory_observation_only(finding)
                or self._startup_configuration_only(finding)
                or self._cadence_observation_only(finding)):
            return {}
        pid, birth = finding.get("pid"), finding.get("process_create_time")
        if finding.get("kind") in {"private_executable_memory", "sensor_memory_injection_scanner"}:
            if self.stopping:
                return {}
            receipt = parse_memory_identity(finding.get("memory_identity"))
            if (finding.get("response_eligible") is not True or receipt is None
                    or not receipt.bound or receipt.pid != pid
                    or receipt.before.create_time != birth):
                return {}  # Unbound memory evidence cannot reach host fallback.
        exact_process = (type(pid) is int and pid > 4 and pid not in {os.getpid(), os.getppid()}
                         and type(birth) in (int, float) and math.isfinite(birth) and birth > 0)
        actions = []
        if exact_process:
            actions.extend(("isolate_program", "suspend_process", "terminate_process"))
        peers = []
        try:
            peer = ipaddress.ip_address(finding.get("remote_ip", ""))
            if peer.is_global and not peer.is_multicast:
                peers = [str(peer)]
                actions.append("block_remote_ip")
        except (ValueError, TypeError):
            pass
        # Only an inspected exact file digest can authorize a filesystem mutation.
        path, digest = finding.get("path"), finding.get("observed_content_sha256")
        if path and normalize_indicator("sha256", digest) and Path(path).is_absolute():
            actions.append("quarantine_file")
        # An absent target is a coverage gap, never whole-host authority.
        return authorize_response(actions, pid=pid, process_create_time=birth,
                                  remote_ips=peers, path=path) if actions else {}

    def _publish_memory(self, finding: dict, stopped, *,
                        response_already_requested: bool = False) -> None:
        # Order memory response admission/emission against stop/restart. A
        # retired generation may retain observations, never response authority.
        with self._lifecycle_lock:
            if stopped.is_set() or stopped is not self._stop:
                finding = dict(finding, response_eligible=False,
                    eligibility_reason="Memory collection owner generation stopped or was replaced; retained as advisory")
                response_already_requested = False
                if finding.get("kind") == "sensor_memory_injection_scanner":
                    with self._lock:
                        self._coverage["memory_sensor_identity"] = {"status": "partial",
                            "detail": finding["eligibility_reason"]}
            self._publish(finding, local_authority=True,
                          response_already_requested=response_already_requested)

    def _publish(self, finding: dict, *, local_authority: bool,
                 response_already_requested: bool = False, native_sample=None) -> None:
        memory_observation = self._memory_observation_only(finding)
        cadence_observation = self._cadence_observation_only(finding)
        if memory_observation or cadence_observation or self._startup_configuration_only(finding):
            finding = dict(finding, response_eligible=False, finding_kind="exposure",
                classification_reason=("Memory permissions alone are an exposure lead; "
                    "JIT runtimes overlap and independent threat evidence is required"
                    if memory_observation else "Connection timing alone is an exposure lead; "
                    "maliciousness is unconfirmed and no corroborated producer policy was supplied"
                    if cadence_observation else "Startup configuration alone is an exposure lead; "
                    "payload existence, execution and maliciousness are unconfirmed"))
            finding.pop("single_rule_host_fallback", None)
            response_already_requested = False
        kind = str(finding.get("kind", "spyware_evidence"))[:100]
        identity = {key: finding.get(key) for key in
                    ("pid", "process_create_time", "remote_ip", "path", "evidence")}
        token = hashlib.sha256(json.dumps([local_authority, kind, identity], sort_keys=True, default=str).encode()).hexdigest()
        now = self._clock()
        with self._lock:
            previous = self._dedup.get(token)
            if previous is not None and 0 <= now - previous < 300:
                return
            self._dedup[token] = now
            self._dedup.move_to_end(token)
            while len(self._dedup) > 2048:
                self._dedup.popitem(last=False)
        response = {} if response_already_requested else self._response(
            finding, local_authority, native_sample=native_sample)
        severity = Severity.__members__.get(str(finding.get("severity", "MEDIUM")).upper(), Severity.MEDIUM)
        details = dict(finding)
        details.pop("summary", None)
        details.pop("severity", None)
        details.pop("response_contract", None)
        details.update(schema="angerona.spyware-guard.finding.v1", finding_code=kind,
                       incident_id=token, actor_attribution="none", spyware_confirmed=False,
                       response_authorized=False, response_authority="none",
                       active_attack=False, disposition="observation")
        if finding.get("response_eligible") is False and finding.get("finding_kind") == "exposure":
            details["disposition"] = "exposure"
        if response:
            details.update(response)
            details.update(response_authority="typed-response", active_attack=True,
                           disposition="active", detector_policy="reviewed-sha256-native-sample")
        summary = str(finding.get("summary") or finding.get("reason") or kind)[:1024]
        if (kind == "persistence_transient_payload" and finding.get("source") == "windows.run"
                and finding.get("reason") in {
                    "Persistence executes a payload from a temporary/public/download directory.",
                    "Configured startup command references a target in a temporary/public/download directory; execution is unverified.",
                }):
            summary = ("Startup entry points to a temporary/public/download payload; "
                       "execution and maliciousness are unconfirmed.")
        response_event = None
        if response:
            # Retain BEFORE inline consumers or response-request accounting.
            response_event = Event(self.name, summary, max(severity, Severity.LOW), now, details)
            try:
                self._retain_native_hash_response(response_event, finding, native_sample)
            except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                response = {}
                response_event = None
                details.pop("response_contract", None)
                details.update(response_authorized=False, response_authority="none", active_attack=False,
                               disposition="observation", response_withheld_reason="producer-proof-payload-bounds")
        hit = {"id": token, "ts": now, "kind": kind, "severity": severity.name,
               "rule": kind,
               "summary": summary, "pid": finding.get("pid"),
               "remote_ip": finding.get("remote_ip", ""), "evidence": finding.get("evidence", {}),
               "response_requested": bool(response),
               "status": "upstream-response-requested" if response_already_requested
                         else "containment-requested" if response
                         else "exposure-review" if details["disposition"] == "exposure"
                         else "no-exact-authorized-target"}
        with self._lock:
            self._hits.appendleft(hit)
            self._counts["findings"] += 1
            if response:
                self._counts["response_requests"] += 1
                self._containments.appendleft({"incident_id": token, "ts": now,
                    "status": "requested", "actions": response["response_contract"]["actions"],
                    "targets": response["response_contract"]["targets"]})
        beacon = self._ensure_beacon()
        if local_authority and beacon is not None and (severity >= Severity.HIGH or kind in {
            "encrypted_egress_spike", "renderer_shell_after_media", "sensor_blinding"}):
            beacon.enqueue({"incident_id": token,
                            "severity": severity.name, "ts": now, "pid": finding.get("pid"),
                            "rule_code": kind.upper().replace("-", "_")[:64]})
            self._dispatch_beacon(beacon)
        if response:
            self.publish_event(response_event)
        else:
            self.emit(summary, max(severity, Severity.LOW), **details)

    def _dispatch_beacon(self, beacon) -> None:
        # An early attempt must not make containment wait for a provider.
        if self._beacon_sender is None or not self._beacon_sender.is_alive():
            self._beacon_sender = threading.Thread(target=beacon.tick,
                name="SpywareGuardBeaconSend", daemon=True)
            self._beacon_sender.start()

    def _consume_events(self) -> None:
        events, overflow = self.poll_bus_events()
        if overflow:
            with self._lock:
                self._coverage["event_bus"] = "loss-detected"
        for event in events:
            if (event.module == self.name or is_remote_observe_only(event)
                    or not isinstance(event.details, dict) or event.details.get("drill")
                    or event.details.get("practice") or event.details.get("synthetic")
                    or event.details.get("simulation")
                    or event.details.get("origin", "local") != "local"
                    or event.details.get("source_host", "local") != "local"):
                continue
            # Beacon Detector's historic `remote` is an IP endpoint. All other
            # truthy values denote forwarded provenance and cannot authorize
            # either the behavioral adapter or the direct sensor conversion.
            remote = event.details.get("remote")
            if remote:
                if not isinstance(remote, str):
                    continue
                try:
                    ipaddress.ip_address(remote)
                except ValueError:
                    continue
            if self._bus is None or not self._bus.verify(event):
                continue
            age = self._clock() - event.ts
            if not math.isfinite(age) or age < -5 or age > 300:
                continue
            details = event.details
            if event.module not in _LOCAL_PRODUCERS:
                continue
            # Memory scan receipts cannot be relabelled as API/network telemetry.
            record = {} if event.module == "Memory Injection Scanner" else self._adapt_event(event)
            event_type = record.get("event_type") if record else None
            if event_type in _TELEMETRY:
                if event_type == "dns_query":
                    record["domain"] = details.get("domain") or details.get("qname") or details.get("query_name")
                for finding in self._engine.observe(record):
                    # These adapters own the local evidence, not a forwarded research claim.
                    self._publish(finding, local_authority=True)
                self._match_indicator(record, "domain", record.get("domain"), local_authority=True)
                self._match_indicator(record, "ip", record.get("remote_ip"), local_authority=True)
            if (event.module in {"Memory Injection Scanner", "API Patch / Anti-Blinding Detector", "LSASS Credential-Access Guard", "C2 Beacon Detector"}
                    and event.severity >= Severity.LOW and type(details.get("pid")) is int
                    and details.get("pid", 0) > 4):
                finding = {"kind": "sensor_" + event.module.lower().replace(" ", "_")[:70],
                           "severity": event.severity.name,
                           "summary": "Spyware-relevant local sensor finding: " + event.module,
                           "evidence": {"producer": event.module, "source_event_ts": event.ts,
                                        "source_event_digest": event.hmac_sig},
                           "pid": details.get("pid"),
                           "process_create_time": details.get("process_create_time")}
                if (event.module == "Memory Injection Scanner"
                        and details.get("detector_policy") == "rwx-memory-indicator-alert-only"
                        and details.get("active_attack") is False
                        and details.get("disposition") == "observation"):
                    finding.update(
                        summary="Uncorroborated memory-permission indicator from Memory Injection Scanner",
                        detector_policy=details["detector_policy"], active_attack=False,
                        disposition="observation", finding_kind="exposure")
                if event.module == "Memory Injection Scanner":
                    finding["evidence"]["producer_policy"] = {key: details.get(key)
                        for key in ("detector_policy", "active_attack", "disposition")}
                    receipt = parse_memory_identity(details.get("memory_identity"))
                    fresh = (receipt is not None and receipt.source == "memory.windows.inject_scanner"
                             and receipt.bound and receipt.pid == details["pid"]
                             and 0 <= receipt.finished_at - receipt.started_at <= 300
                             and -5 <= event.ts - receipt.finished_at <= 5
                             and receipt.request_id not in self._memory_receipts)
                    if receipt is not None:
                        self._memory_receipts[receipt.request_id] = None
                        self._memory_receipts.move_to_end(receipt.request_id)
                        while len(self._memory_receipts) > 2048:
                            self._memory_receipts.popitem(last=False)
                    observation_only = self._memory_observation_only(finding)
                    eligible = (fresh and details.get("response_eligible") is True
                                and not observation_only)
                    identity_reason = ("Fresh authenticated same-handle memory receipt" if fresh
                        else "Memory source identity missing, stale, replayed, or mismatched")
                    finding.update(response_eligible=eligible,
                        process_create_time=receipt.before.create_time if fresh else None,
                        memory_identity=details.get("memory_identity"),
                        eligibility_reason=(identity_reason if not fresh or eligible
                            else "Memory permissions alone are an exposure lead; independent threat evidence is required"
                            if observation_only else "Memory producer did not mark this finding response-eligible"))
                    with self._lock:
                        self._coverage["memory_sensor_identity"] = {
                            "status": "complete" if fresh else "partial",
                            "detail": identity_reason}
                if event.module == "C2 Beacon Detector":
                    finding.update(
                        detector_policy=details.get("detector_policy"),
                        threat_intel_corroborated=details.get("threat_intel_corroborated"),
                    )
                    finding["evidence"]["producer_policy"] = {key: details.get(key)
                        for key in ("detector_policy", "threat_intel_corroborated",
                                    "active_attack", "disposition")}
                    if self._cadence_observation_only(finding):
                        finding.update(response_eligible=False, finding_kind="exposure")
                if event.module == "API Patch / Anti-Blinding Detector":
                    ticks = details.get("process_birth")
                    if type(ticks) is int and 116444736000000000 < ticks < 2650467744000000000:
                        finding["process_create_time"] = ticks / 10000000 - 11644473600
                remote = details.get("remote")
                if isinstance(remote, str):
                    finding["remote_ip"] = remote
                from angerona.modules.adversary_combat import AdversaryCombat
                upstream = (finding.get("response_eligible") is not False
                            and details.get("response_authorized") is True
                            and AdversaryCombat._response_actions(event) is not None)
                if upstream:
                    self._upstream_events[(event.module, event.ts)] = None
                    while len(self._upstream_events) > 2048:
                        self._upstream_events.popitem(last=False)
                if event.module == "Memory Injection Scanner":
                    self._publish_memory(finding, self.generation_stop_event(),
                                         response_already_requested=upstream)
                else:
                    self._publish(finding, local_authority=True, response_already_requested=upstream)

    @staticmethod
    def _adapt_event(event: Event) -> dict:
        details = event.details
        record = dict(details, ts=event.ts)
        event_type = details.get("event_type")
        if event_type in {"process_creation", "process_create"}:
            record["event_type"] = "process_start"
            record["process_name"] = details.get("process_name") or details.get("name")
            record["parent_pid"] = details.get("parent_pid") or details.get("ppid")
        if event.module == "Sysmon Event Bridge" and details.get("eid") == 22:
            record["event_type"] = "dns_query"
            record["domain"] = details.get("query_name")
            # Historical Sysmon EID22 has no process birth proof. Retain DNS
            # evidence but do not fabricate it from a newly reused ProcessId.
            record.pop("pid", None)
            record.pop("process_create_time", None)
        elif event.module == "Network Monitor" and isinstance(details.get("raddr"), str):
            try:
                endpoint, port = details["raddr"].rsplit(":", 1)
                record.update(event_type="network_connection",
                              remote_ip=str(ipaddress.ip_address(endpoint.strip("[]"))))
                record["remote_port"] = int(port)
            except (ValueError, TypeError):
                return {}
        return record

    def _match_indicator(self, record, kind, value, *, local_authority, native_sample=None):
        normalized = normalize_indicator(kind, value)
        definition = self._definitions.lookup(kind, value) if self._definitions is not None else None
        if definition is not None:
            finding = {"kind": "definition_" + kind + "_indicator_match", "severity": "HIGH",
                       "summary": "Local evidence matched a locally activated spyware definition.",
                       "evidence": definition}
            for key in ("pid", "process_create_time", "remote_ip", "path", "observed_content_sha256"):
                if key in record:
                    finding[key] = record[key]
            self._publish(finding, local_authority=local_authority, native_sample=native_sample)
            return
        with self._intel.review_candidates(kind, value, clock=self._clock) as candidates:
            with self._lock:
                review = self._approved.get((kind, normalized))
                now = self._clock()
                approved = next((item for item, identity in candidates
                    if review == (self._review_session, self.lifecycle_generation, identity)
                    and item.fresh(now)), None)
        if approved is None:
            return  # Research mentions do not become live detection rules before review.
        finding = {"kind": "reviewed_" + kind + "_indicator_match", "severity": "HIGH",
                   "summary": "Local evidence matched an explicitly reviewed intelligence indicator.",
                   "evidence": {"indicator_kind": kind, "indicator": normalized,
                                "source": approved.source, "source_sha256": approved.source_sha256,
                                "review_identity": {"session": review[0], "generation": review[1],
                                                    "candidate": asdict(review[2])}, "reviewed": True}}
        for key in ("pid", "process_create_time", "remote_ip", "path", "observed_content_sha256"):
            if key in record:
                finding[key] = record[key]
        self._publish(finding, local_authority=local_authority, native_sample=native_sample)

    def _scan_once(self, *, cancelled=None) -> bool:
        # Ordinary source collection keeps its existing per-source stop and
        # advisory-evidence rules. An explicit priority job adds cancellation
        # at stage boundaries without changing that normal call contract.
        cancelled = cancelled if callable(cancelled) else lambda: False
        if cancelled():
            return False
        self._scan_progress("persistence", total=1, unit="collectors",
                            task="Reading bounded persistence sources")
        report = self._persistence(max_entries=512)
        with self._lock:
            self._coverage["persistence"] = report.get("coverage", {})
        for finding in report.get("findings", [])[:64]:
            if cancelled():
                return False
            # A configuration record alone does not identify a running process.
            self._publish(finding, local_authority=True)
        self._scan_progress("persistence", state="completed", completed=1, total=1,
                            unit="collectors", task="Persistence collection finished; review source coverage")
        if cancelled():
            return False
        self._scan_progress("processes", total=1, unit="collectors",
                            task="Collecting the existing bounded process inventory")
        processes = self._processes()
        rows = list(processes.processes)[:4096]
        self._scan_progress("processes", state="completed", completed=len(rows), total=len(rows),
                            unit="processes", task=f"Process inventory returned {len(rows)} bounded records")
        self._scan_hashes(rows, cancelled=cancelled)
        if cancelled():
            return False
        with self._lock:
            self._coverage["processes"] = {"complete": processes.complete,
                                           "error": processes.error}
        if self._settings["spyware_memory_enabled"] and rows:
            chosen = [rows[(self._memory_cursor + index) % len(rows)]
                      for index in range(min(4, len(rows)))]
            self._memory_cursor = (self._memory_cursor + len(chosen)) % len(rows)
            memory_coverage = {}
            memory_stopped = self.generation_stop_event()
            memory_cancelled = False
            def retired():
                return memory_stopped.is_set() or memory_stopped is not self._stop or cancelled()
            memory_checked = memory_skipped = 0
            self._scan_progress("memory", total=len(chosen), unit="process sample slots",
                                task="Starting the bounded process-memory sample")
            for index, row in enumerate(chosen):
                if retired():
                    memory_cancelled = True
                    break
                pid = row.get("pid")
                if type(pid) is not int or pid <= 4 or pid in {os.getpid(), os.getppid()}:
                    memory_skipped += 1
                    self._scan_progress("memory", completed=index + 1, total=len(chosen),
                                        unit="process sample slots", task="Excluded an ineligible process sample",
                                        checked=memory_checked, skipped=memory_skipped)
                    continue
                self._scan_progress("memory", completed=index, total=len(chosen),
                                    unit="process sample slots", task=f"Inspecting bounded memory for PID {pid}",
                                    checked=memory_checked, skipped=memory_skipped)
                request_id = secrets.token_hex(16)
                try:
                    result = self._memory(pid, max_regions=512,
                        expected_create_time=row.get("create_time"), request_id=request_id,
                        cancelled=retired)
                except Exception as exc:
                    # Do not rerun a legacy collector after TypeError: it may
                    # already have inspected a process before raising.
                    result = {"findings": [], "coverage": {"memory.provider": {
                        "status": "error", "detail": type(exc).__name__ +
                        ": identity protocol collection failed; no legacy fallback executed"}}}
                receipt = parse_memory_identity(result.get("memory_identity"))
                bound = (not retired() and receipt is not None and receipt.bound
                         and receipt.source == "memory.windows.virtualquery"
                         and receipt.pid == pid and receipt.request_id == request_id
                         and type(row.get("create_time")) in (int, float)
                         and receipt.expected_create_time == row["create_time"]
                         and receipt.expected_create_time is not None)
                coverage = dict(result.get("coverage", {}))
                if retired():
                    identity_detail = "Memory collection owner generation stopped or was replaced; retained as advisory"
                elif receipt is None:
                    identity_detail = "Memory identity receipt missing or invalid"
                elif not receipt.bound:
                    identity_detail = receipt.reason
                elif receipt.source != "memory.windows.virtualquery":
                    identity_detail = "Unexpected memory identity source"
                elif receipt.pid != pid:
                    identity_detail = "Memory receipt PID differs from the requested process"
                elif receipt.request_id != request_id:
                    identity_detail = "Memory receipt belongs to another request or a replay"
                elif not bound:
                    identity_detail = "Memory receipt expected birth is missing or differs from the inventory generation"
                else:
                    identity_detail = receipt.reason
                coverage["memory.identity"] = {"status": "complete" if bound else "partial",
                    "detail": identity_detail}
                memory_coverage[str(pid)] = {"expected_process_create_time": row.get("create_time"),
                    "process_create_time": receipt.before.create_time if bound else None,
                    "coverage": coverage}
                for finding in result.get("findings", [])[:8]:
                    finding = dict(finding, pid=pid,
                        process_create_time=receipt.before.create_time if bound else None,
                        memory_identity=result.get("memory_identity"),
                        response_eligible=bound and finding.get("response_eligible") is not False,
                        eligibility_reason=coverage["memory.identity"]["detail"])
                    self._publish_memory(finding, memory_stopped)
                if retired():
                    memory_cancelled = True
                    coverage["memory.identity"] = {"status": "partial",
                        "detail": "Memory collection owner generation stopped or was replaced; retained as advisory"}
                    break
                memory_checked += 1
                self._scan_progress("memory", completed=index + 1, total=len(chosen),
                                    unit="process sample slots", task=f"Memory check for PID {pid} returned",
                                    checked=memory_checked, skipped=memory_skipped)
            complete = not memory_cancelled and bool(memory_coverage) and all(
                entry["coverage"] and all(isinstance(source, dict) and source.get("status") == "complete"
                                          for source in entry["coverage"].values())
                for entry in memory_coverage.values())
            with self._lock:
                self._coverage["memory"] = {"status": "complete" if complete else "partial",
                    "scope": "bounded-sample-only", "cancelled": memory_cancelled, "by_pid": memory_coverage}
                if memory_cancelled:
                    self._coverage["host"] = "scan-cancelled-memory-owner-generation"
            if memory_cancelled:
                return False
            self._scan_progress("memory", state="completed", completed=len(chosen), total=len(chosen),
                                unit="process sample slots", task="Bounded memory sample finished; review coverage",
                                checked=memory_checked, skipped=memory_skipped)
        else:
            with self._lock:
                self._coverage["memory"] = "disabled" if not self._settings["spyware_memory_enabled"] else "no-processes"
            self._scan_progress("memory", state="skipped", total=0, unit="process sample slots",
                                task="Memory check disabled" if not self._settings["spyware_memory_enabled"]
                                else "No process records available for the bounded memory sample")
        if cancelled():
            return False
        self._scan_progress("connections", unit="connections",
                            task="Collecting the existing bounded connection snapshot")
        snapshot = self._connections()
        indexed = {row.get("pid"): row for row in rows}
        connections = snapshot.connections[:4096]
        connection_checked = connection_skipped = 0
        self._scan_progress("connections", total=len(connections), unit="connections",
                            task="Reviewing the bounded connection snapshot")
        for index, connection in enumerate(connections):
            if cancelled():
                return False
            raw = str(connection.get("raddr", ""))
            try:
                address, _port = raw.rsplit(":", 1)
                peer = str(ipaddress.ip_address(address.strip("[]")))
            except ValueError:
                connection_skipped += 1
                self._scan_progress("connections", completed=index + 1, total=len(connections),
                                    unit="connections", task="Connection without a usable remote IP skipped",
                                    checked=connection_checked, skipped=connection_skipped)
                continue
            record = {"remote_ip": peer, "pid": connection.get("pid"),
                      "process_create_time": indexed.get(connection.get("pid"), {}).get("create_time")}
            self._match_indicator(record, "ip", peer, local_authority=True)
            connection_checked += 1
            self._scan_progress("connections", completed=index + 1, total=len(connections),
                                unit="connections", task=f"Checked connection record for PID {connection.get('pid')}",
                                checked=connection_checked, skipped=connection_skipped)
        with self._lock:
            self._coverage["connections"] = {"complete": snapshot.complete, "error": snapshot.error}
            self._coverage["host"] = "scan-completed-with-source-specific-coverage"
        self._last_scan = self._clock()
        self._scan_progress("connections", state="completed", completed=len(connections), total=len(connections),
                            unit="connections", task="Connection review finished; review source coverage",
                            checked=connection_checked, skipped=connection_skipped)
        return True

    def _scan_hashes(self, rows, *, cancelled=None) -> None:
        sample_generation = self.lifecycle_generation
        sample_stop = self.generation_stop_event()
        requested_cancel = cancelled if callable(cancelled) else lambda: False
        cancelled = lambda: (sample_stop.is_set() or sample_stop is not self._stop
                             or sample_generation != self.lifecycle_generation or requested_cancel())
        self._scan_progress("hashes", unit="candidate records",
                            task="Checking whether enabled hash indicators require a bounded file sample")
        with self._lock:
            wanted = any(kind == "sha256" for kind, _value in self._approved)
        wanted = wanted or (self._definitions is not None and self._definitions.has_hashes())
        if not wanted:
            self._scan_progress("hashes", state="skipped", total=0, unit="candidate records",
                                task="Hash matching not scheduled; no enabled hash indicators")
            return
        # Reuse the pinned, bounded archive reader through a caller-independent
        # file handle; do not read arbitrary bytes through a pathname race.
        from angerona.modules.adversary_combat import _PinnedFileMove
        from angerona.core.spyware_quarantine import _duplicate_descriptor
        scanned = 0
        selected = rows[self._hash_cursor:] + rows[:self._hash_cursor]
        for index, row in enumerate(selected):
            path = row.get("exe")
            if scanned >= 4 or cancelled():
                break
            self._scan_progress("hashes", completed=index, total=len(selected), unit="candidate records",
                                task="Selecting at most four eligible executable files", checked=scanned,
                                skipped=max(0, index - scanned))
            if not path:
                continue
            try:
                metadata = Path(path).stat()
                if not 0 < metadata.st_size <= 16 * 1024 * 1024:
                    continue
                scanned += 1
                self._hash_cursor = (rows.index(row) + 1) % len(rows)
                with _PinnedFileMove(Path(path)) as pinned:
                    pinned.require_single_link()
                    with os.fdopen(_duplicate_descriptor(pinned), "rb") as stream:
                        before = os.fstat(stream.fileno())
                        limit = 16 * 1024 * 1024
                        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                            continue
                        hashed, total = hashlib.sha256(), 0
                        deadline = time.monotonic() + 5
                        self._scan_progress("hashes", completed=index, total=len(selected), unit="candidate records",
                                            task="Hashing the current pinned executable", path=str(path), checked=scanned,
                                            skipped=max(0, index - scanned + 1),
                                            item_completed=0, item_total=before.st_size)
                        while True:
                            if cancelled() or time.monotonic() > deadline:
                                raise ValueError("hash-read-deadline")
                            chunk = stream.read(min(65536, limit - total + 1))
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > limit:
                                raise ValueError("hash-byte-limit")
                            hashed.update(chunk)
                            self._scan_progress("hashes", completed=index, total=len(selected), unit="candidate records",
                                                task="Hashing the current pinned executable", path=str(path), checked=scanned,
                                                skipped=max(0, index - scanned + 1),
                                                item_completed=total, item_total=before.st_size)
                        after = os.fstat(stream.fileno())
                        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                                 info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
                        if total != before.st_size or identity(before) != identity(after):
                            raise ValueError("hash-source-changed")
                        digest = hashed.hexdigest()
                if cancelled():
                    break
                # This opaque, short-lived token is created only after the
                # bounded pinned native read. Imported dictionaries cannot mint it.
                native_sample = object()
                with self._lock:
                    self._native_hash_samples[native_sample] = (
                        sample_generation, sample_stop, time.monotonic(), str(path), digest,
                        row.get("pid"), row.get("create_time"))
                try:
                    self._match_indicator({"pid": row.get("pid"),
                        "process_create_time": row.get("create_time"), "path": str(path),
                        "observed_content_sha256": digest}, "sha256", digest,
                        local_authority=True, native_sample=native_sample)
                finally:
                    with self._lock:
                        self._native_hash_samples.pop(native_sample, None)
            except (OSError, ValueError, RuntimeError):
                continue
        if not cancelled():
            self._scan_progress("hashes", state="completed", completed=len(selected), total=len(selected),
                                unit="candidate records", task="Bounded hash sample finished; at most four files attempted",
                                checked=scanned, skipped=max(0, len(selected) - scanned))

    def _export_rules(self) -> None:
        if self._config is None:
            raise ValueError("rule-export-config-unavailable")
        from angerona.core.engine_transport import private_directory
        from angerona.core.config import _atomic_write_text
        target_root = private_directory(Path(self._config.data_dir) / "spyware_guard")
        path = target_root / "candidate_rules.json"
        document = self._intel.export_candidates(now=self._clock())
        _atomic_write_text(path, json.dumps(document, indent=2, sort_keys=True) + "\n")
        with self._lock:
            self._coverage["rule_export"] = {"status": "staged", "path": str(path),
                "review_required": True, "active": False, "ts": self._clock()}

    def _hold_response_coverage(self, state: str, reason: str) -> None:
        # Retained receipt rows are history, never substitute current proof for a
        # journal view whose custody or integrity could not be established.
        with self._lock:
            previous = self._coverage.get("responses", {})
            self._coverage["responses"] = {
                "status": "partial", "state": state, "current": False,
                "reason": reason, "last_attempt_at": self._clock(),
                "last_verified_at": previous.get("last_verified_at"),
                "retained_rows": len(self._response_rows),
            }
        if not self.stopping and self.status != "error":
            self.set_health(50, "Preview; response receipt coverage is held; retained rows are historical")

    def _collect_responses(self) -> None:
        from angerona.modules.adversary_combat import JournalIntegrityError, JournalSnapshotBusy

        modules = getattr(self._manager, "modules", {})
        combat = modules.get("Adversary Combat") if isinstance(modules, dict) else None
        if combat is None or not callable(getattr(combat, "list_actions", None)):
            self._hold_response_coverage("unavailable", "Combat receipt provider is unavailable.")
            return
        try:
            listed = combat.list_actions(limit=200)
        except JournalIntegrityError as exc:
            busy = type(exc) is JournalSnapshotBusy
            self._hold_response_coverage(
                "busy" if busy else "integrity-held",
                "Combat journal custody is busy; retry occurs on the ordinary worker cadence."
                if busy else "Combat journal integrity or custody is held; no current receipt view is available.",
            )
            return
        # list_actions intentionally supports forensic prefixes on a non-strict
        # read. Its latched journal error or recovery circuit cannot become an
        # empty/current response view, nor trigger new archival work here.
        if getattr(combat, "_journal_error", "") or getattr(combat, "_mutation_blocked", False):
            self._hold_response_coverage(
                "integrity-held", "Combat journal integrity or recovery is held; retained rows are historical.",
            )
            return
        rows = [row for row in listed
                if (row.get("trigger_module") == self.name or
                    (row.get("trigger_module"), row.get("trigger_ts")) in self._upstream_events)
                and row.get("integrity_status") == "verified"
                and row.get("record_type") in {"commit", "recovery_required"}]
        with self._lock:
            self._response_rows = rows[:200]
            self._coverage["responses"] = {
                "status": "complete", "state": "current", "current": True,
                "reason": "Authenticated receipt lookup completed; rows remain historical action records.",
                "last_attempt_at": self._clock(), "last_verified_at": self._clock(),
                "retained_rows": len(self._response_rows),
            }
        for row in rows:
            receipt_id = row.get("action_id")
            if not isinstance(receipt_id, str):
                continue
            if receipt_id in self._receipt_ids:
                retry_at = self._receipt_ids[receipt_id]
                if retry_at is None or self._clock() < retry_at:
                    continue
            self._receipt_ids[receipt_id] = None
            while len(self._receipt_ids) > 1024:
                self._receipt_ids.popitem(last=False)
            if (row.get("action") != "quarantine_file" or row.get("status") != "applied"
                    or row.get("undone") is True or row.get("record_type") != "commit"):
                continue
            try:
                vault = self._ensure_vault()
                details = row.get("details") or {}
                sealed = vault.seal_file(details["quarantine"], details["sha256"])
                with self._lock:
                    self._vault_state = dict(sealed, status="encrypted-forensic-copy",
                        plaintext_quarantine_remains=True)
            except Exception as exc:
                self._receipt_ids[receipt_id] = self._clock() + 30
                with self._lock:
                    self._vault_state = {"status": "unavailable", "error": type(exc).__name__,
                                         "plaintext_quarantine_remains": True}

    def _ensure_vault(self):
        if self._vault is not None:
            return self._vault
        if self._config is None:
            raise ValueError("archive-config-unavailable")
        from angerona.core.secure_store import get_or_create_secret
        from angerona.core.spyware_quarantine import EncryptedQuarantine
        root = Path(self._config.data_dir)
        key_name = "SPYWAREGUARD_ARCHIVE_KEY"
        existing = get_or_create_secret(key_name, lambda: secrets.token_bytes(32).hex(), root)
        key = bytes.fromhex(existing)
        from angerona.core.engine_transport import private_directory
        private_directory(root / "spyware_guard")
        self._vault = EncryptedQuarantine(root / "spyware_guard" / "encrypted_evidence", key)
        return self._vault

    def _sandbox(self, scenario: str) -> list[dict]:
        now = [self._clock()]
        engine = SpywareBehaviorEngine(clock=lambda: now[0])
        base = {"pid": 45001, "process_create_time": now[0] - 20}
        findings = []
        if scenario == "dns_tunnel":
            for index in range(16):
                now[0] += 1
                findings += engine.observe(dict(base, event_type="dns_query", ts=now[0],
                    domain=f"{hashlib.sha256(str(index).encode()).hexdigest()[:48]}.example.org"))
        elif scenario == "exfiltration":
            for index in range(10):
                now[0] += 10
                sent = index * 1024 if index < 9 else 100 * 1024 * 1024
                findings += engine.observe(dict(base, event_type="network_egress", ts=now[0],
                                               bytes_sent=sent, encrypted=True))
        else:
            engine.observe(dict(base, event_type="media_render", role="renderer", ts=now[0]))
            now[0] += 1
            findings += engine.observe({"event_type": "process_start", "ts": now[0],
                "pid": 45002, "process_create_time": now[0], "parent_pid": base["pid"],
                "parent_create_time": base["process_create_time"], "process_name": "powershell.exe"})
        with self._lock:
            self._counts["sandbox_runs"] += 1
            self._coverage["last_sandbox"] = {"scenario": scenario, "findings": len(findings),
                "containment_performed": False, "ts": self._clock()}
        self.emit("SpywareGuard inert sandbox scenario completed.", Severity.INFO,
                  drill=True, scenario=scenario, detections=len(findings),
                  response_authorized=False, containment_performed=False)
        return findings

    def _tick(self) -> None:
        if not self._definitions_initialized:
            self._definitions_initialized = True
            try:
                self._ensure_definitions()
                self._cache_definition_snapshot()
            except (ValueError, OSError, RuntimeError) as exc:
                self._cache_definition_snapshot(error=f"Definition storage unavailable ({type(exc).__name__}).")
        if self._run_priority_scan():
            # Priority host work precedes discretionary command/report/news
            # work. Existing intake remains serviced after its bounded stage.
            self._consume_events()
            self._collect_responses()
            self._update_coverage_health()
            return
        self._process_commands()
        if self._definitions is not None:
            # Refresh expiry/generation summaries in the worker, never in Qt.
            with self._lock:
                error = self._definition_state.get("error", "")
            self._cache_definition_snapshot(error=error)
        self._ensure_report_worker()
        self._consume_events()
        self._collect_responses()
        now = self._clock()
        # Headline I/O stays on the research worker. Queue it before a long
        # host scan or general report jobs can postpone the visible feed.
        if self._settings["spyware_network_enabled"] and (
                self._last_news is None or now - self._last_news >= 1800):
            self._schedule_news()
        if self._scan_requested or self._last_scan is None or now - self._last_scan >= 300:
            self._scan_requested = False
            try:
                self._scan_once()
            except Exception as exc:
                with self._lock:
                    self._coverage["host"] = "error:" + type(exc).__name__
        if self._settings["spyware_network_enabled"] and (
                self._last_refresh is None or now - self._last_refresh >= 3600):
            self._last_refresh = now
            for source in OFFICIAL_SOURCES:
                if self.stopping:
                    break
                self._schedule_report("source", source)
        beacon = self._ensure_beacon()
        if beacon is not None:
            if self._settings["spyware_beacon_enabled"]:
                beacon.start_watchdog()
                beacon.heartbeat()
                self._dispatch_beacon(beacon)
            else:
                beacon.close(graceful=True)
                self._beacon = None
        self._update_coverage_health()

    def _update_coverage_health(self) -> None:
        if self.stopping or self.status == "error":
            return  # A real native retirement/restoration failure keeps its own diagnosis.
        with self._lock:
            responses_held = self._coverage.get("responses", {}).get("current") is not True
            gaps = (responses_held or self._coverage.get("event_bus") == "loss-detected"
                    or str(self._coverage.get("host", "")).startswith("error:"))
        detail = ("Preview; response receipt coverage is held; retained rows are historical"
                  if responses_held else "Preview; consult per-source coverage and adapter requirements")
        self.set_health(50 if gaps else 85, detail)

    def dashboard_snapshot(self) -> dict:
        with self._lock:
            result = {"hits": list(self._hits), "containments": list(self._containments),
                      "coverage": dict(self._coverage), "sources": list(self._sources),
                      "stats": dict(self._counts), "settings": dict(self._settings),
                      "last_scan": self._last_scan, "status": self.status,
                      "definitions": self._definition_state,
                      "scope": "preview; local exact-target containment; no actor attribution"}
            result["containments"] = self._response_rows + result["containments"]
            result["encrypted_evidence"] = dict(self._vault_state)
            result["sandbox"] = dict(self._coverage.get("last_sandbox", {}))
            now = self._clock()
            from angerona.core.spyware_news import MAX_CACHED_NEWS_AGE
            result["news"] = [row for row in self._news if 0 <= now - row["published"] <= MAX_CACHED_NEWS_AGE]
            result["news_status"] = dict(self._news_status,
                sources={name: dict(row) for name, row in self._news_status.get("sources", {}).items()})
            if not self._settings["spyware_network_enabled"]:
                result["news_status"].update(state="disabled", refreshing=False)
            result["coverage"]["behavior_adapters"] = self._engine.coverage()
        with self._intel.review_candidates(clock=self._clock) as candidates:
            with self._lock:
                now = self._clock()
                session, generation = self._review_session, self.lifecycle_generation
                result["indicators"] = []
                for item, identity in candidates:
                    if not item.fresh(now):
                        continue
                    result["indicators"].append(dict(asdict(item),
                        review_identity={"session": session, "generation": generation,
                                         "candidate": asdict(identity)},
                        approved=self._approved.get((item.kind, item.value)) == (session, generation, identity)))
                    if len(result["indicators"]) >= 500:
                        break
                result["indicator_review"] = dict(self._coverage.get("indicator_review", {}))
        result["vulnerabilities"] = len(self._intel.vulnerabilities(now=self._clock()))
        result["beacon"] = self._beacon.snapshot() if self._beacon is not None else {"enabled": False, "status": "disabled"}
        # Returning detached JSON state prevents UI code from mutating detection evidence.
        return json.loads(json.dumps(result, default=str))

    def run(self) -> None:
        try:
            self.seed_bus_cursor()
            while not self.stopping:
                self._tick()
                self.sleep(5, _wake_event=self._priority_scan_wake)
        finally:
            with self._lock:
                self._news_command_pending = None
                for source in self._news_jobs:
                    self._news_status.setdefault("sources", {})[source] = {
                        "state": "cancelled", "reason": "Module generation stopped; late results are held"}
                self._news_jobs.clear()
                self._news_pending.clear()
                self._news_status.update(state="stopped", refreshing=False, queued_reason="")
                job = self._priority_scan_job
                if (job is not None and job["generation"] == self.lifecycle_generation
                        and self._priority_scan_status["state"] in {"queued", "running"}):
                    job["cancel"].set()
                    self._priority_scan_status.update(state="cancelled", finished_at=self._clock(),
                                                     request_finished=True, collector_finished=True)
                    self._finish_scan_progress(job, "cancelled")
                self._priority_scan_wake.clear()
            self._report_stop.set()
            if self._report_thread is not None:
                self._report_thread.join(timeout=1.0)
            if self._beacon is not None:
                self._beacon.close(graceful=True)
                self._beacon = None

    def self_test(self) -> tuple[bool, str]:
        probe = SpywareGuardModule(clock=lambda: 1800000000.0)
        probe._settings["spyware_auto_contain"] = True
        finding = {"pid": 45001, "process_create_time": 1799999900.0}
        if (probe._response(finding, True) or probe._response(finding, False)
                or probe._response({"pid": 45001}, True)):
            return False, "An inert spyware sample was incorrectly admitted for response"
        for scenario, expected in (("dns_tunnel", "dns_tunneling_candidate"),
                                   ("exfiltration", "encrypted_egress_spike"),
                                   ("renderer_escape", "renderer_shell_child")):
            results = probe._sandbox(scenario)
            if not any(row["kind"] == expected and row["response_authorized"] is False for row in results):
                return False, f"Inert spyware fixture did not produce its expected advisory detection ({scenario})"
        clock = 1800000000.0
        benign = SpywareBehaviorEngine(clock=lambda: clock)
        if benign.observe({"event_type": "dns_query", "ts": clock, "pid": 45001,
                           "process_create_time": clock - 10, "domain": "static.example.net"}):
            return False, "Ordinary DNS triggered an unexpected spyware finding"
        if probe.dashboard_snapshot()["stats"]["sandbox_runs"] != 3 or probe.queue_report_url("http://127.0.0.1/"):
            return False, "Spyware sandbox accounting or report ingestion fixture failed"
        return True, "Inert DNS tunnel, encrypted egress spike and renderer-shell samples detected; benign DNS ignored"
