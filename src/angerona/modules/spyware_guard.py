"""SpywareGuard: bounded spyware evidence, intelligence and single-rule response.

Research prose is advisory. Only a local detector finding can request an exact
target response; Adversary Combat independently enforces its own host policy.
No country, vendor name, CVE, feed mention or sandbox probe is response authority.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import secrets
import stat
import threading
import time
from urllib.parse import urlsplit

from angerona.core.eventbus import Event, is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity
from angerona.core.response_contract import authorize_response
from angerona.core.spyware_behavior import SpywareBehaviorEngine
from angerona.core.spyware_definitions import DefinitionError, DefinitionStore, parse_definition_review
from angerona.core.spyware_intel import (
    OFFICIAL_SOURCES, IndicatorReviewIdentity, ThreatIntelStore, normalize_indicator,
    parse_indicator_review_identity,
)
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


class SpywareGuardModule(BaseModule):
    CODE = "SPYG"
    NAME = "SpywareGuard"
    name = NAME
    description = (
        "Advanced surveillanceware evidence, persistence and memory audits, NDR heuristics, "
        "reviewed intelligence, exact-target single-rule containment and emergency beacons."
    )
    category = "Spyware Defense"
    version = "1.14.0"
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
        self._news_status: dict = {"state": "disabled", "refreshing": False, "sources": {}}
        self._last_news = None
        self._review_session = secrets.token_hex(16)
        self._approved: OrderedDict[
            tuple[str, str], tuple[str, int, IndicatorReviewIdentity]
        ] = OrderedDict()
        self._dedup: OrderedDict[str, float] = OrderedDict()
        self._coverage: dict = {"host": "not-yet-scanned", "memory": "disabled"}
        self._engine = SpywareBehaviorEngine(clock=clock)
        self._advisory_engine = SpywareBehaviorEngine(clock=clock)
        self._last_scan = None
        self._last_refresh = None
        self._memory_cursor = 0
        self._hash_cursor = 0
        self._scan_requested = True
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
        return self._enqueue("news")

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
                    self._schedule_news()
            except Exception as exc:
                with self._lock:
                    self._coverage["last_command_error"] = type(exc).__name__
                    if command == "report":
                        self._sources.appendleft({"url": payload, "status": "failed",
                            "error": type(exc).__name__, "ts": self._clock()})
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

    def _schedule_news(self) -> None:
        if not self._settings["spyware_network_enabled"]:
            with self._lock:
                self._news_status.update(state="disabled", refreshing=False)
            return
        from angerona.core.spyware_news import NEWS_SOURCES
        self._last_news = self._clock()
        with self._lock:
            sources = [source for source in NEWS_SOURCES if source not in self._news_pending]
            if not sources:
                return
            self._news_pending.update(sources)
            self._news_status.update(state="refreshing", refreshing=True, last_attempt=self._clock(), error="")
            statuses = self._news_status.setdefault("sources", {})
            for source in sources:
                statuses[source] = {"state": "queued"}
        for source in sources:
            if not self._schedule_report("news", source):
                with self._lock:
                    self._news_pending.discard(source)
                    self._news_status["error"] = "QueueFull"
                    self._news_status["sources"][source] = {"state": "failed", "error": "QueueFull"}
        with self._lock:
            self._finish_news_status()

    def _finish_news_status(self) -> None:
        """Called under the state lock; failures never promote old cache to live."""
        statuses = list(self._news_status.get("sources", {}).values())
        failed = [row for row in statuses if row.get("state") == "failed"]
        successful = [row for row in statuses if row.get("state") == "available"]
        state = ("disabled" if not self._settings["spyware_network_enabled"] else
                 "refreshing" if self._news_pending else
                 "partial" if failed and successful else
                 "retry-required" if failed and all(row.get("error") == "QueueFull" for row in failed) else
                 "failed" if failed else
                 "current" if any(row.get("items", 0) for row in successful) else "empty")
        self._news_status.update(state=state, refreshing=bool(self._news_pending)
                                 and self._settings["spyware_network_enabled"])

    def _report_worker(self, stopped) -> None:
        # A slow research publisher must not delay single-rule host containment
        # or the independent watcher's heartbeat.
        while not stopped.is_set():
            try:
                kind, value = self._reports.get(timeout=0.5)
            except queue.Empty:
                continue
            url = OFFICIAL_SOURCES[value].url if kind == "source" else value
            try:
                if not self._settings["spyware_network_enabled"]:
                    continue
                if kind == "news":
                    from angerona.core.spyware_news import fetch_news_source
                    items = fetch_news_source(value, network_enabled=True, now=self._clock())
                    if not stopped.is_set() and self._settings["spyware_network_enabled"]:
                        with self._lock:
                            merged = {item["url"]: item for item in self._news + items}
                            self._news = sorted(merged.values(), key=lambda row: row["published"], reverse=True)[:30]
                            self._news_status.update(last_refresh=self._clock())
                            self._news_status.setdefault("sources", {})[value] = {
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
                            self._news_status["error"] = type(exc).__name__
                            self._news_status.setdefault("sources", {})[value] = {
                                "state": "failed", "error": type(exc).__name__, "checked_at": self._clock()}
                        self._sources.appendleft({"url": url, "status": "failed",
                            "error": type(exc).__name__, "ts": self._clock()})
            finally:
                if kind == "news":
                    with self._lock:
                        self._news_pending.discard(value)
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

    def _response(self, finding: dict, local_authority: bool) -> dict:
        if (not local_authority or not self._settings["spyware_auto_contain"]
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
        # The maintainer requested lockdown on the first rule. If no exact
        # process/peer/file exists, the only independently exact target is this
        # local endpoint. The response engine still applies host-policy gates.
        local_host = not actions
        if local_host:
            actions.append("isolate_host")
        return authorize_response(actions, pid=pid, process_create_time=birth,
                                  remote_ips=peers, path=path, local_host=local_host) if actions else {}

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
                 response_already_requested: bool = False) -> None:
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
        response = {} if response_already_requested else self._response(finding, local_authority)
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
                           disposition="active", detector_policy="single-rule-exact-target-containment")
            if "isolate_host" in response["response_contract"]["actions"]:
                # Response urgency reflects standing single-rule policy, while
                # the original observation and lack of attribution stay explicit.
                details["observed_severity"] = severity.name
                details["single_rule_host_fallback"] = True
                severity = Severity.CRITICAL
        summary = str(finding.get("summary") or finding.get("reason") or kind)[:1024]
        if (kind == "persistence_transient_payload" and finding.get("source") == "windows.run"
                and finding.get("reason") == "Persistence executes a payload from a temporary/public/download directory."):
            summary = ("Startup entry points to a temporary/public/download payload; "
                       "execution and maliciousness are unconfirmed.")
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

    def _match_indicator(self, record, kind, value, *, local_authority):
        normalized = normalize_indicator(kind, value)
        definition = self._definitions.lookup(kind, value) if self._definitions is not None else None
        if definition is not None:
            finding = {"kind": "definition_" + kind + "_indicator_match", "severity": "HIGH",
                       "summary": "Local evidence matched a locally activated spyware definition.",
                       "evidence": definition}
            for key in ("pid", "process_create_time", "remote_ip", "path", "observed_content_sha256"):
                if key in record:
                    finding[key] = record[key]
            self._publish(finding, local_authority=local_authority)
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
        self._publish(finding, local_authority=local_authority)

    def _scan_once(self) -> None:
        report = self._persistence(max_entries=512)
        with self._lock:
            self._coverage["persistence"] = report.get("coverage", {})
        for finding in report.get("findings", [])[:64]:
            # A configuration record alone does not identify a running process.
            self._publish(finding, local_authority=True)
        processes = self._processes()
        rows = list(processes.processes)[:4096]
        self._scan_hashes(rows)
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
                return memory_stopped.is_set() or memory_stopped is not self._stop
            for row in chosen:
                if retired():
                    memory_cancelled = True
                    break
                pid = row.get("pid")
                if type(pid) is not int or pid <= 4 or pid in {os.getpid(), os.getppid()}:
                    continue
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
                return
        else:
            with self._lock:
                self._coverage["memory"] = "disabled" if not self._settings["spyware_memory_enabled"] else "no-processes"
        snapshot = self._connections()
        indexed = {row.get("pid"): row for row in rows}
        for connection in snapshot.connections[:4096]:
            raw = str(connection.get("raddr", ""))
            try:
                address, _port = raw.rsplit(":", 1)
                peer = str(ipaddress.ip_address(address.strip("[]")))
            except ValueError:
                continue
            record = {"remote_ip": peer, "pid": connection.get("pid"),
                      "process_create_time": indexed.get(connection.get("pid"), {}).get("create_time")}
            self._match_indicator(record, "ip", peer, local_authority=True)
        with self._lock:
            self._coverage["connections"] = {"complete": snapshot.complete, "error": snapshot.error}
            self._coverage["host"] = "scan-completed-with-source-specific-coverage"
        self._last_scan = self._clock()

    def _scan_hashes(self, rows) -> None:
        with self._lock:
            wanted = any(kind == "sha256" for kind, _value in self._approved)
        wanted = wanted or (self._definitions is not None and self._definitions.has_hashes())
        if not wanted:
            return
        # Reuse the pinned, bounded archive reader through a caller-independent
        # file handle; do not read arbitrary bytes through a pathname race.
        from angerona.modules.adversary_combat import _PinnedFileMove
        from angerona.core.spyware_quarantine import _duplicate_descriptor
        scanned = 0
        selected = rows[self._hash_cursor:] + rows[:self._hash_cursor]
        for row in selected:
            path = row.get("exe")
            if scanned >= 4 or self.stopping:
                break
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
                        while True:
                            if self.stopping or time.monotonic() > deadline:
                                raise ValueError("hash-read-deadline")
                            chunk = stream.read(min(65536, limit - total + 1))
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > limit:
                                raise ValueError("hash-byte-limit")
                            hashed.update(chunk)
                        after = os.fstat(stream.fileno())
                        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                                 info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
                        if total != before.st_size or identity(before) != identity(after):
                            raise ValueError("hash-source-changed")
                        digest = hashed.hexdigest()
                self._match_indicator({"pid": row.get("pid"),
                    "process_create_time": row.get("create_time"), "path": str(path),
                    "observed_content_sha256": digest}, "sha256", digest, local_authority=True)
            except (OSError, ValueError, RuntimeError):
                continue

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

    def _collect_responses(self) -> None:
        modules = getattr(self._manager, "modules", {})
        combat = modules.get("Adversary Combat") if isinstance(modules, dict) else None
        if combat is None or not callable(getattr(combat, "list_actions", None)):
            return
        rows = [row for row in combat.list_actions(limit=200)
                if (row.get("trigger_module") == self.name or
                    (row.get("trigger_module"), row.get("trigger_ts")) in self._upstream_events)
                and row.get("integrity_status") == "verified"
                and row.get("record_type") in {"commit", "recovery_required"}]
        with self._lock:
            self._response_rows = rows[:200]
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

    def _sandbox(self, scenario: str) -> None:
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

    def _tick(self) -> None:
        if not self._definitions_initialized:
            self._definitions_initialized = True
            try:
                self._ensure_definitions()
                self._cache_definition_snapshot()
            except (ValueError, OSError, RuntimeError) as exc:
                self._cache_definition_snapshot(error=f"Definition storage unavailable ({type(exc).__name__}).")
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
        with self._lock:
            gaps = self._coverage.get("event_bus") == "loss-detected" or str(self._coverage.get("host", "")).startswith("error:")
        self.set_health(50 if gaps else 85, "Preview; consult per-source coverage and adapter requirements")

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
                self.sleep(5)
        finally:
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
        assert probe._response(finding, True).get("response_authorized") is True
        assert not probe._response(finding, False)
        assert probe._response({"pid": 45001}, True)["response_contract"]["actions"] == ["isolate_host"]
        for scenario in ("dns_tunnel", "exfiltration", "renderer_escape"):
            probe._sandbox(scenario)
        assert probe.dashboard_snapshot()["stats"]["sandbox_runs"] == 3
        assert not probe.queue_report_url("http://127.0.0.1/")
        return True, "Offline exact-target policy, inert sandbox and ingestion gates passed"
