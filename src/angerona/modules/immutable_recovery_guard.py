"""Observe-only guard for offline, immutable, and independently signed recovery."""
from __future__ import annotations

import base64
from collections import OrderedDict
import json
import os
import re
import queue
import secrets
import threading
import time
from pathlib import Path
from typing import Mapping

from angerona.core.module_base import BaseModule, Severity
from angerona.core.recovery_assurance import (
    RecoveryAssurancePolicy,
    assess_recovery_assurance,
    evidence_set_digest,
    load_recovery_evidence_directory,
)


_SHA = re.compile(r"^[0-9a-f]{40,64}$")
SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


def _read_trust_store(path: Path) -> dict[str, bytes]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("recovery trust store is not a bounded regular file")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or len(raw) > 32:
        raise ValueError("recovery trust store has an invalid schema")
    result: dict[str, bytes] = {}
    seen_keys: set[bytes] = set()
    for signer_id, encoded in raw.items():
        if not isinstance(signer_id, str) or not isinstance(encoded, str):
            raise ValueError("recovery trust store entry is invalid")
        try:
            public = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True,
            )
        except Exception as exc:
            raise ValueError("recovery trust store key encoding is invalid") from exc
        if len(public) != 32:
            raise ValueError("recovery trust store requires Ed25519 public keys")
        if public in seen_keys:
            raise ValueError("recovery trust store aliases one authority key")
        seen_keys.add(public)
        result[signer_id] = public
    return result


class ImmutableRecoveryGuardModule(BaseModule):
    CODE = "IRAG"
    NAME = "Immutable Recovery Assurance Guard"
    name = NAME
    description = (
        "Verifies externally signed backup-copy, failure-domain, immutability, "
        "air-gap, offsite, encryption, source-revision, and restore-test evidence."
    )
    category = "Resilience"
    version = "1.14.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    capability_permissions = ("event.emit", "operator-authorized-evidence-read", "private-isolated-restore-write")
    data_classes = ("signed-recovery-statement", "private-plaintext-test-restore")
    retention = "at-most-16-operator-reviewed-private-drill-directories; no-automatic-deletion"
    watchdog_work_budget_seconds = 180.0
    platform_requirements = (
        "Pinned Ed25519 recovery-authority public keys",
        "Evidence exported by independently administered backup targets",
    )
    _INTERVAL = 3600.0

    def __init__(
        self,
        *,
        evidence_dir: Path | None = None,
        trust_store_path: Path | None = None,
        trust_store: Mapping[str, bytes] | None = None,
        source_revision: str | None = None,
        clock=time.time,
    ) -> None:
        super().__init__()
        self._evidence_dir = Path(evidence_dir) if evidence_dir is not None else None
        self._trust_path = Path(trust_store_path) if trust_store_path is not None else None
        self._provided_trust = dict(trust_store) if trust_store is not None else None
        self._source_revision = source_revision
        self._clock = clock
        self._last_state = ""
        self._manager = None
        self._workflow = None
        self._commands = queue.Queue(maxsize=4)
        self._wake = threading.Event()
        self._work_units = 0
        self._command_lock = threading.RLock()
        self._command_requests = OrderedDict()

    def bind_manager(self, manager):
        self._manager = manager

    def _continue_recovery(self):
        if self.stopping or getattr(self._manager, "ugcap_paused", False):
            return False
        self._work_units += 1
        return self.background_checkpoint(self._work_units, batch_size=128)

    def _get_workflow(self):
        if self._workflow is None:
            from angerona.core.recovery_workflow import RecoveryWorkflow
            self._workflow = RecoveryWorkflow(self._profile_root(), source_revision=self._revision(),
                clock=self._clock, continue_work=self._continue_recovery)
        return self._workflow

    def _profile_root(self):
        from angerona.core.data_paths import data_dir
        config = getattr(self._manager, "config", None)
        root = getattr(config, "data_dir", None)
        return Path(root) if root else data_dir()

    @staticmethod
    def _wipe_keys(payload):
        for value in payload.get("keys") or ():
            if isinstance(value, bytearray):
                value[:] = b"\0" * len(value)

    def _queue_recovery(self, command, payload, *, return_ticket=False):
        # Admission observes one immutable BaseModule generation/stop token.
        # This brief lock never covers workflow IO or a worker wait.
        return_ticket = return_ticket is True
        with self._lifecycle_lock:
            generation, stop = self.lifecycle_generation, self.generation_stop_event()
            if (self.status != "running" or stop.is_set()
                    or getattr(self._manager, "ugcap_paused", False)
                    or return_ticket and generation <= 0):
                self._wipe_keys(payload)
                return False
            ticket = dict(request_id=secrets.token_hex(16), generation=generation, command=command)
            with self._command_lock:
                if self._commands.full():
                    self._wipe_keys(payload)
                    return False
                for _attempt in range(4):
                    if ticket["request_id"] not in self._command_requests:
                        break
                    ticket["request_id"] = secrets.token_hex(16)
                else:
                    self._wipe_keys(payload)
                    return False
                while len(self._command_requests) >= 16:
                    retired = next((key for key, value in self._command_requests.items()
                                    if value["state"] not in {"queued", "running"}), None)
                    if retired is None:
                        self._wipe_keys(payload)
                        return False
                    self._command_requests.pop(retired)
                self._command_requests[ticket["request_id"]] = dict(ticket, state="queued",
                    operation_settled=False, action_returned=False, completed=None, total=None,
                    workflow_status=None, error_type=None)
                try:
                    self._commands.put_nowait((command, payload, ticket, stop))
                except queue.Full:
                    self._command_requests.pop(ticket["request_id"], None)
                    self._wipe_keys(payload)
                    return False
            self._wake.set()
            return dict(ticket) if return_ticket else True

    def queue_tracked_recovery(self, method, *args, **kwargs):
        """Existing validated command methods, with a presentation-only ticket."""
        allowed = {"queue_enroll_recovery_authority", "queue_import_recovery_evidence",
                   "queue_restore_recovery", "queue_recheck_recovery", "queue_recovery_schedule"}
        if type(method) is not str or method not in allowed or "return_ticket" in kwargs:
            return False
        return getattr(self, method)(*args, **kwargs, return_ticket=True)

    def command_request_snapshot(self, ticket):
        """Memory only; no paths, payloads, keys, IO or response authority."""
        if (type(ticket) is not dict or set(ticket) != {"request_id", "generation", "command"}
                or type(ticket.get("request_id")) is not str
                or not re.fullmatch("[0-9a-f]{32}", ticket["request_id"])
                or type(ticket.get("generation")) is not int or ticket["generation"] < 0
                or type(ticket.get("command")) is not str
                or ticket.get("command") not in {"enroll", "import", "restore", "recheck", "schedule"}):
            return {"state": "unavailable", "operation_settled": False}
        with self._command_lock:
            row = self._command_requests.get(ticket["request_id"])
            if row is None or row["generation"] != ticket["generation"] or row["command"] != ticket.get("command"):
                return dict(ticket, state="unavailable", operation_settled=False)
            return dict(row)

    def _command_state(self, ticket, **values):
        if ticket is None:
            return
        with self._command_lock:
            row = self._command_requests.get(ticket["request_id"])
            if (row is not None and row["generation"] == ticket["generation"]
                    and row["command"] == ticket["command"] and row["state"] in {"queued", "running"}):
                row.update(values)

    @staticmethod
    def _local_path(path):
        return (isinstance(path, str) and 1 <= len(path) <= 32768 and Path(path).is_absolute()
                and not path.startswith(("\\\\", "//")) and not any(ord(c) < 32 for c in path))

    def queue_enroll_recovery_authority(self, signer_id, public_key, *, return_ticket=False):
        if (not isinstance(signer_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}", signer_id)
                or not isinstance(public_key, str) or not 1 <= len(public_key) <= 256):
            return False
        return self._queue_recovery("enroll", {"signer_id": signer_id, "public_key": public_key}, return_ticket=return_ticket)

    def queue_import_recovery_evidence(self, path, *, return_ticket=False):
        return self._local_path(path) and self._queue_recovery("import", {"path": path}, return_ticket=return_ticket)

    def queue_restore_recovery(self, archive, evidence, keys=None, *, return_ticket=False):
        if not self._local_path(archive) or not self._local_path(evidence):
            return False
        if keys is not None and (not isinstance(keys, tuple) or len(keys) != 2
                or any(not isinstance(key, bytearray) or len(key) not in (32, 64) for key in keys)):
            return False
        copies = tuple(bytearray(key) for key in keys) if keys is not None else None
        return self._queue_recovery("restore", {"archive": archive, "evidence": evidence, "keys": copies}, return_ticket=return_ticket)

    def queue_recheck_recovery(self, keys=None, *, return_ticket=False):
        if keys is not None and (not isinstance(keys, tuple) or len(keys) != 2
                or any(not isinstance(key, bytearray) or len(key) not in (32, 64) for key in keys)):
            return False
        copies = tuple(bytearray(key) for key in keys) if keys is not None else None
        return self._queue_recovery("recheck", {"keys": copies}, return_ticket=return_ticket)

    def queue_recovery_schedule(self, enabled, interval_hours=24, *, return_ticket=False):
        if type(enabled) is not bool or type(interval_hours) is not int or not 1 <= interval_hours <= 720:
            return False
        return self._queue_recovery("schedule", {"enabled": enabled, "interval_hours": interval_hours}, return_ticket=return_ticket)

    def _process_recovery_command(self):
        with self._command_lock:
            try:
                queued = self._commands.get_nowait()
            except queue.Empty:
                return
        command, payload = queued[:2]
        ticket, admitted_stop = queued[2:] if len(queued) == 4 else (None, self.generation_stop_event())
        worker_generation = getattr(self._run_context, "generation", self.lifecycle_generation)
        worker_stop = self.generation_stop_event()
        decoded_keys = []
        workflow = None
        state, action_returned, workflow_status, error_type = "failed", False, None, None
        try:
            if (ticket is not None and (ticket["generation"] != worker_generation
                    or admitted_stop is not worker_stop
                    or self.command_request_snapshot(ticket).get("state") != "queued")):
                raise InterruptedError("Recovery command generation no longer owns admission")
            self._command_state(ticket, state="running")
            if not self._continue_recovery():
                raise InterruptedError("Recovery workspace is held or worker stopped")
            workflow = self._get_workflow()
            if payload.get("keys") is not None:
                for key in payload["keys"]:
                    decoded_keys.append(bytearray.fromhex(key.decode("ascii")) if len(key) == 64 else bytearray(key))
            if command == "enroll":
                key = base64.b64decode(payload["public_key"], validate=True)
                workflow.enroll_authority(payload["signer_id"], key)
            elif command == "import":
                workflow.import_evidence(payload["path"])
            elif command == "restore":
                workflow.restore(payload["archive"], payload["evidence"], keys=tuple(decoded_keys) if decoded_keys else None)
            elif command == "recheck":
                workflow.recheck(keys=tuple(decoded_keys) if decoded_keys else None)
            elif command == "schedule":
                workflow.configure_schedule(payload["enabled"], payload["interval_hours"])
            else:
                raise ValueError("Unknown recovery command")
            action_returned = True
            workflow_status = str(workflow.snapshot().get("status", "unknown"))[:80]
            self.emit("Operator recovery workflow completed; review its scoped verification result.",
                      Severity.INFO, event_type="recovery_workflow", workflow_status=workflow_status,
                      request_id=ticket["request_id"] if ticket is not None else None,
                      command_generation=ticket["generation"] if ticket is not None else None,
                      response_authorized=False, observation_only=True)
            state = "completed"
        except Exception as exc:
            error_type = type(exc).__name__
            state = ("cancelled" if worker_stop.is_set() or ticket is not None and ticket["generation"] != worker_generation
                     else "held" if isinstance(exc, InterruptedError) else "failed")
            if workflow is not None:
                try:
                    workflow.failure(exc)
                    workflow_status = str(workflow.snapshot().get("status", "unknown"))[:80]
                except Exception:
                    self._command_state(ticket, failure_reporting_unavailable=True)
            try:
                self.emit("Operator recovery workflow is held or failed verification.", Severity.HIGH,
                          event_type="recovery_workflow", error_type=error_type,
                          request_id=ticket["request_id"] if ticket is not None else None,
                          command_generation=ticket["generation"] if ticket is not None else None,
                          response_authorized=False, observation_only=True, disposition="exposure")
            except Exception:
                self._command_state(ticket, event_delivery_unavailable=True)
        finally:
            self._wipe_keys(payload)
            for key in decoded_keys or ():
                key[:] = b"\0" * len(key)
            self._commands.task_done()
            # Every action is synchronous on this existing worker, including
            # isolated extraction, reread and proof writes. Keys are wiped
            # before this exact command becomes terminal. This is operation
            # settlement, not termination of the persistent guard thread.
            self._command_state(ticket, state=state, operation_settled=True,
                action_returned=action_returned, workflow_status=workflow_status, error_type=error_type)

    def _cancel_queued_recovery(self, generation):
        while True:
            with self._command_lock:
                try:
                    queued = self._commands.get_nowait()
                except queue.Empty:
                    return
                ticket = queued[2] if len(queued) == 4 else None
                if ticket is not None and ticket["generation"] != generation:
                    # All this module's queue writers share _command_lock;
                    # restoring the just-freed slot cannot lose a newer job.
                    self._commands.put_nowait(queued)
                    self._commands.task_done()
                    return
            self._wipe_keys(queued[1])
            self._commands.task_done()
            self._command_state(ticket, state="cancelled", operation_settled=True,
                                action_returned=False, error_type="GuardStoppedBeforeDispatch")

    def dashboard_snapshot(self):
        workflow = self._workflow
        result = workflow.snapshot() if workflow is not None else {
            "status": "deployment-required", "latest_verified_revision": None,
            "latest_restore_seconds": None, "schedule_enabled": False,
            "physical_independence_proven": False, "finding_codes": ["no recovery workflow performed"]}
        with self._command_lock:
            result = dict(result, command_requests=[dict(row) for row in self._command_requests.values()],
                          command_generation=self.lifecycle_generation)
        return result

    def _paths(self) -> tuple[Path, Path]:
        root = self._profile_root() / "recovery-assurance"
        return (
            self._evidence_dir or root / "evidence",
            self._trust_path or root / "trusted-authorities.json",
        )

    def _revision(self) -> str:
        value = self._source_revision or os.environ.get(
            "ANGERONA_SOURCE_REVISION", "",
        ).strip().casefold()
        # Source builds without injected release metadata are explicitly
        # unknown rather than being treated as current.
        return value if _SHA.fullmatch(value) else "0" * 40

    def observe_once(self) -> tuple[object, tuple[str, ...], str]:
        evidence_dir, trust_path = self._paths()
        trust = self._provided_trust
        if trust is None:
            trust = _read_trust_store(trust_path)
        copies, load_errors = load_recovery_evidence_directory(evidence_dir, trust)
        result = assess_recovery_assurance(
            copies, RecoveryAssurancePolicy(), now=float(self._clock()),
            source_revision=self._revision(),
        )
        digest = evidence_set_digest(copies)
        return result, load_errors, digest

    def run(self) -> None:
        next_observe = 0.0
        generation = getattr(self._run_context, "generation", self.lifecycle_generation)
        try:
            while not self.stopping:
                self._process_recovery_command()
                if self._workflow is not None:
                    try:
                        self._workflow.tick()
                    except Exception as exc:
                        self._workflow.failure(exc)
                if time.monotonic() < next_observe:
                    self._wake.wait(5.0)
                    self._wake.clear()
                    self.mark_cycle_complete(interval_seconds=5.0)
                    continue
                next_observe = time.monotonic() + self.background_interval(self._INTERVAL)
                self._observe_and_emit()
                self.mark_cycle_complete(interval_seconds=5.0)
        finally:
            try:
                if self._workflow is not None:
                    self._workflow.cancel_schedule()
            finally:
                self._cancel_queued_recovery(generation)

    def stop(self):
        super().stop()
        self._wake.set()

    def _observe_and_emit(self):
        try:
            result, load_errors, digest = self.observe_once()
            findings = tuple(load_errors) + tuple(result.findings)
            health = min(result.health, max(0, 100 - 15 * len(load_errors)))
            note = "recovery assurance verified" if not findings else "; ".join(findings[:3])
            self.set_health(health, note)
            state = f"{digest}:{health}:{'|'.join(findings)}"
            if state != self._last_state:
                self._last_state = state
                severity = Severity.INFO if not findings else (
                    Severity.CRITICAL if result.offline_copies == 0 else Severity.HIGH
                )
                self.emit(
                    "Recovery assurance verified." if not findings
                    else "Recovery assurance requirements are not met.",
                    severity,
                    evidence_set_sha256=digest,
                    verified_copies=result.verified_copies,
                    failure_domains=result.failure_domains,
                    signing_authorities=result.signing_authorities,
                    immutable_copies=result.immutable_copies,
                    offline_copies=result.offline_copies,
                    offsite_copies=result.offsite_copies,
                    source_revision_current=result.source_revision_current,
                    finding_codes=list(findings[:8]),
                    observation_only=True,
                    # Backup assurance is posture evidence. Missing copies
                    # must not manufacture an active hostile incident.
                    disposition="exposure",
                    response_authorized=False,
                    local_trust_root_replaceable_by_admin=True,
                )
        except Exception as exc:
            self.set_health(10, "recovery evidence verification failed closed")
            state = f"error:{type(exc).__name__}"
            if state != self._last_state:
                self._last_state = state
                self.emit(
                    "Recovery assurance verification failed closed.",
                    Severity.CRITICAL,
                    error_type=type(exc).__name__, observation_only=True,
                    disposition="exposure", response_authorized=False,
                )
        if self._workflow is not None:
            try:
                self._workflow.refresh_assurance()
            except Exception as exc:
                self._workflow.failure(exc)

    def self_test(self) -> tuple[bool, str]:
        try:
            # Pure policy proof: no evidence must never be reported healthy.
            result = assess_recovery_assurance(
                (), RecoveryAssurancePolicy(), now=1_000_000,
                source_revision="a" * 40,
            )
            ok = not result.healthy and result.offline_copies == 0 and result.health < 50
            return ok, (
                "fail-closed signed recovery policy verified; online F: mirrors "
                "do not count as immutable or offline"
            )
        except Exception as exc:
            return False, f"recovery assurance self-test failed: {type(exc).__name__}"


def register() -> ImmutableRecoveryGuardModule:
    return ImmutableRecoveryGuardModule()
