"""Observe-only guard for offline, immutable, and independently signed recovery."""
from __future__ import annotations

import base64
import json
import os
import re
import queue
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

    def _queue_recovery(self, command, payload):
        if (self.status != "running" or self.stopping
                or getattr(self._manager, "ugcap_paused", False)):
            self._wipe_keys(payload)
            return False
        try:
            self._commands.put_nowait((command, payload))
            self._wake.set()
            return True
        except queue.Full:
            self._wipe_keys(payload)
            return False

    @staticmethod
    def _local_path(path):
        return (isinstance(path, str) and 1 <= len(path) <= 32768 and Path(path).is_absolute()
                and not path.startswith(("\\\\", "//")) and not any(ord(c) < 32 for c in path))

    def queue_enroll_recovery_authority(self, signer_id, public_key):
        if (not isinstance(signer_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}", signer_id)
                or not isinstance(public_key, str) or not 1 <= len(public_key) <= 256):
            return False
        return self._queue_recovery("enroll", {"signer_id": signer_id, "public_key": public_key})

    def queue_import_recovery_evidence(self, path):
        return self._local_path(path) and self._queue_recovery("import", {"path": path})

    def queue_restore_recovery(self, archive, evidence, keys=None):
        if not self._local_path(archive) or not self._local_path(evidence):
            return False
        if keys is not None and (not isinstance(keys, tuple) or len(keys) != 2
                or any(not isinstance(key, bytearray) or len(key) not in (32, 64) for key in keys)):
            return False
        copies = tuple(bytearray(key) for key in keys) if keys is not None else None
        return self._queue_recovery("restore", {"archive": archive, "evidence": evidence, "keys": copies})

    def queue_recheck_recovery(self, keys=None):
        if keys is not None and (not isinstance(keys, tuple) or len(keys) != 2
                or any(not isinstance(key, bytearray) or len(key) not in (32, 64) for key in keys)):
            return False
        copies = tuple(bytearray(key) for key in keys) if keys is not None else None
        return self._queue_recovery("recheck", {"keys": copies})

    def queue_recovery_schedule(self, enabled, interval_hours=24):
        if type(enabled) is not bool or type(interval_hours) is not int or not 1 <= interval_hours <= 720:
            return False
        return self._queue_recovery("schedule", {"enabled": enabled, "interval_hours": interval_hours})

    def _process_recovery_command(self):
        try:
            command, payload = self._commands.get_nowait()
        except queue.Empty:
            return
        decoded_keys = []
        workflow = self._get_workflow()
        try:
            if not self._continue_recovery():
                raise InterruptedError("Recovery workspace is held or worker stopped")
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
            self.emit("Operator recovery workflow completed; review its scoped verification result.",
                      Severity.INFO, event_type="recovery_workflow", workflow_status=workflow.snapshot()["status"],
                      response_authorized=False, observation_only=True)
        except Exception as exc:
            workflow.failure(exc)
            self.emit("Operator recovery workflow is held or failed verification.", Severity.HIGH,
                      event_type="recovery_workflow", error_type=type(exc).__name__,
                      response_authorized=False, observation_only=True, disposition="exposure")
        finally:
            self._wipe_keys(payload)
            for key in decoded_keys or ():
                key[:] = b"\0" * len(key)
            self._commands.task_done()

    def dashboard_snapshot(self):
        workflow = self._workflow
        return workflow.snapshot() if workflow is not None else {
            "status": "deployment-required", "latest_verified_revision": None,
            "latest_restore_seconds": None, "schedule_enabled": False,
            "physical_independence_proven": False, "finding_codes": ["no recovery workflow performed"]}

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
            if self._workflow is not None:
                self._workflow.cancel_schedule()
            while True:
                try:
                    _command, payload = self._commands.get_nowait()
                    self._wipe_keys(payload)
                    self._commands.task_done()
                except queue.Empty:
                    break

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
