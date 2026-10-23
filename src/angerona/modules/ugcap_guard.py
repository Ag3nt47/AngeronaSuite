"""User-gated integrity challenges through an isolated, signed worker channel."""
from __future__ import annotations

from collections import deque
import importlib.util
import json
from pathlib import Path
import queue
import re
import threading
import time

from angerona.core.module_base import BaseModule, Severity
from angerona.core.response_contract import authorize_response
from angerona.core.ugcap_witness import WITNESS_DEFAULTS, WitnessAssessment, validate_settings


_DEFAULTS = {
    "ugcap_enabled": False, "ugcap_cadence_hours": 168,
    "ugcap_vault_path": "", "ugcap_key_name": "Angerona.UGCAP.v1", "ugcap_lockdown": True,
}
_DEFAULTS.update(WITNESS_DEFAULTS)


def _wipe(value) -> None:
    if isinstance(value, bytearray):
        for index in range(len(value)):
            value[index] = 0


class UGCAPGuardModule(BaseModule):
    CODE = "UGCP"
    name = "UGCAP Integrity Guard"
    description = (
        "User-gated BLAKE3 integrity vault, TPM-bound encrypted baseline, signed isolated "
        "verification worker, managed-workspace circuit breaker and reviewed source recovery."
    )
    category = "Integrity"
    version = "1.14.0"
    supported_platforms = ("windows", "macos", "linux")
    capability_mode = "protect"
    maturity_channel = "preview"
    capability_inputs = ("explicit-user-challenge", "offline-vault", "hardware-key-proof", "opt-in-pinned-witness")
    capability_outputs = ("integrity-diff", "workspace-gate", "host-isolation-request", "witness-assurance")
    capability_permissions = ("protected-source-read", "user-approved-source-restore", "event.emit", "network.connect")
    high_risk_permissions = ("user-approved-source-restore",)
    data_classes = ("source-manifest", "encrypted-backup", "integrity-diff", "hash-only-witness-checkpoint")
    egress = "optional"
    retention = "encrypted-secondary-media-baseline-and-audit; bounded-public-runtime-status"
    response_authority = "typed-response"
    platform_requirements = (
        "Optional BLAKE3 package; separately attached secondary volume",
        "Explicit user passcode for every operation",
        "Provisioned Windows TPM2 key; other hardware backends unavailable",
        "Witness opt-in requires separately administered private mTLS / Ed25519 enrollment",
    )
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = "missing-proof-stays-locked; incomplete-verification-never-resumes"
    source_health_semantics = ("hardware-required", "no-password-only-fallback", "coverage-gap-is-unknown")
    resource_budget = {"worker_model": "isolated-worker-and-bounded-secret-command-queue",
                       "event_delivery": "signed-encrypted-ipc", "startup_cycle_timeout_seconds": 180.0}
    watchdog_work_budget_seconds = 180.0
    settings_schema = {"type": "object", "properties": {
        "ugcap_enabled": {"type": "boolean", "default": False},
        "ugcap_cadence_hours": {"type": "integer", "minimum": 1, "maximum": 8760},
        "ugcap_vault_path": {"type": "string"}, "ugcap_key_name": {"type": "string"},
        "ugcap_lockdown": {"type": "boolean", "default": True},
        **{name: {"type": "boolean" if type(default) is bool else "string", "default": default}
           for name, default in WITNESS_DEFAULTS.items()}}, "additionalProperties": False}

    def __init__(self, *, clock=time.time, daemon_factory=None, witness_factory=None) -> None:
        super().__init__()
        self._clock = clock
        self._daemon_factory = daemon_factory
        self._daemon = None
        self._manager = None
        self._config = None
        self._settings = dict(_DEFAULTS)
        self._commands: queue.Queue = queue.Queue(maxsize=4)
        self._wake = threading.Event()
        self._state_lock = threading.RLock()
        self._state = "disabled"
        self._report: dict = {}
        self._result: dict = {}
        self._hardware: dict = {"available": False, "status": "not-probed"}
        self._coverage: dict = {"blake3_available": importlib.util.find_spec("blake3") is not None,
                                "worker": "not-started", "hardware": "not-probed"}
        self._error = ""
        self._verified_at = None
        self._challenge_requested = False
        self._authorization_epoch = 0
        self._history = deque(maxlen=50)
        self._witness_factory = witness_factory
        self._witness = None
        self._witness_checkpoint = None
        self._witness_public_key = ""
        self._witness_next = 0.0
        self._witness_backoff = 30.0
        self._witness_succeeded_at = None
        self._witness_status = WitnessAssessment("deployment-required", "local-chain-only").snapshot()

    def bind_manager(self, manager) -> None:
        self._manager = manager
        self._config = getattr(manager, "config", None)
        for key, default in _DEFAULTS.items():
            value = getattr(self._config, key, default)
            if type(value) is type(default):
                self._settings[key] = value
        if self._settings["ugcap_enabled"]:
            self._state = "user-challenge-required"

    def _queue(self, command: str, payload: dict) -> bool:
        try:
            self._commands.put_nowait((command, payload))
            self._wake.set()
            return True
        except queue.Full:
            _wipe(payload.get("secret"))
            return False

    @staticmethod
    def _valid_vault_path(path) -> bool:
        return (isinstance(path, str) and 1 <= len(path) <= 32768
                and Path(path).is_absolute() and not path.startswith(("\\\\", "//")))

    def _secret_command(self, command, vault_path, passcode, **extra) -> bool:
        if getattr(self._manager, "requires_ugcap_restart", False) is True:
            with self._state_lock:
                self._state = "restart-required"
                self._coverage["restart"] = "Enable UGCAP and restart before providing a vault passcode."
            return False
        if (not self._valid_vault_path(vault_path) or not isinstance(passcode, bytearray)
                or not 12 <= len(passcode) <= 1024):
            return False
        with self._state_lock:
            self._authorization_epoch += 1
            epoch = self._authorization_epoch
        return self._queue(command, {"vault_path": vault_path, "secret": bytearray(passcode),
                                     "_epoch": epoch, **extra})

    def queue_initialize(self, vault_path, passcode) -> bool:
        return self._secret_command("initialize", vault_path, passcode)

    def queue_verify(self, vault_path, passcode) -> bool:
        return self._secret_command("verify", vault_path, passcode)

    def queue_restore(self, vault_path, passcode, paths, report_id) -> bool:
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 128
                or any(not isinstance(path, str) or len(path) > 2048 for path in paths)
                or not isinstance(report_id, str) or not 1 <= len(report_id) <= 128):
            return False
        return self._secret_command("restore", vault_path, passcode, paths=list(paths), report_id=report_id)

    def queue_provision_hardware(self, key_name: str) -> bool:
        if not isinstance(key_name, str) or re.fullmatch(r"Angerona\.UGCAP\.[A-Za-z0-9_-]{1,96}", key_name) is None:
            return False
        return self._queue("provision", {"key_name": key_name})

    def queue_provision_witness_key(self) -> bool:
        return self._queue("witness-key", {})

    def queue_probe_witness(self) -> bool:
        return self._queue("witness-probe", {})

    def queue_lock(self) -> bool:
        with self._state_lock:
            self._authorization_epoch += 1
            self._state = "user-challenge-required"
            self._verified_at = None
            self._challenge_requested = True
        if self._manager is not None:
            self._pause("UGCAP workspace locked by the operator")
        return self._queue("lock", {})

    def configure_settings(self, **kwargs) -> dict:
        for key, value in kwargs.items():
            if key not in _DEFAULTS or type(value) is not type(_DEFAULTS[key]):
                return {"queued": False}
            if key == "ugcap_cadence_hours" and not 1 <= value <= 8760:
                return {"queued": False}
            if key == "ugcap_vault_path" and value and not self._valid_vault_path(value):
                return {"queued": False}
            if key == "ugcap_key_name" and re.fullmatch(r"Angerona\.UGCAP\.[A-Za-z0-9_-]{1,96}", value) is None:
                return {"queued": False}
        try:
            validate_settings({name: kwargs.get(name, self._settings[name]) for name in WITNESS_DEFAULTS})
        except (ValueError, RuntimeError, UnicodeError):
            return {"queued": False}
        if kwargs:
            with self._state_lock:
                self._authorization_epoch += 1
        if kwargs.get("ugcap_enabled") is True and self._manager is not None:
            enable = getattr(self._manager, "set_enabled", None)
            if callable(enable):
                enable(self.name, True)
        return {"queued": bool(kwargs) and self._queue("settings", dict(kwargs))}

    def _pause(self, reason: str) -> None:
        if self._manager is None or not callable(getattr(self._manager, "pause_for_ugcap", None)):
            raise RuntimeError("UGCAP managed-workspace gate unavailable")
        held = self._manager.pause_for_ugcap(reason)
        freeze = getattr(self._manager, "freeze_enclave_mesh", None)
        if callable(freeze):
            freeze()
        with self._state_lock:
            self._coverage["workspace"] = held
        self.emit("UGCAP user challenge holds the managed workspace.", Severity.HIGH,
                  event_type="ugcap_gate_changed", response_authorized=False,
                  workspace_locked=True, active_attack=False)

    def _ensure_daemon(self):
        if self._daemon is None:
            if self._daemon_factory is None:
                from angerona.core.ugcap_worker import UGCAPDaemonClient
                self._daemon_factory = UGCAPDaemonClient
            root = Path(getattr(self._config, "data_dir", Path.cwd()))
            self._daemon = self._daemon_factory(root)
        return self._daemon

    def _execute(self, command: str, payload: dict) -> dict:
        root = Path(__file__).resolve().parents[3]
        import sys
        if getattr(sys, "frozen", False):
            root = Path(sys.executable).resolve().parent
        public = {key: value for key, value in payload.items() if key not in {"secret", "_epoch"}}
        public.update(repo_root=str(root), key_name=public.get("key_name", self._settings["ugcap_key_name"]))
        return self._ensure_daemon().execute(command, public, secret=payload.get("secret"), timeout=150.0)

    def _trip(self, report: dict) -> None:
        with self._state_lock:
            self._state = "drift-locked"
        response = (authorize_response(("isolate_host",), local_host=True)
                    if self._settings["ugcap_lockdown"] else {})
        self.emit("UGCAP found divergence from the user-enrolled golden baseline.", Severity.CRITICAL,
                  event_type="ugcap_divergence", report_id=report.get("report_id", ""),
                  active_attack=bool(response), disposition="active" if response else "observation",
                  detector_policy="user-gated-golden-baseline-divergence",
                  response_authorized=bool(response), **{key: value for key, value in response.items()
                                                        if key != "response_authorized"})
        if getattr(self._config, "spyware_beacon_enabled", False) is True:
            from angerona.core.spyware_beacon import EmergencyBeacon
            beacon = EmergencyBeacon(self._config)
            beacon.enqueue({"incident_id": report.get("report_id"), "rule_code": "UGCAP_DRIFT",
                            "severity": "CRITICAL"})
            def deliver():
                try:
                    beacon.tick()
                finally:
                    beacon.close(graceful=True)
            threading.Thread(target=deliver, name="UGCAPEmergencyBeacon", daemon=True).start()

    def _proof_current(self, epoch: int) -> bool:
        with self._state_lock:
            return epoch == self._authorization_epoch and not self.stopping

    @staticmethod
    def _public_report(report: dict) -> dict:
        result = {key: value for key, value in report.items() if key not in {"verified_files", "observations"}}
        receipt = result.get("verification_receipt")
        if isinstance(receipt, dict):
            result["verification_receipt"] = {key: value for key, value in receipt.items()
                                               if key != "verified_files"}
        return result

    def _accept_report(self, report: dict, epoch: int) -> None:
        if not self._proof_current(epoch):
            return
        with self._state_lock:
            self._report = self._public_report(report)
        if report.get("status") == "verified":
            if not self._check_witness(report.get("witness_checkpoint")):
                with self._state_lock:
                    self._state = "witness-held"
                return
            if not self._proof_current(epoch):
                return
            activate = getattr(self._manager, "activate_enclave_mesh", None)
            if not callable(activate) or activate(report) is not True:
                raise RuntimeError("UGCAP mesh activation proof unavailable")
            if not self._proof_current(epoch):
                freeze = getattr(self._manager, "freeze_enclave_mesh", None)
                if callable(freeze):
                    freeze()
                return
            def permit(open_gate):
                with self._state_lock:
                    if epoch != self._authorization_epoch or self.stopping:
                        return False
                    open_gate()
                    self._verified_at = self._clock()
                    self._challenge_requested = False
                    return True
            resumed = self._manager.resume_after_ugcap(permit=permit)
            if resumed.get("paused") is not False or not self._proof_current(epoch):
                return
            with self._state_lock:
                if epoch != self._authorization_epoch or self.stopping:
                    return
                self._state = "verified"
                self.emit("UGCAP verification matched; managed workers may resume.", Severity.INFO,
                          event_type="ugcap_gate_changed", workspace_locked=False,
                          response_authorized=False, report_id=report.get("report_id"))
        elif report.get("status") == "drift":
            self._trip(report)
        else:
            with self._state_lock:
                self._state = "incomplete-locked"

    def _invalidate_witness(self):
        """Worker-only: cached proof belongs to exactly the previous enrollment/key."""
        with self._state_lock:
            required = self._settings["ugcap_witness_enabled"]
            self._witness_status = WitnessAssessment(
                "verification-checkpoint-required" if required else "deployment-required",
                "unverified-witness" if required else "local-chain-only").snapshot()
            self._witness_succeeded_at = None
            self._witness_checkpoint = None
            self._witness = None
            self._witness_next = 0.0
            self._witness_backoff = 30.0

    def _check_witness(self, observation=None, *, heartbeat=False) -> bool:
        """Runs only on this module's worker. No evidence grants response authority."""
        enabled = self._settings["ugcap_witness_enabled"]
        if not enabled:
            with self._state_lock:
                self._witness_status = WitnessAssessment("deployment-required", "local-chain-only").snapshot()
                self._witness_succeeded_at = None
            return True
        if observation is not None:
            self._witness_checkpoint = observation
        if self._witness_checkpoint is None:
            status = WitnessAssessment("verification-checkpoint-required", "unverified-witness")
        else:
            try:
                if self._witness is None:
                    factory = self._witness_factory
                    if factory is None:
                        from angerona.core.ugcap_witness import client_from_settings
                        factory = client_from_settings
                    self._witness = factory({name: self._settings[name] for name in WITNESS_DEFAULTS},
                                            Path(getattr(self._config, "data_dir", Path.cwd())))
                status = self._witness.exchange(self._witness_checkpoint, heartbeat=heartbeat)
                if not isinstance(status, WitnessAssessment):
                    raise RuntimeError("invalid witness assessment")
            except Exception:
                status = WitnessAssessment("unreachable-or-rejected", "unverified-witness")
        with self._state_lock:
            previous = self._witness_status.get("status")
            self._witness_status = status.snapshot()
            if status.gate_allowed:
                self._witness_succeeded_at = time.monotonic()
        self._witness_backoff = 30.0 if status.gate_allowed else min(300.0, self._witness_backoff * 2)
        self._witness_next = time.monotonic() + self._witness_backoff
        if not status.gate_allowed:
            if self._manager is not None and not getattr(self._manager, "ugcap_paused", False):
                self._pause("UGCAP opted-in independent witness is unavailable or conflicts with the local audit")
            with self._state_lock:
                self._state = "witness-held"
            if previous != status.status:
                self.emit("UGCAP witness assurance is unavailable or reports a retained-head conflict.",
                          Severity.HIGH, event_type="ugcap_witness_gap", witness_status=status.status,
                          response_authorized=False, active_attack=False, workspace_locked=True)
        return status.gate_allowed

    def _process_one(self) -> None:
        try:
            command, payload = self._commands.get_nowait()
        except queue.Empty:
            return
        try:
            if command == "settings":
                if self._config is not None:
                    previous = {key: getattr(self._config, key, _DEFAULTS[key]) for key in payload}
                    try:
                        for key, value in payload.items():
                            setattr(self._config, key, value)
                        self._config.save()
                    except Exception:
                        for key, value in previous.items():
                            setattr(self._config, key, value)
                        raise
                with self._state_lock:
                    self._settings.update(payload)
                    if any(name in WITNESS_DEFAULTS for name in payload):
                        self._invalidate_witness()
                if payload.get("ugcap_enabled") is True:
                    self._verified_at = None
                    self._challenge_requested = False
            elif command == "lock":
                self._pause("UGCAP workspace locked by the operator")
                if self._daemon is not None:
                    self._daemon.execute("lock", {}, secret=None, timeout=15)
                with self._state_lock:
                    self._state = "user-challenge-required"
                self._verified_at = None
                self._challenge_requested = True
            elif command == "provision":
                result = self._execute(command, payload)
                with self._state_lock:
                    self._hardware = result
                    self._result = self._public_report(result)
            elif command == "witness-key":
                from angerona.core.ugcap_witness import provision_host_identity
                # Provision can discover lost/changed key custody or fail. Clear
                # prior credit before touching the provider, including on failure.
                with self._state_lock:
                    self._invalidate_witness()
                    self._witness_public_key = ""
                public_key = provision_host_identity(Path(getattr(self._config, "data_dir", Path.cwd())))
                with self._state_lock:
                    self._witness_public_key = public_key
            elif command == "witness-probe":
                self._check_witness(heartbeat=True)
            else:
                epoch = payload.get("_epoch", -1)
                if not self._proof_current(epoch):
                    return
                self._pause("UGCAP verification in progress")
                with self._state_lock:
                    self._state = "verifying" if command != "restore" else "restoring"
                    self._error = ""
                result = self._execute(command, payload)
                if not self._proof_current(epoch):
                    with self._state_lock:
                        self._state = "challenge-revoked"
                    return
                with self._state_lock:
                    self._result = self._public_report(result)
                    self._coverage["worker"] = "isolated-signed-channel"
                if command == "initialize":
                    self._accept_report(self._execute("verify", payload), epoch)
                elif command == "restore":
                    if (not result.get("restart_required") and not result.get("deferred")
                            and not result.get("non_restorable") and not result.get("errors")
                            and not result.get("recovery_required")
                            and result.get("status") in {"restored", "verified", "unchanged"}):
                        self._accept_report(self._execute("verify", payload), epoch)
                    else:
                        with self._state_lock:
                            self._state = "restart-required" if result.get("restart_required") else "offline-recovery-required"
                else:
                    self._accept_report(result, epoch)
        except Exception as exc:
            with self._state_lock:
                self._error = type(exc).__name__
                self._state = "error-locked" if getattr(self._manager, "ugcap_paused", False) else "unavailable"
            self.emit("UGCAP operation could not establish the required proof.", Severity.HIGH,
                      event_type="ugcap_operation_failed", operation=command,
                      error_type=type(exc).__name__, response_authorized=False)
        finally:
            _wipe(payload.get("secret"))
            self._commands.task_done()

    def _tick(self) -> None:
        self._process_one()
        if (self._settings["ugcap_enabled"] and self._settings["ugcap_witness_enabled"]
                and time.monotonic() >= self._witness_next):
            self._check_witness(heartbeat=True)
        if self._settings["ugcap_enabled"] and not self._challenge_requested:
            due = self._verified_at is None or (
                self._clock() - self._verified_at >= self._settings["ugcap_cadence_hours"] * 3600)
            if due:
                self._pause("UGCAP scheduled user challenge required")
                self._challenge_requested = True
                with self._state_lock:
                    self._state = ("restart-required" if getattr(self._manager, "requires_ugcap_restart", False)
                                   else "user-challenge-required")
        self.set_health(90 if self._state == "verified" else 50,
                        "User-gated preview; see vault, hardware, worker and workspace coverage")
        mesh_snapshot = getattr(self._bus, "mesh_snapshot", None)
        if callable(mesh_snapshot):
            mesh = mesh_snapshot()
            with self._state_lock:
                self._coverage["enclave_mesh"] = mesh

    def dashboard_snapshot(self) -> dict:
        with self._state_lock:
            result = {"status": self._state, "settings": dict(self._settings),
                      "report": dict(self._report), "result": dict(self._result),
                      "recovery": dict(self._result), "hardware": dict(self._hardware),
                      "coverage": dict(self._coverage), "error": self._error,
                      "workspace_locked": getattr(self._manager, "ugcap_paused", False),
                      "last_verified_at": self._verified_at}
            result["witness"] = dict(self._witness_status)
            if not self._settings["ugcap_witness_enabled"]:
                result["witness"] = WitnessAssessment("deployment-required", "local-chain-only").snapshot()
            elif (self._witness_status.get("gate_allowed")
                    and (self._witness_succeeded_at is None
                         or not 0 <= time.monotonic() - self._witness_succeeded_at <= 90)):
                result["witness"].update(status="stale", assurance="unverified-witness", gate_allowed=False)
            result["witness_host_public_key"] = self._witness_public_key
        return json.loads(json.dumps(result, default=str))

    def run(self) -> None:
        try:
            while not self.stopping:
                self._tick()
                self.mark_cycle_complete(interval_seconds=5.0)
                self._wake.wait(5.0)
                self._wake.clear()
        finally:
            while True:
                try:
                    _command, payload = self._commands.get_nowait()
                    _wipe(payload.get("secret"))
                    self._commands.task_done()
                except queue.Empty:
                    break
            if self._daemon is not None:
                self._daemon.close()
                self._daemon = None
            self._witness = None

    def stop(self) -> None:
        with self._state_lock:
            self._authorization_epoch += 1
        super().stop()
        self._wake.set()

    def self_test(self) -> tuple[bool, str]:
        probe = UGCAPGuardModule()
        borrowed = bytearray(b"inert-selftest-passphrase")
        assert not probe.queue_verify("relative.ugcap", borrowed)
        assert not probe.configure_settings(ugcap_enabled="true")["queued"]
        assert probe.queue_lock()
        secret = bytearray(borrowed)
        _wipe(secret)
        assert not any(secret) and any(borrowed)
        return True, "Offline queue, passcode-buffer and circuit contract checks; live TPM not exercised"
