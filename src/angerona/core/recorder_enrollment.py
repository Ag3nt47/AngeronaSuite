"""Runtime-owned, explicitly requested public recorder identity enrollment.

Construction/getters do no secure-store I/O. A single retained non-daemon
worker resolves the existing key through recorder_integrity's known action.
Closing a settings window does not own or cancel this task; the App must drain
the owner on STOP before retiring its runtime/security-store custody.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import threading


@dataclass(frozen=True)
class RecorderEnrollmentStatus:
    state: str = "idle"
    public_key: str = ""
    error: str = ""
    revision: int = 0


_OWNERS_LOCK = threading.Lock()
_LIVE_OWNERS: list[object] = []
_RETIREMENT_HOLDS: list[object] = []


class RecorderEnrollmentOwner:
    def __init__(self, data_root: Path):
        self._root = Path(data_root)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._retired = threading.Event()
        self._retired.set()
        self._thread = None
        self._status = RecorderEnrollmentStatus()
        self._start_uncertain = False
        self._join_uncertain = False
        self._write_admitted = False

    def latest_status(self) -> RecorderEnrollmentStatus:
        """Memory-only immutable DTO; never reads keys or waits for a worker."""
        with self._lock:
            return self._status

    def _publish(self, state: str, *, public_key: str = "", error: str = "") -> None:
        self._status = RecorderEnrollmentStatus(state, public_key, error, self._status.revision + 1)

    def _retain(self, *, hold: bool) -> None:
        with _OWNERS_LOCK:
            if not any(owner is self for owner in _LIVE_OWNERS):
                _LIVE_OWNERS.append(self)
            if hold and not any(owner is self for owner in _RETIREMENT_HOLDS):
                _RETIREMENT_HOLDS.append(self)

    def _release(self) -> None:
        with _OWNERS_LOCK:
            _LIVE_OWNERS[:] = [owner for owner in _LIVE_OWNERS if owner is not self]
            _RETIREMENT_HOLDS[:] = [owner for owner in _RETIREMENT_HOLDS if owner is not self]

    def request(self) -> bool:
        with self._lock:
            with _OWNERS_LOCK:
                held = bool(_RETIREMENT_HOLDS)
            if self._start_uncertain or self._join_uncertain or held:
                self._publish("retirement-held", error="Identity worker retirement is unproven; replacement is held.")
                return False
            if self._stop.is_set():
                return False
            prior = self._thread
            if prior is not None:
                if not self._retired.is_set() or prior.ident is None or prior.is_alive():
                    return False
                try:
                    prior.join(0)
                except BaseException:
                    self._join_uncertain = True
                    self._retain(hold=True)
                    self._publish("retirement-held", error="Identity worker retirement remains unproven.")
                    return False
                # An actual dead, completed thread needs no further native
                # drain. Successful public identity is reused without writes.
                if self._status.state == "ready":
                    self._release()
                    return True
            try:
                worker = threading.Thread(target=self._work, name="RecorderPublicIdentity", daemon=False)
            except BaseException:
                self._publish("unavailable", error="The public identity worker could not be prepared.")
                return False
            with _OWNERS_LOCK:
                # Serialize global hold admission with Thread.start, including
                # its uncertain-return branch. A second owner cannot slip a
                # replacement bootstrap past an already established hold.
                if _RETIREMENT_HOLDS:
                    self._publish("retirement-held", error="Identity worker retirement is unproven; replacement is held.")
                    return False
                self._retired.clear()
                self._write_admitted = False
                self._publish("running")
                self._thread = worker
                if not any(owner is self for owner in _LIVE_OWNERS):
                    _LIVE_OWNERS.append(self)
                try:
                    worker.start()
                except BaseException:
                    # ident=None/is_alive=False cannot prove that a delayed
                    # native bootstrap will never enter. Retain exact owner.
                    self._stop.set()
                    self._start_uncertain = True
                    _RETIREMENT_HOLDS.append(self)
                    self._publish("retirement-held", error="Identity worker start was uncertain; replacement and writes are held.")
                    return False
                return True

    @staticmethod
    def _public_result(value: object) -> str:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if type(value) is not str or not 0 < len(value) <= 2048:
            raise ValueError("Invalid public identity result")
        key = serialization.load_pem_public_key(value.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Wrong public identity type")
        return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def _work(self) -> None:
        public_key = ""
        failed = False
        try:
            with self._lock:
                if self._stop.is_set() or self._start_uncertain or self._join_uncertain:
                    return
                # STOP fences work not yet admitted. A call admitted here is
                # synchronous and must drain; cancellation cannot undo a write.
                self._write_admitted = True
            from angerona.core import recorder_integrity

            public_key = self._public_result(recorder_integrity.provision_host_identity(self._root))
        except BaseException:
            failed = True  # do not expose exception text, paths, private keys or arbitrary class names
        finally:
            with self._lock:
                self._write_admitted = False
                if self._start_uncertain or self._join_uncertain:
                    self._publish("retirement-held", error="Identity worker retirement remains unproven.")
                elif self._stop.is_set():
                    self._publish("stopped", public_key=public_key)
                elif failed:
                    self._publish("unavailable", error="Public identity provisioning did not return a verified public key; review recorder enrollment settings.")
                else:
                    self._publish("ready", public_key=public_key)
            self._retired.set()  # body completion is necessary, never sufficient without actual thread retirement

    def request_stop(self) -> None:
        with self._lock:
            self._stop.set()
            if self._start_uncertain or self._join_uncertain:
                self._publish("retirement-held", error="Identity worker retirement remains unproven.")
            elif self._thread is None:
                self._publish("stopped", public_key=self._status.public_key)
            elif not self._retired.is_set():
                self._publish("running", error="Stop requested; waiting for the admitted identity operation to retire.")

    def stop(self, timeout: float = 3.0) -> bool:
        self.request_stop()
        try:
            seconds = float(timeout)
            seconds = max(0.0, min(10.0, seconds)) if math.isfinite(seconds) else 0.0
        except (TypeError, ValueError, OverflowError):
            seconds = 0.0
        with self._lock:
            worker = self._thread
        if worker is not None and worker.ident is not None and worker is not threading.current_thread():
            try:
                worker.join(seconds)
            except BaseException:
                with self._lock:
                    self._join_uncertain = True
        with self._lock:
            clean = (not self._start_uncertain and not self._join_uncertain and
                     (worker is None or worker.ident is not None and self._retired.is_set() and not worker.is_alive()))
            if not clean:
                self._retain(hold=True)
                self._publish("retirement-held", error="Identity operation has not proven retirement; the exact owner is retained.")
                return False
            self._publish("stopped", public_key=self._status.public_key)
            self._release()
            return True
