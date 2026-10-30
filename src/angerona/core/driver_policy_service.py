"""Explicitly provisioned installed driver-policy service composition.

No source startup, GUI, downloaded catalogue or pipe request can enroll this
runtime. The signed installer supplies private keys, pinned native components
and reviewed fixed artifacts. Native changes still require exact plans and two
independent nonrequester OS-bound signatures. Configuration readback does not
establish loaded-driver removal, reboot acceptance or kernel telemetry health.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import math
import re
import secrets
import threading
import time
from pathlib import Path

from .approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof
from .engine_transport import canonical, decode, private_directory, verify_private
from .privileged_pipe import NativePeer
from .privileged_service import PrivilegedService, PrivilegedServiceClient
from .response_broker import ResponseBroker
from .response_capability import ResponseCapabilityAuthority
from . import windows_driver_policy as policy
from .native_pipe_custody import RetainedPipe, native_pipe_retirement_held
from .native_broker_custody import RetainedBrokerPipeServer, native_broker_retirement_held

SCHEMA = "angerona.driver-policy-service.v1"
MAX_JOBS = 64
MAX_PLANS = 64
_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_OWNERS_LOCK = threading.Lock()
_OWNERS: list[object] = []
_HOLDS: list[object] = []
_FILE_LOCK = threading.Lock()
_FILE_HOLD: list[object] = []


DriverPolicyPipe = RetainedPipe
DriverPolicyPipeServer = RetainedBrokerPipeServer

def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise PermissionError("Closed installed driver-policy schema required")


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        raise PermissionError("Canonical reviewed artifact pin required")
    return value


class ProtectedArtifactReader:
    """Single native ReadFile ownership; fixed service paths, bounded bytes."""
    def __init__(self, verify_path):
        self._verify = verify_path

    @staticmethod
    def _identity(handle):
        import ctypes
        from ctypes import wintypes
        class FileId(ctypes.Structure):
            _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]
        fn = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
        fn.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        fn.restype = wintypes.BOOL
        result = FileId()
        if not fn(int(handle), 18, ctypes.byref(result), ctypes.sizeof(result)):
            raise PermissionError("Installed artifact native identity unavailable")
        return result.volume, bytes(result.identifier)

    def __call__(self, path: Path, maximum: int) -> bytes:
        import win32file
        with _FILE_LOCK:
            if _FILE_HOLD:
                raise PermissionError("Installed artifact handle retirement is held")
            self._verify(path)
            handles = []
            try:
                handle = win32file.CreateFile(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
                handles.append(handle)
                before = win32file.GetFileInformationByHandle(handle)
                size = before[5] << 32 | before[6]
                if before[0] & (0x10 | 0x400) or before[7] != 1 or not 1 <= size <= maximum:
                    raise PermissionError("Installed artifact file custody metadata rejected")
                identity = self._identity(handle)
                code, raw = win32file.ReadFile(handle, maximum + 1)
                after = win32file.GetFileInformationByHandle(handle)
                if code or type(raw) is not bytes or len(raw) != size or (before[0], before[1], before[3], before[4:]) != (after[0], after[1], after[3], after[4:]):
                    raise PermissionError("Installed artifact changed during read")
                self._verify(path)
                named = win32file.CreateFile(str(path), 0x80, 1, None, 3, 0x00200000, None)
                handles.append(named)
                if self._identity(named) != identity:
                    raise PermissionError("Installed artifact name changed during read")
                final = win32file.GetFileInformationByHandle(handle)
                named_info = win32file.GetFileInformationByHandle(named)
                if final[7] != 1 or named_info[7] != 1 or final[0] & (0x10 | 0x400) or named_info[0] & (0x10 | 0x400):
                    raise PermissionError("Installed artifact alias or link metadata changed during read")
            finally:
                uncertain = []
                for handle in reversed(handles):
                    try:
                        handle.Close()
                    except BaseException:
                        uncertain.append(handle)
                        try:
                            handle.Detach()  # one numeric close attempt, never a destructor retry
                        except BaseException:
                            pass
                if uncertain:
                    _FILE_HOLD.extend(uncertain)
                    raise PermissionError("Installed artifact retirement remains unproven")
            return raw


class DriverPolicyServiceRuntime:
    """One retained worker; quick bounded IPC submits and memory-only polls.

    read_artifact/installed_guard/native_factory are trusted composition seams,
    never request fields. The production host supplies actual native checks.
    """
    def __init__(self, root: Path, *, manifest_sha256: str, credentials,
                 installed_guard, read_artifact, native_factory=None, clock=time.time):
        self.root = Path(root)
        self._base_guard, self._read, self._clock = installed_guard, read_artifact, clock
        self._manifest_pin = _sha(manifest_sha256)
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._stop_lock = threading.Lock()
        self.stop_event = threading.Event()
        self._done = threading.Event()
        self._thread = self._listener = None
        self._start_uncertain = self._cleanup_failed = False
        self._profile_held = False
        self._pending = self._active = None
        self._jobs, self._plans = {}, {}
        self._broker = self._journal = self._authority = None
        self.backend = None
        self._closed = False
        self._closed_parts = set()
        self._error = ""
        with _OWNERS_LOCK:
            if _HOLDS or _OWNERS:
                raise PermissionError("Previous installed driver-policy owner must retire first")
            _OWNERS.append(self)
        try:
            if not self._base_guard() is True or not self.root.is_absolute() or ".." in self.root.parts:
                raise PermissionError("Accepted installed driver-policy custody required")
            verify_private(self.root, directory=True)
            manifest_raw = self._read(self.root / "manifest.json", 64 * 1024)
            if _digest(manifest_raw) != self._manifest_pin:
                raise PermissionError("Installed driver-policy manifest pin mismatch")
            manifest = decode(manifest_raw)
            _exact(manifest, {"schema", "policy_id", "minimum_audit_seconds", "native_pins", "catalog", "materials", "reviews"})
            if manifest["schema"] != SCHEMA:
                raise PermissionError("Installed driver-policy profile is unavailable")
            self._manifest = manifest
            records = tuple(credentials)
            if any(type(row) is not PrincipalCredential for row in records) or len({row.principal_id for row in records if row.enabled}) < 3:
                raise PermissionError("Requester plus two independently enrolled operators required")
            self._users = frozenset(row.subject for row in records if row.enabled)
            self._records = records
            if any(row.issuer != "windows-token" for row in records):
                raise PermissionError("Installed driver-policy operators must be OS-bound")
            catalog_row = manifest["catalog"]
            _exact(catalog_row, {"source_url", "revision", "review_reference", "artifact_sha256"})
            catalog = policy.ReviewedDriverCatalog(**catalog_row, artifact=self._read(self.root / "catalog.bin", policy.MAX_CATALOG_BYTES))
            pins = policy.NativeDriverPolicyPins(**manifest["native_pins"])
            rows = manifest["materials"]
            if type(rows) is not list or not 1 <= len(rows) <= 16:
                raise PermissionError("Bounded installed material catalogue required")
            materials = {}
            for row in rows:
                _exact(row, {"mode", "version", "xml_sha256", "compiled_sha256"})
                xml_pin, cip_pin = _sha(row["xml_sha256"]), _sha(row["compiled_sha256"])
                xml = self._read(self.root / (xml_pin + ".xml"), policy.MAX_MATERIAL_BYTES)
                cip = self._read(self.root / (cip_pin + ".cip"), policy.MAX_MATERIAL_BYTES)
                if _digest(cip) != cip_pin:
                    raise PermissionError("Reviewed compiled policy artifact differs from its pin")
                value = policy.DriverPolicyMaterial(manifest["policy_id"], **row, xml=xml, catalog=catalog)
                if value.identity in materials:
                    raise PermissionError("Duplicate installed driver policy material")
                materials[value.identity] = value
            reviews = {}
            if type(manifest["reviews"]) is not list or len(manifest["reviews"]) > 16:
                raise PermissionError("Bounded installed compatibility reviews required")
            for row in manifest["reviews"]:
                _exact(row, {"audit_plan_id", "audit_material_id", "report_sha256", "review_reference"})
                report_pin = _sha(row["report_sha256"])
                review = policy.DriverCompatibilityReview(**row, report=self._read(self.root / (report_pin + ".review"), policy.MAX_REVIEW_BYTES))
                if review.identity in reviews:
                    raise PermissionError("Duplicate installed compatibility review")
                reviews[review.identity] = review
            keys = {}
            for name in ("broker", "journal", "capability", "transport"):
                path = self.root / (name + ".key")
                verify_private(path)
                value = self._read(path, 32)
                if type(value) is not bytes or len(value) != 32:
                    raise PermissionError("Exact service-private key material required")
                keys[name] = value
            if len(set(keys.values())) != 4:
                raise PermissionError("Separated installed policy keys required")
            state = private_directory(self.root / "state")
            self._broker = ResponseBroker(keys["broker"], identity_verifier=ApprovalIdentityVerifier(records, clock=clock),
                                          state_path=state / "broker.json", clock=clock)
            self._journal = policy.DriverPolicyJournal(state / "driver-policy.json", keys["journal"], installed_guard=self._guard)
            self._authority = ResponseCapabilityAuthority(keys["capability"], state_path=state / "capabilities.json")
            native = (native_factory or policy.WindowsNativeDriverPolicyApi)(self.root, pins, installed_guard=self._guard)
            endpoint = {}
            self.backend = policy.WindowsDriverPolicyBackend(self._broker, self._journal, native=native, materials=materials,
                reviews=reviews, minimum_audit_seconds=manifest["minimum_audit_seconds"], capabilities=self._authority,
                consumer=lambda **kwargs: endpoint["client"].execute(request_id=kwargs["parameters"]["plan_id"], **kwargs),
                installed_guard=self._guard, clock=clock)
            executor = policy.NativeDriverPolicyExecutor(validator=self.backend.validator, native=native, installed_guard=self._guard)
            self._service = PrivilegedService(self._authority, transport_key=keys["transport"], executor=executor)
            self._client = PrivilegedServiceClient(transport_key=keys["transport"], transport=type("InternalTransport", (), {"exchange": staticmethod(self._service.handle)})())
            endpoint["client"] = self._client
            self.materials = tuple({"material_id": value.identity, "mode": value.mode, "version": value.version} for value in materials.values())
        except BaseException:
            self.stop()
            raise

    def _hold(self, *, sticky=False):
        with _OWNERS_LOCK:
            if sticky:
                self._cleanup_failed = True
            if not any(owner is self for owner in _HOLDS):
                _HOLDS.append(self)

    def _guard(self):
        if self.stop_event.is_set() or self._profile_held or self._cleanup_failed or self._start_uncertain or _FILE_HOLD or native_broker_retirement_held():
            return False
        try:
            valid = self._base_guard() is True and _digest(self._read(self.root / "manifest.json", 64 * 1024)) == self._manifest_pin
            valid = valid and not _FILE_HOLD and not native_broker_retirement_held()
        except BaseException:
            valid = False
        if not valid:
            self._profile_held = True
        return valid

    def fence_profile(self):
        self._profile_held = True
        with self._lock:
            for job in self._jobs.values():
                job["cancel"].set()

    def attach_listener(self, listener):
        if self._listener is not None or self._thread is not None:
            raise RuntimeError("Installed listener cannot be replaced")
        self._listener = listener
        listener.stop_event = self.stop_event

    @property
    def error(self):
        return self._error or getattr(self._listener, "error", "")

    def start(self):
        with self._lock:
            if self._thread is not None or not self._guard():
                raise PermissionError("Installed driver-policy runtime cannot restart")
            self._thread = threading.Thread(target=self._work, name="InstalledDriverPolicy", daemon=False)
            try:
                self._thread.start()
                if self._listener is not None:
                    self._listener.start()
            except BaseException:
                self._start_uncertain = True
                self.stop_event.set()
                self._condition.notify_all()
                self._hold(sticky=True)
                raise

    def _peer(self, peer):
        now = self._clock()
        if (type(peer) is not NativePeer or peer.user_sid not in self._users
                or type(now) not in (int, float) or not math.isfinite(now)
                or not any(row.subject == peer.user_sid and row.enabled and (not row.expires_at or now < row.expires_at)
                           for row in self._records)):
            raise PermissionError("Captured enrolled native OS peer required")

    def dispatch(self, request, peer):
        self._peer(peer)
        if type(request) is not dict or len(canonical(request)) > 16 * 1024:
            raise PermissionError("Bounded closed driver request required")
        op = request.get("operation")
        with self._lock:
            if op == "driver.status" and set(request) == {"operation"}:
                return {"state": "configured" if self._guard() and not self._closed and self._thread is not None and self._thread.is_alive() else "held",
                        "profile": "own-unsigned-multiple-policy", "materials": self.materials,
                        "kernel_prevention_verified": False, "administrator_tamper_resistance": False,
                        "reason": "Explicit installed composition; separate approvals, native readback and reboot acceptance required"}
            if op in {"driver.poll", "driver.cancel"}:
                _exact(request, {"operation", "job_id"})
                job = self._jobs.get(request["job_id"]) if type(request["job_id"]) is str else None
                if job is None or job["subject"] != peer.user_sid:
                    raise PermissionError("Unknown current owned operation")
                if op == "driver.cancel":
                    job["cancel"].set()
                return decode(canonical(job["view"]))
            if not self._guard() or self._thread is None or not self._thread.is_alive():
                raise PermissionError("Installed policy admission is held")
            if op == "driver.prepare":
                _exact(request, {"operation", "material_id", "action", "original_id", "review_id"})
                if (type(request["action"]) is not str or request["action"] not in {"audit", "enforce", "remove"}
                        or type(request["material_id"]) is not str or request["material_id"] not in self.backend.validator.materials):
                    raise PermissionError("Only installed reviewed material IDs are accepted")
                if any(type(request[key]) is not str for key in ("original_id", "review_id")):
                    raise PermissionError("Typed original and review references required")
                if len(self._plans) >= MAX_PLANS:
                    raise PermissionError("Installed plan catalogue is full; explicit service review required")
            elif op in {"driver.approve", "driver.execute"}:
                _exact(request, {"operation", "plan_id", "proof"} if op == "driver.approve" else {"operation", "plan_id"})
                plan = self._plans.get(request["plan_id"]) if type(request["plan_id"]) is str else None
                if plan is None or op == "driver.execute" and plan.requested_by != policy.WindowsPreventionBackend._actor(peer):
                    raise PermissionError("Only current server-owned requester plans are executable")
                if op == "driver.approve":
                    try:
                        if type(request["proof"]) is not dict:
                            raise TypeError("Typed proof required")
                        SignedPrincipalProof(**request["proof"])  # shape only; actual signature on worker
                    except (TypeError, ValueError) as exc:
                        raise PermissionError("Typed purpose-bound operator proof required") from exc
            else:
                raise PermissionError("Operation is outside the closed installed driver surface")
            if self._pending is not None or self._active is not None or len(self._jobs) >= MAX_JOBS:
                raise PermissionError("Installed policy operation/cache capacity is full")
            identity = secrets.token_hex(16)
            job = {"subject": peer.user_sid, "request": decode(canonical(request)), "peer": peer,
                   "cancel": threading.Event(), "view": {"job_id": identity, "state": "queued", "result": {}}}
            self._jobs[identity] = job
            self._pending = identity
            self._condition.notify_all()
            return dict(job_id=identity, state="queued")

    def _work(self):
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: self.stop_event.is_set() or self._pending is not None)
                    if self.stop_event.is_set():
                        return
                    identity = self._pending
                    self._pending, self._active = None, identity
                    job = self._jobs[identity]
                    job["view"]["state"] = "running"
                try:
                    if job["cancel"].is_set() or not self._guard():
                        raise PermissionError("Queued operation cancelled or held")
                    req, peer = job["request"], job["peer"]
                    if req["operation"] == "driver.prepare":
                        plan = self.backend.prepare(req["material_id"], action=req["action"], original_id=req["original_id"], review_id=req["review_id"])
                        proposal = self.backend.proposal(plan, peer)
                        result = {"plan": asdict(plan), "proposal": asdict(proposal), "proposal_digest": proposal.digest,
                                  "description": self.backend.describe_plan(plan)}
                        with self._lock:
                            if job["cancel"].is_set() or self.stop_event.is_set() or not self._guard():
                                raise PermissionError("Plan publication cancelled or held")
                            self._plans[plan.plan_id] = proposal
                    elif req["operation"] == "driver.approve":
                        result = {"approval_count": self.backend.approve(self._plans[req["plan_id"]], SignedPrincipalProof(**req["proof"]), peer)}
                    else:
                        result = asdict(self.backend.execute(self._plans[req["plan_id"]], peer, cancel=job["cancel"]))
                    if job["cancel"].is_set() or not self._guard():
                        raise PermissionError("Completed operation requires reconciliation after cancellation or policy change")
                    encoded = canonical(result)
                    if len(encoded) > 20 * 1024:
                        raise ValueError("Installed result exceeds cache bound")
                    with self._lock:
                        job["view"] = {"job_id": identity, "state": "completed", "result": decode(encoded)}
                except BaseException:
                    with self._lock:
                        job["view"] = {"job_id": identity, "state": "cancelled" if job["cancel"].is_set() else "held",
                                       "result": {"reason": "Operation unavailable, expired, denied or unverified; inspect the protected journal before retrying."}}
                finally:
                    with self._lock:
                        job["request"] = None
                        self._active = None
        finally:
            self._done.set()

    def stop(self, timeout=3.0):
        if not self._stop_lock.acquire(blocking=False):
            with _OWNERS_LOCK:
                if self._closed and not self._cleanup_failed:
                    return True
                self._cleanup_failed = True
                if not any(owner is self for owner in _HOLDS):
                    _HOLDS.append(self)
                return False
        try:
            return self._stop_owned(timeout)
        finally:
            self._stop_lock.release()

    def _stop_owned(self, timeout):
        self.stop_event.set()
        with self._condition:
            for job in self._jobs.values():
                job["cancel"].set()
                if job["view"]["state"] == "queued":
                    job["view"] = {"job_id": job["view"]["job_id"], "state": "cancelled", "result": {}}
            self._condition.notify_all()
        deadline = time.monotonic() + max(0.0, min(10.0, float(timeout)))
        listener_clean = True
        try:
            if self._listener is not None:
                listener_clean = self._listener.stop(max(0.0, deadline - time.monotonic())) is True
            worker = self._thread
            if worker is not None and worker.ident is not None and worker is not threading.current_thread():
                worker.join(max(0.0, deadline - time.monotonic()))
            worker_clean = worker is None or worker.ident is not None and self._done.is_set() and not worker.is_alive()
        except BaseException:
            listener_clean = worker_clean = False
            self._cleanup_failed = True
        if not listener_clean or not worker_clean or self._start_uncertain or self._cleanup_failed or policy._NATIVE_COMMAND_RETIREMENT_HOLD or _FILE_HOLD or native_broker_retirement_held():
            self._hold()
            self._error = "Installed driver-policy retirement is held; exact native owner and leases retained"
            return False
        clean = True
        for name in ("broker", "journal", "authority"):
            part = getattr(self, "_" + name)
            if part is not None and name not in self._closed_parts:
                self._closed_parts.add(name)  # one close attempt even on ambiguous return
                try:
                    if name == "broker" and part.close(timeout=0) is not True:
                        clean = False
                    elif name != "broker":
                        part.close()
                except BaseException:
                    clean = False
        if not clean:
            self._hold(sticky=True)
            return False
        with _OWNERS_LOCK:
            if self._cleanup_failed:
                if not any(owner is self for owner in _HOLDS):
                    _HOLDS.append(self)
                return False
            self._closed = True
            self._error = ""
            _OWNERS[:] = [owner for owner in _OWNERS if owner is not self]
            _HOLDS[:] = [owner for owner in _HOLDS if owner is not self]
        return True
