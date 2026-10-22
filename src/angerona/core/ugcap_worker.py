"""Persistent UGCAP subprocess over inherited, mesh-authenticated anonymous pipes.

The launcher's user token is inherited; no elevation, OS enclave, or privilege
drop is claimed. The initial verified mesh flag authenticates this control plane
only. It does not attest the source tree or authorize general telemetry.

Passphrases travel only inside encrypted application packets. Caller-owned
bytearrays remain caller-owned; temporary mutable copies are wiped best effort.
Python/base64/crypto can retain immutable copies, so perfect erasure is not
claimed. stderr is discarded and protocol errors never include exception text.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
import ctypes
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

from angerona.core.enclave_mesh import (
    CrossProcessMeshChannel, MAX_PAYLOAD, MeshError, MeshPipe, canonical, decode_frame,
)

_REQUEST = "ugcap.request"
_RESPONSE = "ugcap.response"
_MAX_BOOTSTRAP = 64 * 1024
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_KEY_NAME = re.compile(r"Angerona\.UGCAP\.[A-Za-z0-9_-]{1,96}\Z")
_COMMANDS = frozenset({"status", "provision", "initialize", "verify", "restore", "lock", "shutdown"})
_SECRET_COMMANDS = frozenset({"initialize", "verify", "restore"})
_BASE_FIELDS = frozenset({"repo_root", "vault_path", "key_name"})
_ERRORS = frozenset({"invalid_request", "hardware_unavailable", "authentication_failed",
                     "coverage_incomplete", "stale_report", "operation_failed", "response_too_large"})


class UGCAPWorkerError(RuntimeError):
    """Sanitized worker failure; no credentials or child exception text."""


class UGCAPWorkerUnavailable(UGCAPWorkerError):
    pass


def _wipe(value):
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _public_path(value) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 32768 or "\0" in value
            or value.startswith(("\\\\", "//")) or not Path(value).is_absolute()
            or ".." in Path(value).parts):
        raise UGCAPWorkerError("invalid_request")
    return str(Path(value).absolute())


def _payload(command, payload) -> dict:
    if not isinstance(command, str) or command not in _COMMANDS or not isinstance(payload, dict):
        raise UGCAPWorkerError("invalid_request")
    fields = set(payload)
    if command == "shutdown":
        if fields:
            raise UGCAPWorkerError("invalid_request")
    elif command in {"initialize", "verify"}:
        if fields != _BASE_FIELDS:
            raise UGCAPWorkerError("invalid_request")
    elif command == "restore":
        if fields != _BASE_FIELDS | {"paths", "report_id"}:
            raise UGCAPWorkerError("invalid_request")
        paths = payload["paths"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 128
                or not isinstance(payload["report_id"], str) or not _TOKEN.fullmatch(payload["report_id"])):
            raise UGCAPWorkerError("invalid_request")
        # Do not import vault/source-recovery code into the desktop merely to
        # validate a request. The worker applies its full scope policy again.
        if any(not isinstance(path, str) or not 1 <= len(path) <= 2048
               or any(char in path for char in ("\\", ":", "\0"))
               or any(part in {"", ".", ".."} for part in path.split("/")) for path in paths):
            raise UGCAPWorkerError("invalid_request")
    elif command == "provision":
        if not {"key_name"} <= fields <= {"repo_root", "key_name"}:
            raise UGCAPWorkerError("invalid_request")
    elif fields and fields != _BASE_FIELDS:
        raise UGCAPWorkerError("invalid_request")
    result = dict(payload)
    for name in ("repo_root", "vault_path"):
        if name in result:
            result[name] = _public_path(result[name])
    if "key_name" in result and (not isinstance(result["key_name"], str) or not _KEY_NAME.fullmatch(result["key_name"])):
        raise UGCAPWorkerError("invalid_request")
    if "paths" in result:
        result["paths"] = list(result["paths"])
    return result


def _application(value) -> bytes:
    encoded = canonical(value)
    if len(encoded) > MAX_PAYLOAD:
        raise UGCAPWorkerError("response_too_large")
    return encoded


def _request(command, payload, secret=None):
    clean = _payload(command, payload)
    if command in _SECRET_COMMANDS:
        if not isinstance(secret, bytearray) or not 12 <= len(secret) <= 4096:
            raise UGCAPWorkerError("invalid_request")
    elif secret is not None:
        raise UGCAPWorkerError("invalid_request")
    return {"version": 1, "request_id": secrets.token_hex(16), "nonce": secrets.token_hex(16),
            "command": command, "payload": clean,
            "secret": base64.b64encode(secret).decode("ascii") if secret is not None else None}


def _validate_request(value):
    if (not isinstance(value, dict) or set(value) != {"version", "request_id", "nonce", "command", "payload", "secret"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["request_id"], str) or not _TOKEN.fullmatch(value["request_id"])
            or not isinstance(value["nonce"], str) or not _TOKEN.fullmatch(value["nonce"])
            or not isinstance(value["command"], str)):
        raise UGCAPWorkerError("invalid_request")
    clean = _payload(value["command"], value["payload"])
    secret = None
    if value["command"] in _SECRET_COMMANDS:
        if not isinstance(value["secret"], str) or len(value["secret"]) > 5464:
            raise UGCAPWorkerError("invalid_request")
        try:
            secret = bytearray(base64.b64decode(value["secret"], validate=True))
            if not 12 <= len(secret) <= 4096:
                raise ValueError
        except (ValueError, UnicodeError):
            _wipe(secret)
            raise UGCAPWorkerError("invalid_request") from None
    elif value["secret"] is not None:
        raise UGCAPWorkerError("invalid_request")
    return clean, secret


def _response(request, *, result=None, error=None):
    return {"version": 1, "request_id": request["request_id"], "nonce": request["nonce"],
            "command": request["command"], "ok": error is None, "result": result,
            "error": error}


def _compact(result):
    if not isinstance(result, dict):
        raise UGCAPWorkerError("operation_failed")
    # The receipt retains the verified map once. Raw observations and backups
    # remain in the vault process; they never enter the dashboard/control IPC.
    clean = {key: value for key, value in result.items()
             if key not in {"observations", "backups", "verified_files"}}
    if isinstance(clean.get("last_report"), dict):
        clean["last_report"] = _compact(clean["last_report"])
    return clean


def _error_code(exc):
    # Map known exception *types*, never their potentially sensitive messages.
    name = type(exc).__name__
    return {"HardwareUnavailable": "hardware_unavailable", "HardwareIntegrityError": "authentication_failed",
            "VaultAuthenticationError": "authentication_failed", "VaultCoverageError": "coverage_incomplete",
            "StaleReportError": "stale_report"}.get(name, "operation_failed")


class _VaultExecutor:
    def __init__(self):
        self._vaults = OrderedDict()

    def _vault(self, payload):
        from angerona.core.ugcap import UGCAPVault
        from angerona.core.ugcap_hardware import WindowsTPMHardware
        context = tuple(payload[name] for name in ("repo_root", "vault_path", "key_name"))
        if context not in self._vaults:
            if len(self._vaults) >= 8:
                _old, vault = self._vaults.popitem(last=False)
                vault.lock()
            self._vaults[context] = UGCAPVault(context[0], context[1], WindowsTPMHardware(context[2]))
        self._vaults.move_to_end(context)
        return self._vaults[context]

    def execute(self, command, payload, secret):
        if command == "status":
            result = self._vault(payload).snapshot() if payload else {"status": "ready", "cached_vaults": len(self._vaults)}
            result.update(worker_process=True, os_enclave=False, token="launching-user",
                          hardware={"backend": "windows_tpm", "platform_supported": sys.platform == "win32",
                                    "probed": False, "detail": "No TPM access during status"})
            return result
        if command == "provision":
            from angerona.core.ugcap_hardware import WindowsTPMHardware
            return {"status": "provisioned", **WindowsTPMHardware(payload["key_name"]).provision()}
        if command == "shutdown":
            self.close()
            return {"status": "shutdown"}
        if command == "lock":
            if payload:
                return self._vault(payload).lock()
            for vault in self._vaults.values():
                vault.lock()
            return {"status": "locked"}
        vault = self._vault(payload)
        if command == "initialize":
            return vault.initialize(secret)
        if command == "verify":
            return vault.verify(secret)
        if command == "restore":
            return vault.restore(secret, payload["paths"], expected_report_id=payload["report_id"])
        raise UGCAPWorkerError("invalid_request")

    def close(self):
        for vault in self._vaults.values():
            vault.lock()
        self._vaults.clear()


def _assign_worker_job(process):
    """Kill-on-close custody only; no inherited self-test CPU quota on this daemon."""
    from ctypes import wintypes
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
                    ("processes", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                    ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("read", "write", "other", "read_bytes", "write_bytes", "other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    create = kernel.CreateJobObjectW
    create.argtypes, create.restype = [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE
    configure = kernel.SetInformationJobObject
    configure.argtypes, configure.restype = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL
    assign = kernel.AssignProcessToJobObject
    assign.argtypes, assign.restype = [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
    job = create(None, None)
    if not job:
        raise OSError("UGCAP job custody unavailable")
    info = Extended()
    info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not configure(job, 9, ctypes.byref(info), ctypes.sizeof(info)) or not assign(job, int(process._handle)):
        close(job)
        raise OSError("UGCAP job custody unavailable")
    lock = threading.Lock()
    state = [False]
    def close_once(handle):
        with lock:
            if state[0]:
                return
            state[0] = True
        close(handle)
    return job, close_once


def _custody(data_root):
    from angerona.core.engine_transport import private_directory, verify_private
    from angerona.core.hardening import ensure_sensitive_parent, key_acl_required
    from angerona.core.secure_store import _path_traverses_reparse
    root = Path(data_root).absolute()
    if _path_traverses_reparse(root) or not root.is_dir():
        raise UGCAPWorkerUnavailable("Protected worker runtime root is unavailable")
    if os.name == "nt" and key_acl_required():
        ensure_sensitive_parent(root / "ugcap-worker", required=True)
    else:
        verify_private(root, directory=True)
    private_directory(root / "ugcap-worker")
    return root


class UGCAPDaemonClient:
    def __init__(self, data_root, *, launch_factory=None, startup_timeout=10.0,
                 rotation_seconds=10.0, clock=time.monotonic):
        self.data_root = Path(data_root)
        self._launch = launch_factory or subprocess.Popen
        self._startup_timeout = max(1.0, min(float(startup_timeout), 30.0))
        self._rotation_seconds, self._clock = rotation_seconds, clock
        self._state_lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._process = self._job = self._pipe = None
        self._closed = False
        self._reports = {}
        self._starts = 0

    def _command(self):
        if getattr(sys, "frozen", False):
            return [sys.executable, "--ugcap-worker"]
        source = str(Path(__file__).resolve().parents[2])
        bootstrap = (f"import sys;sys.path.insert(0,{source!r});"
                     "from angerona.core.ugcap_worker import worker_main;raise SystemExit(worker_main())")
        return [sys.executable, "-I", "-c", bootstrap]

    def _detach(self):
        with self._state_lock:
            values = self._process, self._job, self._pipe
            self._process = self._job = self._pipe = None
            self._reports.clear()
            return values

    @staticmethod
    def _stop_owned(process, job, pipe):
        if pipe is not None:
            pipe.close()
        from angerona.resilience._selftest_environment import _stop_process_custody
        _stop_process_custody(process, job)
        if process is not None:
            for stream in (process.stdin, process.stdout):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass

    def _ensure(self, deadline):
        with self._state_lock:
            if self._closed:
                raise UGCAPWorkerUnavailable("UGCAP client is closed")
            if (self._process is not None and self._process.poll() is None
                    and not self._pipe.snapshot()["closed"]
                    and self._pipe.endpoint.snapshot()["session_expires"] - self._clock() > 180):
                return self._pipe
        self._stop_owned(*self._detach())
        process = job = channel = parent = None
        try:
            root = _custody(self.data_root)
            parent, child = CrossProcessMeshChannel.create_pair(verified=True, rotation_seconds=self._rotation_seconds)
            nonce = secrets.token_hex(16)
            bootstrap = {"version": 1, "mesh": child, "data_root": str(root), "client_nonce": nonce}
            wire = canonical(bootstrap) + b"\n"
            if len(wire) > _MAX_BOOTSTRAP:
                raise UGCAPWorkerUnavailable("UGCAP bootstrap exceeded its budget")
            from angerona.core.persistent_engine import _child_environment
            environment = _child_environment()
            environment["ANGERONA_DATA"] = str(root)
            kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          close_fds=True, env=environment)
            if os.name == "nt":
                kwargs["creationflags"] = (getattr(subprocess, "CREATE_NO_WINDOW", 0)
                                             | getattr(subprocess, "CREATE_SUSPENDED", 0x4))
            else:
                kwargs["start_new_session"] = True
            process = self._launch(self._command(), **kwargs)
            if os.name == "nt":
                job = _assign_worker_job(process)
                from angerona.resilience._selftest_environment import _resume_windows_process
                _resume_windows_process(process)
            with self._state_lock:
                if self._closed:
                    raise UGCAPWorkerUnavailable("UGCAP client is closed")
                self._process, self._job = process, job
            written, failure = threading.Event(), []
            def bootstrap_write():
                try:
                    process.stdin.write(wire)
                    process.stdin.flush()
                except Exception:
                    failure.append(True)
                finally:
                    written.set()
            threading.Thread(target=bootstrap_write, name="UGCAP-bootstrap-write", daemon=True).start()
            if not written.wait(max(.1, min(self._startup_timeout, deadline - time.monotonic()))) or failure:
                raise UGCAPWorkerUnavailable("UGCAP bootstrap transport failed")
            bootstrap.clear()
            child.clear()
            channel = MeshPipe(parent, process.stdout, process.stdin, allowed_purposes={_REQUEST, _RESPONSE})
            with self._state_lock:
                if self._closed:
                    raise UGCAPWorkerUnavailable("UGCAP client is closed")
                self._process, self._job, self._pipe = process, job, channel
                self._starts += 1
            ready = decode_frame(channel.receive(_RESPONSE, timeout=max(.1, min(self._startup_timeout, deadline - time.monotonic()))))
            if (set(ready) != {"version", "kind", "client_nonce", "session"}
                    or ready["version"] != 1 or ready["kind"] != "ready"
                    or ready["client_nonce"] != nonce or ready["session"] != parent.session):
                raise UGCAPWorkerUnavailable("UGCAP worker did not establish the expected session")
            return channel
        except Exception:
            detached = self._detach()
            self._stop_owned(*(detached if detached[0] is process else (process, job, channel)))
            if channel is None and parent is not None:
                parent.close()
            raise UGCAPWorkerUnavailable("UGCAP worker startup could not establish its protected channel") from None

    @staticmethod
    def _accept_response(raw, request):
        response = decode_frame(raw)
        if (set(response) != {"version", "request_id", "nonce", "command", "ok", "result", "error"}
                or type(response["version"]) is not int or response["version"] != 1
                or response["request_id"] != request["request_id"] or response["nonce"] != request["nonce"]
                or response["command"] != request["command"] or type(response["ok"]) is not bool):
            raise UGCAPWorkerUnavailable("UGCAP response correlation failed")
        if response["ok"]:
            if not isinstance(response["result"], dict) or response["error"] is not None:
                raise UGCAPWorkerUnavailable("UGCAP response schema failed")
            return response["result"]
        if response["result"] is not None or response["error"] not in _ERRORS:
            raise UGCAPWorkerUnavailable("UGCAP error response schema failed")
        raise UGCAPWorkerError("UGCAP worker rejected operation: " + response["error"])

    def execute(self, command: str, payload: dict, *, secret: bytearray | None = None, timeout=150.0) -> dict:
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not .1 <= timeout <= 180:
            raise ValueError("UGCAP timeout must be between0.1 and180 seconds")
        borrowed = bytearray(secret) if isinstance(secret, bytearray) else None
        request = None
        deadline = time.monotonic() + timeout
        if not self._operation_lock.acquire(timeout=timeout):
            _wipe(borrowed)
            raise UGCAPWorkerUnavailable("UGCAP worker is busy")
        try:
            request = _request(command, payload, borrowed)
            channel = self._ensure(deadline)
            context = tuple(request["payload"].get(name, "") for name in ("repo_root", "vault_path", "key_name"))
            if command == "restore" and self._reports.get(request["payload"]["report_id"]) != context:
                raise UGCAPWorkerError("UGCAP worker rejected operation: stale_report")
            channel.send(_application(request), _REQUEST, timeout=max(.1, deadline - time.monotonic()))
            result = self._accept_response(channel.receive(_RESPONSE, timeout=max(.1, deadline - time.monotonic())), request)
            if command == "verify" and isinstance(result.get("report_id"), str):
                self._reports.clear()
                if result.get("status") == "drift":
                    self._reports[result["report_id"]] = context
            elif command in {"lock", "initialize", "provision", "restore"}:
                self._reports.clear()
            if command == "shutdown":
                process = self._process
                process.stdin.close()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                self._stop_owned(*self._detach())
            return result
        except UGCAPWorkerUnavailable:
            self._stop_owned(*self._detach())
            raise
        except UGCAPWorkerError:
            raise
        except Exception:
            self._stop_owned(*self._detach())
            raise UGCAPWorkerUnavailable("UGCAP worker transport or operation timed out or failed") from None
        finally:
            if request is not None:
                request["secret"] = None
                request.clear()
            _wipe(borrowed)
            self._operation_lock.release()

    def close(self):
        with self._state_lock:
            self._closed = True
        if self._operation_lock.acquire(blocking=False):
            try:
                with self._state_lock:
                    pipe, process = self._pipe, self._process
                if pipe is not None and process is not None and process.poll() is None:
                    try:
                        request = _request("shutdown", {})
                        pipe.send(_application(request), _REQUEST, timeout=1)
                        self._accept_response(pipe.receive(_RESPONSE, timeout=1), request)
                        process.stdin.close()
                        process.wait(timeout=2)
                    except Exception:
                        pass
            finally:
                self._operation_lock.release()
        self._stop_owned(*self._detach())

    def snapshot(self):
        with self._state_lock:
            return {"running": self._process is not None and self._process.poll() is None,
                    "closed": self._closed, "starts": self._starts, "os_enclave": False,
                    "channel": self._pipe.snapshot() if self._pipe is not None else None}


def serve(reader, writer, *, executor=None) -> int:
    """Subprocess server; injectable executor is a test seam, never a wire field."""
    pipe = None
    engine = executor or _VaultExecutor()
    try:
        raw = reader.readline(_MAX_BOOTSTRAP + 1)
        if len(raw) > _MAX_BOOTSTRAP or not raw.endswith(b"\n"):
            return 2
        initial = decode_frame(raw)
        if (set(initial) != {"version", "mesh", "data_root", "client_nonce"}
                or type(initial["version"]) is not int or initial["version"] != 1
                or not isinstance(initial["client_nonce"], str) or not _TOKEN.fullmatch(initial["client_nonce"])):
            return 2
        _custody(initial["data_root"])
        endpoint = CrossProcessMeshChannel.from_bootstrap(initial["mesh"], verified=True)
        pipe = MeshPipe(endpoint, reader, writer, allowed_purposes={_REQUEST, _RESPONSE})
        pipe.send(_application({"version": 1, "kind": "ready", "client_nonce": initial["client_nonce"],
                                "session": endpoint.session}), _RESPONSE)
        initial.clear()
        raw = b""
        seen = OrderedDict()
        while True:
            request = None
            secret = None
            try:
                raw = pipe.receive(_REQUEST, timeout=3600)
                request = decode_frame(raw)
                clean, secret = _validate_request(request)
                identities = "request:" + request["request_id"], "nonce:" + request["nonce"]
                if any(identity in seen for identity in identities):
                    raise UGCAPWorkerError("invalid_request")
                for identity in identities:
                    seen[identity] = None
                while len(seen) > 1024:
                    seen.popitem(last=False)
                try:
                    execute = engine.execute if hasattr(engine, "execute") else engine
                    result = _compact(execute(request["command"], clean, secret))
                    response = _response(request, result=result)
                    try:
                        encoded = _application(response)
                    except (UGCAPWorkerError, MeshError):
                        encoded = _application(_response(request, error="response_too_large"))
                except Exception as exc:
                    encoded = _application(_response(request, error=_error_code(exc)))
                pipe.send(encoded, _RESPONSE)
                if request["command"] == "shutdown":
                    return 0
            finally:
                _wipe(secret)
                if request is not None:
                    request["secret"] = None
                    request.clear()
                raw = b""
    except Exception:
        return 2
    finally:
        if hasattr(engine, "close"):
            engine.close()
        if pipe is not None:
            pipe.close()


def worker_main() -> int:
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(worker_main())
