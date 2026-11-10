"""Retained Signal CLI invocation resources; no account or message authority.

Only a fixed caller supplies argv/environment. A local execution result is not
a recipient delivery acknowledgement. Unknown retirement fences this optional
capability and retains its exact resources for shutdown diagnostics.
"""
from __future__ import annotations

import math
import subprocess
import threading
import time
from pathlib import Path

from angerona.core.windows_child_job import OwnedWindowsChild, WindowsChildJob

_LOCK = threading.RLock()
_LAUNCH = threading.Lock()
_STOP = threading.Event()
_ACTIVE: dict[int, object] = {}
_CALLS: dict[int, object] = {}
_HOLDS: dict[int, tuple[object, str, bool]] = {}


class SignalCliRetirementIncomplete(RuntimeError):
    def __init__(self, outcome):
        data = outcome if type(outcome) is dict else {}
        self.outcome = {key: data.get(key) if type(data.get(key)) is int and 0 <= data[key] <= 2**31 - 1 else None
                        for key in ("schema", "active_invocations", "pending_external_trees", "held_resources")}
        self.outcome.update({key: data.get(key) if type(data.get(key)) is bool else None
                             for key in ("launch_quiescent", "capability_held")})
        super().__init__("Signal CLI owned-process retirement remains unverified")


def retain_signal_custody(owner: object, kind: str, *, external: bool = False) -> None:
    if kind not in {"invocation", "executable-pin"} or type(external) is not bool:
        raise ValueError("Invalid Signal custody kind")
    with _LOCK:
        _HOLDS.setdefault(id(owner), (owner, kind, external))
        for active in _ACTIVE.values():
            active.cancel.set()


def signal_cli_custody_snapshot() -> dict:
    """Memory-only, secret-free shutdown facts; never open an inbox or process."""
    with _LOCK:
        active_external = {key for key, owner in _ACTIVE.items()
                           if owner.process is not None and not owner.retirement_proven}
        held_external = {key for key, (_owner, _kind, external) in _HOLDS.items() if external}
        return {"schema": 1, "active_invocations": max(len(_ACTIVE), len(_CALLS)),
                "held_resources": len(_HOLDS),
                "pending_external_trees": len(active_external | held_external),
                "held_kinds": tuple(sorted({kind for _owner, kind, _external in _HOLDS.values()})),
                "launch_quiescent": _STOP.is_set() and not _ACTIVE and not _CALLS,
                "capability_held": bool(_HOLDS),
                "scope": "Signal CLI owned invocations only; no recipient-delivery attestation"}


def begin_signal_call() -> object:
    """Cover executable preflight through its final pin close, including gaps."""
    token = object()
    with _LOCK:
        if _STOP.is_set() or _HOLDS:
            raise OSError("Signal invocation admission is stopped or custody held")
        _CALLS[id(token)] = token
    return token


def end_signal_call(token: object) -> None:
    with _LOCK:
        if _CALLS.get(id(token)) is not token:
            raise ValueError("Signal invocation lease does not match its original owner")
        del _CALLS[id(token)]


def request_signal_stop() -> None:
    """Close admission and signal workers; no native work on the caller thread."""
    with _LOCK:
        _STOP.set()
        for owner in _ACTIVE.values():
            owner.cancel.set()


def resume_signal_admission() -> bool:
    with _LOCK:
        if _ACTIVE or _CALLS or _HOLDS:
            return False
        _STOP.clear()
        return True


class _Invocation:
    def __init__(self, timeout, max_output):
        self.cancel = threading.Event()
        self.process = self.job = self.child = self.reader = None
        self.original_job_handle = self.original_process_handle = None
        self.captured = bytearray()
        self.done, self.overflow, self.failed = threading.Event(), threading.Event(), threading.Event()
        self.max_output = max_output
        self.last_clock = time.monotonic()
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60
                or type(self.last_clock) not in (int, float) or not math.isfinite(self.last_clock)
                or self.last_clock < 0 or type(max_output) is not int or not 1 <= max_output <= 256 * 1024):
            raise ValueError("Signal invocation bounds are invalid")
        self.deadline = self.last_clock + timeout
        self.retire_attempted = self.retirement_proven = self.close_attempted = self.retired = False

    def check(self):
        now = time.monotonic()
        if (type(now) not in (int, float) or not math.isfinite(now) or not self.last_clock <= now < self.deadline):
            raise TimeoutError("Signal invocation deadline expired or clock regressed")
        self.last_clock = now
        if self.cancel.is_set():
            raise InterruptedError("Signal invocation stopped")

    def start(self, argv, environment, cwd):
        from angerona.resilience._selftest_environment import _resume_windows_process
        self.check()
        self.job = WindowsChildJob()
        self.original_job_handle = self.job._handle
        self.check()
        self.process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=str(Path(cwd)), env=environment, close_fds=True,
            creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0)
                           | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                           | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)),
        )
        self.original_process_handle = self.process._handle
        self.check()
        self.job.assign(int(self.process._handle))
        self.child = OwnedWindowsChild(self.process._handle, self.process.pid, self.job)
        self.check()
        _resume_windows_process(self.process)

    def read(self):
        process = self.process
        if process.stdout is None:
            return "io-error"

        def read_output():
            try:
                while True:
                    chunk = process.stdout.read(4096)
                    if not chunk:
                        break
                    available = self.max_output - len(self.captured)
                    self.captured.extend(chunk[:max(0, available)])
                    if len(chunk) > available:
                        self.overflow.set()
                        break
            except Exception:
                self.failed.set()
            finally:
                self.done.set()

        self.reader = threading.Thread(target=read_output, name="angerona-signal-cli-reader", daemon=True)
        self.reader.start()
        while not self.done.wait(0.02):
            self.check()
        self.check()
        if self.failed.is_set():
            return "io-error"
        if self.overflow.is_set():
            return "overflow"
        # EOF alone is not process exit. An executable that closes its pipe
        # and keeps running is a timeout, never a fabricated return code zero.
        process.wait(timeout=max(0.0, self.deadline - time.monotonic()))
        self.check()
        return "complete"

    def retire(self) -> bool:
        if self.retire_attempted:
            return self.retired
        self.retire_attempted = True
        try:
            if self.process is not None:
                if self.child is not None:
                    self.child.prepare_tree_retirement(timeout=2.0)
                    self.child.terminate()
                else:
                    # Assignment/resume never completed: only this exact
                    # suspended Popen object can be terminated here.
                    self.process.kill()
                self.process.wait(timeout=2.0)
                if type(self.process.returncode) is not int:
                    raise OSError("Signal root exit was not proven")
                if self.reader is not None:
                    self.reader.join(timeout=2.0)
                    if self.reader.is_alive():
                        raise OSError("Signal output reader retirement is unproven")
                if self.child is not None:
                    self.child.wait_tree(timeout=2.0)
                    receipt = self.child.tree_retirement_snapshot()
                    if type(receipt) is not dict or receipt.get("signals_proven") is not True:
                        raise OSError("Signal tree signals are unproven")
                elif self.job is not None:
                    self.job.wait_empty(timeout=2.0)
            elif self.job is not None:
                self.job.wait_empty(timeout=2.0)
            self.retirement_proven = True
            self.close_attempted = True
            if self.process is not None and self.process.stdout is not None:
                if self.process.stdout.close() is False:
                    raise OSError("Signal output close was not acknowledged")
            if self.child is not None:
                self.child.close()
                receipt = self.child.tree_retirement_snapshot()
                if type(receipt) is not dict or receipt.get("handles_closed") is not True:
                    raise OSError("Signal native close was not acknowledged")
            else:
                if self.job is not None:
                    self.job.close()
                if self.original_process_handle is not None:
                    self.original_process_handle.Close()
            self.retired = True
            return True
        except BaseException:
            retain_signal_custody(self, "invocation", external=self.process is not None and not self.retirement_proven)
            return False


def run_signal_cli(argv, environment, *, cwd, timeout, max_output):
    """Return output only with exact retained retirement; no transport claim."""
    if not _LAUNCH.acquire(blocking=False):
        return "busy", -1, b""
    owner = None
    state = "execution-error"
    returncode = -1
    try:
        owner = _Invocation(timeout, max_output)
        with _LOCK:
            if _STOP.is_set() or _HOLDS:
                return "custody-held", -1, b""
            _ACTIVE[id(owner)] = owner
        try:
            owner.start(argv, environment, cwd)
            state = owner.read()
            returncode = owner.process.returncode
        except InterruptedError:
            state = "cancelled"
        except (TimeoutError, subprocess.TimeoutExpired):
            state = "timeout"
        except Exception:
            state = "execution-error"
        if not owner.retire():
            state, returncode = "retirement-held", -1
        return state, returncode if type(returncode) is int else -1, bytes(owner.captured)
    finally:
        if owner is not None:
            # Also retain resources on unexpected interruption, including
            # thread-start failure. No raw handle is retried after close began.
            if id(owner) in _ACTIVE and not owner.retire_attempted:
                owner.retire()
            with _LOCK:
                _ACTIVE.pop(id(owner), None)
        _LAUNCH.release()
