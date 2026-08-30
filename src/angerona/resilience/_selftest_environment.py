"""Child-process custody for resilience self-tests with isolated routing."""
from __future__ import annotations

import importlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any


_SAFE_PREFIX = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
_TOKEN = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_POINT = 0x400
_MAX_RESULT_BYTES = 16 * 1024
_SELFTEST_PROCESS_LIMIT = 32
_SELFTEST_PROCESS_MEMORY_BYTES = 512 * 1024 * 1024
_SELFTEST_JOB_MEMORY_BYTES = 1024 * 1024 * 1024
_SELFTEST_CPU_SECONDS = 90
_TARGETS = {
    "diagnostics": ("angerona.resilience.diagnostics", "_isolated_self_test"),
    "manager": ("angerona.resilience.manager", "_isolated_self_test"),
    "scanner": ("angerona.resilience.scanner", "_isolated_self_test"),
    "ecosystem": ("angerona.resilience.selftest", "_isolated_self_test"),
    "supervisor": ("angerona.resilience.supervisor", "_isolated_self_test"),
}
_TARGET_ENVIRONMENT = {
    "diagnostics": frozenset({"ANGERONA_DIAG_DIR"}),
    "manager": frozenset(
        {
            "ANGERONA_DATA",
            "ANGERONA_DIAG_DIR",
            "ANGERONA_SCANNER_INTERVAL",
            "ANGERONA_SCANNER_UI",
            "ANGERONA_BLACKBOX_ENABLED",
        }
    ),
    "scanner": frozenset({"ANGERONA_DATA", "ANGERONA_DIAG_DIR"}),
    "ecosystem": frozenset({"ANGERONA_DATA", "ANGERONA_DIAG_DIR"}),
    "supervisor": frozenset({"ANGERONA_DATA", "ANGERONA_DIAG_DIR"}),
}
_ROUTING_PATH_KEYS = frozenset({"ANGERONA_DATA", "ANGERONA_DIAG_DIR"})
_ROUTING_FIXED_VALUES = {
    "ANGERONA_SCANNER_INTERVAL": "0.2",
    "ANGERONA_SCANNER_UI": "0",
    "ANGERONA_BLACKBOX_ENABLED": "0",
}
_CHILD_BOOTSTRAP = (
    "import sys;"
    "sys.path.insert(0,sys.argv[1]);"
    "from angerona.resilience._selftest_environment import _child_main;"
    "raise SystemExit(_child_main(sys.argv[2]))"
)


def _same_object(current: os.stat_result, created: os.stat_result) -> bool:
    return (
        current.st_dev == created.st_dev
        and current.st_ino == created.st_ino
        and stat.S_ISDIR(current.st_mode)
        and not bool(getattr(current, "st_file_attributes", 0) & _REPARSE_POINT)
    )


def _remove_owned_temp(root: Path, created: os.stat_result) -> None:
    """Detach and remove only the captured, non-reparse directory object."""
    try:
        current = root.lstat()
    except OSError:
        return
    if root.is_symlink() or not _same_object(current, created):
        return
    tombstone = root.with_name(f"{root.name}.remove-{secrets.token_hex(16)}")
    try:
        os.replace(root, tombstone)
        moved = tombstone.lstat()
        if tombstone.is_symlink() or not _same_object(moved, created):
            return
        # Modern shutil never traverses a directory junction while removing a
        # tree. The unpredictable, identity-revalidated tombstone also removes
        # the test path from circulation before recursive cleanup begins.
        shutil.rmtree(tombstone)
    except OSError:
        # Fail safe: a changed object is left behind instead of risking deletion
        # of an unrelated live directory.
        return


def _validated_updates(
    root: Path,
    target: str,
    variables: Callable[[Path], Mapping[str, str]],
) -> dict[str, str]:
    updates = dict(variables(root))
    if set(updates) != _TARGET_ENVIRONMENT[target]:
        raise ValueError("self-test child routing does not match its exact target allowlist")
    for key, value in updates.items():
        if not key.startswith("ANGERONA_") or not isinstance(value, str):
            raise ValueError("self-test child environment update is invalid")
        if "\x00" in key or "\x00" in value:
            raise ValueError("self-test child environment contains a null byte")
        if key in _ROUTING_FIXED_VALUES and value != _ROUTING_FIXED_VALUES[key]:
            raise ValueError("self-test child control does not match its fixed value")
        if key in _ROUTING_PATH_KEYS:
            try:
                Path(value).resolve(strict=False).relative_to(root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError("self-test child routing left its owned root") from exc
    return updates


def _assign_windows_kill_job(process: subprocess.Popen[bytes]) -> Any:
    """Assign the waiting child and all descendants to a kill-on-close job."""
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    create_job.restype = wintypes.HANDLE
    set_job = kernel32.SetInformationJobObject
    set_job.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    set_job.restype = wintypes.BOOL
    assign = kernel32.AssignProcessToJobObject
    assign.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign.restype = wintypes.BOOL
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL

    job = create_job(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "could not create self-test process job")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.PerJobUserTimeLimit = _SELFTEST_CPU_SECONDS * 10_000_000
    info.BasicLimitInformation.ActiveProcessLimit = _SELFTEST_PROCESS_LIMIT
    info.ProcessMemoryLimit = _SELFTEST_PROCESS_MEMORY_BYTES
    info.JobMemoryLimit = _SELFTEST_JOB_MEMORY_BYTES
    info.BasicLimitInformation.LimitFlags = (
        0x00000004  # JOB_OBJECT_LIMIT_JOB_TIME
        | 0x00000008  # JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | 0x00000100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | 0x00000200  # JOB_OBJECT_LIMIT_JOB_MEMORY
        | 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    if not set_job(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        error = ctypes.get_last_error()
        close(job)
        raise OSError(error, "could not configure self-test process job")
    if not assign(job, wintypes.HANDLE(int(process._handle))):  # type: ignore[attr-defined]
        error = ctypes.get_last_error()
        close(job)
        raise OSError(error, "could not custody self-test child process")
    return job, close


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    """Resume only the main thread of a just-created suspended child."""
    import ctypes
    from ctypes import wintypes

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot_fn = kernel32.CreateToolhelp32Snapshot
    snapshot_fn.argtypes = (wintypes.DWORD, wintypes.DWORD)
    snapshot_fn.restype = wintypes.HANDLE
    first = kernel32.Thread32First
    first.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
    first.restype = wintypes.BOOL
    next_entry = kernel32.Thread32Next
    next_entry.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
    next_entry.restype = wintypes.BOOL
    open_thread = kernel32.OpenThread
    open_thread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_thread.restype = wintypes.HANDLE
    resume = kernel32.ResumeThread
    resume.argtypes = (wintypes.HANDLE,)
    resume.restype = wintypes.DWORD
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL

    snapshot = snapshot_fn(0x00000004, 0)  # TH32CS_SNAPTHREAD
    invalid = ctypes.c_void_p(-1).value
    if not snapshot or int(snapshot) == invalid:
        raise OSError(ctypes.get_last_error(), "could not enumerate suspended child threads")
    resumed = 0
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        available = bool(first(snapshot, ctypes.byref(entry)))
        while available:
            if int(entry.th32OwnerProcessID) == int(process.pid):
                thread = open_thread(0x0002, False, entry.th32ThreadID)  # SUSPEND_RESUME
                if not thread:
                    raise OSError(ctypes.get_last_error(), "could not open suspended child thread")
                try:
                    previous = int(resume(thread))
                    if previous == 0xFFFFFFFF:
                        raise OSError(ctypes.get_last_error(), "could not resume self-test child")
                    resumed += 1
                finally:
                    close(thread)
            available = bool(next_entry(snapshot, ctypes.byref(entry)))
    finally:
        close(snapshot)
    if resumed != 1:
        raise OSError("suspended self-test child did not expose exactly one main thread")


def _stop_process_custody(
    process: subprocess.Popen[bytes] | None,
    windows_job: Any,
) -> None:
    if windows_job is not None:
        job, close = windows_job
        close(job)  # Kills any test-owned descendant still in the job.
    elif process is not None and os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if process is not None and process.poll() is None:
        try:
            process.kill()
            process.wait(timeout=2.0)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _apply_posix_child_limits() -> None:
    """Apply portable per-child limits before importing a self-test target."""
    if os.name == "nt":
        return
    try:
        import resource
    except ImportError:
        return

    limits: list[tuple[int, int]] = []
    for name, value in (
        ("RLIMIT_CPU", _SELFTEST_CPU_SECONDS),
        ("RLIMIT_FSIZE", 32 * 1024 * 1024),
        ("RLIMIT_NOFILE", 256),
        # RLIMIT_NPROC is per real user on common POSIX systems rather than a
        # perfect process-tree limit. It is therefore conservative only and is
        # paired with exact process-group cleanup and the wall-clock deadline.
        ("RLIMIT_NPROC", 256),
    ):
        resource_id = getattr(resource, name, None)
        if resource_id is not None:
            limits.append((resource_id, value))
    if sys.platform.startswith("linux"):
        address_space = getattr(resource, "RLIMIT_AS", None)
        if address_space is not None:
            limits.append((address_space, _SELFTEST_JOB_MEMORY_BYTES))
    for resource_id, ceiling in limits:
        try:
            soft, hard = resource.getrlimit(resource_id)
            infinity = getattr(resource, "RLIM_INFINITY", -1)
            bounded_hard = ceiling if hard == infinity else min(int(hard), ceiling)
            bounded_soft = bounded_hard if soft == infinity else min(int(soft), bounded_hard)
            resource.setrlimit(resource_id, (bounded_soft, bounded_hard))
        except (OSError, ValueError):
            # A platform that cannot lower one optional limit retains process-
            # group custody and the hard wall-clock/output bounds.
            continue


def _bounded_process_output(
    process: subprocess.Popen[bytes],
    token: str,
    duration: float,
) -> tuple[str, bytes]:
    """Stream at most 16 KiB from the exact child without ``communicate``."""
    if process.stdin is None or process.stdout is None:
        return "io-error", b""
    try:
        process.stdin.write(f"{token}\n".encode("ascii"))
        process.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass

    captured = bytearray()
    done = threading.Event()
    overflow = threading.Event()
    read_failed = threading.Event()

    def read_output() -> None:
        try:
            while True:
                request = min(4096, _MAX_RESULT_BYTES - len(captured) + 1)
                chunk = process.stdout.read(max(1, request))
                if not chunk:
                    break
                available = _MAX_RESULT_BYTES - len(captured)
                if len(chunk) > available:
                    if available > 0:
                        captured.extend(chunk[:available])
                    overflow.set()
                    break
                captured.extend(chunk)
        except (OSError, ValueError):
            read_failed.set()
        finally:
            done.set()

    reader = threading.Thread(
        target=read_output,
        name="angerona-selftest-output-reader",
        daemon=True,
    )
    reader.start()
    deadline = time.monotonic() + duration
    while not done.wait(0.02):
        if overflow.is_set():
            break
        if time.monotonic() >= deadline:
            try:
                process.kill()
            except OSError:
                pass
            reader.join(timeout=2.0)
            return "timeout", bytes(captured)
    if overflow.is_set():
        try:
            process.kill()
        except OSError:
            pass
        reader.join(timeout=2.0)
        return "overflow", bytes(captured)
    remaining = max(0.0, deadline - time.monotonic())
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        reader.join(timeout=2.0)
        return "timeout", bytes(captured)
    reader.join(timeout=2.0)
    if reader.is_alive() or read_failed.is_set():
        return "io-error", bytes(captured)
    return "complete", bytes(captured)


def run_isolated_selftest(
    target: str,
    prefix: str,
    variables: Callable[[Path], Mapping[str, str]],
    *,
    timeout: float = 30.0,
) -> tuple[bool, str]:
    """Run one fixed self-test target without changing the parent's routing."""
    if target not in _TARGETS:
        raise ValueError("self-test child target is not allowlisted")
    if not _SAFE_PREFIX.fullmatch(prefix):
        raise ValueError("self-test temporary prefix is invalid")
    duration = float(timeout)
    if not 1.0 <= duration <= 60.0:
        raise ValueError("self-test child timeout is outside its allowed range")
    if bool(getattr(sys, "frozen", False)):
        return False, "isolated resilience self-test child is unavailable in this packaged runtime"

    root: Path | None = None
    created: os.stat_result | None = None
    process: subprocess.Popen[bytes] | None = None
    windows_job: Any = None
    try:
        root = Path(tempfile.mkdtemp(prefix=prefix)).resolve(strict=True)
        created = root.lstat()
        if root.is_symlink() or not _same_object(created, created):
            raise RuntimeError("self-test temporary root is not an owned directory")
        updates = _validated_updates(root, target, variables)
        token = secrets.token_hex(32)
        from angerona.core.privilege import sanitized_child_environment

        # Start from no caller-controlled source environment. The shared policy
        # restores only OS/runtime essentials; the exact per-target routing map
        # above is the sole Angerona state admitted to this child.
        child_environment = sanitized_child_environment(source={})
        child_environment.update(updates)
        child_environment["ANGERONA_SELFTEST_CHILD_TOKEN"] = token
        source_root = Path(__file__).resolve(strict=True).parents[2]
        kwargs: dict[str, object] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "env": child_environment,
            "close_fds": True,
            "cwd": str(source_root),
            "bufsize": 0,
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
            )
        else:
            kwargs["start_new_session"] = True
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-c",
                _CHILD_BOOTSTRAP,
                str(source_root),
                target,
            ],
            **kwargs,
        )
        if os.name == "nt":
            try:
                windows_job = _assign_windows_kill_job(process)
                _resume_windows_process(process)
            except OSError:
                process.kill()
                process.wait(timeout=2.0)
                raise
        state, encoded = _bounded_process_output(process, token, duration)
        if state == "timeout":
            return False, f"isolated {target} self-test exceeded its {duration:.0f}s limit"
        if state == "overflow":
            return False, f"isolated {target} self-test output exceeded its bound"
        if state != "complete":
            return False, f"isolated {target} self-test output custody failed closed"
        if process.returncode != 0:
            return False, f"isolated {target} self-test child exited with code {process.returncode}"
        output = encoded.decode("utf-8", errors="replace")
        lines = [line for line in output.splitlines() if line.strip()]
        if not lines:
            return False, f"isolated {target} self-test returned no result"
        try:
            result = json.loads(lines[-1])
        except (json.JSONDecodeError, TypeError):
            return False, f"isolated {target} self-test returned an invalid result"
        if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
            return False, f"isolated {target} self-test returned an invalid schema"
        detail = str(result.get("detail") or "")[:4_000]
        return bool(result["ok"]), detail
    finally:
        _stop_process_custody(process, windows_job)
        if root is not None and created is not None:
            _remove_owned_temp(root, created)


def _child_main(target: str) -> int:
    _apply_posix_child_limits()
    expected = os.environ.pop("ANGERONA_SELFTEST_CHILD_TOKEN", "")
    supplied = sys.stdin.readline(129).strip()
    if not _TOKEN.fullmatch(expected) or not secrets.compare_digest(expected, supplied):
        return 2
    module_name, function_name = _TARGETS.get(target, ("", ""))
    if not module_name:
        return 2
    try:
        module = importlib.import_module(module_name)
        function = getattr(module, function_name)
        ok, detail = function()
        payload = {"ok": bool(ok), "detail": str(detail)[:4_000]}
    except Exception as exc:
        payload = {
            "ok": False,
            "detail": f"isolated {target} self-test raised {type(exc).__name__}",
        }
    print(json.dumps(payload, sort_keys=True, ensure_ascii=True), flush=True)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2]))
    raise SystemExit(2)
