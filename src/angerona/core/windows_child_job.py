"""Retained Windows Job custody for explicitly launched child process trees.

Children are suspended until assigned. No process
table, process-name match, inherited handle, or PID lookup grants ownership.
"""
from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path


class NativeOwnershipObservationError(OSError):
    """A query-only ownership observation could not release its native custody."""


class WindowsChildJob:
    def __init__(self, *, kill_on_close=True):
        import win32job

        self._api = win32job
        self._handle = None
        self._handle = win32job.CreateJobObject(None, "")
        try:
            info = win32job.QueryInformationJobObject(
                self._handle, win32job.JobObjectExtendedLimitInformation,
            )
            if kill_on_close:
                info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(
                self._handle, win32job.JobObjectExtendedLimitInformation, info,
            )
        except BaseException:
            self.close()
            raise

    def assign(self, process):
        self._api.AssignProcessToJobObject(self._handle, process)

    def terminate(self):
        if self._handle is not None:
            self._api.TerminateJobObject(self._handle, 1)

    def close(self):
        handle, self._handle = self._handle, None
        if handle is not None:
            handle.Close()

    def wait_empty(self, timeout=3.0):
        deadline = time.monotonic() + timeout
        while True:
            state = self._api.QueryInformationJobObject(
                self._handle, self._api.JobObjectBasicAccountingInformation,
            )
            if state["ActiveProcesses"] == 0:
                return
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owned child tree", timeout)
            time.sleep(0.01)

    def __del__(self):
        self.close()


class OwnedWindowsChild:
    owns_descendants = True

    def __init__(self, process, pid, job):
        self._process, self.pid, self._job = process, pid, job
        self._handle_lock = threading.RLock()

    def poll(self):
        import win32process

        with self._handle_lock:
            if self._process is None:
                raise OSError("Owned child custody is closed")
            code = win32process.GetExitCodeProcess(self._process)
        return None if code == 259 else code

    def contains_native_process(self, identity) -> bool:
        """Observe one exact live member of this retained Job, without mutation.

        This is background-only identity context. A redirector's PID is not
        substituted for its actual role child, and membership grants no response
        authority. Duplicate only JOB_OBJECT_QUERY while the owner is pinned;
        no borrowed numeric Job handle escapes the owner lock.
        """
        from angerona.core.windows_process_lease import ProcessObjectIdentity, _Native

        if type(identity) is not ProcessObjectIdentity:
            return False
        if not self._handle_lock.acquire(blocking=False):
            return False
        retained_job = None
        try:
            if self._process is None or self._job._handle is None:
                return False
            import win32api
            current = win32api.GetCurrentProcess()
            retained_job = win32api.DuplicateHandle(
                current, self._job._handle, current, 0x0004, False, 0,
            )
        except Exception:
            return False
        finally:
            self._handle_lock.release()
        process = None
        native = None
        try:
            import ctypes
            from ctypes import wintypes as w

            native = _Native()
            process = native.open(identity.pid, 0x101000, False)
            if native.wait(process, 0) or native.identity(process) != identity:
                return False
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.IsProcessInJob.argtypes = (w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL))
            kernel.IsProcessInJob.restype = w.BOOL
            member = w.BOOL()
            if not kernel.IsProcessInJob(process, int(retained_job), ctypes.byref(member)):
                return False
            return bool(member.value and not native.wait(process, 0)
                        and native.identity(process) == identity)
        except Exception:
            return False
        finally:
            cleanup_failure = False
            if process is not None:
                try:
                    native.close(process)
                except Exception:
                    cleanup_failure = True
            if retained_job is not None:
                try:
                    retained_job.Close()
                except Exception:
                    cleanup_failure = True
            if cleanup_failure:
                raise NativeOwnershipObservationError("Query-only native observation cleanup remains unproven")

    def terminate(self):
        # Terminate the job even after its server exits: a runner can outlive it.
        with self._handle_lock:
            self._job.terminate()

    kill = terminate

    def wait_tree(self, timeout=3.0):
        self._job.wait_empty(timeout)

    def wait(self, timeout=None):
        import win32api
        import win32con
        import win32event
        import win32process

        milliseconds = win32event.INFINITE if timeout is None else max(0, int(timeout * 1000))
        # The supervisor's waiter may still be unwinding when STOP closes its
        # owner. Each wait retains the same kernel object independently, so a
        # concurrent close cannot invalidate a pending native wait.
        with self._handle_lock:
            current = win32api.GetCurrentProcess()
            retained = win32api.DuplicateHandle(
                current, self._process, current, 0, False, win32con.DUPLICATE_SAME_ACCESS,
            )
        try:
            if win32event.WaitForSingleObject(retained, milliseconds) == win32event.WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired("owned child", timeout)
            return win32process.GetExitCodeProcess(retained)
        finally:
            retained.Close()

    def close(self):
        with self._handle_lock:
            self._job.close()
            handle, self._process = self._process, None
            if handle is not None:
                handle.Close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def launch_windows_child(argv, environment, *, cwd=None, deadline=None,
                         check_cancelled=None, kill_on_close=True, window="hidden"):
    """Launch trusted fixed argv in a private job before its first instruction."""
    import win32api
    import win32con
    import win32process

    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("Owned child requires an absolute executable path")
    image = str(argv[0])
    if deadline is None:
        deadline = time.monotonic() + 10.0
    job = WindowsChildJob(kill_on_close=kill_on_close)
    process = thread = None
    try:
        startup = win32process.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0 if window == "hidden" else (7 if window == "minimized" else 1)
        visibility = (win32con.DETACHED_PROCESS | win32con.CREATE_NEW_PROCESS_GROUP | win32con.CREATE_NO_WINDOW
                      if window == "hidden" else win32con.CREATE_NEW_CONSOLE | win32con.CREATE_NEW_PROCESS_GROUP)
        process, thread, pid, _ = win32process.CreateProcess(
            image, subprocess.list2cmdline(list(argv)),
            None, None, False,
            win32con.CREATE_SUSPENDED | win32con.CREATE_UNICODE_ENVIRONMENT | visibility,
            environment, cwd, startup,
        )
        job.assign(process)
        if time.monotonic() >= deadline:
            raise TimeoutError
        if check_cancelled is not None:
            check_cancelled()
        if win32process.ResumeThread(thread) != 1:
            raise OSError("Owned Ollama thread could not resume")
        result = OwnedWindowsChild(process, pid, job)
        process = None
        job = None
        return result
    finally:
        try:
            if job is not None:
                try:
                    # Assignment failure leaves this exact process suspended.
                    if process is not None:
                        win32api.TerminateProcess(process, 1)
                finally:
                    job.close()
        finally:
            try:
                if process is not None:
                    process.Close()
            finally:
                if thread is not None:
                    thread.Close()
