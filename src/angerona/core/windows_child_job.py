"""Retained Windows Job custody for explicitly launched child process trees.

Children are suspended until assigned. No process
table, process-name match, inherited handle, or PID lookup grants ownership.
"""
from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path


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

    def terminate(self):
        # Terminate the job even after its server exits: a runner can outlive it.
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
        self._job.close()
        with self._handle_lock:
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
