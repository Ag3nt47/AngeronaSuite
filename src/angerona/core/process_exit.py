"""Immediate self-exit after the operator's bounded shutdown sequence.

This is a final-exit primitive, not a resource-cleanup or response backend. The
caller must first record durable STOP intent and attempt owned-resource cleanup.
It selects no other process and does not establish descendant retirement.
"""
from __future__ import annotations

import os
from typing import NoReturn


def _terminate_current_windows_process() -> None:
    """Use the current-process pseudo-handle only, without DLL-detach notices.

    Successful self-termination does not return. The caller retains the CRT
    fallback if native binding fails or this call unexpectedly returns. No real
    process handle is opened, accepted from a caller, or closed here.
    """
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    current_process = kernel.GetCurrentProcess
    current_process.argtypes = []
    current_process.restype = wintypes.HANDLE
    terminate_process = kernel.TerminateProcess
    terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
    terminate_process.restype = wintypes.BOOL

    # GetCurrentProcess is documented to return this pseudo-handle. Pass the
    # fixed value, never an arbitrary handle returned by an unexpected binding.
    pseudo_handle = ctypes.c_void_p(-1).value
    observed = current_process()
    if type(observed) is not int or observed != pseudo_handle:
        raise OSError("Current-process pseudo-handle is unavailable")
    terminate_process(pseudo_handle, 0)


def exit_after_operator_shutdown() -> NoReturn:
    """Finish this process only, after the existing shutdown cleanup attempt.

    Windows self-termination avoids final DLL process-detach notifications.
    It can still involve pending-I/O cancellation and is not proof of completed
    cleanup or a repair for every native crash. No I/O or logging is added to
    this terminal path. Other platforms retain their existing CRT exit.
    """
    if os.name == "nt":
        try:
            _terminate_current_windows_process()
        except Exception:
            # An unavailable native path cannot leave a recorded STOP hanging.
            pass
    # Even a nominally successful but unexpectedly returning native call must
    # not let the stopped dashboard remain alive or restart its event loop.
    os._exit(0)
