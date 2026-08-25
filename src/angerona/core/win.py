"""Windows process helpers — run child processes completely hidden.

yara64.exe / netstat / cmd are console programs; when launched from the GUI they
flash an empty console window. Passing CREATE_NO_WINDOW + a hidden STARTUPINFO
suppresses that entirely. No-ops cleanly on non-Windows.
"""
from __future__ import annotations

import os
import subprocess

NO_WINDOW = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW


def _startupinfo():
    if os.name != "nt":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def _protected_child_kwargs(kwargs):
    """Return child kwargs with an explicit, secret-free environment.

    Callers that need a non-secret variable must pass it through
    ``env_allowlist={...}``; an ordinary ``env`` mapping is treated only as the
    source of OS/runtime values and is sanitized before launch.
    """
    from angerona.core.privilege import sanitized_child_environment

    prepared = dict(kwargs)
    allowlist = prepared.pop("env_allowlist", None)
    source = prepared.pop("env", None)
    prepared["env"] = sanitized_child_environment(
        allowlist,
        source=os.environ if source is None else source,
    )
    prepared.setdefault("creationflags", NO_WINDOW)
    prepared.setdefault("startupinfo", _startupinfo())
    return prepared


def run_hidden(args, **kwargs):
    """subprocess.run with no popup console window."""
    return subprocess.run(args, **_protected_child_kwargs(kwargs))


def check_output_hidden(args, **kwargs):
    """subprocess.check_output with no popup console window."""
    return subprocess.check_output(args, **_protected_child_kwargs(kwargs))


def popen_hidden(args, **kwargs):
    """subprocess.Popen with no popup console window."""
    return subprocess.Popen(args, **_protected_child_kwargs(kwargs))


def install_no_window_default() -> None:
    """Globally stop child processes from flashing console windows.

    Many modules call ``subprocess.run``/``Popen`` (netsh, tasklist, signal-cli,
    yara, git, …) without hiding the window, so a console flashes every time one
    runs — the "random PowerShell/cmd windows" the user sees. This patches
    ``subprocess.Popen`` so any call that does NOT explicitly set ``creationflags``
    or ``startupinfo`` gets CREATE_NO_WINDOW + a hidden STARTUPINFO. Calls that DO
    set those (e.g. the resilience minimized-window launches) are left untouched.

    Call once at process startup, before modules load. No-op off Windows or if
    already installed.
    """
    if os.name != "nt" or getattr(subprocess.Popen, "_angerona_nowindow", False):
        return
    _orig_init = subprocess.Popen.__init__

    def _patched_init(self, *args, **kwargs):
        if "creationflags" not in kwargs and "startupinfo" not in kwargs:
            kwargs["creationflags"] = NO_WINDOW
            kwargs["startupinfo"] = _startupinfo()
        return _orig_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _patched_init          # type: ignore[assignment]
    subprocess.Popen._angerona_nowindow = True         # marker (idempotent)
