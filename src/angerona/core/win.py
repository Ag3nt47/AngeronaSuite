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


def run_hidden(args, **kwargs):
    """subprocess.run with no popup console window."""
    kwargs.setdefault("creationflags", NO_WINDOW)
    kwargs.setdefault("startupinfo", _startupinfo())
    return subprocess.run(args, **kwargs)


def check_output_hidden(args, **kwargs):
    """subprocess.check_output with no popup console window."""
    kwargs.setdefault("creationflags", NO_WINDOW)
    kwargs.setdefault("startupinfo", _startupinfo())
    return subprocess.check_output(args, **kwargs)


def popen_hidden(args, **kwargs):
    """subprocess.Popen with no popup console window."""
    kwargs.setdefault("creationflags", NO_WINDOW)
    kwargs.setdefault("startupinfo", _startupinfo())
    return subprocess.Popen(args, **kwargs)
