"""Administrator-privilege handling.

Angerona needs an elevated token for full-system telemetry (process internals,
ETW kernel providers, protected file paths). On launch we check whether we are
already elevated; if not, we relaunch ourselves through the UAC prompt. On
non-Windows (developer machines) these are graceful no-ops.
"""
from __future__ import annotations

import ctypes
import sys


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False  # not Windows, or call unavailable


def ensure_admin() -> None:
    """Relaunch elevated if we aren't already. No-op off Windows."""
    if sys.platform != "win32":
        return
    if is_admin():
        return
    try:
        if getattr(sys, "frozen", False):
            # Packaged .exe: relaunch the exe itself with the original args.
            target = sys.executable
            params = " ".join(f'"{a}"' for a in sys.argv[1:])
        else:
            # Dev: relaunch the interpreter as `python -m angerona <args>`.
            target = sys.executable
            args = " ".join(f'"{a}"' for a in sys.argv[1:])
            params = f"-m angerona {args}".strip()
        # ShellExecuteW verb 'runas' triggers the UAC consent dialog.
        ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)
    except Exception:
        # If elevation fails, continue unelevated with reduced visibility
        # rather than refusing to start.
        return
    raise SystemExit(0)  # the elevated instance takes over
