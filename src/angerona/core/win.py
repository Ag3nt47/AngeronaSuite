"""Windows process helpers — suppress background helper console windows.

yara64.exe / netstat / cmd are console programs; when launched from the GUI they
flash an empty console window. Passing CREATE_NO_WINDOW + a hidden STARTUPINFO
suppresses that entirely. No-ops cleanly on non-Windows.
"""
from __future__ import annotations

import os
import subprocess
import copy
import inspect

NO_WINDOW = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_CONSOLE = 0x00000010
_DETACHED_PROCESS = 0x00000008
_INTERACTIVE_CONSOLE = "_angerona_interactive_console"


def _startupinfo(existing=None, *, hidden=True):
    """Copy visibility options without changing caller handles or attributes."""
    if os.name != "nt":
        return existing
    si = subprocess.STARTUPINFO() if existing is None else copy.copy(existing)
    attributes = getattr(si, "lpAttributeList", None)
    if attributes is not None:
        si.lpAttributeList = dict(attributes)
        if "handle_list" in si.lpAttributeList:
            si.lpAttributeList["handle_list"] = list(si.lpAttributeList["handle_list"])
    if hidden:
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
    setattr(si, _INTERACTIVE_CONSOLE, not hidden)
    return si


def _hidden_child_kwargs(kwargs):
    prepared = dict(kwargs)
    if os.name == "nt":
        # Windows ignores CREATE_NO_WINDOW with either of these console flags.
        # Remove both for background launches; job/session/priority/suspended
        # creation flags remain exactly as requested by the existing owner.
        prepared["creationflags"] = (
            prepared.get("creationflags", 0) & ~(_CREATE_NEW_CONSOLE | _DETACHED_PROCESS)
        ) | _CREATE_NO_WINDOW
        prepared["startupinfo"] = _startupinfo(prepared.get("startupinfo"))
    else:
        prepared.setdefault("creationflags", NO_WINDOW)
        prepared.setdefault("startupinfo", None)
    return prepared


def _protected_child_kwargs(kwargs, *, hidden=True):
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
    if hidden:
        return _hidden_child_kwargs(prepared)
    if os.name == "nt":
        prepared["startupinfo"] = _startupinfo(prepared.get("startupinfo"), hidden=False)
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


def popen_interactive(args, **kwargs):
    """Preserve an explicitly requested, reviewed interactive child window.

    Visibility is separate from elevation, trust and process lifetime. The
    protected environment policy still applies. UAC/ShellExecute and native
    installed-process launch boundaries are not changed by this helper.
    """
    return subprocess.Popen(args, **_protected_child_kwargs(kwargs, hidden=False))


def install_no_window_default() -> None:
    """Default this process's subprocess launches to hidden console windows.

    Many modules call ``subprocess.run``/``Popen`` (netsh, tasklist, signal-cli,
    yara, git, …) without hiding the window, so a console flashes every time one
    runs — the "random PowerShell/cmd windows" the user sees. This patches
    ``subprocess.Popen.__init__`` so explicit zero or unrelated creation flags
    cannot accidentally bypass background visibility. Caller STARTUPINFO is
    copied, including handle lists; unrelated creation flags remain intact.
    Deliberately interactive actions use ``popen_interactive``. The Popen class
    and its native process/handle ownership contract remain unchanged.

    Call once at process startup, before modules load. No-op off Windows or if
    already installed.
    """
    if os.name != "nt" or getattr(subprocess.Popen, "_angerona_nowindow", False):
        return
    _orig_init = subprocess.Popen.__init__
    parameters = [parameter for parameter in list(inspect.signature(_orig_init).parameters.values())[1:]
                  if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    positions = {parameter.name: index for index, parameter in enumerate(parameters)}

    def _patched_init(self, *args, **kwargs):
        positional = list(args)
        supplied = {}
        for name, default in (("creationflags", 0), ("startupinfo", None)):
            position = positions.get(name)
            if position is not None and position < len(positional):
                if name in kwargs:
                    # Preserve the standard invalid-argument error rather
                    # than launching with an invented interpretation.
                    return _orig_init(self, *args, **kwargs)
                supplied[name] = positional[position]
            else:
                supplied[name] = kwargs.get(name, default)
        if getattr(supplied["startupinfo"], _INTERACTIVE_CONSOLE, False) is True:
            return _orig_init(self, *args, **kwargs)
        prepared = _hidden_child_kwargs(supplied)
        for name, value in prepared.items():
            position = positions.get(name)
            if position is not None and position < len(positional):
                positional[position] = value
            else:
                kwargs[name] = value
        return _orig_init(self, *positional, **kwargs)

    _patched_init.__wrapped__ = _orig_init
    subprocess.Popen.__init__ = _patched_init          # type: ignore[assignment]
    subprocess.Popen._angerona_nowindow = True         # marker (idempotent)
