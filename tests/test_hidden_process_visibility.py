"""Background visibility composition and preserved process launch contracts."""
from __future__ import annotations

import hashlib
from contextlib import nullcontext
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import win


NO_WINDOW = 0x08000000
NEW_CONSOLE = 0x10
DETACHED = 0x8
NEW_GROUP = 0x200
SUSPENDED = 0x4
BREAKAWAY = 0x01000000


@pytest.fixture
def windows_boundary(monkeypatch):
    """Capture actual Popen argument binding without launching any process."""
    captured = []

    class StartupInfo:
        def __init__(self):
            self.dwFlags = 0
            self.wShowWindow = 1
            self.hStdInput = self.hStdOutput = self.hStdError = None
            self.lpAttributeList = None

    class Popen:
        def __init__(self, args, bufsize=-1, executable=None, stdin=None, stdout=None,
                     stderr=None, preexec_fn=None, close_fds=True, shell=False,
                     cwd=None, env=None, universal_newlines=None, startupinfo=None,
                     creationflags=0, **kwargs):
            self.arguments = dict(args=args, bufsize=bufsize, executable=executable,
                                  stdin=stdin, stdout=stdout, stderr=stderr,
                                  preexec_fn=preexec_fn, close_fds=close_fds,
                                  shell=shell, cwd=cwd, env=env,
                                  universal_newlines=universal_newlines,
                                  startupinfo=startupinfo, creationflags=creationflags,
                                  **kwargs)
            captured.append(self.arguments)

    module = SimpleNamespace(**vars(subprocess))
    module.Popen = Popen
    module.STARTUPINFO = StartupInfo
    module.STARTF_USESHOWWINDOW = 1
    monkeypatch.setattr(win, "subprocess", module)
    # Replace only this module's OS view, never global os.name/pathlib behavior.
    monkeypatch.setattr(win, "os", SimpleNamespace(name="nt", environ=os.environ))
    return SimpleNamespace(module=module, captured=captured)


@pytest.mark.parametrize("flags", [0, NEW_GROUP, SUSPENDED | NEW_GROUP,
                                    BREAKAWAY | SUSPENDED | NEW_GROUP,
                                    NEW_CONSOLE | NEW_GROUP,
                                    DETACHED | NEW_GROUP,
                                    DETACHED | NEW_CONSOLE | BREAKAWAY | SUSPENDED | NEW_GROUP])
def test_default_composes_visibility_with_explicit_security_and_job_flags(windows_boundary, flags):
    boundary = windows_boundary
    win.install_no_window_default()
    process = boundary.module.Popen(["owned-helper"], creationflags=flags,
                                    close_fds=True, start_new_session=True,
                                    cwd="owned-workspace", env={"OWNED": "value"})
    row = process.arguments
    assert row["creationflags"] == ((flags & ~(NEW_CONSOLE | DETACHED)) | NO_WINDOW)
    assert row["startupinfo"].dwFlags & 1
    assert row["startupinfo"].wShowWindow == 0
    assert row["close_fds"] is True and row["start_new_session"] is True
    assert row["cwd"] == "owned-workspace" and row["env"] == {"OWNED": "value"}


def test_startupinfo_handles_and_nonvisibility_flags_are_copied_without_mutation(windows_boundary):
    boundary = windows_boundary
    supplied = boundary.module.STARTUPINFO()
    supplied.dwFlags = 0x100  # STARTF_USESTDHANDLES
    supplied.wShowWindow = 5
    supplied.hStdInput, supplied.hStdOutput, supplied.hStdError = 101, 102, 103
    supplied.lpAttributeList = {"handle_list": [101, 102, 103], "other": "retained"}
    win.install_no_window_default()
    process = boundary.module.Popen(["owned-helper"], startupinfo=supplied, creationflags=0)
    actual = process.arguments["startupinfo"]
    assert actual is not supplied
    assert actual.dwFlags == 0x101 and actual.wShowWindow == 0
    assert (actual.hStdInput, actual.hStdOutput, actual.hStdError) == (101, 102, 103)
    assert actual.lpAttributeList == supplied.lpAttributeList
    actual.lpAttributeList["handle_list"].append(999)
    assert supplied.dwFlags == 0x100 and supplied.wShowWindow == 5
    assert supplied.lpAttributeList["handle_list"] == [101, 102, 103]
    assert not hasattr(supplied, "_angerona_interactive_console")


def test_positional_startupinfo_and_flags_keep_standard_argument_binding(windows_boundary):
    boundary = windows_boundary
    supplied = boundary.module.STARTUPINFO()
    win.install_no_window_default()
    process = boundary.module.Popen(["owned-helper"], -1, None, "input", "output", "errors",
                                    None, True, False, "owned-workspace", {"X": "Y"}, None,
                                    supplied, SUSPENDED | NEW_GROUP)
    row = process.arguments
    assert row["creationflags"] == NO_WINDOW | SUSPENDED | NEW_GROUP
    assert row["startupinfo"] is not supplied
    assert row["stdin"] == "input" and row["stdout"] == "output" and row["stderr"] == "errors"
    assert row["env"] == {"X": "Y"} and row["close_fds"] is True


def test_invalid_duplicate_arguments_do_not_launch_or_get_reinterpreted(windows_boundary):
    boundary = windows_boundary
    win.install_no_window_default()
    with pytest.raises(TypeError):
        boundary.module.Popen(["owned-helper"], -1, None, None, None, None, None,
                              True, False, None, None, None, None, 0, creationflags=NEW_GROUP)
    assert boundary.captured == []


@pytest.mark.parametrize("flags", [0, DETACHED | NEW_CONSOLE])
def test_hidden_helper_cannot_opt_out_with_flags_zero_or_interactive_startupinfo(windows_boundary, flags):
    boundary = windows_boundary
    supplied = boundary.module.STARTUPINFO()
    supplied._angerona_interactive_console = True
    win.install_no_window_default()
    process = win.popen_hidden(["owned-helper"], creationflags=flags, startupinfo=supplied)
    assert process.arguments["creationflags"] == NO_WINDOW
    assert process.arguments["startupinfo"].wShowWindow == 0
    assert process.arguments["startupinfo"]._angerona_interactive_console is False
    assert supplied._angerona_interactive_console is True


def test_explicit_interactive_helper_preserves_reviewed_visible_options(windows_boundary, monkeypatch):
    boundary = windows_boundary
    supplied = boundary.module.STARTUPINFO()
    supplied.dwFlags, supplied.wShowWindow = 1, 5
    monkeypatch.setenv("OPENAI_API_KEY", "private-test-secret")
    win.install_no_window_default()
    process = win.popen_interactive(["reviewed-builder"], creationflags=NEW_CONSOLE | NEW_GROUP,
                                   startupinfo=supplied, env_allowlist={"LANG": "C"})
    actual = process.arguments
    assert actual["creationflags"] == NEW_CONSOLE | NEW_GROUP
    assert actual["startupinfo"].wShowWindow == 5 and actual["startupinfo"].dwFlags == 1
    assert actual["startupinfo"] is not supplied
    assert "OPENAI_API_KEY" not in actual["env"] and actual["env"]["LANG"] == "C"
    assert not hasattr(supplied, "_angerona_interactive_console")


def test_no_window_installation_is_idempotent_without_replacing_popen_class(windows_boundary):
    boundary = windows_boundary
    original_class = boundary.module.Popen
    win.install_no_window_default()
    first = boundary.module.Popen.__init__
    win.install_no_window_default()
    assert boundary.module.Popen is original_class
    assert boundary.module.Popen.__init__ is first
    boundary.module.Popen(["owned-helper"])
    assert len(boundary.captured) == 1


def test_direct_scanner_worker_hides_nested_commands_before_loading_pinned_bytes(
        windows_boundary, monkeypatch, tmp_path):
    """An inert engine fixture tests launch presentation, not scan authority."""
    from angerona.core import curated_tool_worker as worker
    from angerona.core import source_sandbox
    job = tmp_path / "job"
    for key in ("TEMP", "TMP", "TMPDIR"):
        monkeypatch.setenv(key, str(job / "scratch"))
    document = {"kind": "version", "limits": {"retained_bytes": 5 * 1024**2, "working_bytes": 64 * 1024**2}}
    source = b"from angerona.core import win\ndef main(args):\n win.subprocess.Popen(['inert-pinned-reader'], creationflags=0x210)\n return 0\n"
    monkeypatch.setattr(worker, "_pipe_streams", lambda: None)
    monkeypatch.setattr(worker, "_user_only", lambda: None)
    monkeypatch.setattr(worker, "_request", lambda *_: (document, tmp_path, job, tmp_path / "engine.py", source))
    monkeypatch.setattr(worker, "_arguments", lambda *_: [])
    monkeypatch.setattr(worker, "_posix_limits", lambda *_: None)
    monkeypatch.setattr(source_sandbox, "_hold_plain_directories", lambda *_: nullcontext())
    monkeypatch.setattr(worker, "_WriteBudget", lambda *_: SimpleNamespace(install=lambda: None))
    monkeypatch.setattr(worker, "sys", SimpleNamespace(
        stdin=SimpleNamespace(buffer=io.BytesIO(b"{}\n")), stderr=sys.stderr, modules=sys.modules, argv=[]))
    assert worker.main(["inert-private-request.json"]) == 0
    assert len(windows_boundary.captured) == 1
    actual = windows_boundary.captured[0]
    assert actual["args"] == ["inert-pinned-reader"]
    assert actual["creationflags"] == NEW_GROUP | NO_WINDOW
    assert actual["startupinfo"].wShowWindow == 0


def test_nonwindows_keeps_caller_process_options_and_does_not_patch(monkeypatch):
    captured = []

    class Popen:
        def __init__(self, args, **kwargs):
            captured.append((args, kwargs))

    module = SimpleNamespace(**vars(subprocess))
    module.Popen = Popen
    monkeypatch.setattr(win, "subprocess", module)
    monkeypatch.setattr(win, "os", SimpleNamespace(name="posix", environ=os.environ))
    original = Popen.__init__
    win.install_no_window_default()
    token = object()
    win.popen_hidden(["owned-helper"], startupinfo=token, creationflags=0, start_new_session=True)
    assert Popen.__init__ is original
    assert captured[0][1]["startupinfo"] is token
    assert captured[0][1]["creationflags"] == 0 and captured[0][1]["start_new_session"] is True


@pytest.mark.skipif(os.name == "nt", reason="actual non-Windows subprocess contract")
def test_actual_nonwindows_hidden_helper_keeps_pipes_usable():
    result = win.run_hidden([sys.executable, "-I", "-c", "import sys;sys.stdout.write(sys.stdin.read())"],
                            input="owned helper pipe", text=True, capture_output=True,
                            timeout=10, check=True)
    assert result.stdout == "owned helper pipe" and result.stderr == ""


@pytest.mark.skipif(os.name != "nt", reason="actual Windows console and inherited-pipe contract")
def test_actual_windows_default_hides_explicit_new_console_and_preserves_pipes():
    # This entire experiment runs in an isolated diagnostic process. The real
    # pytest subprocess module and the operator's application are not patched.
    inner = r'''
import ctypes, hashlib, json, subprocess, sys, types
from pathlib import Path
source = Path(sys.argv[1])
raw = source.read_bytes()
assert len(raw) < 65536 and hashlib.sha256(raw).hexdigest() == sys.argv[2]
candidate = types.ModuleType('owned_visibility_candidate')
candidate.__file__ = str(source)
exec(compile(raw, str(source), 'exec'), candidate.__dict__)
candidate.install_no_window_default()
supplied = subprocess.STARTUPINFO()
supplied.dwFlags = subprocess.STARTF_USESHOWWINDOW
supplied.wShowWindow = 5
child = "import ctypes,json,sys; ctypes.windll.kernel32.GetConsoleWindow.restype=ctypes.c_void_p; print(json.dumps({'console':ctypes.windll.kernel32.GetConsoleWindow() or 0,'input':sys.stdin.read()}))"
result = subprocess.run([sys.executable, '-I', '-c', child],
    input='owned helper pipe', text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    startupinfo=supplied, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
    timeout=15, check=True)
assert supplied.dwFlags == subprocess.STARTF_USESHOWWINDOW and supplied.wShowWindow == 5
print(json.dumps({'child':json.loads(result.stdout),'stderr':result.stderr,'caller_unchanged':True}))
'''
    # Bind the actual isolated child to this exact module's bytes. A private
    # candidate test must not silently exercise the canonical installed module.
    source = Path(win.__file__).resolve(strict=True)
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    result = subprocess.run([sys.executable, "-I", "-c", inner, str(source), expected], capture_output=True,
                            stdin=subprocess.DEVNULL, text=True, timeout=25, check=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert len(result.stdout) < 4096 and result.stderr == ""
    row = json.loads(result.stdout)
    assert row["child"] == {"console": 0, "input": "owned helper pipe"}
    assert row["stderr"] == "" and row["caller_unchanged"] is True
