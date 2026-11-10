"""Owned CreateProcess presentation and actual venv/nested console regression.

The native case runs only the fixed inert fixture below, with no Qt/Core or
security engine. It never launches the former conflicting flags on a desktop.
"""
from __future__ import annotations

from dataclasses import asdict
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import windows_child_job as jobs


@pytest.mark.parametrize("window,hidden,show", [("hidden", True, 0), ("visible", False, 1), ("minimized", False, 7)])
def test_owned_launch_flags_keep_suspension_job_assignment_and_explicit_visible_modes(monkeypatch, window, hidden, show):
    events = []; captured = {}
    class Handle:
        def Close(self): events.append("close")
    class Job:
        def __init__(self, **options): self._handle = Handle(); captured["job_options"] = options
        def assign(self, process): events.append("assign")
        def close(self): self._handle = None; events.append("job-close")
    def create(*args):
        captured.update(flags=args[5], startup=args[8]); events.append("create")
        return Handle(), Handle(), 424242, 424243
    def resume(_thread): events.append("resume"); return 1
    constants = SimpleNamespace(STARTF_USESHOWWINDOW=1, DETACHED_PROCESS=8,
        CREATE_NEW_PROCESS_GROUP=0x200, CREATE_NO_WINDOW=0x08000000, CREATE_NEW_CONSOLE=0x10,
        CREATE_SUSPENDED=4, CREATE_UNICODE_ENVIRONMENT=0x400)
    api = SimpleNamespace(STARTUPINFO=lambda: SimpleNamespace(), CreateProcess=create, ResumeThread=resume)
    monkeypatch.setitem(sys.modules, "win32con", constants)
    monkeypatch.setitem(sys.modules, "win32process", api)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace())
    monkeypatch.setattr(jobs, "WindowsChildJob", Job)
    owner = jobs.launch_windows_child([str(Path(sys.executable).absolute()), "-I", "fixed-inert.py"], {}, window=window)
    try:
        expected = 4 | 0x400 | 0x200 | (0x08000000 if hidden else 0x10)
        assert captured["flags"] == expected and not captured["flags"] & 8
        assert captured["startup"].dwFlags == 1 and captured["startup"].wShowWindow == show
        assert events[:3] == ["create", "assign", "resume"]
        assert captured["job_options"] == {"kill_on_close": True}
    finally: owner.close()


FIXTURE = r'''
import ctypes,hashlib,json,os,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]);mode=sys.argv[2];expected=sys.argv[3];nested_flags=int(sys.argv[4])
assert mode in ('worker','nested') and hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==expected
kernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.GetConsoleWindow.restype=ctypes.c_void_p
user=ctypes.WinDLL('user32',use_last_error=True);user.IsWindowVisible.argtypes=[ctypes.c_void_p]
console=kernel.GetConsoleWindow() or 0
record={'pid':os.getpid(),'console':console,'console_visible':bool(console and user.IsWindowVisible(console)),'mode':mode}
if mode=='worker':
    from angerona.core.win import install_no_window_default
    install_no_window_default()
    child=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).absolute()),str(root),'nested',expected,str(nested_flags)],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=nested_flags)
    record['spawned_pid']=child.pid
(root/(mode+'.json')).write_text(json.dumps(record),encoding='ascii')
deadline=time.monotonic()+30
while time.monotonic()<deadline: time.sleep(.05)
'''


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows venv redirector/console and owned Job gate")
@pytest.mark.parametrize("nested_flags", [0, 0x8], ids=["default", "detached-caller"])
def test_actual_hidden_venv_and_nested_default_have_no_console_or_visible_owned_window(tmp_path, nested_flags):
    from angerona.core.privilege import sanitized_child_environment
    from angerona.core.windows_process_lease import _Native
    import psutil
    root = Path(__file__).resolve().parents[1]
    executable = root / "venv" / "Scripts" / "python.exe"
    if not executable.is_file():
        pytest.skip("This explicit venv redirector gate requires the source workspace venv")
    source = tmp_path / "fixed-visibility-fixture.py"
    source.write_text(FIXTURE, encoding="utf-8")
    fixture_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    owner = jobs.launch_windows_child([str(executable), "-I", "-B", str(source), str(tmp_path), "worker", fixture_hash, str(nested_flags)],
        sanitized_child_environment(source={}), cwd=str(tmp_path), window="hidden")
    native = _Native(); pins = []; rows = (); evidence = {}; completed = False
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not all((tmp_path / (name + ".json")).exists() for name in ("worker", "nested")):
            assert owner.poll() is None
            time.sleep(.02)
        observed = {name: json.loads((tmp_path / (name + ".json")).read_text()) for name in ("worker", "nested")}
        result = []; errors = []
        def capture():
            try: result.append(owner.observe_owned_process_identities(role="visibility-test"))
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=capture, daemon=False); thread.start(); thread.join(3)
        assert not thread.is_alive() and not errors
        rows = result[0]
        assert {owner.pid, observed["worker"]["pid"], observed["nested"]["pid"], observed["worker"]["spawned_pid"]} <= {row.pid for row in rows}
        for row in rows:
            pin = native.open(row.pid, 0x101000, False); identity = native.identity(pin)
            assert (identity.pid, str(identity.birth_ticks), identity.image) == (row.pid, row.birth_ticks, row.image)
            pins.append((pin, identity))
        actual = psutil.Process(observed["worker"]["pid"])
        nested = psutil.Process(observed["nested"]["pid"])
        assert actual.ppid() == owner.pid and nested.ppid() == observed["worker"]["spawned_pid"]
        assert actual.cmdline()[1:3] == ["-I", "-B"] and nested.cmdline()[1:3] == ["-I", "-B"]
        assert all(row["console"] == 0 and not row["console_visible"] for row in observed.values())
        user = ctypes.WinDLL("user32", use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]; user.EnumWindows.restype = wintypes.BOOL
        user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user.IsWindowVisible.argtypes = [wintypes.HWND]; user.IsWindowVisible.restype = wintypes.BOOL
        visible = []; known = {row.pid for row in rows}
        def window(window, _unused):
            pid = wintypes.DWORD(); user.GetWindowThreadProcessId(window, ctypes.byref(pid))
            if pid.value in known and user.IsWindowVisible(window): visible.append((pid.value, int(window)))
            return True
        callback = callback_type(window)
        for _unused in range(3):
            assert user.EnumWindows(callback, 0); time.sleep(.05)
        assert visible == []
        evidence = dict(observed=observed, visible_owned_windows=visible, requested_nested_flags=nested_flags,
            fixture_sha256=fixture_hash,
            source_sha256=hashlib.sha256(Path(jobs.__file__).read_bytes()).hexdigest())
        completed = True
    finally:
        # Both fixed fixture roles remain alive until this exact owner retires
        # their Job; capture immediately before mutation, never reuse old cuts.
        owner.prepare_tree_retirement(timeout=3)
        owner.terminate(); owner.wait(timeout=3); owner.wait_tree(timeout=3)
        retired = []
        for pin, identity in pins:
            retired.append(dict(pid=identity.pid, birth_ticks=str(identity.birth_ticks),
                object_unchanged=native.object_identity(pin)==(identity.pid, identity.birth_ticks),
                signaled=native.wait(pin,0), exit_code=native.exit_code(pin)))
            native.close(pin)
        owner.close()
        evidence.update(completed=completed, members=[asdict(row) for row in rows], retired=retired,
            tree=owner.tree_retirement_snapshot(), retained_query_handles_closed=True)
        (tmp_path / "visibility-native-witness.json").write_text(json.dumps(evidence,indent=2))
    assert completed and retired and all(row["signaled"] and row["object_unchanged"] for row in retired)
    assert evidence["tree"]["signals_proven"] and evidence["tree"]["handles_closed"]
