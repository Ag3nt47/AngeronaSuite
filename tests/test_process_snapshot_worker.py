"""Inert inventory process/Qt/transport contracts; no security actions."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.telemetry import sensors


@pytest.fixture(scope="session", autouse=True)
def _worker_qt_application():
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        yield
        return
    app = QApplication.instance()
    owns = app is None
    if owns:
        app = QApplication([])
    yield
    if owns:
        app.shutdown()


@pytest.fixture(autouse=True)
def inventory_owner_isolation(monkeypatch):
    monkeypatch.setattr(sensors, "_process_snapshot_provider", None, raising=False)
    monkeypatch.setattr(sensors, "_process_snapshot_provider_generation", 0, raising=False)
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))


def _worker():
    from angerona.telemetry import process_snapshot_worker
    return process_snapshot_worker


def _off_gui(fn, timeout=10):
    output = []
    def call():
        try:
            output.append((True, fn()))
        except BaseException as exc:
            output.append((False, exc))
    thread = threading.Thread(target=call, name="InertInventoryTest")
    thread.start(); thread.join(timeout)
    assert not thread.is_alive(), "owned test caller did not retire"
    if not output[0][0]:
        raise output[0][1]
    return output[0][1]


def _fixture_command(mode="normal", marker=None, executable=None):
    # This fixed test program installs an inert psutil adapter only during the
    # original rich collector. Production worker accepts no collector/code arg.
    directory = str(Path(_worker().__file__).parent)
    code = f'''
import sys,os,time,types
import angerona.telemetry as package
package.__path__.insert(0,{directory!r})
from angerona.telemetry import sensors as s, process_snapshot_worker as w
mode={mode!r}
marker={str(marker) if marker else None!r}
original=s._collect_process_snapshot
row={{"pid":731,"name":"fixture.exe","exe":"C:/fixture.exe","username":"fixture","cmdline":["fixture.exe","literal"],"create_time":100.0,"ppid":4}}
class Process:
 def __init__(self,pid):self.pid=pid
 def as_dict(self,*,attrs,ad_value):return {{key:row.get(key) for key in attrs}}
def collect():
 if marker:
  with open(marker,'w') as target:target.write(str(os.getpid()))
 if mode=='blocked':
  import ctypes
  if os.name=='nt':ctypes.PyDLL('kernel32').Sleep(5000)
  else:ctypes.PyDLL(None).usleep(5000000)
 old=sys.modules.get('psutil')
 sys.modules['psutil']=types.SimpleNamespace(pids=lambda:[731],Process=Process,_ppid_map=lambda:{{731:4}})
 try:return original()
 finally:
  if old is not None:sys.modules['psutil']=old
s._collect_process_snapshot=collect
if mode in ('bad-mac','wrong-sequence','wrong-birth','bad-coverage'):
 old_wrap=w._wrap
 def wrap(body,key,direction):
  if body.get('kind')=='snapshot-result':
   if mode=='wrong-sequence':body={{**body,'sequence':body['sequence']+1}}
   if mode=='wrong-birth':body={{**body,'child_birth':'1'}}
   if mode=='bad-coverage':body={{**body,'snapshot':{{**body['snapshot'],'complete':True,'identity_incomplete':1}}}}
  result=old_wrap(body,key,direction)
  if mode=='bad-mac' and body.get('kind')=='snapshot-result':result['mac']='0'*64
  return result
 w._wrap=wrap
if mode=='oversize':
 old_send=w._send
 def send(sink,value,limit=w.MAX_FRAME):
  if value.get('body',{{}}).get('kind')=='snapshot-result':
   import struct
   sink.write(struct.pack('!I',w.MAX_FRAME+1));sink.flush();return
  return old_send(sink,value,limit)
 w._send=send
if mode=='exit-before-hello':os._exit(9)
if mode=='slow-start':
 if marker:
  with open(marker,'w') as target:target.write('pre-hello-child-executed')
 time.sleep(3)
raise SystemExit(w.worker_main())
'''
    return [executable or sys.executable, "-c", code]


def _provider(mode="normal", *, marker=None, executable=None, request_timeout=3, startup_timeout=5):
    return _worker().ProcessSnapshotProvider(_fixture_command(mode, marker, executable),
        request_timeout=request_timeout, startup_timeout=startup_timeout)


def _retire(provider):
    assert _off_gui(lambda: provider.stop(3)), json.dumps(provider.lifecycle_snapshot())
    state = provider.lifecycle_snapshot()
    assert state["retired"] and not state["ready"]
    assert all(p["wait_signaled"] for p in state["retirement_proofs"])
    assert _off_gui(lambda: provider.stop(1))
    return state


def test_gui_snapshot_admission_precedes_cache_lock_and_local_native_work(monkeypatch):
    qt = pytest.importorskip("PySide6.QtCore")
    assert qt.QCoreApplication.instance() is not None
    native_calls = []
    row = {"pid":731,"name":"fixture","exe":"C:/fixture.exe","username":"fixture",
           "cmdline":["fixture"],"create_time":100.0,"ppid":4}
    class Process:
        def __init__(self, pid): self.pid = pid
        def as_dict(self, *, attrs, ad_value):
            native_calls.append(self.pid)
            time.sleep(0.05)  # Inert provider that would block Qt if called here.
            return {key:row.get(key) for key in attrs}
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        pids=lambda:[731], Process=Process, _ppid_map=lambda:{731:4}))
    provider = SimpleNamespace(snapshot=lambda: pytest.fail("GUI entered provider"))
    monkeypatch.setattr(sensors, "_process_snapshot_provider", provider, raising=False)
    receipt = sensors.process_snapshot(max_age=0)
    assert native_calls == []
    assert not receipt.complete and not receipt.enumeration_complete and receipt.error
    # Holding the global miss lock cannot block a Qt caller either.
    with sensors._proc_cache_lock:
        receipt = sensors.process_snapshot(max_age=0)
    assert not receipt.complete and "GUI-thread" in receipt.error


def test_constructor_and_cached_lifecycle_do_not_launch_or_collect(monkeypatch):
    w = _worker()
    monkeypatch.setattr(w.subprocess, "Popen", lambda *a,**k:pytest.fail("constructor launched"))
    monkeypatch.setattr(w, "_own_birth", lambda:pytest.fail("constructor queried provider"))
    provider = w.ProcessSnapshotProvider()
    state = provider.lifecycle_snapshot()
    assert state["state"] == "not-started" and not state["ready"]
    assert provider.start() is False  # Qt thread cannot launch/await bootstrap.
    assert provider.stop() is False


def test_native_child_preserves_original_collector_receipt_and_frozen_rows():
    provider = _provider()
    try:
        assert _off_gui(provider.start), provider.lifecycle_snapshot()
        first = _off_gui(provider.snapshot)
        second = _off_gui(provider.snapshot)
        assert first.complete and first.enumeration_complete
        assert first.enumerated == 1 and first.skipped == first.unreadable == first.identity_incomplete == 0
        assert dict(first.processes[0]) == {"pid":731,"name":"fixture.exe","exe":"C:/fixture.exe",
            "username":"fixture","cmdline":("fixture.exe","literal"),"create_time":100.0,"ppid":4}
        assert second.collected_at >= first.collected_at
        with pytest.raises(TypeError): first.processes[0]["pid"] = 1
        state = provider.lifecycle_snapshot()
        assert type(state["child_pid"]) is int and type(state["child_birth"]) is str
        if os.name == "nt": assert state["child_birth"].isdecimal()
    finally:
        state = _retire(provider)
    assert state["retirement_proofs"]


@pytest.mark.skipif(os.name != "nt", reason="Windows pythonw inherited stdio/redirector contract")
def test_pythonw_stdio_and_actual_redirector_child_are_pinned():
    executable = str(Path(sys.executable).with_name("pythonw.exe"))
    if not Path(executable).exists(): pytest.skip("pythonw not installed")
    provider = _provider(executable=executable)
    try:
        assert _off_gui(provider.start), json.dumps(provider.lifecycle_snapshot())
        assert _off_gui(provider.snapshot).complete
        state = provider.lifecycle_snapshot()
        assert state["child_pid"] and state["wrapper_pid"]
    finally:
        state = _retire(provider)
    assert {p["pid"] for p in state["retirement_proofs"]} >= {state["child_pid"],state["wrapper_pid"]}


@pytest.mark.parametrize("mode", ["bad-mac","wrong-sequence","wrong-birth","bad-coverage","oversize"])
def test_bad_authenticated_or_framed_reply_holds_and_retires_without_replacement(mode):
    provider = _provider(mode)
    try:
        assert _off_gui(provider.start)
        pid = provider.lifecycle_snapshot()["child_pid"]
        receipt = _off_gui(provider.snapshot)
        assert not receipt.complete and not receipt.enumeration_complete and receipt.error
        assert not _off_gui(provider.start)
        assert provider.lifecycle_snapshot()["child_pid"] == pid
    finally:
        _retire(provider)


@pytest.mark.parametrize("mode", ["exit-before-hello","slow-start"])
def test_startup_failure_is_bounded_and_cannot_spawn_replacement(mode):
    provider = _provider(mode, startup_timeout=0.3)
    try:
        assert not _off_gui(provider.start)
        before = provider.lifecycle_snapshot()["wrapper_pid"]
        assert not _off_gui(provider.start)
        assert provider.lifecycle_snapshot()["wrapper_pid"] == before
        assert not _off_gui(provider.snapshot).complete
    finally:
        _retire(provider)


def test_child_native_gil_block_does_not_block_qt_or_sensor_gui_admission(tmp_path):
    qt = pytest.importorskip("PySide6.QtCore")
    marker = tmp_path / "collector-entered.txt"
    provider = _provider("blocked", marker=marker, request_timeout=0.8)
    request = []
    thread = None
    try:
        assert _off_gui(provider.start)
        sensors.configure_process_snapshot_provider(provider)
        thread = threading.Thread(target=lambda:request.append(sensors.process_snapshot(max_age=0)))
        thread.start()
        deadline = time.monotonic()+3
        while not marker.exists() and time.monotonic()<deadline:
            time.sleep(0.01)
        assert marker.exists(), "inert child never entered native GIL block"
        observed = []
        qt.QTimer.singleShot(0, lambda:observed.append(True))
        receipt = sensors.process_snapshot(max_age=0)
        qt.QCoreApplication.processEvents()
        assert observed and not receipt.complete and "GUI-thread" in receipt.error
        thread.join(5)
        assert not thread.is_alive() and request and not request[0].complete
    finally:
        _retire(provider)
        if thread is not None: thread.join(5)


def test_parent_cache_start_anchor_max_age_zero_and_no_failure_fallback(monkeypatch):
    calls = []
    clock = SimpleNamespace(value=100.0)
    monkeypatch.setattr(sensors, "_process_snapshot_on_gui_thread", lambda:False)
    monkeypatch.setattr(sensors.time, "monotonic", lambda:clock.value)
    snapshot = sensors.ProcessSnapshot((), 100.0, True, 0, 0)
    def remote(): calls.append(clock.value);clock.value+=2.0;return snapshot
    sensors.configure_process_snapshot_provider(SimpleNamespace(snapshot=remote))
    assert sensors.process_snapshot() is snapshot
    assert sensors._proc_cache[0] == 100.0
    assert sensors.process_snapshot() is snapshot and calls == [100.0,102.0]
    clock.value = 104.1
    assert sensors.process_snapshot(max_age=60) is snapshot and len(calls)==2
    assert sensors.process_snapshot(max_age=0) is snapshot and len(calls)==3
    monkeypatch.setattr(sensors, "_collect_process_snapshot", lambda:pytest.fail("native fallback"))
    sensors.configure_process_snapshot_provider(SimpleNamespace(snapshot=lambda:(_ for _ in ()).throw(OSError())))
    receipt = sensors.process_snapshot()
    assert not receipt.complete and not receipt.enumeration_complete and "OSError" in receipt.error


def test_provider_replacement_cannot_publish_old_inflight_receipt(monkeypatch):
    monkeypatch.setattr(sensors, "_process_snapshot_on_gui_thread", lambda:False)
    old = sensors.ProcessSnapshot((),100.0,True,0,0)
    def replace():
        sensors.configure_process_snapshot_provider(SimpleNamespace(snapshot=lambda:old))
        return old
    sensors.configure_process_snapshot_provider(SimpleNamespace(snapshot=replace))
    receipt = sensors.process_snapshot()
    assert not receipt.complete and "lifecycle changed" in receipt.error
    assert sensors._proc_cache == (0.0,None)


def test_stop_during_blocked_process_creation_retains_launch_until_retirement(monkeypatch):
    w = _worker()
    entered, release = threading.Event(), threading.Event()
    original = w.subprocess.Popen
    def launch(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    provider = _provider(startup_timeout=0.2)
    monkeypatch.setattr(w.subprocess, "Popen", launch)
    result = []
    caller = threading.Thread(target=lambda:result.append(provider.start()))
    caller.start()
    try:
        assert entered.wait(3)
        assert not _off_gui(lambda:provider.stop(0.1))
        assert not provider.lifecycle_snapshot()["retired"]
        assert not _off_gui(provider.start)
    finally:
        release.set()
        caller.join(5)
        _retire(provider)
    assert result == [False] and not caller.is_alive()


@pytest.mark.parametrize("failure",["construct","start"])
def test_failed_ipc_thread_start_is_typed_and_stop_does_not_join_unstarted_thread(monkeypatch,failure):
    w=_worker();provider=_provider()
    original=w.threading.Thread.start
    def start(thread):
        if thread.name=="ProcessInventoryIPC":
            raise RuntimeError("inert thread creation failure")
        return original(thread)
    if failure=="start":
        monkeypatch.setattr(w.threading.Thread,"start",start)
    else:
        constructor=w.threading.Thread
        def build(*args,**kwargs):
            if kwargs.get("name")=="ProcessInventoryIPC":
                raise RuntimeError("inert thread construction failure")
            return constructor(*args,**kwargs)
        monkeypatch.setattr(w.threading,"Thread",build)
    monkeypatch.setattr(w.subprocess,"Popen",lambda *a,**k:pytest.fail("failed thread spawned child"))
    assert not _off_gui(provider.start)
    assert not _off_gui(provider.snapshot).complete
    assert provider.lifecycle_snapshot()["error"]=="RuntimeError"
    assert not _off_gui(provider.start)
    assert _off_gui(lambda:provider.stop(1))
    assert provider.lifecycle_snapshot()["retired"]


@pytest.mark.skipif(os.name!="nt",reason="Windows suspended creation/job inheritance boundary")
def test_delayed_job_assignment_cannot_execute_redirector_child_before_custody(monkeypatch,tmp_path):
    w=_worker();entered,release=threading.Event(),threading.Event()
    marker=tmp_path/"unadmitted-child.txt"
    provider=_provider("slow-start",marker=marker,startup_timeout=0.2)
    original=w._Job.assign
    def assign(job,pin):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return original(job,pin)
    monkeypatch.setattr(w._Job,"assign",assign)
    output=[];caller=threading.Thread(target=lambda:output.append(provider.start()))
    caller.start()
    try:
        assert entered.wait(3)
        # The newly created wrapper is held before its first instruction. Even
        # after startup timeout, a redirector cannot create an unowned child.
        time.sleep(0.35)
        assert not marker.exists()
        assert not _off_gui(lambda:provider.stop(0.1))
        assert not provider.lifecycle_snapshot()["retired"]
    finally:
        release.set();caller.join(5)
        _retire(provider)
    assert output==[False] and not marker.exists()


@pytest.mark.skipif(os.name!="nt",reason="Windows auxiliary handle custody")
def test_uncertain_auxiliary_close_retires_processes_but_holds_owner_without_retry(monkeypatch):
    import ctypes
    from ctypes import wintypes
    w=_worker();provider=_provider();original=w._resume_owned_primary
    native=ctypes.WinDLL("kernel32",use_last_error=True)
    close=native.CloseHandle;close.argtypes=[wintypes.HANDLE];close.restype=wintypes.BOOL
    calls=[]
    def close_uncertain(handle):
        calls.append(int(handle))
        result=close(handle)
        return False if len(calls)==1 else result
    class Proxy:
        CloseHandle=staticmethod(close_uncertain)
        def __getattr__(self,name):return getattr(native,name)
    monkeypatch.setattr(w,"_resume_owned_primary",lambda pin:original(pin,_api=Proxy()))
    assert not _off_gui(provider.start)
    assert not _off_gui(lambda:provider.stop(3))
    state=provider.lifecycle_snapshot()
    assert state["error"]=="InventoryCustodyCloseError"
    assert state["auxiliary_close_unproven"] is True
    assert not state["ready"] and not state["retired"]
    assert provider._job.handle is None and not provider._thread.is_alive()
    assert state["retirement_proofs"] and all(p["wait_signaled"] and p["handle_closed"]
                                              for p in state["retirement_proofs"])
    count=len(calls)
    assert not _off_gui(lambda:provider.stop(1))
    assert len(calls)==count==2  # Never retry a possibly recycled auxiliary value.
    assert not _off_gui(provider.start)
    assert not _off_gui(provider.snapshot).complete


@pytest.mark.skipif(os.name != "nt", reason="Windows kill-on-parent-close native lifetime")
def test_parent_forced_exit_retires_busy_worker_job_without_pid_kill(tmp_path):
    import subprocess
    w = _worker()
    marker = tmp_path / "parent-exit-collector-entered.txt"
    command = _fixture_command("blocked", marker)
    directory = str(Path(w.__file__).parent)
    supervisor = f'''
import os,sys,json,threading
import angerona.telemetry as package
package.__path__.insert(0,{directory!r})
from angerona.telemetry.process_snapshot_worker import ProcessSnapshotProvider
p=ProcessSnapshotProvider({command!r})
if not p.start():raise SystemExit(3)
print(json.dumps({{'state':p.lifecycle_snapshot(),'members':p._job.members()}}),flush=True)
threading.Thread(target=p.snapshot).start()
if sys.stdin.buffer.read(1)!=b'x':raise SystemExit(4)
os._exit(0)
'''
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(str(p) for p in sys.path if p)
    # The base interpreter avoids introducing an unrelated supervisor redirector.
    # All inventory child redirector/job behavior still uses the real venv exe.
    proc = subprocess.Popen([sys._base_executable,"-c",supervisor], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment,
        creationflags=subprocess.CREATE_NO_WINDOW)
    supervisor_pin = w._Pin(proc.pid, process=proc)
    pins = []
    try:
        response = []
        reader = threading.Thread(target=lambda:response.append(proc.stdout.readline()))
        reader.start();reader.join(10)
        assert not reader.is_alive() and response and response[0]
        metadata = json.loads(response[0])
        assert metadata["state"]["ready"] and len(metadata["members"]) <= 3
        pins = [w._Pin(pid) for pid in metadata["members"]]
        deadline = time.monotonic()+3
        while not marker.exists() and time.monotonic()<deadline:
            time.sleep(0.01)
        assert marker.exists()
        proc.stdin.write(b'x');proc.stdin.flush()
        assert proc.wait(timeout=5) == 0
        # No terminate calls here: kernel closure of the parent's private job
        # must retire the busy collector, redirector and any owned console host.
        assert supervisor_pin.retire(1, terminate=False)
        assert all(pin.retire(3, terminate=False) for pin in pins)
        assert all(pin.proof["wait_signaled"] for pin in pins)
    finally:
        supervisor_pin.retire(3, terminate=True)
        for pin in pins:
            pin.retire(3, terminate=True)
        for stream in (proc.stdin,proc.stdout):
            stream.close()


def test_strict_json_framing_mac_direction_and_byte_caps():
    w = _worker()
    key = b"x"*32
    envelope = w._wrap({"literal":"value"},key,b"request\0")
    stream=io.BytesIO();w._send(stream,envelope);stream.seek(0)
    assert w._verify(w._receive(stream),key,b"request\0") == {"literal":"value"}
    with pytest.raises(w.InventoryWorkerError):w._verify(envelope,key,b"response\0")
    for raw in [b'{"x":1,"x":2}',b'{"x":NaN}']:
        with pytest.raises(RuntimeError):w._receive(io.BytesIO(struct.pack('!I',len(raw))+raw))
    for size in [0,w.MAX_FRAME+1]:
        with pytest.raises(w.InventoryWorkerError):w._receive(io.BytesIO(struct.pack('!I',size)))
    with pytest.raises(w.InventoryWorkerError):w._send(io.BytesIO(),{"x":"x"*100},32)


@pytest.mark.parametrize("field,value", [("complete",1),("enumerated",True),("collected_at",float('nan')),
    ("identity_incomplete",1),("enumerated",-1),("skipped",65_538)])
def test_receipt_schema_refuses_type_and_coverage_contradictions(field,value):
    w=_worker();value_dict=w.encode_snapshot(sensors.ProcessSnapshot((),100.0,True,0,0))
    value_dict[field]=value
    with pytest.raises(w.InventoryWorkerError):w.decode_snapshot(value_dict)
