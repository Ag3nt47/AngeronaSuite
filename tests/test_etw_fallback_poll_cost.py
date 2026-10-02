"""Native process births retain metadata without re-querying baseline parents."""
import os
import subprocess
import sys
from functools import wraps
from types import SimpleNamespace

import psutil

from angerona.core.privilege import sanitized_child_environment
from angerona.modules.etw_listener import EtwListenerModule
from angerona.modules import etw_listener


def test_native_baseline_skips_parent_queries_and_enriches_owned_birth(monkeypatch):
    calls = []
    original = psutil.Process.ppid

    @wraps(original)
    def observed_parent(process):
        calls.append(process.pid)
        return original(process)

    monkeypatch.setattr(psutil.Process, "ppid", observed_parent)
    module = EtwListenerModule()
    assert module._poll_psutil() == []
    assert module._known_pids and calls == []
    baseline = set(module._known_pids)
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        env=sanitized_child_environment(source={}),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        events = module._poll_psutil()
        births = [event for event in events if event["psutil"]["pid"] == child.pid]
        assert len(births) == 1
        event = births[0]
        assert event["eid"] == 4688 and event["kind"] == "process_created"
        assert event["psutil"]["ppid"] == os.getpid()
        assert event["psutil"]["name"]
        assert calls.count(child.pid) == 1
        assert not baseline.intersection(calls)
        calls.clear()
        events = module._poll_psutil()
        assert not any(event["psutil"]["pid"] == child.pid for event in events)
        assert child.pid not in calls
    finally:
        child.terminate()
        child.wait(timeout=10)


def test_birth_exiting_during_enrichment_does_not_become_a_baseline_pid(monkeypatch):
    def vanished(*, attrs):
        raise psutil.NoSuchProcess(99)

    process = SimpleNamespace(info={"pid": 99}, as_dict=vanished)
    monkeypatch.setattr(etw_listener, "psutil", SimpleNamespace(
        process_iter=lambda _attrs: iter([process]), NoSuchProcess=psutil.NoSuchProcess,
    ))
    module = EtwListenerModule()
    module._known_pids = {1}
    assert module._poll_psutil() == []
    assert 99 not in module._known_pids
