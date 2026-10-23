"""Inert semantic boundaries and separate response-authority controls."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from angerona.core.chill_mode import ChillPolicy
from angerona.core.eventbus import EventBus, Severity
from angerona.core.threat import active_threat_events, event_disposition
from angerona.modules import lsass_guard
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.telemetry.sensors import ProcessSnapshot


@pytest.mark.parametrize("command", [
    "python.exe tools/observe_module_matrix.py --max-cases 8 --case pair-lsass-credential-access-guard--process-monitor",
    'python.exe "tools/observe_module_matrix.py" "--max-cases" 8 "pair-lsass-credential-access-guard--process-monitor"',
    "helper.exe --maximum 8 --label lsass",
    r'helper.exe "C:\lab\-ma\lsass\report.txt"',
    r'helper.exe C:\lab\-ma\lsass\report.txt',
    'helper.exe --label "-ma lsass is a reference"',
])
def test_benign_long_option_or_path_fragment_is_not_a_dump_flag(command):
    assert lsass_guard._looks_like_lsass_dump(command) is None


@pytest.mark.parametrize("command", [
    "procdump.exe -ma lsass.exe",
    "PROCDUMP64.EXE -MA LSASS.EXE",
    r'"C:\Program Files\Tools\procdump64.exe" -ma lsass.exe',
    "helper.exe -ma lsass",
    'helper.exe "-ma" "lsass.exe"',
    "helper.exe '-MA' 'LSASS'",
    'powershell.exe -Command "& $tool -ma lsass.exe"',
    'powershell.exe -Command "& $tool \'-ma\' lsass.exe"',
    "helper.exe\t-ma\tlsass.exe",
])
def test_real_or_embedded_complete_dump_flag_stays_visible(command):
    assert lsass_guard._looks_like_lsass_dump(command) is not None


def test_other_signatures_are_preserved_and_narrative_ambiguity_is_explicit():
    assert lsass_guard._looks_like_lsass_dump("rundll32.exe comsvcs.dll,MiniDump 99 lsass.dmp full")
    assert lsass_guard._looks_like_lsass_dump("helper.exe --description mimikatz")
    # A boundary is not an execution parser. This remains visible, with no
    # response authority as separately established by the inert controls below.
    assert lsass_guard._looks_like_lsass_dump('helper.exe --description "example uses -ma lsass as text"')


def detector_events(monkeypatch, tmp_path, name, argv):
    row = dict(pid=54321, name=name, exe=str(tmp_path / name), cmdline=argv, create_time=1234.5)
    monkeypatch.setattr(lsass_guard, "psutil", SimpleNamespace(
        Process=lambda _pid: SimpleNamespace(ppid=lambda: 43210)))
    monkeypatch.setattr(lsass_guard, "process_snapshot", lambda **_kwargs: ProcessSnapshot(
        (row,), time.time(), True, 1, 0))
    module = lsass_guard.LsassGuardModule()
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())
    module.run()  # One supplied snapshot, no live process/thread or OS mutator.
    return module, [event for event in bus.recent(10) if event.severity == Severity.CRITICAL]


def test_benign_harness_args_emit_no_dump_detection_or_response(monkeypatch, tmp_path):
    argv = ["python.exe", "tools/observe_module_matrix.py", "--max-cases", "8", "--case",
            "pair-lsass-credential-access-guard--process-monitor"]
    module, events = detector_events(monkeypatch, tmp_path, "python.exe", argv)
    assert events == [] and module._detections == 0
    assert lsass_guard._lsass_response_scope("python.exe", str(tmp_path / "python.exe"), argv) is None


@pytest.mark.parametrize("name,argv", [
    ("python.exe", ["python.exe", "-c", "print('mimikatz lsass.dmp')"]),
    ("helper.exe", ["helper.exe", "-ma", "lsass.exe"]),
    ("powershell.exe", ["powershell.exe", "-Command", "& $tool -ma lsass.exe"]),
    ("helper.exe", ["helper.exe", "--description", "example uses -ma lsass as text"]),
    ("procdump64.exe", ["procdump64.exe", "-ma", "notepad.exe", r"C:\reports\lsass.exe"]),
])
def test_weak_semantics_never_gain_process_or_host_response_authority(monkeypatch, tmp_path, name, argv):
    _module, events = detector_events(monkeypatch, tmp_path, name, argv)
    assert len(events) == 1
    event = events[0]
    assert event.details["detector_policy"] == "semantic-indicator-alert-only"
    assert event.details["active_attack"] is False
    assert event.details["response_authorized"] is False
    assert "response_contract" not in event.details
    assert event_disposition(event) == "observation"
    assert AdversaryCombat._response_actions(event) is None
    assert lsass_guard._lsass_response_scope(name, str(tmp_path / name), argv) is None
    chill = ChillPolicy()
    chill.enable()
    assert chill.observe_active(active_threat_events(events)) is None
    assert not chill.escalated


def test_exact_tool_role_keeps_typed_process_response_without_host_scope(monkeypatch, tmp_path):
    argv = ["procdump64.exe", "-ma", "lsass.exe", "out.dmp"]
    _module, events = detector_events(monkeypatch, tmp_path, "procdump64.exe", argv)
    assert len(events) == 1
    event = events[0]
    assert event.details["response_authorized"] is True and event.details["active_attack"] is True
    assert event.details["response_contract"]["targets"]["pid"] == 54321
    assert event.details["response_contract"]["targets"]["process_create_time"] == 1234.5
    actions = AdversaryCombat._response_actions(event)
    assert "terminate_process" in actions and "isolate_host" not in actions
