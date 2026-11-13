from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace

import pytest

from angerona.core.module_base import Severity
from angerona.modules import forensics


PID = 4242
TICKS = forensics._EPOCH + 100 * 10_000_000
IDENTITY = (PID, 100.0, TICKS)


def recorded_module(monkeypatch):
    module = forensics.ForensicsModule()
    events = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: events.append((message, severity, details)))
    monkeypatch.setattr(module, "set_health", lambda *_args: None)
    monkeypatch.setattr(forensics, "retirement_snapshot", lambda: {"capture_held": False})
    monkeypatch.setattr(forensics.time, "monotonic", lambda: 100.0)
    return module, events


def held_events(events):
    return [details for message, _severity, details in events if message.startswith("Forensic capture held:")]


def mocked_capture(monkeypatch, tmp_path, module, *, complete=True, late_failure=False):
    # No process, crypto provider, vault file, memory or socket collector is used.
    event = SimpleNamespace(module="Fixture Detection", ts=200.0, hmac_sig="fixture-hmac",
                            mesh_sig=None, mesh_peer=None, details={"pid": PID, "process_birth_ticks": str(TICKS)})
    monkeypatch.setattr(module, "_admit", lambda _event: IDENTITY)
    monkeypatch.setattr(module, "_root_capacity", lambda _root: (True, 0, 0, "available"))
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    monkeypatch.setattr(forensics, "verify_key_wrapping", lambda: None)
    if late_failure:
        class Pins:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                raise OSError("temporary hold")
        monkeypatch.setattr(forensics, "DirectoryPins", lambda _root: Pins())
    else:
        monkeypatch.setattr(forensics, "DirectoryPins", lambda _root: nullcontext())
    writer = SimpleNamespace(finish=lambda _receipt: None)
    monkeypatch.setattr(forensics, "ForensicVaultWriter", lambda *_args, **_kwargs: nullcontext(writer))
    retained = SimpleNamespace(identity=SimpleNamespace(image="fixture.exe"), check=lambda: None)
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda *_args: nullcontext(retained))
    monkeypatch.setattr(module, "_dump_memory_strings", lambda *_args, **_kwargs: {"complete": complete})
    monkeypatch.setattr(module, "_audit_sockets", lambda *_args, **_kwargs: {"complete": True})
    module._bus = SimpleNamespace(mesh_required=False)
    return event


def test_hold_separates_admitted_native_generations_and_stays_bounded(monkeypatch):
    module, events = recorded_module(monkeypatch)
    module._held("temporary hold", PID, identity=IDENTITY)
    module._held("temporary hold", PID, identity=IDENTITY)
    module._held("temporary hold", PID, identity=(PID, 100.0000001, TICKS + 1))
    reports = held_events(events)
    assert len(reports) == 2
    assert reports[0]["process_birth_ticks"] == str(TICKS)
    assert reports[1]["process_birth_ticks"] == str(TICKS + 1)
    assert all(report["hold_identity_source"] == "authenticated-original-event" for report in reports)
    assert all(report["response_authorized"] is False for report in reports)
    for index in range(forensics._HELD_KEYS_MAX * 3):
        module._held("temporary hold", PID, identity=(PID, 100.0 + index, TICKS + index + 2))
    assert len(module._held_recent) <= forensics._HELD_KEYS_MAX


def test_successful_capture_resets_only_its_hold_episode_and_preserves_original(monkeypatch, tmp_path):
    module, events = recorded_module(monkeypatch)
    event = mocked_capture(monkeypatch, tmp_path, module)
    original = deepcopy(vars(event))
    module._held("temporary hold", PID, identity=IDENTITY)
    module._held("temporary hold", PID, identity=IDENTITY)
    module._held("unknown birth", PID)
    module._held("other generation", PID, identity=(PID, 101.0, TICKS + 10_000_000))
    module._held("delivery gap")
    result = module._capture(PID, expected_create_time=100.0, event=event)
    assert result["complete"] and result["encrypted"]
    assert vars(event) == original
    assert ("temporary hold", PID, TICKS) not in module._held_recent
    assert ("unknown birth", PID, None) in module._held_recent
    assert ("other generation", PID, TICKS + 10_000_000) in module._held_recent
    assert ("delivery gap", None, None) in module._held_recent
    # A rejected/unverified event remains unresolved after another known
    # generation captures successfully; retain its original suppression count.
    unknown_before = module._held_recent[("unknown birth", PID, None)]
    module._held("unknown birth", PID)
    assert module._held_recent[("unknown birth", PID, None)] == (unknown_before[0], unknown_before[1] + 1)
    before = len(held_events(events))
    module._held("temporary hold", PID, identity=IDENTITY)
    assert len(held_events(events)) == before + 1
    assert held_events(events)[-1]["repeats_since_last_report"] == 0


@pytest.mark.parametrize("outcome", ["partial", "unavailable", "late-retirement-failure"])
def test_incomplete_capture_does_not_reset_hold_episode(monkeypatch, tmp_path, outcome):
    module, events = recorded_module(monkeypatch)
    event = mocked_capture(monkeypatch, tmp_path, module, complete=outcome != "partial",
                           late_failure=outcome == "late-retirement-failure")
    module._held("temporary hold", PID, identity=IDENTITY)
    module._held("temporary hold", PID, identity=IDENTITY)
    if outcome == "unavailable":
        def unavailable():
            raise OSError("temporary hold")
        monkeypatch.setattr(forensics, "_evidence_root", unavailable)
    result = module._capture(PID, expected_create_time=100.0, event=event)
    assert result["complete"] is False
    assert len(held_events(events)) == 1
    assert ("temporary hold", PID, TICKS) in module._held_recent
    before = module._held_recent[("temporary hold", PID, TICKS)][1]
    module._held("temporary hold", PID, identity=IDENTITY)
    assert module._held_recent[("temporary hold", PID, TICKS)][1] == before + 1
    assert len(held_events(events)) == 1


def test_run_outer_failure_keeps_admitted_generation_and_every_capture_attempt(monkeypatch):
    module, events = recorded_module(monkeypatch)
    source = [SimpleNamespace(module="Fixture Detection", severity=Severity.HIGH,
                              details={"pid": PID, "birth": birth}) for birth in (TICKS, TICKS, TICKS + 1)]
    attempts = []
    monkeypatch.setattr(module, "_admit", lambda event: (PID, 100.0, event.details["birth"]))
    monkeypatch.setattr(module, "_capture_needed", lambda *_args: True)
    def failure(pid, **_kwargs):
        attempts.append(pid)
        raise OSError("temporary hold")
    monkeypatch.setattr(module, "_capture", failure)
    monkeypatch.setattr(module, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "poll_bus_events", lambda **_kwargs: (source, False))
    monkeypatch.setattr(module, "mark_cycle_complete", lambda: module.generation_stop_event().set())
    module._bus = object()
    module.run()
    assert attempts == [PID, PID, PID]
    assert [row["process_birth_ticks"] for row in held_events(events)] == [str(TICKS), str(TICKS + 1)]
    assert all(event.details["pid"] == PID for event in source)


def test_run_rejected_identity_reports_pid_without_claiming_a_birth(monkeypatch):
    module, events = recorded_module(monkeypatch)
    source = [SimpleNamespace(module="Fixture Detection", severity=Severity.HIGH,
                              details={"pid": PID})]
    def reject(_event):
        raise ValueError("exact birth missing")
    monkeypatch.setattr(module, "_admit", reject)
    monkeypatch.setattr(module, "_capture", lambda *_args, **_kwargs: pytest.fail("unadmitted capture"))
    monkeypatch.setattr(module, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "poll_bus_events", lambda **_kwargs: (source, False))
    monkeypatch.setattr(module, "mark_cycle_complete", lambda: module.generation_stop_event().set())
    module._bus = object()
    module.run()
    report = held_events(events)[0]
    assert report["pid"] == PID
    assert report["process_birth_ticks"] is None
    assert report["hold_identity_source"] == "unavailable"
