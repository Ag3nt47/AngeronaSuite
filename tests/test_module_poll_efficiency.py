"""Inert poll fixtures: preserve detections and avoid redundant metadata work."""
from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus, Severity
from angerona.modules import process_monitor, purple_guard
from angerona.telemetry import sensors


def _process(pid=7, *, birth=10.0, command=None, name="fixture.exe", parent=1):
    return {
        "pid": pid, "ppid": parent, "name": name,
        "exe": rf"C:\Windows\{name}", "cmdline": command or [name],
        "create_time": birth,
    }


def _poll(monkeypatch, snapshots, *, initial=(), capability=None):
    module = process_monitor.ProcessMonitorModule()
    bus = EventBus()
    module.bind(bus)
    module.bind_redteam_receipt_capability(capability)
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(pids=lambda: initial))
    pending = iter(snapshots)
    calls = 0

    def processes(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return next(pending)

    def sleep(_seconds, **_kwargs):
        if calls == len(snapshots):
            module.stop()

    monkeypatch.setattr(process_monitor, "list_processes", processes)
    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    return module, list(reversed(bus.recent(100)))


def test_unchanged_commands_are_only_formatted_when_published(monkeypatch):
    class CountedText:
        calls = 0

        def __str__(self):
            self.calls += 1
            return "--fixture"

    argument = CountedText()
    process = _process(command=["fixture.exe", argument])
    module, events = _poll(monkeypatch, [[process]] * 20)
    creations = [e for e in events if e.details.get("event_type") == "process_creation"]
    assert len(creations) == 1
    assert creations[0].details["cmdline"] == "fixture.exe --fixture"
    assert argument.calls == 1
    assert module.health == 100


def test_parent_lineage_and_pid_reuse_events_remain_complete(monkeypatch):
    parent = _process(10, name="winword.exe")
    child = _process(11, parent=10, name="powershell.exe", command=["powershell", "-NoLogo"])
    replacement = _process(11, birth=20.0, name="replacement.exe")
    module, events = _poll(monkeypatch, [[child, parent], [parent, replacement]], initial=(10,))
    creations = [e for e in events if e.details.get("event_type") == "process_creation"]
    assert [(e.details["pid"], e.details["process_create_time"]) for e in creations] == [
        (11, 10.0), (11, 20.0),
    ]
    detections = [e for e in events if e.severity == Severity.CRITICAL]
    assert len(detections) == 1
    assert detections[0].details["process_create_time"] == 10.0
    assert module._names == {10: "winword.exe", 11: "replacement.exe"}


def test_validation_receipt_still_observes_unchanged_raw_process(monkeypatch):
    calls = []
    process = _process(command=["fixture.exe", "--receipt"])

    def issue(_module, *, process):
        calls.append(process)
        return {"fixture_receipt": True} if len(calls) == 2 else {}

    _module, events = _poll(
        monkeypatch, [[process]] * 3, initial=(7,),
        capability=SimpleNamespace(issue_process_observation=issue),
    )
    creations = [e for e in events if e.details.get("event_type") == "process_creation"]
    assert len(calls) == 2
    assert all(row == process and row is not process for row in calls)
    assert len(creations) == 1
    assert creations[0].details["fixture_receipt"] is True
    assert creations[0].details["cmdline"] == "fixture.exe --receipt"


def test_process_receipt_skips_full_lease_for_unenrolled_processes(monkeypatch):
    """Routine/forged host rows cannot grant credit or force marker rescans."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    producer = SimpleNamespace(
        name="Process Monitor", lifecycle_generation=1,
        _angerona_contract=SimpleNamespace(
            capability_id="angerona.builtin.process_monitor"
        ),
    )
    capability = object.__new__(purple_guard._ProducerReceiptCapability)
    signer = Ed25519PrivateKey.generate()
    capability._ProducerReceiptCapability__kind = "process"
    capability._ProducerReceiptCapability__serial = 0
    capability._ProducerReceiptCapability__site_sha256 = "a" * 64
    capability._ProducerReceiptCapability__private_signer = signer
    identity = {}
    capability._ProducerReceiptCapability__process_validator = (
        lambda *_args, **_kwargs: identity
    )
    state = SimpleNamespace(
        lock=threading.RLock(), consumed=True, released=False,
        run_deadline_monotonic=time.monotonic() + 60,
        _native_generation=lambda _name: 1,
        _native_module=lambda _name: producer,
        _native_capability_is=lambda _name, candidate: candidate is capability,
        lease_id="lease", receipt_id="receipt", bound_run_id="run",
        target=Path("inert-target"),
    )
    lease = object()
    checks = []
    monkeypatch.setattr(
        purple_guard._ProducerReceiptCapability, "_authority",
        lambda _self, _producer: (lease, state),
    )
    monkeypatch.setattr(
        purple_guard._ProducerReceiptCapability, "_canonical_caller",
        lambda _self, _producer: True,
    )
    monkeypatch.setattr(
        purple_guard.BaseModule, "operational_snapshot",
        lambda _self: {"status": "running", "thread_alive": True,
                       "event_overflow_count": 0},
    )
    monkeypatch.setattr(
        purple_guard.RedTeamValidationLease, "_state_matches",
        lambda _lease: checks.append(True) or True,
    )
    process = {"pid": 700, "create_time": 10.0, "cmdline": ["ordinary.exe"]}
    assert capability.issue_process_observation(producer, process=process) == {}
    assert checks == []

    process["cmdline"] = ["ordinary.exe", "ANGERONA_REDTEAM_deadbeef"]
    assert capability.issue_process_observation(producer, process=process) == {}
    assert checks == []

    identity = {"pid": 700, "process_create_time": 10.0,
                "identity_sha256": "b" * 64}
    receipt = capability.issue_process_observation(producer, process=process)
    assert len(checks) == 1
    assert receipt["receipt_type"] == "native_process_observation"
    assert receipt["producer_observation_serial"] == 1
    signature = bytes.fromhex(receipt.pop("detector_receipt_mac"))
    signer.public_key().verify(signature, purple_guard._canonical_json(receipt))


@pytest.fixture
def sensor_clock(monkeypatch):
    clock = [100.0, 1_700_000_000.0]
    calls = {"process": 0, "connection": 0}

    def processes(_attributes):
        calls["process"] += 1
        return [SimpleNamespace(info=_process(birth=float(calls["process"])))]

    def connections(**_kwargs):
        calls["connection"] += 1
        return []

    monkeypatch.setattr(sensors, "_proc_cache", (0.0, []))
    monkeypatch.setattr(sensors, "_conn_cache", (0.0, None))
    monkeypatch.setattr(sensors, "time", SimpleNamespace(
        monotonic=lambda: clock[0], time=lambda: clock[1],
    ))
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        process_iter=processes, net_connections=connections,
    ))
    return clock, calls


@pytest.mark.parametrize("wall_delta", [-86_400.0, 86_400.0])
@pytest.mark.parametrize("kind", ["process", "connection"])
def test_wall_clock_corrections_preserve_sensor_freshness(sensor_clock, kind, wall_delta):
    clock, calls = sensor_clock
    read = sensors.process_snapshot if kind == "process" else sensors.connection_snapshot
    first = read(max_age=1.5)
    clock[0] += 0.5
    clock[1] += wall_delta
    assert read(max_age=1.5) is first
    assert calls[kind] == 1
    clock[0] += 1.0
    second = read(max_age=1.5)
    assert second is not first
    assert calls[kind] == 2
    if kind == "connection":
        assert second.collected_at == clock[1]
        assert second.complete is True
    read(max_age=0)
    assert calls[kind] == 3


@pytest.mark.parametrize("kind", ["process", "connection"])
def test_concurrent_sensor_consumers_share_single_enumeration(sensor_clock, kind):
    _clock, calls = sensor_clock
    read = sensors.process_snapshot if kind == "process" else sensors.connection_snapshot
    with ThreadPoolExecutor(max_workers=8) as workers:
        snapshots = list(workers.map(lambda _index: read(max_age=1.5), range(32)))
    assert calls[kind] == 1
    assert all(item is snapshots[0] for item in snapshots)


def test_failed_connection_receipt_preserves_epoch_and_retries_after_ttl(
    monkeypatch, sensor_clock,
):
    clock, _calls = sensor_clock

    def denied(**_kwargs):
        raise PermissionError("fixture denied")

    monkeypatch.setattr(sys.modules["psutil"], "net_connections", denied)
    first = sensors.connection_snapshot(max_age=1.5)
    assert first.complete is False
    assert first.collected_at == clock[1]
    clock[1] -= 86_400
    clock[0] += 2
    assert sensors.connection_snapshot(max_age=1.5) is not first


def test_process_monitor_offline_self_test():
    ok, note = process_monitor.ProcessMonitorModule().self_test()
    assert ok, note


@pytest.mark.parametrize("fail", [False, True])
def test_repeated_entropy_self_tests_release_files_even_on_failure(monkeypatch, tmp_path, fail):
    import tempfile

    from angerona.core import entropy_pool

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    if fail:
        def failed_compute(*_args, **_kwargs):
            raise OSError("fixture failure after files created")

        monkeypatch.setattr(entropy_pool, "compute_entropies", failed_compute)
    for _repeat in range(3):
        ok, note = entropy_pool.self_test()
        assert ok is not fail, note
        assert list(tmp_path.iterdir()) == []
