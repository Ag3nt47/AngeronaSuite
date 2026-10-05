"""Inert reproductions for confirmed group-B module review findings."""
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

from angerona.modules import forensics, frz_heartbeat
from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.modules import intel_sync, mobile_bridge
from angerona.modules import network_monitor
from angerona.telemetry.sensors import ConnectionList, ConnectionSnapshot


@pytest.mark.parametrize("exit_code", [1, -1, None])
def test_failed_socket_collector_never_claims_an_empty_successful_capture(tmp_path, monkeypatch, exit_code):
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "run_hidden", lambda *_a, **_k: SimpleNamespace(
        returncode=exit_code, stdout="", stderr="inert failure",
    ))
    receipt = module._audit_sockets(123, tmp_path)
    assert receipt["complete"] is False
    assert receipt["written_bytes"] == 0
    assert not (tmp_path / "network_sockets.txt").exists()


def test_successful_empty_socket_capture_remains_complete(tmp_path, monkeypatch):
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "run_hidden", lambda *_a, **_k: SimpleNamespace(
        returncode=0, stdout="", stderr="",
    ))
    receipt = module._audit_sockets(123, tmp_path)
    assert receipt["complete"] is True
    assert receipt["rows"] == 0
    assert "No tracked endpoints" in (tmp_path / "network_sockets.txt").read_text()


@pytest.mark.parametrize("recover", [False, True])
def test_live_watchdog_cannot_overwrite_repeated_writer_failure(monkeypatch, recover):
    module = frz_heartbeat.FrzHeartbeatModule()
    monkeypatch.setattr(module, "_open_mmap", lambda: None)
    monkeypatch.setattr(module, "_launch_watchdog", lambda: None)
    monkeypatch.setattr(module, "_watchdog_alive", lambda: True)
    monkeypatch.setattr(module, "_close_mmap", lambda: None)
    monkeypatch.setattr(module, "_release_watchdog_custody", lambda: None)
    monkeypatch.setattr(module, "emit", lambda *_a, **_k: None)
    monkeypatch.setattr(frz_heartbeat, "_mmap_path", lambda: Path("inert.mmap"))
    module._watchdog_custody = SimpleNamespace(
        still_valid=lambda: True, sha256="a" * 64, publisher="inert fixture",
    )
    attempts = []
    health_at_wait = []

    def write_beat():
        attempts.append(1)
        if not recover or len(attempts) <= 5:
            raise OSError("inert writer failure")
        module._beats += 1

    def sleep(_seconds):
        health_at_wait.append(module.health)
        if len(health_at_wait) == 6:
            module._stop.set()

    monkeypatch.setattr(module, "_write_beat", write_beat)
    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert health_at_wait[4] == 40
    assert health_at_wait[5] == (100 if recover else 40)
    assert module._beats == int(recover)


def test_mobile_eco_only_changes_explicit_release_safe_capabilities(monkeypatch):
    class Analytical(BaseModule):
        adaptive_throttle_allowed = True
        adaptive_throttle_max = 2.0

    class Inherited(Analytical):
        pass

    class Response(BaseModule):
        category = "Response"
        adaptive_throttle_allowed = True
        adaptive_throttle_max = 8.0

    analytical = Analytical()
    inherited = Inherited()
    response = Response()
    heartbeat = frz_heartbeat.FrzHeartbeatModule()
    external = Analytical()
    instance_opt_in = BaseModule()
    instance_opt_in.adaptive_throttle_allowed = True
    instance_opt_in.adaptive_throttle_max = 8.0
    targets = {
        "analytical": analytical, "heartbeat": heartbeat,
        "response": response, "inherited": inherited,
        "external": external, "instance": instance_opt_in,
    }
    bridge = mobile_bridge.MobileResponseBridge()
    bridge.bind_manager(SimpleNamespace(
        modules=targets,
        module_trust={"external": {"origin": "extension", "trust": "release"}},
    ))
    receipts = []
    monkeypatch.setattr(bridge, "_send", lambda _message: True)
    monkeypatch.setattr(bridge, "_emit_change_receipt", lambda *a, **k: receipts.append(k) or ("inert", True))

    bridge._eco(True, "a" * 64)
    assert analytical._throttle == 2.0
    assert all(mod._throttle == 1.0 for name, mod in targets.items() if name != "analytical")
    assert receipts[-1]["outcome"] == "applied"
    assert receipts[-1]["details"]["module_count"] == 1
    bridge._eco(False, "b" * 64)
    assert all(mod._throttle == 1.0 for mod in targets.values())


def test_mobile_alert_burst_has_bounded_authority_and_constant_rate_state(monkeypatch):
    bridge = mobile_bridge.MobileResponseBridge()
    sent = []
    probes = []
    monkeypatch.setattr(bridge, "_send", lambda message: sent.append(message) or True)
    monkeypatch.setattr(bridge, "_bind_process_target", lambda *_: probes.append(1) or None)
    monkeypatch.setattr(bridge, "_prepare_rollback_artifact", lambda *_: None)
    monkeypatch.setattr(mobile_bridge.time, "time", lambda: 1000.0)
    event = SimpleNamespace(details={}, module="inert", message="alert", severity=Severity.HIGH)
    bridge._gate_alert(event)
    first_token, first_info = next(iter(bridge.pending_alerts.items()))
    for _ in range(999):
        bridge._gate_alert(event)
    assert len(bridge.pending_alerts) == mobile_bridge._MAX_PENDING_ALERTS
    assert len(probes) == mobile_bridge._MAX_PENDING_ALERTS
    assert len(bridge._alert_times) == mobile_bridge._FLOOD_MAX + 1
    assert len(bridge._digest) == 15
    assert bridge.pending_alerts[first_token] is first_info
    assert bridge._digest_count == 1000 - mobile_bridge._FLOOD_MAX
    bridge._flush_digest()
    assert f"{1000 - mobile_bridge._MAX_PENDING_ALERTS} alert(s) received no new" in sent[-1]


def test_mobile_expiry_burst_keeps_audits_but_batches_phone_notification(monkeypatch):
    bridge = mobile_bridge.MobileResponseBridge()
    bus = EventBus()
    bus.arm(BusAuthority(b"review-expiry-key" * 2))
    bridge.bind(bus)
    sent = []
    monkeypatch.setattr(bridge, "_send", lambda message: sent.append(message) or True)
    # Preserve one live exact-scope authorization, and expire the rest.
    active = {"expires_monotonic": time.monotonic() + 60, "allowed_actions": ("MUTE",)}
    bridge.pending_alerts["active"] = active
    for index in range(255):
        bridge.pending_alerts[str(index)] = {
            "pid": 42, "expires_monotonic": time.monotonic() - 1,
        }
    bridge._sweep_tokens()
    assert bridge.pending_alerts == {"active": active}
    assert len(sent) == 1
    assert "255 alert token(s) expired. No action taken" in sent[0]
    events = bus.recent(300)
    assert len(events) == 255
    assert all(event.details["response_authorized"] is False for event in events)
    assert all(bus.verify(event) for event in events)


def test_intel_selftest_does_not_replace_or_restore_live_snapshot_during_refresh(monkeypatch):
    now = time.time()
    old = intel_sync._IocSnapshot(
        ips=frozenset({"192.0.2.1"}), updated_at=now, expires_at=now + 600, verified=True,
    )
    refreshed = intel_sync._IocSnapshot(
        ips=frozenset({"192.0.2.2"}), updated_at=now, expires_at=now + 600, verified=True,
    )
    monkeypatch.setattr(intel_sync, "_IOC_SNAPSHOT", old)
    original = intel_sync._ioc_matches
    calls = []

    def interleaved_lookup(snapshot, value, **kwargs):
        assert intel_sync._IOC_SNAPSHOT is (refreshed if calls else old)
        calls.append(1)
        with intel_sync._IOC_LOCK:
            intel_sync._IOC_SNAPSHOT = refreshed
        return original(snapshot, value, **kwargs)

    monkeypatch.setattr(intel_sync, "_ioc_matches", interleaved_lookup)
    assert intel_sync.IntelSyncModule().self_test()[0] is True
    assert calls
    assert intel_sync._IOC_SNAPSHOT is refreshed
    assert intel_sync.is_ip_flagged("192.0.2.2") is True
    assert intel_sync.is_ip_flagged("192.0.2.1") is False


def test_network_collection_failure_stays_degraded_until_complete_recovery(monkeypatch):
    module = network_monitor.NetworkMonitorModule()
    snapshots = iter([
        ConnectionList(ConnectionSnapshot((), 1.0, False, 0, 0, "inert failure")),
        ConnectionList(ConnectionSnapshot((), 2.0, False, 0, 0, "still unavailable")),
        ConnectionList(ConnectionSnapshot((), 3.0, True, 0, 0)),
    ])
    monkeypatch.setattr(network_monitor, "list_connections", lambda **_: next(snapshots))
    health = []

    def sleep(_seconds):
        health.append(module.health)
        if len(health) == 3:
            module._stop.set()

    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert health == [55, 55, 100]


def test_network_untyped_empty_collection_does_not_claim_complete_coverage():
    module = network_monitor.NetworkMonitorModule()
    module._set_connection_health([])
    assert module.health < 100


class _NativeCall:
    """Assignable ctypes signatures around a strictly inert Python callback."""
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


@pytest.mark.parametrize("read_mode,region_size,expected_calls,complete", [
    ("fail", 256, 2, False),
    ("fail", 128, 2, False),
    ("partial", 128, 2, False),
    ("success", 128, 2, True),
    ("stop", 256, 1, False),
])
def test_forensics_read_failures_consume_work_and_never_claim_completeness(
    tmp_path, monkeypatch, read_mode, region_size, expected_calls, complete,
):
    module = forensics.ForensicsModule()
    calls = {"query": 0, "read": 0, "close": 0}

    def query(_handle, _address, pointer, size):
        calls["query"] += 1
        if calls["query"] > 1:
            return 0
        mbi = pointer._obj
        mbi.BaseAddress, mbi.RegionSize, mbi.State = 4096, region_size, forensics.MEM_COMMIT
        return size

    def read(_handle, _address, buffer, size, returned):
        calls["read"] += 1
        if read_mode == "stop":
            module._stop.set()
        if read_mode in {"fail", "stop"}:
            return 0
        returned._obj.value = size // 2 if read_mode == "partial" else size
        buffer.raw = b"x" * size
        return 1

    def close(_handle):
        calls["close"] += 1

    kernel = SimpleNamespace(
        OpenProcess=_NativeCall(lambda *_: 1), VirtualQueryEx=_NativeCall(query),
        ReadProcessMemory=_NativeCall(read), CloseHandle=_NativeCall(close),
    )
    monkeypatch.setattr(forensics.ctypes, "windll", SimpleNamespace(kernel32=kernel), raising=False)
    monkeypatch.setattr(forensics, "_MEMORY_CHUNK_BYTES", 64)
    monkeypatch.setattr(forensics, "_MEMORY_READ_BUDGET", 128)
    receipt = module._dump_memory_strings(42, tmp_path)
    assert calls["read"] == expected_calls
    assert calls["close"] == 1
    assert receipt["attempted_bytes"] == expected_calls * 64
    assert receipt["complete"] is complete
    if read_mode != "success":
        assert receipt["failed_reads"] == expected_calls
