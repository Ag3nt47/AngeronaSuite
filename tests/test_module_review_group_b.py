"""Inert reproductions for confirmed group-B module review findings."""
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

from angerona.modules import forensics, frz_heartbeat
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.core.module_base import BaseModule
from angerona.modules import intel_sync, mobile_bridge
from angerona.modules import network_monitor
from angerona.telemetry.sensors import ConnectionList, ConnectionSnapshot


class _InertForensicNative:
    """Retained-handle fixture; no host process, memory or socket table access."""
    ticks = forensics._EPOCH + 100 * 10_000_000

    def __init__(self):
        self.closed = []

    def open(self, pid, rights, inherit):
        assert pid == 4242 and inherit is False
        assert rights & 0x0010 and not rights & 0x0001
        return 901

    def identity(self, handle):
        assert handle == 901
        return ProcessObjectIdentity(4242, self.ticks, r"D:\fixtures\sample.exe")

    def wait(self, handle, milliseconds):
        assert handle == 901 and milliseconds == 0
        return False

    def is_system(self, handle):
        assert handle == 901
        return False

    def close(self, handle):
        self.closed.append(handle)

    socket_rows = forensics._NativeCapture.socket_rows


def _forensic_event(module):
    bus = EventBus()
    bus.arm(BusAuthority(b"group-b-inert-forensic-key-32!!!!"))
    module.bind(bus)
    bus.publish(Event("Native Detection", "Inert authenticated active evidence", Severity.HIGH,
        details={"pid": 4242, "process_birth_ticks": str(_InertForensicNative.ticks),
                 "process_create_time": 100.0, "active_attack": True}))
    return bus.recent(1)[0]


@pytest.mark.parametrize("native_error", [1, -1, None])
def test_failed_socket_collector_never_claims_an_empty_successful_capture(tmp_path, native_error):
    module, native, output = forensics.ForensicsModule(), _InertForensicNative(), []
    event = _forensic_event(module)

    def failed_table(_buffer, size, *_args):
        size._obj.value = 4
        return native_error

    native._iphlp = SimpleNamespace(GetExtendedTcpTable=failed_table, GetExtendedUdpTable=failed_table)
    writer = SimpleNamespace(append=lambda *args: output.append(args))
    with forensics._CaptureHandle(4242, native.ticks, 100, _native=native, _clock=lambda: 1) as retained:
        with pytest.raises(ValueError, match="native socket table unavailable"):
            module._audit_sockets(retained, writer, event=event)
    assert output == []  # Failure cannot append even an empty successful record.
    assert sum(len(data) for _kind, data in output) == 0
    assert native.closed == [901]
    assert not (tmp_path / "network_sockets.txt").exists()


def test_successful_empty_socket_capture_remains_complete(tmp_path):
    module, native, output = forensics.ForensicsModule(), _InertForensicNative(), []
    event = _forensic_event(module)
    table_calls = []

    def empty_table(buffer, size, *_args):
        size._obj.value = 4
        table_calls.append(buffer is None)
        if buffer is None:
            return 122
        forensics.ctypes.memmove(buffer, b"\0" * 4, 4)
        return 0

    native._iphlp = SimpleNamespace(GetExtendedTcpTable=empty_table, GetExtendedUdpTable=empty_table)
    writer = SimpleNamespace(append=lambda *args: output.append(args))
    with forensics._CaptureHandle(4242, native.ticks, 100, _native=native, _clock=lambda: 1) as retained:
        receipt = module._audit_sockets(retained, writer, event=event)
    assert receipt["complete"] is True
    assert receipt["rows"] == 0 and receipt["written_bytes"] == 0
    assert table_calls == [True, False] * 4  # TCP/UDP, IPv4/IPv6 were queried.
    assert output == [("sockets", b"")]
    assert native.closed == [901]
    assert not (tmp_path / "network_sockets.txt").exists()  # No plaintext fallback.


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
    module, native = forensics.ForensicsModule(), _InertForensicNative()
    event = _forensic_event(module)
    calls = {"query": 0, "read": 0}
    output = []

    def region(handle, _address):
        assert handle == 901
        calls["query"] += 1
        return (4096, region_size, 0x1000, 4) if calls["query"] == 1 else None

    def memory(handle, _address, amount):
        assert handle == 901
        calls["read"] += 1
        if read_mode == "stop":
            module._stop.set()
        if read_mode in {"fail", "stop"}:
            return b"", False
        returned = amount // 2 if read_mode == "partial" else amount
        return b"x" * returned, returned == amount

    native.region, native.memory = region, memory
    monkeypatch.setattr(forensics, "_MEMORY_CHUNK_BYTES", 64)
    monkeypatch.setattr(forensics, "_MEMORY_READ_BUDGET", 128)
    writer = SimpleNamespace(append=lambda *args: output.append(args))
    with forensics._CaptureHandle(4242, native.ticks, 100, _native=native, _clock=lambda: 1) as retained:
        receipt = module._dump_memory_strings(retained, writer, event=event)
    assert calls["read"] == expected_calls
    assert native.closed == [901]
    assert receipt["attempted_bytes"] == expected_calls * 64
    assert receipt["complete"] is complete
    assert receipt["read_bytes"] == (expected_calls * (32 if read_mode == "partial" else 64)
                                      if read_mode in {"partial", "success"} else 0)
    if read_mode != "success":
        assert receipt["failed_reads"] == expected_calls
    assert all(kind == "memory" for kind, _data in output)
    assert not list(tmp_path.iterdir())  # Only the bounded encrypted-writer interface is used.
