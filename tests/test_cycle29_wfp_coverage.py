from __future__ import annotations

from angerona.core.eventbus import EventBus
from angerona.modules import wfp_controller
from angerona.modules.wfp_controller import (
    ConnectionCoverage,
    ConnectionOwnership,
    WFPController,
    WFPControllerModule,
)


def _record(
    *,
    pid: int = 10,
    local_port: int = 50000,
    remote_address: str = "203.0.113.10",
    remote_port: int = 443,
    image: str = r"C:\Windows\System32\lsass.exe",
) -> ConnectionOwnership:
    return ConnectionOwnership(
        protocol="tcp",
        family="ipv4",
        local_address="192.0.2.10",
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        state="ESTABLISHED",
        pid=pid,
        process_birth=1000.0 + pid,
        process_image=image,
    )


def _coverage(**updates) -> ConnectionCoverage:
    values = {
        "source": "ip-helper-snapshot",
        "collection_ok": True,
        "rows": 1,
        "ipv4_rows": 1,
        "ipv6_rows": 0,
        "tcp_rows": 1,
        "udp_rows": 0,
        "unresolved_process_rows": 0,
        "ambiguous_port_keys": 0,
        "row_errors": 0,
        "error": "",
    }
    values.update(updates)
    return ConnectionCoverage(**values)


def test_legacy_port_lookup_withholds_collisions_but_full_tuples_survive(
    monkeypatch,
) -> None:
    records = (_record(pid=10), _record(pid=20, remote_address="198.51.100.8"))
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: True)
    monkeypatch.setattr(
        wfp_controller,
        "_collect_connection_ownership",
        lambda: (records, _coverage(rows=2, ambiguous_port_keys=1)),
    )
    controller = WFPController()
    controller._refresh()

    assert controller.pid_for_port(50000, "tcp") is None
    assert controller.connection_records() == records
    assert controller.coverage().ambiguous_port_keys == 1
    assert controller._wfp_library_available is True
    assert controller._wfp_telemetry_available is False


class _Controller:
    def __init__(self, records, coverage) -> None:
        self.records = records
        self.current_coverage = coverage

    def connection_records(self):
        return self.records

    def coverage(self):
        return self.current_coverage


def test_sensitive_remote_flow_emits_exact_full_tuple_and_never_claims_wfp() -> None:
    bus = EventBus()
    module = WFPControllerModule()
    module.bind(bus)
    module._ctrl = _Controller((_record(),), _coverage())

    module._scan_suspicious()

    assert module.health == 70
    assert "native WFP" in module.health_note
    event = next(event for event in bus.recent(20) if event.details.get("remote_port") == 443)
    assert event.details["local_address"] == "192.0.2.10"
    assert event.details["remote_address"] == "203.0.113.10"
    assert event.details["process_birth"] == 1010.0
    assert event.details["telemetry_source"] == "ip-helper-snapshot"
    assert event.details["response_authorized"] is False


def test_listener_without_remote_endpoint_is_not_described_as_outbound() -> None:
    bus = EventBus()
    module = WFPControllerModule()
    module.bind(bus)
    module._ctrl = _Controller(
        (_record(remote_address="", remote_port=0),),
        _coverage(),
    )

    module._scan_suspicious()

    assert not any("remote" in event.message.lower() for event in bus.recent(20))
    assert module.health == 70


def test_empty_or_failed_collection_can_never_be_health_100() -> None:
    module = WFPControllerModule()
    module._ctrl = _Controller((), _coverage(rows=0, ipv4_rows=0, tcp_rows=0))
    module._scan_suspicious()
    assert module.health == 45
    assert "unproven" in module.health_note

    module._ctrl = _Controller(
        (),
        _coverage(
            collection_ok=False,
            rows=0,
            ipv4_rows=0,
            tcp_rows=0,
            error="access denied",
        ),
    )
    module._scan_suspicious()
    assert module.health == 20
    assert "access denied" in module.health_note


def test_unresolved_process_identity_caps_health() -> None:
    module = WFPControllerModule()
    module._ctrl = _Controller((_record(image=""),), _coverage(unresolved_process_rows=1))

    module._scan_suspicious()

    assert module.health == 60
    assert "PID birth/image" in module.health_note
