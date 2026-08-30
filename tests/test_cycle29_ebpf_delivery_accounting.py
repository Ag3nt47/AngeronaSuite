from __future__ import annotations

import socket
from types import SimpleNamespace

from angerona.modules import ebpf_sensor


class _Map:
    def __init__(self, event) -> None:
        self._event = event

    def event(self, _data):
        return self._event


def test_ebpf_program_has_no_attacker_controlled_sys_name_drop() -> None:
    source = ebpf_sensor._BPF_C
    assert "e.comm[0] == 's'" not in source
    assert "exec_sequence" in source
    assert "net_sequence" in source
    assert "daddr6[16]" in source
    assert "skc_v6_daddr" in source


def test_exec_sequence_gap_is_latched_into_degraded_health() -> None:
    module = ebpf_sensor.EbpfSensorNode()
    events: list[tuple[tuple, dict]] = []
    module.emit = lambda *args, **kwargs: events.append((args, kwargs))
    event = SimpleNamespace(
        comm=b"system-shaped-malware",
        argv0=b"/tmp/payload",
        pid=77,
        uid=1000,
        seq=1,
    )
    mapping = _Map(event)
    module._bpf = {"exec_events": mapping}
    module._attached = True

    module._on_exec(2, object(), 0)
    event.seq = 3
    module._on_exec(2, object(), 0)
    module._set_delivery_health()

    assert module._events_received == 2
    assert module._sequence_gaps == 1
    assert events[0][1]["comm"] == "system-shaped-malware"
    assert events[0][1]["sequence"] == 1
    assert events[0][1]["cpu"] == 2
    assert module.health == 35
    assert "sequence_gaps=1" in module.health_note


def test_ipv6_destination_is_preserved_exactly() -> None:
    module = ebpf_sensor.EbpfSensorNode()
    events: list[tuple[tuple, dict]] = []
    module.emit = lambda *args, **kwargs: events.append((args, kwargs))
    packed = socket.inet_pton(socket.AF_INET6, "2001:db8::42")
    event = SimpleNamespace(
        comm=b"client",
        pid=81,
        dport=443,
        daddr=0,
        daddr6=packed,
        family=socket.AF_INET6,
        v6=1,
        seq=1,
    )
    module._bpf = {"net_events": _Map(event)}

    module._on_net(0, object(), 0)
    assert events[0][1]["raddr"] == "2001:db8::42"
    assert events[0][1]["ipv6"] is True
    assert events[0][1]["address_family"] == socket.AF_INET6


def test_perf_loss_and_callback_error_never_recover_to_green() -> None:
    module = ebpf_sensor.EbpfSensorNode()
    module.emit = lambda *_args, **_kwargs: None
    module._bpf = object()
    module._attached = True

    module._on_lost("network", 4, 9)
    module._set_delivery_health()
    assert module._events_lost == 9
    assert module.health == 35
    assert "lost=9" in module.health_note

    class _BrokenMap:
        @staticmethod
        def event(_data):
            raise ValueError("malformed perf record")

    module = ebpf_sensor.EbpfSensorNode()
    module._bpf = {"exec_events": _BrokenMap()}
    module._attached = True
    module._on_exec(0, object(), 0)
    module._set_delivery_health()
    assert module._callback_errors == 1
    assert module.health == 55
    assert "malformed perf record" in module.health_note


def test_bcc_perf_buffers_register_lost_callbacks_in_source() -> None:
    source = __import__("inspect").getsource(ebpf_sensor.EbpfSensorNode.run)
    assert source.count("lost_cb=") == 2
    assert '_on_lost("exec"' in source
    assert '_on_lost("network"' in source
