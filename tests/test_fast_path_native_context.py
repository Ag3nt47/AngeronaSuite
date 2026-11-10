from __future__ import annotations

from dataclasses import replace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.threat import is_active_threat
from angerona.modules import etw_realtime_sensor as etwr, fast_path, forensics

TICKS = 116444736000000000 + 1000000000


def mesh():
    bus = EventBus()
    bus.arm(BusAuthority(b"fast-path-offline-authority-key!!"))
    bus.activate_mesh()
    module = fast_path.FastPathModule()
    module.bind(bus)
    module._mesh_publishers = {module.name: bus.enroll_mesh_publisher(module.name, "b" * 64)}
    native = bus.enroll_mesh_publisher(fast_path._ETWR_MODULE, "a" * 64)
    other = bus.enroll_mesh_publisher("Other Sensor", "c" * 64)
    return bus, module, native, other


def source_event(**changes):
    return Event(fast_path._ETWR_MODULE, "Native process-start observation", Severity.HIGH,
                 details={"pid": 4242, "event_type": "process_creation", "source": "ETW:Kernel-Process",
                          "collection_generation": "a" * 32, "cmdline": "sekurlsa::logonpasswords",
                          "process_birth_ticks": str(TICKS), **changes})


def outputs(bus, module):
    return [event for event in bus.recent(20) if event.module == module.name]


def test_native_canonical_string_is_normalized_losslessly_and_stays_observation():
    bus, module, native, _other = mesh()
    native(source_event())
    original = bus.recent(1)[0]
    module._check_event(original)
    result, = outputs(bus, module)
    assert result.details["process_birth_ticks"] == TICKS
    assert type(result.details["process_birth_ticks"]) is int
    origin = result.details["native_origin"]
    assert origin["wire_birth"] == [{"field": "process_birth_ticks", "type": "str", "value": str(TICKS)}]
    assert origin["source_hmac"] == original.hmac_sig
    assert origin["source_mesh_sig"] == original.mesh_sig
    assert origin["collection_generation"] == "a" * 32
    assert origin["identity_inferred"] is False
    assert result.details["response_authorized"] is False
    assert result.details["forensic_coverage"] == "held"
    assert not is_active_threat(result)
    capture = forensics.ForensicsModule()
    capture.bind(bus)
    with pytest.raises(ValueError, match="active local evidence"):
        capture._admit(result)


def test_actual_etwr_parser_wire_string_is_preserved_but_info_threshold_is_unchanged():
    bus, module, native, _other = mesh()
    sensor = etwr.ETWProcessSensor(lambda _event: None)
    parsed = sensor._parse({"ProcessID": 4242, "ImageName": r"D:\fixtures\sample.exe",
                            "CreateTime": TICKS, "CommandLine": "sekurlsa::logonpasswords"})
    assert parsed["process_birth_ticks"] == str(TICKS)
    original = source_event(process_birth_ticks=parsed["process_birth_ticks"], cmdline=parsed["cmdline"])
    native(replace(original, severity=Severity.INFO))
    admitted = bus.recent(1)[0]
    plan, _held = fast_path._raw_etwr_context(admitted, bus, verified=bus.verify(admitted))
    assert plan["process_birth_ticks"] == TICKS
    module._check_event(admitted)
    assert outputs(bus, module) == []  # transport aliasing is not a new detector policy


@pytest.mark.parametrize("value", [True, None, 1.0, -1, 0, "001", "+1", "-1", "1.0", "١٢٣", "9" * 21, 2**64])
def test_malformed_ticks_cannot_become_native_identity_or_capture_authority(value):
    bus, module, native, _other = mesh()
    native(source_event(process_birth_ticks=value))
    module._check_event(bus.recent(1)[0])
    result, = outputs(bus, module)
    assert "process_birth_ticks" not in result.details
    assert "native_origin" not in result.details
    assert result.details["response_authorized"] is False
    assert not is_active_threat(result)


def test_conflicting_aliases_hold_and_equal_native_int_aliases_pass_without_inference():
    for supplied, forwarded in ((TICKS + 1, False), (TICKS, True)):
        bus, module, native, _other = mesh()
        native(source_event(native_birth_ticks=supplied))
        module._check_event(bus.recent(1)[0])
        result, = outputs(bus, module)
        assert ("native_origin" in result.details) is forwarded
        if forwarded:
            assert result.details["native_birth_ticks"] == TICKS


def test_other_source_cannot_mint_etwr_context_and_unsigned_or_modified_input_is_rejected():
    bus, module, native, other = mesh()
    other(replace(source_event(), module="Other Sensor"))
    module._check_event(bus.recent(1)[0])
    result, = outputs(bus, module)
    assert "process_birth_ticks" not in result.details
    assert "native_origin" not in result.details
    assert result.details["forensic_coverage"] == "held"
    before = len(outputs(bus, module))
    module._check_event(source_event())
    native(source_event(pid=4243))
    changed = replace(bus.recent(1)[0], details={**bus.recent(1)[0].details, "process_birth_ticks": TICKS + 1})
    module._check_event(changed)
    assert len(outputs(bus, module)) == before


def test_hmac_only_source_name_is_not_native_publisher_proof():
    bus, module = EventBus(), fast_path.FastPathModule()
    authority = BusAuthority(b"legacy-fast-path-source-key-32!!!")
    bus.arm(authority)
    module.bind(bus)
    original = source_event()
    module._check_event(replace(original, hmac_sig=authority.sign(original)))
    result, = outputs(bus, module)
    assert "native_origin" not in result.details and "process_birth_ticks" not in result.details
    assert not is_active_threat(result)


def test_old_native_generation_is_rejected_by_mesh_not_recovered_by_text_alias():
    bus, module, native, _other = mesh()
    native(source_event())
    original = bus.recent(1)[0]
    bus.freeze_mesh()
    module._check_event(original)
    assert not outputs(bus, module)


def test_native_birth_dedup_does_not_cross_pid_reuse():
    bus, module, native, _other = mesh()
    for birth in (TICKS, TICKS + 1):
        native(source_event(process_birth_ticks=str(birth)))
        module._check_event(bus.recent(1)[0])
    assert len(outputs(bus, module)) == 2


def test_command_alias_malformed_or_conflicting_fields_do_not_execute_objects():
    bus, module, native, _other = mesh()
    native(source_event(command_line="benign", cmdline="sekurlsa::logonpasswords"))
    module._check_event(bus.recent(1)[0])
    assert not outputs(bus, module)
    native(source_event(cmdline="x" * 4097))
    module._check_event(bus.recent(1)[0])
    assert not outputs(bus, module)
