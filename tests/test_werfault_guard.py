"""WER observations preserve generation uncertainty and never authorize mutation."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import threading
from types import SimpleNamespace

import pytest
from defusedxml import ElementTree as ET

from angerona.core import werfault_guard as guard
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules import fast_path, sysmon_listener

CORE_GUID = "11111111-1111-1111-1111-111111111111"
WER_GUID = "22222222-2222-2222-2222-222222222222"
CORE = r"C:\Owned Suite\angerona.exe"
WER = r"C:\Windows\System32\WerFaultSecure.exe"
ACTOR = r"C:\Inert Fixture\caller.exe"


def owned(*, pid=4321, birth=1000.0, now=100.0):
    ticks = str(116444736000000000 + int(birth * 10_000_000))
    return guard.OwnedProcessIdentity(pid, ticks, birth, CORE, "core", now, now + 5)


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def telemetry(eid=1, *, stamp=1001.0, now=101.0, **fields):
    details = dict(eid=eid, raw_sensor_evidence=True, sensor_source="sysmon-native", **fields)
    event = Event("Sysmon Event Bridge", "Inert native-record fixture", Severity.INFO, stamp, details, hmac_sig="a" * 64)
    result = guard.capture_wer_telemetry(event, now=now, mesh_required=False)
    assert result is not None
    return result


def creation(**changes):
    fields = dict(pid=5432, image=WER, process_guid=WER_GUID, source_utc_time=utc(1001),
                  command_line=f'"{WER}" /h /pid 4321 /tid 12 /type 268310 /encfile 55 /cancel 56')
    fields.update(changes)
    return telemetry(**fields)


def register_core(correlator, identity):
    event = telemetry(pid=identity.pid, image=CORE, process_guid=CORE_GUID,
                      source_utc_time=utc(identity.create_time), command_line=f'"{CORE}"')
    assert correlator.observe(event, (identity,), now=101) is None


def wer_to_core_access():
    return telemetry(10, source_pid=5432, source_image=WER, source_process_guid=WER_GUID,
                     target_pid=4321, target_image=CORE, target_process_guid=CORE_GUID,
                     source_utc_time=utc(1001), granted_access="0x1010")


def suspend_access(**changes):
    fields = dict(source_pid=6543, source_image=ACTOR,
                  source_process_guid="33333333-3333-3333-3333-333333333333",
                  target_pid=5432, target_image=WER, target_process_guid=WER_GUID,
                  source_utc_time=utc(1001), granted_access="0x001f0fff")
    fields.update(changes)
    return telemetry(10, **fields)


@pytest.mark.parametrize("change", [
    {"birth_ticks": "00116444746000000000"}, {"birth_ticks": 116444746000000000},
    {"pid": True}, {"create_time": 1001}, {"expires_monotonic": 106},
    {"image": r"C:\Owned Suite\angerona.exe:stream"}, {"image": "relative.exe"},
    {"observed_monotonic": float("nan")}, {"role": "imported event role"},
])
def test_owned_cache_requires_exact_native_identity_and_bounded_lease(change):
    with pytest.raises(ValueError):
        replace(owned(), **change)


def test_unavailable_stale_duplicate_and_untyped_ownership_caches_are_rejected():
    row = owned()
    assert guard.read_owned_processes(lambda: (row,), now=101) == (row,)
    for supplier in (None, lambda: (), lambda: [row], lambda: (row, row), lambda: (SimpleNamespace(pid=4321),)):
        with pytest.raises(ValueError):
            guard.read_owned_processes(supplier, now=101)
    with pytest.raises(ValueError):
        guard.read_owned_processes(lambda: (row,), now=105)


def test_creation_pid_reference_does_not_claim_exact_dump_target_generation():
    row, correlator = owned(), guard.WerFaultCorrelator()
    result = correlator.observe(creation(), (row,), now=101)
    details = result.event_details()
    assert result.kind == "suite-dump-request"
    assert details["candidate_protected_pid"] == 4321
    assert details["protected_generation_bound"] is False and details["protected_birth_ticks"] is None
    assert details["protected_pid"] is None and details["microsoft_wer_identity_verified"] is False
    assert not details["active_attack"] and not details["response_authorized"]
    assert details["trigger_hmac"] == "a" * 64


@pytest.mark.parametrize("argv0", ["WerFaultSecure.exe", "unrelated-argv-zero", '"C:\\Inert Fixture\\different.exe"', ""])
def test_native_image_not_commandline_argv0_gates_the_candidate(argv0):
    command = argv0 + " /pid 4321 /type 268310 /encfile 1 /cancel 2"
    observed = guard.WerFaultCorrelator().observe(creation(command_line=command), (owned(),), now=101)
    assert observed is not None and observed.protected_generation_bound is False
    assert guard.WerFaultCorrelator().observe(creation(image=ACTOR, command_line=command), (owned(),), now=101) is None


def test_guid_birth_and_native_access_chain_only_bind_an_observed_precursor():
    row, correlator = owned(), guard.WerFaultCorrelator()
    register_core(correlator, row)
    correlator.observe(creation(), (row,), now=101)
    assert correlator.observe(wer_to_core_access(), (row,), now=101) is None
    result = correlator.observe(suspend_access(), (row,), now=101)
    details = result.event_details()
    assert result.kind == "suspend-capable-wer-access" and result.granted_access & 0x800
    assert details["protected_generation_bound"] is True
    assert details["protected_birth_ticks"] == row.birth_ticks
    assert details["suspension_confirmed"] is False
    assert details["pre_dump_prevention_verified"] is False
    assert details["native_response_contract_available"] is False and details["response_authorized"] is False


@pytest.mark.parametrize("change", [
    {"target_pid": 5433}, {"target_process_guid": CORE_GUID},
    {"target_image": r"C:\Different\WerFaultSecure.exe"}, {"granted_access": "0x1000"},
    {"granted_access": "0x800junk"}, {"granted_access": "0x100000800"},
    {"granted_access": True}, {"source_utc_time": utc(999)},
])
def test_unrelated_wrong_generation_or_non_suspend_access_does_not_match(change):
    row, correlator = owned(), guard.WerFaultCorrelator()
    register_core(correlator, row)
    correlator.observe(creation(), (row,), now=101)
    correlator.observe(wer_to_core_access(), (row,), now=101)
    assert correlator.observe(suspend_access(**change), (row,), now=101) is None


def test_missing_native_guid_or_mismatched_birth_never_becomes_exact_generation():
    row, correlator = owned(), guard.WerFaultCorrelator()
    wrong = telemetry(pid=4321, image=CORE, process_guid=CORE_GUID,
                      source_utc_time=utc(999), command_line=f'"{CORE}"')
    correlator.observe(wrong, (row,), now=101)
    correlator.observe(creation(), (row,), now=101)
    correlator.observe(wer_to_core_access(), (row,), now=101)
    result = correlator.observe(suspend_access(), (row,), now=101)
    assert result is not None and result.protected_generation_bound is False
    replacement = owned(birth=1000.5, now=101)
    assert correlator.observe(suspend_access(), (replacement,), now=101) is None


def test_conflicting_owned_guid_invalidates_an_already_correlated_dump_chain():
    row, correlator = owned(), guard.WerFaultCorrelator()
    register_core(correlator, row)
    correlator.observe(creation(), (row,), now=101)
    correlator.observe(wer_to_core_access(), (row,), now=101)
    assert correlator.observe(suspend_access(), (row,), now=101).protected_generation_bound
    conflict = telemetry(pid=4321, image=CORE, process_guid="44444444-4444-4444-4444-444444444444",
                         source_utc_time=utc(row.create_time), command_line=f'"{CORE}"')
    correlator.observe(conflict, (row,), now=101)
    after = correlator.observe(suspend_access(), (row,), now=101)
    assert after is not None and after.protected_generation_bound is False
    assert after.event_details()["protected_birth_ticks"] is None


@pytest.mark.parametrize("command", [
    f'"{WER}" /pid 4321 /pid 4321 /type 268310 /encfile 1 /cancel 2',
    f'"{WER}" /pid -4321 /type 268310 /encfile 1 /cancel 2',
    f'"{WER}" /pid 4321 /type 268310 /encfile 1 /cancel 2 /unparsed 3',
    f'"{WER}" /pid 4321 /type 268310 /encfile 99999999999999999999 /cancel 2',
    f'"{WER}" /pid 4321 /type 268310',
    f'"{WER} /pid 4321 /type 268310 /encfile 1 /cancel 2',
    f'"{WER}" /pid 4321 /type 268310 /encfile 1 /cancel 2\n',
])
def test_ambiguous_malformed_and_ordinary_wer_commands_are_not_promoted(command):
    assert guard.WerFaultCorrelator().observe(creation(command_line=command), (owned(),), now=101) is None


def test_bounded_native_sysmon_metadata_is_copied_without_response_authority():
    body = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>' + ''.join(
        f'<Data Name="{key}">{value}</Data>' for key, value in {
            "SourceProcessGUID": WER_GUID, "TargetProcessGUID": CORE_GUID,
            "SourceProcessId": "5432", "TargetProcessId": "4321", "UtcTime": utc(1001),
        }.items()) + '</EventData></Event>'
    details = sysmon_listener._build_details(10, ET.fromstring(body), "inert", [])
    assert details["source_process_guid"] == WER_GUID and details["target_process_guid"] == CORE_GUID
    assert details["source_utc_time"] == utc(1001) and details["response_authorized"] is False


def test_info_ingress_uses_current_native_cache_and_never_waits_for_high_severity(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"w" * 32))
    module = fast_path.FastPathModule()
    module.bind(bus)
    module.bind_owned_processes(lambda: (owned(),))
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: 101.0, time=lambda: 1001.0))
    data = creation()
    event = Event(data.module, "inert INFO source", Severity.INFO, data.event_ts,
                  dict(data.fields, eid=1, raw_sensor_evidence=True))
    bus.subscribe(module._capture_wer_event)
    bus.publish(event)
    assert module._wer_wake.is_set() and module._wer_queue.qsize() == 1
    module._drain_wer_events()
    output = next(row for row in bus.recent(10) if row.module == module.name)
    assert output.severity == Severity.HIGH and output.details["active_attack"] is False
    assert output.details["protected_generation_bound"] is False
    assert module.wer_coverage_snapshot()["owned_roles"] == ("core",)
    assert "absent companions" in module.wer_coverage_snapshot()["ownership_scope"]
    assert "response_contract" not in output.details


def test_ingress_is_bounded_and_authentication_failures_cannot_create_a_precursor(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"q" * 32))
    module = fast_path.FastPathModule()
    module.bind(bus)
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: 101.0, time=lambda: 1001.0))
    data = creation()
    event = Event(data.module, "inert source", Severity.INFO, data.event_ts,
                  dict(data.fields, eid=1, raw_sensor_evidence=True), hmac_sig="a" * 64)
    module._capture_wer_event(event)
    assert module._wer_queue.empty()
    bus.subscribe(module._capture_wer_event)
    for _index in range(65):
        bus.publish(replace(event, hmac_sig=""))
    assert module._wer_queue.qsize() == 64 and module.wer_coverage_snapshot()["dropped"] == 1


def test_event_driven_worker_unsubscribes_and_retires_on_stop(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"t" * 32))
    module = fast_path.FastPathModule()
    module.bind(bus)
    entered = threading.Event()
    monkeypatch.setattr(module, "_drain_wer_events", lambda: entered.set())
    worker = threading.Thread(target=module.run)
    worker.start()
    try:
        module._wer_wake.set()
        assert entered.wait(5)
    finally:
        module.stop()
        worker.join(5)
    assert not worker.is_alive()
    before = module._wer_queue.qsize()
    bus.publish(Event("Unrelated", "inert", Severity.INFO, details={}))
    assert module._wer_queue.qsize() == before == 0
