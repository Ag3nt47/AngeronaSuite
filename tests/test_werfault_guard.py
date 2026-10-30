"""WER observations preserve generation uncertainty and never authorize mutation."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import threading
from types import SimpleNamespace

import pytest
from defusedxml import ElementTree as ET

from angerona.core import live_debug, werfault_guard as guard
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


def test_post_acquisition_snapshot_admits_new_cache_without_changing_its_lease():
    row = replace(owned(now=100.25), expires_monotonic=102.25)
    rows, calls = (row,), []

    def supplier():
        calls.append("supplier")
        return rows

    def clock():
        calls.append("clock")
        return 100.5

    snapshot = guard.read_owned_process_snapshot(supplier, not_before=100.0, clock=clock)
    assert calls == ["supplier", "clock"]
    assert snapshot.rows is rows and snapshot.rows[0] is row
    assert snapshot.checked_monotonic == 100.5
    assert (row.observed_monotonic, row.expires_monotonic) == (100.25, 102.25)
    with pytest.raises(FrozenInstanceError):
        snapshot.checked_monotonic = 101.0
    with pytest.raises(guard.OwnedProcessReadError) as error:
        guard.read_owned_processes(supplier, now=100.0)
    assert error.value.reason_code == "row_not_yet_valid"


@pytest.mark.parametrize("checked, reason", [
    (100.2, "row_not_yet_valid"), (102.25, "row_expired"),
])
def test_post_acquisition_snapshot_keeps_future_and_exact_expiry_boundaries(checked, reason):
    row = replace(owned(now=100.25), expires_monotonic=102.25)
    with pytest.raises(guard.OwnedProcessReadError) as error:
        guard.read_owned_process_snapshot(lambda: (row,), not_before=100.0, clock=lambda: checked)
    assert error.value.reason_code == reason and error.value.snapshot_count == 1


@pytest.mark.parametrize("not_before", [None, True, -1.0, float("nan"), float("inf"), "100"])
def test_invalid_caller_clock_is_rejected_before_supplier_or_observation_clock(not_before):
    calls = []
    with pytest.raises(guard.OwnedProcessReadError) as error:
        guard.read_owned_process_snapshot(lambda: calls.append("supplier"), not_before=not_before,
                                          clock=lambda: calls.append("clock"))
    assert error.value.reason_code == "caller_clock_invalid" and calls == []


@pytest.mark.parametrize("checked, reason", [
    (None, "observation_clock_invalid"), (True, "observation_clock_invalid"),
    (float("nan"), "observation_clock_invalid"), (float("inf"), "observation_clock_invalid"),
    ("100.5", "observation_clock_invalid"), (99.9, "regressed"),
])
def test_invalid_or_regressed_post_acquisition_clock_rejects_the_snapshot(checked, reason):
    calls = []

    def supplier():
        calls.append("supplier")
        return (owned(),)

    def clock():
        calls.append("clock")
        return checked

    with pytest.raises(guard.OwnedProcessReadError) as error:
        guard.read_owned_process_snapshot(supplier, not_before=100.0, clock=clock)
    assert calls == ["supplier", "clock"] and error.value.reason_code == reason


def test_supplier_and_clock_exceptions_only_expose_fixed_consumer_reasons():
    formatting_attempts = []

    class PrivateFailure(RuntimeError):
        def __str__(self):
            formatting_attempts.append("exception")
            raise AssertionError("Private supplier or clock exception must never be formatted")

    def private_failure():
        raise PrivateFailure(r"private C:\\host\\capture command line")

    for supplier, clock, reason in (
        (private_failure, lambda: 100.5, "supplier_failed"),
        (lambda: (owned(),), private_failure, "observation_clock_invalid"),
    ):
        with pytest.raises(guard.OwnedProcessReadError) as error:
            guard.read_owned_process_snapshot(supplier, not_before=100.0, clock=clock)
        assert str(error.value) == "Current native-owned process cache is unavailable"
        assert error.value.reason_code == reason
        assert error.value.snapshot_count is None
    assert formatting_attempts == []


@pytest.mark.parametrize("supplier, now, reason, message", [
    (lambda: (owned(),), 105.0, "row_expired", "Native-owned process cache is stale or malformed"),
    (lambda: (owned(),), 99.0, "row_not_yet_valid", "Native-owned process cache is stale or malformed"),
    (lambda: (owned(), owned()), 101.0, "duplicate_pid", "Native-owned process cache has ambiguous process IDs"),
    (lambda: (), 101.0, "snapshot_empty", "Current native-owned process cache is unavailable"),
])
def test_fixed_time_reader_keeps_legacy_messages_separate_from_rejection_codes(supplier, now, reason, message):
    with pytest.raises(guard.OwnedProcessReadError) as error:
        guard.read_owned_processes(supplier, now=now)
    assert str(error.value) == message and error.value.reason_code == reason


@pytest.mark.parametrize("supplier, reason, count", [
    (None, "supplier_unbound", None), (object(), "supplier_unbound", None),
    (lambda: [owned()], "snapshot_type_invalid", None),
    (lambda: (), "snapshot_empty", 0),
    (lambda: (owned(),) * 17, "snapshot_oversized", 17),
    (lambda: (SimpleNamespace(pid=4321),), "row_type_invalid", 1),
    (lambda: (owned(), owned()), "duplicate_pid", 2),
    (lambda: (owned(), owned(pid=4322, now=90.0)), "row_expired", 2),
])
def test_snapshot_rejection_codes_hold_the_entire_cache(supplier, reason, count):
    with pytest.raises(guard.OwnedProcessReadError) as error:
        guard.read_owned_process_snapshot(supplier, not_before=100.0, clock=lambda: 100.5)
    assert error.value.reason_code == reason and error.value.snapshot_count == count


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


def test_queued_authenticated_wer_uses_post_acquisition_time_for_admission_and_correlation(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    module = fast_path.FastPathModule()
    module.bind(bus)
    row = replace(owned(now=100.25), expires_monotonic=102.25)
    rows, calls, observed = (row,), [], []
    samples = iter((99.9, 100.0, 100.5))

    def clock():
        value = next(samples, 100.5)
        calls.append(("clock", value))
        return value

    def supplier():
        calls.append(("supplier", None))
        return rows

    original_observe = module._wer_guard.observe

    def observe(event, supplied, *, now):
        observed.append((supplied, now))
        return original_observe(event, supplied, now=now)

    module.bind_owned_processes(supplier)
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=clock, time=lambda: 1001.0))
    monkeypatch.setattr(module._wer_guard, "observe", observe)
    data = creation()
    event = Event(data.module, "inert authenticated race fixture", Severity.INFO, data.event_ts,
                  dict(data.fields, eid=1, raw_sensor_evidence=True))
    bus.subscribe(module._capture_wer_event)
    bus.publish(event)
    source = bus.recent(1)[0]
    source_fields, source_hmac = dict(source.details), source.hmac_sig
    assert module._wer_queue.qsize() == 1 and bus.verify(source)
    module._drain_wer_events()

    assert calls[:4] == [("clock", 99.9), ("clock", 100.0), ("supplier", None), ("clock", 100.5)]
    assert observed == [(rows, 100.5)] and observed[0][0] is rows
    outputs = [item for item in bus.recent(10) if item.module == module.name]
    assert len(outputs) == 1 and outputs[0].severity == Severity.HIGH
    details = outputs[0].details
    assert details["finding_code"] == "werfault.suite-dump-request"
    assert details["protected_generation_bound"] is False and details["protected_birth_ticks"] is None
    assert details["protected_pid"] is None and details["response_authorized"] is False
    assert details["trigger_hmac"] == source_hmac and bus.verify(source)
    assert source.details == source_fields and source.hmac_sig == source_hmac
    assert (row.observed_monotonic, row.expires_monotonic) == (100.25, 102.25)
    assert module._wer_seen[source_hmac] == 100.0
    coverage = module.wer_coverage_snapshot()
    assert coverage["state"] == "available" and coverage["owned_roles"] == ("core",)
    assert coverage["ownership_reason_code"] == "" and coverage["ownership_snapshot_count"] == 1


@pytest.mark.parametrize("checked, reason", [
    (float("nan"), "observation_clock_invalid"), (99.9, "regressed"),
    (100.2, "row_not_yet_valid"), (102.25, "row_expired"),
])
def test_fast_path_holds_queued_wer_when_post_acquisition_admission_fails(monkeypatch, checked, reason):
    module = fast_path.FastPathModule()
    row = replace(owned(now=100.25), expires_monotonic=102.25)
    module.bind_owned_processes(lambda: (row,))
    module._wer_queue.put_nowait(creation())
    samples = iter((100.0, checked))
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: next(samples)))
    emitted = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: emitted.append((severity, details)))
    module._drain_wer_events()
    coverage = module.wer_coverage_snapshot()
    assert module._wer_queue.empty() and coverage["skipped_admission_attempts"] == 1
    assert coverage["ownership_reason_code"] == reason and coverage["owned_roles"] == ()
    assert len(emitted) == 1 and emitted[0][0] == Severity.LOW
    assert emitted[0][1]["disposition"] == "health" and emitted[0][1]["response_authorized"] is False


def test_ownership_rejection_and_ingress_loss_remain_independent_and_reason_deduplicated(monkeypatch):
    module = fast_path.FastPathModule()
    module.bind_owned_processes(lambda: ())
    module._wer_dropped = 1
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: 100.5))
    emitted = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: emitted.append((message, severity, details)))
    module._drain_wer_events()
    module._wer_dropped = 2
    module._drain_wer_events()
    coverage = module.wer_coverage_snapshot()
    assert coverage["ownership_reason_code"] == "snapshot_empty" and coverage["ownership_snapshot_count"] == 0
    assert coverage["owned_roles"] == () and coverage["ingress_lost_records"] == 2
    assert "cache unavailable" in coverage["reason"] and "ingress lost records" in coverage["reason"]
    assert len(emitted) == 1 and emitted[0][1] == Severity.LOW
    assert emitted[0][2]["ownership_reason_code"] == "snapshot_empty"
    assert emitted[0][2]["ingress_lost_records"] == 1
    assert "supplier_failed" not in emitted[0][0]


def test_fixed_ownership_rejection_is_visible_through_real_live_debug_export(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"x" * 32))
    module = fast_path.FastPathModule()
    module.bind(bus)
    module.bind_owned_processes(lambda: ())
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: 100.5))
    module._drain_wer_events()
    event = bus.recent(1)[0]
    signature, original_details = event.hmac_sig, dict(event.details)

    # Exercise the exporter and framing without constructing a service or pipe.
    exporter = object.__new__(live_debug.LiveDebugService)
    exporter.bus = bus
    exported = exporter._event_view(event)
    framed = live_debug._decode(live_debug._encode(dict(exported, protocol=live_debug.PROTOCOL)))
    assert framed["details"]["coverage_reason"] == "snapshot_empty"
    assert framed["details"]["disposition"] == "health"
    assert framed["details"]["response_authorized"] is False
    assert framed["original_hmac"] == signature and framed["original_integrity_verified"] is True
    assert event.details == original_details and event.hmac_sig == signature and bus.verify(event)
    assert event.severity == Severity.LOW


@pytest.mark.parametrize("corruption", [
    "missing_fields", "pid", "birth_ticks", "create_time", "image", "role",
    "observed_monotonic", "expires_monotonic",
])
def test_malformed_exact_class_rows_hold_queued_wer_without_exposing_field_exceptions(monkeypatch, corruption):
    formatting_attempts = []

    class PrivateFieldFailure(RuntimeError):
        def __str__(self):
            formatting_attempts.append("exception")
            raise AssertionError("Private field exception must never be formatted")

    class PoisonedField:
        def __str__(self):
            formatting_attempts.append("field")
            raise PrivateFieldFailure(r"private C:\\host\\capture command line")

        def __le__(self, other):
            raise PrivateFieldFailure(r"private C:\\host\\capture command line")

        def __gt__(self, other):
            raise PrivateFieldFailure(r"private C:\\host\\capture command line")

        def __hash__(self):
            raise PrivateFieldFailure(r"private C:\\host\\capture command line")

    if corruption == "missing_fields":
        malformed = object.__new__(guard.OwnedProcessIdentity)
    else:
        malformed = owned()
        object.__setattr__(malformed, corruption, PoisonedField())
    rows = (owned(pid=4322), malformed)
    for reader in (
        lambda: guard.read_owned_processes(lambda: rows, now=101.0),
        lambda: guard.read_owned_process_snapshot(lambda: rows, not_before=100.0, clock=lambda: 101.0),
    ):
        with pytest.raises(guard.OwnedProcessReadError) as error:
            reader()
        assert error.value.reason_code == "row_type_invalid" and error.value.snapshot_count == 2
        assert str(error.value) == "Native-owned process cache is stale or malformed"

    module = fast_path.FastPathModule()
    module.bind_owned_processes(lambda: rows)
    module._wer_queue.put_nowait(creation())
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: 101.0))
    emitted = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: emitted.append((message, severity, details)))
    module._drain_wer_events()
    coverage = module.wer_coverage_snapshot()
    assert coverage["ownership_reason_code"] == "row_type_invalid"
    assert coverage["owned_roles"] == () and coverage["skipped_admission_attempts"] == 1
    assert module._wer_queue.empty() and formatting_attempts == []
    assert len(emitted) == 1 and emitted[0][1] == Severity.LOW
    assert emitted[0][2]["coverage_reason"] == "row_type_invalid"
    assert emitted[0][2]["response_authorized"] is False
    assert "private" not in emitted[0][0] and "PrivateFieldFailure" not in emitted[0][0]


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
