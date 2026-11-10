"""Mock AMSI verdicts over real enrolled native wire events; no host scans/reads."""
from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.threat import is_active_threat
from angerona.modules import amsi_bridge as amsi
from angerona.modules import etw_realtime_sensor as etwr
from angerona.modules import forensics


NOW = 1_800_000_000.0
MONOTONIC = 1000.0
TICKS = amsi._WINDOWS_EPOCH + int((NOW - 10) * 10_000_000) + 7
TEXT = "powershell.exe -NoProfile -Command Write-Output inert-offline-fixture"
IMAGE = r"D:\fixtures\inert-powershell.exe"


@pytest.fixture
def linked(monkeypatch):
    monkeypatch.setattr(amsi.time, "time", lambda: NOW)
    monkeypatch.setattr(amsi.time, "monotonic", lambda: MONOTONIC)
    bus = EventBus()
    bus.arm(BusAuthority(b"amsi-native-offline-authority-32!"))
    bus.activate_mesh()
    source = etwr.EtwRealtimeSensorModule()
    source.bind(bus)
    source.status = "running"
    source._collection_generation = "a" * 32
    source._collection_cache = source._collection_state("native", True, 0, "offline cached native fixture")
    source._mesh_publishers = {source.name: bus.enroll_mesh_publisher(source.name, "a" * 64)}
    bridge = amsi.AMSIBridgeModule()
    bridge.bind(bus)
    bridge.bind_manager(SimpleNamespace(modules={source.name: source}))
    bridge._mesh_publishers = {bridge.name: bus.enroll_mesh_publisher(bridge.name, "b" * 64)}
    bridge._amsi = SimpleNamespace(scan=lambda _buffer, _label: amsi.AMSI_RESULT_DETECTED)
    capture = forensics.ForensicsModule()
    capture.bind(bus)
    # Even admission must not manufacture missing original identity via a
    # current-PID lookup. No native scanner or memory reader runs in this file.
    import psutil
    monkeypatch.setattr(etwr._PidNameCache, "_seed", lambda _self: None)
    monkeypatch.setattr(psutil, "Process", lambda *_a, **_k: pytest.fail("current PID lookup forbidden"))
    yield bus, source, bridge, capture
    bus.close_mesh()


def original(linked, **changes):
    bus, source, _bridge, _capture = linked
    parser = etwr.ETWProcessSensor(lambda _event: None)
    parsed = parser._parse({"ProcessID": 4242, "ImageName": IMAGE,
                            "CreateTime": TICKS, "CommandLine": TEXT})
    assert parsed["process_birth_ticks"] == str(TICKS)
    # Use the actual producer, including its INFO severity and original string
    # FILETIME. This is not a high-severity invented raw sensor event.
    source._on_event(parsed, _generation=source._collection_generation)
    ev = bus.recent(1)[0]
    if changes:
        source.publish_event(replace(ev, details={**ev.details, **changes}))
        ev = bus.recent(1)[0]
    assert ev.severity is Severity.INFO and bus.verify(ev)
    return ev


def scan(linked, ev, content=TEXT.encode("ascii")):
    bus, _source, bridge, _capture = linked
    bridge._scan_and_alert(content, ev)
    return [item for item in bus.recent(20) if item.module == bridge.name]


def assert_held(linked, result):
    _bus, _source, _bridge, capture = linked
    assert result.severity is Severity.CRITICAL
    assert result.details["amsi_result"] == amsi.AMSI_RESULT_DETECTED
    assert result.details["active_attack"] is False
    assert result.details["forensic_coverage"] == "held"
    assert result.details["forensic_hold_reason"]
    assert result.details["response_authorized"] is False
    assert "pid" not in result.details and "process_birth_ticks" not in result.details
    assert not is_active_threat(result)
    with pytest.raises(ValueError, match="active local evidence"):
        capture._admit(result)


def test_native_info_plus_actual_positive_api_verdict_preserves_original_wire_and_admits_capture(linked):
    bus, source, bridge, capture = linked
    ev = original(linked)
    received = []
    bridge._amsi = SimpleNamespace(scan=lambda data, label: (
        received.append((data, label)) or amsi.AMSI_RESULT_DETECTED))
    result, = scan(linked, ev)
    assert received == [(TEXT.encode("ascii"), "angerona_script_scan")]
    assert bus.verify(result) and is_active_threat(result)
    detail = result.details
    assert detail["pid"] == 4242 and detail["image"] == IMAGE
    assert detail["process_birth_ticks"] == TICKS and type(detail["process_birth_ticks"]) is int
    assert detail["scan_content_sha256"] == hashlib.sha256(TEXT.encode("ascii")).hexdigest()
    origin = detail["native_origin"]
    assert origin["wire_birth"] == [{"field": "process_birth_ticks", "type": "str", "value": str(TICKS)}]
    assert origin["source_hmac"] == ev.hmac_sig and origin["source_mesh_sig"] == ev.mesh_sig
    assert origin["source_mesh_peer"] == ev.mesh_peer and origin["ts"] == ev.ts
    assert origin["collection_generation"] == source._collection_generation
    assert origin["identity_inferred"] is False
    assert detail["amsi_post_observation"] is True
    assert detail["response_authorized"] is False and "response_contract" not in detail
    assert capture._admit(result) == (4242, (TICKS - amsi._WINDOWS_EPOCH) / 10_000_000, TICKS)
    # Neither normalization nor scanning changed the original native event.
    assert bus.verify(ev) and type(ev.details["process_birth_ticks"]) is str


@pytest.mark.parametrize("aliases", [
    {"process_birth_ticks": TICKS},
    {"native_birth_ticks": TICKS, "command_line": TEXT},
    {"create_time": (TICKS - amsi._WINDOWS_EPOCH) / 10_000_000},
])
def test_equal_original_identity_aliases_preserved_without_current_pid_lookup(linked, aliases):
    ev = original(linked, **aliases)
    result, = scan(linked, ev)
    origin = result.details["native_origin"]
    assert origin["wire_birth"][0]["value"] == ev.details["process_birth_ticks"]
    if "create_time" in aliases:
        assert origin["wire_seconds"] == {"create_time": aliases["create_time"]}
    assert linked[3]._admit(result)[2] == TICKS


def test_exact_registered_inert_drill_is_never_promoted_to_intrusive_capture(linked, monkeypatch):
    from angerona.core import practice_scope
    for name in ("_runs", "_artifacts", "_process_tokens"):
        monkeypatch.setattr(practice_scope, name, {})
    practice_scope.register_process("inert-offline-fixture", "amsi-offline-practice", pid=4242)
    ev = original(linked)
    assert practice_scope.is_practice_event(ev)
    result, = scan(linked, ev)
    assert_held(linked, result)


@pytest.mark.parametrize("verdict", [amsi.AMSI_RESULT_CLEAN, amsi.AMSI_RESULT_NOT_DETECTED,
                                    amsi.AMSI_RESULT_BLOCKED_BY_ADMIN_START])
def test_raw_info_is_not_promoted_without_positive_malware_verdict(linked, verdict):
    _bus, _source, bridge, _capture = linked
    bridge._amsi = SimpleNamespace(scan=lambda _data, _label: verdict)
    output = scan(linked, original(linked))
    if verdict == amsi.AMSI_RESULT_BLOCKED_BY_ADMIN_START:
        result, = output
        assert result.severity is Severity.HIGH
        assert not is_active_threat(result) and result.details["response_authorized"] is False
        assert "process_birth_ticks" not in result.details
    else:
        assert output == []


@pytest.mark.parametrize("ticks", [None, True, 1.0, "+1", "001", "١٢٣", "9" * 21,
                                 0, -1, 2**64, str(2**64), str(amsi._WINDOWS_EPOCH)])
def test_positive_content_retained_but_bad_original_raw_birth_never_mints_capture(linked, ticks):
    result, = scan(linked, original(linked, process_birth_ticks=ticks))
    assert_held(linked, result)


@pytest.mark.parametrize("change", [
    {"pid": True}, {"pid": 4}, {"pid": "4242"}, {"pid": 2**32},
    {"image": None}, {"image": "sample.exe"}, {"image": r"\rooted-without-drive.exe"},
    {"image": IMAGE + "\0"}, {"fallback": True}, {"source": "polling"},
    {"event_type": "inventory"}, {"collection_generation": "b" * 32},
    {"collection_generation": "a" * 64}, {"native_birth_ticks": TICKS + 1},
    {"process_create_time": NOW}, {"create_time": None}, {"start_time": float("nan")},
    {"command_line": "powershell different bytes"}, {"script_block": TEXT},
    {"cmdline": TEXT + " altered"}, {"cmdline": b"powershell"},
    {"drill": True}, {"self_test": True}, {"simulation": True}, {"practice": True},
])
def test_positive_content_without_exact_live_native_identity_stays_unattributed(linked, change):
    # Nonfinite payloads cannot enter the real mesh, so exercise that malformed
    # annotation as unsigned input below instead of inventing a signed NaN.
    if change.get("start_time") != change.get("start_time"):
        ev = replace(original(linked), details={**original(linked).details, **change})
    else:
        ev = original(linked, **change)
    result, = scan(linked, ev)
    assert_held(linked, result)


@pytest.mark.parametrize("state", ["old-event", "future-event", "old-receipt", "future-receipt",
                                   "stopped", "fallback", "loss", "other-owner", "other-bus",
                                   "no-manager", "no-mesh", "hmac-only", "unsigned", "mutated",
                                   "remote", "forged-source-name"])
def test_source_authentication_generation_freshness_and_cached_owner_required(linked, state):
    bus, source, bridge, _capture = linked
    ev = original(linked)
    if state in {"old-event", "future-event"}:
        source.publish_event(replace(ev, ts=NOW - 31 if state == "old-event" else NOW + 2))
        ev = bus.recent(1)[0]
    elif state in {"old-receipt", "future-receipt"}:
        source._collection_cache["sampled_monotonic"] = MONOTONIC + (-16 if state == "old-receipt" else 1)
    elif state == "stopped":
        source.status = "stopped"
    elif state == "fallback":
        source._collection_cache.update(mode="polling", live=False)
    elif state == "loss":
        source._collection_cache["loss_count"] = 1
    elif state == "other-owner":
        bridge._manager.modules[source.name] = SimpleNamespace(collection_snapshot=source.collection_snapshot)
    elif state == "other-bus":
        source._bus = EventBus()
    elif state == "no-manager":
        bridge._manager = None
    elif state == "no-mesh":
        bus.freeze_mesh()
        # A new consumer generation can report the old source as held, but
        # cannot reuse that source's retired telemetry receipt.
        bus.activate_mesh()
        bridge._mesh_publishers = {bridge.name: bus.enroll_mesh_publisher(bridge.name, "b" * 64)}
    elif state == "hmac-only":
        ev = replace(ev, mesh_sig="", mesh_peer="")
    elif state == "unsigned":
        ev = Event(ev.module, ev.message, ev.severity, ev.ts, ev.details)
    elif state == "mutated":
        ev.details["image"] = r"D:\fixtures\replaced.exe"
    elif state == "remote":
        ev = replace(ev, details={**ev.details, "node_origin": "other-host"})
    elif state == "forged-source-name":
        bus.enroll_mesh_publisher("Other Sensor", "c" * 64)(replace(ev, module="Other Sensor"))
        ev = replace(bus.recent(1)[0], module=source.name)
    result, = scan(linked, ev)
    assert_held(linked, result)


@pytest.mark.parametrize("mutation", ["bytes", "generation", "receipt", "source-mutation", "mesh-freeze"])
def test_changes_during_native_scan_keep_positive_content_but_withhold_target(linked, mutation):
    bus, source, bridge, _capture = linked
    ev = original(linked)
    def provider(data, _label):
        assert data == TEXT.encode("ascii")
        if mutation == "bytes":
            ev.details["cmdline"] = TEXT + " changed during native scan"
        elif mutation == "generation":
            source._collection_generation = "b" * 32
        elif mutation == "receipt":
            source._collection_cache["live"] = False
        elif mutation == "source-mutation":
            ev.details["pid"] = 4343
        else:
            bus.freeze_mesh()
            # The AMSI module's publisher also belongs to the frozen telemetry
            # generation: collect its emitted finding without bypassing the bus.
        return amsi.AMSI_RESULT_DETECTED
    bridge._amsi = SimpleNamespace(scan=provider)
    emitted = []
    real_emit = bridge.emit
    def keep_finding(message, severity=Severity.INFO, **details):
        emitted.append(Event(bridge.name, message, severity, details=details))
        if mutation != "mesh-freeze":
            real_emit(message, severity, **details)
    bridge.emit = keep_finding
    bridge._scan_and_alert(TEXT.encode("ascii"), ev)
    result, = emitted
    assert_held(linked, result)


@pytest.mark.parametrize("result", [True, None, "32768", -1, 2**32, float("inf")])
def test_malformed_native_results_cannot_supply_detector_verdict(linked, result):
    _bus, _source, bridge, _capture = linked
    bridge._amsi = SimpleNamespace(scan=lambda _data, _label: result)
    assert scan(linked, original(linked)) == []
    assert "invalid native result" in bridge.last_error


def test_same_text_in_distinct_native_pid_generations_is_scanned_separately(linked):
    bus, _source, bridge, _capture = linked
    original(linked)
    original(linked, process_birth_ticks=str(TICKS + 1))
    bridge._drain_bus()
    detections = [ev for ev in bus.recent(20) if ev.module == bridge.name]
    assert len(detections) == 2
    assert {ev.details["process_birth_ticks"] for ev in detections} == {TICKS, TICKS + 1}


def test_unsigned_bus_input_does_not_call_native_provider(linked):
    _bus, _source, bridge, _capture = linked
    ev = original(linked)
    bridge.poll_bus_events = lambda: ([replace(ev, hmac_sig="")], False)
    bridge._amsi = SimpleNamespace(scan=lambda *_a: pytest.fail("unsigned input must not reach AMSI"))
    bridge._drain_bus()
