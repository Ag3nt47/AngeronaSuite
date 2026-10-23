"""Known collection gaps retain evidence; detections and integrity failures stay active."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

import pytest

from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.core.peripheral_posture import POSTURE_SCHEMA, PeripheralPostureSnapshot
from angerona.core.threat import event_disposition, is_active_threat
from angerona.core.windows_auth_extensions import AuthExtensionBaselineStore, AuthExtensionCollection
from angerona.modules.app_control_monitor import AppControlDecisionSensor
from angerona.modules.authentication_extension_guard import AuthenticationExtensionIntegrityGuardModule
from angerona.modules.peripheral_dma_guard import PeripheralDMAGuardModule


KINDS = ("app-control", "peripheral", "authentication")


def _armed():
    authority = BusAuthority(b"c" * 32)
    bus = EventBus()
    bus.arm(authority)
    return authority, bus


def _actual_failure(kind, error_factory, tmp_path):
    """Only inert collector callbacks; no module.start or native provider."""
    authority, bus = _armed()

    def unavailable():
        raise error_factory()

    if kind == "app-control":
        class InertSource:
            oldest_record_id = staticmethod(unavailable)

        module = AppControlDecisionSensor(
            InertSource(), tmp_path, cursor_key=b"c" * 32,
        )
        module.bind(bus)
        module.sleep = lambda *_args, **_kwargs: module.stop()
        # Invoke the real error-handling loop once; the source fails before
        # filesystem state, native queries, or XML correlation can be reached.
        module.run()
    elif kind == "peripheral":
        module = PeripheralDMAGuardModule(observer=unavailable)
        module.bind(bus)
        module._tick()
    else:
        class InertProvider:
            collect = staticmethod(unavailable)

        # The baseline is never called if collection fails.
        module = AuthenticationExtensionIntegrityGuardModule(
            provider=InertProvider(), baseline_store=object(),
        )
        module.bind(bus)
        module.observe_once()
    assert module._thread is None
    assert len(bus.recent(10)) == 1
    return module, bus.recent(1)[0], bus, authority


def _resigned(event, authority, **changes):
    candidate = replace(event, **changes, hmac_sig="")
    return replace(candidate, hmac_sig=authority.sign(candidate))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("error_type", [
    PermissionError, FileNotFoundError, ModuleNotFoundError, ImportError,
])
def test_actual_known_unavailable_producer_is_signed_degraded_health(kind, error_type, tmp_path):
    module, event, bus, authority = _actual_failure(
        kind, lambda: error_type("inert denied or unavailable collector"), tmp_path,
    )
    original = deepcopy(event)
    assert module.health == {"app-control": 25, "peripheral": 10, "authentication": 15}[kind]
    assert event.severity is (Severity.CRITICAL if kind == "peripheral" else Severity.HIGH)
    assert event_disposition(event) == "health" and not is_active_threat(event)
    assert module.health < 50 and event.details["collection_complete"] is False
    assert event.details["observation_only"] is True
    assert event.details["enforcement_performed"] is False
    assert event.details["response_authorized"] is False
    assert bus.verify(event) and authority.verify(event) and event == original
    # Source provenance comes from the real set_health callsite, not fixture
    # text or a replacement emit implementation.
    evidence = module.health_evidence
    source = Path(sys.modules[type(module).__module__].__file__)
    assert evidence["source_state"] == "available"
    assert evidence["source_path"] == "src/angerona/modules/" + source.name
    assert evidence["source_provenance"] == "verified-loaded-implementation"
    assert evidence["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert type(evidence["source_line"]) is int and evidence["source_line"] > 0


@pytest.mark.parametrize("code", [5, 15007])
def test_native_eventlog_denial_or_missing_channel_remains_a_visible_health_gap(code, tmp_path):
    pywintypes = pytest.importorskip("pywintypes")
    _module, event, bus, _authority = _actual_failure(
        "app-control", lambda: pywintypes.error(code, "inert source", "unavailable"), tmp_path,
    )
    assert event.details["failure_type"] == "error"
    assert event.details["native_error_code"] == code
    assert event_disposition(event) == "health" and bus.verify(event)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("error_type", [ValueError, RuntimeError, OSError])
def test_unexpected_actual_collector_errors_are_not_whitelisted(kind, error_type, tmp_path):
    module, event, bus, _authority = _actual_failure(
        kind, lambda: error_type("inert integrity or unexpected runtime failure"), tmp_path,
    )
    assert module.health < 50 and bus.verify(event)
    assert event_disposition(event) == "active" and is_active_threat(event)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("native_code", [True, 5.0, "5", 9999])
def test_actual_exception_with_contradictory_native_error_is_not_guessed_denied(kind, native_code, tmp_path):
    def ambiguous():
        error = PermissionError("inert contradictory native error")
        error.winerror = native_code
        return error

    _module, event, bus, _authority = _actual_failure(kind, ambiguous, tmp_path)
    assert bus.verify(event) and is_active_threat(event)


def test_peripheral_dedup_does_not_hide_a_changed_native_failure_contract():
    _authority, bus = _armed()
    codes = iter((5, 9999))

    def unavailable():
        error = PermissionError("inert changing native error")
        error.winerror = next(codes)
        raise error

    module = PeripheralDMAGuardModule(observer=unavailable)
    module.bind(bus)
    module._tick()
    first = bus.recent(1)[0]
    assert event_disposition(first) == "health"
    module._tick()
    assert len(bus.recent(10)) == 2
    assert is_active_threat(bus.recent(1)[0])


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("change", [
    {"active_attack": True}, {"active_exploitation": True},
    {"response_authorized": True}, {"response_authority": "privileged-service"},
    {"response_contract": {"actions": ["isolate_host"]}}, {"target": "endpoint"},
    {"tamper": True}, {"integrity_failure": "baseline MAC mismatch"},
    {"digest_mismatch": True}, {"custody_authenticated": False},
    {"unknown_evidence": "unreviewed field"}, {"observation_only": False},
    {"enforcement_performed": True}, {"collection_complete": True},
    {"collector_status": "complete"}, {"health_percent": True},
    {"health_percent": 25.0}, {"schema": "unknown.v2"},
    {"finding_code": "collection.baseline.tampered"},
    {"native_error_code": True}, {"native_error_code": 5.0},
    {"native_error_code": 9999},
])
def test_resigned_contradictory_unknown_or_malformed_details_remain_active(kind, change, tmp_path):
    _module, event, bus, authority = _actual_failure(kind, PermissionError, tmp_path)
    candidate = _resigned(event, authority, details={**event.details, **change})
    assert bus.verify(candidate)
    assert event_disposition(candidate) == "active" and is_active_threat(candidate)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("removed", ["schema", "finding_code", "health_percent", "enforcement_performed"])
def test_incomplete_or_legacy_records_are_not_guessed_safe(kind, removed, tmp_path):
    _module, event, _bus, authority = _actual_failure(kind, PermissionError, tmp_path)
    details = dict(event.details)
    del details[removed]
    assert is_active_threat(_resigned(event, authority, details=details))


@pytest.mark.parametrize("kind", KINDS)
def test_another_source_or_changed_severity_cannot_borrow_the_contract(kind, tmp_path):
    _module, event, _bus, authority = _actual_failure(kind, PermissionError, tmp_path)
    assert is_active_threat(_resigned(event, authority, module="Unrelated Detector"))
    other = Severity.HIGH if kind == "peripheral" else Severity.CRITICAL
    assert is_active_threat(_resigned(event, authority, severity=other))
    wrong_error_field = "error_type" if kind == "peripheral" else "failure_type"
    details = {**event.details, wrong_error_field: "ValueError"}
    assert is_active_threat(_resigned(event, authority, details=details))


class _MemoryCodeIntegritySource:
    def __init__(self, rows):
        self.rows = rows

    @staticmethod
    def _id(xml):
        return int(xml.split("<EventRecordID>")[1].split("</EventRecordID>")[0])

    def oldest_record_id(self):
        return min(map(self._id, self.rows), default=0)

    def newest_record_id(self):
        return max(map(self._id, self.rows), default=0)

    def record_anchor(self, record_id):
        row = next((xml for xml in self.rows if self._id(xml) == record_id), "")
        return hashlib.sha256(row.encode()).hexdigest() if row else ""

    def read_after(self, record_id, limit):
        return [xml for xml in self.rows if self._id(xml) > record_id][:limit]


def _xml(event_id, record_id, fields):
    data = "".join(f"<Data Name='{key}'>{value}</Data>" for key, value in fields.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>"
        "<Correlation ActivityID='{22222222-2222-2222-2222-222222222222}'/>"
        f"</System><EventData>{data}</EventData></Event>"
    )


def test_actual_app_control_decision_and_cursor_authentication_failure_stay_active(tmp_path):
    authority, bus = _armed()
    source = _MemoryCodeIntegritySource([_xml(3099, 10, {"PolicyName": "inert existing"})])
    module = AppControlDecisionSensor(source, tmp_path, cursor_key=b"c" * 32)
    module.bind(bus)
    module.poll_once()
    source.rows.extend([
        _xml(3077, 11, {"FileName": "inert-blocked.exe", "SHA256Hash": "a" * 64}),
        _xml(3089, 12, {"TotalSignatureCount": "0", "Signature": "0", "Hash": "a" * 64}),
    ])
    module.poll_once()
    decision = next(event for event in bus.recent(10) if event.details.get("decision") == "enforced-block")
    assert bus.verify(decision) and is_active_threat(decision)
    assert decision.details["response_authorized"] is False
    cursor = tmp_path / "sensor-cursors" / "app-control.json"
    document = json.loads(cursor.read_text(encoding="utf-8"))
    document["record_id"] = 999
    cursor.write_text(json.dumps(document), encoding="utf-8")
    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=b"c" * 32)
    restarted.bind(bus)
    restarted.poll_once()
    rejected = next(event for event in bus.recent(10) if event.details.get("sensor_state") == "untrusted")
    assert authority.verify(rejected) and is_active_threat(rejected)


def test_actual_peripheral_dma_risk_is_not_suppressed_by_collector_health_contract():
    _authority, bus = _armed()
    snapshot = PeripheralPostureSnapshot(
        POSTURE_SCHEMA, "windows", "disabled", "unknown", "present", "open", "present",
        "present", "allowed", "allowed", True,
        ("windows-deviceguard", "windows-pnp", "windows-removable-policy"), 1_800_000_000.0,
    )
    module = PeripheralDMAGuardModule(observer=lambda: snapshot)
    module.bind(bus)
    module._tick()
    event = bus.recent(1)[0]
    assert event.severity is Severity.CRITICAL and bus.verify(event)
    assert event.details["risk_codes"] and is_active_threat(event)


def test_actual_auth_extension_baseline_authentication_failure_stays_active(tmp_path):
    _authority, bus = _armed()
    snapshot = AuthenticationExtensionIntegrityGuardModule._selftest_snapshot("a" * 64)

    class InertProvider:
        def collect(self):
            return AuthExtensionCollection(snapshot)

    path = tmp_path / "baselines" / "windows_auth_extensions.json"
    store = AuthExtensionBaselineStore(path, data_root=tmp_path, master_key=b"c" * 32, clock=lambda: 1000.0)
    module = AuthenticationExtensionIntegrityGuardModule(provider=InertProvider(), baseline_store=store)
    module.bind(bus)
    module.observe_once()
    path.write_text("{}", encoding="utf-8")
    result = module.observe_once()
    event = bus.recent(1)[0]
    assert result["baseline_status"] == "tampered" and module.health == 15
    assert event.severity is Severity.CRITICAL and bus.verify(event)
    assert event.details["finding_code"] == "auth_extension.baseline.authentication_failed"
    assert is_active_threat(event)
