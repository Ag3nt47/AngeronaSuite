"""Shark native credit requires a real built-in producer scan receipt."""
from __future__ import annotations

import copy
import json
import time
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.config import Config
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.module_manager import ModuleManager
from angerona.core.storage import FlightRecorder
from angerona.modules.yara_scanner import YaraScannerModule
from angerona.shark.aar_report import generate_aar, _verify_shark_native_event
from angerona.shark.run_manifest import build_run_history, preflight_run, write_run_history


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    key_path = tmp_path / "bus.key"
    key_path.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    bus = EventBus()
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    manager = ModuleManager(bus, Config(data_dir=tmp_path), recorder=recorder)
    detector = YaraScannerModule()
    detector.bind(bus)
    manager.modules[detector.name] = detector
    marker = tmp_path / "inert-signature.txt"
    marker.write_text("ANGERONA_AAR_NATIVE_SCAN_FIXTURE_2026", encoding="utf-8")
    began = time.time() - 1
    steps = [
        {"stage": "Persistence (simulated)", "technique": "Inert signature T1547.001",
         "description": "Expected positive inert file signature", "artifact_paths": [str(marker)]},
        {"stage": "Exfiltration", "technique": "Network marker T1041",
         "description": "Expected positive with no matching detector receipt"},
        {"stage": "Noise Injection", "technique": "Benign I/O",
         "description": "Completed benign workload"},
        {"stage": "Discovery", "technique": "Read-only enumeration T1087",
         "description": "Informational enumeration"},
    ]
    for step in steps:
        step.update(ts_start=began, ts_end=began + .1, ok=True)
    history = build_run_history(
        kind="shark", run_id="shark-native-fixture", generated="2026-09-23",
        steps=steps, status="completed", preflight=preflight_run(
            kind="shark", cycles=1, jitter_range=(0, 1), noise_chance=.25,
        ),
    )
    assert write_run_history(tmp_path / "shark_history.json", history)
    try:
        yield SimpleNamespace(root=tmp_path, bus=bus, recorder=recorder,
                              manager=manager, detector=detector, marker=marker)
    finally:
        recorder.close()


def _scan(runtime):
    import yara_x

    rules = yara_x.compile('rule AAR_InertFixture { strings: '
                           '$a="ANGERONA_AAR_NATIVE_SCAN_FIXTURE_2026" condition: $a }')
    scanner = YaraScannerModule._make_scanner(rules)
    assert runtime.detector._scan_file(scanner, runtime.marker) == "scanned", runtime.detector.last_error
    events = runtime.bus.recent(5)
    assert len(events) == 1
    return events[0]


def _generate(runtime):
    text = generate_aar(runtime.root, bus=runtime.bus, recorder=runtime.recorder,
                        manager=runtime.manager)
    assert "AFTER-ACTION REPORT" in text
    return text, json.loads((runtime.root / "shark_aar.json").read_text(encoding="utf-8"))


def test_real_yara_scan_receipt_is_credited_and_denominators_remain_honest(runtime):
    event = _scan(runtime)
    assert event.details["response_authorized"] is False
    text, report = _generate(runtime)
    taxonomy = report["evidence_taxonomy"]
    assert taxonomy["denominator"] == 2  # The unmatched exfiltration stays a miss.
    assert taxonomy["native_analytic_detection"] == {"count": 1, "rate": .5}
    assert taxonomy["sensor_observation"]["count"] == 1
    assert taxonomy["observation_only"]["count"] == 0
    assert taxonomy["simulation_contract_validation"]["count"] == 0
    assert taxonomy["benign_resilience"]["denominator"] == 1
    assert taxonomy["benign_resilience"]["recorded_analytic_alerts"] == 0
    assert taxonomy["benign_resilience"]["negative_detector_coverage_verified"] is False
    assert taxonomy["unscored_steps"] == 1
    assert "Expected-positive: 2" in text and "NO ALERT" in text
    assert "PASS — no false alert" not in text
    assert report["detection_remediated"] == 0


def test_signed_module_name_and_native_fields_cannot_fabricate_scan_credit(runtime):
    event = Event("YARA Scanner", "fabricated signature result", Severity.HIGH,
                  details={"path": str(runtime.marker), "evidence_type": "native_analytic_detection",
                           "detector_verdict": "positive", "producer_generation": 0,
                           "observed_content_sha256": "a" * 64,
                           "detector_receipt_nonce": "a" * 32})
    runtime.bus.publish(event)
    # Instance monkeypatches may not grant producer authority either.
    runtime.detector.verify_detection_event = lambda _event: True
    _, report = _generate(runtime)
    taxonomy = report["evidence_taxonomy"]
    assert taxonomy["native_analytic_detection"]["count"] == 0
    assert taxonomy["sensor_observation"]["count"] == 1
    assert taxonomy["observation_only"]["count"] == 1


@pytest.mark.parametrize("change", ["generation", "replacement", "manager", "recorder", "bus"])
def test_producer_proof_is_bound_to_exact_live_graph(runtime, change):
    event = _scan(runtime)
    assert _verify_shark_native_event(event, manager=runtime.manager,
                                     bus=runtime.bus, recorder=runtime.recorder)
    manager, bus, recorder = runtime.manager, runtime.bus, runtime.recorder
    if change == "generation":
        runtime.detector._lifecycle_generation += 1
    elif change == "replacement":
        manager.modules["YARA Scanner"] = SimpleNamespace(
            verify_detection_event=lambda _event: True, _bus=bus,
        )
    elif change == "manager":
        manager = SimpleNamespace(modules=manager.modules, bus=bus, recorder=recorder)
    elif change == "recorder":
        recorder = object()
    else:
        bus = EventBus()
    assert not _verify_shark_native_event(event, manager=manager, bus=bus, recorder=recorder)


def test_mutated_and_resigned_receipt_does_not_acquire_native_credit(runtime):
    event = _scan(runtime)
    altered = copy.deepcopy(event)
    altered.details["observed_content_sha256"] = "f" * 64
    runtime.bus.publish(altered)
    signed_altered = runtime.bus.recent(1)[0]
    assert runtime.bus.verify(signed_altered)
    assert not _verify_shark_native_event(signed_altered, manager=runtime.manager,
                                         bus=runtime.bus, recorder=runtime.recorder)


def test_historical_refresh_without_live_producer_does_not_claim_native_scan(runtime):
    _scan(runtime)
    text = generate_aar(runtime.root, bus=runtime.bus, recorder=runtime.recorder)
    assert "AFTER-ACTION REPORT" in text
    payload = json.loads((runtime.root / "shark_aar.json").read_text(encoding="utf-8"))
    assert payload["evidence_taxonomy"]["native_analytic_detection"]["count"] == 0
