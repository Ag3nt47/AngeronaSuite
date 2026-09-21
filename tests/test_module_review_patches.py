"""Inert regressions for the September module review; no live sensor actions."""
from __future__ import annotations

import ctypes
import threading
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import amsi_bridge, api_patch_detector, flight_cache
from angerona.modules.canary_drill import CanaryDrillModule
from angerona.modules.network_protocol_decoder import NetworkProtocolDecoderModule
from angerona.modules.provenance_graph import ProvenanceGraphModule
from angerona.modules.speculative_triage import SpeculativeTriageModule


def _dns_event():
    return Event("fixture", "DNS", Severity.INFO, details={
        "protocol": "dns", "qname": "www.example.com", "pid": 4242,
    })


@pytest.mark.parametrize("factory", [
    NetworkProtocolDecoderModule, ProvenanceGraphModule,
    SpeculativeTriageModule, flight_cache.FlightCacheModule, CanaryDrillModule,
])
def test_stopped_subscribers_do_not_even_read_event(factory):
    module = factory()
    module.stop()

    class Unreadable:
        def __getattribute__(self, name):
            pytest.fail(f"stopped subscriber read {name}")

    module._on_event(Unreadable())


@pytest.mark.parametrize("factory", [NetworkProtocolDecoderModule, ProvenanceGraphModule])
def test_retained_subscription_processes_once_after_restart(factory):
    module = factory()
    bus = EventBus()
    module.bind(bus)
    ready = threading.Event()

    def inert_run():
        bus.subscribe(module._on_event)
        ready.set()
        module.generation_stop_event().wait(2)

    module.run = inert_run
    count = (lambda: module.stats()["dns_seen"]) if factory is NetworkProtocolDecoderModule else (
        lambda: len(module.graph.nodes)
    )
    try:
        module.start()
        assert ready.wait(1)
        module.stop()
        module._thread.join(1)
        bus.publish(_dns_event())
        assert count() == 0
        ready.clear()
        module.start()
        assert ready.wait(1)
        bus.publish(_dns_event())
        assert count() == 1
        assert sum(callback == module._on_event for callback in bus._subs) == 1
    finally:
        module.stop()
        module._thread.join(1)


def test_closed_cache_does_not_serialize_details(monkeypatch):
    cache = flight_cache.FlightCache()
    cache.close()
    monkeypatch.setattr(flight_cache.json, "dumps", lambda *_a, **_k: pytest.fail("serialized"))
    cache.put(0, "fixture", 0, "ignored", {"details": "ignored"})
    assert cache.count() == 0


def test_spec_stop_discards_pending_and_rejects_disabled_admission():
    module = SpeculativeTriageModule()
    assert module.speculate({"pid": 1})
    module._primed[1] = {"warmed": True}
    module.stop()
    assert module._q.empty()
    assert module._primed == {}
    assert module._last_prewarm == {}
    assert not module.speculate({"pid": 2})


def test_spec_retired_callback_cannot_queue_into_new_generation(monkeypatch):
    module = SpeculativeTriageModule()
    entered, release = threading.Event(), threading.Event()

    def classify(*_args):
        entered.set()
        assert release.wait(2)
        return True

    monkeypatch.setattr(module, "_is_high_risk", classify)
    caller = threading.Thread(target=module._on_event, args=(_dns_event(),))
    caller.start()
    try:
        assert entered.wait(1)
        module.stop()
        # Inert new-generation token: no sensor/model workers are started.
        module._stop = threading.Event()
        release.set()
        caller.join(1)
        assert not caller.is_alive()
        assert module._q.empty()
        assert module._last_prewarm == {}
    finally:
        release.set()
        caller.join(2)


def test_spec_watchdog_restart_retires_pending_generation(monkeypatch):
    module = SpeculativeTriageModule()
    module._MAX_INFLIGHT = 0  # Observe pending work without any model workers.
    entered = threading.Event()
    monkeypatch.setattr(module, "_update_health", entered.set)
    module.start()
    try:
        assert entered.wait(1)
        assert module.speculate({"pid": 10})
        module._primed[10] = {"warmed": True}
        generation = module.lifecycle_generation
        entered.clear()
        assert module.restart_if_generation(generation)
        assert entered.wait(1)
        assert module.lifecycle_generation == generation + 1
        assert module._q.empty()
        assert module._primed == {}
    finally:
        module.stop()
        module._thread.join(2)


def test_spec_inflight_prewarm_result_is_retired(monkeypatch):
    from angerona.modules import ai_model_integrity, speculative_triage

    module = SpeculativeTriageModule()
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(ai_model_integrity, "require_fresh_model_attestation", lambda *_a: None)

    def inert_model(*_args, **_kwargs):
        entered.set()
        assert release.wait(2)
        return {}

    monkeypatch.setattr(speculative_triage.ollama_client, "analyze_telemetry", inert_model)
    worker = threading.Thread(target=module._prewarm, args=({"pid": 10},))
    worker.start()
    try:
        assert entered.wait(1)
        module.stop()
        release.set()
        worker.join(1)
        assert not worker.is_alive()
        assert module._primed == {}
        assert module.prewarms == 0
    finally:
        release.set()
        worker.join(2)


class _NativeFixture:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.closed = threading.Event()
        self.closed_during_scan = False

    def AmsiScanBuffer(self, *_args):
        self.entered.set()
        assert self.release.wait(3)
        self.closed_during_scan = self.closed.is_set()
        return 0

    def AmsiCloseSession(self, *_args):
        self.closed.set()

    def AmsiUninitialize(self, *_args):
        self.closed.set()


def _amsi_fixture(native):
    wrapper = amsi_bridge._AMSI.__new__(amsi_bridge._AMSI)
    wrapper._lock = threading.Lock()
    wrapper._lib = native
    wrapper._ok = True
    wrapper._hAmsi = ctypes.c_void_p(1)
    wrapper._hSession = ctypes.c_void_p(2)
    return wrapper


def test_amsi_stop_is_nonblocking_and_worker_closes_after_scan(monkeypatch):
    native = _NativeFixture()
    wrapper = _amsi_fixture(native)
    module = amsi_bridge.AMSIBridgeModule()
    monkeypatch.setattr(module, "_try_init_amsi", lambda: wrapper)
    monkeypatch.setattr(module, "_check_eicar_health", lambda: wrapper.scan(b"safe fixture"))
    module.start()
    try:
        assert native.entered.wait(1)
        module.stop()
        assert not native.closed.is_set()
        assert module._thread.is_alive()
        native.release.set()
        module._thread.join(2)
        assert native.closed.is_set()
        assert not native.closed_during_scan
        assert module._amsi is None
    finally:
        native.release.set()
        module.stop()
        module._thread.join(2)


def test_amsi_close_waits_for_concurrent_selftest_scan():
    native = _NativeFixture()
    wrapper = _amsi_fixture(native)
    scanner = threading.Thread(target=wrapper.scan, args=(b"safe fixture",))
    closer = threading.Thread(target=wrapper.close)
    scanner.start()
    try:
        assert native.entered.wait(1)
        closer.start()
        assert not native.closed.wait(0.05)
        native.release.set()
        scanner.join(1)
        closer.join(1)
        assert native.closed.is_set()
        assert not native.closed_during_scan
    finally:
        native.release.set()
        scanner.join(2)
        if closer.ident is not None:
            closer.join(2)


def test_amsi_successful_reinit_resets_fallback_and_closes(monkeypatch):
    closed = []
    module = amsi_bridge.AMSIBridgeModule()
    module._fallback = True
    monkeypatch.setattr(module, "_try_init_amsi", lambda: SimpleNamespace(close=lambda: closed.append(True)))
    monkeypatch.setattr(module, "_check_eicar_health", lambda: None)
    monkeypatch.setattr(module, "sleep", lambda *_a: module.stop())
    monkeypatch.setattr(module, "_drain_bus", lambda: pytest.fail("drained after stop"))
    module.run()
    assert module._fallback is False
    assert closed == [True]


def test_amsi_native_failure_and_closed_session_never_report_clean():
    native = _NativeFixture()
    native.AmsiScanBuffer = lambda *_a: -1
    wrapper = _amsi_fixture(native)
    module = amsi_bridge.AMSIBridgeModule()
    module._amsi = wrapper
    module.status = "running"
    ok, message = module.self_test()
    assert not ok and "HRESULT" in message
    wrapper.close()
    with pytest.raises(RuntimeError, match="closed"):
        wrapper.scan(b"safe fixture")


def _apid(tmp_path, monkeypatch):
    module = api_patch_detector.ApiPatchDetectorModule()
    module._soar = tmp_path / "events.jsonl"
    events = []
    monkeypatch.setattr(module, "emit", lambda *a, **k: events.append((a, k)))
    return module, events


def _hook(**kwargs):
    return {"dll": "fixture.dll", "function": "export", "indicator": "E9", **kwargs}


def test_apid_clean_export_rearms_same_incident(tmp_path, monkeypatch):
    module, events = _apid(tmp_path, monkeypatch)
    monkeypatch.setattr(api_patch_detector, "_WATCH", {"fixture.dll": ["export"]})
    clean = b"\x90" * 16
    hooked = b"\xe9" + clean[1:]
    prologues = iter([hooked, clean, hooked])
    monkeypatch.setattr(module, "_disk_prologues", lambda _dll: {"export": clean})
    monkeypatch.setattr(module, "_mem_prologue", lambda *_a: next(prologues))
    for _ in range(3):
        findings = module.scan_once()
        for finding in findings:
            module._raise_alert(finding)
        module._update_coverage_health(findings)
    assert len(events) == 2
    assert module.health == 20


def test_apid_dedup_is_bounded_expires_and_binds_process_birth(tmp_path, monkeypatch):
    module, events = _apid(tmp_path, monkeypatch)
    module._MAX_FLAGGED = 4
    clock = [1.0]
    monkeypatch.setattr(api_patch_detector, "time", SimpleNamespace(
        monotonic=lambda: clock[0], time=lambda: 123.0,
    ))
    module._raise_alert(_hook(pid=42, process_birth=1))
    module._raise_alert(_hook(pid=42, process_birth=1))
    assert len(events) == 1
    module._raise_alert(_hook(pid=42, process_birth=2))
    assert len(events) == 2
    for pid in range(100, 110):
        module._raise_alert(_hook(pid=pid, process_birth=1))
    assert len(module._flagged) == 4
    clock[0] += module._ALERT_TTL
    module._raise_alert(_hook(pid=109, process_birth=1))
    assert len(events) == 13
    assert len(module._flagged) == 1


def test_apid_unknown_birth_and_incomplete_scan_cannot_hide_new_alert(tmp_path, monkeypatch):
    module, events = _apid(tmp_path, monkeypatch)
    module._raise_alert(_hook(pid=42))
    module._raise_alert(_hook(pid=42))
    assert len(events) == 2
    module._raise_alert(_hook(pid=42, process_birth=1))
    module._coverage = {"expected": 1, "compared": 0, "disk_ready": 0}
    module._update_coverage_health([])
    assert len(module._flagged) == 1
    module._forget_clean_export(42, 1, "fixture.dll", "export")
    module._raise_alert(_hook(pid=42, process_birth=1))
    assert len(events) == 4


def test_apid_birth_identity_comes_from_open_memory_handle():
    seen = []

    def times(handle, created, *_others):
        seen.append(handle.value)
        created._obj.dwHighDateTime = 2
        created._obj.dwLowDateTime = 7
        return 1

    k32 = SimpleNamespace(GetProcessTimes=times)
    assert api_patch_detector.ApiPatchDetectorModule._process_birth(k32, 123) == (2 << 32) | 7
    assert seen == [123]
