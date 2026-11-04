"""Role diagnostics use real processing paths with inert, isolated inputs."""
from __future__ import annotations

import pytest

from angerona.modules import kernel_bridge
from angerona.modules.detection_runtime import DetectionRuntimeEngine, DetectionRuntimeModule
from angerona.modules.dynamic_resource import DynamicResourceModule
from angerona.modules.ebpf_sensor import EbpfSensorNode
from angerona.modules.linux_observe import LinuxObserveModule
from angerona.modules.macos_observe import MacOSObserveCollector, MacOSObserveModule
from angerona.modules.mobile_bridge import MobileResponseBridge


def _forbidden(*_args, **_kwargs):
    pytest.fail("offline role fixture invoked a live action")


def test_linux_fixture_classifies_but_never_advances_live_baseline(monkeypatch):
    module = LinuxObserveModule()
    monkeypatch.setattr(module._collector, "poll", _forbidden)
    assert module.self_test()[0]
    monkeypatch.setattr(module, "classify", lambda _event: (None, "incorrect classification"))
    ok, detail = module.self_test()
    assert not ok and "failed classification" in detail


def test_macos_fixture_checks_normalization_but_never_advances_live_baseline(monkeypatch):
    module = MacOSObserveModule()
    monkeypatch.setattr(module._collector, "poll", _forbidden)
    assert module.self_test()[0]
    monkeypatch.setattr(MacOSObserveCollector, "poll", lambda _self: [])
    ok, detail = module.self_test()
    assert not ok and "failed normalization" in detail


def test_kernel_fixture_detects_malformed_wire_and_leaves_device_unopened(monkeypatch):
    module = kernel_bridge.KernelBridgeModule()
    monkeypatch.setattr(kernel_bridge, "_open_device", _forbidden)
    assert module.self_test() == (False, kernel_bridge.KERNEL_BRIDGE_LIVE_UNAVAILABLE)
    parse = kernel_bridge._parse_event
    monkeypatch.setattr(kernel_bridge, "_parse_event", lambda wire, offset: parse(wire, offset) or {})
    ok, detail = module.self_test()
    assert not ok and "wire parser fixture failed" in detail


def test_ebpf_fixture_detects_a_lost_callback_without_attaching(monkeypatch):
    module = EbpfSensorNode()
    assert module.self_test()[0]
    monkeypatch.setattr(EbpfSensorNode, "_on_lost", lambda *_args: None)
    ok, detail = module.self_test()
    assert not ok and "loss accounting" in detail


def test_mobile_fixture_rejects_wrong_purpose_and_leaves_cli_unopened(monkeypatch):
    module = MobileResponseBridge()
    monkeypatch.setattr(module, "_invoke_cli", _forbidden)
    assert module.self_test()[0]
    monkeypatch.setattr(MobileResponseBridge, "_result_valid", lambda *_args: True)
    ok, detail = module.self_test()
    assert not ok and "purpose binding" in detail


def test_detection_runtime_fixture_catches_missing_shadow_match_without_mutating_live_engine(monkeypatch):
    module = DetectionRuntimeModule()
    before = module.engine.snapshot()
    assert module.self_test()[0]
    assert module.engine.snapshot() == before
    monkeypatch.setattr(DetectionRuntimeEngine, "process", lambda _self: (0, 0))
    ok, detail = module.self_test()
    assert not ok and "shadow isolation" in detail


def test_dynamic_resource_fixture_catches_premature_escalation_without_changing_priority(monkeypatch):
    module = DynamicResourceModule()
    monkeypatch.setattr(DynamicResourceModule, "_escalate", _forbidden)
    monkeypatch.setattr(DynamicResourceModule, "_restore", _forbidden)
    assert module.self_test()[0]
    monkeypatch.setattr(DynamicResourceModule, "_priority_transition", lambda *_args: "escalate")
    ok, detail = module.self_test()
    assert not ok and "below the incident threshold" in detail
