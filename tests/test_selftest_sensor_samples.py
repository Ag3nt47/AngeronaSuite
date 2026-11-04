"""The in-app diagnostics must fail when a module misses its sample."""
from __future__ import annotations

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import (
    amsi_bridge,
    api_patch_detector,
    arp_watchdog,
    av_telemetry_bridge,
    mem_inject_scanner,
    packet_sniffer,
    packet_sniffer_worker,
    ransomware_heuristics,
    sysmon_listener,
    wlan_monitor,
)


@pytest.mark.parametrize(("module_type", "target", "helper", "replacement"), [
    (amsi_bridge.AMSIBridgeModule, amsi_bridge.AMSIBridgeModule, "_scan_and_alert", None),
    (api_patch_detector.ApiPatchDetectorModule, api_patch_detector, "_looks_hooked", None),
    (arp_watchdog.ARPWatchdogModule, arp_watchdog.ARPWatchdogModule, "_evaluate_cache", None),
    (av_telemetry_bridge.AVTelemetryBridgeModule, av_telemetry_bridge.AVTelemetryBridgeModule,
     "_decode_record", None),
    (mem_inject_scanner.MemInjectScannerModule, mem_inject_scanner, "_is_suspicious_region", False),
    (packet_sniffer.PacketSnifferModule, packet_sniffer_worker, "_token_kind", ""),
    (sysmon_listener.SysmonListenerModule, sysmon_listener.SysmonListenerModule, "_process_record", None),
    (wlan_monitor.WLANMonitorModule, wlan_monitor.WLANMonitorModule, "_observe_query", None),
])
def test_module_sample_checks_the_production_path(monkeypatch, module_type, target, helper, replacement):
    monkeypatch.setattr(wlan_monitor, "_query_wlan", lambda: wlan_monitor._WLANQuery("disconnected", None))
    monkeypatch.setattr(api_patch_detector.ApiPatchDetectorModule, "_disk_prologues",
                        lambda _self, dll: dict.fromkeys(api_patch_detector._WATCH[dll], b"fixture"))
    module = module_type()
    live_bus = EventBus()
    module.bind(live_bus)

    ok, detail = module.self_test()
    assert ok, detail
    assert live_bus.revision() == 0

    monkeypatch.setattr(target, helper, lambda *args, **kwargs: replacement)
    ok, detail = module.self_test()
    assert not ok and ("sample" in detail.casefold() or "fixture" in detail.casefold()), detail
    assert live_bus.revision() == 0


def test_disconnected_wlan_output_cannot_report_stale_identity():
    output = "    State : disconnected\n    SSID : old-link\n    BSSID : 02:11:22:33:44:55\n"
    assert wlan_monitor._parse_interface(output) is None


def test_ransomware_sample_rejects_an_overbroad_entropy_classifier(monkeypatch):
    monkeypatch.setattr(ransomware_heuristics, "_windows_directory_api", lambda: None)
    module = ransomware_heuristics.RansomwareHeuristicsModule()
    assert module.self_test()[0]
    monkeypatch.setattr(ransomware_heuristics, "_is_high_entropy", lambda _score: True)
    ok, detail = module.self_test()
    assert not ok and "Entropy sample classification failed" in detail
