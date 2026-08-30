from __future__ import annotations

import json

from angerona.core.eventbus import EventBus
from angerona.modules import wlan_monitor
from angerona.modules.wlan_monitor import WLANMonitorModule, _WLANQuery


def _state(
    bssid: str,
    *,
    ssid: str = "Corp",
    authentication: str = "WPA3-Personal",
    cipher: str = "CCMP",
    signal: int = 50,
) -> dict[str, object]:
    return {
        "ssid": ssid,
        "bssid": bssid,
        "signal": signal,
        "radio": "802.11ax",
        "authentication": authentication,
        "cipher": cipher,
    }


def _runtime(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "bus.key").write_text((b"w" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(wlan_monitor, "data_dir", lambda: root)
    return root


def test_query_distinguishes_disconnect_from_collector_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        wlan_monitor,
        "check_output_hidden",
        lambda *_args, **_kwargs: "    State : disconnected\n",
    )
    assert wlan_monitor._query_wlan().status == "disconnected"

    def fail(*_args, **_kwargs):
        raise OSError("netsh unavailable")

    monkeypatch.setattr(wlan_monitor, "check_output_hidden", fail)
    failed = wlan_monitor._query_wlan()
    assert failed.status == "error"
    assert "unavailable" in failed.reason


def test_disconnect_reconnect_to_unapproved_bssid_is_critical(
    tmp_path,
    monkeypatch,
) -> None:
    _runtime(tmp_path, monkeypatch)
    bus = EventBus()
    module = WLANMonitorModule()
    module.bind(bus)
    assert module._load_baseline() == "new"
    module._last = _state("AA:BB:CC:DD:EE:01")
    assert module.approve_current_network()[0] is True

    module._observe_query(_WLANQuery("disconnected", None))
    assert module._last["bssid"] == "AA:BB:CC:DD:EE:01"
    module._observe_query(
        _WLANQuery("connected", _state("AA:BB:CC:DD:EE:99", signal=90))
    )

    findings = [event.details.get("finding_code") for event in bus.recent(50)]
    assert "wlan.identity.unapproved_bssid" in findings
    assert "wlan.identity.transition" in findings
    assert module.health == 25
    assert "unapproved BSSID" in module.health_note


def test_collector_failure_retains_last_identity_and_degrades_health() -> None:
    module = WLANMonitorModule()
    original = _state("AA:BB:CC:DD:EE:01")
    module._last = original

    module._observe_query(_WLANQuery("error", None, "access denied"))

    assert module._last is original
    assert module.health == 35
    assert "access denied" in module.health_note


def test_observation_never_auto_approves_a_new_network(tmp_path, monkeypatch) -> None:
    _runtime(tmp_path, monkeypatch)
    module = WLANMonitorModule()
    assert module._load_baseline() == "new"
    observation = _state("AA:BB:CC:DD:EE:01")

    module._observe_query(_WLANQuery("connected", observation))
    module._observe_query(_WLANQuery("connected", observation))

    assert module._baseline["networks"] == {}
    assert module.health == 65
    assert "not operator-approved" in module.health_note


def test_security_downgrade_on_approved_bssid_is_critical(tmp_path, monkeypatch) -> None:
    _runtime(tmp_path, monkeypatch)
    bus = EventBus()
    module = WLANMonitorModule()
    module.bind(bus)
    assert module._load_baseline() == "new"
    module._last = _state("AA:BB:CC:DD:EE:01")
    assert module.approve_current_network()[0] is True

    downgraded = _state(
        "AA:BB:CC:DD:EE:01",
        authentication="Open",
        cipher="None",
    )
    module._observe_query(_WLANQuery("connected", downgraded))

    assert module.health == 25
    assert any(
        event.details.get("finding_code") == "wlan.security.changed"
        for event in bus.recent(20)
    )


def test_tampered_approved_baseline_is_not_overwritten(tmp_path, monkeypatch) -> None:
    _runtime(tmp_path, monkeypatch)
    module = WLANMonitorModule()
    assert module._load_baseline() == "new"
    module._last = _state("AA:BB:CC:DD:EE:01")
    assert module.approve_current_network()[0] is True
    path = module._baseline_path()
    document = json.loads(path.read_text(encoding="utf-8"))
    document["networks"]["Corp"]["bssids"] = ["AA:BB:CC:DD:EE:99"]
    path.write_text(json.dumps(document), encoding="utf-8")

    attacked = WLANMonitorModule()
    assert attacked._load_baseline() == "invalid"
    attacked._last = _state("AA:BB:CC:DD:EE:99")
    before = path.read_bytes()
    approved, reason = attacked.approve_current_network()

    assert approved is False
    assert "not writable" in reason
    assert path.read_bytes() == before
