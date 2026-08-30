from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from angerona.core.module_base import Severity
from angerona.modules import arp_watchdog
from angerona.modules.arp_watchdog import ARPWatchdogModule


_IP = "192.0.2.1"
_OLD_MAC = "00-11-22-33-44-55"
_NEW_MAC = "66-77-88-99-aa-bb"


def _capture(module: ARPWatchdogModule) -> list[tuple[str, Severity, dict]]:
    emitted: list[tuple[str, Severity, dict]] = []
    module.emit = lambda message, severity, **details: emitted.append(
        (message, severity, details)
    )
    return emitted


def test_collector_failure_retains_approved_baseline_and_degrades(monkeypatch) -> None:
    module = ARPWatchdogModule()
    module._baseline = {_IP: _OLD_MAC}
    module._baseline_status = "approved"

    def fail() -> dict[str, str]:
        raise RuntimeError("collector failed")

    monkeypatch.setattr(arp_watchdog, "_parse_arp_cache", fail)
    module._check_cache()

    assert module._baseline == {_IP: _OLD_MAC}
    assert module.health <= 25
    assert "collector unavailable" in module.health_note


def test_observation_is_never_implicitly_trusted_and_is_deduplicated(
    monkeypatch,
) -> None:
    module = ARPWatchdogModule()
    module._baseline_status = "approval-required"
    emitted = _capture(module)
    monkeypatch.setattr(
        arp_watchdog,
        "_parse_arp_cache",
        lambda: {_IP: _OLD_MAC},
    )

    module._check_cache()
    module._check_cache()

    assert module._baseline == {}
    assert module._candidate == {_IP: _OLD_MAC}
    assert module.health <= 45
    assert len(emitted) == 1
    assert emitted[0][1] == Severity.MEDIUM
    assert emitted[0][2]["ip"] == _IP


def test_explicit_approval_is_authenticated_and_invalid_evidence_is_preserved(
    tmp_path,
) -> None:
    path = tmp_path / "arp-watchdog.json"
    module = ARPWatchdogModule()
    module._baseline_path_override = path
    module._baseline_key_override = b"k" * 32
    module._candidate = {_IP: _OLD_MAC}
    module._collector_ok = True
    module._baseline_status = "approval-required"

    with pytest.raises(PermissionError):
        module.approve_current_baseline()
    assert module.approve_current_baseline(approved=True) == path

    loaded = ARPWatchdogModule()
    loaded._baseline_path_override = path
    loaded._baseline_key_override = b"k" * 32
    assert loaded._load_baseline() is True
    assert loaded._baseline == {_IP: _OLD_MAC}

    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"][_IP] = _NEW_MAC
    path.write_text(json.dumps(document), encoding="utf-8")
    invalid_bytes = path.read_bytes()

    attacked = ARPWatchdogModule()
    attacked._baseline_path_override = path
    attacked._baseline_key_override = b"k" * 32
    assert attacked._load_baseline() is False
    assert attacked._baseline_status == "invalid"
    attacked._candidate = {_IP: _NEW_MAC}
    attacked._collector_ok = True
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        attacked.approve_current_baseline(approved=True)
    assert path.read_bytes() == invalid_bytes


def test_approved_mapping_change_is_critical(monkeypatch) -> None:
    module = ARPWatchdogModule()
    module._baseline = {_IP: _OLD_MAC}
    module._baseline_status = "approved"
    emitted = _capture(module)
    monkeypatch.setattr(
        arp_watchdog,
        "_parse_arp_cache",
        lambda: {_IP: _NEW_MAC},
    )

    module._check_cache()

    assert module._baseline == {_IP: _OLD_MAC}
    assert emitted[0][1] == Severity.CRITICAL
    assert emitted[0][2]["original_mac"] == _OLD_MAC
    assert emitted[0][2]["current_mac"] == _NEW_MAC


def test_scapy_unknown_mapping_stays_untrusted_candidate() -> None:
    module = ARPWatchdogModule()
    module._baseline_status = "approval-required"
    emitted = _capture(module)
    handler = module._make_scapy_handler(threading.Event())

    handler(
        SimpleNamespace(
            getlayer=lambda _name: SimpleNamespace(
                op=2,
                psrc=_IP,
                hwsrc=_OLD_MAC,
            )
        )
    )

    assert module._baseline == {}
    assert module._candidate == {_IP: _OLD_MAC}
    assert emitted[0][1] == Severity.MEDIUM
    assert emitted[0][2]["realtime"] is True


def test_self_test_is_hermetic(monkeypatch) -> None:
    module = ARPWatchdogModule()
    monkeypatch.setattr(
        arp_watchdog,
        "_parse_arp_cache",
        lambda: (_ for _ in ()).throw(AssertionError("host command was called")),
    )

    passed, detail = module.self_test()

    assert passed is True
    assert "ARP parser ready" in detail
