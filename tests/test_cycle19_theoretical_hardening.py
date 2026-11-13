from __future__ import annotations

import hashlib
import hmac
import json
import time
from types import SimpleNamespace

from angerona.modules.mobile_bridge import MobileResponseBridge, _signal_identity
from angerona.resilience import shutdown_token


def _signed_command(key: bytes, ts: float) -> dict:
    nonce = "ab" * 16
    reason = "test"
    payload = f"{nonce}\x00{int(ts)}\x00{reason}"
    signature = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return {"nonce": nonce, "ts": ts, "reason": reason, "sig": signature}


def test_standdown_rejects_future_and_nonfinite_timestamps(tmp_path) -> None:
    key = b"k" * 32
    path = tmp_path / "standdown.cmd"
    path.write_text(json.dumps(_signed_command(key, time.time() + 300)), encoding="utf-8")
    assert not shutdown_token.is_standdown_requested(
        key=key, path=path, max_future_skew_s=30
    )

    command = _signed_command(key, time.time())
    command["ts"] = float("nan")
    path.write_text(json.dumps(command), encoding="utf-8")
    assert not shutdown_token.is_standdown_requested(key=key, path=path)


def test_standdown_accepts_only_bounded_printable_reasons(tmp_path) -> None:
    key = b"r" * 32
    path = tmp_path / "standdown.cmd"
    shutdown_token.request_standdown("operator maintenance", key=key, path=path)
    assert shutdown_token.is_standdown_requested(key=key, path=path)
    for reason in ("", "x" * 257, "line\nbreak"):
        try:
            shutdown_token.request_standdown(reason, key=key, path=path)
        except ValueError:
            pass
        else:  # pragma: no cover - explicit fail-closed assertion
            raise AssertionError("unsafe stand-down reason was accepted")


def test_signal_identity_is_explicit_and_canonical() -> None:
    assert _signal_identity("+1 (303) 555-0100") == "+13035550100"
    assert _signal_identity("") == ""
    assert _signal_identity("anonymous") == ""


def test_mobile_pin_reads_only_strict_protected_store_and_holds_legacy_values(monkeypatch, tmp_path) -> None:
    from angerona.core import mobile_command_auth as auth_module
    from test_cycle29_mobile_typed_authorization import _protected_store

    values = _protected_store(monkeypatch, tmp_path)
    values.update({auth_module.MOBILE_PIN_SECRET: "482137",
                   auth_module.LEGACY_MOBILE_PIN_SECRET: "preserved-legacy-ciphertext"})
    bridge = MobileResponseBridge()
    bridge._config = SimpleNamespace(
        data_dir=tmp_path, mobile_signal_cli=r"C:\fixtures\signal-cli.exe",
        mobile_signal_cli_sha256="a" * 64,
        mobile_signal_cli_publisher="CN=Inert Signal Fixture",
        mobile_host_number="+13035550101", mobile_dest_number="+13035550100",
    )
    monkeypatch.setenv("ANGERONA_MOBILE_PIN", "0000")
    monkeypatch.setenv("ANGERONA_MOBILE_PIN_DPAPI", "not-protected-authority")
    assert bridge._pin() == "482137"
    values[auth_module.MOBILE_PIN_SECRET] = "4821"
    monkeypatch.setenv("ANGERONA_MOBILE_PIN", "999999")
    assert bridge._pin() is None
    assert values[auth_module.LEGACY_MOBILE_PIN_SECRET] == "preserved-legacy-ciphertext"

def test_mobile_bridge_rejects_missing_or_wrong_sender(monkeypatch) -> None:
    bridge = MobileResponseBridge()
    bridge._config = SimpleNamespace(mobile_dest_number="+1 303 555 0100")
    sent: list[str] = []
    spoofed: list[str] = []
    monkeypatch.setattr(bridge, "_send", sent.append)
    monkeypatch.setattr(bridge, "_spoof", lambda _body, reason: spoofed.append(reason))
    monkeypatch.setattr(bridge, "_status_text", lambda: "SAFE STATUS")

    bridge._handle("", "STATUS")
    bridge._handle("+1 999 555 0100", "STATUS")
    assert sent == []
    assert len(spoofed) == 2

    bridge._handle("+1 (303) 555-0100", "STATUS")
    assert sent == ["SAFE STATUS"]
