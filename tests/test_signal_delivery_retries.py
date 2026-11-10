"""Bounded mocked transport retries; no Signal messages or inbox operations."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.modules import mobile_bridge as mobile


@pytest.fixture
def bridge(monkeypatch):
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(mobile.time, "time", lambda: clock.now)
    value = mobile.MobileResponseBridge()
    return value, clock


def seed(value, count=15):
    value._alert_times = [1000.0] * (mobile._FLOOD_MAX + 1)
    value._digest = [f"original-{index}" for index in range(count)]
    value._digest_count = count
    value._token_admission_drops = 2


def test_unsent_immediate_alert_moves_to_bounded_digest_without_new_authority(bridge, monkeypatch):
    value, _clock = bridge
    token = {"allowed_actions": ("MUTE",), "expires_monotonic": 10.0}
    value.pending_alerts["already-issued"] = token
    monkeypatch.setattr(value, "_send", lambda _text: False)
    value._deliver_alert_line("inert unsent alert")
    assert value._digest == ["inert unsent alert"] and value._digest_count == 1
    assert value.pending_alerts == {"already-issued": token}


@pytest.mark.parametrize("failure", [False, "raises"])
def test_failed_digest_preserves_samples_counts_and_minute_retry_cadence(bridge, monkeypatch, failure):
    value, clock = bridge
    seed(value)
    calls = []
    def send(text):
        calls.append(text)
        if failure == "raises":
            raise OSError("inert transport failure")
        return False
    monkeypatch.setattr(value, "_send", send)
    if failure == "raises":
        with pytest.raises(OSError):
            value._flush_digest()
    else:
        value._flush_digest()
    assert value._digest == [f"original-{index}" for index in range(15)]
    assert value._digest_count == 15 and value._token_admission_drops == 2
    value._flush_digest()  # Not due, even after the failure.
    assert len(calls) == 1
    clock.now += mobile._FLOOD_WINDOW
    monkeypatch.setattr(value, "_send", lambda text: calls.append(text) or True)
    value._flush_digest()
    assert len(calls) == 2 and value._digest == [] and value._digest_count == 0
    assert value._token_admission_drops == 0


@pytest.mark.parametrize("delivered", [False, True])
def test_arrival_during_send_is_not_erased_by_completion_or_failed_merge(bridge, monkeypatch, delivered):
    value, _clock = bridge
    seed(value)
    sent = []
    def send(text):
        sent.append(text)
        value._deliver_alert_line("arrived while first digest was in flight")
        value._flush_digest()  # A reentrant flush must not send recursively.
        return delivered
    monkeypatch.setattr(value, "_send", send)
    value._flush_digest()
    assert len(sent) == 1
    assert value._digest_count == (1 if delivered else 16)
    if delivered:
        assert value._digest == ["arrived while first digest was in flight"]
        assert value._token_admission_drops == 0
    else:
        assert len(value._digest) == 15 and value._token_admission_drops == 2


def test_local_cli_version_fixture_is_not_described_as_live_signal_connectivity(bridge, monkeypatch):
    value, _clock = bridge
    value._config = SimpleNamespace(mobile_enabled=True)
    monkeypatch.setattr(value, "_trust_config_error", lambda _cfg: "")
    def local_version(*_args, **_kwargs):
        output = b"inert signal-cli version fixture"
        receipt = value._make_receipt(nonce="a" * 64, purpose="self-test", binary_sha256="b" * 64,
                                     returncode=0, output=output, state="complete")
        return mobile._CliResult(output, receipt, True)
    monkeypatch.setattr(value, "_invoke_cli", local_version)
    ok, reason = value.self_test()
    assert ok and "local CLI version" in reason
    assert "recipient delivery remain unverified" in reason
    assert "live signal-cli custody" not in reason
