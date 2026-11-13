from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from types import SimpleNamespace

from angerona.core import mobile_command_auth as auth_module
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.module_base import BaseModule
from angerona.modules import mobile_bridge as mobile_module
from angerona.modules.mobile_bridge import MobileResponseBridge


_PIN = "482137"


def _message_id(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class _ThrottleTarget(BaseModule):
    category = "Detection"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 8.0

    def __init__(self) -> None:
        super().__init__()

    def run(self) -> None:
        return


def _protected_store(monkeypatch, tmp_path):
    """Serialized named-secret adapter; never calls an operating-system store."""
    values: dict[str, str] = {}
    lock = threading.RLock()
    depth = [0]

    @contextmanager
    def transaction(data_root=None):
        assert data_root == tmp_path
        with lock:
            depth[0] += 1
            try:
                yield
            finally:
                depth[0] -= 1

    def read(names, data_root=None, *, strict=False):
        assert data_root == tmp_path and strict is True and depth[0] > 0
        return {name: values[name] for name in names if name in values}

    def write(updates, data_root=None):
        assert data_root == tmp_path and depth[0] > 0
        for name, value in updates.items():
            if value in (None, ""):
                values.pop(name, None)
            else:
                values[name] = str(value)
        return tmp_path / "inert-protected-map"

    monkeypatch.setattr(auth_module, "secret_transaction", transaction)
    monkeypatch.setattr(auth_module, "read_secret_values", read)
    monkeypatch.setattr(auth_module, "write_secret_map", write)
    return values


def _bridge(monkeypatch, tmp_path):
    # Exercise the real admission protocol against fake protected storage.
    values = _protected_store(monkeypatch, tmp_path)
    clock = [1_700_000_000.0, 1_000.0]
    monkeypatch.setattr(mobile_module, "time", SimpleNamespace(
        time=lambda: clock[0], monotonic=lambda: clock[1],
    ))
    monkeypatch.setattr(mobile_module, "MobileCommandAuthorization", lambda data_root, *, scope:
                        auth_module.MobileCommandAuthorization(
                            data_root, scope=scope, clock=lambda: clock[0],
                            monotonic=lambda: clock[1]))
    monkeypatch.setenv("ANGERONA_MOBILE_PIN", "0000")
    bus = EventBus()
    bus.arm(BusAuthority(b"m" * 32))
    target = _ThrottleTarget()
    governor = SimpleNamespace(_level=1.0)
    config = SimpleNamespace(
        data_dir=tmp_path, mobile_signal_cli=r"C:\fixtures\signal-cli.exe",
        mobile_signal_cli_sha256="a" * 64,
        mobile_signal_cli_publisher="CN=Inert Signal Fixture",
        mobile_host_number="+13035550101", mobile_dest_number="+13035550100",
    )
    manager = SimpleNamespace(config=config, modules={
        "Adaptive Resource Governor": governor, "Network Monitor": target,
    })
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge.bind_manager(manager)
    bridge._fixture_clock = clock
    bridge._fixture_protected = values
    assert bridge._command_authorization().rearm_local(_PIN, _PIN).ready
    sent: list[str] = []
    monkeypatch.setattr(bridge, "_send", lambda value: sent.append(value) or True)
    return bridge, bus, target, governor, sent


def _advance(bridge, seconds: float) -> None:
    bridge._fixture_clock[0] += seconds
    bridge._fixture_clock[1] += seconds


def test_every_eco_change_requires_fresh_scoped_nonce_pin_and_signed_receipt(
    monkeypatch, tmp_path,
) -> None:
    bridge, bus, target, governor, sent = _bridge(monkeypatch, tmp_path)
    now = mobile_module.time.time()
    bridge._handle("+13035550100", "ECO ON", message_id=_message_id("ungated"), sent_at=now)
    assert target._throttle == 1.0
    bridge._handle("+13035550100", "ARM", message_id=_message_id("arm"), sent_at=now)
    challenge = bridge._admin_challenge
    assert challenge is not None and len(challenge.token) == 64
    assert challenge.authorization_generation == bridge._mobile_auth_status().generation
    bridge._handle("+13035550100", f"ECO ON {challenge.token} {_PIN}",
                   message_id=_message_id("eco-on"), sent_at=now)
    assert target._throttle == 6.0
    assert governor._level == 6.0
    assert bridge._admin_challenge is None
    assert bridge._mobile_auth_status().failures == 0
    receipts = [event for event in bus.recent(20)
                if event.details.get("event_type") == "mobile_change_receipt"]
    assert receipts and receipts[-1].details["command"] == "ECO_ON"
    assert receipts[-1].details["outcome"] == "applied"
    assert bus.verify(receipts[-1])
    assert any("signed receipt" in message for message in sent)


def test_replayed_transport_envelope_and_reused_admin_nonce_are_rejected(
    monkeypatch, tmp_path,
) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch, tmp_path)
    now = mobile_module.time.time()
    arm_id = _message_id("one-arm")
    bridge._handle("+13035550100", "ARM", message_id=arm_id, sent_at=now)
    challenge = bridge._admin_challenge
    assert challenge is not None
    bridge._handle("+13035550100", "ARM", message_id=arm_id, sent_at=now)
    assert bridge._admin_challenge == challenge
    command = f"ECO ON {challenge.token} {_PIN}"
    eco_id = _message_id("one-eco")
    bridge._handle("+13035550100", command, message_id=eco_id, sent_at=now)
    assert target._throttle == 6.0
    bridge._handle("+13035550100", command, message_id=eco_id, sent_at=now)
    assert bridge._admin_challenge is None
    assert bridge._mobile_auth_status().failures == 0


def test_failed_pin_burns_nonce_and_enters_bounded_mutation_lockout(monkeypatch, tmp_path) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch, tmp_path)
    for index in range(mobile_module._AUTH_FAILURE_LIMIT):
        now = mobile_module.time.time()
        bridge._handle("+13035550100", "ARM", message_id=_message_id(f"arm-{index}"), sent_at=now)
        challenge = bridge._admin_challenge
        assert challenge is not None
        bridge._handle("+13035550100", f"ECO ON {challenge.token} 000000",
                       message_id=_message_id(f"bad-pin-{index}"), sent_at=now)
        assert bridge._admin_challenge is None
        status = bridge._mobile_auth_status()
        assert status.failures == index + 1 and status.retry_after_s > 0
        if index + 1 < mobile_module._AUTH_FAILURE_LIMIT:
            _advance(bridge, status.retry_after_s + 1)
    assert bridge._lockout_remaining() > 0
    _advance(bridge, bridge._mobile_auth_status().retry_after_s + 1)
    bridge._handle("+13035550100", "ARM", message_id=_message_id("correct-but-locked"),
                   sent_at=mobile_module.time.time())
    assert bridge._admin_challenge is None
    assert target._throttle == 1.0
    assert bridge._mobile_auth_status().failures == mobile_module._AUTH_FAILURE_LIMIT


def test_alert_token_is_256_bit_action_sender_expiry_and_single_use_bound(
    monkeypatch, tmp_path,
) -> None:
    bridge, bus, _target, _governor, sent = _bridge(monkeypatch, tmp_path)
    now = mobile_module.time.time()
    token = bridge._new_token()
    assert len(token) == 64
    status = bridge._mobile_auth_status()
    bridge.pending_alerts[token] = {
        "module": "Network Monitor", "allowed_actions": ("MUTE",),
        "operator_identity": "+13035550100",
        "expires_monotonic": mobile_module.time.monotonic() + 60.0, "timestamp": now,
        "authorization_generation": status.generation,
        "authorization_scope": status.scope_digest,
    }
    bridge._handle("+13035550100", f"KILL {token} {_PIN}",
                   message_id=_message_id("wrong-action"), sent_at=now)
    assert token in bridge.pending_alerts
    bridge._handle("+13035550100", f"MUTE {token} {_PIN}",
                   message_id=_message_id("mute"), sent_at=now)
    assert token not in bridge.pending_alerts
    assert bridge._is_muted("Network Monitor")
    receipt = bus.recent(1)[0]
    assert receipt.details["command"] == "MUTE"
    assert receipt.details["authorization_nonce_sha256"] == hashlib.sha256(token.encode("ascii")).hexdigest()
    assert bus.verify(receipt)
    assert any("signed receipt" in message for message in sent)


def test_state_change_rejects_missing_stale_or_future_transport_evidence(
    monkeypatch, tmp_path,
) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch, tmp_path)
    for label in ("missing", "stale", "future"):
        now = mobile_module.time.time()
        bridge._handle("+13035550100", "ARM", message_id=_message_id(f"arm-{label}"), sent_at=now)
        challenge = bridge._admin_challenge
        assert challenge is not None
        command = f"ECO ON {challenge.token} {_PIN}"
        if label == "missing":
            bridge._handle("+13035550100", command)
        else:
            sent = (now - mobile_module._COMMAND_FRESHNESS_SECONDS - 1.0 if label == "stale"
                    else now + mobile_module._COMMAND_FUTURE_SKEW_SECONDS + 1.0)
            bridge._handle("+13035550100", command, message_id=_message_id(label), sent_at=sent)
        assert bridge._admin_challenge is None
        assert target._throttle == 1.0
    assert bridge._mobile_auth_status().failures == 0
