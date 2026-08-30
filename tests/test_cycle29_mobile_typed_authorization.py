from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.module_base import BaseModule
from angerona.modules import mobile_bridge as mobile_module
from angerona.modules.mobile_bridge import MobileResponseBridge


def _message_id(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class _ThrottleTarget(BaseModule):
    category = "Detection"

    def __init__(self) -> None:
        super().__init__()

    def run(self) -> None:
        return


def _bridge(monkeypatch):
    monkeypatch.setenv("ANGERONA_MOBILE_PIN", "4821")
    bus = EventBus()
    bus.arm(BusAuthority(b"m" * 32))
    target = _ThrottleTarget()
    governor = SimpleNamespace(_level=1.0)
    config = SimpleNamespace(mobile_dest_number="+13035550100")
    manager = SimpleNamespace(
        config=config,
        modules={
            "Adaptive Resource Governor": governor,
            "Network Monitor": target,
        },
    )
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge.bind_manager(manager)
    sent: list[str] = []
    monkeypatch.setattr(bridge, "_send", lambda value: sent.append(value) or True)
    return bridge, bus, target, governor, sent


def test_every_eco_change_requires_fresh_scoped_nonce_pin_and_signed_receipt(
    monkeypatch,
) -> None:
    bridge, bus, target, governor, sent = _bridge(monkeypatch)
    now = time.time()

    bridge._handle(
        "+13035550100",
        "ECO ON",
        message_id=_message_id("ungated"),
        sent_at=now,
    )
    assert target._throttle == 1.0

    bridge._handle(
        "+13035550100",
        "ARM",
        message_id=_message_id("arm"),
        sent_at=now,
    )
    challenge = bridge._admin_challenge
    assert challenge is not None and len(challenge.token) == 64

    bridge._handle(
        "+13035550100",
        f"ECO ON {challenge.token} 4821",
        message_id=_message_id("eco-on"),
        sent_at=now,
    )

    assert target._throttle == 6.0
    assert governor._level == 6.0
    assert bridge._admin_challenge is None
    receipts = [
        event
        for event in bus.recent(20)
        if event.details.get("event_type") == "mobile_change_receipt"
    ]
    assert receipts and receipts[-1].details["command"] == "ECO_ON"
    assert receipts[-1].details["outcome"] == "applied"
    assert bus.verify(receipts[-1])
    assert any("signed receipt" in message for message in sent)


def test_replayed_transport_envelope_and_reused_admin_nonce_are_rejected(
    monkeypatch,
) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch)
    now = time.time()
    arm_id = _message_id("one-arm")
    bridge._handle("+13035550100", "ARM", message_id=arm_id, sent_at=now)
    challenge = bridge._admin_challenge
    assert challenge is not None

    bridge._handle("+13035550100", "ARM", message_id=arm_id, sent_at=now)
    assert bridge._admin_challenge == challenge

    command = f"ECO ON {challenge.token} 4821"
    eco_id = _message_id("one-eco")
    bridge._handle("+13035550100", command, message_id=eco_id, sent_at=now)
    assert target._throttle == 6.0
    bridge._handle("+13035550100", command, message_id=eco_id, sent_at=now)
    assert bridge._admin_challenge is None


def test_failed_pin_search_enters_bounded_mutation_lockout(monkeypatch) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch)
    now = time.time()
    bridge._handle(
        "+13035550100", "ARM", message_id=_message_id("lock-arm"), sent_at=now
    )
    challenge = bridge._admin_challenge
    assert challenge is not None

    for index in range(mobile_module._AUTH_FAILURE_LIMIT):
        bridge._handle(
            "+13035550100",
            f"ECO ON {challenge.token} 0000",
            message_id=_message_id(f"bad-pin-{index}"),
            sent_at=now,
        )

    assert bridge._lockout_remaining() > 0
    bridge._handle(
        "+13035550100",
        f"ECO ON {challenge.token} 4821",
        message_id=_message_id("correct-but-locked"),
        sent_at=now,
    )
    assert target._throttle == 1.0


def test_alert_token_is_256_bit_action_sender_expiry_and_single_use_bound(
    monkeypatch,
) -> None:
    bridge, bus, _target, _governor, sent = _bridge(monkeypatch)
    now = time.time()
    token = bridge._new_token()
    assert len(token) == 64
    bridge.pending_alerts[token] = {
        "module": "Network Monitor",
        "allowed_actions": ("MUTE",),
        "operator_identity": "+13035550100",
        "expires_monotonic": time.monotonic() + 60.0,
        "timestamp": now,
    }

    bridge._handle(
        "+13035550100",
        f"KILL {token} 4821",
        message_id=_message_id("wrong-action"),
        sent_at=now,
    )
    assert token in bridge.pending_alerts
    bridge._handle(
        "+13035550100",
        f"MUTE {token} 4821",
        message_id=_message_id("mute"),
        sent_at=now,
    )

    assert token not in bridge.pending_alerts
    assert bridge._is_muted("Network Monitor")
    receipt = bus.recent(1)[0]
    assert receipt.details["command"] == "MUTE"
    assert receipt.details["authorization_nonce_sha256"] == hashlib.sha256(
        token.encode("ascii")
    ).hexdigest()
    assert bus.verify(receipt)
    assert any("signed receipt" in message for message in sent)


def test_state_change_rejects_missing_stale_or_future_transport_evidence(
    monkeypatch,
) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch)
    now = time.time()
    bridge._handle(
        "+13035550100", "ARM", message_id=_message_id("fresh-arm"), sent_at=now
    )
    challenge = bridge._admin_challenge
    assert challenge is not None
    command = f"ECO ON {challenge.token} 4821"

    bridge._handle("+13035550100", command)
    bridge._handle(
        "+13035550100",
        command,
        message_id=_message_id("stale"),
        sent_at=now - mobile_module._COMMAND_FRESHNESS_SECONDS - 1.0,
    )
    bridge._handle(
        "+13035550100",
        command,
        message_id=_message_id("future"),
        sent_at=now + mobile_module._COMMAND_FUTURE_SKEW_SECONDS + 1.0,
    )

    assert target._throttle == 1.0
