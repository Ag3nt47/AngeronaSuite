from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core import mobile_command_auth as auth_module
from test_cycle29_mobile_typed_authorization import _protected_store
from angerona.core.module_base import BaseModule
from angerona.modules import mobile_bridge as mobile_module
from angerona.modules.mobile_bridge import MobileResponseBridge


_DEST = "+13035550100"
_PIN = "482137"


def _message_id(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class _ThrottleTarget(BaseModule):
    category = "Detection"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 8.0

    def __init__(self, level: float = 1.0) -> None:
        super().__init__()
        self._throttle = level

    def run(self) -> None:
        return


def _bridge(monkeypatch, tmp_path, *, modules: dict[str, object] | None = None):
    _protected_store(monkeypatch, tmp_path)
    clock = _FastClock()
    monkeypatch.setattr(mobile_module, "time", clock)
    monkeypatch.setattr(mobile_module, "MobileCommandAuthorization", lambda data_root, *, scope:
                        auth_module.MobileCommandAuthorization(
                            data_root, scope=scope, clock=lambda: mobile_module.time.time(),
                            monotonic=lambda: mobile_module.time.monotonic()))
    monkeypatch.setenv("ANGERONA_MOBILE_PIN", "0000")
    bus = EventBus()
    bus.arm(BusAuthority(b"b10-independent-reattack-key!!"))
    target = _ThrottleTarget()
    governor = SimpleNamespace(_level=1.0)
    configured_modules: dict[str, object] = {
        "Adaptive Resource Governor": governor,
        "Network Monitor": target,
    }
    configured_modules.update(modules or {})
    manager = SimpleNamespace(
        config=SimpleNamespace(
            data_dir=tmp_path, mobile_signal_cli=r"C:\fixtures\signal-cli.exe",
            mobile_signal_cli_sha256="a" * 64,
            mobile_signal_cli_publisher="CN=Inert Signal Fixture",
            mobile_host_number="+13035550101", mobile_dest_number=_DEST,
        ),
        modules=configured_modules,
    )
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge.bind_manager(manager)
    assert bridge._command_authorization().rearm_local(_PIN, _PIN).ready
    sent: list[str] = []
    monkeypatch.setattr(bridge, "_send", lambda message: sent.append(str(message)) or True)
    monkeypatch.setattr(bridge, "_soar_event", lambda *_args, **_kwargs: None)
    return bridge, bus, target, governor, sent


def _arm(bridge: MobileResponseBridge, label: str, now: float) -> str:
    bridge._handle(_DEST, "ARM", message_id=_message_id(label), sent_at=now)
    challenge = bridge._admin_challenge
    assert challenge is not None
    return challenge.token


@pytest.mark.parametrize(
    "command",
    ("ECO_ON", "ECO_OFF", "LOCKDOWN", "KILL", "SUSPEND", "ROLLBACK", "MUTE"),
)
@pytest.mark.parametrize("evidence", ("missing", "stale", "future", "replay"))
def test_every_mutator_rejects_bad_transport_identity(
    monkeypatch, tmp_path, command: str, evidence: str
) -> None:
    bridge, _bus, _target, _governor, _sent = _bridge(monkeypatch, tmp_path)
    now = mobile_module.time.time()
    effects: list[str] = []
    monkeypatch.setattr(bridge, "_eco", lambda *_args, **_kwargs: effects.append(command))
    monkeypatch.setattr(bridge, "_lockdown", lambda *_args, **_kwargs: effects.append(command))
    monkeypatch.setattr(bridge, "_gated", lambda *_args, **_kwargs: effects.append(command))
    monkeypatch.setattr(bridge, "_mute", lambda *_args, **_kwargs: effects.append(command))

    if command.startswith("ECO_") or command == "LOCKDOWN":
        token = _arm(bridge, f"arm-{command}-{evidence}", now)
        if command == "LOCKDOWN":
            body = f"LOCKDOWN {token} {_PIN}"
        else:
            body = f"ECO {command.removeprefix('ECO_')} {token} {_PIN}"
    else:
        token = bridge._new_token()
        bridge.pending_alerts[token] = {
            "module": "Network Monitor",
            "allowed_actions": (command,),
            "operator_identity": _DEST,
            "expires_monotonic": mobile_module.time.monotonic() + 60.0,
            "response_eligible": True,
            "authorization_generation": bridge._mobile_auth_status().generation,
            "authorization_scope": bridge._mobile_auth_status().scope_digest,
        }
        body = f"{command} {token} {_PIN}"

    message_id = _message_id(f"{command}-{evidence}")
    sent_at: float | None = now
    if evidence == "missing":
        message_id = ""
        sent_at = None
    elif evidence == "stale":
        sent_at = now - mobile_module._COMMAND_FRESHNESS_SECONDS - 0.01
    elif evidence == "future":
        sent_at = now + mobile_module._COMMAND_FUTURE_SKEW_SECONDS + 0.01
    else:
        bridge._seen_command_ids[message_id] = mobile_module.time.monotonic()

    assert bridge._mobile_auth_status().ready
    bridge._handle(_DEST, body, message_id=message_id, sent_at=sent_at)

    assert effects == []
    assert bridge._mobile_auth_status().failures == 0
    if command.startswith("ECO_") or command == "LOCKDOWN":
        assert bridge._admin_challenge is None
    else:
        assert token not in bridge.pending_alerts


def test_nonce_sender_scope_expiry_reuse_and_pin_lockout_hold(monkeypatch, tmp_path) -> None:
    bridge, _bus, target, _governor, _sent = _bridge(monkeypatch, tmp_path)
    now = mobile_module.time.time()
    token = _arm(bridge, "scope-arm", now)

    bridge._handle(
        "+13035550199",
        f"ECO ON {token} {_PIN}",
        message_id=_message_id("wrong-sender"),
        sent_at=now,
    )
    assert target._throttle == 1.0
    assert bridge._admin_challenge is not None

    bridge._admin_challenge = replace(
        bridge._admin_challenge,
        expires_monotonic=mobile_module.time.monotonic() - 0.01,
    )
    bridge._handle(
        _DEST,
        f"ECO ON {token} {_PIN}",
        message_id=_message_id("expired-admin"),
        sent_at=now,
    )
    assert target._throttle == 1.0

    # Expiry rejection above must not pre-consume the PIN loop's protocol budget.
    mobile_module.time.wall += mobile_module._AUTH_FAILURE_WINDOW_SECONDS + 1
    mobile_module.time.mono += mobile_module._AUTH_FAILURE_WINDOW_SECONDS + 1
    for index in range(mobile_module._AUTH_FAILURE_LIMIT):
        now = mobile_module.time.time()
        token = _arm(bridge, f"pin-arm-{index}", now)
        bridge._handle(_DEST, f"ECO ON {token} 000000",
                       message_id=_message_id(f"bad-pin-independent-{index}"), sent_at=now)
        assert bridge._admin_challenge is None
        status = bridge._mobile_auth_status()
        assert status.failures == index + 1 and status.retry_after_s > 0
        if index + 1 < mobile_module._AUTH_FAILURE_LIMIT:
            mobile_module.time.wall += status.retry_after_s + 1
            mobile_module.time.mono += status.retry_after_s + 1
    assert bridge._lockout_remaining() > 0.0
    assert target._throttle == 1.0

    # Clearing only the old in-memory protocol throttle does not erase protected
    # PIN failures. The earlier nonce remains burned; request a fresh one.
    bridge._auth_locked_until = 0.0
    bridge._auth_failures.clear()
    delay = bridge._mobile_auth_status().retry_after_s + 1
    mobile_module.time.wall += delay
    mobile_module.time.mono += delay
    now = mobile_module.time.time()
    fresh = _arm(bridge, "fresh-after-lockout", now)
    assert fresh != token
    bridge._handle(_DEST, f"ECO ON {fresh} {_PIN}",
                   message_id=_message_id("first-use"), sent_at=now)
    assert target._throttle == 6.0
    assert bridge._mobile_auth_status().failures == mobile_module._AUTH_FAILURE_LIMIT
    bridge._handle(_DEST, f"ECO OFF {fresh} {_PIN}",
                   message_id=_message_id("nonce-reuse"), sent_at=now)
    assert target._throttle == 6.0


def test_alert_tokens_are_random_scoped_expiring_sender_bound_and_single_use(
    monkeypatch, tmp_path,
) -> None:
    bridge, bus, _target, _governor, _sent = _bridge(monkeypatch, tmp_path)
    generated = {bridge._new_token() for _ in range(256)}
    assert len(generated) == 256
    assert all(re.fullmatch(r"[0-9a-f]{64}", token) for token in generated)

    now = mobile_module.time.time()
    token = next(iter(generated))
    bridge.pending_alerts[token] = {
        "module": "Network Monitor",
        "allowed_actions": ("MUTE",),
        "operator_identity": _DEST,
        "expires_monotonic": mobile_module.time.monotonic() + 60.0,
        "response_eligible": False,
        "authorization_generation": bridge._mobile_auth_status().generation,
        "authorization_scope": bridge._mobile_auth_status().scope_digest,
    }
    bridge._handle(
        _DEST,
        f"KILL {token} {_PIN}",
        message_id=_message_id("alert-action-confusion"),
        sent_at=now,
    )
    bridge._handle(
        "+13035550199",
        f"MUTE {token} {_PIN}",
        message_id=_message_id("alert-sender-confusion"),
        sent_at=now,
    )
    assert token in bridge.pending_alerts
    assert not bridge._is_muted("Network Monitor")

    bridge.pending_alerts[token]["expires_monotonic"] = mobile_module.time.monotonic() - 0.01
    bridge._handle(
        _DEST,
        f"MUTE {token} {_PIN}",
        message_id=_message_id("expired-alert"),
        sent_at=now,
    )
    assert not bridge._is_muted("Network Monitor")

    token = bridge._new_token()
    bridge.pending_alerts[token] = {
        "module": "Network Monitor",
        "allowed_actions": ("MUTE",),
        "operator_identity": _DEST,
        "expires_monotonic": mobile_module.time.monotonic() + 60.0,
        "response_eligible": False,
        "authorization_generation": bridge._mobile_auth_status().generation,
        "authorization_scope": bridge._mobile_auth_status().scope_digest,
    }
    bridge._handle(
        _DEST,
        f"MUTE {token} {_PIN}",
        message_id=_message_id("valid-alert"),
        sent_at=now,
    )
    assert token not in bridge.pending_alerts
    assert bridge._is_muted("Network Monitor")
    receipt_count = sum(
        event.details.get("event_type") == "mobile_change_receipt"
        for event in bus.recent(100)
    )
    bridge._handle(
        _DEST,
        f"MUTE {token} {_PIN}",
        message_id=_message_id("alert-token-reuse"),
        sent_at=now,
    )
    assert sum(
        event.details.get("event_type") == "mobile_change_receipt"
        for event in bus.recent(100)
    ) == receipt_count


class _RollbackFailureTarget:
    category = "Detection"

    def __init__(self) -> None:
        self._throttle = 2.0

    def set_throttle(self, value: float) -> None:
        if float(value) == 6.0:
            self._throttle = 6.0
            raise RuntimeError("apply failed after mutation")
        if float(value) == 2.0:
            raise RuntimeError("rollback refused")
        self._throttle = float(value)


def test_eco_rejects_unmanaged_setter_without_any_partial_state_change(
    monkeypatch, tmp_path,
) -> None:
    failing = _RollbackFailureTarget()
    governor = SimpleNamespace(_level=4.0)
    bridge, bus, _target, _unused_governor, sent = _bridge(
        monkeypatch, tmp_path,
        modules={
            "Adaptive Resource Governor": governor,
            "Failing Detector": failing,
        },
    )
    # Remove the default successful target so the fault is the first mutation.
    bridge._manager.modules.pop("Network Monitor")
    now = mobile_module.time.time()
    token = _arm(bridge, "rollback-arm", now)

    bridge._handle(
        _DEST,
        f"ECO ON {token} {_PIN}",
        message_id=_message_id("rollback-eco"),
        sent_at=now,
    )

    receipts = [
        event
        for event in bus.recent(50)
        if event.details.get("event_type") == "mobile_change_receipt"
    ]
    assert receipts
    assert receipts[-1].details["outcome"] == "rejected"
    assert bus.verify(receipts[-1])
    assert "no cadence change" in sent[-1]
    assert failing._throttle == 2.0
    assert governor._level == 4.0


def test_bus_authority_loss_after_applied_change_is_reported_without_signed_claim(
    monkeypatch, tmp_path,
) -> None:
    bridge, bus, target, governor, sent = _bridge(monkeypatch, tmp_path)
    original_emit = bridge._emit_change_receipt

    def lose_authority(*args, **kwargs):
        # Inert fault injection: authority disappears after the safe cadence
        # transaction but before its candidate receipt is published.
        bus._authority = None
        return original_emit(*args, **kwargs)

    monkeypatch.setattr(bridge, "_emit_change_receipt", lose_authority)
    now = mobile_module.time.time()
    token = _arm(bridge, "authority-arm", now)

    bridge._handle(
        _DEST,
        f"ECO ON {token} {_PIN}",
        message_id=_message_id("authority-eco"),
        sent_at=now,
    )

    receipts = [
        event
        for event in bus.recent(50)
        if event.details.get("event_type") == "mobile_change_receipt"
    ]
    assert receipts == []
    assert bus.integrity_enabled is False
    assert target._throttle == 6.0
    assert governor._level == 6.0
    assert "signed receipt unavailable" in sent[-1]
    assert bridge.health == 0


class _LateCombat:
    status = "running"

    def __init__(self) -> None:
        self.rows: list[dict] = []

    @staticmethod
    def policy():
        return SimpleNamespace(isolate_host=True, mode="maximum", process_action="terminate")

    def list_actions(self, limit: int = 250) -> list[dict]:
        return self.rows[-limit:]


class _FastClock:
    def __init__(self) -> None:
        self.wall = 1_800_000_000.0
        self.mono = 100.0

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def sleep(self, seconds: float) -> None:
        self.mono += float(seconds)


def test_combat_timeout_is_pending_and_late_completion_is_reconciled(
    monkeypatch, tmp_path,
) -> None:
    combat = _LateCombat()
    bridge, bus, _target, _governor, sent = _bridge(
        monkeypatch, tmp_path, modules={"Adversary Combat": combat}
    )
    clock = _FastClock()
    monkeypatch.setattr(mobile_module, "time", clock)
    token = _arm(bridge, "late-arm", clock.time())

    bridge._handle(
        _DEST,
        f"LOCKDOWN {token} {_PIN}",
        message_id=_message_id("late-lockdown"),
        sent_at=clock.time(),
    )

    directive = next(
        event
        for event in bus.recent(100)
        if event.module == bridge.name and event.details.get("response_authorized") is True
    )
    receipt = next(
        event
        for event in reversed(bus.recent(100))
        if event.details.get("event_type") == "mobile_change_receipt"
    )
    assert receipt.details["outcome"] == "pending"
    assert bus.verify(receipt)
    assert "Do not assume action or no action" in sent[-1]
    request_id = str(directive.details["queue_request_id"])
    assert directive.details["mobile_request_id"] == request_id
    assert request_id in bridge._pending_combat_requests

    # The accepted directive has no cancellation identity or tombstone. Model
    # its worker completing just after the fixed polling deadline.
    combat.rows.append(
        {
            "action_id": "late-isolation",
            "action": "isolate_host",
            "trigger_module": bridge.name,
            "trigger_ts": directive.ts,
            "status": "applied",
            "integrity_status": "verified",
            "details": {
                "postcondition_verified": True,
                "queue_request_id": request_id,
            },
        }
    )
    assert bridge._receipt_ids(
        combat,
        trigger_ts=directive.ts,
        expected_action="isolate_host",
        request_id=request_id,
    ) == {"late-isolation"}
    bridge._reconcile_pending_combat()
    assert request_id not in bridge._pending_combat_requests
    assert any("later completed" in message for message in sent)
    final = next(
        event
        for event in bus.recent(100)
        if event.details.get("event_type") == "mobile_change_receipt"
        and event.details.get("mobile_request_id") == request_id
        and event.details.get("outcome") == "applied"
    )
    assert bus.verify(final)
