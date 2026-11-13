"""Inert mobile authority ordering and explicit host enrollment regressions."""
from __future__ import annotations

import ast
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus
from angerona.core.module_base import Severity
from angerona.core import mobile_command_auth as auth_module
from angerona.core.mobile_command_auth import MobileCommandStatus
from angerona.modules import mobile_bridge as mobile_module
from angerona.modules.mobile_bridge import MobileResponseBridge, _AdminChallenge


def _ready(*, generation="a" * 64, scope="b" * 64):
    return MobileCommandStatus(ready=True, reason="ready", generation=generation, scope_digest=scope)


def test_bridge_health_never_reenters_phone_or_token_pipeline(monkeypatch):
    bridge = MobileResponseBridge()
    bridge._bus = object()
    health = Event(module="Driver coverage", severity=Severity.HIGH,
                   message="coverage held", details={"disposition": "health"})
    own = Event(module=bridge.name, severity=Severity.CRITICAL,
                message="authorization audit", details={})
    monkeypatch.setattr(bridge, "poll_bus_events", lambda **_: ([health, own], False))
    monkeypatch.setattr(bridge, "_gate_alert", lambda *_a, **_k: pytest.fail("health was regated"))
    monkeypatch.setattr(bridge, "_mobile_auth_status", lambda: pytest.fail("health read protected authority"))
    bridge._poll_alerts()
    assert bridge.pending_alerts == {}


def test_unauthorized_sender_storm_has_one_bounded_health_counter_per_window(monkeypatch):
    bridge = MobileResponseBridge()
    bridge._config = SimpleNamespace(mobile_dest_number="+13035550100")
    bus = EventBus()
    bus.arm(BusAuthority(b"mobile-flood-fixture-key-32-bytes!"))
    bridge.bind(bus)
    now = [1000.0]
    monkeypatch.setattr(mobile_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(bridge, "_send", lambda *_: pytest.fail("unauthorized sender caused phone I/O"))
    monkeypatch.setattr(bridge, "_command_authorization", lambda: pytest.fail("unauthorized sender read PIN"))
    for number in range(1000):
        bridge._handle("+13035550199", "LOCKDOWN unique-fixture-" + str(number))
    records = bus.recent(20)
    assert len(records) == 1
    assert records[0].details["disposition"] == "health"
    assert records[0].details["response_authorized"] is False
    assert bridge._auth_audit_count == 1000 and bridge.pending_alerts == {}
    now[0] += mobile_module._FLOOD_WINDOW + 1
    bridge._handle("+13035550199", "new-window")
    assert bus.recent(1)[0].details["previous_window_attempts"] == 1000
    assert len(bus.recent(20)) == 2


def test_exact_admin_nonce_is_gone_before_pin_verification(monkeypatch):
    bridge = MobileResponseBridge()
    status = _ready()
    token = "c" * 64
    bridge._admin_challenge = _AdminChallenge(
        token, "+13035550100", time.monotonic(), time.monotonic() + 60,
        "d" * 64, ("ECO_ON",), status.generation, status.scope_digest,
    )
    monkeypatch.setattr(bridge, "_mobile_auth_status", lambda: status)
    monkeypatch.setattr(bridge, "_consume_fresh_message", lambda **_: True)
    seen = []

    def reject_pin(_pin, **_kwargs):
        seen.append(bridge._admin_challenge)
        return False

    monkeypatch.setattr(bridge, "_pin_authorized", reject_pin)
    assert bridge._authorize_admin_change(
        "ECO_ON", token, "000000", sender="+13035550100", message_id="e" * 64,
        sent_at=time.time(), body="inert command",
    ) is None
    assert seen == [None] and bridge._admin_challenge is None


def test_alert_token_is_gone_before_pin_and_new_generation_cannot_use_old_token(monkeypatch):
    bridge = MobileResponseBridge()
    token = "c" * 64
    old = _ready()
    info = {"allowed_actions": ("KILL",), "operator_identity": "+13035550100",
            "expires_monotonic": time.monotonic() + 60,
            "authorization_generation": old.generation, "authorization_scope": old.scope_digest}
    bridge.pending_alerts[token] = dict(info)
    monkeypatch.setattr(bridge, "_mobile_auth_status", lambda: old)
    monkeypatch.setattr(bridge, "_consume_fresh_message", lambda **_: True)
    checks = []

    def reject_pin(_pin, **_kwargs):
        checks.append(token not in bridge.pending_alerts)
        return False

    monkeypatch.setattr(bridge, "_pin_authorized", reject_pin)
    kwargs = dict(sender="+13035550100", message_id="e" * 64, sent_at=time.time(), body="inert command")
    assert bridge._authorize_alert_change("KILL", token, "000000", **kwargs) is None
    assert checks == [True]
    bridge.pending_alerts[token] = dict(info)
    monkeypatch.setattr(bridge, "_mobile_auth_status", lambda: _ready(generation="f" * 64))
    monkeypatch.setattr(bridge, "_spoof", lambda *_: None)
    assert bridge._authorize_alert_change("KILL", token, "482137", **kwargs) is None
    assert token not in bridge.pending_alerts and checks == [True]


class _Field:
    def __init__(self, text=""):
        self.value = text
    def text(self):
        return self.value
    def setText(self, value):
        self.value = value
    def clear(self):
        self.value = ""


class _Messages:
    Yes, No = 1, 2
    answer = No
    warnings = []
    questions = []
    @classmethod
    def warning(cls, _parent, title, text):
        cls.warnings.append((title, text))
    @classmethod
    def question(cls, *_args):
        cls.questions.append(_args)
        return cls.answer


def _local_handler():
    path = Path(__file__).parents[1] / "src/angerona/gui/pages.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    settings = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SettingsDialog")
    method = next(node for node in settings.body if isinstance(node, ast.FunctionDef) and node.name == "_save_mobile_pin")
    namespace = {"re": re, "QMessageBox": _Messages}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(path), "exec"), namespace)
    return namespace["_save_mobile_pin"]


def _local_ui(tmp_path):
    config = SimpleNamespace(
        mobile_enabled=True, mobile_signal_cli="C:/Program Files/SignalCli/signal-cli.exe",
        mobile_signal_cli_sha256="a" * 64, mobile_signal_cli_publisher="CN=Fixture",
        mobile_host_number="+13035550101", mobile_dest_number="+13035550100", data_dir=tmp_path,
    )
    ui = SimpleNamespace(_cfg=config, _mob_pin=_Field("482137"), _mob_pin_confirm=_Field("482137"),
                         _mob_cli=_Field(config.mobile_signal_cli), _mob_sha256=_Field(config.mobile_signal_cli_sha256),
                         _mob_publisher=_Field(config.mobile_signal_cli_publisher), _mob_host=_Field(config.mobile_host_number),
                         _mob_dest=_Field(config.mobile_dest_number), _mob_auth_status=_Field(), parent=lambda: None)
    _Messages.answer, _Messages.warnings, _Messages.questions = _Messages.No, [], []
    return ui


@pytest.mark.parametrize("pin", ["1234", "１２３４５６", " 482137", "1" * 13])
def test_local_rearm_rejects_short_non_ascii_or_padded_pin_without_store_access(tmp_path, monkeypatch, pin):
    ui = _local_ui(tmp_path)
    ui._mob_pin.value = ui._mob_pin_confirm.value = pin
    monkeypatch.setattr(auth_module, "MobileCommandAuthorization", lambda *_a, **_k: pytest.fail("invalid PIN reached store"))
    _local_handler()(ui)
    assert _Messages.warnings and not _Messages.questions


def test_local_rearm_requires_saved_scope_and_explicit_confirmation(tmp_path, monkeypatch):
    ui = _local_ui(tmp_path)
    monkeypatch.setattr(auth_module, "MobileCommandAuthorization", lambda *_a, **_k: pytest.fail("unapproved rearm reached store"))
    ui._mob_dest.value = "+13035550199"
    _local_handler()(ui)
    assert _Messages.warnings and not _Messages.questions
    ui._mob_dest.value = ui._cfg.mobile_dest_number
    _Messages.warnings = []
    _local_handler()(ui)
    assert len(_Messages.questions) == 1 and ui._mob_pin.text() == "482137"


def test_local_rearm_does_not_clear_pin_fields_after_unverified_publication(tmp_path, monkeypatch):
    ui = _local_ui(tmp_path)
    _Messages.answer = _Messages.Yes
    fake = SimpleNamespace(rearm_local=lambda *_: MobileCommandStatus(reason="publication-uncertain"))
    monkeypatch.setattr(auth_module, "MobileCommandAuthorization", lambda *_a, **_k: fake)
    _local_handler()(ui)
    assert ui._mob_pin.text() == ui._mob_pin_confirm.text() == "482137"
    assert ui._mob_auth_status.text() == "publication-uncertain"


def test_verified_local_rearm_refreshes_only_its_live_generation(tmp_path, monkeypatch):
    ui = _local_ui(tmp_path)
    _Messages.answer = _Messages.Yes
    refreshes, enrollments = [], []
    bridge = SimpleNamespace(_accept_local_rearm=refreshes.append)
    ui.parent = lambda: SimpleNamespace(manager=SimpleNamespace(modules={"Mobile Response Bridge": bridge}))

    def rearm(pin, confirmation):
        enrollments.append((pin, confirmation))
        return _ready(generation="f" * 64)

    monkeypatch.setattr(auth_module, "MobileCommandAuthorization", lambda *_a, **_k: SimpleNamespace(rearm_local=rearm))
    _local_handler()(ui)
    assert enrollments == [("482137", "482137")] and refreshes == ["f" * 64]
    assert ui._mob_pin.text() == ui._mob_pin_confirm.text() == ""


def test_process_binding_uses_only_the_inert_supplied_process_identity(tmp_path, monkeypatch):
    target = str(tmp_path / "inert-target.exe")
    process = SimpleNamespace(create_time=lambda: 152.25, exe=lambda: target, name=lambda: "inert-target")
    monkeypatch.setattr(mobile_module, "psutil", SimpleNamespace(Process=lambda _pid: process))
    bound = MobileResponseBridge._bind_process_target(41, {"process_create_time": 152.25, "exe": target})
    assert bound is not None and bound["pid"] == 41 and bound["process_create_time"] == 152.25


def test_eco_consumer_refuses_a_generation_changed_after_admission(monkeypatch):
    from angerona.core.module_base import BaseModule

    class Target(BaseModule):
        category = "Detection"
        adaptive_throttle_allowed = True
        adaptive_throttle_max = 8.0
        def run(self):
            return

    target = Target()
    bridge = MobileResponseBridge()
    bridge._manager = SimpleNamespace(modules={"fixture": target})
    receipts = []
    monkeypatch.setattr(bridge, "_authorization_current", lambda *_: False)
    monkeypatch.setattr(bridge, "_emit_change_receipt", lambda *_a, **kw: receipts.append(kw) or ("inert", True))
    monkeypatch.setattr(bridge, "_send", lambda *_: True)
    prior = target._throttle
    bridge._eco(True, "c" * 64, authorization=("a" * 64, "b" * 64))
    assert target._throttle == prior
    assert receipts and receipts[0]["outcome"] == "rejected"


def test_unicode_nonce_is_rejected_without_dropping_the_receive_batch(monkeypatch):
    bridge = MobileResponseBridge()
    old = _ready()
    bridge._admin_challenge = _AdminChallenge("c" * 64, "+13035550100", 0, time.monotonic() + 60,
                                              "d" * 64, ("ECO_ON",), old.generation, old.scope_digest)
    original = bridge._admin_challenge
    failures = []
    monkeypatch.setattr(bridge, "_record_auth_failure", lambda *_: failures.append(True))
    assert bridge._authorize_admin_change("ECO_ON", "💥", "482137", sender="+13035550100",
                                          message_id="e" * 64, sent_at=time.time(), body="inert") is None
    assert failures == [True] and bridge._admin_challenge is original


def test_local_rearm_refresh_clears_transient_lockout_and_preserves_pending_receipts(monkeypatch):
    bridge = MobileResponseBridge()
    old_helper = object()
    bridge._command_auth, bridge._command_auth_scope = old_helper, ("old",)
    bridge._auth_failures, bridge._auth_locked_until = [time.monotonic()], time.monotonic() + 900
    bridge.pending_alerts["old-token"] = {"authorization_generation": "c" * 64, "authorization_scope": "d" * 64}
    pending = object()
    bridge._pending_combat_requests["already-admitted"] = pending
    status = _ready(generation="f" * 64)
    new_helper = SimpleNamespace(status=lambda: status)

    def refresh():
        bridge._command_auth, bridge._command_auth_scope = new_helper, ("new",)
        return new_helper

    monkeypatch.setattr(bridge, "_command_authorization", refresh)
    monkeypatch.setattr(bridge, "emit", lambda *_a, **_k: None)
    bridge._accept_local_rearm(status.generation)
    assert bridge._command_auth is new_helper and bridge.pending_alerts == {}
    assert bridge._auth_failures == [] and bridge._lockout_remaining() == 0
    assert bridge._pending_combat_requests["already-admitted"] is pending


def test_refused_local_rearm_refresh_restores_both_cached_helper_and_scope(monkeypatch):
    bridge = MobileResponseBridge()
    old_helper, old_scope = object(), ("old",)
    bridge._command_auth, bridge._command_auth_scope = old_helper, old_scope

    def rejected():
        bridge._command_auth, bridge._command_auth_scope = object(), ("different",)
        return SimpleNamespace(status=lambda: MobileCommandStatus(reason="held"))

    monkeypatch.setattr(bridge, "_command_authorization", rejected)
    with pytest.raises(ValueError):
        bridge._accept_local_rearm("f" * 64)
    assert bridge._command_auth is old_helper and bridge._command_auth_scope is old_scope


@pytest.mark.parametrize("secret_name", auth_module.MOBILE_AUTH_SECRET_NAMES)
def test_signal_child_refuses_any_mobile_authority_in_its_environment(tmp_path, monkeypatch, secret_name):
    from angerona.core import privilege
    sealed = SimpleNamespace(identity=SimpleNamespace(path=str(tmp_path / "inert-signal-cli.exe")))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {secret_name: "inert-sensitive-value"})
    monkeypatch.setattr(mobile_module, "run_signal_cli", lambda *_a, **_k: pytest.fail("secret-bearing child was launched"))
    assert MobileResponseBridge._launch_cli(sealed, ["--version"], 1.0) == ("environment-invalid", -1, b"")


def test_signal_child_uses_only_the_inert_secret_free_environment(tmp_path, monkeypatch):
    from angerona.core import privilege
    sealed = SimpleNamespace(identity=SimpleNamespace(path=str(tmp_path / "inert-signal-cli.exe")))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {"FIXTURE": "safe"})
    launches = []
    monkeypatch.setattr(mobile_module, "run_signal_cli", lambda argv, env, **kw: launches.append((argv, env, kw)) or ("complete", 0, b"inert"))
    assert MobileResponseBridge._launch_cli(sealed, ["--version"], 1.0) == ("complete", 0, b"inert")
    assert launches[0][1] == {"FIXTURE": "safe"}
    assert launches[0][2]["max_output"] == mobile_module._MAX_CLI_OUTPUT


def test_review_only_poll_never_reads_protected_authority_or_probes_targets(monkeypatch):
    bridge = MobileResponseBridge()
    bridge._bus = SimpleNamespace(integrity_enabled=True, verify=lambda _event: True)
    review = Event(module="Inbox", severity=Severity.HIGH, message="advisory fixture",
                   details={"disposition": "observation", "response_authorized": False, "pid": 42})
    monkeypatch.setattr(bridge, "poll_bus_events", lambda **_: ([review], False))
    monkeypatch.setattr(bridge, "_mobile_auth_status", lambda: pytest.fail("review-only input read protected authority"))
    monkeypatch.setattr(bridge, "_bind_process_target", lambda *_: pytest.fail("review-only input probed a process"))
    lines = []
    monkeypatch.setattr(bridge, "_deliver_alert_line", lines.append)
    bridge._poll_alerts()
    assert len(lines) == 1 and "REVIEW ONLY" in lines[0]
    assert bridge.pending_alerts == {}
