from __future__ import annotations

import json
import os
import time
from types import SimpleNamespace

import angerona.modules.adversary_combat as combat_module
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.mobile_bridge import MobileResponseBridge


def _combat(tmp_path, **overrides) -> AdversaryCombat:
    values = {
        "data_dir": tmp_path,
        "adversary_combat_enabled": True,
        "adversary_combat_mode": "maximum",
        "adversary_combat_min_severity": "LOW",
        "adversary_combat_block_network": True,
        "adversary_combat_quarantine_files": True,
        "adversary_combat_process_action": "terminate",
        "adversary_combat_isolate_host": True,
        "adversary_combat_activate_honeypots": True,
        "adversary_combat_isolation_threshold": 3,
    }
    values.update(overrides)
    manager = SimpleNamespace(config=SimpleNamespace(**values), modules={})
    module = AdversaryCombat(tmp_path)
    module.bind(EventBus())
    module.bind_manager(manager)
    manager.modules[module.name] = module
    return module


def _event(module: str, severity: Severity, **details) -> Event:
    details.setdefault("response_authorized", True)
    actions: list[str] = []
    targets: dict[str, object] = {}
    if details.get("path"):
        actions.append("quarantine_file")
        targets["path"] = details["path"]
    remote_ip = details.get("remote_ip")
    if remote_ip:
        actions.append("block_remote_ip")
        targets["remote_ips"] = [remote_ip]
    if isinstance(details.get("pid"), int) and details.get("process_create_time"):
        actions.extend(("isolate_program", "suspend_process", "terminate_process"))
        targets["pid"] = details["pid"]
        targets["process_create_time"] = details["process_create_time"]
    if details.get("active_attack"):
        actions.append("isolate_host")
        targets["host"] = "local"
    if not actions:
        actions.append("isolate_host")
        targets["host"] = "local"
    details.setdefault(
        "response_contract",
        {"version": 1, "actions": actions, "targets": targets},
    )
    return Event(module, "boundary test", severity, time.time(), details)


def test_remote_critical_is_rejected_before_every_combat_mutation(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_block_remote_ip",
        lambda *_args: calls.append("block") or None,
    )
    monkeypatch.setattr(
        module,
        "_act_on_process",
        lambda *_args: calls.append("process") or None,
    )
    monkeypatch.setattr(
        module,
        "_quarantine_file",
        lambda *_args: calls.append("quarantine") or None,
    )
    monkeypatch.setattr(
        module,
        "_isolate_host",
        lambda *_args: calls.append("isolate") or None,
    )
    monkeypatch.setattr(
        module,
        "_ensure_honeypots",
        lambda *_args, **_kwargs: calls.append("honeypot") or None,
    )

    module._handle(
        _event(
            "Remote Bridge",
            Severity.CRITICAL,
            response_authority="remote-observe-only",
            node_origin="peer-a",
            active_attack=True,
            remote_ip="203.0.113.7",
            pid=4242,
            path=str(tmp_path / "target.bin"),
        )
    )

    assert calls == []
    assert list(module._active_events) == []
    assert module.list_actions() == []


def test_spoof_burst_and_expiry_are_non_response_health_audits(tmp_path, monkeypatch):
    bus = EventBus()
    emitted: list[Event] = []
    bus.subscribe(emitted.append)
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    monkeypatch.setattr(bridge, "_send", lambda _message: None)

    for body in ("STATUS", "KILL 1111 2222", "LOCKDOWN 0000"):
        bridge._spoof(body, "unauthorized sender")
    bridge.pending_alerts["9876"] = {
        "pid": 4242,
        "timestamp": time.time() - 601,
        "module": "EDR",
    }
    bridge._sweep_tokens()

    assert len(emitted) == 4
    assert all(event.details["response_authorized"] is False for event in emitted)
    assert all(event.details["disposition"] == "health" for event in emitted)

    combat = _combat(tmp_path)
    isolated: list[bool] = []
    monkeypatch.setattr(
        combat,
        "_isolate_host",
        lambda *_args: isolated.append(True) or None,
    )
    for event in emitted:
        combat._handle(event)

    assert isolated == []
    assert list(combat._active_events) == []


def test_exact_mobile_directive_cannot_cascade_into_generic_host_isolation(
    tmp_path, monkeypatch
):
    bus = EventBus()
    emitted: list[Event] = []
    bus.subscribe(emitted.append)
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge._emit_mitigation(
        "KILL",
        4242,
        "operator KILL token 1234",
        directive_authorized=True,
    )
    assert emitted[-1].details["directive_authorized"] is True
    assert emitted[-1].details["response_scope"] == "mobile-directive-only"
    assert emitted[-1].details["response_authorized"] is False

    combat = _combat(tmp_path)
    isolated: list[bool] = []
    monkeypatch.setattr(
        combat,
        "_isolate_host",
        lambda *_args: isolated.append(True) or None,
    )
    combat._handle(emitted[-1])

    assert isolated == []
    assert list(combat._active_events) == []


class _FakeProcess:
    def __init__(self, *, name: str, exe: str, created: float):
        self._name = name
        self._exe = exe
        self._created = created
        self.killed = False

    def create_time(self):
        return self._created

    def name(self):
        return self._name

    def exe(self):
        return self._exe

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        return 0

    def is_running(self):
        return not self.killed


def test_protected_process_is_never_blocked_or_terminated(tmp_path, monkeypatch):
    process = _FakeProcess(name="lsass.exe", exe=str(tmp_path / "lsass.exe"), created=9.0)
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: process),
    )
    module = _combat(tmp_path)
    firewall_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        module,
        "_run_firewall",
        lambda args: firewall_calls.append(tuple(args)) or True,
    )

    result = module._act_on_process(500, module.policy(), _event("EDR", Severity.HIGH), "c")

    assert result is None
    assert process.killed is False
    assert firewall_calls == []


def test_system_file_is_never_quarantined(tmp_path, monkeypatch):
    windows = tmp_path / "Windows"
    artifact = windows / "System32" / "critical.dll"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"system")
    monkeypatch.setenv("SystemRoot", str(windows))
    module = _combat(tmp_path)

    module._handle(
        _event("EDR", Severity.HIGH, path=str(artifact), active_attack=True)
    )

    assert artifact.read_bytes() == b"system"
    assert not any(
        item.get("action") == "quarantine_file" for item in module.list_actions()
    )


def test_pid_reuse_mismatch_prevents_process_and_firewall_action(tmp_path, monkeypatch):
    process = _FakeProcess(name="malware.exe", exe=str(tmp_path / "malware.exe"), created=20.0)
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: process),
    )
    module = _combat(tmp_path)
    firewall_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        module,
        "_run_firewall",
        lambda args: firewall_calls.append(tuple(args)) or True,
    )
    event = _event("EDR", Severity.HIGH, process_create_time=10.0)

    result = module._act_on_process(500, module.policy(), event, "c")

    assert result is None
    assert process.killed is False
    assert firewall_calls == []


def test_invalid_supplied_process_identity_fails_closed(tmp_path, monkeypatch):
    process = _FakeProcess(name="malware.exe", exe=str(tmp_path / "malware.exe"), created=20.0)
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: process),
    )
    module = _combat(tmp_path)

    result = module._act_on_process(
        500,
        module.policy(),
        _event("EDR", Severity.HIGH, process_create_time="not-a-timestamp"),
        "c",
    )

    assert result is None
    assert process.killed is False


def test_program_firewall_rule_is_removed_if_pid_identity_changes_after_netsh(
    tmp_path, monkeypatch
):
    expected_exe = str(tmp_path / "malware.exe")
    reused = _FakeProcess(
        name="innocent.exe",
        exe=str(tmp_path / "innocent.exe"),
        created=21.0,
    )
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: reused),
    )
    module = _combat(tmp_path)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "_run_firewall",
        lambda args: calls.append(list(args)) or True,
    )

    result = module._block_program(
        expected_exe,
        500,
        20.0,
        _event("EDR", Severity.CRITICAL),
        "combat-aaaaaaaaaaaa",
    )

    assert result is None
    assert calls[0][:2] == ["add", "rule"]
    assert calls[1][:2] == ["delete", "rule"]
    assert os.path.normcase(os.path.abspath(expected_exe)) not in module._blocked_programs


def test_same_explicit_cause_counts_once_toward_burst_isolation(tmp_path, monkeypatch):
    module = _combat(
        tmp_path,
        adversary_combat_block_network=False,
        adversary_combat_quarantine_files=False,
        adversary_combat_activate_honeypots=False,
    )
    isolated: list[str] = []
    monkeypatch.setattr(
        module,
        "_isolate_host",
        lambda event, _combat_id: isolated.append(event.details["incident_id"]) or None,
    )
    for _ in range(3):
        module._handle(
            _event("EDR", Severity.HIGH, active_attack=True, incident_id="same")
        )

    assert len(module._active_events) == 1
    assert isolated == []

    for incident in ("second", "third"):
        module._handle(
            _event("EDR", Severity.HIGH, active_attack=True, incident_id=incident)
        )

    assert len(module._active_events) == 3
    assert isolated == ["third"]


def test_startup_refuses_unsigned_legacy_firewall_receipts(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    records = [
        {
            "action_id": "act-ip",
            "combat_id": "c",
            "action": "block_remote_ip",
            "applied_at": 1.0,
            "reversible": True,
            "target": "203.0.113.9",
            "details": {
                "remote_ip": "203.0.113.9",
                "rules": ["Angerona-Combat-IP-a-in", "Angerona-Combat-IP-a-out"],
            },
            "trigger_module": "EDR",
            "trigger_ts": 1.0,
            "status": "applied",
        },
        {
            "action_id": "act-host",
            "combat_id": "c",
            "action": "isolate_host",
            "applied_at": 1.0,
            "reversible": True,
            "target": "all",
            "details": {
                "rules": [
                    "Angerona-Combat-Host-a-in",
                    "Angerona-Combat-Host-a-out",
                ],
            },
            "trigger_module": "EDR",
            "trigger_ts": 1.0,
            "status": "applied",
        },
    ]
    module.receipt_path.parent.mkdir(parents=True)
    module.receipt_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda _rule: True)

    module._reconcile_state()

    assert module._host_isolated is False
    assert module._blocked_ips == set()
    assert all(
        item["integrity_status"] == "legacy-untrusted"
        for item in module.list_actions()
    )


def test_startup_does_not_trust_unmanaged_or_missing_firewall_rules(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    record = {
        "action_id": "act-host",
        "combat_id": "c",
        "action": "isolate_host",
        "applied_at": 1.0,
        "reversible": True,
        "target": "all",
        "details": {"rules": ["Allow-All-Corporate"]},
        "trigger_module": "EDR",
        "trigger_ts": 1.0,
        "status": "applied",
    }
    module.receipt_path.parent.mkdir(parents=True)
    module.receipt_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    queried: list[str] = []
    monkeypatch.setattr(
        module,
        "_firewall_rule_exists",
        lambda rule: queried.append(rule) or True,
    )

    module._reconcile_state()

    assert module._host_isolated is False
    assert queried == []


def test_firewall_exit_zero_is_rejected_when_rule_postcondition_is_absent(
    tmp_path, monkeypatch
):
    from angerona.core import win

    module = _combat(tmp_path)
    monkeypatch.setattr(combat_module.os, "name", "nt")
    monkeypatch.setattr(
        win,
        "run_hidden",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda _rule: False)

    assert module._run_firewall(
        [
            "add",
            "rule",
            "name=Angerona-Combat-IP-test-out",
            "dir=out",
            "action=block",
            "remoteip=203.0.113.20",
        ]
    ) is False
