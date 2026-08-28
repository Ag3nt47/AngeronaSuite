from __future__ import annotations

import csv
import hashlib
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMenuBar, QPushButton

from angerona.core.host_adaptation import (
    AdaptationError,
    CircuitBreakerOpen,
    HostAdaptationService,
    IntegrityError,
)
from angerona.gui.adaptation_workbench import AdaptationWorkbench
from angerona.gui.header_controls import navigation_icon


def _snapshot(service: HostAdaptationService) -> dict:
    return {
        "schema": "angerona.host-snapshot/v1",
        "captured_at": "2026-08-24T18:00:00+00:00",
        "host_id": service.host_id(),
        "hardware": {
            "system": "Windows", "release": "11", "machine": "AMD64",
            "logical_cpus": 8, "physical_cpus": 4, "memory_bytes": 16_000,
            "disks": [{"mount": "C:\\", "filesystem": "NTFS", "total_bytes": 100_000}],
        },
        "services": [{
            "name": "Demo", "display_name": "Demo", "status": "running",
            "start_type": "automatic",
        }],
        "ports": [{
            "key": "tcp|loopback|9000|demo.exe", "protocol": "tcp",
            "scope": "loopback", "port": 9000, "process": "demo.exe",
            "pid_observed": 100,
        }],
        "network": {
            "captured_at": "2026-08-24T18:00:00+00:00", "ssid": "Lab",
            "network_category": "Private", "vpn_active": False,
            "remote_session": False,
            "interfaces": [{"name": "Ethernet", "type": "Physical", "up": True}],
        },
        "firewall": {
            "supported": True, "provider": "Windows Firewall", "reason": "",
            "profiles": [
                {"name": "Domain", "enabled": True, "inbound": "Block", "outbound": "Allow"},
                {"name": "Private", "enabled": True, "inbound": "Block", "outbound": "Allow"},
                {"name": "Public", "enabled": True, "inbound": "Block", "outbound": "Allow"},
            ],
        },
        "collector_status": {
            name: {
                "available": True,
                "complete": True,
                "truncated": False,
                "error": "",
            }
            for name in ("services", "ports", "network", "firewall")
        },
    }


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _enroll_recovery_baseline(
    service: HostAdaptationService, snapshot: dict
) -> None:
    source = service.snapshots_dir / "test-enrolled-firewall.wfw"
    source.write_bytes(b"complete test firewall policy export")
    service._ensure_security_baseline(
        source_snapshot_id="snap-test-enrollment",
        current=snapshot,
        firewall_file=source,
    )


def test_baseline_drift_exact_exceptions_feedback_and_exports(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    baseline = _snapshot(service)
    service.save_baseline(baseline)

    current = json.loads(json.dumps(baseline))
    # PID changes are useful context but do not create exposure drift.
    current["ports"][0]["pid_observed"] = 999
    assert service.compare(baseline, current) == []

    current["ports"].append({
        "key": "tcp|wildcard|5432|postgres.exe", "protocol": "tcp",
        "scope": "wildcard", "port": 5432, "process": "postgres.exe",
        "pid_observed": 200,
    })
    findings = service.compare(baseline, current)
    assert len(findings) == 1
    assert findings[0]["category"] == "ports"
    assert findings[0]["score"] == 5.0

    service.add_exception(findings[0], "approved local developer database", tune_feedback=True)
    excluded = service.compare(baseline, current)[0]
    assert excluded["excluded"] is True
    assert excluded["score"] == 0.0
    # One dismissal cannot globally attenuate a category. Three distinct,
    # operator-reviewed examples are required and tuning remains bounded.
    assert "ports" not in service.state()["adaptive_weights"]
    for index in (1, 2):
        reviewed = dict(findings[0])
        reviewed["key"] = f"tcp|wildcard|{6000 + index}|demo-{index}.exe"
        reviewed["current"] = {"port": 6000 + index, "scope": "wildcard"}
        reviewed["id"] = f"review-{index}"
        service.add_exception(reviewed, f"reviewed false positive {index}", tune_feedback=True)
    assert service.state()["adaptive_weights"]["ports"] == 0.95
    with pytest.raises(ValueError, match="already been excluded or reviewed"):
        service.add_exception(findings[0], "replay", tune_feedback=True)

    variant = json.loads(json.dumps(current))
    variant["ports"][-1]["scope"] = "loopback"
    changed_variant = service.compare(baseline, variant)[0]
    assert changed_variant["key"] == findings[0]["key"]
    assert changed_variant["excluded"] is False

    review_to_remove = next(
        item for item in service.list_exceptions() if item["key"].endswith("demo-1.exe")
    )
    assert service.remove_exception(review_to_remove["id"])
    assert "ports" not in service.state()["adaptive_weights"]

    report = {
        "generated_at": "now", "risk_score": 0,
        "findings": service.compare(baseline, current),
    }
    report["findings"][0]["key"] = "=WEBSERVICE(\"https://example.invalid\")"
    json_path = service.export_report(report, tmp_path / "audit", "json")
    csv_path = service.export_report(report, tmp_path / "audit-table", "csv")
    assert json.loads(json_path.read_text(encoding="utf-8"))["risk_score"] == 0
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["category"] == "ports"
    assert rows[0]["excluded"] == "True"
    assert rows[0]["key"].startswith("'=")


def test_integrity_checked_state_fails_closed(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    service.set_automation(True, False)
    payload = json.loads(service.state_path.read_text(encoding="utf-8"))
    payload["body"]["auto_apply"] = True
    service.state_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(IntegrityError):
        service.state()


def test_adaptation_store_rejects_recomputed_unkeyed_digest(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    service.set_automation(True, False)
    payload = json.loads(service.state_path.read_text(encoding="utf-8"))
    payload["body"]["auto_apply"] = True
    unsigned = {
        key: value
        for key, value in payload.items()
        if key not in {"sha256", "hmac_sha256"}
    }
    payload["sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    service.state_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(IntegrityError):
        service.state()


def test_security_baseline_is_immutable_scoped_and_restorable(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr("angerona.core.host_adaptation.platform.system", lambda: "Windows")
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    source = service.snapshots_dir / "source-firewall.wfw"
    source.write_bytes(b"exact complete firewall policy export")
    manifest = service._ensure_security_baseline(
        source_snapshot_id="snap-test-source",
        current=snapshot,
        firewall_file=source,
    )
    status = service.security_baseline_status()
    assert status["available"] is True
    assert status["restorable_components"] == ["windows-firewall-policy"]
    assert "services" in status["observational_only"]
    assert manifest["replacement_allowed"] is False

    second = service.snapshots_dir / "another-firewall.wfw"
    second.write_bytes(b"different policy")
    assert service._ensure_security_baseline(
        source_snapshot_id="snap-later",
        current=snapshot,
        firewall_file=second,
    )["firewall_sha256"] == manifest["firewall_sha256"]

    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    restored_paths = []
    receipt = service.restore_security_baseline(
        approved=True,
        snapshot_provider=lambda *_: "snap-before-restore",
        executor=lambda path: restored_paths.append(path) or True,
        postcondition_provider=lambda: snapshot["firewall"],
    )
    assert restored_paths == [service.security_baseline_firewall_path]
    assert receipt["pre_restore_snapshot_id"] == "snap-before-restore"


def test_incomplete_capture_cannot_become_golden_baseline(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    snapshot["collector_status"]["ports"]["complete"] = False
    with pytest.raises(AdaptationError, match="incomplete host collectors: ports"):
        service.save_baseline(snapshot)


def test_first_apply_requires_explicit_recovery_baseline_enrollment(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    plan = service.build_plan("balanced", snapshot)
    executed: list[str] = []

    with pytest.raises(AdaptationError, match="explicitly enrolled"):
        service.apply_plan(
            plan,
            approved=True,
            approved_plan_id=plan.plan_id,
            snapshot_provider=lambda *_: "snap-should-not-exist",
            executor=lambda _plan: executed.append("mutated") or ("done",),
        )

    assert executed == []
    assert not service.security_baseline_manifest_path.exists()
    assert not service.security_baseline_firewall_path.exists()
    assert service.transactions() == []


def test_preview_sandbox_apply_binding_and_circuit_breaker(tmp_path: Path, monkeypatch) -> None:
    now = [1_800_000_000.0]
    service = HostAdaptationService(tmp_path, clock=lambda: now[0])
    snapshot = _snapshot(service)
    _enroll_recovery_baseline(service, snapshot)
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)

    plan = service.build_plan("lockdown", snapshot)
    commands = service.command_stack(plan)
    assert plan.drastic is True
    assert plan.plan_id.startswith("adapt-")
    assert "DefaultOutboundAction Block" in commands[0]

    simulation = service.sandbox("lockdown", snapshot)
    assert simulation["host_mutated"] is False
    assert {item["profile"] for item in simulation["changes"]} == {
        "Domain", "Private", "Public",
    }
    exact_simulation = service.simulate_plan(plan, snapshot)
    assert exact_simulation["plan_id"] == plan.plan_id

    with pytest.raises(PermissionError):
        service.apply_plan(
            plan, approved=True, approved_plan_id="another-plan",
            snapshot_provider=lambda *_: "snap-test",
            executor=lambda _: ("done",),
        )

    receipt = service.apply_plan(
        plan, approved=True, approved_plan_id=plan.plan_id,
        snapshot_provider=lambda *_: "snap-test",
        executor=lambda _: commands,
        postcondition_provider=lambda: {
            **snapshot["firewall"],
            "profiles": [
                {**row, "enabled": True, "inbound": "Block", "outbound": "Block"}
                for row in snapshot["firewall"]["profiles"]
            ],
        },
    )
    assert receipt.snapshot_id == "snap-test"
    assert receipt.profile_id == "lockdown"
    committed = service.transactions()[-1]
    assert committed["status"] == "COMMITTED"
    assert committed["receipt_digest"] == receipt.receipt_digest

    now[0] += 30
    fresh = service.build_plan("balanced", snapshot)
    with pytest.raises(CircuitBreakerOpen, match="cooling down"):
        service.apply_plan(
            fresh, approved=True, approved_plan_id=fresh.plan_id,
            snapshot_provider=lambda *_: "snap-next",
            executor=lambda _: service.command_stack(fresh),
        )


def test_context_priority_proposal_mode_and_breaker_reset(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    public = service.add_trigger("public_network", "", "public")
    ssid = service.add_trigger("ssid", "Coffee Shop", "lockdown")
    service.add_trigger("vpn_active", "", "balanced")

    evaluation = service.evaluate_context({
        "ssid": "Coffee Shop", "network_category": "Public", "vpn_active": True,
    })
    assert evaluation["matches"][0]["id"] == ssid["id"]
    assert public["id"] in {row["id"] for row in evaluation["matches"]}

    service.set_automation(True, False)
    # Keep the collector deterministic for the automatic proposal cycle.
    service.capture_context = lambda: {
        "ssid": "Coffee Shop", "network_category": "Public", "vpn_active": True,
    }
    cycle = service.run_automatic_cycle()
    assert cycle["status"] == "proposed"
    assert cycle["rule"]["profile_id"] == "lockdown"
    assert service.run_automatic_cycle()["status"] == "stable"

    state = service.state()
    state["breaker"]["locked"] = True
    state["breaker"]["reason"] = "test"
    service._save_state(state)
    service.reset_breaker()
    assert service.breaker_status()["locked"] is False


def test_context_transition_can_propose_again_after_no_match(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    service.add_trigger("ssid", "Coffee Shop", "public")
    service.set_automation(True, False)
    contexts = iter([
        {"ssid": "Coffee Shop", "network_category": "Public", "vpn_active": False},
        {"ssid": "Home", "network_category": "Private", "vpn_active": False},
        {"ssid": "Coffee Shop", "network_category": "Public", "vpn_active": False},
    ])
    service.capture_context = lambda: next(contexts)

    assert service.run_automatic_cycle()["status"] == "proposed"
    assert service.run_automatic_cycle()["status"] == "no-match"
    assert service.run_automatic_cycle()["status"] == "proposed"


def test_unattended_apply_request_remains_proposal_only(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    service.add_trigger("ssid", "Coffee Shop", "balanced")
    service.set_automation(True, True)
    monkeypatch.setattr(service, "capture_context", lambda: {
        "ssid": "Coffee Shop", "network_category": "Public", "vpn_active": False,
    })
    monkeypatch.setattr(
        service, "capture_snapshot",
        lambda: pytest.fail("proposal-only automation captured a mutation snapshot"),
    )
    result = service.run_automatic_cycle()
    assert result["status"] == "proposed"
    assert service.state()["auto_apply"] is False
    assert service.state()["active_profile_id"] == ""


def test_context_marks_any_active_public_network_as_public(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    monkeypatch.setattr("angerona.core.host_adaptation.platform.system", lambda: "Windows")

    def fake_read(args, timeout=8.0):
        del timeout
        if Path(args[0]).name.casefold() == "netsh.exe":
            return "    SSID : Lab Wi-Fi\n"
        return "Private\nPublic\n"

    monkeypatch.setattr(service, "_netsh_path", lambda: "C:/Windows/System32/netsh.exe")
    monkeypatch.setattr(
        service, "_powershell_path",
        lambda: "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    )
    monkeypatch.setattr(service, "_run_readonly", fake_read)
    context = service.capture_context()
    assert context["ssid"] == "Lab Wi-Fi"
    assert context["network_category"] == "Public"


def test_workbench_has_complete_navigation_and_nonwriting_sandbox(tmp_path: Path) -> None:
    _app()
    service = HostAdaptationService(tmp_path)
    dialog = AdaptationWorkbench(service)
    assert dialog.windowTitle() == "Adaptation — Adapt to Host"
    assert [dialog.tabs.tabText(index) for index in range(dialog.tabs.count())] == [
        "Overview", "Audit + Drift", "Exceptions + Feedback", "Adapt Host",
        "Sandbox", "Automation", "Activity",
    ]
    menus = [action.text() for action in dialog.findChild(QMenuBar).actions()]
    assert menus == ["File", "Audit", "Adapt", "Safety", "Help"]
    buttons = {button.text() for button in dialog.findChildren(QPushButton)}
    assert {
        "AUTO ADAPT…", "Choose an adaptation profile…",
        "Run deep audit", "Save as golden baseline…", "1. Preview adaptation",
        "3. ADAPT HOST with this preview…", "Run no-write simulation",
        "Evaluate current context now", "Reset circuit breaker…",
        "Roll back selected snapshot…", "Run safe automatic checkup",
        "Capture immutable host baseline…", "Restore host baseline…",
    }.issubset(buttons)
    dialog.tabs.setCurrentIndex(0)
    dialog._show_adapt_host()
    assert dialog.tabs.currentIndex() == dialog.adapt_tab_index
    assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "Adapt Host"
    assert not navigation_icon("adaptation").isNull()
    dialog.close()


def test_workbench_surfaces_incomplete_audit_collectors(tmp_path: Path) -> None:
    _app()
    dialog = AdaptationWorkbench(HostAdaptationService(tmp_path))
    dialog._display_audit({
        "baseline_exists": True,
        "baseline_captured_at": "2026-08-24T18:00:00+00:00",
        "findings": [],
        "active_findings": 0,
        "excluded_findings": 0,
        "risk_score": 0,
        "incomplete_collectors": ["services", "ports"],
        "skipped_incomplete_collectors": ["services", "ports"],
    })
    assert "PARTIAL AUDIT" in dialog.audit_summary.text()
    assert "services, ports" in dialog.audit_summary.text()
    assert "unavailable · coverage incomplete (2)" in dialog.risk_status.text()
    dialog.close()


def test_dashboard_places_adaptation_before_other_left_header_actions() -> None:
    source = Path("src/angerona/gui/main_window.py").read_text(encoding="utf-8")
    adaptation = source.index("bl.addWidget(adaptation_btn)")
    self_test = source.index("bl.addWidget(test_btn)", adaptation)
    assert adaptation < self_test
    assert '"ADAPTATION"' in source
    assert "_open_adaptation" in source


def test_partial_port_collector_never_creates_mass_drift(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    connections = [
        SimpleNamespace(
            type=socket.SOCK_STREAM, family=socket.AF_INET,
            status="LISTEN", laddr=SimpleNamespace(ip="0.0.0.0", port=port), pid=0,
        )
        for port in (8000, 8001, 8002)
    ]
    monkeypatch.setattr("angerona.core.host_adaptation.MAX_PORTS", 2)
    monkeypatch.setattr(
        "angerona.core.host_adaptation.psutil.net_connections",
        lambda **_: connections,
    )
    rows, quality = service._collect_ports()
    assert len(rows) == 2
    assert quality["truncated"] is True
    assert quality["complete"] is False
    assert all("address_family" in row and "local_address_id" in row for row in rows)

    baseline = _snapshot(service)
    baseline["ports"] = rows
    baseline["collector_status"] = {
        name: {"complete": True} for name in ("services", "ports", "network", "firewall")
    }
    current = json.loads(json.dumps(baseline))
    current["ports"] = []
    current["collector_status"]["ports"] = quality
    assert not [row for row in service.compare(baseline, current) if row["category"] == "ports"]


def test_service_collector_distinguishes_builtin_privilege_levels(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)

    class Service:
        def __init__(self, name: str, username: str) -> None:
            self.name = name
            self.username = username

        def as_dict(self) -> dict:
            return {
                "name": self.name,
                "display_name": self.name,
                "status": "running",
                "start_type": "auto",
                "binpath": f'C:\\Windows\\System32\\{self.name}.exe',
                "username": self.username,
            }

    monkeypatch.setattr(
        "angerona.core.host_adaptation.psutil.win_service_iter",
        lambda: iter([
            Service("low", "NT AUTHORITY\\LocalService"),
            Service("high", "NT AUTHORITY\\SYSTEM"),
        ]),
        raising=False,
    )
    rows, quality = service._collect_services()
    by_name = {row["name"]: row for row in rows}
    assert quality["complete"] is True
    assert by_name["low"]["account_id"] == "local-service"
    assert by_name["high"]["account_id"] == "local-system"
    assert by_name["low"] != by_name["high"]


def test_firewall_collector_parses_explicit_values_and_rejects_numeric_enums(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    monkeypatch.setattr("angerona.core.host_adaptation.platform.system", lambda: "Windows")
    monkeypatch.setattr(service, "_powershell_path", lambda: "trusted-powershell.exe")
    observed_scripts = []

    def payload(enabled="True", inbound="Block", outbound="Allow"):
        return json.dumps({
            "Profiles": [{
                "Name": name, "Enabled": enabled,
                "DefaultInboundAction": inbound,
                "DefaultOutboundAction": outbound,
                "PolicyStore": "ActiveStore", "PolicyStoreSourceType": "Local",
            } for name in ("Domain", "Private", "Public")],
            "Rules": [{
                "Name": "allow-demo", "DisplayName": "Allow demo",
                "Enabled": "True", "Direction": "Inbound", "Action": "Allow",
                "Profile": "Public", "PolicyStoreSourceType": "Local",
                "Group": "Demo", "EdgeTraversalPolicy": "Block",
                "LooseSourceMapping": "False", "LocalOnlyMapping": "False",
                "PolicyStoreSource": "PersistentStore",
                "ApplicationFilter": {"Program": "C:/demo.exe", "Package": "Any"},
                "AddressFilter": {"LocalAddress": "Any", "RemoteAddress": "10.0.0.0/8"},
                "PortFilter": {
                    "Protocol": "TCP", "LocalPort": "443", "RemotePort": "Any",
                    "IcmpType": "Any", "DynamicTarget": "Any",
                },
                "InterfaceFilter": {"InterfaceAlias": "Any"},
                "InterfaceTypeFilter": {"InterfaceType": "Any"},
                "ServiceFilter": {"Service": "Any"},
                "SecurityFilter": {
                    "LocalUser": "Any", "RemoteUser": "Any", "RemoteMachine": "Any",
                    "Authentication": "NotRequired", "Encryption": "NotRequired",
                    "OverrideBlockRules": "False",
                },
            }],
        })

    def fake_read(args, timeout=8.0):
        del timeout
        observed_scripts.append(args[-1])
        return payload()

    monkeypatch.setattr(service, "_run_readonly", fake_read)
    firewall = service._firewall()
    assert firewall["complete"] is True
    assert firewall["profiles"][0]["enabled"] is True
    assert firewall["rules"][0]["action"] == "Allow"
    assert firewall["rules"][0]["application"]["program"] == "C:/demo.exe"
    assert firewall["rules"][0]["address"]["remote"] == "10.0.0.0/8"
    assert firewall["rules"][0]["port"]["local"] == "443"
    assert "$ErrorActionPreference='Stop'" in observed_scripts[0]
    assert "Get-NetFirewallProfile -PolicyStore ActiveStore" in observed_scripts[0]

    monkeypatch.setattr(service, "_run_readonly", lambda *_args, **_kwargs: payload("2", "0", "0"))
    incomplete = service._firewall()
    assert incomplete["complete"] is False
    assert incomplete["profiles"][0]["enabled"] is None


def test_restore_verification_binds_full_firewall_rule_scope(tmp_path: Path) -> None:
    service = HostAdaptationService(tmp_path)
    expected = _snapshot(service)["firewall"]
    expected["complete"] = True
    expected["rules"] = [{
        "name": "allow-demo", "enabled": True, "direction": "Inbound",
        "action": "Allow", "profile": "Public",
        "application": {"program": "C:/demo.exe", "package": "Any"},
        "address": {"local": "Any", "remote": "10.0.0.0/8"},
        "port": {"protocol": "TCP", "local": "443", "remote": "Any"},
        "interface": {"alias": "Any"}, "interface_type": {"type": "Any"},
        "service": {"name": "Any"},
        "security": {"authentication": "NotRequired", "encryption": "NotRequired"},
    }]
    widened = json.loads(json.dumps(expected))
    widened["rules"][0]["application"]["program"] = "Any"
    widened["rules"][0]["address"]["remote"] = "Any"
    widened["rules"][0]["port"]["local"] = "Any"

    with pytest.raises(AdaptationError, match="rollback postcondition mismatch"):
        service._verify_restore_postconditions(expected, widened)


def test_auto_apply_never_executes_lockdown_or_changes_remote_session(
    tmp_path: Path, monkeypatch,
) -> None:
    for remote_session, profile_id in ((False, "lockdown"), (True, "balanced")):
        service = HostAdaptationService(tmp_path / f"case-{remote_session}-{profile_id}")
        service.add_trigger("ssid", "Lab", profile_id)
        service.set_automation(True, True)
        state = service.state()
        state["auto_apply"] = True  # legacy state must still hit inner safety guards
        service._save_state(state)
        context = {
            "ssid": "Lab", "network_category": "Private", "vpn_active": False,
            "remote_session": remote_session,
        }
        snapshot = _snapshot(service)
        snapshot["network"].update(context)
        monkeypatch.setattr(service, "capture_context", lambda value=context: dict(value))
        monkeypatch.setattr(service, "capture_snapshot", lambda value=snapshot: dict(value))
        monkeypatch.setattr(
            service, "apply_plan",
            lambda *_args, **_kwargs: pytest.fail("unsafe automatic apply was reached"),
        )

        result = service.run_automatic_cycle()
        assert result["status"] in {"manual-review", "context-changed", "proposed"}


def test_apply_rolls_back_when_fresh_firewall_postcondition_mismatches(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    _enroll_recovery_baseline(service, snapshot)
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    plan = service.build_plan("lockdown", snapshot)
    monkeypatch.setattr(service, "_capture_rollback_snapshot", lambda *_: "snap-real")
    monkeypatch.setattr(service, "_execute_actions", lambda _: service.command_stack(plan))
    monkeypatch.setattr(service, "_firewall", lambda: snapshot["firewall"])
    rollbacks = []
    monkeypatch.setattr(
        service, "rollback",
        lambda snapshot_id, **kwargs: rollbacks.append((snapshot_id, kwargs)) or True,
    )

    with pytest.raises(AdaptationError, match="postcondition mismatch"):
        service.apply_plan(plan, approved=True, approved_plan_id=plan.plan_id)
    assert rollbacks[0][0] == "snap-real"
    assert rollbacks[0][1]["authorization"] == "automatic-failure-recovery"
    script = service._action_script(plan.actions[0])
    assert "$ErrorActionPreference='Stop'" in script
    assert "-ErrorAction Stop" in script


def test_apply_and_rollback_failure_locks_breaker_and_records_needs_review(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    _enroll_recovery_baseline(service, snapshot)
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    plan = service.build_plan("lockdown", snapshot)
    monkeypatch.setattr(service, "_capture_rollback_snapshot", lambda *_: "snap-real")
    monkeypatch.setattr(service, "_execute_actions", lambda _: service.command_stack(plan))
    monkeypatch.setattr(service, "_firewall", lambda: snapshot["firewall"])
    monkeypatch.setattr(
        service,
        "rollback",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AdaptationError("injected rollback failure")
        ),
    )

    with pytest.raises(AdaptationError, match="locked for recovery review"):
        service.apply_plan(plan, approved=True, approved_plan_id=plan.plan_id)

    transaction = service.transactions()[-1]
    assert transaction["status"] == "NEEDS_REVIEW"
    assert "rollback failure" in transaction["rollback_error"]
    assert service.breaker_status()["locked"] is True
    with pytest.raises(CircuitBreakerOpen):
        service.apply_plan(plan, approved=True, approved_plan_id=plan.plan_id)


def test_startup_reconciles_interrupted_transaction_against_exact_firewall_state(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    snapshot["firewall"]["complete"] = True
    plan = service.build_plan("balanced", snapshot)
    transaction = service._begin_transaction(
        "apply",
        snapshot_id="snap-reconcile",
        authorization="test",
        before_firewall=snapshot["firewall"],
        plan=plan,
    )
    service._transition_transaction(transaction["transaction_id"], "MUTATING")
    monkeypatch.setattr(
        HostAdaptationService,
        "_firewall",
        lambda _self: snapshot["firewall"],
    )

    reopened = HostAdaptationService(tmp_path)

    assert reopened.transactions()[-1]["status"] == "ROLLED_BACK"
    assert reopened.breaker_status()["locked"] is False


def test_startup_locks_on_ambiguous_interrupted_transaction(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
    snapshot["firewall"]["complete"] = True
    plan = service.build_plan("balanced", snapshot)
    transaction = service._begin_transaction(
        "apply",
        snapshot_id="snap-ambiguous",
        authorization="test",
        before_firewall=snapshot["firewall"],
        plan=plan,
    )
    service._transition_transaction(transaction["transaction_id"], "MUTATING")
    ambiguous = json.loads(json.dumps(snapshot["firewall"]))
    ambiguous["profiles"][0]["outbound"] = "Block"
    monkeypatch.setattr(
        HostAdaptationService,
        "_firewall",
        lambda _self: ambiguous,
    )

    reopened = HostAdaptationService(tmp_path)

    assert reopened.transactions()[-1]["status"] == "NEEDS_REVIEW"
    assert reopened.breaker_status()["locked"] is True


def test_rollback_requires_fresh_canonical_firewall_postcondition(
    tmp_path: Path,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot_id = "snap-1800000000-regression"
    firewall_file = service._snapshot_path(snapshot_id, ".wfw")
    firewall_file.write_bytes(b"safe firewall export")
    expected = _snapshot(service)["firewall"]
    service._save_store(
        service._snapshot_path(snapshot_id, ".json"),
        "rollback-snapshot",
        {
            "snapshot_id": snapshot_id,
            "host_id": service.host_id(),
            "firewall_sha256": hashlib.sha256(firewall_file.read_bytes()).hexdigest(),
            "firewall": expected,
            "status": "ready",
        },
    )
    restored = json.loads(json.dumps(expected))
    restored["profiles"][0]["outbound"] = "Block"
    with pytest.raises(AdaptationError, match="rollback postcondition mismatch"):
        service.rollback(
            snapshot_id,
            approved=True,
            executor=lambda _path: True,
            postcondition_provider=lambda: restored,
        )
    assert service.list_snapshots()[0]["status"] == "ready"


def test_legacy_auto_apply_is_migrated_to_proposal_only(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    service.add_trigger("ssid", "Lab", "balanced")
    service.set_automation(True, True)
    state = service.state()
    state["auto_apply"] = True  # simulate legacy/tampered persisted pre-authorization
    service._save_state(state)
    monkeypatch.setattr(service, "capture_context", lambda: {
        "ssid": "Lab", "network_category": "Private", "vpn_active": False,
    })
    snapshot = _snapshot(service)

    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    monkeypatch.setattr(
        service, "apply_plan",
        lambda *_args, **_kwargs: pytest.fail("disabled automation reached apply"),
    )
    result = service.run_automatic_cycle()
    assert result["status"] == "proposed"
    state = service.state()
    assert state["automation_enabled"] is True
    assert state["auto_apply"] is False


def test_public_matching_prefers_strongest_rule_and_auto_never_relaxes(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    public = service.add_trigger("public_network", "", "lockdown")
    service.add_trigger("ssid", "Home", "balanced")
    evaluation = service.evaluate_context({
        "ssid": "Home", "network_category": "Public", "vpn_active": False,
    })
    assert evaluation["matches"][0]["id"] == public["id"]

    service = HostAdaptationService(tmp_path / "no-relax")
    service.add_trigger("ssid", "Lab", "balanced")
    service.set_automation(True, True)
    state = service.state()
    state["auto_apply"] = True  # exercise legacy fail-closed migration path
    service._save_state(state)
    monkeypatch.setattr(service, "capture_context", lambda: {
        "ssid": "Lab", "network_category": "Private", "vpn_active": False,
    })
    snapshot = _snapshot(service)
    for row in snapshot["firewall"]["profiles"]:
        row["outbound"] = "Block"
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    result = service.run_automatic_cycle()
    assert result["status"] == "proposed"


def test_remote_session_state_detects_shell_and_third_party_agents(monkeypatch) -> None:
    monkeypatch.setenv("SSH_CONNECTION", "198.51.100.8 1234 192.0.2.4 22")
    assert HostAdaptationService._remote_session_state() == (True, "")
    monkeypatch.delenv("SSH_CONNECTION")

    processes = [SimpleNamespace(info={"name": "AnyDesk.exe"})]
    monkeypatch.setattr(
        "angerona.core.host_adaptation.psutil.process_iter",
        lambda attrs: processes,
    )
    assert HostAdaptationService._remote_control_agent_active() == (True, "")
