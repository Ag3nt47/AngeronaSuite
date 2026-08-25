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
    }


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


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


def test_preview_sandbox_apply_binding_and_circuit_breaker(tmp_path: Path, monkeypatch) -> None:
    now = [1_800_000_000.0]
    service = HostAdaptationService(tmp_path, clock=lambda: now[0])
    snapshot = _snapshot(service)
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


def test_auto_apply_refuses_context_that_changes_during_plan_capture(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    service.add_trigger("ssid", "Coffee Shop", "balanced")
    service.set_automation(True, True)
    monkeypatch.setattr(service, "capture_context", lambda: {
        "ssid": "Coffee Shop", "network_category": "Public", "vpn_active": False,
    })
    # The deeper snapshot observes that the machine already moved away from
    # that SSID. No executor or firewall mutation should be reached.
    snapshot = _snapshot(service)
    snapshot["network"]["ssid"] = "Home"
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    result = service.run_automatic_cycle()
    assert result["status"] == "context-changed"
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
    assert dialog.windowTitle() == "Adaption — Adapt to Host"
    assert [dialog.tabs.tabText(index) for index in range(dialog.tabs.count())] == [
        "Overview", "Audit + Drift", "Exceptions + Feedback", "Adapt Host",
        "Sandbox", "Automation", "Activity",
    ]
    menus = [action.text() for action in dialog.findChild(QMenuBar).actions()]
    assert menus == ["File", "Audit", "Adapt", "Safety", "Help"]
    buttons = {button.text() for button in dialog.findChildren(QPushButton)}
    assert {
        "ADAPT HOST…", "Choose an adaptation profile…",
        "Run deep audit", "Save as golden baseline…", "1. Preview adaptation",
        "3. ADAPT HOST with this preview…", "Run no-write simulation",
        "Evaluate current context now", "Reset circuit breaker…",
        "Roll back selected snapshot…",
    }.issubset(buttons)
    dialog.tabs.setCurrentIndex(0)
    dialog.adapt_host_button.click()
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


def test_dashboard_places_adaption_before_other_left_header_actions() -> None:
    source = Path("src/angerona/gui/main_window.py").read_text(encoding="utf-8")
    adaptation = source.index("bl.addWidget(adaptation_btn)")
    self_test = source.index("bl.addWidget(test_btn)", adaptation)
    assert adaptation < self_test
    assert '"ADAPTION"' in source
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
    assert "$ErrorActionPreference='Stop'" in observed_scripts[0]
    assert "Get-NetFirewallProfile -PolicyStore ActiveStore" in observed_scripts[0]

    monkeypatch.setattr(service, "_run_readonly", lambda *_args, **_kwargs: payload("2", "0", "0"))
    incomplete = service._firewall()
    assert incomplete["complete"] is False
    assert incomplete["profiles"][0]["enabled"] is None


def test_apply_rolls_back_when_fresh_firewall_postcondition_mismatches(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    snapshot = _snapshot(service)
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


def test_concurrent_disable_cancels_stale_automatic_cycle(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    service.add_trigger("ssid", "Lab", "balanced")
    service.set_automation(True, True)
    monkeypatch.setattr(service, "capture_context", lambda: {
        "ssid": "Lab", "network_category": "Private", "vpn_active": False,
    })
    snapshot = _snapshot(service)

    def capture_then_disable():
        service.set_automation(False)
        return snapshot

    monkeypatch.setattr(service, "capture_snapshot", capture_then_disable)
    monkeypatch.setattr(
        service, "apply_plan",
        lambda *_args, **_kwargs: pytest.fail("disabled automation reached apply"),
    )
    result = service.run_automatic_cycle()
    assert result["status"] == "context-changed"
    state = service.state()
    assert state["automation_enabled"] is False
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
    monkeypatch.setattr(service, "capture_context", lambda: {
        "ssid": "Lab", "network_category": "Private", "vpn_active": False,
    })
    snapshot = _snapshot(service)
    for row in snapshot["firewall"]["profiles"]:
        row["outbound"] = "Block"
    monkeypatch.setattr(service, "capture_snapshot", lambda: snapshot)
    result = service.run_automatic_cycle()
    assert result["status"] == "manual-review"
