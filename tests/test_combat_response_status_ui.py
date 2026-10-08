from types import SimpleNamespace

from PySide6.QtCore import Qt

from angerona.gui.response_status import ResponseStatusPanel
from angerona.core.eventbus import Severity
from angerona.modules.adversary_combat import CombatPolicy


def test_status_explains_recovery_as_plain_text_without_action_reads():
    snapshot = {
        "state": "RECOVERY REQUIRED", "reason": "<b>incomplete anchor transaction</b>",
        "queue_depth": 0, "queue_capacity": 2048, "queue_drops": 2,
        "counts": {}, "last_decision": "missing_contract",
    }
    module = SimpleNamespace(response_snapshot=lambda: snapshot)
    panel = ResponseStatusPanel(lambda: module)
    try:
        assert "RECOVERY REQUIRED" in panel.state_label.text()
        assert panel.reason_label.textFormat() == Qt.PlainText
        assert panel.reason_label.text() == snapshot["reason"]
        assert "no exact response authorization" in panel.activity_label.text()
        assert "verified recovery" in panel.guidance_label.text()
        assert not panel._timer.isActive()
        panel.show()
        assert panel._timer.isActive()
        panel.hide()
        assert not panel._timer.isActive()
    finally:
        panel.close()


def test_missing_response_module_does_not_claim_readiness():
    panel = ResponseStatusPanel(lambda: None)
    try:
        assert "unavailable" in panel.state_label.text()
        assert not panel.activity_label.text()
    finally:
        panel.close()


def test_rule_summary_uses_effective_policy_without_rearming_recovery():
    policy = CombatPolicy(mode="contain", process_action="terminate", min_severity=Severity.HIGH)
    module = SimpleNamespace(
        response_snapshot=lambda: {"state": "RECOVERY REQUIRED", "ready": False},
        policy=lambda: policy,
    )
    panel = ResponseStatusPanel(lambda: module)
    try:
        assert "RECOVERY REQUIRED" in panel.state_label.text()
        assert panel.rules_label.textFormat() == Qt.PlainText
        rules = panel.rules_label.text()
        assert "HIGH+ authenticated" in rules
        assert "Exact process instance → Suspend" in rules
        assert "Whole-host isolation → Off" in rules
        assert "without per-alert approval when ARMED" in rules
        assert "verified recovery" in panel.guidance_label.text()
    finally:
        panel.close()


def test_rule_summary_tracks_effective_permissions_and_policy_read_failure():
    policy = CombatPolicy(block_network=False, quarantine_files=False, activate_honeypots=False)
    module = SimpleNamespace(
        response_snapshot=lambda: {"state": "ARMED", "ready": True},
        policy=lambda: policy,
    )
    panel = ResponseStatusPanel(lambda: module)
    try:
        assert "No automatic network block" in panel.rules_label.text()
        assert "No automatic quarantine" in panel.rules_label.text()
        assert "No automatic activation" in panel.rules_label.text()
        assert "3 distinct causes" in panel.rules_label.text()
        def unavailable():
            raise RuntimeError("offline")
        module.policy = unavailable
        panel.refresh()
        assert panel.rules_label.text() == "Automatic rules unavailable; no policy could be read."
    finally:
        panel.close()
