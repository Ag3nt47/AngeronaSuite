from types import SimpleNamespace

from PySide6.QtCore import Qt

from angerona.gui.response_status import ResponseStatusPanel


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
