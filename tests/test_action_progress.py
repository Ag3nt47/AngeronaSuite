"""Plain presentation retirement survives deletion of its native Qt owner."""
from PySide6.QtWidgets import QWidget
from shiboken6 import delete, isValid

from angerona.gui import action_progress as actions


def test_retained_activity_close_after_parent_deletion_is_idempotent(monkeypatch):
    finished, delivered = [], []
    monkeypatch.setattr(actions, "begin_loading", lambda *_a, **_kw: "owned-token")
    monkeypatch.setattr(actions, "finish_loading", finished.append)
    owner = QWidget()
    activities = actions.ActionActivities(owner)
    activities.changed.connect(delivered.append)
    handle = activities.begin("check", "Inert owned action")
    assert activities.snapshot()["active_count"] == 1
    delete(owner)
    assert not isValid(activities)
    before = len(delivered)
    activities.close()
    activities.close()
    assert activities.snapshot() == {}
    assert finished == [handle.token]
    assert len(delivered) == before


def test_live_activity_close_still_clears_the_visible_projection():
    owner = QWidget()
    activities = actions.ActionActivities(owner, publish_global=False)
    delivered = []
    activities.changed.connect(delivered.append)
    try:
        activities.begin("check", "Inert owned action")
        activities.close()
        assert delivered[-1] == {}
        assert activities.snapshot() == {}
    finally:
        delete(owner)
