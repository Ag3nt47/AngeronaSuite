"""Complete App ownership composition uses the actual tool Job observer.

Only native calls are inert, using the same fixtures as the existing complete
App composition gate. No application or process is launched here.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from test_app_owned_process_composition import composition  # noqa: F401
from test_child_job_owned_identities import inert_child_factory  # noqa: F401
from test_owned_process_context import context, publish  # noqa: F401
from test_process_snapshot_owned_identities import inert_owner  # noqa: F401

from angerona.core.werfault_guard import OwnedProcessFailurePhase, OwnedProcessReadError, read_owned_process_snapshot
from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner
from angerona.telemetry.process_snapshot_worker import _Pin


def bind_tool(sample):
    from PySide6.QtCore import QObject
    child = sample.make_child((2301, 2302, 2303))
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._native_owner, owner._job = child.owner, child.job
    def inert_pin(pid):
        pin = object.__new__(_Pin)
        pin.pid, pin.closed, pin.close_failed, pin.handle = pid, False, False, object()
        return pin
    owner._wrapper, owner._child = inert_pin(2301), inert_pin(2302)
    owner._ready.set()
    bridge = RedTeamBridge.__new__(RedTeamBridge)
    QObject.__init__(bridge)
    bridge.owner = owner
    sample.app.manager = SimpleNamespace(red_team_tool_owner=bridge)
    return owner, bridge, child


def test_complete_roster_includes_every_tool_job_member_and_preserves_other_scopes(composition):
    owner, _bridge, child = bind_tool(composition)
    rows = composition.app._owned_process_identities_for_response()
    actual = {row.pid for row in rows if row.role == "redteam-tool"}
    assert actual == {2301, 2302, 2303}
    assert {"core", "watchdog", "scanner", "blackbox", "inventory-worker", "redteam-tool"} <= {row.role for row in rows}
    assert owner.capture_scope()[2] is child.owner


@pytest.mark.parametrize("failure,phase", [("startup", "tool-capture"), ("member", "tool-observe"),
    ("retire-during-observe", "tool-revalidate")])
def test_unknown_tool_scope_never_degrades_to_a_core_only_or_truncated_roster(composition, monkeypatch, failure, phase):
    owner, _bridge, child = bind_tool(composition)
    if failure == "startup":
        owner._ready.clear()
    elif failure == "member":
        child.members[:] = [[]]
    else:
        actual = owner.observe_owned_process_identities
        def change(**kwargs):
            rows = actual(**kwargs)
            owner._ready.clear()
            return rows
        monkeypatch.setattr(owner, "observe_owned_process_identities", change)
    with pytest.raises(OwnedProcessReadError) as result:
        read_owned_process_snapshot(composition.app._owned_process_identities_for_response,
            not_before=100., clock=lambda: 100.)
    assert result.value.reason_code == "supplier_failed"
    assert result.value.supplier_phase.phase == phase
    assert type(result.value.supplier_phase) is OwnedProcessFailurePhase


def test_fully_retired_explicit_tool_lifetime_has_no_live_scope(composition):
    owner, _bridge, _child = bind_tool(composition)
    owner._retired.set()  # Explicit inert native-retirement fixture boundary.
    rows = composition.app._owned_process_identities_for_response()
    assert not any(row.role == "redteam-tool" for row in rows)
    assert {"core", "watchdog", "scanner", "blackbox"} <= {row.role for row in rows}
