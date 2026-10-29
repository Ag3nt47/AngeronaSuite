"""Cached inventory lifecycle diagnostics never launch or authorize collection."""
from __future__ import annotations

import copy
import json
import os
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.status_report import StatusReporter, _process_inventory_snapshot

_BIRTH = "134377724236965739" if os.name == "nt" else (100.0).hex()


def _view(**changes):
    result = dict(state="running", ready=True, retired=False, error_type="",
                  provider=dict(state="ready", ready=True, retired=False, error=None,
                                retirement_error=None, auxiliary_close_unproven=False,
                                child_pid=731, child_birth=_BIRTH, wrapper_pid=730,
                                retirement_proofs=[]))
    result.update(changes)
    return result


def _owner(view):
    return SimpleNamespace(lifecycle_snapshot=lambda: view,
                          start=lambda: pytest.fail("status started inventory"),
                          snapshot=lambda: pytest.fail("status queried inventory"),
                          stop=lambda: pytest.fail("status stopped inventory"))


def _reporter(tmp_path, owner):
    return StatusReporter(
        EventBus(), SimpleNamespace(count_since=lambda _: 0),
        SimpleNamespace(modules={}, is_enabled=lambda _: False),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=True,
                        ollama_host="local", ollama_model="fixture"),
        process_snapshot_lifecycle=owner,
    )


def test_reporter_persists_cached_inventory_and_exact_birth_without_collection(tmp_path):
    source = _view()
    source["provider"]["key"] = "untrusted-key-not-for-export"
    source["provider"]["command"] = ["private-command-not-for-export"]
    original = copy.deepcopy(source)
    reporter = _reporter(tmp_path, _owner(source))
    assert reporter._write(force=True)
    view = json.loads((tmp_path / "diagnostics/status.json").read_text())["process_inventory"]
    assert view["state"] == "running" and view["ready"] is True
    assert view["advisory_only"] is True
    assert view["provider"]["child_birth"] == _BIRTH
    assert view["provider"]["child_pid"] == 731
    assert view["provider"]["retirement_proof_count"] == 0
    assert view["provider"]["retirement_waits_signaled"] is False
    assert "key" not in view["provider"] and "command" not in view["provider"]
    assert "Inventory : running" in (tmp_path / "diagnostics/status.txt").read_text()
    assert source == original


def test_stale_owner_ready_is_not_persisted_after_provider_retirement(tmp_path):
    source = _view()
    source["provider"].update(state="retired", ready=False, retired=True,
                              error="request-deadline", retirement_proofs=[
                                  dict(pid=731, birth=_BIRTH, wait_signaled=True),
                              ])
    reporter = _reporter(tmp_path, _owner(source))
    snapshot = reporter._snapshot()
    view = snapshot["process_inventory"]
    assert view["state"] == "unavailable" and view["ready"] is False
    assert view["provider"]["error"] == "request-deadline"
    assert view["provider"]["retirement_waits_signaled"] is True
    assert "Inventory : unavailable — request-deadline" in reporter._render_text(snapshot)


@pytest.mark.parametrize("source", [None, [], {"state": "running", "ready": True}])
def test_missing_or_malformed_cached_lifecycle_cannot_claim_readiness(source):
    view = _process_inventory_snapshot(_owner(source))
    assert view["ready"] is False and view["state"] == "unavailable"
    assert view["error_type"]


def test_absent_owner_and_provider_exception_remain_explicit():
    missing = _process_inventory_snapshot(None)
    assert missing["state"] == "not-configured" and missing["ready"] is False
    def fail():
        raise RuntimeError("private exception content must not be copied")
    view = _process_inventory_snapshot(SimpleNamespace(lifecycle_snapshot=fail))
    assert view["state"] == "unavailable" and view["error_type"] == "RuntimeError"
    assert "private exception" not in json.dumps(view)


@pytest.mark.parametrize("field,value", [
    ("ready", 1), ("retired", "false"), ("child_pid", True),
    ("wrapper_pid", 2**64), ("child_birth", 134377724236965739),
    ("retirement_proofs", [dict(wait_signaled=True)] * 4),
    ("retirement_error", True), ("child_birth", "not-a-native-birth"),
])
def test_invalid_provider_fields_are_bounded_unavailable_diagnostics(field, value):
    source = _view()
    source["provider"][field] = value
    view = _process_inventory_snapshot(_owner(source))
    assert view["ready"] is False and view["state"] == "unavailable"
    assert 1 <= len(view["diagnostic_gaps"]) <= 8
    if field == "child_birth":
        assert view["provider"][field] is None  # Never coerce a rounded numeric generation.


def test_long_and_unknown_fields_do_not_escape_the_fixed_projection():
    source = _view()
    source["provider"].update(state="retired", ready=False, retired=True,
                              error="request-deadline\n" + "x" * 10000,
                              retirement_error="y" * 10000,
                              unknown={"untrusted": "DO_NOT_EXECUTE"})
    source["unknown"] = "z" * 10000
    view = _process_inventory_snapshot(_owner(source))
    assert view["ready"] is False
    assert len(view["provider"]["error"]) <= 120 and "\n" not in view["provider"]["error"]
    assert len(view["provider"]["retirement_error"]) <= 120
    assert len(json.dumps(view)) < 2048
    assert "DO_NOT_EXECUTE" not in json.dumps(view)


def test_unknown_owner_state_or_contradictory_provider_state_cannot_be_ready():
    for source in (_view(state="fictional"), _view()):
        if source["state"] == "running":
            source["provider"]["state"] = "retired"
        view = _process_inventory_snapshot(_owner(source))
        assert view["state"] == "unavailable" and view["ready"] is False


@pytest.mark.parametrize("change", [
    {"state": "configured"}, {"state": "starting"}, {"state": "unavailable"},
    {"state": "retiring"}, {"state": "stopped"}, {"retired": True},
])
def test_ready_requires_running_nonretired_owner(change):
    view = _process_inventory_snapshot(_owner(_view(**change)))
    assert view["ready"] is False


def test_ready_contradiction_with_provider_retirement_error_is_unavailable():
    source = _view()
    source["provider"]["retirement_error"] = "InventoryCustodyCloseError"
    view = _process_inventory_snapshot(_owner(source))
    assert view["state"] == "unavailable" and view["ready"] is False


def test_ready_provider_with_missing_native_identity_is_unavailable():
    source = _view()
    source["provider"]["child_birth"] = None
    view = _process_inventory_snapshot(_owner(source))
    assert view["state"] == "unavailable" and view["ready"] is False
    assert view["diagnostic_gaps"] == ["Cached ready provider lacks process identity"]
