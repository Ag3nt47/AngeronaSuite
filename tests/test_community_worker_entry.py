from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from angerona import __main__ as entry
from angerona.core import privilege


def environment(monkeypatch, arguments, *, frozen=False, administrator=False, trusted=True):
    monkeypatch.setattr(entry, "_source_activation_pending_guard", lambda: False)
    monkeypatch.setattr(entry, "sys", SimpleNamespace(argv=["angerona", *arguments], platform="win32", frozen=frozen, stderr=sys.stderr))
    monkeypatch.setattr(privilege, "is_admin", lambda: administrator)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("Internal workers must not request UAC"))
    from angerona.core import windows_package_identity
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority", lambda: SimpleNamespace(trusted=trusted, reason="fixture package"))


@pytest.mark.parametrize("frozen", [False, True])
def test_community_probe_dispatch_precedes_config_core_and_qt(monkeypatch, frozen):
    from angerona.core import community_tool_probe_worker as worker
    calls = []
    monkeypatch.setattr(worker, "worker_main", lambda arguments: calls.append(arguments) or 73)
    arguments = ["--community-tool-probe", "--request", "private-request.json", "--sha256", "a" * 64]
    environment(monkeypatch, arguments, frozen=frozen)
    assert entry.main() == 73
    assert calls == [arguments[1:]]


@pytest.mark.parametrize("frozen", [False, True])
def test_standalone_tool_dispatch_is_one_fixed_flag(monkeypatch, frozen):
    worker = ModuleType("angerona.gui.red_team_app")
    calls = []
    worker.worker_main = lambda: calls.append("worker") or 71
    monkeypatch.setitem(sys.modules, worker.__name__, worker)
    environment(monkeypatch, ["--red-team-tool-worker"], frozen=frozen)
    assert entry.main() == 71
    assert calls == ["worker"]


@pytest.mark.parametrize("arguments", [
    ["--community-tool-probe-unknown"], ["--community-tool-probe", "--chill"],
    ["--community-tool-probe", "--request", "x", "--sha256", "a", "--setup"],
    ["--red-team-tool-worker", "--setup"], ["--red-team-tool-worker-x"],
    ["--red-team-inert-probe", "ANGERONA_REDTEAM_12345678", "--setup"],
    ["--red-team-inert-probe", "ANGERONA_REDTEAM_ABCDEF01"], ["--red-team-inert-probe-other"],
])
def test_malformed_reserved_worker_modes_never_fall_through(monkeypatch, arguments):
    environment(monkeypatch, arguments)
    assert entry.main() == 2


@pytest.mark.parametrize("arguments", [["--red-team-tool-worker"],
    ["--red-team-inert-probe", "ANGERONA_REDTEAM_12345678"],
    ["--community-tool-probe", "--request", "x", "--sha256", "a" * 64]])
@pytest.mark.parametrize("frozen,administrator,trusted", [(False, True, True), (True, True, True), (True, False, False)])
def test_internal_helpers_cannot_bypass_source_or_package_privilege_guard(monkeypatch, arguments, frozen, administrator, trusted):
    environment(monkeypatch, arguments, frozen=frozen, administrator=administrator, trusted=trusted)
    assert entry.main() == 2


def test_inert_target_is_fixed_sleep_with_no_code_or_path(monkeypatch):
    environment(monkeypatch, ["--red-team-inert-probe", "ANGERONA_REDTEAM_12abcdef"])
    slept = []
    monkeypatch.setattr("time.sleep", lambda seconds: slept.append(seconds))
    assert entry.main() == 0
    assert slept == [30]
