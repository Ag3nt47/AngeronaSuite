"""Inert peer source-policy checks never start or stop a real component."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.resilience import manager, watchdog
from angerona.resilience.source_guard import SourceGuard


@pytest.fixture
def source(tmp_path, monkeypatch):
    package = tmp_path / "src" / "angerona"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(manager, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(watchdog, "_repo_root", lambda: tmp_path)
    # Record the prior environment even when the name started absent; the
    # production policy intentionally sets it for its later peer children.
    monkeypatch.setenv("ANGERONA_PEER_SOURCE_DIGEST", "")
    monkeypatch.delenv("ANGERONA_PEER_SOURCE_DIGEST")
    monkeypatch.setattr(manager.sys, "frozen", False, raising=False)
    return tmp_path


def core_policy():
    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    owner._source_guard = None
    owner._source_guard_lock = threading.Lock()
    owner._source_integrity = {"state": "pending"}
    owner._sup = SimpleNamespace(launch_guard=None)
    owner.events = []
    owner._publish = lambda *args: owner.events.append(args)
    owner._prepare_source_guard()
    return owner


def test_core_binds_child_seal_and_holds_changes_without_overwriting(source, monkeypatch):
    owner = core_policy()
    digest = owner._source_guard.digest
    assert manager.os.environ["ANGERONA_PEER_SOURCE_DIGEST"] == digest
    assert owner._sup.launch_guard(None)
    path = source / "src" / "angerona" / "__init__.py"
    path.write_text("VALUE = 2\n", encoding="utf-8")
    assert owner._sup.launch_guard(None) is False
    assert owner._source_integrity["state"] == "changed"
    assert path.read_text() == "VALUE = 2\n"
    assert owner.events[-1][-1]["response_authorized"] is False
    assert len(owner.events) == 1
    path.write_text("VALUE = 1\n", encoding="utf-8")
    assert owner._sup.launch_guard(None) is False
    assert len(owner.events) == 1


def test_fresh_reviewed_source_session_can_adopt_intentional_user_changes(source, monkeypatch):
    old = core_policy()
    (source / "src" / "angerona" / "__init__.py").write_text("VALUE = 2\n")
    assert old._sup.launch_guard(None) is False
    # Explicit normal startup has no inherited peer digest. It is a new session,
    # whose trust must come from the launcher/approved source activation.
    monkeypatch.delenv("ANGERONA_PEER_SOURCE_DIGEST")
    new = core_policy()
    assert new._sup.launch_guard(None)
    assert new._source_guard.digest != old._source_guard.digest


def test_peer_cannot_silently_reseal_a_different_parent_tree(source, monkeypatch):
    parent_digest = SourceGuard.capture(source).digest
    monkeypatch.setenv("ANGERONA_PEER_SOURCE_DIGEST", parent_digest)
    (source / "src" / "angerona" / "__init__.py").write_text("VALUE = 2\n")
    owner = core_policy()
    assert owner._source_guard is None
    assert owner._source_integrity["state"] == "unavailable"
    assert owner._sup.launch_guard(None) is False
    assert manager.os.environ["ANGERONA_PEER_SOURCE_DIGEST"] == parent_digest


def test_watchdog_receives_same_digest_and_latches_failed_source_check(source):
    core = core_policy()
    sup = SimpleNamespace(launch_guard=None)
    snapshot = watchdog._prepare_source_guard(sup)
    assert snapshot()["digest"] == core._source_guard.digest
    assert sup.launch_guard(None)
    path = source / "src" / "angerona" / "__init__.py"
    path.write_text("VALUE = 2\n")
    assert sup.source_integrity_check() is False
    assert snapshot()["state"] == "changed"
    assert sup.launch_guard(None) is False
    assert path.read_text() == "VALUE = 2\n"


@pytest.mark.parametrize("side", ["core", "watchdog"])
def test_observer_exception_holds_relaunch_instead_of_crashing_peer(source, monkeypatch, side):
    owner = core_policy()
    sup = owner._sup
    if side == "watchdog":
        sup = SimpleNamespace(launch_guard=None)
        snapshot = watchdog._prepare_source_guard(sup)
    else:
        snapshot = lambda: owner._source_integrity
    monkeypatch.setattr(SourceGuard, "check", lambda _: (_ for _ in ()).throw(RuntimeError("collector failed")))
    assert sup.launch_guard(None) is False
    assert snapshot()["state"] == "unavailable"
    assert sup.launch_guard(None) is False


def test_seal_inherited_by_sanitized_peer_environment(source):
    from angerona.core.privilege import sanitized_child_environment

    digest = SourceGuard.capture(source).digest
    environment = sanitized_child_environment(source={"ANGERONA_PEER_SOURCE_DIGEST": digest,
                                                       "UNTRUSTED_API_KEY": "discard"})
    assert environment["ANGERONA_PEER_SOURCE_DIGEST"] == digest
    assert "UNTRUSTED_API_KEY" not in environment


def test_plugin_named_package_directory_is_still_sealed(source):
    guard = SourceGuard.capture(source)
    plugins = source / "src" / "angerona" / "external_modules"
    plugins.mkdir()
    (plugins / "plugin.py").write_text("VALUE = 3\n")
    result = guard.check()
    assert not result.ok
    assert result.changed == ("src/angerona/external_modules/plugin.py",)


def test_packaged_boundary_does_not_claim_a_source_seal(source, monkeypatch):
    monkeypatch.setattr(manager.sys, "frozen", True)
    owner = core_policy()
    assert owner._source_guard is None
    assert owner._source_integrity["state"] == "not-applicable"
    assert owner._sup.launch_guard is None
    sup = SimpleNamespace(launch_guard=None)
    assert watchdog._prepare_source_guard(sup)()["state"] == "not-applicable"
    assert sup.launch_guard is None


def test_watchdog_cached_status_never_waits_for_source_scan(source, monkeypatch):
    sup = SimpleNamespace(launch_guard=None)
    snapshot = watchdog._prepare_source_guard(sup)
    entered, release = threading.Event(), threading.Event()
    original = SourceGuard.check

    def slow_check(guard):
        entered.set()
        assert release.wait(3.0)
        return original(guard)

    monkeypatch.setattr(SourceGuard, "check", slow_check)
    worker = threading.Thread(target=sup.source_integrity_check)
    worker.start()
    try:
        assert entered.wait(2.0)
        assert snapshot()["state"] == "verified"
    finally:
        release.set()
        worker.join(timeout=3.0)
    assert not worker.is_alive()


def test_core_does_not_fabricate_heartbeats_when_supervision_stalls(monkeypatch):
    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    waits = iter([False, False, False, True])
    work_health = iter([True, False, False])
    beats = []
    owner.heartbeat_interval = 0.1
    owner._stop = SimpleNamespace(wait=lambda _: next(waits))
    owner._sup = SimpleNamespace(heartbeat_allowed=lambda: next(work_health))
    owner._core_beat = SimpleNamespace(beat=lambda: beats.append("beat"))
    monkeypatch.setattr(manager.tok, "is_standdown_requested", lambda: False)
    owner._heartbeat_loop()
    assert beats == ["beat"]


def test_integrity_monitor_watches_new_peer_gates(monkeypatch):
    from angerona.modules.self_integrity import SelfIntegrityEngine

    guard = SelfIntegrityEngine(targets=("angerona.resilience.source_guard:SourceGuard.check",))
    guard.arm()
    monkeypatch.setattr(SourceGuard, "check", lambda _: True)
    assert guard.check()
