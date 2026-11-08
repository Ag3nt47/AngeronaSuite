from __future__ import annotations

import os
from pathlib import Path

import pytest

from angerona.resilience import source_guard
from angerona.resilience.source_guard import SourceGuard, SourceGuardError


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    package = tmp_path / "src" / "angerona"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"VALUE = 1\n")
    (package / "resilience").mkdir()
    (package / "resilience" / "watchdog.py").write_bytes(b"WATCH = True\n")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "startup_source_recovery.py").write_bytes(b"RECOVER = True\n")
    return tmp_path


def test_seal_is_deterministic_read_only_and_parent_bound(installed: Path) -> None:
    guard = SourceGuard.capture(installed)
    assert guard.file_count == 3
    assert len(guard.digest) == 64
    assert guard.check().ok
    assert SourceGuard.capture(installed, guard.digest).digest == guard.digest
    with pytest.raises(SourceGuardError, match="parent session seal"):
        SourceGuard.capture(installed, "0" * 64)
    assert sorted(path.relative_to(installed).as_posix() for path in installed.rglob("*") if path.is_file()) == [
        "src/angerona/__init__.py", "src/angerona/resilience/watchdog.py", "tools/startup_source_recovery.py",
    ]


@pytest.mark.parametrize("digest", ["", "A" * 64, "a" * 63, True, 1, b"a" * 64])
def test_malformed_parent_binding_is_refused(installed: Path, digest) -> None:
    with pytest.raises(SourceGuardError, match="malformed"):
        SourceGuard.capture(installed, digest)


def test_same_size_same_timestamp_edit_is_detected_without_rebaseline(installed: Path) -> None:
    guard = SourceGuard.capture(installed)
    path = installed / "src" / "angerona" / "__init__.py"
    before = path.stat()
    path.write_bytes(b"VALUE = 2\n")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    for _ in range(2):
        result = guard.check()
        assert not result.ok and result.state == "changed"
        assert result.changed == ("src/angerona/__init__.py",)
        assert result.changed_count == 1
        assert guard.digest != result.digest


@pytest.mark.parametrize("name", ["added.py", "added.pyw", "added.pyc", "added.pyd", "added.so"])
def test_new_execution_file_is_detected(installed: Path, name: str) -> None:
    guard = SourceGuard.capture(installed)
    (installed / "src" / "angerona" / name).write_bytes(b"new")
    result = guard.check()
    assert result.state == "changed"
    assert result.changed == ("src/angerona/" + name,)


def test_missing_source_and_new_launch_file_are_detected(installed: Path) -> None:
    guard = SourceGuard.capture(installed)
    (installed / "src" / "angerona" / "__init__.py").unlink()
    (installed / "blackbox_recorder.py").write_bytes(b"new")
    result = guard.check()
    assert not result.ok
    assert result.changed == ("blackbox_recorder.py", "src/angerona/__init__.py")


@pytest.mark.parametrize("name", ["start-angerona.bat", "tools/verify_startup_recovery_bundle.ps1",
                                  "assets/startup-recovery-manifest.json"])
def test_bootstrap_and_repair_anchor_changes_are_detected(installed: Path, name: str) -> None:
    path = installed / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"reviewed anchor")
    guard = SourceGuard.capture(installed)
    path.write_bytes(b"changed anchor")
    assert guard.check().changed == (name,)


def test_unreadable_scope_is_unknown_not_healthy(installed: Path, monkeypatch) -> None:
    guard = SourceGuard.capture(installed)

    def fail(*_args, **_kwargs):
        raise PermissionError("private path must not leak")

    monkeypatch.setattr(source_guard, "_read_bytes", fail)
    result = guard.check()
    assert not result.ok and result.state == "unavailable"
    assert result.digest == "" and result.changed == ()
    assert "private path" not in result.reason


def test_hardlinked_source_is_refused(installed: Path, tmp_path: Path) -> None:
    target = installed / "src" / "angerona" / "__init__.py"
    try:
        os.link(target, tmp_path / "alias")
    except OSError:
        pytest.skip("hard links unavailable")
    with pytest.raises(SourceGuardError, match="single-link"):
        SourceGuard.capture(installed)


def test_source_symlink_is_refused(installed: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.py"
    target.write_bytes(b"outside")
    link = installed / "src" / "angerona" / "redirect.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(SourceGuardError, match="linked or redirected"):
        SourceGuard.capture(installed)


def test_generated_cache_and_private_root_caches_are_out_of_scope(installed: Path) -> None:
    guard = SourceGuard.capture(installed)
    cache = installed / "src" / "angerona" / "__pycache__"
    cache.mkdir()
    (cache / "__init__.cpython-312.pyc").write_bytes(b"cache")
    private = installed / ".tmp" / "copy" / "src" / "angerona"
    private.mkdir(parents=True)
    (private / "a.py").write_bytes(b"private")
    (installed / "user-settings.json").write_bytes(b"preferences")
    assert guard.check().ok


def test_change_paths_are_bounded_with_true_count(installed: Path) -> None:
    guard = SourceGuard.capture(installed)
    for number in range(40):
        (installed / "src" / "angerona" / f"new{number:02}.py").write_bytes(b"new")
    result = guard.check()
    assert not result.ok and result.changed_count == 40
    assert len(result.changed) == source_guard.MAX_CHANGED_PATHS


@pytest.mark.parametrize("budget", ["MAX_FILES", "MAX_FILE_BYTES", "MAX_TOTAL_BYTES", "MAX_ENTRIES", "MAX_DIRECTORIES"])
def test_inventory_budgets_refuse_incomplete_observation(installed: Path, monkeypatch, budget: str) -> None:
    monkeypatch.setattr(source_guard, budget, 1)
    with pytest.raises(SourceGuardError, match="budget|limit"):
        SourceGuard.capture(installed)


def test_inventory_race_fails_closed(installed: Path, monkeypatch) -> None:
    guard = SourceGuard.capture(installed)
    original = source_guard._read_bytes
    changed = False

    def concurrent_add(path, *, root):
        nonlocal changed
        data = original(path, root=root)
        if not changed:
            changed = True
            (installed / "src" / "angerona" / "concurrent.py").write_bytes(b"new")
        return data

    monkeypatch.setattr(source_guard, "_read_bytes", concurrent_add)
    result = guard.check()
    assert not result.ok and result.state == "unavailable"
    assert "during observation" in result.reason


def test_approved_changes_require_a_new_session_seal(installed: Path) -> None:
    old = SourceGuard.capture(installed)
    (installed / "src" / "angerona" / "__init__.py").write_bytes(b"approved edit")
    assert not old.check().ok
    with pytest.raises(SourceGuardError, match="parent session seal"):
        SourceGuard.capture(installed, old.digest)
    fresh = SourceGuard.capture(installed)
    assert fresh.check().ok and fresh.digest != old.digest


def test_relative_and_traversing_roots_are_refused(installed: Path) -> None:
    for path in (Path("relative"), installed / ".." / installed.name):
        with pytest.raises(SourceGuardError, match="absolute local root"):
            SourceGuard.capture(path)
