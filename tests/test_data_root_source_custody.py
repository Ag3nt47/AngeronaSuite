from __future__ import annotations

from pathlib import Path

import pytest

from angerona.core import data_paths, privilege


def _reset_caches() -> None:
    data_paths._canonical_data_path.cache_clear()
    data_paths._ready_source_roots.clear()
    data_paths._hardened_roots.clear()


def _mock_secure_create(monkeypatch: pytest.MonkeyPatch) -> None:
    def create(path: Path) -> bool:
        path.mkdir()
        return True

    monkeypatch.setattr(data_paths, "_create_admin_directory_atomic", create)


def test_elevated_source_data_root_requires_protected_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert data_paths._pytest_isolated_runtime()
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: True)
    monkeypatch.setattr(
        data_paths,
        "_admin_acl_valid",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("bounded pytest root must not require production ACL")
        ),
    )
    data_paths._verify_protected_source_data_root(
        Path(data_paths.os.environ["ANGERONA_DATA"])
    )
    root = tmp_path / "runtime"
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: True)
    monkeypatch.setattr(data_paths, "_canonical_source_data_root", lambda: root)
    monkeypatch.setattr(data_paths, "_admin_acl_valid", lambda _path: False)
    _mock_secure_create(monkeypatch)
    _reset_caches()
    assert not data_paths._pytest_isolated_runtime()

    with pytest.raises(PermissionError, match="guarded launcher"):
        data_paths.data_dir()


def test_elevated_source_data_root_accepts_launcher_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: True)
    monkeypatch.setattr(data_paths, "_canonical_source_data_root", lambda: root)
    monkeypatch.setattr(data_paths, "_admin_acl_valid", lambda _path: True)
    _mock_secure_create(monkeypatch)
    _reset_caches()

    assert data_paths.data_dir() == root.resolve()


def test_unprivileged_source_development_does_not_require_admin_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: False)
    monkeypatch.setattr(
        data_paths,
        "_admin_acl_valid",
        lambda _path: (_ for _ in ()).throw(AssertionError("ACL check not expected")),
    )
    _reset_caches()

    assert data_paths.data_dir() == root.resolve()


def test_sanitized_elevated_bootstrap_derives_and_verifies_canonical_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attacker_root = tmp_path / "redirected"
    canonical_root = tmp_path / "canonical" / "AngeronaData"
    acl_checks: list[Path] = []
    monkeypatch.setattr(privilege.sys, "platform", "win32")
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setattr(
        privilege,
        "_minimal_environment",
        lambda source: {
            key: value
            for key, value in source.items()
            if not key.startswith("ANGERONA_")
        },
    )
    monkeypatch.setattr(privilege, "_validated_watchdog_context", lambda _value: {})
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: True)
    monkeypatch.setattr(
        data_paths, "_canonical_source_data_root", lambda: canonical_root
    )
    canonical_root.parent.mkdir(parents=True)
    _mock_secure_create(monkeypatch)
    monkeypatch.setattr(
        data_paths,
        "_admin_acl_valid",
        lambda path: acl_checks.append(Path(path)) or True,
    )
    monkeypatch.setenv("ANGERONA_DATA", str(attacker_root))
    monkeypatch.setenv("ANGERONA_ENFORCE_KEY_ACL", "1")
    _reset_caches()

    original = dict(privilege.os.environ)
    try:
        privilege.sanitize_privileged_bootstrap_environment()
        selected = data_paths.data_dir()

        assert "ANGERONA_ENFORCE_KEY_ACL" not in privilege.os.environ
        assert selected == canonical_root.resolve()
        assert selected != attacker_root.resolve()
        assert acl_checks == [canonical_root.resolve()]
        assert privilege.os.environ["ANGERONA_DATA"] == str(canonical_root.resolve())
    finally:
        privilege.os.environ.clear()
        privilege.os.environ.update(original)
