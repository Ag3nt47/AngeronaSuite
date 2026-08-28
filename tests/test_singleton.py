from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from angerona.core import singleton


@pytest.fixture()
def lease_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(singleton, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(singleton, "key_acl_required", lambda: False)
    return tmp_path


def test_genuine_second_instance_yields_and_release_reacquires(lease_root: Path) -> None:
    first = singleton.acquire_single_instance()
    assert first is not None
    try:
        assert singleton.acquire_single_instance() is None
    finally:
        first.close()

    replacement = singleton.acquire_single_instance()
    assert replacement is not None
    replacement.close()
    assert (lease_root / "angerona.instance.lock").is_file()


def test_loopback_port_squatting_does_not_affect_file_lease(lease_root: Path) -> None:
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    squatter.bind(("127.0.0.1", 0))
    squatter.listen(1)
    try:
        lease = singleton.acquire_single_instance()
        assert lease is not None
        lease.close()
    finally:
        squatter.close()


def test_malformed_incumbent_record_fails_visibly(lease_root: Path) -> None:
    first = singleton.acquire_single_instance()
    assert first is not None
    (lease_root / "angerona.instance.json").write_text("not-json", encoding="utf-8")
    try:
        with pytest.raises(singleton.SingletonError, match="ownership record"):
            singleton.acquire_single_instance()
    finally:
        first.close()


def test_unrelated_live_process_record_fails_visibly(lease_root: Path) -> None:
    first = singleton.acquire_single_instance()
    assert first is not None
    record = lease_root / "angerona.instance.json"
    payload = json.loads(record.read_text(encoding="utf-8"))
    payload["launcher"] = singleton._canonical_executable(lease_root / "not-angerona.exe")
    record.write_text(json.dumps(payload), encoding="utf-8")
    try:
        with pytest.raises(singleton.SingletonError, match="not a verified"):
            singleton.acquire_single_instance()
    finally:
        first.close()


def test_ambiguous_lock_failure_is_not_reported_as_an_instance(
    lease_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_lock(_stream: object) -> None:
        raise OSError(5, "storage failure")

    monkeypatch.setattr(singleton, "_try_lock", fail_lock)
    with pytest.raises(singleton.SingletonError, match="lock failed"):
        singleton.acquire_single_instance()


def test_singleton_source_has_no_network_lock() -> None:
    source = Path(singleton.__file__).read_text(encoding="utf-8")
    assert "_LOCK_PORT" not in source
    assert "socket.socket" not in source
