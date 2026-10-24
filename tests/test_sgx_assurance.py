from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from angerona.core import sgx_guard


def test_runtime_hint_is_reported_as_unverified(monkeypatch):
    monkeypatch.setattr(sgx_guard, "Path", lambda path: SimpleNamespace(exists=lambda: False))
    monkeypatch.setattr(sgx_guard, "os", SimpleNamespace(environ={"SGX": "1"}))
    guard = sgx_guard.SgxEnclaveGuard()
    assert guard.active is True  # Legacy hint API remains compatible.
    assert "runtime hint" in guard.summary()
    assert "unverified" in guard.summary()
    assert "ACTIVE" not in guard.summary()


def test_no_hint_does_not_generate_key(monkeypatch):
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: False)
    monkeypatch.setattr(sgx_guard, "os", SimpleNamespace(
        urandom=lambda size: pytest.fail("key generated with no runtime hint"),
    ))
    guard = sgx_guard.SgxEnclaveGuard()
    assert guard.enclave_key() is None
    assert "unverified" in guard.summary()


def test_concurrent_helper_calls_receive_one_key(monkeypatch):
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: True)
    entered, release = threading.Event(), threading.Event()
    generated = []
    def generate(size):
        assert size == 32
        generated.append(size)
        entered.set()
        assert release.wait(5)
        return b"K" * 32
    monkeypatch.setattr(sgx_guard, "os", SimpleNamespace(urandom=generate))
    guard = sgx_guard.SgxEnclaveGuard()
    with ThreadPoolExecutor(max_workers=4) as workers:
        one = workers.submit(guard.enclave_key)
        try:
            assert entered.wait(5)
            others = [workers.submit(guard.enclave_key) for _ in range(3)]
        finally:
            release.set()
        keys = [one.result(5), *(future.result(5) for future in others)]
    assert generated == [32]
    assert keys == [keys[0]] * 4
    assert len(keys[0]) == 32


def test_plain_sqlite_cannot_report_success_for_ignored_cipher_pragmas(monkeypatch):
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: True)
    guard = sgx_guard.SgxEnclaveGuard()
    connection = sqlite3.connect(":memory:")
    try:
        assert connection.execute("PRAGMA cipher_version").fetchone() is None
        assert guard.patch_memc(connection) is False
        connection.execute("CREATE TABLE ordinary(value INTEGER)")
        assert connection.execute("SELECT count(*) FROM ordinary").fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize("version", [None, (), ("",), ("  ",), (0,)])
def test_sqlcipher_requires_a_nonempty_version_before_key_application(monkeypatch, version):
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: True)
    calls = []
    class Connection:
        def execute(self, query):
            calls.append(query)
            return SimpleNamespace(fetchone=lambda: version)
    assert sgx_guard.SgxEnclaveGuard().patch_memc(Connection()) is False
    assert calls == ["PRAGMA cipher_version"]


def test_sqlcipher_helper_checks_schema_and_retains_inert_key_on_retry(monkeypatch):
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: True)
    guard = sgx_guard.SgxEnclaveGuard()
    guard._key = b"K" * 32
    calls = []
    class Connection:
        def execute(self, query):
            calls.append(query)
            if query == "PRAGMA cipher_version":
                return SimpleNamespace(fetchone=lambda: ("4.6.1",))
            return SimpleNamespace(fetchone=lambda: (0,))
    assert guard.patch_memc(Connection()) is True
    assert calls[0] == "PRAGMA cipher_version"
    assert calls[-1] == "SELECT count(*) FROM sqlite_master"
    assert any(query.startswith("PRAGMA key = ") for query in calls)


def test_sqlcipher_schema_failure_is_not_reported_as_encryption_success(monkeypatch):
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: True)
    class Connection:
        def execute(self, query):
            if query == "PRAGMA cipher_version":
                return SimpleNamespace(fetchone=lambda: ("4.6.1",))
            if query.startswith("SELECT"):
                raise sqlite3.DatabaseError("inert key rejection")
            return SimpleNamespace(fetchone=lambda: None)
    assert sgx_guard.SgxEnclaveGuard().patch_memc(Connection()) is False


def test_concurrent_singleton_calls_share_one_guard(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    guards = []
    class Guard:
        def __init__(self):
            guards.append(self)
            entered.set()
            assert release.wait(5)
    monkeypatch.setattr(sgx_guard, "_GUARD", None)
    monkeypatch.setattr(sgx_guard, "SgxEnclaveGuard", Guard)
    with ThreadPoolExecutor(max_workers=4) as workers:
        one = workers.submit(sgx_guard.get_guard)
        try:
            assert entered.wait(5)
            others = [workers.submit(sgx_guard.get_guard) for _ in range(3)]
        finally:
            release.set()
        instances = [one.result(5), *(future.result(5) for future in others)]
    assert len(guards) == 1
    assert all(instance is guards[0] for instance in instances)
