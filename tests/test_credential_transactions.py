"""Inert credential-map transactions; never contact an OS secret store."""
from __future__ import annotations

import json
import multiprocessing
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import secure_store
from angerona.core.file_lease import ExclusiveFileLeaseError


_PREFIX = b"ANGERONA-INERT-TRANSACTION-TEST\0"


def _inert_protect(value):
    return _PREFIX + value


def _inert_unprotect(value):
    return value[len(_PREFIX):] if value.startswith(_PREFIX) else None


def _configure_child_backend():
    # Spawned children repeat the inert backend setup before any store access.
    # sys.platform is replaced only in this module, not process-wide.
    secure_store.sys = SimpleNamespace(platform="win32")
    secure_store._protect_bytes = _inert_protect
    secure_store._unprotect_bytes = _inert_unprotect
    secure_store._private_acl = lambda _path: None
    from angerona.core import hardening

    hardening.key_acl_required = lambda: False


@pytest.fixture
def inert_store(monkeypatch, tmp_path):
    monkeypatch.setattr(secure_store, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(secure_store, "_protect_bytes", _inert_protect)
    monkeypatch.setattr(secure_store, "_unprotect_bytes", _inert_unprotect)
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)
    from angerona.core import hardening

    monkeypatch.setattr(hardening, "key_acl_required", lambda: False)
    return tmp_path


def test_pending_writer_cannot_remove_a_concurrent_new_key(inert_store, monkeypatch):
    entered, release, attempted = threading.Event(), threading.Event(), threading.Event()
    original_lock = secure_store._TRANSACTION_LOCK

    class ObservedLock:
        def acquire(self, *args, **kwargs):
            if threading.current_thread().name == "second-writer":
                attempted.set()
            return original_lock.acquire(*args, **kwargs)

        def release(self):
            return original_lock.release()

    def protect(value):
        if threading.current_thread().name == "first-writer":
            entered.set()
            assert release.wait(5), "test did not release its owned writer"
        return _inert_protect(value)

    monkeypatch.setattr(secure_store, "_TRANSACTION_LOCK", ObservedLock())
    monkeypatch.setattr(secure_store, "_protect_bytes", protect)
    errors = []

    def save(name, value):
        try:
            secure_store.write_secret_map({name: value}, inert_store)
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=save, args=("NEW_MASTER", "inert-master"), name="first-writer")
    second = threading.Thread(target=save, args=("PROVIDER", "inert-provider"), name="second-writer")
    try:
        first.start()
        assert entered.wait(5)
        second.start()
        assert attempted.wait(5), "second writer did not reach the transaction boundary"
    finally:
        release.set()
        for thread in (first, second):
            if thread.ident is not None:
                thread.join(5)
    assert not first.is_alive() and not second.is_alive()
    assert not errors
    assert secure_store.read_secret_map(inert_store, strict=True) == {
        "NEW_MASTER": "inert-master", "PROVIDER": "inert-provider",
    }


def test_competing_thread_creators_return_one_persisted_winner(inert_store):
    start = threading.Barrier(3)
    created = []

    def create(label):
        start.wait(5)

        def factory():
            created.append(label)
            return label

        return secure_store.get_or_create_secret("INERT_AUTHORITY", factory, inert_store)

    with ThreadPoolExecutor(max_workers=2) as workers:
        one = workers.submit(create, "candidate-one")
        two = workers.submit(create, "candidate-two")
        start.wait(5)
        results = (one.result(5), two.result(5))
    assert len(created) == 1
    assert results == (created[0], created[0])
    assert secure_store.read_secret_values(("INERT_AUTHORITY",), inert_store, strict=True) == {
        "INERT_AUTHORITY": created[0],
    }


def test_soc_creators_share_the_actual_persisted_key(inert_store):
    from angerona.core.operations_center import load_or_create_master_key

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(load_or_create_master_key, inert_store) for _ in range(2)]
        keys = [future.result(10) for future in futures]
    assert keys[0] == keys[1] and len(keys[0]) == 32
    assert load_or_create_master_key(inert_store) == keys[0]


def test_drill_key_pair_creators_do_not_split_authority(inert_store):
    from angerona.core.recovery_drill import protected_keys

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(protected_keys, create=True, data_root=inert_store) for _ in range(2)]
        keys = [future.result(10) for future in futures]
    assert keys[0] == keys[1] and keys[0][0] != keys[0][1]


def test_fleet_migrators_return_the_same_random_device_and_audit_keys(inert_store, monkeypatch):
    import base64

    from angerona.core import fleet_credentials as fleet

    generated = []
    generated_lock = threading.Lock()
    generate = fleet._random_distinct_key

    def record_generation(excluded):
        key = generate(excluded)
        with generated_lock:
            generated.append(key)
        return key

    monkeypatch.setattr(fleet, "_random_distinct_key", record_generation)
    secure_store.write_secret_map(
        {fleet.LEGACY_FLEET_SERVICE_KEY: "inert-legacy-credential-" * 2}, inert_store,
    )
    start = threading.Barrier(3)

    def migrate():
        start.wait(5)
        return fleet.load_or_migrate_local_credentials(
            inert_store, "tenant-test", "device-test", clock=lambda: 100,
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(migrate) for _ in range(2)]
        start.wait(5)
        credentials = [future.result(10) for future in futures]
    winner = credentials[0]
    assert len(generated) == 2
    assert set(generated) == {winner.device.secret, winner.authorization_audit_key}
    assert len({
        winner.operator.secret, winner.device.secret,
        winner.receipt_signing_key, winner.authorization_audit_key,
    }) == 4

    stored = secure_store.read_secret_map(inert_store, strict=True)
    assert fleet.LEGACY_FLEET_SERVICE_KEY not in stored
    persisted = json.loads(stored[fleet.INTERNAL_FLEET_CREDENTIALS_KEY])
    assert (
        base64.urlsafe_b64decode(persisted["receipt_signing_key"] + "=")
        == winner.receipt_signing_key
    )
    assert (
        base64.urlsafe_b64decode(persisted["authorization_audit_key"] + "=")
        == winner.authorization_audit_key
    )
    persisted_credentials = {row["credential_id"]: row for row in persisted["credentials"]}
    for credential in (winner.operator, winner.device):
        stored_secret = persisted_credentials[credential.credential_id]["secret"]
        assert base64.urlsafe_b64decode(stored_secret + "=") == credential.secret

    before_reload = secure_store.secure_store_path(inert_store).read_bytes()
    reloaded = fleet.load_or_migrate_local_credentials(
        inert_store, "tenant-test", "device-test", clock=lambda: 101,
    )
    for bundle in (*credentials, reloaded):
        assert (bundle.tenant_id, bundle.device_id) == ("tenant-test", "device-test")
        assert bundle.operator == winner.operator
        assert bundle.device == winner.device
        assert bundle.receipt_signing_key == winner.receipt_signing_key
        assert bundle.authorization_audit_key == winner.authorization_audit_key
        for credential in (winner.operator, winner.device):
            assert bundle.registry.resolve(credential.credential_id, now=101) == credential
    assert secure_store.secure_store_path(inert_store).read_bytes() == before_reload
    assert secure_store.read_secret_map(inert_store, strict=True) == stored
    assert len(generated) == 2


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_shared_os_item_has_one_lock_across_data_roots(inert_store, monkeypatch, platform):
    monkeypatch.setattr(secure_store, "sys", SimpleNamespace(platform=platform))
    lock_root = inert_store / "account-locks"
    lock_root.mkdir()
    monkeypatch.setattr(secure_store, "_account_lock_directory", lambda: lock_root)
    monkeypatch.setenv("HOME", str(inert_store / "untrusted-home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(inert_store / "untrusted-state"))
    one = secure_store._backing_store_identity(inert_store / "one")
    two = secure_store._backing_store_identity(inert_store / "two")
    assert one == two
    assert secure_store._transaction_path(one) == secure_store._transaction_path(two)
    assert secure_store._transaction_path(one).parent == lock_root


def test_account_lock_home_comes_from_os_identity_not_environment(inert_store, monkeypatch):
    import sys

    home = inert_store / "os-account-home"
    home.mkdir()
    user_id = home.stat().st_uid
    directory = home / ".angerona-credential-locks"
    metadata = {current: SimpleNamespace(st_mode=0o040755, st_uid=0)
                for current in (home, *home.parents)}
    metadata[home] = SimpleNamespace(st_mode=0o040700, st_uid=user_id)
    metadata[directory] = SimpleNamespace(st_mode=0o040700, st_uid=user_id)
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: metadata[path] if path in metadata else original(path))
    monkeypatch.setattr(secure_store.os, "geteuid", lambda: user_id, raising=False)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(
        getpwuid=lambda observed: SimpleNamespace(pw_dir=str(home)) if observed == user_id else pytest.fail("wrong UID"),
    ))
    monkeypatch.setenv("HOME", str(inert_store / "untrusted-home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(inert_store / "untrusted-state"))
    assert secure_store._account_lock_directory() == directory
    assert directory.is_dir()


def test_dpapi_lock_follows_canonical_store_path(inert_store):
    alias = inert_store / "not-present" / ".."
    assert secure_store._backing_store_identity(alias) == secure_store._backing_store_identity(inert_store)
    assert secure_store._backing_store_identity(inert_store / "other") != secure_store._backing_store_identity(inert_store)


@pytest.mark.parametrize("value", ["", "malformed-existing-key"])
def test_existing_values_never_authorize_factory_replacement(inert_store, value):
    path = secure_store.secure_store_path(inert_store)
    path.write_bytes(_inert_protect(json.dumps({"INERT_AUTHORITY": value}).encode()))
    before = path.read_bytes()
    assert secure_store.get_or_create_secret(
        "INERT_AUTHORITY", lambda: pytest.fail("existing authority was replaced"), inert_store,
    ) == value
    assert path.read_bytes() == before


def test_unreadable_store_never_authorizes_factory_creation(inert_store):
    path = secure_store.secure_store_path(inert_store)
    path.write_bytes(b"not-an-inert-protected-map")
    with pytest.raises(RuntimeError, match="unreadable"):
        secure_store.get_or_create_secret(
            "INERT_AUTHORITY", lambda: pytest.fail("failed lookup created a key"), inert_store,
        )
    assert path.read_bytes() == b"not-an-inert-protected-map"


def test_full_map_readback_rejects_loss_of_an_unrelated_key(inert_store, monkeypatch):
    secure_store.write_secret_map({"EXISTING_AUTHORITY": "inert-existing"}, inert_store)

    def lose_unrelated_key(path):
        if path == secure_store.secure_store_path(inert_store):
            value = json.loads(_inert_unprotect(path.read_bytes()))
            value.pop("EXISTING_AUTHORITY")
            path.write_bytes(_inert_protect(json.dumps(value).encode()))

    monkeypatch.setattr(secure_store, "_private_acl", lose_unrelated_key)
    with pytest.raises(RuntimeError, match="readback"):
        secure_store.write_secret_map({"PROVIDER": "inert-update"}, inert_store)


@pytest.mark.parametrize("unsafe_mode", [0o777, 0o770])
@pytest.mark.parametrize("unsafe_level", ["home", "ancestor"])
def test_posix_lock_namespace_rejects_other_account_write_access(
    inert_store, monkeypatch, unsafe_mode, unsafe_level,
):
    home = inert_store / "account-home"
    metadata = {current: SimpleNamespace(st_mode=0o040755, st_uid=1001)
                for current in (home, *home.parents)}
    unsafe = home if unsafe_level == "home" else home.parent
    metadata[unsafe] = SimpleNamespace(st_mode=0o040000 | unsafe_mode, st_uid=1001)
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: metadata[path] if path in metadata else original(path))
    with pytest.raises(PermissionError, match="another account"):
        secure_store._private_posix_directory_chain(home, 1001)


def test_posix_lock_namespace_allows_only_root_and_current_account_owners(inert_store, monkeypatch):
    home = inert_store / "account-home"
    metadata = {current: SimpleNamespace(st_mode=0o040755, st_uid=0)
                for current in (home, *home.parents)}
    metadata[home] = SimpleNamespace(st_mode=0o040700, st_uid=1001)
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: metadata[path] if path in metadata else original(path))
    secure_store._private_posix_directory_chain(home, 1001)
    metadata[home.parent] = SimpleNamespace(st_mode=0o040755, st_uid=1002)
    with pytest.raises(PermissionError, match="another account"):
        secure_store._private_posix_directory_chain(home, 1001)


def test_lock_custody_failure_does_not_read_or_create_keys(inert_store):
    lock = secure_store._transaction_path(secure_store._backing_store_identity(inert_store))
    lock.mkdir()
    with pytest.raises(ExclusiveFileLeaseError):
        secure_store.get_or_create_secret(
            "INERT_AUTHORITY", lambda: pytest.fail("unsafe lease created a key"), inert_store,
        )
    assert not secure_store.secure_store_path(inert_store).exists()


def test_nested_store_change_is_rejected_and_same_store_is_reentrant(inert_store):
    with secure_store.secret_transaction(inert_store):
        secure_store.write_secret_map({"INERT_AUTHORITY": "inert-winner"}, inert_store)
        with pytest.raises(RuntimeError, match="same backing store"):
            with secure_store.secret_transaction(inert_store / "other"):
                pytest.fail("different store nested under the current transaction")


def test_thread_wait_budget_fails_without_reading_or_replacing_keys(inert_store, monkeypatch):
    secure_store.write_secret_map({"INERT_AUTHORITY": "parent-winner"}, inert_store)
    before = secure_store.secure_store_path(inert_store).read_bytes()
    monkeypatch.setattr(secure_store, "_TRANSACTION_WAIT_SECONDS", 0.0)
    with secure_store.secret_transaction(inert_store):
        with ThreadPoolExecutor(max_workers=1) as worker:
            future = worker.submit(secure_store.get_or_create_secret, "NEW_AUTHORITY",
                                   lambda: pytest.fail("busy transaction created a key"), inert_store)
            with pytest.raises(TimeoutError, match="busy"):
                future.result(5)
    assert secure_store.secure_store_path(inert_store).read_bytes() == before


def _spawned_attempt(root, action, connection):
    _configure_child_backend()
    try:
        if action == "create":
            value = secure_store.get_or_create_secret("INERT_AUTHORITY", lambda: "child-candidate", Path(root))
        else:
            secure_store.write_secret_map({"CHILD_UPDATE": "inert-child"}, Path(root))
            value = "saved"
        connection.send(("ok", value))
    except ExclusiveFileLeaseError:
        connection.send(("contended", ""))
    except BaseException as exc:
        connection.send(("error", type(exc).__name__))
    finally:
        connection.close()


def _owned_child_result(context, target, args):
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(*args, writer))
    try:
        process.start()
        writer.close()
        assert reader.poll(10), "owned inert child did not report"
        result = reader.recv()
        process.join(10)
        assert not process.is_alive() and process.exitcode == 0
        return result
    finally:
        writer.close()
        reader.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
                process.join(5)
            assert not process.is_alive(), "owned inert child retirement failed"
            process.close()


@pytest.mark.parametrize("action", ["create", "update"])
def test_separate_process_contention_fails_visible_then_retry_preserves_winner(inert_store, action):
    context = multiprocessing.get_context("spawn")
    with secure_store.secret_transaction(inert_store):
        secure_store.write_secret_map({"INERT_AUTHORITY": "parent-winner"}, inert_store)
        assert _owned_child_result(context, _spawned_attempt, (str(inert_store), action)) == ("contended", "")
    expected = "parent-winner" if action == "create" else "saved"
    assert _owned_child_result(context, _spawned_attempt, (str(inert_store), action)) == ("ok", expected)
    stored = secure_store.read_secret_map(inert_store, strict=True)
    assert stored["INERT_AUTHORITY"] == "parent-winner"
    if action == "update":
        assert stored["CHILD_UPDATE"] == "inert-child"


def _forked_attempt(root, connection):
    try:
        try:
            secure_store._write_secret_map_locked({"INHERITED": "forbidden"}, Path(root))
        except RuntimeError:
            pass
        else:
            connection.send(("error", "inherited transaction remained authorized"))
            return
        _spawned_attempt(root, "create", connection)
    finally:
        connection.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork lifecycle")
def test_forked_child_cannot_reuse_or_unlock_parent_transaction(inert_store):
    with secure_store.secret_transaction(inert_store):
        secure_store.write_secret_map({"INERT_AUTHORITY": "parent-winner"}, inert_store)
        assert _owned_child_result(multiprocessing.get_context("fork"), _forked_attempt,
                                   (str(inert_store),)) == ("contended", "")
        # The child must not release the parent's open-file-description lock.
        assert _owned_child_result(multiprocessing.get_context("spawn"), _spawned_attempt,
                                   (str(inert_store), "create")) == ("contended", "")
    assert secure_store.get_or_create_secret("INERT_AUTHORITY", lambda: "forbidden", inert_store) == "parent-winner"
