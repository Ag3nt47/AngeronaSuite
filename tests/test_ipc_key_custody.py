"""Desired raw-ring key protocol; private synthetic files and modeled custody only."""
from __future__ import annotations

import errno
import mmap as real_mmap
import os as real_os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import hardening, secure_store
from angerona.core.file_lease import ExclusiveFileLeaseError
from angerona.resilience import ipc_ring


_FAKE_KEY = b"a" * 32
_WINNER = b"w" * 32
_TIMEOUT = 5.0


class _InjectedFailure(RuntimeError):
    pass


class _FixtureExhaustion(RuntimeError):
    pass


@pytest.fixture
def private_authority(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    state = SimpleNamespace(
        root=root, key=root / "synthetic.key", ring=root / "synthetic.ring",
        successor=root / "successor.key", rejected=root / "rejected.key",
        pending=set(), opened=[], files=[], maps=[], reads=[], generated=[],
        create_attempts=0, prepare_calls=0, secure_calls=0, product_unlinks=[], custody_records=[],
        collision=None, read_mutation=None, write_failure=None, constructor_failure=None,
        custody_failure=None, required=False, parent_refused=False,
        quarantine=False, failure=_InjectedFailure("private sentinel"),
        first_secure=threading.Event(), release=threading.Event(), attempted=threading.Event(),
        threads=[], hold_first=False,
    )

    def owned(path):
        target = Path(path)
        assert target.is_absolute() and target.parent.resolve() == root
        assert target.name in {"synthetic.key", "synthetic.ring", "successor.key",
                               "rejected.key", "secrets.dpapi.lock"}
        return target

    def no_host(*args, **kwargs):
        pytest.fail("fixture attempted installed key/data/account/backend access")

    monkeypatch.setattr(ipc_ring, "_key_path", no_host)
    monkeypatch.setattr(ipc_ring, "_data_dir", no_host)
    monkeypatch.setattr(ipc_ring, "ring_path", no_host)
    # Model only the Windows transaction namespace, on every test platform.
    # The real lease still uses the current OS primitive on its private file.
    monkeypatch.setattr(secure_store, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(secure_store, "_account_lock_directory", no_host)
    for name in ("read_secret_values", "write_secret_map", "_protect_bytes", "_unprotect_bytes"):
        monkeypatch.setattr(secure_store, name, no_host)
    local_lock = threading.RLock()
    monkeypatch.setattr(secure_store, "_TRANSACTION_LOCK", local_lock)
    monkeypatch.setattr(secure_store, "_TRANSACTION_LOCAL", threading.local())
    monkeypatch.setattr(secure_store, "_ACTIVE_LEASE", None)
    state.local_lock = local_lock

    def parent(path, *, required=False):
        owned(path)
        if state.parent_refused:
            raise PermissionError("controlled private parent refusal")

    def prepare(path, *, required=False):
        target = owned(path)
        assert target == state.key
        state.prepare_calls += 1
        state.custody_records.append(("prepare", getattr(secure_store._TRANSACTION_LOCAL, "record", None) is not None))
        if state.quarantine == "refuse":
            if state.prepare_calls > 2:
                raise _FixtureExhaustion("fixture stopped unbounded custody retry")
            return False
        if state.quarantine == "once" and state.prepare_calls == 1:
            real_os.replace(target, state.rejected)
            return False
        return True

    def secure(path, *, required=False):
        target = owned(path)
        assert target == state.key
        state.secure_calls += 1
        state.custody_records.append(("secure", getattr(secure_store._TRANSACTION_LOCAL, "record", None) is not None))
        if state.hold_first and threading.current_thread().name == "private-first":
            state.first_secure.set()
            assert state.release.wait(_TIMEOUT), "owned final-custody barrier not released"
        if state.custody_failure:
            state.successor.write_bytes(_WINNER.hex().encode("ascii"))
            real_os.replace(state.successor, target)
            if state.custody_failure == "raise":
                raise state.failure
        return True

    monkeypatch.setattr(hardening, "key_acl_required", lambda: state.required)
    monkeypatch.setattr(hardening, "ensure_sensitive_parent", parent)
    monkeypatch.setattr(hardening, "prepare_sensitive_key", prepare)
    monkeypatch.setattr(hardening, "secure_sensitive_file", secure)

    def fake_random(size):
        assert size == 32
        state.generated.append(threading.current_thread().name)
        return _FAKE_KEY

    monkeypatch.setattr(ipc_ring, "secrets", SimpleNamespace(token_bytes=fake_random))

    class ObservedFile:
        def __init__(self, actual, target):
            self.actual, self.target = actual, target
            state.files.append(actual)

        def __getattr__(self, name):
            return getattr(self.actual, name)

        def __enter__(self):
            self.actual.__enter__()
            return self

        def __exit__(self, *exc):
            return self.actual.__exit__(*exc)

        def read(self, size=-1):
            result = self.actual.read(size)
            state.reads.append((threading.current_thread().name, size, len(result)))
            return result

    class ObservedPath(type(Path())):
        def open(self, *args, **kwargs):
            target = owned(self)
            return ObservedFile(super().open(*args, **kwargs), target)

        def unlink(self, *args, **kwargs):
            state.product_unlinks.append(str(self))
            pytest.fail("product attempted to unlink a final authority name")

    monkeypatch.setattr(ipc_ring, "Path", ObservedPath)

    class LocalOS:
        def __getattr__(self, name):
            return getattr(real_os, name)

        def open(self, path, flags, *args, **kwargs):
            target = owned(path)
            creating = target == state.key and bool(flags & real_os.O_EXCL)
            if creating:
                state.create_attempts += 1
                if state.collision == "churn" and state.create_attempts > 2:
                    raise _FixtureExhaustion("fixture stopped unbounded create retry")
            if creating and state.collision:
                with target.open("xb") as stream:
                    stream.write(_WINNER.hex().encode("ascii"))
                created = target.stat()
                try:
                    # A genuine create-only call observes the private competitor.
                    unexpected = real_os.open(path, flags, *args, **kwargs)
                except FileExistsError:
                    if state.collision == "churn":
                        current = target.stat()
                        assert (created.st_dev, created.st_ino) == (current.st_dev, current.st_ino)
                        target.unlink()  # fixture owns this exact closed competitor
                    raise
                else:
                    real_os.close(unexpected)
                    pytest.fail("controlled real O_EXCL unexpectedly succeeded")
            descriptor = real_os.open(path, flags, *args, **kwargs)
            state.pending.add(descriptor)
            state.opened.append((descriptor, target))
            return descriptor

        def close(self, descriptor):
            assert descriptor in state.pending
            real_os.close(descriptor)
            state.pending.remove(descriptor)

        def fdopen(self, descriptor, *args, **kwargs):
            assert descriptor in state.pending
            if state.constructor_failure == "fdopen":
                raise state.failure
            actual = real_os.fdopen(descriptor, *args, **kwargs)
            state.pending.remove(descriptor)
            target = [path for number, path in state.opened if number == descriptor][-1]
            return ObservedFile(actual, target)

        def read(self, descriptor, size):
            assert descriptor in state.pending
            if state.read_mutation:
                mutation, state.read_mutation = state.read_mutation, None
                if mutation == "grow":
                    with state.key.open("ab") as stream:
                        stream.write(b"00")
                else:
                    with state.key.open("r+b") as stream:
                        stream.truncate(32)
            result = real_os.read(descriptor, size)
            state.reads.append((threading.current_thread().name, size, len(result)))
            return result

        def write(self, descriptor, value):
            assert descriptor in state.pending
            if state.write_failure == "short":
                return real_os.write(descriptor, value[:16])
            return real_os.write(descriptor, value)

    monkeypatch.setattr(ipc_ring, "os", LocalOS())

    def mapped(descriptor, length, *args, **kwargs):
        if state.constructor_failure == "mmap":
            raise state.failure
        result = real_mmap.mmap(descriptor, length, *args, **kwargs)
        state.maps.append(result)
        return result

    monkeypatch.setattr(ipc_ring, "mmap", SimpleNamespace(mmap=mapped))

    def close_owned():
        for mapping in reversed(state.maps):
            if not mapping.closed:
                mapping.close()
        for file in reversed(state.files):
            if not file.closed:
                file.close()
        for descriptor in tuple(state.pending):
            ipc_ring.os.close(descriptor)

    state.close_owned = close_owned
    try:
        yield state
    finally:
        state.release.set()
        for thread in state.threads:
            if thread.ident is not None:
                thread.join(_TIMEOUT)
        assert all(not thread.is_alive() for thread in state.threads), "UNRESOLVED owned fixture thread"
        close_owned()
        assert not state.pending
        assert all(file.closed for file in state.files)
        assert all(mapping.closed for mapping in state.maps)
        assert secure_store._ACTIVE_LEASE is None
        assert getattr(secure_store._TRANSACTION_LOCAL, "record", None) is None


@pytest.mark.parametrize("encoded", [
    b"ab" * 32, b"AB" * 32, b"  " + b"ab" * 32 + b"\t\r\n",
    b"ab " * 32, b" " * (4096 - 64) + b"ab" * 32,
], ids=["plain", "uppercase", "edge-whitespace", "interior-whitespace", "max-padding"])
def test_existing_valid_key_is_bounded_stable_and_never_rotated(private_authority, encoded):
    state = private_authority
    state.key.write_bytes(encoded)
    try:
        assert ipc_ring._load_or_create_key(state.key) == bytes.fromhex("ab" * 32)
        assert state.generated == [] and state.key.read_bytes() == encoded
        assert state.reads and all(size == len(encoded) + 1 and consumed == len(encoded)
                                   for _thread, size, consumed in state.reads)
        assert all(size <= 4097 for _thread, size, _consumed in state.reads)
        assert len(state.reads) == 2  # complete raw-byte readback after custody
        assert all(held for _phase, held in state.custody_records)
        assert state.product_unlinks == [] and not state.pending
    finally:
        state.close_owned()


@pytest.mark.parametrize("encoded", [b"", b"gg" * 32, b"ab", b"a" * 63, bytes([255]) * 64])
def test_existing_malformed_key_fails_without_generation_or_rewrite(private_authority, encoded):
    state = private_authority
    state.key.write_bytes(encoded)
    try:
        with pytest.raises(RuntimeError):
            ipc_ring._load_or_create_key(state.key)
        assert state.key.read_bytes() == encoded
        assert state.generated == [] and state.product_unlinks == []
        assert not state.pending and all(file.closed for file in state.files)
    finally:
        state.close_owned()


def test_oversize_key_is_refused_before_any_content_read(private_authority):
    state = private_authority
    original = b"0" * 4097
    state.key.write_bytes(original)
    try:
        with pytest.raises(RuntimeError):
            ipc_ring._load_or_create_key(state.key)
        assert state.reads == [] and state.generated == []
        assert state.key.read_bytes() == original and state.product_unlinks == []
        assert not state.pending
    finally:
        state.close_owned()


@pytest.mark.parametrize("mutation", ["grow", "shrink"])
def test_changed_held_key_cannot_return_authority(private_authority, mutation):
    state = private_authority
    state.key.write_bytes(_FAKE_KEY.hex().encode("ascii"))
    state.read_mutation = mutation
    try:
        with pytest.raises(RuntimeError):
            ipc_ring._load_or_create_key(state.key)
        assert len(state.reads) == 1 and state.reads[0][1] == 65
        assert state.generated == [] and state.product_unlinks == [] and not state.pending
    finally:
        state.close_owned()


@pytest.mark.parametrize("existing", [False, True])
def test_parent_refusal_does_not_read_create_or_accept_key(private_authority, existing):
    state = private_authority
    original = _WINNER.hex().encode("ascii")
    if existing:
        state.key.write_bytes(original)
    state.required = state.parent_refused = True
    try:
        with pytest.raises(PermissionError, match="parent refusal"):
            ipc_ring._load_or_create_key(state.key)
        assert state.reads == [] and state.create_attempts == 0
        assert state.key.exists() is existing
        if existing:
            assert state.key.read_bytes() == original
        # The old baseline may generate one candidate before this refusal.
        # This control asserts no byte access/create/acceptance, not RNG order.
    finally:
        state.close_owned()


def test_competing_cooperative_caller_never_reads_pending_key(private_authority, monkeypatch):
    state = private_authority
    state.hold_first = True
    results, errors = {}, {}

    class ObservedLock:
        def acquire(self, *args, **kwargs):
            if threading.current_thread().name == "private-second":
                state.attempted.set()
            return state.local_lock.acquire(*args, **kwargs)

        def release(self):
            return state.local_lock.release()

    monkeypatch.setattr(secure_store, "_TRANSACTION_LOCK", ObservedLock())

    def load(label):
        try:
            results[label] = ipc_ring._load_or_create_key(state.key)
        except BaseException as exc:
            errors[label] = exc

    first = threading.Thread(target=load, args=("first",), name="private-first")
    second = threading.Thread(target=load, args=("second",), name="private-second")
    state.threads.extend((first, second))
    try:
        first.start()
        assert state.first_secure.wait(_TIMEOUT), "first caller did not reach final custody"
        pending_bytes = state.key.read_bytes()
        assert pending_bytes == _FAKE_KEY.hex().encode("ascii")
        second.start()
        assert state.attempted.wait(_TIMEOUT), "second caller bypassed transaction admission"
        assert all(name != "private-second" for name, _size, _consumed in state.reads)
        assert state.generated == ["private-first"]
        assert state.key.read_bytes() == pending_bytes
    finally:
        state.release.set()
        for thread in state.threads:
            if thread.ident is not None:
                thread.join(_TIMEOUT)
        assert all(not thread.is_alive() for thread in state.threads)
    assert results.get("first") == _FAKE_KEY and "first" not in errors
    if "second" in errors:
        assert isinstance(errors["second"], TimeoutError)  # visible bounded busy is permitted
    else:
        assert results["second"] == _FAKE_KEY
    assert state.generated == ["private-first"]
    assert state.key.read_bytes() == _FAKE_KEY.hex().encode("ascii")


def test_local_admission_exhaustion_has_no_key_access(private_authority, monkeypatch):
    state = private_authority
    monkeypatch.setattr(secure_store, "_TRANSACTION_WAIT_SECONDS", 0.0)
    errors = []

    def contend():
        try:
            ipc_ring._load_or_create_key(state.key)
        except BaseException as exc:
            errors.append(exc)

    contender = threading.Thread(target=contend, name="private-exhausted")
    state.threads.append(contender)
    state.local_lock.acquire()
    try:
        contender.start()
        contender.join(_TIMEOUT)
        assert not contender.is_alive()
        assert len(errors) == 1 and isinstance(errors[0], TimeoutError)
        assert state.reads == state.generated == [] and state.create_attempts == 0
        assert not state.key.exists()
    finally:
        state.local_lock.release()


@pytest.mark.parametrize("existing", [False, True])
def test_os_lease_refusal_has_no_key_access(private_authority, monkeypatch, existing):
    state = private_authority
    original = _WINNER.hex().encode("ascii")
    if existing:
        state.key.write_bytes(original)

    def refuse(_path):
        raise ExclusiveFileLeaseError("controlled independent lease contention")

    monkeypatch.setattr(secure_store, "_CredentialLease", refuse)
    try:
        with pytest.raises(ExclusiveFileLeaseError, match="controlled independent lease"):
            ipc_ring._load_or_create_key(state.key)
        assert state.reads == state.generated == [] and state.create_attempts == 0
        assert state.key.exists() is existing
        if existing:
            assert state.key.read_bytes() == original
    finally:
        state.close_owned()


def test_one_custody_quarantine_is_reclassified_without_recursion(private_authority):
    state = private_authority
    rejected = b"known-unsafe-private-value"
    state.key.write_bytes(rejected)
    state.quarantine = "once"
    try:
        assert ipc_ring._load_or_create_key(state.key) == _FAKE_KEY
        assert state.rejected.read_bytes() == rejected
        assert state.key.read_bytes() == _FAKE_KEY.hex().encode("ascii")
        assert state.prepare_calls == 1 and len(state.generated) == 1
        assert state.product_unlinks == [] and not state.pending
        assert all(held for _phase, held in state.custody_records)
    finally:
        state.close_owned()


def test_repeated_custody_refusal_stops_at_two_rounds(private_authority):
    state = private_authority
    original = _WINNER.hex().encode("ascii")
    state.key.write_bytes(original)
    state.quarantine = "refuse"
    try:
        with pytest.raises(RuntimeError, match="changed repeatedly"):
            ipc_ring._load_or_create_key(state.key)
        assert state.prepare_calls == 2 and state.reads == [] and state.generated == []
        assert state.key.read_bytes() == original and state.product_unlinks == []
    finally:
        state.close_owned()


def test_genuine_create_collision_returns_only_validated_winner(private_authority):
    state = private_authority
    state.collision = "winner"
    try:
        assert ipc_ring._load_or_create_key(state.key) == _WINNER
        assert state.key.read_bytes() == _WINNER.hex().encode("ascii")
        assert state.create_attempts == 1 and len(state.generated) == 1
        assert state.product_unlinks == [] and not state.pending
        assert state.reads and all(0 <= size <= 4097 for _thread, size, _consumed in state.reads)
    finally:
        state.close_owned()


def test_repeated_real_create_collisions_exhaust_without_recursion(private_authority):
    state = private_authority
    state.collision = "churn"
    try:
        with pytest.raises(RuntimeError, match="changed repeatedly"):
            ipc_ring._load_or_create_key(state.key)
        assert state.create_attempts == 2 and len(state.generated) == 2
        assert state.reads == [] and state.product_unlinks == [] and not state.pending
        assert not state.key.exists()
    finally:
        state.close_owned()


@pytest.mark.parametrize("failure", ["raise", "return"])
def test_failed_final_custody_never_unlinks_substituted_winner(private_authority, failure):
    state = private_authority
    state.custody_failure = failure
    try:
        with pytest.raises(RuntimeError) as caught:
            ipc_ring._load_or_create_key(state.key)
        if failure == "raise":
            assert caught.value is state.failure
        assert state.key.read_bytes() == _WINNER.hex().encode("ascii")
        assert state.product_unlinks == [] and not state.pending
    finally:
        state.close_owned()


def test_short_creation_retains_failed_state_for_explicit_recovery(private_authority):
    state = private_authority
    state.write_failure = "short"
    try:
        with pytest.raises(RuntimeError, match="incomplete"):
            ipc_ring._load_or_create_key(state.key)
        partial = _FAKE_KEY.hex().encode("ascii")[:16]
        assert state.key.read_bytes() == partial and not state.pending
        generation_count = len(state.generated)
        with pytest.raises(RuntimeError):
            ipc_ring._load_or_create_key(state.key)
        assert len(state.generated) == generation_count
        assert state.key.read_bytes() == partial and state.product_unlinks == []
    finally:
        state.close_owned()


@pytest.mark.parametrize("stage", ["fdopen", "mmap", "header-read", "header-init"])
def test_constructor_failure_closes_actual_resources_before_fallback(private_authority, monkeypatch, stage):
    state = private_authority
    state.constructor_failure = stage
    partial = ipc_ring.RingWriter.__new__(ipc_ring.RingWriter)
    if stage in {"header-read", "header-init"}:
        name = "_read_header" if stage == "header-read" else "_init_header"
        original = getattr(ipc_ring._RingBase, name)

        def genuine_then_fail(self):
            original(self)
            raise state.failure

        monkeypatch.setattr(ipc_ring._RingBase, name, genuine_then_fail)
    try:
        with pytest.raises(_InjectedFailure) as caught:
            ipc_ring.RingWriter.__init__(partial, state.ring, slot_count=2, slot_size=128, key=_FAKE_KEY)
        assert caught.value is state.failure
        # These observations precede independent fallback and retain all real objects.
        assert not state.pending
        assert all(file.closed for file in state.files)
        assert all(mapping.closed for mapping in state.maps)
        if stage == "fdopen":
            descriptor, _path = state.opened[0]
            with pytest.raises(OSError) as closed:
                real_os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
        else:
            assert len(state.files) == 1
            assert len(state.maps) == (0 if stage == "mmap" else 1)
    finally:
        state.close_owned()


def test_serial_reuse_and_real_authenticated_ring_round_trip(private_authority):
    state = private_authority
    try:
        first = ipc_ring._load_or_create_key(state.key)
        assert first == _FAKE_KEY
        assert ipc_ring._load_or_create_key(state.key) == first
        assert state.key.read_bytes() == first.hex().encode("ascii") and len(state.generated) == 1
        with ipc_ring.RingWriter(state.ring, slot_count=2, slot_size=128, key=first) as writer:
            with ipc_ring.RingReader(state.ring, slot_count=2, slot_size=128, key=first) as reader:
                assert writer.write(b"private-authenticated-frame", sensor_id=7)
                batch = reader.read_batch()
                assert len(batch) == 1 and batch[0]["payload"] == b"private-authenticated-frame"
                assert batch[0]["sensor_id"] == 7 and batch[0]["seq"] == 0
                assert reader.authentication_failures == 0
        assert all(file.closed for file in state.files)
        assert all(mapping.closed for mapping in state.maps)
        assert not state.pending and state.product_unlinks == []
    finally:
        state.close_owned()


@pytest.fixture
def inert_key_metadata(monkeypatch):
    """Exact stat semantics only: fd42 is an inert token, never an OS handle."""
    named = dict(st_mode=0o100600, st_dev=7, st_ino=11, st_size=64,
                 st_mtime_ns=100, st_ctime_ns=200, st_birthtime_ns=200,
                 st_nlink=1, st_file_attributes=0)
    held = dict(named, st_ctime_ns=300)
    state = SimpleNamespace(
        named=[dict(named), dict(named)], held=[dict(held), dict(held)],
        opens=0, stats=0, named_checks=0, reads=[], closes=0, closed=False,
        raw=b"ab" * 32,
    )

    def no_host(*args, **kwargs):
        pytest.fail("inert metadata attempted default/installed key access")

    for name in ("_key_path", "_data_dir", "ring_path"):
        monkeypatch.setattr(ipc_ring, name, no_host)

    class InertPath:
        def lstat(self):
            assert state.named_checks < len(state.named)
            value = state.named[state.named_checks]
            state.named_checks += 1
            return SimpleNamespace(**value)

        def __str__(self):
            return "<inert-private-key>"

    state.path = InertPath()

    def opened(path, flags):
        assert path is state.path and flags == 0 and state.opens == 0
        state.opens += 1
        return 42

    def descriptor_stat(descriptor):
        assert descriptor == 42 and not state.closed and state.stats < len(state.held)
        value = state.held[state.stats]
        state.stats += 1
        return SimpleNamespace(**value)

    def read(descriptor, limit):
        assert descriptor == 42 and not state.closed and limit == 65
        state.reads.append(limit)
        return state.raw

    def close(descriptor):
        assert descriptor == 42 and not state.closed
        state.closed = True
        state.closes += 1

    proxy = SimpleNamespace(name="nt", O_RDONLY=0, O_BINARY=0, O_NOFOLLOW=0,
                            open=opened, fstat=descriptor_stat, read=read, close=close)
    monkeypatch.setattr(ipc_ring, "os", proxy)
    state.os = proxy
    try:
        yield state
    finally:
        # No independent close can give the product cleanup credit.
        if state.opens:
            assert state.closed and state.closes == 1


@pytest.mark.parametrize("platform", ["windows-new", "windows-old", "posix"])
def test_key_metadata_accepts_exact_comparable_platform_timestamps(inert_key_metadata, platform):
    state = inert_key_metadata
    if platform == "windows-old":
        for value in state.named + state.held:
            value.pop("st_birthtime_ns")
        for value in state.held:
            value["st_ctime_ns"] = 200
    elif platform == "posix":
        state.os.name = "posix"
        for value in state.held:
            value["st_ctime_ns"] = 200
            value["st_birthtime_ns"] = 999  # POSIX ctime, not birth time, is comparable.
    key, identity, raw = ipc_ring._read_ring_key(state.path)
    assert key == bytes.fromhex("ab" * 32) and identity == (7, 11) and raw == state.raw
    assert state.reads == [65] and state.stats == state.named_checks == 2
    assert state.closed and state.closes == 1


@pytest.mark.parametrize("field", [
    "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns",
])
def test_key_metadata_cross_api_mismatch_is_refused(inert_key_metadata, field):
    state = inert_key_metadata
    for value in state.held:
        value[field] += 1
    with pytest.raises(RuntimeError, match="changed before read"):
        ipc_ring._read_ring_key(state.path)
    assert state.reads == [] and state.closed and state.closes == 1


def test_key_metadata_held_raw_change_time_drift_is_refused(inert_key_metadata):
    state = inert_key_metadata
    state.held[1]["st_ctime_ns"] += 1
    with pytest.raises(RuntimeError, match="changed during read"):
        ipc_ring._read_ring_key(state.path)
    assert state.reads == [65] and state.stats == 2
    assert state.closed and state.closes == 1


def test_key_metadata_named_raw_change_time_drift_is_refused(inert_key_metadata):
    state = inert_key_metadata
    state.named[1]["st_ctime_ns"] += 1
    with pytest.raises(RuntimeError, match="changed during read"):
        ipc_ring._read_ring_key(state.path)
    assert state.reads == [65] and state.named_checks == 2
    assert state.closed and state.closes == 1


@pytest.mark.parametrize("platform", ["windows-old", "posix"])
def test_key_metadata_ctime_fallback_remains_exact_across_apis(inert_key_metadata, platform):
    state = inert_key_metadata
    if platform == "posix":
        state.os.name = "posix"
    else:
        for value in state.named + state.held:
            value.pop("st_birthtime_ns")
    # Held raw300 versus named raw200 must be refused on these contracts.
    with pytest.raises(RuntimeError, match="changed before read"):
        ipc_ring._read_ring_key(state.path)
    assert state.reads == [] and state.closed and state.closes == 1
