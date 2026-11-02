"""Inert writer gates using temporary files and fixture authority only."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.core.file_lease as lease_module
import angerona.core.module_base as producer
from angerona.core.eventbus import Event, Severity


KEY = b"k" * 32
TB = 'Traceback:\n  File "D:/fixture/angerona/example.py", line 7, in run\nRuntimeError: fixture'


def _bundle(**overrides):
    values = {
        "module": "Fixture", "error": "fixture error", "tb": TB,
        "memory": {}, "memory_available": False, "events": [], "crashed_at": 1.0,
    }
    values.update(overrides)
    return producer._bounded_crash_snapshot_bundle(**values)


def _encoded(bundle):
    document = producer.sign_crash_snapshot_bundle(bundle, key=KEY)
    return json.dumps(
        document, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
    ).encode("utf-8")


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "snapshots"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture(autouse=True)
def inert_lease(monkeypatch):
    class Lease:
        def __init__(self, _path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    # Lease mechanics have separate tests. Faults below must target the record
    # boundary rather than an incidental fsync in lock-file bootstrap.
    monkeypatch.setattr(lease_module, "ExclusiveFileLease", Lease)
    monkeypatch.setattr(producer, "_CRASH_SNAPSHOT_CUSTODY_UNKNOWN", None)
    # Every test stubs free space. No gate samples a real host volume.
    monkeypatch.setattr(producer.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(producer, "_snapshot_verify_windows_directory", lambda _path: None)


@pytest.mark.parametrize("owner", ["S-1-5-21-fixture-user", "S-1-5-18", "S-1-5-32-544"])
def test_source_and_historical_admin_directory_owners_are_admitted(owner):
    user = "S-1-5-21-fixture-user"
    assert producer._snapshot_acl_admitted(owner, user, [("allow", user), ("allow", "S-1-5-32-544")])


@pytest.mark.parametrize("owner,aces", [
    ("S-1-5-21-foreign", [("allow", "S-1-5-32-544")]),
    ("S-1-5-32-544", [("allow", "S-1-1-0")]),
    ("S-1-5-32-544", [("unsupported", "S-1-5-32-544")]),
    ("S-1-5-32-544", []),
])
def test_foreign_or_unknown_directory_acl_is_held_without_repair(owner, aces):
    assert not producer._snapshot_acl_admitted(owner, "S-1-5-21-fixture-user", aces)


def test_legacy_exact_eight_field_v1_hmac_is_unchanged():
    legacy = {
        "module": "Fixture", "crashed_at": 1.0, "error": "fixture",
        "traceback": TB, "memory": {}, "last_50_events": [],
    }
    document = producer.sign_crash_snapshot_bundle(legacy, key=KEY)
    body = dict(legacy, snapshot_schema=1)
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    expected = hmac.new(KEY, b"angerona/crash-snapshot/v1\x00" + canonical, hashlib.sha256).hexdigest()
    assert set(document) == {
        "snapshot_schema", "module", "crashed_at", "error", "traceback",
        "memory", "last_50_events", "snapshot_hmac",
    }
    assert document["snapshot_hmac"] == expected
    assert producer.verify_crash_snapshot_bundle(document, key=KEY)
    assert not producer.verify_crash_snapshot_bundle(document, key=b"x" * 32)
    assert not producer.verify_crash_snapshot_bundle(dict(document, extra=True), key=KEY)


@pytest.mark.parametrize("character", ["界", "😀", "\x00", '"', "\\", "a"])
def test_fifty_long_events_and_error_fit_actual_encoded_record(character):
    events = [Event(module=character * 128, severity=Severity.HIGH, message=character * 4096, ts=1.0) for _ in range(50)]
    bundle = _bundle(module=character * 1000, error=character * 100_000, events=events)
    encoded = _encoded(bundle)
    capture = bundle["memory"]["capture"]
    assert len(encoded) <= 480 * 1024 < 512 * 1024
    assert producer.verify_crash_snapshot_bundle(json.loads(encoded), key=KEY)
    assert capture["events"]["returned"] == capture["events"]["retained"] == 50
    assert capture["text"]["error"]["omitted_chars"] > 0
    for record, loss in zip(bundle["last_50_events"], capture["events"]["text"]):
        assert loss["message"]["retained_chars"] == len(record["message"])
        assert loss["message"]["original_chars"] == 4096
        assert loss["message"]["omitted_chars"] == 4096 - len(record["message"])


@pytest.mark.parametrize(
    "traceback_text",
    [TB + "a" * 300_000, TB + "界" * 300_000, TB + "\x00" * 100_000],
    ids=["ascii", "unicode", "controls"],
)
def test_incomplete_traceback_is_never_a_top_level_source_candidate(traceback_text):
    bundle = _bundle(tb=traceback_text)
    capture = bundle["memory"]["capture"]
    excerpt = capture["traceback_excerpt"]
    assert bundle["traceback"] == ""
    assert capture["traceback_complete"] is False
    assert traceback_text.startswith(excerpt["head"])
    assert traceback_text.endswith(excerpt["tail"])
    retained = len(excerpt["head"]) + len(excerpt["tail"])
    assert capture["text"]["traceback"]["retained_chars"] == retained
    assert capture["text"]["traceback"]["omitted_chars"] == len(traceback_text) - retained
    assert retained <= len(traceback_text)
    assert len(_encoded(bundle)) <= 480 * 1024


def test_complete_traceback_is_exact_and_loss_metadata_is_authenticated():
    bundle = _bundle()
    capture = bundle["memory"]["capture"]
    assert bundle["traceback"] == TB
    assert capture["traceback_complete"] is True
    assert capture["traceback_excerpt"] == {"head": "", "tail": ""}
    document = producer.sign_crash_snapshot_bundle(bundle, key=KEY)
    document["memory"]["capture"]["text"]["error"]["omitted_chars"] += 1
    assert not producer.verify_crash_snapshot_bundle(document, key=KEY)


def test_combined_traceback_events_error_and_metadata_fit_record():
    events = [Event(module="界" * 1000, message="\x00" * 4096, ts=1.0) for _ in range(50)]
    bundle = _bundle(tb=TB + "界" * 200_000, error="\x00" * 100_000, events=events)
    assert len(_encoded(bundle)) <= 480 * 1024


def test_non_string_fields_are_explicitly_unavailable_without_str_hooks():
    class Hostile:
        def __str__(self):
            raise AssertionError("must not stringify an arbitrary diagnostic object")

    event = Event(module=Hostile(), message=Hostile(), severity=Hostile(), ts=True)
    bundle = _bundle(module=Hostile(), error=Hostile(), events=[event, Hostile()])
    capture = bundle["memory"]["capture"]
    assert bundle["module"] == bundle["error"] == ""
    assert capture["text"]["module"] == {
        "original_chars": None, "retained_chars": 0, "omitted_chars": None, "unavailable": True,
    }
    assert capture["events"]["retained"] == capture["events"]["omitted"] == 1
    assert bundle["last_50_events"] == [{"ts": None, "module": "", "severity": "", "message": ""}]
    assert capture["events"]["text"][0]["timestamp_available"] is False


@pytest.mark.parametrize("events", [None, object(), [None] * 51])
def test_unavailable_event_collection_has_unknown_counts(events):
    capture = _bundle(events=events)["memory"]["capture"]["events"]
    assert capture == {
        "requested": 50, "returned": None, "retained": 0,
        "omitted": None, "unavailable": True, "text": [],
    }


@pytest.mark.parametrize("overrides", [
    {"memory_available": 1}, {"memory_available": True, "memory": {"extra": "bad"}},
    {"memory_available": True, "memory": {"rss_mb": float("nan"), "vms_mb": 1, "percent": 1}},
    {"crashed_at": float("nan")}, {"crashed_at": True},
])
def test_invalid_capture_scalars_refuse_typed(overrides):
    with pytest.raises(producer._SnapshotCaptureError):
        _bundle(**overrides)


def test_unpaired_unicode_is_refused_without_replacement():
    with pytest.raises(producer._SnapshotCaptureError):
        _bundle(error="\ud800" * 100)


def test_same_time_records_publish_to_distinct_generated_names(monkeypatch, directory):
    monkeypatch.setattr(producer.time, "time_ns", lambda: 123)
    tokens = iter(["a" * 32, "b" * 32])
    monkeypatch.setattr(producer.uuid, "uuid4", lambda: SimpleNamespace(hex=next(tokens)))
    assert producer._publish_crash_snapshot_bytes(directory, b"first") == "published"
    assert producer._publish_crash_snapshot_bytes(directory, b"second") == "published"
    assert sorted(path.read_bytes() for path in directory.glob("*.json")) == [b"first", b"second"]


def test_forced_final_collision_preserves_old_bytes(monkeypatch, directory):
    monkeypatch.setattr(producer.time, "time_ns", lambda: 123)
    monkeypatch.setattr(producer.uuid, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    old = directory / f"crash.123.{'a' * 32}.json"
    old.write_bytes(b"authenticated historical original")
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_write"
    assert old.read_bytes() == b"authenticated historical original"
    assert list(directory.glob("*.tmp")) == []


@pytest.mark.parametrize("boundary", ["create", "fsync", "publish"])
def test_prepublication_fault_never_exposes_partial_json(monkeypatch, directory, boundary):
    historical = directory / "old.json"
    historical.write_bytes(b"old")

    def fail(*_args, **_kwargs):
        raise OSError("injected inert boundary refusal")

    target, name = {
        "create": (producer, "_snapshot_create_private"),
        "fsync": (producer.os, "fsync"),
        "publish": (producer, "_snapshot_publish_new"),
    }[boundary]
    monkeypatch.setattr(target, name, fail)
    assert producer._publish_crash_snapshot_bytes(directory, b"complete-new-record") == "held_write"
    assert [(path.name, path.read_bytes()) for path in directory.glob("*.json")] == [("old.json", b"old")]
    assert list(directory.glob("*.tmp")) == []


@pytest.mark.parametrize("fault", ["short_write", "write"])
def test_unbuffered_write_failures_leave_no_final(monkeypatch, directory, fault):
    original_write = os.write

    def write(descriptor, body):
        assert list(directory.glob("*.json")) == []
        if fault == "write":
            raise OSError("injected unbuffered write failure")
        return original_write(descriptor, body[:3])

    monkeypatch.setattr(producer.os, "write", write)
    assert producer._publish_crash_snapshot_bytes(directory, b"complete-new-record") == "held_write"
    assert list(directory.glob("*.json")) == []


def test_count_admission_preserves_zero_byte_history(monkeypatch, directory):
    monkeypatch.setattr(producer, "_MAX_CRASH_RECORDS", 2)
    (directory / "empty.json").write_bytes(b"")
    (directory / "original.json").write_bytes(b"old")
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_storage_budget"
    assert (directory / "empty.json").read_bytes() == b""
    assert (directory / "original.json").read_bytes() == b"old"


def test_byte_admission_includes_abandoned_private_temporary(monkeypatch, directory):
    monkeypatch.setattr(producer, "_MAX_CRASH_DIRECTORY_BYTES", 8)
    (directory / ".crash.abandoned.tmp").write_bytes(b"123456")
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_storage_budget"
    assert (directory / ".crash.abandoned.tmp").read_bytes() == b"123456"


def test_entry_limit_and_unsafe_entry_hold_without_recursion(monkeypatch, directory):
    monkeypatch.setattr(producer, "_MAX_CRASH_DIRECTORY_ENTRIES", 1)
    (directory / "a.json").write_bytes(b"a")
    (directory / "b.json").write_bytes(b"b")
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_accounting"
    monkeypatch.setattr(producer, "_MAX_CRASH_DIRECTORY_ENTRIES", 1024)
    (directory / "nested-private-evidence").mkdir()
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_accounting"
    assert len(list(directory.glob("*.json"))) == 2


def test_busy_process_or_cooperating_lease_is_visible(monkeypatch, directory):
    producer._CRASH_SNAPSHOT_WRITE_LOCK.acquire()
    try:
        assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_busy"
    finally:
        producer._CRASH_SNAPSHOT_WRITE_LOCK.release()

    def busy(_path):
        raise lease_module.ExclusiveFileLeaseError("fixture busy")

    monkeypatch.setattr(lease_module, "ExclusiveFileLease", busy)
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_busy"
    assert list(directory.glob("*.json")) == []


def test_custody_latched_during_lock_acquire_blocks_all_admission_work(monkeypatch, directory):
    releases = []
    calls = []
    uncertain = ("transfer", directory / "uncertain.tmp", object(), 42)

    class Lock:
        def acquire(self, *, blocking):
            assert blocking is False
            # Deterministic interleaving: another writer latched unknown after
            # this caller's initial check, before it acquired the write lock.
            producer._CRASH_SNAPSHOT_CUSTODY_UNKNOWN = uncertain
            return True

        def release(self):
            releases.append(True)

    def forbidden(*_args, **_kwargs):
        calls.append(True)
        pytest.fail("latched custody must refuse before any admission or creation")

    monkeypatch.setattr(producer, "_CRASH_SNAPSHOT_WRITE_LOCK", Lock())
    monkeypatch.setattr(lease_module, "ExclusiveFileLease", forbidden)
    for name in (
        "_snapshot_plain_directory", "_snapshot_directory_admission",
        "_snapshot_free_space_admission", "_snapshot_create_private",
    ):
        monkeypatch.setattr(producer, name, forbidden)
    assert producer._CRASH_SNAPSHOT_CUSTODY_UNKNOWN is None
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "held_custody_unknown"
    assert producer._CRASH_SNAPSHOT_CUSTODY_UNKNOWN is uncertain
    assert calls == []
    assert releases == [True]
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("free,expected", [
    (None, "held_space_unknown"), (True, "held_space_unknown"),
    (-1, "held_space_unknown"), ("unknown", "held_space_unknown"),
    (2 * 1024**3, "held_free_space"),
])
def test_free_space_admission_holds_before_temporary_creation(monkeypatch, directory, free, expected):
    samples = []
    monkeypatch.setattr(producer.shutil, "disk_usage", lambda path: samples.append(path) or SimpleNamespace(free=free))
    monkeypatch.setattr(producer, "_snapshot_create_private", lambda _path: pytest.fail("must refuse before creating a temporary"))
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == expected
    assert samples == [directory]
    assert list(directory.glob("*.json")) == []


def test_free_space_probe_failure_is_unknown_and_non_destructive(monkeypatch, directory):
    def unavailable(_path):
        raise OSError("fixture unavailable")

    monkeypatch.setattr(producer.shutil, "disk_usage", unavailable)
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_space_unknown"
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("error", [
    lease_module.ExclusiveFileLeaseError("fixture lease retirement gap"),
    producer._SnapshotStorageHeld("held_storage_budget"),
])
def test_lease_finalization_refusal_keeps_known_publication(monkeypatch, directory, error):
    class FailingRetirement:
        def __init__(self, _path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            raise error

    published = []
    publish = producer._snapshot_publish_new

    def count_publication(temporary, destination):
        publish(temporary, destination)
        published.append(destination)

    monkeypatch.setattr(lease_module, "ExclusiveFileLease", FailingRetirement)
    monkeypatch.setattr(producer, "_snapshot_publish_new", count_publication)
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "published_finalization_gap"
    assert len(published) == 1
    assert [path.read_bytes() for path in directory.glob("*.json")] == [b"complete"]


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_unsafe_existing_file_alias_refuses_without_touching_target(directory, kind):
    target = directory.parent / "outside-evidence"
    target.write_bytes(b"preserve")
    alias = directory / "alias.json"
    try:
        if kind == "symlink":
            alias.symlink_to(target)
        else:
            os.link(target, alias)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"fixture alias unavailable: {type(exc).__name__}")
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_accounting"
    assert target.read_bytes() == b"preserve"


def test_ambiguously_raised_publication_preserves_exact_new_final(monkeypatch, directory):
    publish = producer._snapshot_publish_new
    publications = []

    def publish_then_raise(temporary, destination):
        publish(temporary, destination)
        publications.append(destination)
        raise OSError("fixture error after publication")

    monkeypatch.setattr(producer, "_snapshot_publish_new", publish_then_raise)
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "published_finalization_gap"
    assert len(publications) == 1
    assert [path.read_bytes() for path in directory.glob("*.json")] == [b"complete"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-fsync boundary")
def test_postpublication_sync_failure_preserves_committed_record(monkeypatch, directory):
    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(descriptor):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture directory fsync refusal")
        real_fsync(descriptor)

    monkeypatch.setattr(producer.os, "fsync", fail_directory_fsync)
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "published_durability_gap"
    assert [path.read_bytes() for path in directory.glob("*.json")] == [b"complete"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard-link temporary cleanup boundary")
def test_postpublication_cleanup_failure_retains_final_and_temporary(monkeypatch, directory):
    real_unlink = Path.unlink

    def held_unlink(path, *args, **kwargs):
        if path.parent == directory and path.suffix == ".tmp":
            raise PermissionError("fixture cleanup held")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", held_unlink)
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "published_cleanup_gap"
    assert [path.read_bytes() for path in directory.glob("*.json")] == [b"complete"]
    assert [path.read_bytes() for path in directory.glob("*.tmp")] == [b"complete"]


def test_record_bound_refuses_before_creating_any_file(directory):
    assert producer._publish_crash_snapshot_bytes(directory, b"x" * (480 * 1024 + 1)) == "held_capture_bound"
    assert list(directory.iterdir()) == []


def test_unknown_open_file_identity_is_held_without_guessing_cleanup(monkeypatch, directory):
    real_fstat = os.fstat

    def unknown_identity(descriptor):
        info = real_fstat(descriptor)
        return SimpleNamespace(
            st_dev=info.st_dev, st_ino=0, st_mode=info.st_mode,
            st_nlink=info.st_nlink, st_size=info.st_size,
        )

    monkeypatch.setattr(producer.os, "fstat", unknown_identity)
    assert producer._publish_crash_snapshot_bytes(directory, b"new") == "held_directory"
    assert list(directory.glob("*.json")) == []
    # No trustworthy identity was obtained for exact cleanup. Preserve the
    # exclusive private empty temporary and account it in later admission.
    assert [path.read_bytes() for path in directory.glob("*.tmp")] == [b""]


@pytest.mark.parametrize("stage,error", [("success", None), ("transfer", OSError)])
def test_windows_handle_transfer_success_or_documented_refusal(monkeypatch, directory, stage, error):
    import sys

    wrapper_closes = []
    native_closes = []
    transfers = []

    class Handle:
        def Detach(self):
            return 42

        def Close(self):
            wrapper_closes.append(42)

    def transfer(raw, flags):
        transfers.append((raw, flags))
        if stage == "transfer":
            raise error("fixture transfer refusal")
        return 7

    monkeypatch.setattr(producer, "os", SimpleNamespace(name="nt", O_WRONLY=1))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=transfer))
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(CloseHandle=native_closes.append))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(
        GENERIC_WRITE=1, FILE_SHARE_READ=1, CREATE_NEW=1, FILE_ATTRIBUTE_NORMAL=1,
    ))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CreateFile=lambda *_args: Handle()))
    monkeypatch.setitem(sys.modules, "angerona.core.engine_transport", SimpleNamespace(_windows_private_attributes=lambda: None))
    if error is None:
        assert producer._snapshot_create_private(directory / "fixture.tmp") == 7
        assert wrapper_closes == native_closes == []
        assert len(transfers) == 1
    else:
        with pytest.raises(error):
            producer._snapshot_create_private(directory / "fixture.tmp")
        assert wrapper_closes == []
        assert native_closes == [42]
        assert len(transfers) == 1
    assert producer._CRASH_SNAPSHOT_CUSTODY_UNKNOWN is None


@pytest.mark.parametrize("phase", ["detach", "transfer", "refusal_close"])
def test_ambiguous_windows_handoff_never_recloses_or_creates_again(monkeypatch, directory, phase):
    import sys

    creations = []
    wrapper_closes = []
    native_closes = []
    adopted = []

    class Handle:
        def Detach(self):
            if phase == "detach":
                raise KeyboardInterrupt("fixture interrupted detach")
            return 42

        def Close(self):
            wrapper_closes.append(42)

    wrapper = Handle()

    def create(path, *_args):
        creations.append(path)
        Path(path).write_bytes(b"")
        return wrapper

    def transfer(raw, _flags):
        if phase == "refusal_close":
            raise OSError("documented non-adopting refusal")
        adopted.append(raw)
        # The fake has already adopted the handle. Closing raw here would
        # violate custody and might close a reused handle in a real process.
        raise KeyboardInterrupt("fixture after CRT adoption, before result")

    def close(raw):
        native_closes.append(raw)
        raise KeyboardInterrupt("fixture ambiguous refusal cleanup")

    file_operations = dict(vars(os))
    file_operations["name"] = "nt"
    monkeypatch.setattr(producer, "os", SimpleNamespace(**file_operations))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=transfer))
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(CloseHandle=close))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(
        GENERIC_WRITE=1, FILE_SHARE_READ=1, CREATE_NEW=1, FILE_ATTRIBUTE_NORMAL=1,
    ))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CreateFile=create))
    monkeypatch.setitem(sys.modules, "angerona.core.engine_transport", SimpleNamespace(_windows_private_attributes=lambda: None))
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "held_custody_unknown"
    retained = producer._CRASH_SNAPSHOT_CUSTODY_UNKNOWN
    assert retained is not None
    temporary = retained[1]
    assert temporary.parent == directory and temporary.suffix == ".tmp"
    assert retained == (phase, temporary, wrapper, None if phase == "detach" else 42)
    assert wrapper_closes == []
    assert native_closes == ([42] if phase == "refusal_close" else [])
    assert adopted == ([42] if phase == "transfer" else [])
    assert temporary.read_bytes() == b""
    monkeypatch.setattr(lease_module, "ExclusiveFileLease", lambda _path: pytest.fail("held process must not create another lease"))
    with pytest.raises(producer._SnapshotStorageHeld, match="held_custody_unknown"):
        producer._snapshot_create_private(directory / "must-not-create.tmp")
    assert producer._publish_crash_snapshot_bytes(directory, b"complete") == "held_custody_unknown"
    module = object.__new__(producer.BaseModule)
    assert module._write_crash_snapshot(RuntimeError("original"), TB) == "held_custody_unknown"
    assert producer._CRASH_SNAPSHOT_CUSTODY_UNKNOWN is retained
    assert creations == [str(temporary)]
    assert native_closes == ([42] if phase == "refusal_close" else [])
    assert not (directory / "must-not-create.tmp").exists()
    assert list(directory.glob("*.json")) == []


def test_writer_uses_cached_error_and_fixed_outcome_without_host_sampling(monkeypatch, directory):
    import sys

    class HostileError(Exception):
        def __str__(self):
            raise AssertionError("capture must not reformat the original exception")

    sample = SimpleNamespace(memory_info=lambda: SimpleNamespace(rss=1024, vms=2048), memory_percent=lambda: 1.0)
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(Process=lambda: sample))
    monkeypatch.setattr(producer, "_crash_snapshot_master_key", lambda: KEY)
    monkeypatch.setattr(producer, "_get_snapshot_dir", lambda: directory)
    captured = []
    monkeypatch.setattr(producer, "_publish_crash_snapshot_bytes", lambda _path, body: captured.append(body) or "held_storage_budget")
    module = object.__new__(producer.BaseModule)
    module.name = "../path-components-do-not-name-the-file"
    module.last_error = "original exception retained"
    module._bus = None
    assert module._write_crash_snapshot(HostileError(), TB) == "held_storage_budget"
    assert module.last_error == "original exception retained"
    document = json.loads(captured[0])
    assert document["error"] == "original exception retained"
    assert producer.verify_crash_snapshot_bundle(document, key=KEY)
