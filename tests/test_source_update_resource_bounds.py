from __future__ import annotations

import io
import os
import stat
import ctypes
import subprocess
import zipfile
import threading
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager, nullcontext

import pytest

from angerona.core import file_lease
from angerona.updater import source_stage as stage

TARGET = "b" * 40


def test_snapshot_aggregate_and_count_caps_precede_every_content_read(tmp_path, monkeypatch) -> None:
    for name in ("a", "b", "c"):
        (tmp_path / name).write_bytes(b"1234")
    original_open = Path.open
    reads = []

    def observed_open(path, *args, **kwargs):
        reads.append(path.name)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(stage, "MAX_TREE_BYTES", 7)
    monkeypatch.setattr(Path, "open", observed_open)
    with pytest.raises(stage.SourceStageError, match="before capture"):
        stage.snapshot_local(tmp_path, ("a", "b", "c"))
    assert reads == []
    monkeypatch.setattr(stage, "MAX_FILES", 1)
    with pytest.raises(stage.SourceStageError, match="count"):
        stage.snapshot_local(tmp_path, ("a", "b"))
    assert reads == []


@pytest.mark.parametrize("suffix", ["nested-stage", "missing/../nested-stage"])
def test_inside_source_stage_is_rejected_before_mkdir_git_or_network(tmp_path, monkeypatch, suffix) -> None:
    source = tmp_path / "source"
    source.mkdir()
    before = tuple(source.iterdir())
    monkeypatch.setattr(stage, "source_git_session", lambda: pytest.fail("Git must not start"))
    with pytest.raises(stage.SourceStageError, match="outside"):
        stage.prepare_source_update(source / "child" / "..", source / suffix, TARGET,
                                    fetch=lambda path: pytest.fail("network must not start"),
                                    download=lambda sha: pytest.fail("download must not start"))
    assert tuple(source.iterdir()) == before


@pytest.mark.parametrize("path", ["COM¹", "com².txt", "LPT³.log", "folder/COM³.txt"])
def test_superscript_dos_device_aliases_are_refused(path) -> None:
    with pytest.raises(stage.SourceStageError, match="unsafe"):
        stage.safe_relative(path)


def test_case_aliased_parent_directories_are_refused_before_writes() -> None:
    with pytest.raises(stage.SourceStageError, match="parent"):
        stage._validate_tree({"Foo/a": b"a", "foo/b": b"b"})


def test_repetitive_merge_work_is_refused_at_a_lowered_work_limit(monkeypatch) -> None:
    monkeypatch.setattr(stage, "MAX_MERGE_COMPARISONS", 10)
    base = b"x\n" * 20
    result = stage.merge_file(base, b"local\n" + base, base + b"upstream\n")
    assert result.action == "conflict" and "work limit" in result.reason


def test_archive_transaction_remaining_budget_is_checked_before_decompression(monkeypatch) -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        output.writestr("AngeronaSuite-" + TARGET + "/a", b"1234")
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda *args, **kwargs: pytest.fail("over-budget member must not be opened"))
    with pytest.raises(stage.SourceStageError, match="byte limit"):
        stage.read_source_archive(stream.getvalue(), TARGET, remaining_bytes=3)


def test_empty_hardlink_lease_never_writes_to_the_original_sentinel(tmp_path) -> None:
    original = tmp_path / "original"
    original.write_bytes(b"")
    alias = tmp_path / "check.lock"
    os.link(original, alias)
    with pytest.raises(file_lease.ExclusiveFileLeaseError, match="single-link"):
        file_lease.ExclusiveFileLease(alias)
    assert original.read_bytes() == b"" and alias.read_bytes() == b""


def test_descriptor_hardlink_recheck_precedes_the_first_write(tmp_path, monkeypatch) -> None:
    alias, original = tmp_path / "check.lock", tmp_path / "original"
    real_os = file_lease.os

    class Proxy:
        def __getattr__(self, name):
            return getattr(real_os, name)

        def open(self, *args, **kwargs):
            descriptor = real_os.open(*args, **kwargs)
            real_os.link(alias, original)
            return descriptor

    monkeypatch.setattr(file_lease, "os", Proxy())
    with pytest.raises(file_lease.ExclusiveFileLeaseError, match="single-link"):
        file_lease.ExclusiveFileLease(alias)
    assert original.read_bytes() == b""


def _budget_fixture(tmp_path, monkeypatch):
    base, user, incoming = {"a": b"base"}, {"a": b"user", "custom": b"xx"}, {"a": b"base", "new": b"n"}
    source, state = tmp_path / "source", tmp_path / "state"
    source.mkdir()
    for name, data in user.items():
        (source / name).write_bytes(data)
    archives = {}
    for revision, tree in (("a" * 40, base), (TARGET, incoming)):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as output:
            for name, data in tree.items():
                output.writestr(f"AngeronaSuite-{revision}/{name}", data)
        archives[revision] = stream.getvalue()
    monkeypatch.setattr(stage, "source_git_session", nullcontext)
    monkeypatch.setattr(stage, "local_source_revision", lambda root: "c" * 40)
    monkeypatch.setattr(stage, "_git", lambda root, args: ("a" * 40).encode() if args[0] == "rev-parse" else b"")
    monkeypatch.setattr(stage, "source_inventory", lambda root: ("a", "custom"))
    compare = {"status": "ahead", "base_commit": {"sha": "a" * 40}, "merge_base_commit": {"sha": "a" * 40}}
    return source, state, archives, compare


@pytest.mark.parametrize("limit_kind", ["candidate", "transaction", "disk"])
def test_combined_candidate_and_exact_disk_budget_hold_before_any_blob_or_candidate_write(tmp_path, monkeypatch, limit_kind) -> None:
    source, state, archives, compare = _budget_fixture(tmp_path, monkeypatch)
    if limit_kind == "candidate":
        monkeypatch.setattr(stage, "MAX_TREE_BYTES", 6)  # U=6,T=5,B=4 each fit, C=7 does not.
    elif limit_kind == "transaction":
        monkeypatch.setattr(stage, "MAX_TRANSACTION_BYTES", 21)  # B+U+T+C=22.
    else:
        monkeypatch.setattr(stage.shutil, "disk_usage", lambda root: SimpleNamespace(free=16 * 1024 * 1024 + 21))
    with pytest.raises(stage.SourceStageError, match="budget|space"):
        stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare, download=archives.__getitem__)
    stages = list(state.glob("source-*"))
    assert len(stages) == (0 if limit_kind == "disk" else 1)
    if stages:
        assert not (stages[0] / "preserved-blobs").exists() and not (stages[0] / "candidate").exists()
    assert (source / "a").read_bytes() == b"user" and (source / "custom").read_bytes() == b"xx"


def _retained_stage(root, number, content=b"USER_EDIT=True\n"):
    candidate = root / f"source-{number:032x}"
    candidate.mkdir(parents=True)
    (candidate / "custom.py").write_bytes(content)
    return candidate


def _deny_producers(monkeypatch):
    monkeypatch.setattr(stage, "source_git_session", lambda: pytest.fail("Git must not start before storage admission"))
    return dict(fetch=lambda _path: pytest.fail("metadata must not be fetched"),
                download=lambda _sha: pytest.fail("archives must not be downloaded"))


def test_third_retained_candidate_holds_before_git_download_and_preserves_readonly_data(tmp_path, monkeypatch):
    source, state, _archives, _compare = _budget_fixture(tmp_path, monkeypatch)
    first = _retained_stage(state, 1)
    second = _retained_stage(state, 2, b"PREFS_AND_CODE=unchanged\n")
    payload = first / "custom.py"
    original_mode = payload.stat().st_mode
    payload.chmod(stat.S_IREAD)
    before = payload.read_bytes(), payload.stat().st_mtime_ns, payload.stat().st_mode
    try:
        with pytest.raises(stage.SourceStageError, match="retained source-stage limit"):
            stage.prepare_source_update(source, state, TARGET, **_deny_producers(monkeypatch))
        assert (payload.read_bytes(), payload.stat().st_mtime_ns, payload.stat().st_mode) == before
        assert (second / "custom.py").read_bytes() == b"PREFS_AND_CODE=unchanged\n"
        assert (source / "a").read_bytes() == b"user"
        assert len(list(state.glob("source-*"))) == 2
    finally:
        payload.chmod(original_mode)


def test_first_and_second_preparations_are_admitted_but_never_activate(tmp_path, monkeypatch):
    source, state, archives, compare = _budget_fixture(tmp_path, monkeypatch)
    first = stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare,
                                        download=archives.__getitem__)
    second = stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare,
                                         download=archives.__getitem__)
    assert first.stage_id != second.stage_id
    assert first.activation_status == second.activation_status == "not_authorized"
    assert (source / "a").read_bytes() == b"user" and not (source / "new").exists()
    assert len(list(state.glob("source-*"))) == 2


@pytest.mark.parametrize("kind", ["aggregate", "reserve", "entries", "time", "unknown-file", "unknown-directory"])
def test_storage_admission_failure_is_bounded_and_precedes_every_producer(tmp_path, monkeypatch, kind):
    source, state, _archives, _compare = _budget_fixture(tmp_path, monkeypatch)
    existing = _retained_stage(state, 1, b"12345678")
    if kind == "aggregate":
        monkeypatch.setattr(stage, "MAX_TRANSACTION_BYTES", 12)
        monkeypatch.setattr(stage, "MAX_STAGE_METADATA_BYTES", 4)
        monkeypatch.setattr(stage, "MAX_RETAINED_STAGE_BYTES", 20)
    elif kind == "reserve":
        monkeypatch.setattr(stage.shutil, "disk_usage", lambda _path: SimpleNamespace(free=stage.MIN_STAGE_FREE_BYTES))
    elif kind == "entries":
        monkeypatch.setattr(stage, "MAX_STAGE_SCAN_ENTRIES", 2)
    elif kind == "time":
        monkeypatch.setattr(stage, "MAX_STAGE_SCAN_SECONDS", 0)
    elif kind == "unknown-file":
        (state / "unrecognized.txt").write_bytes(b"KEEP")
    else:
        (state / "unrecognized-directory").mkdir()
    before = (existing / "custom.py").read_bytes()
    with pytest.raises(stage.SourceStageError, match="storage held"):
        stage.prepare_source_update(source, state, TARGET, **_deny_producers(monkeypatch))
    assert (existing / "custom.py").read_bytes() == before
    assert (source / "a").read_bytes() == b"user" and (source / "custom").read_bytes() == b"xx"
    assert len(list(state.glob("source-*"))) == 1


def test_retained_hardlink_is_preserved_and_blocks_another_stage(tmp_path, monkeypatch):
    source, state, _archives, _compare = _budget_fixture(tmp_path, monkeypatch)
    existing = _retained_stage(state, 1)
    sentinel = tmp_path / "original-custom.py"
    os.link(existing / "custom.py", sentinel)
    before = sentinel.read_bytes(), sentinel.stat().st_mtime_ns
    with pytest.raises(stage.SourceStageError, match="unsafe"):
        stage.prepare_source_update(source, state, TARGET, **_deny_producers(monkeypatch))
    assert (sentinel.read_bytes(), sentinel.stat().st_mtime_ns) == before
    assert sentinel.stat().st_nlink == 2


def test_retained_directory_reparse_is_rejected_without_following_or_deleting_it(tmp_path, monkeypatch):
    source, state, _archives, _compare = _budget_fixture(tmp_path, monkeypatch)
    state.mkdir()
    target = tmp_path / "owned-target"
    target.mkdir()
    sentinel = target / "keep.py"
    sentinel.write_bytes(b"UNCHANGED")
    link = state / ("source-" + "1" * 32)
    _owned_directory_link(tmp_path, tmp_path / "owned-link", target)
    # Move only the exact fixture link within its verified private workspace.
    (tmp_path / "owned-link").rename(link)
    with pytest.raises(stage.SourceStageError, match="unsafe|link|reparse"):
        stage.prepare_source_update(source, state, TARGET, **_deny_producers(monkeypatch))
    assert sentinel.read_bytes() == b"UNCHANGED" and os.path.lexists(link)


def test_file_edit_during_completed_inventory_holds_without_reverting_the_edit(tmp_path, monkeypatch):
    source, state, _archives, _compare = _budget_fixture(tmp_path, monkeypatch)
    existing = _retained_stage(state, 1)
    payload = existing / "custom.py"
    real = stage._held_storage_file

    @contextmanager
    def edited_after_close(path):
        with real(path) as stamp:
            yield stamp
        if path == payload:
            path.write_bytes(b"USER_NEW_EDIT=True\n")

    monkeypatch.setattr(stage, "_held_storage_file", edited_after_close)
    with pytest.raises(stage.SourceStageError, match="changed during inventory"):
        stage.prepare_source_update(source, state, TARGET, **_deny_producers(monkeypatch))
    assert payload.read_bytes() == b"USER_NEW_EDIT=True\n"
    assert (source / "a").read_bytes() == b"user"


def test_reserve_drop_after_download_preserves_originals_and_preparing_evidence(tmp_path, monkeypatch):
    source, state, archives, compare = _budget_fixture(tmp_path, monkeypatch)
    available = [16 * 1024**3]
    monkeypatch.setattr(stage.shutil, "disk_usage", lambda _path: SimpleNamespace(free=available[0]))
    downloaded = []

    def download(revision):
        downloaded.append(revision)
        available[0] = stage.MIN_STAGE_FREE_BYTES - 1
        return archives[revision]

    with pytest.raises(stage.SourceStageError, match="free-space reserve"):
        stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare, download=download)
    assert downloaded == ["a" * 40]
    retained = list(state.glob("source-*"))
    assert len(retained) == 1 and (retained[0] / "intent.json").is_file()
    assert not (retained[0] / "candidate").exists()
    assert (source / "a").read_bytes() == b"user"


def test_planned_directory_and_file_entry_budget_precedes_payload_writes(tmp_path, monkeypatch):
    source, state, archives, compare = _budget_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(stage, "MAX_STAGE_OUTPUT_ENTRIES", 9)
    with pytest.raises(stage.SourceStageError, match="output entry budget"):
        stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare,
                                    download=archives.__getitem__)
    retained = list(state.glob("source-*"))
    assert len(retained) == 1 and not (retained[0] / "candidate").exists()
    assert not (retained[0] / "preserved-blobs").exists()
    assert (source / "a").read_bytes() == b"user"


def test_capture_rechecks_reserve_between_bounded_chunks_and_keeps_partial_bytes(tmp_path, monkeypatch):
    original = stage._require_stage_free
    calls = []

    def guarded(path, pending_bytes=0):
        calls.append(pending_bytes)
        if len(calls) == 3:
            raise stage.SourceStageError("reserve held during owned write")
        return original(path, pending_bytes)

    monkeypatch.setattr(stage, "_require_stage_free", guarded)
    target = tmp_path / "owned-partial.bin"
    with pytest.raises(stage.SourceStageError, match="reserve held"):
        stage._write_capture(target, b"x" * (128 * 1024), lambda: False)
    assert target.read_bytes() == b"x" * (64 * 1024)
    assert len(calls) == 3


def _prepared_conflict(tmp_path, monkeypatch):
    source, state, archives, compare = _budget_fixture(tmp_path, monkeypatch)
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as output:
        output.writestr(f"AngeronaSuite-{TARGET}/a", b"remote")
    archives[TARGET] = raw.getvalue()
    result = stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare,
                                         download=archives.__getitem__)
    assert result.conflicts == ("a",)
    return source, state, state / result.stage_id, result


def _fixture_bytes(root):
    return {path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in root.rglob("*") if path.is_file()}


def test_existing_resolution_at_full_stage_count_uses_actual_growth_not_new_stage_reservation(tmp_path, monkeypatch):
    source, state, existing, result = _prepared_conflict(tmp_path, monkeypatch)
    _retained_stage(state, 7)
    retained = stage._stage_storage_inventory(state, lambda: False)
    monkeypatch.setattr(stage, "MAX_RETAINED_STAGE_BYTES", retained.logical_bytes + 32768)
    resolution = stage.resolve_source_conflict(existing, result.manifest_sha256, "a", "upstream")
    assert resolution["choice"] == "upstream" and (existing / "candidate/a").read_bytes() == b"remote"
    assert (source / "a").read_bytes() == b"user" and len(list(state.glob("source-*"))) == 2


def test_resolution_storage_hold_preserves_every_retained_byte_and_preference(tmp_path, monkeypatch):
    source, state, existing, result = _prepared_conflict(tmp_path, monkeypatch)
    before = _fixture_bytes(state)
    monkeypatch.setattr(stage.shutil, "disk_usage", lambda _path: SimpleNamespace(free=stage.MIN_STAGE_FREE_BYTES - 1))
    with pytest.raises(stage.SourceStageError, match="storage held"):
        stage.resolve_source_conflict(existing, result.manifest_sha256, "a", "upstream")
    assert _fixture_bytes(state) == before
    assert (source / "a").read_bytes() == b"user"


def test_static_review_remains_available_under_reserve_hold_without_new_report_or_lease(tmp_path, monkeypatch):
    source, state, existing, result = _prepared_conflict(tmp_path, monkeypatch)
    before = _fixture_bytes(state)
    monkeypatch.setattr(stage.shutil, "disk_usage", lambda _path: SimpleNamespace(free=stage.MIN_STAGE_FREE_BYTES - 1))
    report = stage.validate_source_candidate(existing, result.manifest_sha256)
    assert report["activation"] == "held" and report["report_persisted"] is False
    assert report["storage_status"] == "held" and report["unresolved_conflicts"] == ["a"]
    assert _fixture_bytes(state) == before
    assert not (existing / "validation.json").exists() and not (existing / "resolution.lock").exists()
    assert (source / "custom").read_bytes() == b"xx"


@pytest.mark.parametrize("missing", ["stage", "candidate"])
def test_static_review_never_recreates_a_missing_namespace_under_storage_pressure(tmp_path, monkeypatch, missing):
    if missing == "stage":
        existing = tmp_path / ("source-" + "1" * 32)
        digest = "a" * 64
    else:
        _source, _state, existing, result = _prepared_conflict(tmp_path, monkeypatch)
        # Remove only exact, small owned fixture files and empty directories.
        for path in (existing / "candidate").iterdir():
            assert path.is_file() and not path.is_symlink()
            path.unlink()
        (existing / "candidate").rmdir()
        digest = result.manifest_sha256
    monkeypatch.setattr(stage.shutil, "disk_usage", lambda _path: SimpleNamespace(free=stage.MIN_STAGE_FREE_BYTES - 1))
    with pytest.raises(stage.SourceStageError, match="physical|missing|existing"):
        stage.validate_source_candidate(existing, digest)
    assert not (existing / "candidate").exists()
    assert not (existing / "resolution.lock").exists()


def test_competing_preparation_cannot_reserve_the_last_slot_twice(tmp_path, monkeypatch):
    source, state, archives, compare = _budget_fixture(tmp_path, monkeypatch)
    _retained_stage(state, 1)
    entered, release = threading.Event(), threading.Event()
    results, errors = [], []

    @contextmanager
    def retained_git():
        entered.set()
        assert release.wait(10), "owned fixture wait exceeded its budget"
        yield

    monkeypatch.setattr(stage, "source_git_session", retained_git)

    def prepare():
        try:
            results.append(stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare,
                                                        download=archives.__getitem__))
        except BaseException as exc:
            errors.append(exc)

    owner = threading.Thread(target=prepare)
    owner.start()
    try:
        assert entered.wait(10)
        with pytest.raises(file_lease.ExclusiveFileLeaseError):
            stage.prepare_source_update(source, state, TARGET, fetch=lambda _path: compare,
                                        download=archives.__getitem__)
    finally:
        release.set()
        owner.join(10)
    assert not owner.is_alive() and not errors and len(results) == 1
    assert len(list(state.glob("source-*"))) == 2 and (source / "a").read_bytes() == b"user"


def _owned_directory_link(owned: Path, link: Path, target: Path) -> None:
    assert link.parent == owned and target.is_relative_to(owned) and target.is_dir()
    assert not os.path.lexists(link)
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except OSError:
        if os.name != "nt":
            raise
    # A native junction also exercises Windows' reparse attribute without a
    # symlink privilege. Both endpoints remain inside this inert fixture.
    query = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
    query.argtypes, query.restype = [ctypes.c_wchar_p, ctypes.c_uint], ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = query(buffer, len(buffer))
    assert 0 < length < len(buffer)
    processor = Path(buffer.value) / "cmd.exe"
    assert processor.is_absolute() and processor.is_file()
    for value in (str(link), str(target)):
        assert not any(character in value for character in '\r\n"%!&|<>^'), "fixture path is unsafe for the native junction helper"
    # Supply the native command line directly: list2cmdline backslash-
    # escapes nested quotes, which cmd.exe does not interpret as escapes.
    command = f'"{processor}" /d /s /c "mklink /J "{link}" "{target}""'
    result = subprocess.run(command, executable=str(processor), shell=False,
                            capture_output=True, text=True, check=False, timeout=10,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0, result.stdout + result.stderr
    assert getattr(link.lstat(), "st_file_attributes", 0) & 0x400


@pytest.mark.parametrize("alias_kind", ["source_root", "source_ancestor"])
def test_source_root_and_ancestor_links_are_refused_before_creating_an_inside_stage(tmp_path, monkeypatch, alias_kind) -> None:
    physical = tmp_path / "physical"
    checkout = physical / "checkout"
    checkout.mkdir(parents=True)
    sentinel = checkout / "custom.py"
    sentinel.write_bytes(b"LOCAL_CUSTOMIZATION=True\n")
    alias = tmp_path / "alias"
    _owned_directory_link(tmp_path, alias, checkout if alias_kind == "source_root" else physical)
    source = alias if alias_kind == "source_root" else alias / "checkout"
    forbidden_stage = checkout / "absent-update-stage"
    before = (tuple(sorted(path.name for path in physical.iterdir())),
              tuple(sorted(path.name for path in checkout.iterdir())),
              sentinel.read_bytes(), sentinel.stat().st_mtime_ns, checkout.stat().st_mtime_ns)
    monkeypatch.setattr(stage, "source_git_session", lambda: pytest.fail("Git/runtime staging must not start"))
    with pytest.raises(stage.SourceStageError, match="link|reparse"):
        stage.prepare_source_update(source, forbidden_stage, TARGET,
                                    fetch=lambda path: pytest.fail("metadata must not be fetched"),
                                    download=lambda sha: pytest.fail("archives must not be downloaded"))
    after = (tuple(sorted(path.name for path in physical.iterdir())),
             tuple(sorted(path.name for path in checkout.iterdir())),
             sentinel.read_bytes(), sentinel.stat().st_mtime_ns, checkout.stat().st_mtime_ns)
    assert not forbidden_stage.exists() and after == before


@pytest.mark.parametrize("alias_side", ["source", "staging_parent"])
def test_plain_directory_spelling_alias_is_canonicalized_before_containment(tmp_path, monkeypatch, alias_side) -> None:
    physical = tmp_path / "physical-long-directory"
    physical.mkdir()
    sentinel = physical / "custom.py"
    sentinel.write_bytes(b"PRIVATE_CUSTOM_CODE=True\n")
    alias = tmp_path / "SHORTALIAS"
    real_lstat, real_resolve = Path.lstat, Path.resolve

    def lstat(path, *args, **kwargs):
        return real_lstat(physical) if path == alias else real_lstat(path, *args, **kwargs)

    def resolve(path, *args, **kwargs):
        return real_resolve(physical, strict=True) if path == alias else real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "resolve", resolve)
    source = alias if alias_side == "source" else physical
    staging = (physical if alias_side == "source" else alias) / "absent-stage"
    monkeypatch.setattr(stage, "source_git_session", lambda: pytest.fail("Git must not start"))
    before = (tuple(physical.iterdir()), sentinel.read_bytes(), physical.stat().st_mtime_ns)
    with pytest.raises(stage.SourceStageError, match="outside"):
        stage.prepare_source_update(source, staging, TARGET,
                                    fetch=lambda path: pytest.fail("metadata must not be fetched"),
                                    download=lambda sha: pytest.fail("archives must not be fetched"))
    assert (tuple(physical.iterdir()), sentinel.read_bytes(), physical.stat().st_mtime_ns) == before


def test_native_windows_short_directory_alias_cannot_hide_source_containment(tmp_path, monkeypatch) -> None:
    if os.name != "nt":
        pytest.skip("Windows 8.3 directory identity control")
    physical = tmp_path / "long physical source directory for short alias control"
    physical.mkdir()
    query = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
    query.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    query.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = query(str(physical), buffer, len(buffer))
    if not 0 < length < len(buffer) or buffer.value.casefold() == str(physical).casefold():
        pytest.skip("This fixture volume has no available distinct 8.3 directory alias; host policy was unchanged")
    short = Path(buffer.value)
    assert short.samefile(physical)
    stage_path = physical / "absent-stage"
    before = (tuple(physical.iterdir()), physical.stat().st_mtime_ns)
    monkeypatch.setattr(stage, "source_git_session", lambda: pytest.fail("Git must not start"))
    with pytest.raises(stage.SourceStageError, match="outside"):
        stage.prepare_source_update(short, stage_path, TARGET,
                                    fetch=lambda path: pytest.fail("metadata must not be fetched"),
                                    download=lambda sha: pytest.fail("archives must not be fetched"))
    assert (tuple(physical.iterdir()), physical.stat().st_mtime_ns) == before
