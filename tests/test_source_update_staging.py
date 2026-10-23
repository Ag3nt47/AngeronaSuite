from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.updater import source_stage as stage

BASE, TARGET, LOCAL = "a" * 40, "b" * 40, "c" * 40


def archive(tree: dict[str, bytes], revision: str) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        for name, content in tree.items():
            output.writestr(f"AngeronaSuite-{revision}/{name}", content)
    return stream.getvalue()


def fixture(tmp_path: Path, monkeypatch, base, user, incoming):
    for tree in (base, user, incoming):
        tree.setdefault("pyproject.toml", b'[project]\nname="angerona"\nversion="1.14.0"\n')
        tree.setdefault("src/angerona/__init__.py", b'__version__="1.14.0"\n')
        tree.setdefault("src/angerona/__main__.py", b"pass\n")
    source, state = tmp_path / "installation", tmp_path / "state"
    source.mkdir()
    for name, content in user.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    paths = tuple(sorted(set(base) | set(user)))
    monkeypatch.setattr(stage, "local_source_revision", lambda root: LOCAL)
    monkeypatch.setattr(stage, "source_git_session", nullcontext)
    monkeypatch.setattr(stage, "source_inventory", lambda root: paths)
    monkeypatch.setattr(stage, "_git", lambda root, args: (BASE + "\n").encode() if args[0] == "rev-parse" else b"")
    archives = {BASE: archive(base, BASE), TARGET: archive(incoming, TARGET)}
    compare = {"status": "ahead", "base_commit": {"sha": BASE}, "merge_base_commit": {"sha": BASE}}
    return source, state, archives, compare


@pytest.mark.parametrize("base,user,incoming,action,expected", [
    (b"a", b"a", b"b", "upstream", b"b"),
    (b"a", b"local", b"a", "preserved", b"local"),
    (b"a", None, b"a", "preserved", None),
    (b"a", b"a", None, "upstream", None),
    (None, b"same", b"same", "preserved", b"same"),
    (b"a", b"a", b"a", "upstream", b"a"),
    (b"a\nb\nc\nd\n", b"A\nb\nc\nd\n", b"a\nb\nc\nD\n", "merged", b"A\nb\nc\nD\n"),
    (b"a\n", b"local\n", b"remote\n", "conflict", None),
    (b"a", None, b"b", "conflict", None),
    (b"a", b"b", None, "conflict", None),
    (None, b"ours", b"theirs", "conflict", None),
    (b"a\x00", b"b\x00", b"c\x00", "conflict", None),
])
def test_conservative_three_way_merge(base, user, incoming, action, expected) -> None:
    result = stage.merge_file(base, user, incoming)
    assert (result.action, result.content) == (action, expected)


@pytest.mark.parametrize("path", ["../x", "/x", "C:/x", "x/../y", "x\\y", ".git/config", ".GIT/config", "x/NUL", "x/COM1.txt", "x/file.", "x//y", "x\x00y"])
def test_source_paths_cannot_escape_or_alias_windows_paths(path) -> None:
    with pytest.raises(stage.SourceStageError):
        stage.safe_relative(path)


def test_case_and_file_directory_collisions_are_rejected_before_writes() -> None:
    for tree in ({"A": b"", "a": b""}, {"folder": b"", "folder/x": b""}):
        with pytest.raises(stage.SourceStageError):
            stage._validate_tree(tree)


def test_archives_reject_traversal_symlinks_duplicate_and_oversized_entries(monkeypatch) -> None:
    for name, mode in (("../outside", 0), ("link", stat.S_IFLNK | 0o777)):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as output:
            info = zipfile.ZipInfo(f"AngeronaSuite-{BASE}/{name}")
            info.external_attr = mode << 16
            output.writestr(info, b"target")
        with pytest.raises(stage.SourceStageError):
            stage.read_source_archive(stream.getvalue(), BASE)
    monkeypatch.setattr(stage, "MAX_FILE_BYTES", 3)
    with pytest.raises(stage.SourceStageError):
        stage.read_source_archive(archive({"large": b"1234"}, BASE), BASE)


def test_preparation_preserves_custom_code_deletions_and_conflict_sides_without_mutation(tmp_path, monkeypatch) -> None:
    base = {"code.py": b"a=1\nb=2\nc=3\nd=4\n", "deleted.txt": b"keep?", "conflict.txt": b"base"}
    user = {"code.py": b"a=10\nb=2\nc=3\nd=4\n", "custom.py": b"custom=True\n", "conflict.txt": b"user"}
    incoming = {"code.py": b"a=1\nb=2\nc=3\nd=40\n", "deleted.txt": b"keep?", "conflict.txt": b"remote", "new.py": b"new=True\n"}
    source, state, archives, compare = fixture(tmp_path, monkeypatch, base, user, incoming)
    result = stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare, download=archives.__getitem__)
    assert result.status == "conflicts" and result.conflicts == ("conflict.txt",)
    candidate = state / result.stage_id / "candidate"
    assert (candidate / "code.py").read_bytes() == b"a=10\nb=2\nc=3\nd=40\n"
    assert (candidate / "custom.py").read_bytes() == user["custom.py"]
    assert not (candidate / "deleted.txt").exists() and not (candidate / "conflict.txt").exists()
    manifest_path = state / result.stage_id / "manifest.json"
    manifest_before = manifest_path.read_bytes()
    assert hashlib.sha256(manifest_before).hexdigest() == result.manifest_sha256
    manifest = json.loads(manifest_before)
    conflict = next(row for row in manifest["files"] if row["path"] == "conflict.txt")
    for side, expected in (("base", b"base"), ("user", b"user"), ("upstream", b"remote")):
        assert (state / result.stage_id / "preserved-blobs" / conflict[side]).read_bytes() == expected
    stage.resolve_source_conflict(state / result.stage_id, result.manifest_sha256, "conflict.txt", "user")
    assert (candidate / "conflict.txt").read_bytes() == b"user"
    assert manifest_path.read_bytes() == manifest_before
    validation = stage.validate_source_candidate(state / result.stage_id, result.manifest_sha256)
    assert validation["static_checks"] == "passed" and validation["activation"] == "held"
    assert validation["golden_baseline_reenrolled"] is False
    assert stage.snapshot_local(source, tuple(sorted(user))) == user
    assert not (source / "new.py").exists()


def test_already_cancelled_stage_does_not_create_state_or_start_any_producer(tmp_path, monkeypatch) -> None:
    base, user, incoming = {"code.py": b"a=1\n"}, {"code.py": b"a=2\n"}, {"code.py": b"a=3\n"}
    source, state, archives, compare = fixture(tmp_path, monkeypatch, base, user, incoming)
    before = {path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*") if path.is_file()}
    monkeypatch.setattr(stage, "_physical_source_root", lambda root: pytest.fail("cancelled work must not inspect the source"))
    monkeypatch.setattr(stage, "_safe_state_root", lambda root: pytest.fail("cancelled work must not create state"))
    monkeypatch.setattr(stage, "source_git_session", lambda: pytest.fail("cancelled work must not stage Git"))
    with pytest.raises(stage.SourceStageError, match="cancelled"):
        stage.prepare_source_update(source, state, TARGET,
                                    fetch=lambda path: pytest.fail("cancelled work must not fetch metadata"),
                                    download=lambda sha: pytest.fail("cancelled work must not download archives"),
                                    cancelled=lambda: True)
    assert not state.exists()
    assert {path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*") if path.is_file()} == before


def test_cancellation_after_git_ancestry_stops_before_metadata_fetch(tmp_path, monkeypatch) -> None:
    source, state, archives, compare = fixture(tmp_path, monkeypatch, {"a": b"base"}, {"a": b"user"}, {"a": b"new"})
    cancelled = [False]
    commands = []

    def git(root, args):
        commands.append(args)
        if args[0] == "merge-base":
            cancelled[0] = True
            return b""
        return BASE.encode()

    monkeypatch.setattr(stage, "_git", git)
    with pytest.raises(stage.SourceStageError, match="cancelled"):
        stage.prepare_source_update(source, state, TARGET, cancelled=lambda: cancelled[0],
                                    fetch=lambda path: pytest.fail("close during Git must stop the next fetch"),
                                    download=lambda sha: pytest.fail("cancelled work must not download archives"))
    assert [args[0] for args in commands] == ["rev-parse", "merge-base"]
    assert not list(state.glob("source-*"))
    assert (source / "a").read_bytes() == b"user"


def test_cancellation_after_intent_retains_cancelled_evidence_and_original(tmp_path, monkeypatch) -> None:
    base, user, incoming = {"code.py": b"a=1\n"}, {"code.py": b"a=2\n"}, {"code.py": b"a=3\n"}
    source, state, archives, compare = fixture(tmp_path, monkeypatch, base, user, incoming)
    cancelled = [False]
    downloads = []

    def download(revision):
        intents = list(state.glob("source-*/intent.json"))
        assert len(intents) == 1 and json.loads(intents[0].read_bytes())["status"] == "preparing"
        downloads.append(revision)
        cancelled[0] = True
        return archives[revision]

    with pytest.raises(stage.SourceStageError, match="cancelled"):
        stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare,
                                    download=download, cancelled=lambda: cancelled[0])
    assert (source / "code.py").read_bytes() == b"a=2\n"
    intents = list(state.glob("source-*/intent.json"))
    assert len(intents) == 1 and json.loads(intents[0].read_bytes())["status"] == "cancelled"
    assert downloads == [BASE]
    assert not (intents[0].parent / "candidate").exists()


def test_diverged_or_unknown_base_is_held_before_download(tmp_path, monkeypatch) -> None:
    source, state, archives, compare = fixture(tmp_path, monkeypatch, {"a": b"a"}, {"a": b"a"}, {"a": b"b"})
    compare["status"] = "diverged"
    with pytest.raises(stage.SourceStageError, match="ancestry"):
        stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare,
                                    download=lambda revision: pytest.fail("divergence must not download"))


def test_changed_source_during_download_holds_candidate(tmp_path, monkeypatch) -> None:
    source, state, archives, compare = fixture(tmp_path, monkeypatch, {"a": b"a"}, {"a": b"a"}, {"a": b"b"})

    def download(revision):
        (source / "a").write_bytes(b"concurrent edit")
        return archives[revision]

    with pytest.raises(stage.SourceStageError, match="changed during"):
        stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare, download=download)
    assert (source / "a").read_bytes() == b"concurrent edit"


def test_candidate_tampering_and_syntax_failures_are_reported_truthfully(tmp_path, monkeypatch) -> None:
    source, state, archives, compare = fixture(tmp_path, monkeypatch, {"a.py": b"a=1\n"}, {"a.py": b"a=1\n"}, {"a.py": b"def broken(\n"})
    result = stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare, download=archives.__getitem__)
    root = state / result.stage_id
    report = stage.validate_source_candidate(root, result.manifest_sha256)
    assert report["static_checks"] == "failed" and report["syntax_errors"] == [{"path": "a.py", "error_type": "SyntaxError"}]
    (root / "candidate" / "a.py").write_bytes(b"a=9\n")
    with pytest.raises(stage.SourceStageError, match="differ"):
        stage.validate_source_candidate(root, result.manifest_sha256)


def test_entire_deleted_tracked_directory_remains_deleted(tmp_path, monkeypatch) -> None:
    base = {"removed/subdirectory/file.py": b"old=True\n"}
    user = {}
    incoming = {"removed/subdirectory/file.py": b"old=True\n"}
    source, state, archives, compare = fixture(tmp_path, monkeypatch, base, user, incoming)
    result = stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare, download=archives.__getitem__)
    assert result.status == "prepared"
    assert not (state / result.stage_id / "candidate" / "removed").exists()
    manifest = json.loads((state / result.stage_id / "manifest.json").read_bytes())
    record = next(row for row in manifest["files"] if row["path"] == "removed/subdirectory/file.py")
    assert record["user"] is None and record["candidate"] is None and record["action"] == "preserved"


def _resolution_recovery_fixture(tmp_path, monkeypatch, *, user_content=b"local chosen bytes"):
    name = "custom/conflict.txt"
    base = {name: b"base chosen bytes"}
    user = {} if user_content is None else {name: user_content}
    incoming = {name: b"upstream chosen bytes"}
    source, state, archives, compare = fixture(tmp_path, monkeypatch, base, user, incoming)
    result = stage.prepare_source_update(source, state, TARGET, fetch=lambda path: compare,
                                         download=archives.__getitem__)
    root = state / result.stage_id
    originals = (stage.snapshot_local(source, tuple(sorted(user))), (root / "manifest.json").read_bytes(),
                 {p.name: p.read_bytes() for p in (root / "preserved-blobs").iterdir()})
    return source, root, result, name, originals


def _assert_resolution_originals(source, root, originals):
    original, manifest, blobs = originals
    assert stage.snapshot_local(source, tuple(sorted(original))) == original
    assert (root / "manifest.json").read_bytes() == manifest
    assert {p.name: p.read_bytes() for p in (root / "preserved-blobs").iterdir()} == blobs


def _interrupt_resolution_index(monkeypatch):
    write = stage._write_json
    calls = []

    def fail_once(path, value, **kwargs):
        if path.name == "resolutions.json":
            calls.append(dict(value["files"]))
            if len(calls) == 1:
                raise OSError("inert interrupted resolution-index commit")
        return write(path, value, **kwargs)

    monkeypatch.setattr(stage, "_write_json", fail_once)
    return calls


@pytest.mark.parametrize("choice", ["base", "user", "upstream", "delete"])
def test_resolution_retry_reconciles_fsynced_candidate_after_index_failure(tmp_path, monkeypatch, choice):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    calls = _interrupt_resolution_index(monkeypatch)
    fsynced = set()
    real_os = stage.os

    class RecordingOS:
        def __getattr__(self, attribute):
            return getattr(real_os, attribute)

        def fsync(self, descriptor):
            real_os.fsync(descriptor)
            info = real_os.fstat(descriptor)
            fsynced.add((info.st_dev, info.st_ino))

    monkeypatch.setattr(stage, "os", RecordingOS())
    with pytest.raises(OSError, match="interrupted resolution-index"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, choice)
    target = root / "candidate" / name
    intent_path = root / "resolution-intents" / (hashlib.sha256(name.encode()).hexdigest() + ".json")
    intent_before = intent_path.read_bytes()
    intent = json.loads(intent_before)
    assert intent["manifest_sha256"] == result.manifest_sha256 and intent["choice"] == choice
    assert not (root / "resolutions.json").exists()
    if choice == "delete":
        assert not target.exists() and intent["candidate_identity"] is None
    else:
        info = target.stat()
        assert (info.st_dev, info.st_ino) in fsynced
        assert intent["candidate_identity"]["inode"] == str(info.st_ino)
        assert hashlib.sha256(target.read_bytes()).hexdigest() == intent["sha256"]
    _assert_resolution_originals(source, root, originals)
    recovered = stage.resolve_source_conflict(root, result.manifest_sha256, name, choice)
    assert recovered == {"path": name, "choice": choice, "sha256": intent["sha256"]}
    assert stage.resolve_source_conflict(root, result.manifest_sha256, name, choice) == recovered
    assert len(calls) == 2  # The second retry verifies, without rewriting a committed index.
    assert intent_path.read_bytes() == intent_before
    checked = stage.validate_source_candidate(root, result.manifest_sha256)
    assert checked["static_checks"] == "passed" and checked["activation"] == "held"
    _assert_resolution_originals(source, root, originals)


def test_resolution_retry_preserves_selected_absent_side(tmp_path, monkeypatch):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch, user_content=None)
    _interrupt_resolution_index(monkeypatch)
    with pytest.raises(OSError, match="interrupted resolution-index"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert stage.resolve_source_conflict(root, result.manifest_sha256, name, "user") == {
        "path": name, "choice": "user", "sha256": None}
    assert not (root / "candidate" / name).exists()
    assert stage.validate_source_candidate(root, result.manifest_sha256)["static_checks"] == "passed"
    _assert_resolution_originals(source, root, originals)


def test_resolution_retry_refuses_changed_explicit_choice(tmp_path, monkeypatch):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    _interrupt_resolution_index(monkeypatch)
    with pytest.raises(OSError):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    candidate = (root / "candidate" / name).read_bytes()
    with pytest.raises(stage.SourceStageError, match="recorded choice or manifest"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "upstream")
    assert (root / "candidate" / name).read_bytes() == candidate
    assert not (root / "resolutions.json").exists()
    _assert_resolution_originals(source, root, originals)


@pytest.mark.parametrize("change", ["modified", "same-content-replacement", "missing"])
def test_resolution_retry_holds_modified_replaced_or_missing_owned_candidate(tmp_path, monkeypatch, change):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    _interrupt_resolution_index(monkeypatch)
    with pytest.raises(OSError):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    target = root / "candidate" / name
    chosen = target.read_bytes()
    if change == "modified":
        target.write_bytes(b"unexpected changed bytes")
    else:
        target.replace(tmp_path / "retained-original-candidate")
        if change == "same-content-replacement":
            target.write_bytes(chosen)
    unexpected = target.read_bytes() if target.exists() else None
    with pytest.raises(stage.SourceStageError, match="conflict candidate"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert (target.read_bytes() if target.exists() else None) == unexpected
    assert not (root / "resolutions.json").exists()
    if change != "modified":
        assert (tmp_path / "retained-original-candidate").read_bytes() == chosen
    _assert_resolution_originals(source, root, originals)


@pytest.mark.parametrize("failure", ["planned-intent", "created-identity"])
def test_resolution_retry_holds_unowned_or_partial_candidate_without_overwrite(tmp_path, monkeypatch, failure):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    write = stage._write_json
    target = root / "candidate" / name

    def interrupt(path, value, **kwargs):
        if path.parent.name == "resolution-intents" and value["candidate_identity"] is not None:
            if failure == "created-identity":
                write(path, value, **kwargs)
            raise OSError("inert interruption before candidate content write")
        return write(path, value, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(stage, "_write_json", interrupt)
        with pytest.raises(OSError, match="before candidate content write"):
            stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert target.read_bytes() == b""
    if failure == "created-identity":
        target.write_bytes(b"local")  # A prefix of the selected side is still not a complete candidate.
    before = target.read_bytes()
    with pytest.raises(stage.SourceStageError, match="ownership|recorded object or size"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert target.read_bytes() == before and not (root / "resolutions.json").exists()
    _assert_resolution_originals(source, root, originals)


def test_resolution_retry_can_resume_planned_intent_before_candidate_create(tmp_path, monkeypatch):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    write = stage._write_json

    def interrupt(path, value, **kwargs):
        write(path, value, **kwargs)
        if path.parent.name == "resolution-intents":
            raise OSError("inert interruption after planned intent commit")

    with monkeypatch.context() as patch:
        patch.setattr(stage, "_write_json", interrupt)
        with pytest.raises(OSError, match="after planned intent"):
            stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert not (root / "candidate" / name).exists()
    stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert stage.validate_source_candidate(root, result.manifest_sha256)["activation"] == "held"
    _assert_resolution_originals(source, root, originals)


def test_resolution_retry_rechecks_pinned_manifest_before_reconciling(tmp_path, monkeypatch):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    _interrupt_resolution_index(monkeypatch)
    with pytest.raises(OSError):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    target = root / "candidate" / name
    candidate = target.read_bytes()
    (root / "manifest.json").write_bytes(originals[1] + b" ")
    with pytest.raises(stage.SourceStageError, match="manifest digest mismatch"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert target.read_bytes() == candidate and not (root / "resolutions.json").exists()
    assert stage.snapshot_local(source, tuple(sorted(originals[0]))) == originals[0]
    assert {p.name: p.read_bytes() for p in (root / "preserved-blobs").iterdir()} == originals[2]


def _forbid_resolution_candidate_open(monkeypatch, target):
    safe_root = stage._safe_state_root

    class OpenObservedPath(type(target)):
        def open(self, *args, **kwargs):
            if self == target:
                pytest.fail("an unsafe or unowned candidate must be refused before opening")
            return super().open(*args, **kwargs)

    def observed_root(path):
        return OpenObservedPath(safe_root(path))

    monkeypatch.setattr(stage, "_safe_state_root", observed_root)


@pytest.mark.parametrize("replacement", ["same-content-file", "directory"])
def test_resolution_retry_rejects_unsafe_or_replaced_name_before_candidate_open(tmp_path, monkeypatch, replacement):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    _interrupt_resolution_index(monkeypatch)
    with pytest.raises(OSError):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    target = root / "candidate" / name
    chosen = target.read_bytes()
    target.replace(tmp_path / "retained-original-candidate")
    if replacement == "same-content-file":
        target.write_bytes(chosen)
    else:
        target.mkdir()
    _forbid_resolution_candidate_open(monkeypatch, target)
    with pytest.raises(stage.SourceStageError, match="conflict candidate"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert not (root / "resolutions.json").exists()
    assert (tmp_path / "retained-original-candidate").read_bytes() == chosen
    if replacement == "same-content-file":
        assert target.read_bytes() == chosen
    else:
        assert target.is_dir()
    _assert_resolution_originals(source, root, originals)


def test_committed_resolution_cannot_recreate_candidate_from_planned_only_intent(tmp_path, monkeypatch):
    source, root, result, name, originals = _resolution_recovery_fixture(tmp_path, monkeypatch)
    stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    index_before = (root / "resolutions.json").read_bytes()
    target = root / "candidate" / name
    chosen = target.read_bytes()
    target.replace(tmp_path / "retained-original-candidate")
    intent_path = root / "resolution-intents" / (hashlib.sha256(name.encode()).hexdigest() + ".json")
    intent = json.loads(intent_path.read_bytes())
    intent["candidate_identity"] = None  # Inertly inconsistent committed/planned metadata.
    stage._write_json(intent_path, intent)
    _forbid_resolution_candidate_open(monkeypatch, target)
    with pytest.raises(stage.SourceStageError, match="committed conflict resolution"):
        stage.resolve_source_conflict(root, result.manifest_sha256, name, "user")
    assert not target.exists() and (root / "resolutions.json").read_bytes() == index_before
    assert (tmp_path / "retained-original-candidate").read_bytes() == chosen
    _assert_resolution_originals(source, root, originals)


@pytest.mark.parametrize("replacement", ["fifo", "symlink", "different-regular-file"])
def test_posix_recorded_candidate_open_refuses_post_lstat_replacement_before_fdopen(monkeypatch, replacement):
    # Inert kernel-contract control: no FIFO, device or symlink is opened.
    real_os, real_io = stage.os, stage.io
    events, acquired, closed = [], [], []
    original = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                               st_dev=7, st_ino=11, st_birthtime_ns=None)
    replaced = SimpleNamespace(st_mode=(stat.S_IFIFO if replacement == "fifo" else stat.S_IFREG) | 0o600,
                               st_nlink=1, st_dev=7, st_ino=12, st_birthtime_ns=None)
    intent = {"candidate_identity": {"device": "7", "inode": "11", "birth_ns": None}}

    class NamedCandidate:
        def __fspath__(self):
            return "inert-candidate"

        def lstat(self):
            events.append("lstat")
            return original

    class PosixOS:
        name = "posix"
        O_NONBLOCK = getattr(real_os, "O_NONBLOCK", 0x04000000)
        O_NOFOLLOW = getattr(real_os, "O_NOFOLLOW", 0x08000000)

        def __getattr__(self, attribute):
            return getattr(real_os, attribute)

        def open(self, name, flags):
            assert events == ["lstat", "stream-request"]
            events.append("replacement-after-lstat")
            assert flags & self.O_NONBLOCK and flags & self.O_NOFOLLOW
            if replacement == "symlink":
                raise OSError("inert O_NOFOLLOW symlink refusal")
            acquired.append(29)
            return 29  # Inert owned-descriptor token; never passed to the real OS.

        def fstat(self, descriptor):
            assert descriptor == 29
            events.append("fstat")
            return replaced

        def close(self, descriptor):
            assert descriptor == 29
            events.append("close")
            closed.append(descriptor)

    class UnopenedIO:
        def __getattr__(self, attribute):
            return getattr(real_io, attribute)

        def open(self, target, mode, *, opener):
            assert mode == "rb"
            events.append("stream-request")
            opener(real_os.fspath(target), real_os.O_RDONLY)
            events.append("fdopen")
            pytest.fail("raced objects must be refused before stream construction or read")

    monkeypatch.setattr(stage, "os", PosixOS())
    monkeypatch.setattr(stage, "io", UnopenedIO())
    with pytest.raises(OSError if replacement == "symlink" else stage.SourceStageError):
        stage._verify_recorded_resolution_candidate(NamedCandidate(), intent, b"chosen bytes")
    assert "replacement-after-lstat" in events and "fdopen" not in events
    assert acquired == closed == ([] if replacement == "symlink" else [29])
    if replacement != "symlink":
        assert events[-2:] == ["fstat", "close"]
