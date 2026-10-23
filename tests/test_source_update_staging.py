from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from contextlib import nullcontext
from pathlib import Path

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
