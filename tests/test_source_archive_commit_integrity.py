"""Immutable source ZIP consistency under inert canonical API transports."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import io
import json

import pytest

from angerona.updater import github_updater as updates
from angerona.updater import source_stage as stage
from source_archive_fixture import git_tree_metadata
from test_source_update_staging import BASE, TARGET, archive, fixture


def frozen_git(files, revision=TARGET):
    tree = git_tree_metadata(files)
    commit = dict(sha=revision, tree=dict(sha=tree["sha"]))
    paths = {"git/commits/" + revision: commit,
             "git/trees/" + tree["sha"] + "?recursive=1": tree}
    calls = []

    def fetch(path):
        calls.append(path)
        assert path in paths, "unexpected endpoint or revision"
        return copy.deepcopy(paths[path])

    return fetch, paths, calls


def test_exact_tree_and_blob_proof_accepts_nested_unicode_and_git_directory_order():
    files = {"a.c": b"x", "a/file.py": b"print('ok')\n", "a0": b"", "news/é.txt": b"utf8"}
    fetch, _paths, calls = frozen_git(files)
    assert stage.read_verified_source_archive(archive(files, TARGET), TARGET, fetch=fetch) == files
    assert calls[0] == "git/commits/" + TARGET
    assert len(calls) == 2 and calls[1].endswith("?recursive=1")


@pytest.mark.parametrize("damage", ["same-size", "size", "extra", "missing"])
def test_changed_zip_cannot_reuse_immutable_commit_metadata(damage):
    files = {"src/one.py": b"one", "src/two.py": b"two"}
    fetch, _paths, _calls = frozen_git(files)
    changed = dict(files)
    if damage == "same-size":
        changed["src/one.py"] = b"BAD"
    elif damage == "size":
        changed["src/one.py"] = b"different"
    elif damage == "extra":
        changed["src/other.py"] = b"extra"
    else:
        del changed["src/one.py"]
    with pytest.raises(stage.SourceStageError, match="differs"):
        stage.read_verified_source_archive(archive(changed, TARGET), TARGET, fetch=fetch)


@pytest.mark.parametrize("damage", [
    "commit-id", "commit-tree", "tree-id", "truncated", "truncated-integer", "duplicate",
    "missing-parent", "case-parent", "symlink", "submodule", "blob-id", "blob-size-bool",
    "tree-object-id", "invalid-kind", "unpaired-surrogate",
])
def test_inconsistent_git_object_graph_is_held(damage):
    files = {"src/a.py": b"one"}
    fetch, paths, _calls = frozen_git(files)
    commit = paths["git/commits/" + TARGET]
    tree = paths[next(path for path in paths if path.startswith("git/trees/"))]
    blob = next(row for row in tree["tree"] if row["type"] == "blob")
    directory = next(row for row in tree["tree"] if row["type"] == "tree")
    if damage == "commit-id":
        commit["sha"] = BASE
    elif damage == "commit-tree":
        commit["tree"] = {"sha": "invalid"}
    elif damage == "tree-id":
        tree["sha"] = BASE
    elif damage == "truncated":
        tree["truncated"] = True
    elif damage == "truncated-integer":
        tree["truncated"] = 0
    elif damage == "duplicate":
        tree["tree"].append(dict(blob))
    elif damage == "missing-parent":
        tree["tree"].remove(directory)
    elif damage == "case-parent":
        directory["path"] = "SRC"
    elif damage == "symlink":
        blob["mode"] = "120000"
    elif damage == "submodule":
        blob.update(type="commit", mode="160000")
    elif damage == "blob-id":
        blob["sha"] = BASE
    elif damage == "blob-size-bool":
        blob["size"] = True
    elif damage == "tree-object-id":
        directory["sha"] = BASE
    elif damage == "invalid-kind":
        blob["type"] = []
    else:
        blob["path"] = "src/\ud800.py"
    with pytest.raises(stage.SourceStageError):
        stage.read_verified_source_archive(archive(files, TARGET), TARGET, fetch=fetch)


@pytest.mark.parametrize("bound", ["entries", "files", "bytes"])
def test_metadata_bounds_hold_before_archive_decompression(monkeypatch, bound):
    files = {"a.py": b"aaa", "b.py": b"bbb", "c.py": b"ccc"}
    fetch, _paths, _calls = frozen_git(files)
    if bound == "entries":
        monkeypatch.setattr(stage, "MAX_FILES", 1)
    elif bound == "files":
        monkeypatch.setattr(stage, "MAX_FILES", 2)
    else:
        monkeypatch.setattr(stage, "MAX_TREE_BYTES", 2)
    monkeypatch.setattr(stage, "read_source_archive", lambda *_args, **_kwargs: pytest.fail("unsafe metadata must precede decompression"))
    with pytest.raises(stage.SourceStageError, match="budget"):
        stage.read_verified_source_archive(b"never decompressed", TARGET, fetch=fetch)


def test_cancellation_during_metadata_stops_before_archive_work(monkeypatch):
    files = {"a.py": b"aaa"}
    supplied, _paths, _calls = frozen_git(files)
    cancelled = [False]

    def fetch(path):
        result = supplied(path)
        if path.startswith("git/trees/"):
            cancelled[0] = True
        return result

    monkeypatch.setattr(stage, "read_source_archive", lambda *_args, **_kwargs: pytest.fail("cancelled producer must retire"))
    with pytest.raises(stage.SourceStageError, match="cancelled"):
        stage.read_verified_source_archive(b"unused", TARGET, fetch=fetch, cancelled=lambda: cancelled[0])


def test_actual_preparation_rejects_tampered_target_before_candidate_or_blob_writes(tmp_path, monkeypatch):
    base, user, incoming = {"code.py": b"a=1\n"}, {"code.py": b"a=1\n"}, {"code.py": b"a=2\n"}
    source, state, archives, comparison = fixture(tmp_path, monkeypatch, base, user, incoming)
    target_fetch, _paths, _calls = frozen_git(incoming)
    base_fetch, _paths, _calls = frozen_git(base, BASE)
    base_tree = git_tree_metadata(base)["sha"]

    def fetch(path):
        if path.startswith("compare/"):
            return comparison
        if path == "git/commits/" + BASE or path.startswith("git/trees/" + base_tree):
            return base_fetch(path)
        return target_fetch(path)

    damaged = dict(incoming, **{"code.py": b"a=9\n"})
    archives[TARGET] = archive(damaged, TARGET)
    original = {name: (source / name).read_bytes() for name in user}
    with pytest.raises(stage.SourceStageError, match="blob differs"):
        stage.prepare_source_update(source, state, TARGET, fetch=fetch, download=archives.__getitem__)
    prepared = list(state.glob("source-*"))
    assert len(prepared) == 1
    assert not (prepared[0] / "candidate").exists() and not (prepared[0] / "preserved-blobs").exists()
    assert json.loads((prepared[0] / "intent.json").read_bytes())["status"] == "failed"
    assert {name: (source / name).read_bytes() for name in user} == original


@pytest.mark.parametrize("path", ["git/commits/" + TARGET, "git/trees/" + TARGET + "?recursive=1",
                                  "branches/main", "releases/latest", "compare/" + BASE + "..." + TARGET])
def test_closed_metadata_endpoint_policy_retains_separate_read_budgets(monkeypatch, path):
    observed = []

    @contextmanager
    def fake_open(request, **kwargs):
        observed.append(request.full_url)
        yield io.BytesIO(b"{}")

    def read_bounded(response, maximum):
        observed.append(maximum)
        return response.read()

    monkeypatch.setattr(updates, "safe_urlopen", fake_open)
    monkeypatch.setattr(updates, "read_bounded", read_bounded)
    assert updates.github_json(path) == {}
    assert observed == ["https://api.github.com/repos/Ag3nt47/AngeronaSuite/" + path,
                        updates.MAX_GIT_METADATA_BYTES if path.startswith("git/") else updates.MAX_METADATA_BYTES]


@pytest.mark.parametrize("path", ["git/commits/main", "git/trees/" + TARGET, "git/trees/" + TARGET + "?recursive=2",
                                  "git/commits/" + TARGET + "/extra", "../git/commits/" + TARGET])
def test_git_metadata_cannot_expand_repository_or_endpoint_authority(monkeypatch, path):
    monkeypatch.setattr(updates, "safe_urlopen", lambda *_a, **_k: pytest.fail("invalid endpoint must not egress"))
    with pytest.raises(ValueError, match="unsupported"):
        updates.github_json(path)
