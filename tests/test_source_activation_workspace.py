"""Actual workspace files/ACLs/identities; no activation or retirement grant.

The small plan is content-addressed helper-contract metadata, not a fabricated
full activation approval. The separately opted-in D:/C: case uses actual native
volumes. Default tests do not claim cross-volume deployment or model device IDs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from angerona.core import source_activation_file as files
from angerona.core import source_activation_workspace as workspace
from angerona.core.startup_recovery import private_directory


_PROFILE_SCRATCH = "ANGERONA_TEST_SOURCE_ACTIVATION_PROFILE_SCRATCH"


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _plan(root, state):
    body = {"schema": "angerona.source-activation-plan/v1",
            "source_root": str(root), "state_root": str(state),
            "plan_nonce": "1" * 32, "root_identity": files.directory_identity(root)}
    plan = {**body, "activation_id": _sha(_encoded(body))[:32]}
    return plan, _sha(_encoded(plan))


def _private(path):
    assert private_directory(path, create=True)
    assert private_directory(path, create=False)
    return path


@pytest.fixture
def sample(tmp_path):
    root, data = _private(tmp_path / "source"), _private(tmp_path / "data")
    state = _private(data / "github-updates")
    plan, digest = _plan(root, state)
    return SimpleNamespace(root=root, state=state, plan=plan, digest=digest,
                           temporary=root / ".tmp", fixture=tmp_path)


def _path(sample):
    return workspace.workspace_path(sample.root, sample.plan)


def _marker(path):
    return path / "workspace.json"


def _create(sample):
    descriptor = workspace.create_workspace(sample.root, sample.state,
                                           sample.plan, sample.digest)
    return _path(sample), descriptor


def _read_tree(path):
    # Only this fixture's tiny, already-owned tree; no host inventory discovery.
    return {item.relative_to(path).as_posix():
            (item.read_bytes(), item.stat().st_dev, item.stat().st_ino)
            for item in path.rglob("*") if item.is_file()}


def _directory_security(path):
    if os.name != "nt":
        info = path.stat()
        return info.st_uid, info.st_gid, info.st_mode
    import ctypes
    from ctypes import wintypes as w
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    query = api.GetFileSecurityW
    query.argtypes = (w.LPCWSTR, w.DWORD, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
    query.restype = w.BOOL
    needed = w.DWORD()
    assert not query(str(path), 0x5, None, 0, ctypes.byref(needed))
    assert ctypes.get_last_error() == 122 and 0 < needed.value <= 65536
    capacity = needed.value
    buffer = ctypes.create_string_buffer(capacity)
    if not query(str(path), 0x5, buffer, capacity, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    assert 0 < needed.value <= capacity
    return buffer.raw[:needed.value]


def test_derive_only_leaves_source_and_state_untouched(sample):
    root_id, state_id = files.directory_identity(sample.root), files.directory_identity(sample.state)
    path = _path(sample)
    assert path == sample.root / ".tmp" / ("source-activation-" + sample.plan["plan_nonce"])
    assert not sample.temporary.exists()
    assert list(sample.root.iterdir()) == [] and list(sample.state.iterdir()) == []
    assert files.directory_identity(sample.root) == root_id
    assert files.directory_identity(sample.state) == state_id


@pytest.mark.parametrize("case", [
    "foreign-root", "foreign-state", "wrong-pin", "changed-plan", "wrong-id",
    "bad-nonce", "bad-schema", "changed-root-id",
])
def test_invalid_plan_scope_or_full_content_pin_cannot_create_workspace(sample, case):
    root, state, digest = sample.root, sample.state, sample.digest
    plan = dict(sample.plan, root_identity=dict(sample.plan["root_identity"]))
    if case == "foreign-root":
        root = _private(sample.fixture / "other-source")
    elif case == "foreign-state":
        state = _private(sample.fixture / "other-state")
    elif case == "wrong-pin":
        digest = "0" * 64
    elif case == "changed-plan":
        plan["preserved_changes"] = 1  # The supplied old full-plan SHA must fail.
    elif case == "wrong-id":
        plan["activation_id"] = "0" * 32
        digest = _sha(_encoded(plan))  # Matching outer SHA does not repair content ID.
    elif case == "bad-nonce":
        plan["plan_nonce"] = "../escape"
    elif case == "bad-schema":
        plan["schema"] = "foreign-workspace"
    elif case == "changed-root-id":
        plan["root_identity"]["inode"] = "0"
    with pytest.raises(workspace.SourceActivationWorkspaceError):
        workspace.create_workspace(root, state, plan, digest)
    assert not sample.temporary.exists()
    assert list(sample.state.iterdir()) == []


def test_real_creation_writes_exact_private_marker_before_staging_directories(sample, monkeypatch):
    actual = workspace.write_new
    observed = []

    def write(path, raw):
        assert Path(path) == _marker(_path(sample))
        assert list(Path(path).parent.iterdir()) == []
        assert private_directory(Path(path).parent, create=False)
        observed.append(raw)
        return actual(path, raw)

    monkeypatch.setattr(workspace, "write_new", write)
    path, descriptor = _create(sample)
    assert len(observed) == 1
    assert set(descriptor) == {"relative", "identity", "marker_sha256"}
    assert descriptor["identity"] == files.directory_identity(path)
    assert descriptor["identity"]["device"] == files.directory_identity(sample.root)["device"]
    assert descriptor["marker_sha256"] == _sha(_marker(path).read_bytes())
    value = json.loads(observed[0])
    assert set(value) == {"schema", "source_root", "state_root", "activation_id",
                          "plan_nonce", "plan_sha256", "root_identity", "workspace_identity"}
    assert value == {"schema": "angerona.source-activation-workspace/v1",
        "source_root": str(sample.root), "state_root": str(sample.state),
        "activation_id": sample.plan["activation_id"], "plan_nonce": sample.plan["plan_nonce"],
        "plan_sha256": sample.digest, "root_identity": sample.plan["root_identity"],
        "workspace_identity": descriptor["identity"]}
    assert set(item.name for item in path.iterdir()) == {"workspace.json", "new", "old", "rolled-back"}
    for leaf in ("new", "old", "rolled-back"):
        assert private_directory(path / leaf, create=False)
    assert workspace.validate_workspace(sample.root, sample.state, sample.plan,
                                        sample.digest, descriptor) == (path, descriptor)
    assert workspace.validate_workspace(sample.root, sample.state, sample.plan,
                                        sample.digest) == (path, descriptor)
    assert list(sample.state.iterdir()) == []


def test_existing_plain_tmp_parent_is_not_hardened_or_replaced(sample, monkeypatch):
    sample.temporary.mkdir(mode=0o700)
    before = sample.temporary.stat()
    before_security = _directory_security(sample.temporary)
    actual, calls = workspace.private_directory, []

    def privacy(path, *, create):
        calls.append((Path(path), create))
        assert Path(path) != sample.temporary
        return actual(path, create=create)

    monkeypatch.setattr(workspace, "private_directory", privacy)
    path, _descriptor = _create(sample)
    after = sample.temporary.stat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
    assert path.parent == sample.temporary and calls
    assert _directory_security(sample.temporary) == before_security


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_preexisting_nonce_collision_is_preserved_without_adoption(sample, kind):
    _private(sample.temporary)
    path = _path(sample)
    if kind == "file":
        path.write_bytes(b"unrelated existing file")
        before = path.read_bytes(), path.stat().st_dev, path.stat().st_ino
    else:
        _private(path)
        (path / "retained.txt").write_bytes(b"unrelated existing directory")
        before = _read_tree(path), files.directory_identity(path)
    with pytest.raises(workspace.SourceActivationWorkspaceError, match="already exists"):
        workspace.create_workspace(sample.root, sample.state, sample.plan, sample.digest)
    after = ((path.read_bytes(), path.stat().st_dev, path.stat().st_ino) if kind == "file"
             else (_read_tree(path), files.directory_identity(path)))
    assert after == before
    if kind == "directory":
        assert not _marker(path).exists()


@pytest.mark.parametrize("phase", ["before-marker", "before-second-leaf"])
def test_partial_creation_stays_held_and_never_reused_or_repaired(sample, monkeypatch, phase):
    failure = OSError("inert failure during exclusive workspace creation")
    actual_write, actual_private = workspace.write_new, workspace.private_directory

    def write(path, raw):
        if phase == "before-marker":
            raise failure
        return actual_write(path, raw)

    def privacy(path, *, create):
        if phase == "before-second-leaf" and create and Path(path) == _path(sample) / "old":
            raise failure
        return actual_private(path, create=create)

    with monkeypatch.context() as faults:
        faults.setattr(workspace, "write_new", write)
        faults.setattr(workspace, "private_directory", privacy)
        with pytest.raises(OSError) as result:
            workspace.create_workspace(sample.root, sample.state, sample.plan, sample.digest)
        assert result.value is failure
    path = _path(sample)
    before = _read_tree(path), files.directory_identity(path), set(item.name for item in path.iterdir())
    with pytest.raises((FileNotFoundError, workspace.SourceActivationWorkspaceError)):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest)
    with pytest.raises(workspace.SourceActivationWorkspaceError, match="already exists"):
        workspace.create_workspace(sample.root, sample.state, sample.plan, sample.digest)
    assert (_read_tree(path), files.directory_identity(path), set(item.name for item in path.iterdir())) == before
    if phase == "before-marker":
        assert not _marker(path).exists() and before[2] == set()
    else:
        assert before[2] == {"workspace.json", "new"}


@pytest.mark.parametrize("case", ["malformed", "duplicate", "foreign-state", "wrong-pin", "foreign-workspace", "extra-field"])
def test_actual_marker_tampering_is_held_without_rewrite(sample, case):
    path, descriptor = _create(sample)
    marker = _marker(path)
    value = json.loads(marker.read_bytes())
    if case == "malformed":
        raw = b"{not json"
    elif case == "duplicate":
        raw = b'{"schema":"duplicate",' + marker.read_bytes()[1:]
    else:
        if case == "foreign-state":
            value["state_root"] = str(sample.fixture / "foreign-state")
        elif case == "wrong-pin":
            value["plan_sha256"] = "0" * 64
        elif case == "foreign-workspace":
            value["workspace_identity"] = {**value["workspace_identity"], "inode": "0"}
        else:
            value["unexpected"] = True
        raw = _encoded(value)
    original_id = marker.stat().st_ino
    with marker.open("r+b") as stream:
        stream.write(raw)
        stream.truncate()
    before = _read_tree(path)
    with pytest.raises(workspace.SourceActivationWorkspaceError):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest, descriptor)
    assert _read_tree(path) == before and marker.stat().st_ino == original_id
    assert marker.read_bytes() == raw


@pytest.mark.parametrize("kind", ["unknown-file", "unknown-directory", "missing-leaf"])
def test_unknown_objects_or_missing_leaf_remain_held_without_cleanup(sample, kind):
    path, descriptor = _create(sample)
    if kind == "unknown-file":
        (path / "unowned.txt").write_bytes(b"must remain")
    elif kind == "unknown-directory":
        _private(path / "unowned")
        (path / "unowned/retained.txt").write_bytes(b"must remain")
    else:
        (path / "old").rename(sample.fixture / "preserved-original-old")
    before = _read_tree(path), set(item.name for item in path.iterdir())
    with pytest.raises(workspace.SourceActivationWorkspaceError):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest, descriptor)
    assert (_read_tree(path), set(item.name for item in path.iterdir())) == before
    if kind == "missing-leaf":
        assert not (path / "old").exists()
        assert (sample.fixture / "preserved-original-old").is_dir()


def test_replaced_workspace_native_generation_cannot_reuse_original_marker(sample):
    path, descriptor = _create(sample)
    raw = _marker(path).read_bytes()
    retained = sample.fixture / "preserved-original-workspace"
    path.rename(retained)
    original = _read_tree(retained), files.directory_identity(retained)
    _private(path)
    files.write_new(_marker(path), raw)
    for leaf in ("new", "old", "rolled-back"):
        _private(path / leaf)
    assert files.directory_identity(path) != descriptor["identity"]
    before = _read_tree(path), files.directory_identity(path)
    with pytest.raises(workspace.SourceActivationWorkspaceError, match="marker binding"):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest, descriptor)
    assert (_read_tree(path), files.directory_identity(path)) == before
    assert (_read_tree(retained), files.directory_identity(retained)) == original


def test_replaced_source_root_generation_does_not_admit_old_workspace(sample):
    path, descriptor = _create(sample)
    raw = _marker(path).read_bytes()
    retained = sample.fixture / "preserved-original-source"
    sample.root.rename(retained)
    _private(sample.root)
    with pytest.raises(workspace.SourceActivationWorkspaceError, match="native root identity"):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest, descriptor)
    assert list(sample.root.iterdir()) == []
    assert (retained / descriptor["relative"] / "workspace.json").read_bytes() == raw


def test_marker_hardlink_is_refused_without_removing_either_name(sample):
    path, descriptor = _create(sample)
    marker, second = _marker(path), sample.fixture / "retained-marker-hardlink"
    os.link(marker, second)
    original = marker.read_bytes(), marker.stat().st_ino
    assert marker.stat().st_nlink == 2
    with pytest.raises(workspace.SourceActivationWorkspaceError, match="marker is not private"):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest, descriptor)
    assert (marker.read_bytes(), marker.stat().st_ino) == original
    assert second.read_bytes() == original[0] and second.stat().st_ino == original[1]
    assert marker.stat().st_nlink == 2


def test_actual_tmp_reparse_or_symlink_is_held_without_touching_target(sample):
    target = _private(sample.fixture / "unrelated-directory")
    sentinel = target / "do-not-touch.txt"
    sentinel.write_bytes(b"unrelated fixture data")
    before = sentinel.read_bytes(), sentinel.stat().st_ino
    try:
        sample.temporary.symlink_to(target, target_is_directory=True)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Actual Windows symlink creation privilege unavailable")
        raise
    with pytest.raises(files.ActivationFileError, match="redirected"):
        workspace.create_workspace(sample.root, sample.state, sample.plan, sample.digest)
    assert sample.temporary.is_symlink()
    assert (sentinel.read_bytes(), sentinel.stat().st_ino) == before
    assert set(item.name for item in target.iterdir()) == {sentinel.name}


@pytest.mark.parametrize("field", ["relative", "identity", "marker_sha256"])
def test_descriptor_never_redirects_verification_to_another_object(sample, field):
    path, descriptor = _create(sample)
    selected = dict(descriptor, identity=dict(descriptor["identity"]))
    if field == "relative":
        selected[field] = "../unrelated"
    elif field == "identity":
        selected[field]["inode"] = "0"
    else:
        selected[field] = "0" * 64
    before = _read_tree(path), files.directory_identity(path)
    with pytest.raises(workspace.SourceActivationWorkspaceError, match="descriptor changed"):
        workspace.validate_workspace(sample.root, sample.state, sample.plan, sample.digest, selected)
    assert (_read_tree(path), files.directory_identity(path)) == before
    assert not (sample.fixture / "unrelated").exists()


def test_actual_d_source_c_profile_workspace_uses_real_distinct_native_volumes(tmp_path):
    supplied = os.environ.get(_PROFILE_SCRATCH)
    if not supplied:
        pytest.skip("Root-supplied exact owned C-profile scratch unavailable; cross-volume gate not executed")
    profile = Path(supplied)
    assert profile.is_absolute() and profile.drive.casefold() == "c:"
    assert not str(profile).startswith(("\\\\", "//")) and ".." not in profile.parts
    profile = files.plain_path(profile, directory=True)
    assert private_directory(profile, create=False)
    profile_id = files.directory_identity(profile)
    root = _private(tmp_path / "source")
    assert root.drive.casefold() == "d:"
    owned = profile / ("activation-workspace-test-" + uuid.uuid4().hex)
    _private(owned)
    owned_id = files.directory_identity(owned)
    state = _private(owned / "github-updates")
    state_id = files.directory_identity(state)
    try:
        assert files.directory_identity(root)["device"] != state_id["device"]
        plan, digest = _plan(root, state)
        descriptor = workspace.create_workspace(root, state, plan, digest)
        path, actual = workspace.validate_workspace(root, state, plan, digest, descriptor)
        assert actual == descriptor and path.is_relative_to(root)
        assert actual["identity"]["device"] == files.directory_identity(root)["device"]
        assert actual["identity"]["device"] != state_id["device"]
        marker = json.loads(_marker(path).read_bytes())
        assert marker["source_root"] == str(root) and marker["state_root"] == str(state)
        assert list(state.iterdir()) == []
        assert files.directory_identity(profile) == profile_id
    finally:
        # Only exact exclusively created empty C: directories are removed;
        # no recursive deletion, existing scratch changes or payload cleanup.
        assert files.directory_identity(profile) == profile_id
        assert files.directory_identity(state) == state_id and list(state.iterdir()) == []
        assert files.directory_identity(owned) == owned_id
        state.rmdir()
        assert list(owned.iterdir()) == []
        owned.rmdir()
