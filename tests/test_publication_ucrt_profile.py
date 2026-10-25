from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import publication_transport as transport
from tools import windows_publication_runtime as runtime


def test_reviewed_profile_requires_authenticated_security_release_ucrt_closure():
    profile = runtime.load_runtime_profile()
    assert profile.git_version == "2.56.0.windows.3"
    assert profile.git_build_commit == "0e9926caea36270e3e9067b5ac512ac0335a004a"
    assert runtime.TREE_ROOTS == ("cmd", "ucrt64/bin", "ucrt64/libexec/git-core")
    assert all("mingw64" not in item.relative for item in profile.files)
    assert {"ucrt64/bin/git-credential-manager.exe", "ucrt64/libexec/git-core/git-remote-https.exe"}.issubset({item.relative for item in profile.files})


def test_reanchored_legacy_root_is_rejected_by_fixed_schema(monkeypatch):
    import hashlib
    document = json.loads(runtime.PROFILE_PATH.read_bytes())
    document["tree_roots"] = [value.replace("ucrt64", "mingw64") for value in document["tree_roots"]]
    raw = (json.dumps(document, indent=2)+"\n").encode()
    monkeypatch.setattr(runtime, "REVIEWED_PROFILE_SIZE", len(raw))
    monkeypatch.setattr(runtime, "REVIEWED_PROFILE_SHA256", hashlib.sha256(raw).hexdigest())
    with pytest.raises(runtime.WindowsRuntimeError, match="tree roots changed"):
        runtime._parse_reviewed_profile(raw)


def test_reanchored_downgrade_metadata_still_refuses_compiled_authority(monkeypatch):
    import hashlib
    document = json.loads(runtime.PROFILE_PATH.read_bytes())
    document["git_version"] = "2.55.0.windows.5"
    document["git_build_commit"] = "32c4f7689275d233577576630e1ac5b7eb354eb0"
    raw = (json.dumps(document, indent=2)+"\n").encode()
    monkeypatch.setattr(runtime, "REVIEWED_PROFILE_SIZE", len(raw))
    monkeypatch.setattr(runtime, "REVIEWED_PROFILE_SHA256", hashlib.sha256(raw).hexdigest())
    with pytest.raises(runtime.WindowsRuntimeError, match="compiled tree authority"):
        runtime._parse_reviewed_profile(raw)


def test_staged_entrypoints_have_no_legacy_toolchain_fallback(tmp_path):
    staged = runtime.StagedWindowsRuntime(root=tmp_path, scratch_root=tmp_path / "state", scratch_handle=0,
        scratch_identity=None, parent_handle=0, file_handles={}, directory_handles={}, profile=SimpleNamespace(), current_sid="fixture")
    try:
        assert staged.executable == tmp_path / "cmd" / "git.exe"
        assert staged.credential_helper == tmp_path / "ucrt64" / "bin" / "git-credential-manager.exe"
        assert staged.git_exec_path == tmp_path / "ucrt64" / "libexec" / "git-core"
    finally:
        # No native objects were created; keep the destructor out of fixture paths.
        staged._closed = True


def test_windows_transport_path_contains_only_reviewed_ucrt_bins(tmp_path, monkeypatch):
    if transport.os.name != "nt":
        pytest.skip("Windows transport environment")
    windows = tmp_path / "Windows"
    system = windows / "System32"
    system.mkdir(parents=True)
    (system / "cmd.exe").write_bytes(b"inert command processor")
    monkeypatch.setattr(transport, "_windows_directory", lambda: windows)
    staged = SimpleNamespace(root=tmp_path / "reviewed", git_exec_path=tmp_path / "reviewed/ucrt64/libexec/git-core",
        shell_path=tmp_path / "reviewed/usr/bin", scratch_root=tmp_path / "state")
    for path in (staged.root / "cmd", staged.root / "ucrt64/bin", staged.git_exec_path, staged.shell_path):
        path.mkdir(parents=True, exist_ok=True)
    environment = transport._minimal_git_environment(staged.root, staged=staged)
    paths = tuple(environment["PATH"].split(transport.os.pathsep))
    assert str(staged.root / "ucrt64/bin") in paths
    assert str(staged.root / "mingw64/bin") not in paths
    assert environment["GIT_EXEC_PATH"] == str(staged.git_exec_path)
