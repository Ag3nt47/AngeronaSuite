from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import publication_transport as transport
from tools import publish_github_update as publisher
from tools import windows_publication_runtime as runtime


ROOT = Path(__file__).resolve().parents[1]


def _internally_consistent_addition(raw: bytes) -> bytes:
    document = json.loads(raw.decode("utf-8"))
    record = {
        "path": "cmd/inert-unreviewed.exe",
        "size": 0,
        "sha256": hashlib.sha256(b"").hexdigest(),
    }
    document["files"].append(record)
    document["files"].sort(key=lambda item: item["path"])
    document["file_count"] = len(document["files"])
    records = tuple(
        runtime.RuntimeFile(item["path"], item["size"], item["sha256"])
        for item in document["files"]
    )
    directories = tuple(document["directories"])
    document["total_bytes"] = sum(item.size for item in records)
    document["tree_sha256"] = runtime._tree_digest(directories, records)
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def _fixture_profile(source: Path) -> runtime.RuntimeProfile:
    payloads = {
        "cmd/git.exe": b"reviewed-git-image",
        "mingw64/bin/git-credential-manager.exe": b"reviewed-gcm-image",
        "mingw64/libexec/git-core/git-remote-https.exe": b"reviewed-https-image",
        "usr/bin/msys-2.0.dll": b"reviewed-shell-runtime",
        "usr/bin/sh.exe": b"reviewed-shell-image",
    }
    directories: set[str] = set()
    records: list[runtime.RuntimeFile] = []
    for relative, payload in payloads.items():
        path = source / Path(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        parent = path.parent
        while parent != source:
            directories.add(parent.relative_to(source).as_posix())
            parent = parent.parent
        records.append(
            runtime.RuntimeFile(
                relative,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            )
        )
    ordered_directories = tuple(sorted(directories))
    ordered_records = tuple(sorted(records, key=lambda item: item.relative))
    return runtime.RuntimeProfile(
        git_version="fixture",
        git_build_commit="0" * 40,
        directories=ordered_directories,
        files=ordered_records,
        total_bytes=sum(item.size for item in ordered_records),
        tree_sha256=runtime._tree_digest(ordered_directories, ordered_records),
    )


def test_compiled_profile_anchor_matches_the_exact_lf_reviewed_bytes() -> None:
    raw = runtime.PROFILE_PATH.read_bytes()
    assert b"\r\n" not in raw
    assert len(raw) == runtime.REVIEWED_PROFILE_SIZE
    assert hashlib.sha256(raw).hexdigest() == runtime.REVIEWED_PROFILE_SHA256
    profile = runtime.load_runtime_profile()
    assert profile.git_version == runtime.REVIEWED_GIT_VERSION
    assert profile.git_build_commit == runtime.REVIEWED_GIT_BUILD_COMMIT
    assert len(profile.directories) == runtime.REVIEWED_DIRECTORY_COUNT
    assert len(profile.files) == runtime.REVIEWED_FILE_COUNT
    assert profile.total_bytes == runtime.REVIEWED_TREE_BYTES
    assert profile.tree_sha256 == runtime.REVIEWED_TREE_SHA256


def test_profile_mutation_and_internally_consistent_addition_fail_compiled_anchor() -> None:
    raw = runtime.PROFILE_PATH.read_bytes()
    reviewed = json.loads(raw)["reviewed_at"]
    altered = ("0" if reviewed[0] != "0" else "1") + reviewed[1:]
    mutation = raw.replace(
        f'"reviewed_at": "{reviewed}"'.encode(),
        f'"reviewed_at": "{altered}"'.encode(),
    )
    assert len(mutation) == len(raw) and mutation != raw
    with pytest.raises(runtime.WindowsRuntimeError, match="compiled SHA-256"):
        runtime._parse_reviewed_profile(mutation)
    addition = _internally_consistent_addition(raw)
    with pytest.raises(runtime.WindowsRuntimeError, match="compiled (size|SHA-256)"):
        runtime._parse_reviewed_profile(addition)


def test_duplicate_profile_keys_remain_invalid_even_if_bytes_were_reanchored(
    monkeypatch,
) -> None:
    raw = runtime.PROFILE_PATH.read_bytes()
    duplicate = raw.replace(
        b'{\n  "schema":',
        b'{\n  "schema": "angerona.publication-git-runtime/v1",\n  "schema":',
        1,
    )
    monkeypatch.setattr(runtime, "REVIEWED_PROFILE_SIZE", len(duplicate))
    monkeypatch.setattr(
        runtime,
        "REVIEWED_PROFILE_SHA256",
        hashlib.sha256(duplicate).hexdigest(),
    )
    with pytest.raises(runtime.WindowsRuntimeError, match="invalid JSON"):
        runtime._parse_reviewed_profile(duplicate)


def test_compiled_profile_constant_mismatch_rejects_exact_profile(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "REVIEWED_PROFILE_SHA256", "0" * 64)
    with pytest.raises(runtime.WindowsRuntimeError, match="compiled SHA-256"):
        runtime.load_runtime_profile()


def test_alternate_profile_path_is_rejected_before_it_can_be_opened(
    tmp_path: Path,
    monkeypatch,
) -> None:
    alternate = tmp_path / runtime.PROFILE_PATH.name
    alternate.write_bytes(runtime.PROFILE_PATH.read_bytes())
    monkeypatch.setattr(
        runtime,
        "_open_profile_at",
        lambda *_args, **_kwargs: pytest.fail("alternate profile must not be opened"),
    )
    with pytest.raises(runtime.WindowsRuntimeError, match="alternate paths"):
        runtime.load_runtime_profile(alternate)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sharing boundary")
def test_profile_read_handle_denies_write_replace_and_link_races(
    tmp_path: Path,
    monkeypatch,
) -> None:
    candidate = (tmp_path / runtime.PROFILE_PATH.name).resolve()
    candidate.write_bytes(runtime.PROFILE_PATH.read_bytes())
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"x" * runtime.REVIEWED_PROFILE_SIZE)
    alias = tmp_path / "profile-alias.json"
    attempted: list[str] = []
    original = runtime._read_handle

    def _race(handle: int, expected_size: int):
        attempted.append("read")
        with pytest.raises(OSError):
            candidate.write_bytes(b"y" * runtime.REVIEWED_PROFILE_SIZE)
        with pytest.raises(OSError):
            os.replace(replacement, candidate)
        try:
            alias.hardlink_to(candidate)
        except OSError:
            pass
        else:
            attempted.append("linked")
        yield from original(handle, expected_size)

    monkeypatch.setattr(runtime, "_read_handle", _race)
    sealed = runtime._open_profile_at(candidate, expected_path=candidate)
    try:
        assert attempted
        if "linked" in attempted:
            with pytest.raises(runtime.WindowsRuntimeError, match="identity changed"):
                sealed.revalidate()
        else:
            sealed.revalidate()
    finally:
        sealed.close()
    assert candidate.read_bytes() == runtime.PROFILE_PATH.read_bytes()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows staging boundary")
def test_profile_seal_is_revalidated_through_lightweight_staging(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = (tmp_path / "source").resolve()
    profile = _fixture_profile(source)
    staging_parent = tmp_path / "staging"
    staging_parent.mkdir()

    class _FixtureSeal:
        def __init__(self) -> None:
            self.profile = profile
            self.calls = 0
            self.closed = False

        def revalidate(self) -> None:
            assert not self.closed
            self.calls += 1

        def close(self) -> None:
            self.closed = True

    seal = _FixtureSeal()
    monkeypatch.setattr(runtime, "_open_reviewed_profile", lambda: seal)
    staged = runtime.stage_pinned_runtime(
        source,
        staging_parent=staging_parent.resolve(),
    )
    try:
        assert seal.calls >= 3
        assert seal.closed
        assert staged.executable.read_bytes() == b"reviewed-git-image"
    finally:
        staged.close()


def test_publisher_constructs_and_binds_transport_before_git_logic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []

    class _Boundary:
        credential_helper = None

        def close(self) -> None:
            events.append("close")

    boundary = _Boundary()

    def _resolve():
        events.append("resolve")
        return boundary

    def _publish(*_args, **_kwargs) -> str:
        assert publisher._ACTIVE_GIT_BOUNDARY.get() is boundary
        events.append("git-logic")
        return "a" * 40

    monkeypatch.setattr(publisher, "resolve_trusted_git_boundary", _resolve)
    monkeypatch.setattr(publisher, "_publish_with_trusted_git", _publish)
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("no pre-boundary process is allowed"),
    )
    assert publisher.publish(tmp_path, verify_only=True) == "a" * 40
    assert events == ["resolve", "git-logic", "close"]


def test_transient_self_consistent_profile_and_git_substitution_launches_nothing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    alternate = _internally_consistent_addition(runtime.PROFILE_PATH.read_bytes())
    fake_git = tmp_path / "git.exe"
    fake_git.write_bytes(b"inert actor-selected image")
    launches: list[list[str]] = []

    def _run(arguments, **_kwargs):
        launches.append(list(arguments))
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

    monkeypatch.setattr(transport.subprocess, "run", _run)
    with pytest.raises(runtime.WindowsRuntimeError, match="compiled (size|SHA-256)"):
        runtime._parse_reviewed_profile(alternate)
    assert fake_git.read_bytes() == b"inert actor-selected image"
    assert launches == []
