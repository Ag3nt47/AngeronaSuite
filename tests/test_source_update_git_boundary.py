from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from angerona.updater import github_updater as updates
from angerona.updater import source_git


def test_source_git_uses_only_bound_executable_and_closed_read_only_arguments(tmp_path, monkeypatch) -> None:
    calls = []

    class Boundary:
        def run(self, root, args, *, text, timeout):
            calls.append((root, args, text, timeout))
            return SimpleNamespace(returncode=0, stdout=b"a" * 40 + b"\n")

    token = source_git._ACTIVE.set(Boundary())
    try:
        assert source_git.read_source_git(tmp_path, ("rev-parse", "--verify", "HEAD")) == b"a" * 40 + b"\n"
        with pytest.raises(source_git.SourceGitUnavailable, match="unsupported"):
            source_git.read_source_git(tmp_path, ("checkout", "main"))
        with pytest.raises(source_git.SourceGitUnavailable, match="unsupported"):
            source_git.read_source_git(tmp_path, ("merge-base", "--is-ancestor", "--evil", "a" * 40))
    finally:
        source_git._ACTIVE.reset(token)
    assert len(calls) == 1
    _, args, text, timeout = calls[0]
    assert args[:3] == ("--no-optional-locks", "--no-replace-objects", "--literal-pathspecs")
    assert "diff.external=" in args and "credential.helper=" in args
    assert text is False and timeout == 15


def test_source_identity_never_falls_back_to_path_git(tmp_path, monkeypatch) -> None:
    def unavailable():
        raise source_git.SourceGitUnavailable("unavailable")

    monkeypatch.setattr(updates, "source_git_session", unavailable)
    assert updates.local_source_revision(tmp_path) == ""


def test_source_identity_requires_byte_exact_canonical_origin(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(updates, "source_git_session", nullcontext)
    monkeypatch.setattr(updates, "read_source_git", lambda root, args: b"https://github.com/attacker/AngeronaSuite.git\n" if args[0] == "remote" else b"a" * 40 + b"\n")
    assert updates.local_source_revision(tmp_path) == ""


def test_not_due_ticks_do_not_stage_or_run_the_git_runtime(tmp_path) -> None:
    def fetch(path):
        return {"name": "main", "commit": {"sha": "a" * 40}} if path == "branches/main" else {"tag_name": "v1.14.0", "draft": False, "prerelease": False}

    updates.daily_update_check(tmp_path, now=10, fetch=fetch)
    report = updates.daily_update_check(tmp_path, now=11, fetch=fetch,
                                        revision_reader=lambda: pytest.fail("Git runtime must not start for a not-due tick"))
    assert report.status == "not_due"
