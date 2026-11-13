"""Inert tracking proofs: no Git executable, host probe, network or publication."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools import publish_github_update as publisher
from tools import validate_documentation_drift as drift


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "docs/fixture.png"


@pytest.fixture
def image_repository(tmp_path: Path) -> Path:
    image = tmp_path / IMAGE
    image.parent.mkdir()
    image.write_bytes((ROOT / "assets/icons/backup_f_preview.png").read_bytes())
    (tmp_path / "README.md").write_text(f"![fixture]({IMAGE})\n", encoding="utf-8")
    return tmp_path.resolve()


def _forbid_ambient(*_args, **_kwargs):
    pytest.fail("injected tracking must never launch ambient Git")


@pytest.mark.parametrize("ambient", ["missing", "poisoned"])
def test_injected_tracking_uses_only_closed_queries_and_exact_root(
    image_repository: Path, monkeypatch, ambient: str,
) -> None:
    root = image_repository
    path = root / ambient
    path.mkdir()
    if ambient == "poisoned":
        (path / "git.exe").write_bytes(b"inert untrusted executable must never run")
    monkeypatch.setenv("PATH", str(path))
    monkeypatch.setattr(drift.subprocess, "run", _forbid_ambient)
    calls = []

    def admitted(repository: Path, arguments: tuple[str, ...]):
        calls.append((repository, arguments))
        output = str(root) + "\n" if arguments[0] == "rev-parse" else IMAGE + "\n"
        return subprocess.CompletedProcess(arguments, 0, output, "")

    assert drift._validate_local_readme_images(
        root, f"![fixture]({IMAGE})", git_runner=admitted,
    ) == []
    assert calls == [
        (root, ("rev-parse", "--show-toplevel")),
        (root, ("ls-files", "--error-unmatch", "--", IMAGE)),
    ]


def test_validate_forwards_the_same_explicit_runner(image_repository: Path, monkeypatch) -> None:
    root = image_repository
    monkeypatch.setattr(drift.subprocess, "run", _forbid_ambient)
    calls = []

    def admitted(repository: Path, arguments: tuple[str, ...]):
        calls.append((repository, arguments))
        return subprocess.CompletedProcess(arguments, 0, str(root) + "\n", "")

    errors = drift.validate(root, git_runner=admitted)
    assert errors  # The miniature fixture deliberately lacks release metadata.
    assert not any("Git image tracking" in error or "not tracked by Git" in error for error in errors)
    assert calls == [
        (root, ("rev-parse", "--show-toplevel")),
        (root, ("ls-files", "--error-unmatch", "--", IMAGE)),
    ]


@pytest.mark.parametrize("fault,expected", [
    ("untracked", False),
    ("tracking-error", False),
    ("repository-error", None),
    ("wrong-root", None),
    ("missing-repository-query", None),
    ("missing-tracking-query", None),
    ("repository-timeout", None),
    ("tracking-timeout", None),
])
def test_tracking_failures_never_admit_an_image(
    image_repository: Path, monkeypatch, fault: str, expected: bool | None,
) -> None:
    root = image_repository
    monkeypatch.setattr(drift.subprocess, "run", _forbid_ambient)

    def admitted(_repository: Path, arguments: tuple[str, ...]):
        probe = arguments[0] == "rev-parse"
        if fault == ("missing-repository-query" if probe else "missing-tracking-query"):
            raise FileNotFoundError("inert unavailable runner")
        if fault == ("repository-timeout" if probe else "tracking-timeout"):
            raise subprocess.TimeoutExpired(arguments, 30.0)
        code = 1 if (probe and fault == "repository-error") or (not probe and fault == "untracked") else 0
        if not probe and fault == "tracking-error":
            code = 128
        output = str(root.parent if fault == "wrong-root" else root) + "\n"
        return subprocess.CompletedProcess(arguments, code, output, "")

    assert drift._git_tracks(root, IMAGE, git_runner=admitted) is expected
    errors = drift._validate_local_readme_images(
        root, f"![fixture]({IMAGE})", git_runner=admitted,
    )
    assert len(errors) == 1
    assert ("not tracked by Git" if expected is False else "tracking is unavailable") in errors[0]


@pytest.mark.parametrize("failure", ["missing", "timeout"])
def test_standalone_unavailable_git_is_bounded_hidden_and_fails_closed(
    image_repository: Path, monkeypatch, failure: str,
) -> None:
    calls = []

    def unavailable(arguments, **kwargs):
        calls.append((arguments, kwargs))
        if failure == "timeout":
            raise subprocess.TimeoutExpired(arguments, kwargs["timeout"])
        raise FileNotFoundError("inert missing ambient Git")

    monkeypatch.setattr(drift.subprocess, "run", unavailable)
    errors = drift._validate_local_readme_images(image_repository, f"![fixture]({IMAGE})")
    assert len(errors) == 1 and "tracking is unavailable" in errors[0]
    assert calls == [(["git", "rev-parse", "--show-toplevel"], {
        "cwd": image_repository,
        "capture_output": True,
        "text": True,
        "check": False,
        "timeout": 30.0,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
    })]


def test_publication_documentation_adapter_refuses_an_unbound_transport(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(publisher, "resolve_trusted_git_boundary", _forbid_ambient)
    token = publisher._ACTIVE_GIT_BOUNDARY.set(None)
    try:
        with pytest.raises(publisher.PublicationError, match="active trusted Git boundary"):
            publisher._documentation_git(tmp_path, ("ls-files", "--error-unmatch", "--", IMAGE))
    finally:
        publisher._ACTIVE_GIT_BOUNDARY.reset(token)


def test_publisher_injects_its_already_active_boundary_for_documentation(
    image_repository: Path, monkeypatch,
) -> None:
    root = image_repository
    head = "a" * 40
    calls = []

    class ValidationReached(Exception):
        pass

    class Boundary:
        credential_helper = None
        closed = False

        def run(self, repository, arguments, *, text, timeout):
            assert publisher._ACTIVE_GIT_BOUNDARY.get() is self
            assert repository == root and text is True and timeout == 30.0
            calls.append(tuple(arguments))
            outputs = {
                ("rev-parse", "--show-toplevel"): str(root) + "\n",
                ("symbolic-ref", "--quiet", "--short", "HEAD"): "codex/inert-fixture\n",
                ("check-ref-format", "--branch", "codex/inert-fixture"): "",
                ("rev-parse", "HEAD"): head + "\n",
                ("ls-files", "--error-unmatch", "--", IMAGE): IMAGE + "\n",
            }
            assert tuple(arguments) in outputs
            return subprocess.CompletedProcess(arguments, 0, outputs[tuple(arguments)], "")

        def close(self):
            self.closed = True

    boundary = Boundary()
    resolutions = []

    def resolve():
        resolutions.append("admit")
        return boundary

    def validation(repository, *, git_runner):
        assert repository == root
        assert git_runner is publisher._documentation_git
        assert publisher._ACTIVE_GIT_BOUNDARY.get() is boundary
        assert drift._validate_local_readme_images(
            repository, f"![fixture]({IMAGE})", git_runner=git_runner,
        ) == []
        raise ValidationReached

    monkeypatch.setattr(publisher, "resolve_trusted_git_boundary", resolve)
    monkeypatch.setattr(publisher, "_worktree_status", lambda _root: "")
    monkeypatch.setattr(publisher, "_single_remote_url", lambda *_args, **_kwargs: publisher.CANONICAL_ORIGIN)
    monkeypatch.setattr(publisher, "_assert_local_configuration_policy", lambda _root: None)
    monkeypatch.setattr(publisher, "_configuration_snapshot", lambda _root: object())
    monkeypatch.setattr(publisher, "_assert_publication_boundary", lambda *_args: None)
    monkeypatch.setattr(publisher, "_remote_default_branch", lambda *_args: "main")
    monkeypatch.setattr(publisher, "validate", validation)
    monkeypatch.setattr(drift.subprocess, "run", _forbid_ambient)
    with pytest.raises(ValidationReached):
        publisher.publish(root, verify_only=True)
    assert calls[-2:] == [
        ("rev-parse", "--show-toplevel"),
        ("ls-files", "--error-unmatch", "--", IMAGE),
    ]
    assert resolutions == ["admit"]
    assert boundary.closed
    assert publisher._ACTIVE_GIT_BOUNDARY.get() is None
