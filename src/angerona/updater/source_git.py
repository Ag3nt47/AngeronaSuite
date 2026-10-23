"""Closed read-only Git commands through Angerona's pinned transport boundary."""
from __future__ import annotations

import contextvars
import os
import re
from contextlib import contextmanager
from pathlib import Path

_ACTIVE = contextvars.ContextVar("angerona_source_update_git", default=None)
_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


class SourceGitUnavailable(RuntimeError):
    pass


@contextmanager
def source_git_session():
    """One retained executable/runtime lease for all queries in a transaction."""
    existing = _ACTIVE.get()
    if existing is not None:
        yield
        return
    try:
        from tools.publication_transport import resolve_trusted_git_boundary
    except ImportError as exc:
        raise SourceGitUnavailable("source update tools are not installed; source identity is unavailable") from exc
    try:
        boundary = resolve_trusted_git_boundary()
    except Exception as exc:
        raise SourceGitUnavailable("the trusted Git source boundary is unavailable") from exc
    token = _ACTIVE.set(boundary)
    try:
        yield
    finally:
        _ACTIVE.reset(token)
        boundary.close()


def read_source_git(root: Path, arguments: tuple[str, ...]) -> bytes:
    allowed = arguments in {
        ("remote", "get-url", "origin"),
        ("rev-parse", "--verify", "HEAD"),
        ("rev-parse", "--verify", "refs/remotes/origin/main"),
        ("ls-files", "-z", "--cached", "--others", "--exclude-standard"),
    }
    if len(arguments) == 4 and arguments[:2] == ("merge-base", "--is-ancestor"):
        allowed = all(isinstance(value, str) and _SHA.fullmatch(value) for value in arguments[2:])
    if not allowed:
        raise SourceGitUnavailable("unsupported source Git command")
    with source_git_session():
        boundary = _ACTIVE.get()
        # The resolver pins the executable/dependencies, scrubs the inherited
        # environment and disables hooks, fsmonitor and interactive helpers.
        # These commands never request checkout filters, textconv or diff tools.
        fixed = ("--no-optional-locks", "--no-replace-objects", "--literal-pathspecs",
                 "-c", "diff.external=", "-c", "core.attributesFile=" + os.devnull,
                 "-c", "credential.helper=", *arguments)
        result = boundary.run(Path(root).absolute(), fixed, text=False, timeout=15)
        if result.returncode != 0:
            raise SourceGitUnavailable("source Git identity or ancestry could not be established")
        if not isinstance(result.stdout, bytes) or len(result.stdout) > MAX_OUTPUT_BYTES:
            raise SourceGitUnavailable("source Git output exceeds its limit")
        return result.stdout
