"""Publish one reviewed Angerona commit and prove default-branch visibility."""

from __future__ import annotations

import argparse
import contextvars
import hashlib
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar
from urllib.parse import unquote, urlsplit

if __package__ in {None, ""}:  # Allow direct execution from the repository.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.validate_documentation_drift import validate  # noqa: E402
from tools.publication_transport import (  # noqa: E402
    PublicationTransportError,
    TrustedGitBoundary,
    bounded_error,
    resolve_trusted_git_boundary,
)
from tools.verify_published_readme_assets import (  # noqa: E402
    PublishedAssetError,
    verify_published_assets,
)


CANONICAL_REPOSITORY = "Ag3nt47/AngeronaSuite"
CANONICAL_ORIGIN = "https://github.com/Ag3nt47/AngeronaSuite.git"
SHA_RE = re.compile(r"[0-9a-f]{40,64}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_MAX_GIT_CONFIG_BYTES = 512 * 1024
_WINDOWS_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ACTIVE_GIT_BOUNDARY: contextvars.ContextVar[TrustedGitBoundary | None] = (
    contextvars.ContextVar("angerona_publication_git_boundary", default=None)
)
_NETWORK_RESULT = TypeVar("_NETWORK_RESULT")


class PublicationError(RuntimeError):
    """Raised when GitHub publication cannot be proven safe and complete."""


@dataclass(frozen=True)
class _ConfigurationSnapshot:
    path: Path
    device: int
    inode: int
    size: int
    modified_ns: int
    sha256: str


def _git(
    root: Path,
    *arguments: str,
    check: bool = True,
    text: bool = True,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    boundary = _ACTIVE_GIT_BOUNDARY.get()
    owned: TrustedGitBoundary | None = None
    try:
        active = boundary or resolve_trusted_git_boundary()
        if boundary is None:
            owned = active
        result = active.run(root, arguments, text=text, timeout=timeout)
    except PublicationTransportError as exc:
        if owned is not None:
            try:
                owned.close()
            except PublicationTransportError:
                pass
        raise PublicationError(str(exc)) from exc
    if owned is not None:
        try:
            owned.close()
        except PublicationTransportError as exc:
            raise PublicationError(str(exc)) from exc
    if check and result.returncode != 0:
        detail = bounded_error(result) or "unknown Git error"
        raise PublicationError(f"git {' '.join(arguments)} failed: {detail}")
    return result


_FULL_TREE_STATUS_TIMEOUT = 120.0


def _worktree_status(root: Path) -> str:
    """Return the complete porcelain status within a fixed fail-closed budget."""

    try:
        return _git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            timeout=_FULL_TREE_STATUS_TIMEOUT,
        ).stdout
    except PublicationError as exc:
        if str(exc) == "trusted Git process timed out":
            raise PublicationError(
                "local worktree status exceeded the 120-second safety deadline; "
                "publication remains unverified"
            ) from None
        raise


def github_repository_from_origin(origin: str) -> str:
    """Parse a credential-free canonical github.com HTTPS remote."""

    parsed = urlsplit(origin.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise PublicationError("origin contains an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise PublicationError(
            "origin must be credential-free HTTPS on canonical github.com"
        )
    decoded = unquote(parsed.path)
    if decoded != parsed.path or "\\" in decoded:
        raise PublicationError("origin contains a non-canonical repository path")
    parts = [part for part in decoded.strip("/").split("/") if part]
    if len(parts) != 2:
        raise PublicationError("origin must identify exactly one owner/repository")
    repository = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    slug = f"{parts[0]}/{repository}"
    if not REPOSITORY_RE.fullmatch(slug):
        raise PublicationError("origin owner/repository contains invalid characters")
    return slug


def require_canonical_publication_origin(origin: str, *, kind: str) -> str:
    """Require the byte-exact maintainer-authorized GitHub origin."""

    if origin != CANONICAL_ORIGIN:
        raise PublicationError(
            f"{kind} origin must equal {CANONICAL_ORIGIN!r} byte-for-byte"
        )
    repository = github_repository_from_origin(origin)
    if repository != CANONICAL_REPOSITORY:
        raise PublicationError(f"{kind} origin repository is not canonical")
    return repository


def _remote_default_branch(root: Path, remote: str) -> str:
    if remote != CANONICAL_ORIGIN:
        raise PublicationError("default-branch query requires the literal canonical URL")
    output = _git(
        root,
        "ls-remote",
        "--symref",
        remote,
        "HEAD",
        timeout=120.0,
    ).stdout
    matches: list[str] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2 and fields[0].startswith("ref: ") and fields[1] == "HEAD":
            ref = fields[0][5:]
            prefix = "refs/heads/"
            if ref.startswith(prefix):
                matches.append(ref[len(prefix) :])
    if len(matches) != 1:
        raise PublicationError("GitHub default branch could not be resolved exactly")
    return matches[0]


def _single_remote_url(root: Path, remote: str, *, push: bool) -> str:
    if remote != "origin":
        raise PublicationError("publication remote must be the exact origin remote")
    kind = "push" if push else "fetch"
    key = "remote.origin.pushurl" if push else "remote.origin.url"
    result = _git(
        root,
        "config",
        "--local",
        "--no-includes",
        "--null",
        "--get-all",
        key,
        check=False,
        text=False,
    )
    if push and result.returncode == 1 and not result.stdout and not result.stderr:
        result = _git(
            root,
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--get-all",
            "remote.origin.url",
            check=False,
            text=False,
        )
    if result.returncode != 0:
        raise PublicationError(
            bounded_error(result) or f"origin {kind} URL query failed"
        )
    expected = CANONICAL_ORIGIN.encode("ascii") + b"\0"
    if result.stdout != expected:
        raise PublicationError(
            f"origin must have exactly one byte-exact canonical {kind} URL"
        )
    return CANONICAL_ORIGIN


def _remote_sha(root: Path, remote: str, branch: str) -> str | None:
    if remote != CANONICAL_ORIGIN:
        raise PublicationError("remote ref query requires the literal canonical URL")
    result = _git(
        root,
        "ls-remote",
        "--exit-code",
        "--heads",
        remote,
        f"refs/heads/{branch}",
        check=False,
        timeout=120.0,
    )
    if result.returncode == 2 and not result.stdout.strip():
        return None
    if result.returncode != 0:
        detail = result.stderr.strip() or "remote ref query failed"
        raise PublicationError(detail)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise PublicationError(f"remote branch {branch!r} is missing or ambiguous")
    fields = lines[0].split("\t")
    if len(fields) != 2 or fields[1] != f"refs/heads/{branch}":
        raise PublicationError(f"remote branch {branch!r} response is malformed")
    sha = fields[0].lower()
    if not SHA_RE.fullmatch(sha):
        raise PublicationError(f"remote branch {branch!r} has an invalid object ID")
    return sha


def _assert_ancestor(root: Path, ancestor: str, descendant: str, label: str) -> None:
    result = _git(
        root,
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        check=False,
    )
    if result.returncode != 0:
        raise PublicationError(
            f"{label} has diverged; refusing automatic merge, rebase, reset, or force-push"
        )


def _fetch_branch(root: Path, remote: str, branch: str) -> str:
    if remote != CANONICAL_ORIGIN:
        raise PublicationError("fetch requires the literal canonical URL")
    tracking = f"refs/remotes/origin/{branch}"
    _git(
        root,
        "fetch",
        "--no-tags",
        remote,
        f"refs/heads/{branch}:{tracking}",
        timeout=180.0,
    )
    return tracking


def _local_configuration_entries(root: Path) -> list[tuple[str, str]]:
    result = _git(
        root,
        "config",
        "--local",
        "--no-includes",
        "--null",
        "--list",
        text=False,
    )
    if not isinstance(result.stdout, bytes) or len(result.stdout) > _MAX_GIT_CONFIG_BYTES:
        raise PublicationError("local Git configuration output is unbounded")
    entries: list[tuple[str, str]] = []
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        if b"\n" not in raw_entry:
            raise PublicationError("local Git configuration entry is malformed")
        raw_key, raw_value = raw_entry.split(b"\n", 1)
        try:
            key = raw_key.decode("utf-8", errors="strict").casefold()
            value = raw_value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PublicationError("local Git configuration is not strict UTF-8") from exc
        entries.append((key, value))
    return entries


def _assert_local_configuration_policy(root: Path) -> None:
    """Reject repository configuration that can alter publication authority."""

    for key, _value in _local_configuration_entries(root):
        permitted_remote = key in {
            "remote.origin.url",
            "remote.origin.pushurl",
            "remote.origin.fetch",
        }
        forbidden = (
            key.startswith(("include.", "includeif.", "url.", "http."))
            or key.startswith(("https.", "credential.", "protocol."))
            or key.startswith(("ssh.", "submodule."))
            or (key.startswith("remote.") and not permitted_remote)
            or key
            in {
                "core.askpass",
                "core.attributesfile",
                "core.fsmonitor",
                "core.gitproxy",
                "core.hookspath",
                "core.sshcommand",
                "core.worktree",
                "extensions.worktreeconfig",
            }
        )
        if forbidden:
            raise PublicationError(
                f"local Git publication authority is forbidden: {key}"
            )


def _configuration_path(root: Path) -> Path:
    raw = _git(
        root,
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "config",
    ).stdout.strip()
    if not raw or "\0" in raw:
        raise PublicationError("local Git configuration path is invalid")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise PublicationError("local Git configuration path is not absolute")
    try:
        resolved = candidate.resolve(strict=True)
        details = candidate.lstat()
    except OSError as exc:
        raise PublicationError("local Git configuration file is unavailable") from exc
    if resolved != candidate or (
        int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
    ):
        raise PublicationError("local Git configuration file is an alias")
    return resolved


def _configuration_snapshot(root: Path) -> _ConfigurationSnapshot:
    path = _configuration_path(root)
    try:
        before = path.stat()
        if (
            not path.is_file()
            or int(getattr(before, "st_nlink", 1)) != 1
            or before.st_size < 0
            or before.st_size > _MAX_GIT_CONFIG_BYTES
        ):
            raise PublicationError("local Git configuration object is untrusted")
        payload = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise PublicationError("local Git configuration could not be read") from exc
    identity_before = (
        int(before.st_dev),
        int(before.st_ino),
        int(before.st_size),
        int(before.st_mtime_ns),
    )
    identity_after = (
        int(after.st_dev),
        int(after.st_ino),
        int(after.st_size),
        int(after.st_mtime_ns),
    )
    if identity_before != identity_after or len(payload) != before.st_size:
        raise PublicationError("local Git configuration changed while being read")
    return _ConfigurationSnapshot(
        path=path,
        device=identity_after[0],
        inode=identity_after[1],
        size=identity_after[2],
        modified_ns=identity_after[3],
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _assert_origin_configuration(
    root: Path,
    expected: _ConfigurationSnapshot,
) -> None:
    _assert_local_configuration_policy(root)
    require_canonical_publication_origin(
        _single_remote_url(root, "origin", push=False),
        kind="fetch",
    )
    require_canonical_publication_origin(
        _single_remote_url(root, "origin", push=True),
        kind="push",
    )
    if _configuration_snapshot(root) != expected:
        raise PublicationError("local Git configuration changed during publication")


def _assert_local_snapshot(root: Path, expected_head: str) -> None:
    """Prove the captured commit and clean worktree still describe this checkout."""

    current = _git(root, "rev-parse", "HEAD").stdout.strip().lower()
    if current != expected_head:
        raise PublicationError("local HEAD changed during publication")
    if _worktree_status(root):
        raise PublicationError("working tree changed during publication")


def _assert_publication_boundary(
    root: Path,
    expected_head: str,
    expected_configuration: _ConfigurationSnapshot,
) -> None:
    _assert_local_snapshot(root, expected_head)
    _assert_origin_configuration(root, expected_configuration)


def _guarded_network_operation(
    root: Path,
    expected_head: str,
    expected_configuration: _ConfigurationSnapshot,
    operation: Callable[[], _NETWORK_RESULT],
) -> _NETWORK_RESULT:
    _assert_publication_boundary(root, expected_head, expected_configuration)
    result = operation()
    _assert_publication_boundary(root, expected_head, expected_configuration)
    return result


def publish(
    root: Path,
    *,
    remote: str = "origin",
    public_branch: str = "main",
    canonical_repository: str = CANONICAL_REPOSITORY,
    verify_only: bool = False,
) -> str:
    """Publish current HEAD to its branch and a safe fast-forward of main."""

    try:
        boundary = resolve_trusted_git_boundary()
    except PublicationTransportError as exc:
        raise PublicationError(str(exc)) from exc
    if not verify_only and boundary.credential_helper is None:
        raise PublicationError(
            "trusted Git Credential Manager is unavailable; publication cannot authenticate"
        )
    token = _ACTIVE_GIT_BOUNDARY.set(boundary)
    try:
        result = _publish_with_trusted_git(
            root,
            remote=remote,
            public_branch=public_branch,
            canonical_repository=canonical_repository,
            verify_only=verify_only,
        )
    except BaseException:
        try:
            boundary.close()
        except PublicationTransportError:
            pass
        raise
    else:
        try:
            boundary.close()
        except PublicationTransportError as exc:
            raise PublicationError(str(exc)) from exc
        return result
    finally:
        _ACTIVE_GIT_BOUNDARY.reset(token)


def _publish_with_trusted_git(
    root: Path,
    *,
    remote: str,
    public_branch: str,
    canonical_repository: str,
    verify_only: bool,
) -> str:
    root = root.resolve()
    if remote != "origin":
        raise PublicationError("publication remote must be the exact origin remote")
    top = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != root:
        raise PublicationError("publication must run from the repository root")
    if _worktree_status(root):
        raise PublicationError("working tree must be clean before publication")

    branch = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    if branch != public_branch and not branch.startswith("codex/"):
        raise PublicationError("publication branch must be main or codex/*")
    if _git(root, "check-ref-format", "--branch", branch, check=False).returncode != 0:
        raise PublicationError("current branch name is invalid")

    head = _git(root, "rev-parse", "HEAD").stdout.strip().lower()
    if not SHA_RE.fullmatch(head):
        raise PublicationError("local HEAD is not a valid immutable object ID")

    if canonical_repository != CANONICAL_REPOSITORY:
        raise PublicationError("canonical repository authority cannot be overridden")
    origin = _single_remote_url(root, remote, push=False)
    repository = require_canonical_publication_origin(origin, kind="fetch")
    push_origin = _single_remote_url(root, remote, push=True)
    push_repository = require_canonical_publication_origin(push_origin, kind="push")
    if repository != push_repository:
        raise PublicationError("fetch and push origin repositories differ")
    _assert_local_configuration_policy(root)
    configuration = _configuration_snapshot(root)
    _assert_publication_boundary(root, head, configuration)

    default_branch = _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_default_branch(root, CANONICAL_ORIGIN),
    )
    if default_branch != public_branch:
        raise PublicationError(
            f"GitHub default branch is {default_branch!r}, expected {public_branch!r}"
        )

    documentation_errors = validate(root)
    if documentation_errors:
        raise PublicationError(
            "offline publication validation failed: " + "; ".join(documentation_errors)
        )

    public_tracking = _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _fetch_branch(root, CANONICAL_ORIGIN, public_branch),
    )
    _assert_ancestor(root, public_tracking, head, f"remote {public_branch}")

    branch_remote = _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_sha(root, CANONICAL_ORIGIN, branch),
    )
    if branch != public_branch and branch_remote is not None:
        branch_tracking = _guarded_network_operation(
            root,
            head,
            configuration,
            lambda: _fetch_branch(root, CANONICAL_ORIGIN, branch),
        )
        _assert_ancestor(root, branch_tracking, head, f"remote {branch}")

    if verify_only:
        public_sha = _guarded_network_operation(
            root,
            head,
            configuration,
            lambda: _remote_sha(root, CANONICAL_ORIGIN, public_branch),
        )
        if branch_remote != head or public_sha != head:
            raise PublicationError("remote branch/default-main SHA does not equal HEAD")
    else:
        refspecs = [f"{head}:refs/heads/{branch}"]
        if branch != public_branch:
            refspecs.append(f"{head}:refs/heads/{public_branch}")
        _guarded_network_operation(
            root,
            head,
            configuration,
            lambda: _git(
                root,
                "push",
                "--porcelain",
                "--atomic",
                "--no-follow-tags",
                CANONICAL_ORIGIN,
                *refspecs,
                timeout=240.0,
            ),
        )

    if _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_sha(root, CANONICAL_ORIGIN, branch),
    ) != head:
        raise PublicationError(f"remote {branch} did not advance to exact HEAD")
    if _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_sha(root, CANONICAL_ORIGIN, public_branch),
    ) != head:
        raise PublicationError(f"remote {public_branch} is not default-page visible at HEAD")
    if _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_default_branch(root, CANONICAL_ORIGIN),
    ) != public_branch:
        raise PublicationError("GitHub default branch changed during publication")
    _assert_publication_boundary(root, head, configuration)

    try:
        _assert_publication_boundary(root, head, configuration)
        verified = verify_published_assets(
            root,
            repository=repository,
            ref=head,
            expected_commit=head,
            git_boundary=_ACTIVE_GIT_BOUNDARY.get(),
        )
        _assert_publication_boundary(root, head, configuration)
    except (OSError, PublishedAssetError) as exc:
        raise PublicationError(f"public README asset verification failed: {exc}") from exc
    if _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_sha(root, CANONICAL_ORIGIN, branch),
    ) != head:
        raise PublicationError(f"remote {branch} changed during asset verification")
    if _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_sha(root, CANONICAL_ORIGIN, public_branch),
    ) != head:
        raise PublicationError(f"remote {public_branch} changed during asset verification")
    if _guarded_network_operation(
        root,
        head,
        configuration,
        lambda: _remote_default_branch(root, CANONICAL_ORIGIN),
    ) != public_branch:
        raise PublicationError("GitHub default branch changed during asset verification")
    # This is deliberately the last proof before reporting success. The network
    # verifier read only immutable blobs from ``head``; a concurrent worktree or
    # checkout edit cannot change its expected README target set or image bytes.
    _assert_publication_boundary(root, head, configuration)
    print(
        f"GitHub publication verified: {repository} {branch} -> {public_branch} "
        f"at {head}; {len(verified)} public images match"
    )
    return head


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root",
    )
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        publish(
            args.root,
            verify_only=args.verify_only,
        )
    except (OSError, PublicationError) as exc:
        print(f"GitHub publication: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
