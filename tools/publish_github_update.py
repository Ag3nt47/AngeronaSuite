"""Publish one reviewed Angerona commit and prove default-branch visibility."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

if __package__ in {None, ""}:  # Allow direct execution from the repository.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.validate_documentation_drift import validate  # noqa: E402
from tools.verify_published_readme_assets import (  # noqa: E402
    PublishedAssetError,
    verify_published_assets,
)


CANONICAL_REPOSITORY = "Ag3nt47/AngeronaSuite"
SHA_RE = re.compile(r"[0-9a-f]{40,64}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class PublicationError(RuntimeError):
    """Raised when GitHub publication cannot be proven safe and complete."""


def _git(
    root: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise PublicationError(f"git {' '.join(arguments)} failed: {detail}")
    return result


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


def _remote_default_branch(root: Path, remote: str) -> str:
    output = _git(root, "ls-remote", "--symref", remote, "HEAD").stdout
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
    arguments = ["remote", "get-url"]
    if push:
        arguments.append("--push")
    arguments.extend(["--all", remote])
    urls = [line.strip() for line in _git(root, *arguments).stdout.splitlines()]
    urls = [url for url in urls if url]
    if len(urls) != 1:
        kind = "push" if push else "fetch"
        raise PublicationError(f"origin must have exactly one {kind} URL")
    return urls[0]


def _remote_sha(root: Path, remote: str, branch: str) -> str | None:
    result = _git(
        root,
        "ls-remote",
        "--exit-code",
        "--heads",
        remote,
        f"refs/heads/{branch}",
        check=False,
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
    tracking = f"refs/remotes/{remote}/{branch}"
    _git(
        root,
        "fetch",
        "--no-tags",
        remote,
        f"refs/heads/{branch}:{tracking}",
    )
    return tracking


def publish(
    root: Path,
    *,
    remote: str = "origin",
    public_branch: str = "main",
    canonical_repository: str = CANONICAL_REPOSITORY,
    verify_only: bool = False,
) -> str:
    """Publish current HEAD to its branch and a safe fast-forward of main."""

    root = root.resolve()
    top = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != root:
        raise PublicationError("publication must run from the repository root")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all").stdout:
        raise PublicationError("working tree must be clean before publication")

    branch = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    if branch != public_branch and not branch.startswith("codex/"):
        raise PublicationError("publication branch must be main or codex/*")
    if _git(root, "check-ref-format", "--branch", branch, check=False).returncode != 0:
        raise PublicationError("current branch name is invalid")

    head = _git(root, "rev-parse", "HEAD").stdout.strip().lower()
    if not SHA_RE.fullmatch(head):
        raise PublicationError("local HEAD is not a valid immutable object ID")

    origin = _single_remote_url(root, remote, push=False)
    repository = github_repository_from_origin(origin)
    push_origin = _single_remote_url(root, remote, push=True)
    push_repository = github_repository_from_origin(push_origin)
    if repository != canonical_repository:
        raise PublicationError(
            f"origin is {repository!r}, expected {canonical_repository!r}"
        )
    if push_repository != canonical_repository:
        raise PublicationError(
            f"push origin is {push_repository!r}, expected {canonical_repository!r}"
        )
    default_branch = _remote_default_branch(root, remote)
    if default_branch != public_branch:
        raise PublicationError(
            f"GitHub default branch is {default_branch!r}, expected {public_branch!r}"
        )

    documentation_errors = validate(root)
    if documentation_errors:
        raise PublicationError(
            "offline publication validation failed: " + "; ".join(documentation_errors)
        )

    public_tracking = _fetch_branch(root, remote, public_branch)
    _assert_ancestor(root, public_tracking, head, f"remote {public_branch}")

    branch_remote = _remote_sha(root, remote, branch)
    if branch != public_branch and branch_remote is not None:
        branch_tracking = _fetch_branch(root, remote, branch)
        _assert_ancestor(root, branch_tracking, head, f"remote {branch}")

    if verify_only:
        if branch_remote != head or _remote_sha(root, remote, public_branch) != head:
            raise PublicationError("remote branch/default-main SHA does not equal HEAD")
    else:
        refspecs = [f"{head}:refs/heads/{branch}"]
        if branch != public_branch:
            refspecs.append(f"{head}:refs/heads/{public_branch}")
        _git(
            root,
            "-c",
            "core.hooksPath=/dev/null",
            "push",
            "--porcelain",
            "--atomic",
            "--no-follow-tags",
            push_origin,
            *refspecs,
        )

    if _remote_sha(root, remote, branch) != head:
        raise PublicationError(f"remote {branch} did not advance to exact HEAD")
    if _remote_sha(root, remote, public_branch) != head:
        raise PublicationError(f"remote {public_branch} is not default-page visible at HEAD")
    if _remote_default_branch(root, remote) != public_branch:
        raise PublicationError("GitHub default branch changed during publication")
    if _git(root, "rev-parse", "HEAD").stdout.strip().lower() != head:
        raise PublicationError("local HEAD changed during publication")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all").stdout:
        raise PublicationError("working tree changed during publication")

    try:
        verified = verify_published_assets(
            root,
            repository=repository,
            ref=head,
        )
    except (OSError, PublishedAssetError) as exc:
        raise PublicationError(f"public README asset verification failed: {exc}") from exc
    if _remote_sha(root, remote, branch) != head:
        raise PublicationError(f"remote {branch} changed during asset verification")
    if _remote_sha(root, remote, public_branch) != head:
        raise PublicationError(f"remote {public_branch} changed during asset verification")
    if _remote_default_branch(root, remote) != public_branch:
        raise PublicationError("GitHub default branch changed during asset verification")
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
