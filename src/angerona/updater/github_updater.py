"""Bounded, read-only GitHub update discovery shared by the GUI and CLI.

Discovery is not installation authority. GitHub main and published releases are
reported separately; a source revision difference is not proof of a newer or
safe release. Installation keeps the independently pinned release verifier.
"""
from __future__ import annotations

import json
import math
import os
import re
import stat
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from angerona import __version__
from angerona.core.atomic_io import replace_with_retry
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError
from angerona.core.url_policy import host_policy, read_bounded, safe_urlopen
from angerona.updater.source_git import read_source_git, source_git_session

CANONICAL_REPOSITORY = "Ag3nt47/AngeronaSuite"
CANONICAL_ORIGIN = f"https://github.com/{CANONICAL_REPOSITORY}.git"
DAILY_SECONDS = 24 * 60 * 60
MANUAL_MIN_SECONDS = 60
MAX_METADATA_BYTES = 512 * 1024
MAX_STATE_BYTES = 16 * 1024
_SHA = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
_GITHUB_POLICY = host_policy("canonical GitHub update API", {"api.github.com"})
_STATE_SCHEMA = "angerona.github-update-check/v1"


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json(raw: bytes, maximum: int) -> dict:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        raise ValueError("metadata exceeds its byte limit")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    return value


def version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ValueError("release version must be vMAJOR.MINOR.PATCH")
    return tuple(int(part) for part in value.removeprefix("v").split("."))


def _repository(repo: str) -> str:
    if repo != CANONICAL_REPOSITORY:
        raise ValueError(f"Updates require the canonical repository {CANONICAL_REPOSITORY}")
    return repo


def github_json(path: str) -> dict:
    """Only internal fixed-shape API paths may reach the canonical repository."""
    if not re.fullmatch(r"(?:branches/main|releases/latest|compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40})", path):
        raise ValueError("unsupported GitHub update endpoint")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{CANONICAL_REPOSITORY}/{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "Angerona-Updater"},
    )
    with safe_urlopen(req, policy=_GITHUB_POLICY, timeout=15) as response:
        return _json(read_bounded(response, MAX_METADATA_BYTES), MAX_METADATA_BYTES)


@dataclass(frozen=True)
class UpdateReport:
    status: str
    checked_at: float
    local_version: str
    local_revision: str = ""
    remote_revision: str = ""
    release_tag: str = ""
    release_status: str = "unavailable"
    source_status: str = "unavailable"
    message: str = ""
    next_check_at: float = 0.0

    @property
    def available(self) -> bool:
        return self.release_status == "newer" or self.source_status == "different"

    @property
    def source_url(self) -> str:
        return f"https://github.com/{CANONICAL_REPOSITORY}/commit/{self.remote_revision}" if _SHA.fullmatch(self.remote_revision) else ""

    @property
    def release_url(self) -> str:
        return f"https://github.com/{CANONICAL_REPOSITORY}/releases/tag/{self.release_tag}" if self.release_tag and _VERSION.fullmatch(self.release_tag) else ""

    def summary(self) -> str:
        if self.status in {"failed", "busy", "not_due", "clock_rollback"}:
            return self.message
        release = {
            "newer": f"Published release {self.release_tag} is available (installed v{self.local_version}).",
            "current": f"Published release is not newer than installed v{self.local_version}.",
            "none": "No published stable GitHub release is available.",
            "unavailable": "Published release status is unavailable.",
        }[self.release_status]
        source = {
            "different": "GitHub main differs from this checkout; ancestry and preservation checks are required before updating.",
            "same": "This checkout matches the observed GitHub main revision.",
            "unknown": "The installed source revision is unknown; source currency cannot be established.",
            "unavailable": "GitHub main could not be checked.",
        }[self.source_status]
        return f"{release} {source} {self.message}".strip()


def local_source_revision(root: Path) -> str:
    """Read canonical checkout identity without changing refs or the index."""
    try:
        with source_git_session():
            values = []
            for args in (("remote", "get-url", "origin"), ("rev-parse", "--verify", "HEAD")):
                raw = read_source_git(root, args)
                if len(raw) > 4096:
                    return ""
                values.append(raw.decode("ascii").strip())
        return values[1] if values[0] == CANONICAL_ORIGIN and _SHA.fullmatch(values[1]) else ""
    except Exception:
        return ""


def check_installed_updates(state_dir: Path, source_root: Path, *, force: bool = False) -> UpdateReport:
    """Plain Qt-free reader; inputs may safely be captured by an AsyncSnapshot."""
    return daily_update_check(state_dir, force=force, revision_reader=lambda: local_source_revision(source_root))


def discover_updates(*, local_revision: str = "", version: str = __version__,
                     now: float | None = None, fetch: Callable[[str], dict] = github_json) -> UpdateReport:
    """Malformed or unavailable metadata never produces an up-to-date verdict."""
    version_tuple(version)
    if local_revision and not _SHA.fullmatch(local_revision):
        raise ValueError("invalid local source revision")
    when = time.time() if now is None else now
    errors = []
    remote = tag = ""
    source_status = release_status = "unavailable"
    try:
        branch = fetch("branches/main")
        commit = branch.get("commit") if isinstance(branch, dict) else None
        remote = commit.get("sha", "") if isinstance(commit, dict) else ""
        if branch.get("name") != "main" or not isinstance(remote, str) or not _SHA.fullmatch(remote):
            raise ValueError("invalid main branch metadata")
        source_status = "unknown" if not local_revision else "same" if remote == local_revision else "different"
    except Exception as exc:
        remote = ""
        errors.append(f"Source check failed ({type(exc).__name__}).")
    try:
        release = fetch("releases/latest")
        if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
            raise ValueError("invalid stable release metadata")
        tag = release.get("tag_name", "")
        newer = version_tuple(tag) > version_tuple(version)
        release_status = "newer" if newer else "current"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            release_status = "none"
        else:
            errors.append(f"Release check failed (HTTP {exc.code}).")
    except Exception as exc:
        tag = ""
        errors.append(f"Release check failed ({type(exc).__name__}).")
    return UpdateReport("partial" if errors else "checked", when, version, local_revision,
                        remote, tag, release_status, source_status, " ".join(errors), when + DAILY_SECONDS)


def _safe_state_root(directory: Path) -> Path:
    root = Path(os.path.abspath(directory))
    for ancestor in (root, *root.parents):
        if ancestor.exists() or ancestor.is_symlink():
            info = ancestor.lstat()
            if ancestor.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("update state path is reparse-backed")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not root.is_dir():
        raise ValueError("update state is not a directory")
    return root


def _read_state(path: Path) -> dict:
    if not path.exists():
        return {}
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > MAX_STATE_BYTES:
        raise ValueError("update state is not a bounded regular file")
    state = _json(path.read_bytes(), MAX_STATE_BYTES)
    if state.get("schema") != _STATE_SCHEMA or state.get("repository") != CANONICAL_REPOSITORY:
        raise ValueError("update state identity mismatch")
    attempted = state.get("last_attempt")
    if type(attempted) not in (int, float) or not math.isfinite(attempted) or attempted < 0:
        raise ValueError("invalid update check timestamp")
    return state


def _write_state(path: Path, value: dict) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("update state exceeds byte limit")
    pending = path.with_name(path.name + "." + uuid.uuid4().hex + ".pending")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def daily_update_check(state_dir: Path, *, force: bool = False, local_revision: str = "",
                       version: str = __version__, now: float | None = None,
                       fetch: Callable[[str], dict] = github_json,
                       revision_reader: Callable[[], str] | None = None) -> UpdateReport:
    """Coalesce app/CLI checks; record an attempt durably before any request."""
    when = time.time() if now is None else now
    if type(when) not in (int, float) or not math.isfinite(when) or when < 0:
        raise ValueError("invalid update check time")
    try:
        root = _safe_state_root(state_dir)
        with ExclusiveFileLease(root / "check.lock"):
            path = root / "check.json"
            state = _read_state(path)
            last = state.get("last_attempt")
            if last is not None:
                interval = MANUAL_MIN_SECONDS if force else DAILY_SECONDS
                if when < last:
                    return UpdateReport("clock_rollback", when, version, local_revision,
                                        message="The update-check clock moved backwards; no network request was made.",
                                        next_check_at=last + interval)
                if when < last + interval:
                    return UpdateReport("not_due", when, version, local_revision,
                                        message="An update check was already attempted recently; no duplicate request was made.",
                                        next_check_at=last + interval)
            state = {"schema": _STATE_SCHEMA, "repository": CANONICAL_REPOSITORY,
                     "last_attempt": when, "outcome": "checking"}
            _write_state(path, state)
            # Do not stage/inspect a trusted Git runtime for hourly not-due
            # ticks. Source identity work occurs only inside a real attempt.
            if revision_reader is not None:
                try:
                    local_revision = revision_reader()
                except Exception:
                    local_revision = ""
            report = discover_updates(local_revision=local_revision, version=version, now=when, fetch=fetch)
            state["outcome"] = asdict(report)
            _write_state(path, state)
            return report
    except ExclusiveFileLeaseError:
        return UpdateReport("busy", when, version, local_revision,
                            message="Another Angerona process is checking for updates.")
    except Exception as exc:
        return UpdateReport("failed", when, version, local_revision,
                            message=f"Update check failed ({type(exc).__name__}); update status is unknown.")


def check_for_updates(repo: str = CANONICAL_REPOSITORY) -> str:
    """Compatibility entry point; callers must run this blocking read off Qt."""
    try:
        _repository(repo)
        return discover_updates().summary()
    except Exception as exc:
        return f"Update check failed ({type(exc).__name__}); update status is unknown."
