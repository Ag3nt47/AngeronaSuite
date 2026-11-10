"""Bounded, read-only source seals for one mutual-supervision session.

The initial snapshot inherits the launcher's trust decision.  A parent can bind
a peer to that same snapshot with ``expected_digest``; this is not an enrollment
or a replacement for signed release verification.  A failed check never updates
the seal, downloads code, changes files, or grants response authority.

Only the named execution tree and fixed recovery launch files are read.  Cache
directories are excluded because normal imports can write them.  These checks
therefore do not attest already loaded code, cached bytecode, dependencies outside
the tree, the interpreter, or a compromised kernel.  The bounded observation is
also not an execution lease: a later file change can race a subsequent launch.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from angerona.core.source_sandbox import (
    _hold_plain_directories,
    _is_link_or_reparse,
    _read_bytes,
)


MAX_FILES = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_DIRECTORIES = 2000
MAX_CHANGED_PATHS = 32
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DOMAIN = b"angerona-peer-source-v1\0"
_EXTENSIONS = frozenset({".py", ".pyw", ".pyc", ".pyd", ".so"})
_EXCLUDED_DIRECTORIES = frozenset({
    "__pycache__", ".git", ".tmp",
})
# Optional at first capture.  Subsequent appearance/removal is still a change.
_LAUNCH_FILES = (
    "blackbox_recorder.py",
    "start-angerona.bat",
    "Repair-Angerona-Python.ps1",
    "assets/startup-recovery-manifest.json",
    "tools/verify_startup_recovery_bundle.ps1",
    "tools/Invoke-AngeronaSourceStartup.ps1",
    "tools/Invoke-AngeronaStartupRepair.ps1",
    "tools/angerona_recovery.py",
    "tools/ensure_mutual_recovery.py",
    "tools/startup_source_recovery.py",
)


class SourceGuardError(RuntimeError):
    """A bounded source observation or parent snapshot binding failed."""


class SourceGuardTimeout(SourceGuardError):
    """An explicitly bounded observation exhausted its cooperative deadline."""


class SourceGuardCancelled(SourceGuardError):
    """An observation's caller requested cancellation before completion."""


class _CooperativeWork:
    def __init__(self, deadline: float | None, check_cancelled: Callable[[], bool] | None):
        self.deadline = deadline
        self.check_cancelled = check_cancelled
        self.last_clock: float | None = None

    def checkpoint(self) -> None:
        if self.deadline is not None:
            try:
                current = time.monotonic()
                if type(current) not in (int, float):
                    raise ValueError
                now = float(current)
                if (not math.isfinite(now) or now < 0
                        or (self.last_clock is not None and now < self.last_clock)):
                    raise ValueError
            except Exception as exc:
                raise SourceGuardError("Execution source deadline clock is unavailable") from exc
            self.last_clock = now
            if now >= self.deadline:
                raise SourceGuardTimeout("Execution source observation deadline expired")
        if self.check_cancelled is not None:
            try:
                cancelled = self.check_cancelled()
            except Exception as exc:
                raise SourceGuardError("Execution source cancellation check is unavailable") from exc
            if type(cancelled) is not bool:
                raise SourceGuardError("Execution source cancellation check is malformed")
            if cancelled:
                raise SourceGuardCancelled("Execution source observation was cancelled")


def _cooperative_work(
    deadline: float | None, check_cancelled: Callable[[], bool] | None,
) -> _CooperativeWork | None:
    if deadline is None and check_cancelled is None:
        return None
    if deadline is not None:
        try:
            if type(deadline) not in (int, float):
                raise ValueError
            deadline = float(deadline)
            if not math.isfinite(deadline) or deadline <= 0:
                raise ValueError
        except (ValueError, OverflowError) as exc:
            raise SourceGuardError("Execution source deadline is malformed") from exc
    if check_cancelled is not None and not callable(check_cancelled):
        raise SourceGuardError("Execution source cancellation check is malformed")
    return _CooperativeWork(deadline, check_cancelled)


def _checkpoint(work: _CooperativeWork | None) -> None:
    if work is not None:
        work.checkpoint()


@dataclass(frozen=True)
class SourceCheck:
    ok: bool
    state: str
    reason: str
    changed: tuple[str, ...] = ()
    digest: str = ""
    changed_count: int = 0


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _relative(path: Path, root: Path) -> str:
    name = path.relative_to(root).as_posix()
    if (len(name) > 512 or len(path.relative_to(root).parts) > 32
            or "\\" in name or ":" in name):
        raise SourceGuardError("Execution source contains an unsupported path")
    return name


def _plain(info: os.stat_result, *, directory: bool = False) -> None:
    if _is_link_or_reparse(info):
        raise SourceGuardError("Execution source contains a linked or redirected path")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise SourceGuardError("Execution source directory is unavailable")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SourceGuardError("Execution source must use plain single-link files")


def _inventory(
    root: Path, *, _work: _CooperativeWork | None = None,
) -> dict[str, tuple[int, int, int, int]]:
    """Walk only the execution package, never the repository's private caches."""
    package = root / "src" / "angerona"
    found: dict[str, tuple[int, int, int, int]] = {}
    folded: set[str] = set()
    pending = [package]
    directories = entries = total = 0

    def admit(path: Path, info: os.stat_result) -> None:
        nonlocal total
        _plain(info)
        name = _relative(path, root)
        key = name.casefold()
        if key in folded:
            raise SourceGuardError("Execution source contains case-colliding paths")
        if info.st_size > MAX_FILE_BYTES:
            raise SourceGuardError("Execution source exceeds its per-file byte limit")
        folded.add(key)
        total += info.st_size
        if len(found) >= MAX_FILES or total > MAX_TOTAL_BYTES:
            raise SourceGuardError("Execution source exceeds its inventory budget")
        found[name] = _identity(info)
        _checkpoint(_work)

    _checkpoint(_work)
    while pending:
        _checkpoint(_work)
        directory = pending.pop()
        directory_key = _relative(directory, root).casefold()
        if directory_key in folded:
            raise SourceGuardError("Execution source contains case-colliding paths")
        folded.add(directory_key)
        _plain(directory.lstat(), directory=True)
        directories += 1
        if directories > MAX_DIRECTORIES:
            raise SourceGuardError("Execution source exceeds its directory budget")
        _checkpoint(_work)
        with _hold_plain_directories(root, directory):
            _checkpoint(_work)
            with os.scandir(directory) as scan:
                for entry in scan:
                    _checkpoint(_work)
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise SourceGuardError("Execution source exceeds its entry budget")
                    path = Path(entry.path)
                    # Windows DirEntry metadata can omit file IDs/link counts;
                    # collect fresh named metadata for custody instead.
                    info = path.lstat()
                    if entry.name.casefold() in _EXCLUDED_DIRECTORIES:
                        # Exclusions are never traversed, including redirected
                        # bytecode caches and separately enrolled plugin trees.
                        _checkpoint(_work)
                        continue
                    if stat.S_ISDIR(info.st_mode) or _is_link_or_reparse(info):
                        _plain(info, directory=True)
                        pending.append(path)
                    elif path.suffix.casefold() in _EXTENSIONS:
                        admit(path, info)
                    _checkpoint(_work)
        _checkpoint(_work)

    if not found:
        raise SourceGuardError("Execution source package has no sealable files")
    for name in _LAUNCH_FILES:
        _checkpoint(_work)
        path = root / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            _checkpoint(_work)
            continue
        admit(path, info)
    _checkpoint(_work)
    return found


def _observe(
    root: Path, *, _work: _CooperativeWork | None = None,
) -> tuple[tuple[tuple[str, str], ...], str]:
    try:
        _checkpoint(_work)
        with _hold_plain_directories(root):
            _checkpoint(_work)
            before = _inventory(root) if _work is None else _inventory(root, _work=_work)
            _checkpoint(_work)
            values: list[tuple[str, str]] = []
            for name in sorted(before):
                _checkpoint(_work)
                path = root / name
                raw = _read_bytes(path, root=root)
                if len(raw) > MAX_FILE_BYTES or _identity(path.lstat()) != before[name]:
                    raise SourceGuardError("Execution source changed during observation")
                _checkpoint(_work)
                values.append((name, hashlib.sha256(raw).hexdigest()))
                _checkpoint(_work)
            after = _inventory(root) if _work is None else _inventory(root, _work=_work)
            if after != before:
                raise SourceGuardError("Execution source inventory changed during observation")
            _checkpoint(_work)
    except SourceGuardError:
        raise
    except (OSError, ValueError) as exc:
        # Report fixed text rather than leaking an arbitrary native path/error
        # into peer status or treating an unreadable scope as a clean seal.
        raise SourceGuardError("Execution source custody or availability is unverified") from exc
    _checkpoint(_work)
    files = tuple(values)
    encoded = json.dumps(files, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    _checkpoint(_work)
    digest = hashlib.sha256(_DOMAIN + encoded).hexdigest()
    _checkpoint(_work)
    return files, digest


@dataclass(frozen=True)
class SourceGuard:
    root: Path
    digest: str
    _files: tuple[tuple[str, str], ...]

    @classmethod
    def capture(
        cls, root: Path, expected_digest: str | None = None, *,
        deadline: float | None = None, check_cancelled: Callable[[], bool] | None = None,
    ) -> SourceGuard:
        """Seal source, optionally stopping cooperatively between bounded reads.

        ``deadline`` is an absolute monotonic time; it cannot interrupt an
        already-blocked native operation. Cancellation never relaxes custody or
        returns a partial seal. Omitted options preserve the unbounded caller's
        existing inventory/byte limits without querying a clock or callback.
        """
        if (expected_digest is not None
                and (type(expected_digest) is not str or not _DIGEST.fullmatch(expected_digest))):
            raise SourceGuardError("Parent execution source digest is malformed")
        root = Path(root)
        if (not root.is_absolute() or ".." in root.parts
                or str(root).startswith(("\\\\", "//"))):
            raise SourceGuardError("Execution source requires an absolute local root")
        root = Path(os.path.abspath(root))
        work = _cooperative_work(deadline, check_cancelled)
        _checkpoint(work)
        files, digest = _observe(root) if work is None else _observe(root, _work=work)
        if expected_digest is not None and digest != expected_digest:
            raise SourceGuardError("Execution source differs from the parent session seal")
        _checkpoint(work)
        return cls(root, digest, files)

    @property
    def file_count(self) -> int:
        return len(self._files)

    def check(
        self, *, deadline: float | None = None, check_cancelled: Callable[[], bool] | None = None,
    ) -> SourceCheck:
        try:
            work = _cooperative_work(deadline, check_cancelled)
            _checkpoint(work)
            files, digest = _observe(self.root) if work is None else _observe(self.root, _work=work)
            if digest == self.digest:
                result = SourceCheck(True, "verified", "Execution source matches this session seal", digest=digest)
                _checkpoint(work)
            else:
                # Preserve an already observed integrity finding. A late STOP
                # or deadline must fence success, not erase negative evidence.
                before, after = dict(self._files), dict(files)
                changed = tuple(sorted(name for name in before.keys() | after.keys()
                                       if before.get(name) != after.get(name)))
                result = SourceCheck(
                    False, "changed", "Execution source changed; review edits before a new trusted session",
                    changed[:MAX_CHANGED_PATHS], digest, len(changed),
                )
            return result
        except SourceGuardError as exc:
            return SourceCheck(False, "unavailable", str(exc))
