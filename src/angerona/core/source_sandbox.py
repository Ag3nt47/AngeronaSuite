"""Isolated working copies for operator-facing source-code exploration.

The menu Info tabs expose the implementation files behind a feature.  Those
files must never be edited merely because an operator wants to experiment, so
this module copies an allow-listed set into Angerona's runtime data directory.
Only the copies are writable.  Reset means "restore the copies from the
installed source"; it never rewrites the installed application.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir, project_root, resource_root


_SAFE_KEY = re.compile(r"[^a-z0-9_-]+")


def _slug(value: object) -> str:
    text = _SAFE_KEY.sub("-", str(value or "").strip().casefold()).strip("-")
    if not text:
        raise ValueError("sandbox key must contain a letter or number")
    return text[:80]


def _relative_source(value: object) -> str:
    """Normalize a catalog path without permitting traversal or absolutes."""
    raw = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe sandbox source path: {value!r}")
    normalized = path.as_posix()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _atomic_bytes_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _atomic_text_write(path: Path, text: str) -> None:
    _atomic_bytes_write(path, text.encode("utf-8"))


@dataclass(frozen=True)
class SandboxFile:
    """One immutable source and its operator-editable working copy."""

    relative_path: str
    source_path: Path
    working_path: Path


class SourceSandboxWorkspace:
    """Manage bounded working copies for one menu/topic.

    ``source_paths`` are repository/resource-root-relative allow-list entries.
    Missing packaged sources are omitted cleanly.  Every public write operation
    addresses an entry from that allow-list, and all writes remain underneath
    ``sandbox_root``.
    """

    def __init__(
        self,
        key: str,
        source_paths: Iterable[str],
        *,
        source_root: Path | None = None,
        sandbox_root: Path | None = None,
    ) -> None:
        self.key = _slug(key)
        preferred = Path(source_root) if source_root is not None else resource_root()
        preferred = preferred.resolve()
        # Source installs use project_root(); frozen builds use resource_root().
        # Keep both as read-only candidates because their layout can differ.
        roots: list[Path] = []
        for candidate in (preferred, project_root().resolve(), resource_root().resolve()):
            if candidate not in roots:
                roots.append(candidate)
        self.source_roots = tuple(roots)

        base = (
            Path(sandbox_root)
            if sandbox_root is not None
            else data_dir() / "code-sandboxes"
        ).resolve()
        self.root = (base / self.key).resolve()
        if not _within(self.root, base):
            raise ValueError("sandbox root escaped its data boundary")

        normalized: list[str] = []
        for raw in source_paths:
            item = _relative_source(raw)
            if item not in normalized:
                normalized.append(item)

        files: list[SandboxFile] = []
        for relative in normalized:
            source = self._find_source(relative)
            if source is None:
                continue
            working = (self.root / Path(relative)).resolve()
            if not _within(working, self.root):
                raise ValueError(f"sandbox working path escaped boundary: {relative}")
            files.append(SandboxFile(relative, source, working))
        self.files = tuple(files)
        self._by_relative = {item.relative_path: item for item in self.files}

    def _find_source(self, relative: str) -> Path | None:
        for root in self.source_roots:
            candidate = (root / Path(relative)).resolve()
            if not _within(candidate, root):
                continue
            try:
                if candidate.is_file() and not candidate.is_symlink():
                    return candidate
            except OSError:
                continue
        return None

    @property
    def available(self) -> bool:
        return bool(self.files)

    def ensure(self) -> tuple[SandboxFile, ...]:
        """Create missing working copies while preserving existing experiments."""
        for item in self.files:
            if not item.working_path.exists():
                _atomic_bytes_write(
                    item.working_path,
                    item.source_path.read_bytes(),
                )
        return self.files

    def file(self, relative_path: str) -> SandboxFile:
        relative = _relative_source(relative_path)
        try:
            return self._by_relative[relative]
        except KeyError as exc:
            raise ValueError(f"source is not allow-listed for this sandbox: {relative}") from exc

    def read(self, relative_path: str) -> str:
        item = self.file(relative_path)
        if not item.working_path.exists():
            self.ensure()
        return item.working_path.read_text(encoding="utf-8")

    def save(self, relative_path: str, text: str) -> SandboxFile:
        """Save an experiment after a syntax gate; never touch ``source_path``."""
        item = self.file(relative_path)
        content = str(text)
        if item.working_path.suffix.casefold() == ".py":
            ast.parse(content, filename=item.relative_path)
        _atomic_text_write(item.working_path, content)
        return item

    def reset(self, relative_paths: Iterable[str] | None = None) -> tuple[SandboxFile, ...]:
        """Restore selected working copies from installed source.

        This deliberately overwrites only known files below the sandbox root.
        The installed source tree is always read-only from this class.
        """
        selected = (
            tuple(self.file(path) for path in relative_paths)
            if relative_paths is not None
            else self.files
        )
        for item in selected:
            _atomic_bytes_write(
                item.working_path,
                item.source_path.read_bytes(),
            )
        return selected

    def changed(self, relative_path: str) -> bool:
        item = self.file(relative_path)
        try:
            original = hashlib.sha256(item.source_path.read_bytes()).digest()
            working = hashlib.sha256(item.working_path.read_bytes()).digest()
            return original != working
        except OSError:
            return False

    def changed_paths(self) -> tuple[str, ...]:
        return tuple(item.relative_path for item in self.files if self.changed(item.relative_path))
