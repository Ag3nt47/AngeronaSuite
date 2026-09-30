"""Bounded, authenticated reads for the Red Team console's report history."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from angerona.core import report_attest


_HISTORY_NAME = re.compile(r"(redteam_aar|shark_aar)_[0-9]{8}_[0-9]{6}\.txt\Z")
_KINDS = {"redteam_aar": "red_team", "shark_aar": "shark"}
_MAX_MEMBERS = 80
_MAX_SCAN = 2048
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_METADATA_CANDIDATES = 256
_MAX_METADATA_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_METADATA_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class HistoryListing:
    rows: list[tuple[str, float, str]]
    limited: bool = False


def _history_root(path: Path) -> Path:
    root = Path(path)
    try:
        identity = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("report history directory is unavailable") from exc
    if not stat.S_ISDIR(identity.st_mode) or bool(
        getattr(identity, "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("report history directory has an unsafe identity")
    return root


def _verified_metadata(path: Path, basename: str) -> tuple[dict, datetime]:
    try:
        payload = json.loads(_read_member(path, max_bytes=_MAX_METADATA_BYTES).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("report history metadata is unreadable") from exc
    if not isinstance(payload, dict) or report_attest.verify(payload) != "ok":
        raise ValueError("report history signature is missing or invalid")
    if (
        payload.get("report_basename") != basename
        or payload.get("report_kind") != _KINDS[basename]
        or not str(payload.get("run_id") or "").strip()
        or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("report_text_sha256") or ""))
    ):
        raise ValueError("report history metadata has the wrong run identity")
    try:
        signed_time = datetime.strptime(str(payload.get("generated") or ""), "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ValueError("report history has no signed generation time") from exc
    return payload, signed_time


def list_history(path: Path) -> HistoryListing:
    """List bounded, signed reports by their authenticated generation time."""
    try:
        root = _history_root(path)
    except ValueError:
        return HistoryListing([])
    candidates: list[tuple[str, str, float]] = []
    limited = False
    try:
        with os.scandir(root) as entries:
            for scanned, entry in enumerate(entries):
                if scanned >= _MAX_SCAN:
                    limited = True
                    break
                match = _HISTORY_NAME.fullmatch(entry.name)
                if match is None:
                    continue
                try:
                    # Windows DirEntry.stat() reports st_nlink=0 even for an
                    # ordinary file; Path.stat() returns its true link count.
                    info = Path(entry.path).stat(follow_symlinks=False)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or bool(getattr(info, "st_file_attributes", 0) & 0x400)
                        or int(getattr(info, "st_nlink", 1)) != 1
                        or not 0 < info.st_size <= _MAX_MEMBER_BYTES
                    ):
                        continue
                    filename_time = datetime.strptime(
                        entry.name[-19:-4], "%Y%m%d_%H%M%S"
                    ).timestamp()
                except (OSError, ValueError):
                    continue
                candidates.append((entry.name, match.group(1), filename_time))
    except OSError:
        return HistoryListing([])
    # Prioritize likely recent archive names while keeping forged files from
    # causing an unbounded series of signature checks or disk reads.
    candidates.sort(key=lambda row: row[2], reverse=True)
    if len(candidates) > _MAX_METADATA_CANDIDATES:
        candidates = candidates[:_MAX_METADATA_CANDIDATES]
        limited = True
    accepted: dict[tuple[str, str], tuple[str, float, str, float]] = {}
    read_bytes = 0
    for name, basename, filename_time in candidates:
        metadata_path = root / name.removesuffix(".txt")
        try:
            info = metadata_path.with_suffix(".json").stat(follow_symlinks=False)
            if not 0 < info.st_size <= _MAX_METADATA_BYTES:
                continue
            if read_bytes + info.st_size > _MAX_TOTAL_METADATA_BYTES:
                limited = True
                break
            read_bytes += info.st_size
            payload, signed_time = _verified_metadata(metadata_path.with_suffix(".json"), basename)
        except (OSError, ValueError, RecursionError, TypeError):
            continue
        try:
            stamp = signed_time.timestamp()
        except (OverflowError, OSError, ValueError):
            continue
        key = (str(payload["run_id"]), str(payload["report_text_sha256"]))
        row = (name, stamp, basename, abs(filename_time - stamp))
        prior = accepted.get(key)
        if prior is None or row[3] < prior[3]:
            accepted[key] = row
    rows = sorted(accepted.values(), key=lambda row: row[1], reverse=True)
    if len(rows) > _MAX_MEMBERS:
        limited = True
    return HistoryListing([(name, stamp, basename) for name, stamp, basename, _ in rows[:_MAX_MEMBERS]], limited)


def _read_member(path: Path, *, max_bytes: int | None = None) -> bytes:
    """Read one identity-held regular file without following reparse/symlink paths."""
    if max_bytes is None:
        max_bytes = _MAX_MEMBER_BYTES
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        pathname = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(pathname.st_mode)
            or bool(getattr(before, "st_file_attributes", 0) & 0x400)
            or bool(getattr(pathname, "st_file_attributes", 0) & 0x400)
            or int(getattr(before, "st_nlink", 1)) != 1
            or int(getattr(pathname, "st_nlink", 1)) != 1
            or (before.st_dev, before.st_ino) != (pathname.st_dev, pathname.st_ino)
            or not 0 < before.st_size <= max_bytes
        ):
            raise ValueError("report history member has an unsafe identity")
        remaining = int(before.st_size)
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(128 * 1024, remaining))
            if not chunk:
                raise ValueError("report history member changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        final_path = path.stat(follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (after.st_dev, after.st_ino) != (final_path.st_dev, final_path.st_ino)
            or int(getattr(after, "st_nlink", 1)) != 1
            or int(getattr(final_path, "st_nlink", 1)) != 1
        ):
            raise ValueError("report history member changed identity during read")
        return b"".join(chunks)
    except OSError as exc:
        raise ValueError("report history member is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_verified_history_text(path: Path, name: str) -> str:
    """Return report text only when its companion JSON and digest authenticate."""
    match = _HISTORY_NAME.fullmatch(name)
    if match is None:
        raise ValueError("report history name is invalid")
    root = _history_root(path)
    basename = match.group(1)
    metadata_path = root / name.removesuffix(".txt")
    payload, _signed_time = _verified_metadata(metadata_path.with_suffix(".json"), basename)
    raw_text = _read_member(root / name)
    expected_digest = str(payload.get("report_text_sha256") or "")
    actual_digest = hashlib.sha256(raw_text).hexdigest()
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise ValueError("report history text does not match its signed metadata")
    try:
        return raw_text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("report history text is not UTF-8") from exc
