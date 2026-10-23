"""Preserve user edits while preparing a source update beside the installation.

The installed checkout is read-only throughout. Candidate files and all three
conflict sides are retained in a private stage. No downloaded code, Git hook,
merge driver, dependency installer, or validator is executed. A successful
merge is a prepared candidate, not proof that arbitrary custom code works.
"""
from __future__ import annotations

import difflib
import ast
import hashlib
import io
import json
import os
import re
import stat
import shutil
import uuid
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping
from urllib.request import Request

from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.url_policy import host_policy, read_bounded, safe_urlopen
from angerona.updater.source_git import read_source_git, source_git_session
from angerona.updater.github_updater import (
    CANONICAL_ORIGIN, CANONICAL_REPOSITORY, _safe_state_root, _write_state,
    github_json, local_source_revision,
    _json,
)

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_TRANSACTION_BYTES = 1024 * 1024 * 1024
MAX_FILES = 8192
MAX_PATH = 240
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_TEXT_LINES = 20000
MAX_MERGE_COMPARISONS = 2_000_000
_SHA = re.compile(r"^[0-9a-f]{40}$")
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)
_ARCHIVE_POLICY = host_policy("canonical source archive", {"codeload.github.com"})


class SourceStageError(RuntimeError):
    """A preservation or provenance precondition was not established."""


@dataclass(frozen=True)
class MergeDecision:
    action: str
    content: bytes | None
    reason: str = ""


@dataclass(frozen=True)
class StageResult:
    stage_id: str
    status: str
    base_revision: str
    target_revision: str
    local_revision: str
    candidate_files: int
    preserved_changes: int
    conflicts: tuple[str, ...]
    manifest_sha256: str
    activation_status: str = "not_authorized"
    message: str = ("Original installation is unchanged. This is a source candidate for review; automatic activation is held. "
                    "Application, dependency, service and enabled UGCAP checks require a separate reviewed activation phase.")


def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_PATH:
        raise SourceStageError("invalid source path length")
    path = PurePosixPath(value)
    parts = value.split("/")
    if (path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} or part.casefold() == ".git" or part.endswith((".", " "))
        or _RESERVED.match(part) or any(ord(ch) < 32 or ch in '\\:*?"<>|' for ch in part)
        for part in parts
    )):
        raise SourceStageError("source path is unsafe or not portable")
    return value


def _validate_tree(tree: Mapping[str, bytes]) -> dict[str, bytes]:
    if len(tree) > MAX_FILES:
        raise SourceStageError("source file count exceeds limit")
    result = {}
    folded = set()
    prefixes = {}
    total = 0
    for path, data in tree.items():
        safe_relative(path)
        if path.casefold() in folded:
            raise SourceStageError("source contains case-colliding paths")
        folded.add(path.casefold())
        parts = PurePosixPath(path).parts
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            previous = prefixes.setdefault(prefix.casefold(), prefix)
            if previous != prefix:
                raise SourceStageError("source contains case-aliased parent paths")
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise SourceStageError("source file exceeds byte limit")
        total += len(data)
        if total > MAX_TREE_BYTES:
            raise SourceStageError("source tree exceeds byte limit")
        result[path] = data
    for path in result:
        if any(parent.as_posix().casefold() in folded for parent in PurePosixPath(path).parents if parent.as_posix() != "."):
            raise SourceStageError("source contains file/directory collisions")
    return result


def read_source_archive(raw: bytes, revision: str, *, remaining_bytes: int = MAX_TRANSACTION_BYTES,
                        cancelled: Callable[[], bool] = lambda: False) -> dict[str, bytes]:
    if not _SHA.fullmatch(revision) or not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARCHIVE_BYTES:
        raise SourceStageError("invalid source archive identity or size")
    if type(remaining_bytes) is not int or remaining_bytes < 0:
        raise SourceStageError("source archive has no remaining transaction budget")
    prefix = f"AngeronaSuite-{revision}/"
    tree = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES * 2:
            raise SourceStageError("source archive entry count exceeds limit")
        for entry in entries:
            if cancelled():
                raise SourceStageError("source staging was cancelled")
            if not entry.filename.startswith(prefix):
                raise SourceStageError("source archive has an unexpected root")
            relative = entry.filename[len(prefix):]
            if not relative:
                if not entry.is_dir():
                    raise SourceStageError("source archive root is not a directory")
                continue
            safe_relative(relative.rstrip("/") if entry.is_dir() else relative)
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG):
                raise SourceStageError("source archive contains a link or special file")
            if entry.flag_bits & 1:
                raise SourceStageError("encrypted archive entries are unsupported")
            if entry.is_dir():
                continue
            if relative in tree or entry.file_size > MAX_FILE_BYTES:
                raise SourceStageError("duplicate or oversized source archive entry")
            total += entry.file_size
            if total > min(MAX_TREE_BYTES, remaining_bytes):
                raise SourceStageError("source archive expands beyond byte limit")
            with archive.open(entry) as stream:
                chunks = []
                consumed = 0
                while True:
                    if cancelled():
                        raise SourceStageError("source staging was cancelled")
                    chunk = stream.read(min(64 * 1024, entry.file_size - consumed + 1))
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > entry.file_size:
                        raise SourceStageError("source archive entry expands beyond declared size")
                    chunks.append(chunk)
                data = b"".join(chunks)
            if len(data) != entry.file_size or len(data) > MAX_FILE_BYTES:
                raise SourceStageError("source archive entry length mismatch")
            tree[relative] = data
    return _validate_tree(tree)


def download_source_archive(revision: str) -> bytes:
    if not isinstance(revision, str) or not _SHA.fullmatch(revision):
        raise SourceStageError("invalid source revision")
    request = Request(f"https://codeload.github.com/{CANONICAL_REPOSITORY}/zip/{revision}",
                      headers={"User-Agent": "Angerona-Updater"})
    with safe_urlopen(request, policy=_ARCHIVE_POLICY, timeout=30) as response:
        return read_bounded(response, MAX_ARCHIVE_BYTES)


def _edits(base: list[str], changed: list[str]) -> list[tuple[int, int, list[str]]]:
    return [(start, end, changed[cstart:cend])
            for tag, start, end, cstart, cend in difflib.SequenceMatcher(None, base, changed, autojunk=False).get_opcodes()
            if tag != "equal"]


def merge_file(base: bytes | None, local: bytes | None, incoming: bytes | None,
               *, cancelled: Callable[[], bool] = lambda: False) -> MergeDecision:
    """Merge only disjoint text edits; preserve ambiguous/binary changes as conflicts."""
    if local == base:
        return MergeDecision("upstream", incoming)
    if incoming == base or incoming == local:
        return MergeDecision("preserved", local)
    if base is None:
        return MergeDecision("conflict", None, "both sides added different content")
    if local is None or incoming is None:
        return MergeDecision("conflict", None, "modified/deleted conflict")
    if any(len(value) > MAX_TEXT_BYTES or b"\x00" in value for value in (base, local, incoming)):
        return MergeDecision("conflict", None, "binary or large-file conflict")
    try:
        texts = [value.decode("utf-8").splitlines(keepends=True) for value in (base, local, incoming)]
    except UnicodeDecodeError:
        return MergeDecision("conflict", None, "non-UTF-8 conflict")
    if any(len(lines) > MAX_TEXT_LINES for lines in texts):
        return MergeDecision("conflict", None, "text line limit exceeded")
    if len(texts[0]) * (len(texts[1]) + len(texts[2])) > MAX_MERGE_COMPARISONS:
        return MergeDecision("conflict", None, "automatic merge work limit exceeded")
    if cancelled():
        raise SourceStageError("source staging was cancelled")
    ours, theirs = _edits(texts[0], texts[1]), _edits(texts[0], texts[2])
    merged = list(ours)
    for edit in theirs:
        if edit in ours:
            continue
        start, end, _ = edit
        for ostart, oend, _ in ours:
            # Boundary insertions are deliberately conservative, as are two
            # insertions at the same point. No guessed conflict resolution.
            if start <= oend and ostart <= end:
                return MergeDecision("conflict", None, "overlapping text changes")
        merged.append(edit)
    result = texts[0][:]
    for start, end, replacement in sorted(merged, key=lambda item: (item[0], item[1]), reverse=True):
        result[start:end] = replacement
    return MergeDecision("merged", "".join(result).encode("utf-8"))


def _git(root: Path, args: list[str]) -> bytes:
    try:
        return read_source_git(root, tuple(args))
    except Exception as exc:
        raise SourceStageError("read-only Git identity/inventory check failed") from exc


def source_inventory(root: Path) -> tuple[str, ...]:
    raw = _git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    values = raw.decode("utf-8").split("\x00")
    if values[-1] != "":
        raise SourceStageError("unterminated Git inventory")
    paths = tuple(sorted(set(safe_relative(value) for value in values[:-1])))
    if len(paths) > MAX_FILES:
        raise SourceStageError("local source file count exceeds limit")
    return paths


def snapshot_local(root: Path, paths: tuple[str, ...], *,
                   cancelled: Callable[[], bool] = lambda: False,
                   verify_against: Mapping[str, bytes] | None = None) -> dict[str, bytes]:
    root = Path(os.path.abspath(root))
    if len(paths) > MAX_FILES:
        raise SourceStageError("local source file count exceeds limit")
    _validate_tree({safe_relative(name): b"" for name in paths})
    if len(set(paths)) != len(paths):
        raise SourceStageError("duplicate local source path")
    planned = []
    total = 0
    # All size/count/path checks precede the first content read.
    for name in paths:
        if cancelled():
            raise SourceStageError("source staging was cancelled")
        path = root.joinpath(*PurePosixPath(safe_relative(name)).parts)
        missing = False
        # Check ancestors before asking the filesystem to inspect a child.
        for item in (*reversed(root.parents), root, *[root.joinpath(*PurePosixPath(name).parts[:index])
                                                    for index in range(1, len(PurePosixPath(name).parts) + 1)]):
            try:
                info = item.lstat()
            except FileNotFoundError:
                if item != root and root in item.parents:
                    missing = True
                    break  # A deleted tracked directory is preserved absence.
                raise SourceStageError("source root or its ancestor disappeared") from None
            if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise SourceStageError("local source is link/reparse-backed")
        if missing or not path.exists():
            continue  # Tracked deletion: absence is part of the preserved state.
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES or before.st_nlink != 1:
            raise SourceStageError("local source is not a bounded, single-link regular file")
        total += before.st_size
        if total > MAX_TREE_BYTES:
            raise SourceStageError("local source tree exceeds byte limit before capture")
        planned.append((name, path, before))
    if verify_against is not None and {name for name, _, _ in planned} != set(verify_against):
        raise SourceStageError("local source inventory changed during verification")
    tree = {}
    used = 0
    for name, path, before in planned:
        if cancelled():
            raise SourceStageError("source staging was cancelled")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode)):
                raise SourceStageError("local source changed before capture")
            chunks = []
            length = 0
            while True:
                if cancelled():
                    raise SourceStageError("source staging was cancelled")
                remaining = min(before.st_size - length, MAX_FILE_BYTES - length, MAX_TREE_BYTES - used)
                chunk = handle.read(min(64 * 1024, remaining + 1))
                if not chunk:
                    break
                if len(chunk) > remaining:
                    raise SourceStageError("local source grew beyond capture budget")
                used += len(chunk)
                length += len(chunk)
                chunks.append(chunk)
            data = b"".join(chunks)
            after = os.fstat(handle.fileno())
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise SourceStageError("local source changed during capture")
        if verify_against is None:
            tree[name] = data
        elif data != verify_against[name]:
            raise SourceStageError("local source bytes changed during verification")
    return _validate_tree(tree)


def _digest(value: bytes | None) -> str | None:
    return hashlib.sha256(value).hexdigest() if value is not None else None


def _physical_source_root(path: Path) -> Path:
    """Read-only refusal of aliased source roots before any state is created."""
    root = Path(os.path.abspath(path))

    def check(candidate):
        for current in (*reversed(candidate.parents), candidate):
            try:
                info = current.lstat()
            except OSError as exc:
                raise SourceStageError("source/staging ancestors must be existing physical directories") from exc
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400):
                raise SourceStageError("source/staging root or ancestor is a link, reparse point or non-directory")
        return info

    before = check(root)
    try:
        # Windows pathlib/ntpath uses GetFinalPathNameByHandle here. This
        # normalizes ordinary 8.3 aliases as well as long directory spellings.
        final = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourceStageError("physical directory canonical identity is unavailable") from exc
    after = check(final)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise SourceStageError("physical directory changed during canonicalization")
    return final


def _physical_staging_path(path: Path) -> Path:
    """Canonicalize an existing physical ancestor without creating missing parts."""
    root = Path(os.path.abspath(path))
    missing = []
    current = root
    while True:
        try:
            current.lstat()
            break
        except FileNotFoundError:
            if current == current.parent:
                raise SourceStageError("staging directory has no existing physical ancestor") from None
            missing.append(current.name)
            current = current.parent
        except OSError as exc:
            raise SourceStageError("staging ancestor identity is unavailable") from exc
    final = _physical_source_root(current)
    return final.joinpath(*reversed(missing))


def prepare_source_update(source_root: Path, staging_root: Path, target_revision: str,
                          *, base_revision: str = "", cancelled: Callable[[], bool] = lambda: False,
                          fetch: Callable[[str], dict] = github_json,
                          download: Callable[[str], bytes] = download_source_archive) -> StageResult:
    """Download and merge into a fresh isolated stage; never edit the checkout."""
    if cancelled():
        raise SourceStageError("source staging was cancelled")
    if not _SHA.fullmatch(target_revision):
        raise SourceStageError("a full canonical target revision is required")
    # This preflight must precede stage directory/lease creation and trusted
    # Git runtime staging. A source alias could otherwise hide containment.
    source_root = _physical_source_root(source_root)
    root = _physical_staging_path(staging_root)
    if source_root == root or source_root in root.parents or root in source_root.parents:
        raise SourceStageError("staging must be outside the source installation")
    # Containment rejection must not create even an empty directory in the
    # installed checkout, launch Git, or make a network request.
    root = _safe_state_root(root)
    with ExclusiveFileLease(root / "stage.lock"), source_git_session():
        local = local_source_revision(source_root)
        if not local:
            raise SourceStageError(f"source checkout must have exact origin {CANONICAL_ORIGIN}")
        if not base_revision:
            base_revision = _git(source_root, ["rev-parse", "--verify", "refs/remotes/origin/main"]).decode("ascii").strip()
        if not _SHA.fullmatch(base_revision):
            raise SourceStageError("known canonical base revision is required")
        _git(source_root, ["merge-base", "--is-ancestor", base_revision, local])
        if cancelled():
            raise SourceStageError("source staging was cancelled")
        comparison = fetch(f"compare/{base_revision}...{target_revision}")
        if not isinstance(comparison, dict) or comparison.get("status") not in {"ahead", "identical"}:
            raise SourceStageError("canonical base and target ancestry is not fast-forward")
        for field in ("base_commit", "merge_base_commit"):
            if not isinstance(comparison.get(field), dict) or comparison[field].get("sha") != base_revision:
                raise SourceStageError("canonical ancestry identity mismatch")
        if comparison.get("status") == "identical" and base_revision != target_revision:
            raise SourceStageError("canonical ancestry contradicts requested target")
        paths = source_inventory(source_root)
        original = snapshot_local(source_root, paths, cancelled=cancelled)
        original_digest = hashlib.sha256(json.dumps({name: _digest(data) for name, data in original.items()}, sort_keys=True).encode()).hexdigest()
        stage_id = "source-" + uuid.uuid4().hex
        stage = root / stage_id
        stage.mkdir(mode=0o700)
        intent = {"schema": "angerona.source-stage/v1", "stage_id": stage_id,
                  "status": "preparing", "base_revision": base_revision,
                  "target_revision": target_revision, "local_revision": local,
                  "original_tree_sha256": original_digest, "original_unchanged": True,
                  "ignored_files": "retained in original installation; excluded from candidate"}
        _write_state(stage / "intent.json", intent)
        try:
            if cancelled():
                raise SourceStageError("source staging was cancelled")
            captured_bytes = sum(map(len, original.values()))
            base = read_source_archive(download(base_revision), base_revision,
                                       remaining_bytes=MAX_TRANSACTION_BYTES - captured_bytes, cancelled=cancelled)
            captured_bytes += sum(map(len, base.values()))
            if cancelled():
                raise SourceStageError("source staging was cancelled")
            incoming = read_source_archive(download(target_revision), target_revision,
                                           remaining_bytes=MAX_TRANSACTION_BYTES - captured_bytes, cancelled=cancelled)
            captured_bytes += sum(map(len, incoming.values()))
            records = []
            conflicts = []
            changes = candidate_count = 0
            candidate_bytes = 0
            plan = []
            combined = set(base) | set(original) | set(incoming)
            if len(combined) > MAX_FILES:
                raise SourceStageError("combined source file count exceeds limit")
            # Validate names across trees before writing any candidate file.
            _validate_tree({name: b"" for name in combined})
            for name in sorted(combined):
                if cancelled():
                    raise SourceStageError("source staging was cancelled")
                before, user, after = base.get(name), original.get(name), incoming.get(name)
                decision = merge_file(before, user, after, cancelled=cancelled)
                if decision.content is not None:
                    candidate_bytes += len(decision.content)
                    if candidate_bytes > MAX_TREE_BYTES or captured_bytes + candidate_bytes > MAX_TRANSACTION_BYTES:
                        raise SourceStageError("combined candidate bytes exceed preparation budget")
                changes += user != before
                record = {"path": name, "base": _digest(before), "user": _digest(user),
                          "upstream": _digest(after), "candidate": _digest(decision.content),
                          "action": decision.action, "reason": decision.reason}
                records.append(record)
                plan.append((name, before, user, after, decision))
            required_space = captured_bytes + candidate_bytes + 16 * 1024 * 1024
            if shutil.disk_usage(root).free < required_space:
                raise SourceStageError("insufficient free space for preserved copies and candidate")
            blobs = stage / "preserved-blobs"
            blobs.mkdir(mode=0o700)
            candidate = stage / "candidate"
            candidate.mkdir(mode=0o700)
            for name, before, user, after, decision in plan:
                for value in (before, user, after):
                    if value is not None:
                        blob = blobs / _digest(value)
                        if not blob.exists():
                            _write_capture(blob, value, cancelled)
                if decision.action == "conflict":
                    conflicts.append(name)
                elif decision.content is not None:
                    target = candidate.joinpath(*PurePosixPath(name).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _write_capture(target, decision.content, cancelled)
                    candidate_count += 1
            if source_inventory(source_root) != paths or local_source_revision(source_root) != local:
                raise SourceStageError("local installation changed during preparation; staged candidate is held")
            snapshot_local(source_root, paths, cancelled=cancelled, verify_against=original)
            manifest = dict(intent, status="conflicts" if conflicts else "prepared", files=records,
                            conflicts=conflicts, validation="not_run", activation="not_authorized")
            encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            with (stage / "manifest.json").open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            result = StageResult(stage_id, manifest["status"], base_revision, target_revision, local,
                                 candidate_count, changes, tuple(conflicts), hashlib.sha256(encoded).hexdigest())
            _write_json(stage / "result.json", asdict(result))
            _write_state(stage / "intent.json", dict(intent, status=result.status))
            return result
        except BaseException as exc:
            _write_state(stage / "intent.json", dict(intent, status="cancelled" if cancelled() else "failed",
                                                     failure_type=type(exc).__name__))
            raise


def _write_capture(path: Path, value: bytes, cancelled: Callable[[], bool]) -> None:
    with path.open("xb") as handle:
        for offset in range(0, len(value), 64 * 1024):
            if cancelled():
                raise SourceStageError("source staging was cancelled")
            handle.write(value[offset:offset + 64 * 1024])
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: dict, *, maximum: int = 4 * 1024 * 1024) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > maximum:
        raise SourceStageError("source-stage metadata exceeds byte limit")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".pending")
    with temporary.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _stage_manifest(stage: Path, expected_digest: str) -> dict:
    stage = _safe_state_root(stage)
    path = stage / "manifest.json"
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise SourceStageError("source manifest is not a private regular file")
    if not 1 <= info.st_size <= 16 * 1024 * 1024:
        raise SourceStageError("source manifest exceeds byte limit")
    raw = path.read_bytes()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or hashlib.sha256(raw).hexdigest() != expected_digest:
        raise SourceStageError("source manifest digest mismatch")
    value = _json(raw, 16 * 1024 * 1024)
    if value.get("schema") != "angerona.source-stage/v1" or value.get("status") not in {"prepared", "conflicts"}:
        raise SourceStageError("source manifest is not a completed preparation")
    if not isinstance(value.get("files"), list) or len(value["files"]) > MAX_FILES:
        raise SourceStageError("source manifest file inventory is invalid")
    return value


def _read_blob(stage: Path, digest: str | None) -> bytes | None:
    if digest is None:
        return None
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SourceStageError("invalid preserved blob identity")
    root = _safe_state_root(stage / "preserved-blobs")
    path = root / digest
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES
            or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400):
        raise SourceStageError("preserved blob is not a bounded private regular file")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise SourceStageError("preserved blob digest mismatch")
    return raw


def _resolution_index(stage: Path, manifest_digest: str) -> dict:
    path = stage / "resolutions.json"
    if not path.exists():
        return {"schema": "angerona.source-resolutions/v1", "manifest_sha256": manifest_digest, "files": {}}
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024 or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise SourceStageError("conflict resolution index is unsafe")
    value = _json(path.read_bytes(), 4 * 1024 * 1024)
    if value.get("schema") != "angerona.source-resolutions/v1" or value.get("manifest_sha256") != manifest_digest or not isinstance(value.get("files"), dict):
        raise SourceStageError("conflict resolution index identity mismatch")
    if len(value["files"]) > MAX_FILES:
        raise SourceStageError("conflict resolution count exceeds limit")
    return value


def _resolution_file_identity(info: os.stat_result) -> dict:
    """Keep exact OS object IDs; POSIX ctime is not a creation timestamp."""
    birth = getattr(info, "st_birthtime_ns", None)
    if birth is None and os.name == "nt":
        birth = info.st_ctime_ns  # Python 3.10/3.11 expose Windows creation time here.
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400
            or type(info.st_dev) is not int or info.st_dev < 0
            or type(info.st_ino) is not int or info.st_ino <= 0
            or (birth is not None and (type(birth) is not int or birth <= 0))
            or (os.name == "nt" and birth is None)):
        raise SourceStageError("conflict candidate object identity is unavailable or unsafe")
    # Decimal strings preserve 64/128-bit IDs when a review tool reads the JSON.
    return {"device": str(info.st_dev), "inode": str(info.st_ino),
            "birth_ns": None if birth is None else str(birth)}


def _named_resolution_file(handle, target: Path) -> os.stat_result:
    opened = os.fstat(handle.fileno())
    named = target.lstat()
    if _resolution_file_identity(opened) != _resolution_file_identity(named):
        raise SourceStageError("conflict candidate is not the recorded named object")
    return opened


def _read_resolution_intent(path: Path, expected: dict) -> dict | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    _resolution_file_identity(info)
    if not 1 <= info.st_size <= 4096:
        raise SourceStageError("conflict resolution intent exceeds byte limit")
    with path.open("rb") as handle:
        before = _named_resolution_file(handle, path)
        raw = handle.read(4097)
        after = _named_resolution_file(handle, path)
    if (len(raw) != before.st_size or len(raw) > 4096
            or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise SourceStageError("conflict resolution intent changed during read")
    value = _json(raw, 4096)
    identity = value.get("candidate_identity")
    if value != dict(expected, candidate_identity=identity):
        raise SourceStageError("conflict resolution intent differs from the recorded choice or manifest")
    if identity is not None:
        if (not isinstance(identity, dict) or set(identity) != {"device", "inode", "birth_ns"}
                or any(not isinstance(identity[key], str) or not re.fullmatch(r"0|[1-9][0-9]{0,38}", identity[key])
                       for key in ("device", "inode"))
                or identity["inode"] == "0"
                or (identity["birth_ns"] is not None and (
                    not isinstance(identity["birth_ns"], str)
                    or not re.fullmatch(r"[1-9][0-9]{0,38}", identity["birth_ns"])))
                or (os.name == "nt" and identity["birth_ns"] is None)
                or expected["sha256"] is None):
            raise SourceStageError("conflict resolution intent has an invalid candidate identity")
    return value


def _verify_resolution_candidate(handle, target: Path, intent: dict, data: bytes) -> None:
    before = _named_resolution_file(handle, target)
    if (_resolution_file_identity(before) != intent["candidate_identity"]
            or before.st_size != len(data) or before.st_size > MAX_FILE_BYTES):
        raise SourceStageError("conflict candidate differs from its recorded object or size")
    handle.seek(0)
    actual = handle.read(len(data) + 1)
    after = _named_resolution_file(handle, target)
    if (actual != data or _resolution_file_identity(after) != intent["candidate_identity"]
            or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise SourceStageError("conflict candidate bytes changed or are incomplete")


def _verify_recorded_resolution_candidate(target: Path, intent: dict, data: bytes) -> None:
    """Constrain POSIX leaf races before descriptor wrapping or candidate reads.

    This is no general device-I/O deadline or isolation from same-user/admin writers.
    """
    if os.name == "nt":
        with target.open("rb") as handle:
            _verify_resolution_candidate(handle, target, intent, data)
        return
    nonblock = getattr(os, "O_NONBLOCK", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (os.name != "posix" or type(nonblock) is not int or not nonblock
            or type(nofollow) is not int or not nofollow):
        raise SourceStageError("safe nonblocking no-follow conflict candidate open is unavailable")
    if _resolution_file_identity(target.lstat()) != intent["candidate_identity"]:
        raise SourceStageError("conflict candidate differs from its recorded object")

    def open_recorded(name, flags):
        descriptor = os.open(name, flags | nonblock | nofollow)
        try:
            # Reject a raced FIFO/special/replaced object before fdopen or read.
            if _resolution_file_identity(os.fstat(descriptor)) != intent["candidate_identity"]:
                raise SourceStageError("conflict candidate differs from its recorded object")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor  # io.open owns and closes it after the opener returns.

    with io.open(target, "rb", opener=open_recorded) as handle:
        _verify_resolution_candidate(handle, target, intent, data)


def resolve_source_conflict(stage: Path, manifest_digest: str, path: str, choice: str) -> dict:
    """Choose a retained side; retry only the same recorded choice after interruption.

    Recovery checks a completed candidate's recorded OS identity and exact bytes.
    Unrecorded, partial, missing or replaced objects stay held. This does not promise
    power-loss durability or authority to activate the candidate.
    """
    stage = _safe_state_root(stage)
    path = safe_relative(path)
    if choice not in {"user", "upstream", "base", "delete"}:
        raise SourceStageError("conflict resolution must explicitly name a retained side or deletion")
    with ExclusiveFileLease(stage / "resolution.lock"):
        manifest = _stage_manifest(stage, manifest_digest)
        records = [row for row in manifest["files"] if isinstance(row, dict) and row.get("path") == path]
        if len(records) != 1 or records[0].get("action") != "conflict":
            raise SourceStageError("path is not an original unresolved conflict")
        index = _resolution_index(stage, manifest_digest)
        record = records[0]
        data = None if choice == "delete" else _read_blob(stage, record[choice])
        resolution = {"choice": choice, "sha256": _digest(data)}
        root = _safe_state_root(stage / "candidate")
        target = root.joinpath(*PurePosixPath(path).parts)
        for parent in reversed(target.parent.parents):
            if parent == root or root in parent.parents:
                _safe_state_root(parent)
        _safe_state_root(target.parent)
        intents = _safe_state_root(stage / "resolution-intents")
        intent_path = intents / (hashlib.sha256(path.encode("utf-8")).hexdigest() + ".json")
        expected = {"schema": "angerona.source-resolution-intent/v1", "manifest_sha256": manifest_digest,
                    "path": path, **resolution, "size": None if data is None else len(data)}
        intent = _read_resolution_intent(intent_path, expected)
        if path in index["files"] and (intent is None or index["files"][path] != resolution):
            raise SourceStageError("conflict already has a different or legacy explicit resolution")
        if path in index["files"] and data is not None and intent["candidate_identity"] is None:
            raise SourceStageError("committed conflict resolution has no recorded object ownership")
        try:
            named = target.lstat()
            present = True
        except FileNotFoundError:
            present = False
        if intent is None:
            if present:
                raise SourceStageError("conflict target unexpectedly exists without a recorded intent")
            intent = dict(expected, candidate_identity=None)
            _write_json(intent_path, intent)
        if data is None:
            if present:
                raise SourceStageError("deleted conflict target unexpectedly exists")
        elif intent["candidate_identity"] is None:
            if present:
                raise SourceStageError("conflict target exists without recorded object ownership")
            with target.open("x+b") as handle:
                # Checkpoint ownership before writing. An interruption before this
                # checkpoint deliberately leaves an unowned object held for review.
                info = _named_resolution_file(handle, target)
                intent = dict(expected, candidate_identity=_resolution_file_identity(info))
                _write_json(intent_path, intent)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                _verify_resolution_candidate(handle, target, intent, data)
        else:
            if not present:
                raise SourceStageError("recorded conflict candidate is missing")
            if _resolution_file_identity(named) != intent["candidate_identity"]:
                raise SourceStageError("conflict candidate differs from its recorded object")
            _verify_recorded_resolution_candidate(target, intent, data)
        if path not in index["files"]:
            index["files"][path] = resolution
            _write_json(stage / "resolutions.json", index)
        # Original manifest and every retained side remain byte-identical. The
        # existing index is the commit record; retained intents permit safe retry.
        return dict(path=path, **resolution)

def validate_source_candidate(stage: Path, manifest_digest: str) -> dict:
    """Check preserved hashes and Python syntax without executing candidate code.

    Passing static checks is explicitly insufficient for activation. Dependency,
    service, runtime, and UGCAP verification require a separate reviewed phase.
    """
    stage = _safe_state_root(stage)
    with ExclusiveFileLease(stage / "resolution.lock"):
        manifest = _stage_manifest(stage, manifest_digest)
        index = _resolution_index(stage, manifest_digest)
        expected = {}
        unresolved = []
        for row in manifest["files"]:
            if not isinstance(row, dict):
                raise SourceStageError("invalid source file record")
            name = safe_relative(row.get("path"))
            if name in expected:
                raise SourceStageError("duplicate candidate path")
            if row.get("action") == "conflict":
                if name not in index["files"]:
                    unresolved.append(name)
                    continue
                resolution = index["files"][name]
                if not isinstance(resolution, dict) or resolution.get("choice") not in {"base", "user", "upstream", "delete"}:
                    raise SourceStageError("invalid conflict resolution record")
                choice = resolution["choice"]
                digest = None if choice == "delete" else row.get(choice)
                if resolution.get("sha256") != digest:
                    raise SourceStageError("conflict resolution digest mismatch")
            else:
                digest = row.get("candidate")
            expected[name] = digest
        root = _safe_state_root(stage / "candidate")
        actual_names = []
        directory_count = 0
        for current, directories, files in os.walk(root, followlinks=False):
            for name in directories:
                directory_count += 1
                if directory_count > MAX_FILES * 16:
                    raise SourceStageError("candidate directory count exceeds limit")
                _safe_state_root(Path(current) / name)
            for name in files:
                actual_names.append((Path(current) / name).relative_to(root).as_posix())
                if len(actual_names) > MAX_FILES:
                    raise SourceStageError("candidate inventory exceeds file limit")
        actual = snapshot_local(root, tuple(actual_names))
        hashes = {name: _digest(data) for name, data in actual.items()}
        if hashes != {name: digest for name, digest in expected.items() if digest is not None}:
            raise SourceStageError("candidate bytes differ from the preservation plan")
        syntax_errors = []
        for name, raw in actual.items():
            if name.endswith(".py"):
                try:
                    ast.parse(raw, filename=name)
                except (SyntaxError, ValueError, RecursionError) as exc:
                    syntax_errors.append({"path": name, "error_type": type(exc).__name__})
        missing_components = [name for name in ("pyproject.toml", "src/angerona/__init__.py", "src/angerona/__main__.py") if name not in actual]
        dependencies_changed = any(row.get("base") != row.get("upstream") for row in manifest["files"]
                                   if row.get("path") in {"pyproject.toml", "requirements.txt", "requirements.lock", "uv.lock"})
        result = {"schema": "angerona.source-static-validation/v1", "manifest_sha256": manifest_digest,
                  "static_checks": "failed" if syntax_errors or unresolved or missing_components else "passed",
                  "syntax_errors": syntax_errors, "unresolved_conflicts": unresolved,
                  "missing_components": missing_components,
                  "dependency_changes": dependencies_changed, "activation": "held",
                  "required_follow_up": ["isolated application and dependency validation", "stop the suite before activation",
                                         "privileged-service compatibility", "executable permission and launch-environment validation",
                                         "explicit UGCAP baseline review if enabled"],
                  "trust_roots_changed": False, "golden_baseline_reenrolled": False,
                  "original_installation_changed": False}
        _write_json(stage / "validation.json", result)
        return result
