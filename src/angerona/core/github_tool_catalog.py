"""Pinned, data-only GitHub source imports for the Red Team console.

Repositories stay inside ZIP containers and are never extracted, imported,
installed or executed. Review status grants no execution or response authority.
"""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
import re
import stat
import struct
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from angerona.core.archive_safety import read_bounded_member, safe_archive_path, validate_zip_members
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError
from angerona.core.source_sandbox import (
    _absolute, _atomic_bytes_write, _ensure_directory, _hold_plain_directories,
    _validate_regular_file,
)

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXPANDED_BYTES = 250 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_IMPORTS = 32
MAX_CACHE_BYTES = 512 * 1024 * 1024
MAX_PREVIEW_BYTES = 256 * 1024
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}")
_REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}")
_STORE_LOCK = threading.Lock()


class ImportCancelled(ValueError):
    pass


class ImportOperation:
    """Cancellation stays nonblocking; a sealed durable save is allowed to finish."""

    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._sealed = False
        self.deadline = time.monotonic() + 120

    def cancel(self) -> bool:
        with self._lock:
            if self._sealed:
                return False
            self.cancelled.set()
            return True

    def check(self) -> None:
        if self.cancelled.is_set():
            raise ImportCancelled("Import cancelled; no source review entry was saved.")
        if time.monotonic() >= self.deadline:
            raise ValueError("Source import exceeded its phase deadline.")

    def next_phase(self) -> None:
        self.check()
        self.deadline = time.monotonic() + 120

    def seal(self) -> None:
        with self._lock:
            self.check()
            self._sealed = True


def repository_identity(url: str) -> str:
    if not isinstance(url, str) or len(url) > 256:
        raise ValueError("Enter an HTTPS github.com owner/repository URL.")
    parsed = urllib.parse.urlsplit(url.strip())
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com"
            or parsed.query or parsed.fragment):
        raise ValueError("Only public HTTPS github.com repository URLs are supported.")
    name = parsed.path.removeprefix("/").removesuffix("/").removesuffix(".git")
    if not _REPOSITORY.fullmatch(name) or name.split("/")[1] in {".", ".."}:
        raise ValueError("Use the repository URL, without a file or release path.")
    return name.lower()


def _revision(value: str) -> str:
    if not isinstance(value, str) or not _REF.fullmatch(value) or any(
        part in {"", ".", ".."} for part in value.split("/")
    ):
        raise ValueError("Enter a bounded branch, tag or full commit SHA.")
    return value


def plain_text(value: str) -> str:
    return "".join(
        char if char in "\n\t" or unicodedata.category(char)[0] != "C" else "\ufffd"
        for char in value
    )


def _require_unprivileged() -> None:
    from angerona.core.privilege import is_admin
    if (os.name == "nt" and is_admin()) or (
        os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0
    ):
        raise PermissionError("GitHub source import requires a non-administrator Angerona session.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("GitHub redirected this request; use the canonical repository URL.")


def _download(url: str, limit: int, operation: ImportOperation) -> bytes:
    """Only fixed GitHub endpoints; no ambient proxy, cookies, netrc or credentials."""
    _require_unprivileged()
    target = urllib.parse.urlsplit(url)
    if target.scheme != "https" or target.netloc not in {"api.github.com", "codeload.github.com"}:
        raise ValueError("Unapproved source download endpoint.")
    operation.check()
    request = urllib.request.Request(url, headers={
        "User-Agent": "Angerona-Source-Review/1",
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "identity",
        "X-GitHub-Api-Version": "2026-03-10",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    chunks: list[bytes] = []
    total = 0
    try:
        with opener.open(request, timeout=10) as response:
            if response.geturl() != url or response.status != 200:
                raise ValueError("Unexpected GitHub response identity or status.")
            size = response.headers.get("Content-Length")
            if size is not None and (not size.isdecimal() or int(size) > limit):
                raise ValueError("GitHub response exceeds the download limit.")
            while True:
                operation.check()
                chunk = response.read1(min(64 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError("GitHub response exceeds the download limit.")
                chunks.append(chunk)
    except urllib.error.HTTPError as exc:
        if exc.code in {403, 429}:
            raise ValueError("GitHub rate limit or public access restriction; retry later.") from None
        raise ValueError(f"GitHub request failed (HTTP {exc.code}).") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ValueError("GitHub download unavailable or timed out.") from exc
    operation.check()
    return b"".join(chunks)


@dataclass(frozen=True)
class ImportPlan:
    repository: str
    revision: str
    commit: str
    license: str


def resolve_import(url: str, revision: str, operation: ImportOperation) -> ImportPlan:
    repository = repository_identity(url)
    revision = _revision(revision.strip())
    base = f"https://api.github.com/repos/{repository}"
    metadata = json.loads(_download(base, 1024 * 1024, operation))
    if not isinstance(metadata, dict) or str(metadata.get("full_name", "")).lower() != repository:
        raise ValueError("GitHub repository identity did not match the request.")
    if metadata.get("private") is not False:
        raise ValueError("Only public repository source review is supported.")
    commit = json.loads(_download(
        base + "/commits/" + urllib.parse.quote(revision, safe=""), 8 * 1024 * 1024, operation,
    ))
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        raise ValueError("GitHub did not return a complete commit identity.")
    if _SHA.fullmatch(revision.lower()) and sha != revision.lower():
        raise ValueError("Resolved commit differs from the requested full SHA.")
    license_data = metadata.get("license")
    license_id = license_data.get("spdx_id") if isinstance(license_data, dict) else None
    license_id = license_id if isinstance(license_id, str) else "Not reported"
    return ImportPlan(repository, revision, sha, plain_text(license_id[:100]))


def _validate_plan(plan: ImportPlan) -> None:
    if type(plan) is not ImportPlan:
        raise ValueError("Invalid source import plan.")
    if repository_identity("https://github.com/" + plan.repository) != plan.repository:
        raise ValueError("Invalid repository identity.")
    _revision(plan.revision)
    if (not isinstance(plan.commit, str) or not _SHA.fullmatch(plan.commit)
            or not isinstance(plan.license, str) or len(plan.license) > 100):
        raise ValueError("Invalid commit or license metadata.")


def _members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = validate_zip_members(
        archive.infolist(), max_files=MAX_ENTRIES, max_member_bytes=MAX_EXPANDED_BYTES,
        max_total_bytes=MAX_EXPANDED_BYTES, max_ratio=512, allow_directories=True,
    )
    roots = {info.filename.split("/", 1)[0] for info in infos}
    if len(roots) != 1 or any("/" not in info.filename for info in infos):
        raise ValueError("Expected one GitHub source archive root.")
    files: dict[str, zipfile.ZipInfo] = {}
    names = {info.filename.rstrip("/").casefold(): info.is_dir() for info in infos}
    for info in infos:
        parts = info.filename.rstrip("/").split("/")
        if any(names.get("/".join(parts[:index]).casefold()) is False
               for index in range(1, len(parts))):
            raise ValueError("Archive file conflicts with a parent directory.")
        if not info.is_dir():
            files[info.filename.split("/", 1)[1]] = info
    if not files:
        raise ValueError("The source archive contains no regular files.")
    return files


def _open_archive(content: bytes) -> zipfile.ZipFile:
    # Bound metadata before ZipFile allocates one Python object per entry.
    position = content.rfind(b"PK\x05\x06", max(0, len(content) - 65_557))
    if position < 0 or len(content) - position < 22:
        raise ValueError("Source archive has no supported ZIP directory.")
    _, disk, directory_disk, local_count, count, size, offset, comment = struct.unpack(
        "<4s4H2LH", content[position:position + 22],
    )
    if (disk or directory_disk or local_count != count or count > MAX_ENTRIES
            or size > MAX_ENTRIES * 1100 or offset + size != position
            or position + 22 + comment != len(content)):
        raise ValueError("Source ZIP metadata exceeds bounds or uses unsupported volumes/ZIP64.")
    cursor = offset
    for _ in range(count):
        if cursor + 46 > position or content[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("Source ZIP entry count or directory is inconsistent.")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", content, cursor + 28)
        flags = struct.unpack_from("<H", content, cursor + 8)[0]
        end = cursor + 46 + name_size + extra_size + comment_size
        if end > position:
            raise ValueError("Source ZIP directory entry is incomplete.")
        # ZipInfo normalizes platform separators on Windows. Validate the original
        # filename before that normalization, including NUL and alias rejection.
        name = content[cursor + 46:cursor + 46 + name_size].decode(
            "utf-8" if flags & 0x800 else "cp437", errors="strict",
        )
        if any(unicodedata.category(char)[0] == "C" for char in name):
            raise ValueError("Source archive filename contains invisible control characters.")
        safe_archive_path(name, allow_directory=True)
        cursor = end
    if cursor != position:
        raise ValueError("Source ZIP directory contains unaccounted entries.")
    return zipfile.ZipFile(io.BytesIO(content))


def _bounded_read(path: Path, root: Path, limit: int) -> bytes:
    with _hold_plain_directories(root, path.parent):
        before = path.lstat()
        _validate_regular_file(path)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or not os.path.samestat(before, info)
                    or info.st_size > limit):
                raise ValueError("Source store file is redirected or exceeds its limit.")
            content = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
            if len(content) > limit or (info.st_size, info.st_mtime_ns) != (
                after.st_size, after.st_mtime_ns
            ):
                raise ValueError("Source store file changed during its read.")
        _validate_regular_file(path)
        if not os.path.samestat(info, path.lstat()):
            raise ValueError("Source store identity changed during its read.")
        return content


class GitHubToolCatalog:
    """A bounded local source-review library. No executable catalog entries exist."""

    def __init__(self, root: Path):
        self.root = _absolute(root)

    @contextlib.contextmanager
    def _transaction(self):
        with _STORE_LOCK:
            _ensure_directory(self.root)
            try:
                with _hold_plain_directories(self.root):
                    lease = ExclusiveFileLease(self.root / "library.lock")
            except ExclusiveFileLeaseError as exc:
                raise ValueError("Source library is busy or its file lease is unavailable.") from exc
            with lease:
                yield

    def _index(self) -> list[dict]:
        _ensure_directory(self.root)
        try:
            raw = _bounded_read(self.root / "index.json", self.root, 256 * 1024)
        except FileNotFoundError:
            return []
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) > MAX_IMPORTS:
            raise ValueError("Invalid source review index.")
        seen: set[str] = set()
        for row in data:
            expected = {"id", "repository", "revision", "commit", "license", "sha256",
                        "bytes", "files", "expanded_bytes", "imported_at", "state"}
            if not isinstance(row, dict) or set(row) != expected:
                raise ValueError("Invalid source review record.")
            _validate_plan(ImportPlan(**{key: row[key] for key in
                                        ("repository", "revision", "commit", "license")}))
            if (not isinstance(row["id"], str) or not _DIGEST.fullmatch(row["id"])
                    or not isinstance(row["sha256"], str) or not _DIGEST.fullmatch(row["sha256"])
                    or row["state"] not in {"review_only", "reviewed", "revoked"}
                    or row["id"] in seen):
                raise ValueError("Invalid source identity or review state.")
            for field, maximum in (("bytes", MAX_ARCHIVE_BYTES), ("files", MAX_ENTRIES),
                                   ("expanded_bytes", MAX_EXPANDED_BYTES),
                                   ("imported_at", 10**12)):
                minimum = 0 if field == "expanded_bytes" else 1
                if type(row[field]) is not int or not minimum <= row[field] <= maximum:
                    raise ValueError("Invalid source record limits.")
            identity = f'{row["repository"]}\n{row["commit"]}\n{row["sha256"]}'
            if hashlib.sha256(identity.encode()).hexdigest() != row["id"]:
                raise ValueError("Source record identity does not match its digest.")
            seen.add(row["id"])
        return data

    def list_imports(self) -> list[dict]:
        with self._transaction():
            return self._index()

    def _row(self, identity: str) -> dict:
        for row in self._index():
            if row["id"] == identity:
                return row
        raise ValueError("Source import no longer exists.")

    def _archive(self, row: dict) -> bytes:
        content = _bounded_read(self.root / (row["id"] + ".zip"), self.root, MAX_ARCHIVE_BYTES)
        if len(content) != row["bytes"] or hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise ValueError("Imported source failed its stored SHA-256 check.")
        return content

    def import_source(self, plan: ImportPlan, operation: ImportOperation) -> dict:
        _validate_plan(plan)
        _require_unprivileged()
        operation.next_phase()
        content = _download(
            f"https://codeload.github.com/{plan.repository}/zip/{plan.commit}",
            MAX_ARCHIVE_BYTES, operation,
        )
        return self.store_source(plan, content, operation)

    def store_source(self, plan: ImportPlan, content: bytes, operation: ImportOperation) -> dict:
        """Validate downloaded inert bytes, then publish the review index last."""
        _require_unprivileged()
        _validate_plan(plan)
        if not content or len(content) > MAX_ARCHIVE_BYTES:
            raise ValueError("Source archive exceeds its byte budget.")
        operation.next_phase()
        with _open_archive(content) as archive:
            files = _members(archive)
            for info in files.values():
                with archive.open(info) as stream:
                    count = 0
                    while chunk := stream.read(64 * 1024):
                        operation.check()
                        count += len(chunk)
                        if count > info.file_size:
                            raise ValueError("Source member expanded beyond its declared size.")
                    if count != info.file_size:
                        raise ValueError("Source member size is inconsistent.")
            expanded = sum(info.file_size for info in files.values())
        digest = hashlib.sha256(content).hexdigest()
        identity = hashlib.sha256(f"{plan.repository}\n{plan.commit}\n{digest}".encode()).hexdigest()
        row = dict(asdict(plan), id=identity, sha256=digest, bytes=len(content),
                   files=len(files), expanded_bytes=expanded, imported_at=int(time.time()),
                   state="review_only")
        with self._transaction():
            index = self._index()
            prior = next((entry for entry in index if entry["id"] == identity), None)
            if prior is not None:
                operation.check()
                self._archive(prior)
                return prior
            if len(index) >= MAX_IMPORTS:
                raise ValueError("Source library is full (32 imports).")
            # Count unindexed interrupted imports too: they cannot bypass cache limits.
            total = 0
            with _hold_plain_directories(self.root):
                paths = list(self.root.iterdir())
                if len(paths) > MAX_IMPORTS * 3:
                    raise ValueError("Source store needs operator cleanup before importing.")
                for path in paths:
                    _validate_regular_file(path)
                    total += path.stat().st_size
            next_index = json.dumps([*index, row], ensure_ascii=True, sort_keys=True).encode()
            if total + len(content) + len(next_index) > MAX_CACHE_BYTES:
                raise ValueError("Source library exceeds its 512 MiB cache limit.")
            operation.check()
            _atomic_bytes_write(self.root / (identity + ".zip"), content, root=self.root)
            # Seal only the tiny index transaction. A close/cancel before this point
            # leaves at most an inert, unindexed archive which cannot appear ready.
            operation.seal()
            _atomic_bytes_write(self.root / "index.json", next_index, root=self.root)
        return row

    def files(self, identity: str) -> list[str]:
        with self._transaction():
            row = self._row(identity)
            content = self._archive(row)
        with _open_archive(content) as archive:
            return sorted(_members(archive), key=str.casefold)

    def preview(self, identity: str, filename: str) -> str:
        with self._transaction():
            row = self._row(identity)
            content = self._archive(row)
        with _open_archive(content) as archive:
            files = _members(archive)
            if filename not in files:
                raise ValueError("File is not part of this source import.")
            info = files[filename]
            if info.file_size > MAX_PREVIEW_BYTES:
                return f"Preview unavailable: {info.file_size:,} bytes exceeds the 256 KiB text limit."
            raw = read_bounded_member(archive, info, max_bytes=MAX_PREVIEW_BYTES)
        try:
            decoded = raw.decode("utf-8-sig", errors="strict")
        except UnicodeError:
            return f"Binary or unsupported text encoding: {len(raw):,} bytes."
        if "\x00" in decoded:
            return f"Binary content: {len(raw):,} bytes."
        return plain_text(decoded)

    def set_review_state(
        self, identity: str, state: str, operation: ImportOperation,
    ) -> list[dict]:
        _require_unprivileged()
        if state not in {"reviewed", "revoked"}:
            raise ValueError("Unsupported source review transition.")
        with self._transaction():
            index = self._index()
            row = next((entry for entry in index if entry["id"] == identity), None)
            if row is None:
                raise ValueError("Unknown source import.")
            if row["state"] == "revoked":
                raise ValueError("Revocation is permanent for this exact source import.")
            if state == "reviewed":
                self._archive(row)
            row["state"] = state
            operation.seal()
            _atomic_bytes_write(self.root / "index.json", json.dumps(
                index, ensure_ascii=True, sort_keys=True,
            ).encode(), root=self.root)
            return index


def analysis_readiness() -> str:
    """No imported bytes may use the installed-module self-test subprocess."""
    return (
        "Analysis execution unavailable: this release has no verified disposable-VM "
        "backend or approved executable catalog. GitHub imports are available for "
        "source review. Installing Windows Sandbox alone does not enable Run."
    )
