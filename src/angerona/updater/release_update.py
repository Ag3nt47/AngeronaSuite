"""Approved release acquisition; installation belongs to the protected installer.

GitHub metadata and adjacent checksums provide transport identity only. They do
not authenticate a publisher or authorize an installation. Never execute code
from a downloaded ZIP here, and never enroll release trust here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import multiprocessing
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from angerona import __version__
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.url_policy import host_policy, safe_urlopen
from angerona.updater import github_updater as discovery

MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
DOWNLOAD_SECONDS = 15 * 60
MAX_CHECKSUM_BYTES = 1024
_TAG = re.compile(r"v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
_DOWNLOAD_POLICY = host_policy(
    "canonical GitHub release download",
    {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
)
_CACHE_SCHEMA = "angerona.approved-release-check/v1"


class ReleaseUpdateError(RuntimeError):
    """An update was held without weakening the existing release boundary."""


class DownloadRetirementError(ReleaseUpdateError):
    """An owned networking child may still hold its private stage."""


@dataclass(frozen=True)
class ReleaseAsset:
    id: int
    name: str
    size: int
    digest: str = ""


@dataclass(frozen=True)
class ReleaseCandidate:
    release_id: int
    tag: str
    published_at: str
    archive: ReleaseAsset
    checksum: ReleaseAsset

    @property
    def identity(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def url(self, asset: ReleaseAsset) -> str:
        if asset not in (self.archive, self.checksum):
            raise ReleaseUpdateError("The asset is outside the reviewed release.")
        return f"https://github.com/{discovery.CANONICAL_REPOSITORY}/releases/download/{self.tag}/{asset.name}"


@dataclass(frozen=True)
class ReleaseCheck:
    report: discovery.UpdateReport
    candidate: ReleaseCandidate | None
    cached: bool = False
    hold: str = ""


@dataclass(frozen=True)
class ReleaseApproval:
    identity: str
    action: str


@dataclass(frozen=True)
class DownloadedRelease:
    candidate: ReleaseCandidate
    directory: Path
    archive_sha256: str

    @property
    def archive(self) -> Path:
        return self.directory / self.candidate.archive.name


@dataclass(frozen=True)
class ProcessEvidence:
    pid: int
    executable: str
    created_at: float


def _asset(value: object, name: str, maximum: int, *, require_digest: bool = False) -> ReleaseAsset:
    if not isinstance(value, dict) or value.get("name") != name:
        raise ReleaseUpdateError("The exact signed release asset is unavailable.")
    identifier, size = value.get("id"), value.get("size")
    if (
        type(identifier) is not int
        or identifier <= 0
        or type(size) is not int
        or not 1 <= size <= maximum
    ):
        raise ReleaseUpdateError("The release asset identity or byte count is invalid.")
    digest = value.get("digest")
    if digest is None:
        digest = ""
    if not isinstance(digest, str) or (digest and not _DIGEST.fullmatch(digest)):
        raise ReleaseUpdateError("The release asset metadata digest is invalid.")
    if require_digest and not digest:
        raise ReleaseUpdateError(
            "A GitHub archive SHA256 metadata digest is required to bind approved bytes."
        )
    return ReleaseAsset(identifier, name, size, digest)


def select_release(metadata: dict, *, version: str = __version__) -> ReleaseCandidate:
    """Select only the exact stable signed Windows ZIP and adjacent checksum."""
    if (
        not isinstance(metadata, dict)
        or metadata.get("draft") is not False
        or metadata.get("prerelease") is not False
    ):
        raise ReleaseUpdateError("Only published stable releases can be offered.")
    tag = metadata.get("tag_name")
    if not isinstance(tag, str) or not _TAG.fullmatch(tag):
        raise ReleaseUpdateError("A strict vMAJOR.MINOR.PATCH release tag is required.")
    if discovery.version_tuple(tag) <= discovery.version_tuple(version):
        raise ReleaseUpdateError("The published release is not newer than this installation.")
    identifier, published = metadata.get("id"), metadata.get("published_at")
    if (
        type(identifier) is not int
        or identifier <= 0
        or not isinstance(published, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", published)
    ):
        raise ReleaseUpdateError("The stable release identity is incomplete.")
    assets = metadata.get("assets")
    if not isinstance(assets, list) or len(assets) > 100:
        raise ReleaseUpdateError("Release assets are unavailable or oversized.")
    name = f"Angerona-{tag}-win64.zip"
    selected = []
    for expected, maximum in ((name, MAX_ARCHIVE_BYTES), (name + ".sha256", MAX_CHECKSUM_BYTES)):
        matches = [
            item for item in assets if isinstance(item, dict) and item.get("name") == expected
        ]
        if len(matches) != 1:
            raise ReleaseUpdateError(
                "The signed ZIP and its adjacent checksum are required; unsigned/source downloads cannot install."
            )
        selected.append(_asset(matches[0], expected, maximum, require_digest=expected == name))
    return ReleaseCandidate(identifier, tag, published, *selected)


def _candidate_document(candidate: ReleaseCandidate) -> dict:
    return {
        "id": candidate.release_id,
        "tag_name": candidate.tag,
        "published_at": candidate.published_at,
        "draft": False,
        "prerelease": False,
        "assets": [asdict(candidate.archive), asdict(candidate.checksum)],
    }


def _read_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    _regular_file(path, discovery.MAX_STATE_BYTES)
    value = discovery._json(path.read_bytes(), discovery.MAX_STATE_BYTES)
    if (
        value.get("schema") != _CACHE_SCHEMA
        or value.get("repository") != discovery.CANONICAL_REPOSITORY
    ):
        raise ReleaseUpdateError("Release cache identity is invalid.")
    return value


def check_release_updates(
    state_dir: Path,
    source_root: Path,
    *,
    force: bool = False,
    version: str = __version__,
    now: float | None = None,
    fetch: Callable[[str], dict] = discovery.github_json,
) -> ReleaseCheck:
    """Share app daily/manual retry limits and retain safe same-day results.

    Cache replay never authorizes a download. Approval and a fresh exact-metadata
    comparison are required before any payload request.
    """
    try:
        root = discovery._safe_state_root(state_dir)
        with ExclusiveFileLease(root / "release-check.lock"):
            captured: dict = {}

            def capture(path: str) -> dict:
                result = fetch(path)
                if path == "releases/latest":
                    captured["release"] = result
                return result

            report = discovery.daily_update_check(
                root,
                force=force,
                version=version,
                now=now,
                fetch=capture,
                revision_reader=lambda: discovery.local_source_revision(source_root),
            )
            cached = report.status == "not_due"
            candidate = None
            hold = ""
            if cached:
                state = discovery._read_state(root / "check.json")
                cache = _read_cache(root / "release-check.json")
                outcome = state.get("outcome")
                if not isinstance(outcome, dict):
                    return ReleaseCheck(
                        report,
                        None,
                        True,
                        "Previous check did not finish; retry after the shared interval.",
                    )
                previous = discovery.UpdateReport(**outcome)
                # The cache must belong to the precise shared attempt and this
                # installed version; a different app attempt invalidates it.
                if (
                    cache.get("attempted_at") != state.get("last_attempt")
                    or cache.get("version") != version
                ):
                    return ReleaseCheck(
                        report,
                        None,
                        True,
                        "No release-asset cache for the shared check; use --check-now after the retry floor.",
                    )
                report = previous
                if previous.release_status == "newer":
                    try:
                        candidate = select_release(cache.get("candidate"), version=version)
                    except ReleaseUpdateError:
                        hold = cache.get(
                            "hold", "The previously observed signed release assets are unavailable."
                        )
            elif report.status in {"checked", "partial"}:
                if report.release_status == "newer":
                    try:
                        candidate = select_release(captured.get("release"), version=version)
                    except ReleaseUpdateError as exc:
                        hold = str(exc)
                discovery._write_state(
                    root / "release-check.json",
                    {
                        "schema": _CACHE_SCHEMA,
                        "repository": discovery.CANONICAL_REPOSITORY,
                        "attempted_at": report.checked_at,
                        "version": version,
                        "candidate": _candidate_document(candidate) if candidate else None,
                        "hold": hold,
                    },
                )
            return ReleaseCheck(report, candidate, cached, hold)
    except Exception as exc:
        return ReleaseCheck(
            discovery.UpdateReport(
                "failed",
                time.time(),
                version,
                message=f"Release check held ({type(exc).__name__}); update status is unknown.",
            ),
            None,
        )


def approve_release(
    candidate: ReleaseCandidate, *, action: str, accepted: bool
) -> ReleaseApproval | None:
    if action not in {"download", "install"} or type(accepted) is not bool:
        raise ValueError("An explicit download or install decision is required.")
    return ReleaseApproval(candidate.identity, action) if accepted else None


def _require_approval(
    candidate: ReleaseCandidate, approval: ReleaseApproval | None, *, install: bool = False
) -> None:
    if select_release(_candidate_document(candidate), version="0.0.0") != candidate:
        raise ReleaseUpdateError("The reviewed candidate identity is invalid.")
    if (
        not isinstance(approval, ReleaseApproval)
        or approval.identity != candidate.identity
        or approval.action not in ({"install"} if install else {"download", "install"})
    ):
        raise ReleaseUpdateError("Explicit approval of this exact release identity is required.")


def _regular_file(path: Path, maximum: int) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_nlink != 1
        or getattr(info, "st_file_attributes", 0) & 0x400
        or not 0 <= info.st_size <= maximum
    ):
        raise ReleaseUpdateError("A bounded, single-link, non-reparse regular file is required.")


def _new_private_directory(path: Path) -> None:
    if sys.platform != "win32":
        path.mkdir(mode=0o700)
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ReleaseUpdateError("Private stage permissions could not be established.")
        return
    import ctypes
    from ctypes import wintypes

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi, kernel = (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
    )
    advapi.OpenProcessToken.argtypes, advapi.OpenProcessToken.restype = (
        [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
        wintypes.BOOL,
    )
    advapi.GetTokenInformation.argtypes, advapi.GetTokenInformation.restype = (
        [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ],
        wintypes.BOOL,
    )
    advapi.ConvertSidToStringSidW.argtypes, advapi.ConvertSidToStringSidW.restype = (
        [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)],
        wintypes.BOOL,
    )
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CreateDirectoryW.argtypes, kernel.CreateDirectoryW.restype = (
        [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)],
        wintypes.BOOL,
    )
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [wintypes.HLOCAL], wintypes.HLOCAL
    token, text, descriptor = wintypes.HANDLE(), wintypes.LPWSTR(), wintypes.LPVOID()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ReleaseUpdateError("Private-stage account identity is unavailable.")
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 0 < needed.value <= 65536:
            raise ReleaseUpdateError("Private-stage token identity is invalid.")
        information = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, information, needed, ctypes.byref(needed)):
            raise ReleaseUpdateError("Private-stage account identity is unavailable.")
        sid = ctypes.cast(information, ctypes.POINTER(wintypes.LPVOID))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ReleaseUpdateError("Private-stage SID identity is unavailable.")
        sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{text.value})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise ReleaseUpdateError("Private-stage access policy is unavailable.")
        attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ReleaseUpdateError("A new private release stage could not be created.")
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if text:
            kernel.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
        if token:
            kernel.CloseHandle(token)


def _fetch_worker(url: str, target: str, expected: int, maximum: int, seconds: float, pipe) -> None:
    """One owned networking child; the parent enforces a wall-clock deadline."""
    try:
        # Policy-selected GitHub hosts must not be routed through arbitrary
        # inherited proxy endpoints. This mutation is confined to our child.
        for key in tuple(os.environ):
            if key.casefold() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                os.environ.pop(key, None)
        deadline = time.monotonic() + seconds
        request = urllib.request.Request(
            url, headers={"User-Agent": "Angerona-Approved-Release-Updater"}
        )
        with safe_urlopen(request, policy=_DOWNLOAD_POLICY, timeout=min(20, seconds)) as response:
            if getattr(response, "status", 200) != 200:
                raise ReleaseUpdateError("The release asset request was unsuccessful.")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) != expected):
                raise ReleaseUpdateError("The release asset response size changed.")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            total = 0
            with os.fdopen(descriptor, "wb") as handle:
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Release download deadline exceeded.")
                    chunk = response.read(min(65536, maximum - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > maximum or total > expected:
                        raise ReleaseUpdateError(
                            "The release asset exceeded its approved byte count."
                        )
                    handle.write(chunk)
                if total != expected:
                    raise ReleaseUpdateError("The release asset was truncated.")
                handle.flush()
                os.fsync(handle.fileno())
        pipe.send(None)
    except BaseException as exc:
        # Never copy remote exception text or signed CDN query strings to logs.
        pipe.send(type(exc).__name__)
    finally:
        pipe.close()


def fetch_release_file(url: str, target: Path, expected: int, maximum: int, seconds: float) -> None:
    """Bound DNS, redirects and slow response bodies with an owned process."""
    if (
        type(seconds) not in (int, float)
        or not math.isfinite(seconds)
        or not 0 < seconds <= DOWNLOAD_SECONDS
    ):
        raise ValueError("The release download deadline is invalid.")
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_fetch_worker, args=(url, str(target), expected, maximum, seconds, sender)
    )
    try:
        process.start()
        sender.close()
        if not receiver.poll(seconds):
            raise ReleaseUpdateError("Release download exceeded its total deadline.")
        result = receiver.recv()
        process.join(5)
        if result is not None or process.exitcode != 0:
            raise ReleaseUpdateError(f"Release download failed ({result or 'worker exit'}).")
    finally:
        sender.close()
        receiver.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            if process.is_alive():
                raise DownloadRetirementError(
                    "Owned download worker did not retire; stage cleanup is held."
                )
            process.close()


def _hash_file(path: Path, expected: int, maximum: int) -> str:
    _regular_file(path, maximum)
    if path.stat().st_size != expected:
        raise ReleaseUpdateError("Downloaded size does not match the approved metadata.")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(block)
            if total > expected or total > maximum:
                raise ReleaseUpdateError(
                    "Downloaded bytes grew beyond their approved size during verification."
                )
            digest.update(block)
    if total != expected:
        raise ReleaseUpdateError("Downloaded bytes changed size during verification.")
    return digest.hexdigest()


def _verify_download(candidate: ReleaseCandidate, directory: Path) -> str:
    digests = {}
    for asset, maximum in (
        (candidate.archive, MAX_ARCHIVE_BYTES),
        (candidate.checksum, MAX_CHECKSUM_BYTES),
    ):
        actual = _hash_file(directory / asset.name, asset.size, maximum)
        if asset.digest and asset.digest != "sha256:" + actual:
            raise ReleaseUpdateError(
                "Downloaded bytes differ from the approved GitHub metadata digest."
            )
        digests[asset.name] = actual
    checksum = (directory / candidate.checksum.name).read_bytes()
    expected = re.fullmatch(
        rb"([0-9A-Fa-f]{64})  "
        + re.escape(candidate.archive.name.encode("ascii"))
        + rb"(?:\r?\n)?",
        checksum,
    )
    if not expected or expected[1].decode("ascii").lower() != digests[candidate.archive.name]:
        raise ReleaseUpdateError(
            "The adjacent checksum does not name and hash the exact approved ZIP."
        )
    return digests[candidate.archive.name]


def download_release(
    candidate: ReleaseCandidate,
    approval: ReleaseApproval | None,
    stages_dir: Path,
    *,
    version: str = __version__,
    fetch: Callable[[str], dict] = discovery.github_json,
    transport: Callable = fetch_release_file,
    seconds: float = DOWNLOAD_SECONDS,
) -> DownloadedRelease:
    _require_approval(candidate, approval)
    if (
        type(seconds) not in (int, float)
        or not math.isfinite(seconds)
        or not 0 < seconds <= DOWNLOAD_SECONDS
    ):
        raise ValueError("The release download deadline is invalid.")
    fresh = select_release(fetch("releases/latest"), version=version)
    if fresh != candidate:
        raise ReleaseUpdateError(
            "Release metadata changed after review; check and approve the new identity."
        )
    root = discovery._safe_state_root(stages_dir)
    pending = root / (".downloading-" + uuid.uuid4().hex)
    completed = root / ("release-" + uuid.uuid4().hex)
    _new_private_directory(pending)
    deadline = time.monotonic() + seconds
    try:
        for asset, maximum in (
            (candidate.checksum, MAX_CHECKSUM_BYTES),
            (candidate.archive, MAX_ARCHIVE_BYTES),
        ):
            # Floating-point deadline subtraction can exceed the original
            # budget by an ULP even when the monotonic clock has not advanced.
            remaining = min(seconds, deadline - time.monotonic())
            if remaining <= 0:
                raise ReleaseUpdateError("The release download deadline expired.")
            transport(candidate.url(asset), pending / asset.name, asset.size, maximum, remaining)
        digest = _verify_download(candidate, pending)
        discovery._write_state(
            pending / "receipt.json",
            {
                "schema": "angerona.release-download/v1",
                "repository": discovery.CANONICAL_REPOSITORY,
                "candidate_identity": candidate.identity,
                "candidate": _candidate_document(candidate),
                "archive_sha256": digest,
                "install_trust": "unverified; protected installer required",
            },
        )
        pending.rename(completed)
        return DownloadedRelease(candidate, completed, digest)
    except DownloadRetirementError:
        raise
    except Exception:
        # Only this newly-created directory is removed, after transport retires.
        if pending.exists():
            shutil.rmtree(pending)
        raise


def protected_windows_paths() -> tuple[Path, Path]:
    if sys.platform != "win32":
        raise ReleaseUpdateError(
            "Verified portable upgrades require Windows; use your platform's governed installer."
        )
    from angerona.core.privilege import _windows_known_folder, trusted_windows_directories

    _, system = trusted_windows_directories()
    return _windows_known_folder(
        0x26
    ) / "Angerona", system / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def installed_processes(install_root: Path) -> list[ProcessEvidence]:
    """Select by exact installed executable paths and retain PID/birth evidence.

    Incomplete executable coverage holds installation. No process is stopped.
    """
    import psutil

    names = (
        "Angerona.exe",
        "AngeronaStartup.exe",
        "AngeronaBlackBox.exe",
        "AngeronaReleaseVerifier.exe",
        "frz_watchdog_v2.exe",
    )
    paths = {str(install_root / name).casefold() for name in names}
    basenames = {name.casefold() for name in names}
    found = []
    for process in psutil.process_iter():
        if process.pid in {0, 4}:
            continue  # Windows kernel generations cannot be installed executables.
        try:
            # A basename only discovers possible candidates; it never proves
            # ownership. Do not inspect unrelated denied system executables.
            name = process.name()
            if not isinstance(name, str) or not name:
                raise ReleaseUpdateError(
                    "Process-name discovery coverage is unavailable; installation is held."
                )
            if name.casefold() not in basenames:
                continue
            executable = process.exe()
            if not executable:
                raise ReleaseUpdateError(
                    "Process executable coverage is unavailable; installation is held."
                )
            if executable.casefold() in paths:
                created = process.create_time()
                if not math.isfinite(created) or created <= 0:
                    raise ReleaseUpdateError("Installed process creation identity is unavailable.")
                found.append(ProcessEvidence(process.pid, executable, created))
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            raise ReleaseUpdateError(
                "Angerona-candidate process identity coverage is denied; close the suite and retry with sufficient inspection rights."
            ) from exc
    return found


def _powershell_execute(
    powershell: Path, installer: Path, archive: Path, *, preflight: bool
) -> int:
    from angerona.core.privilege import sanitized_child_environment

    environment = sanitized_child_environment(source={})
    environment["PSModulePath"] = str(powershell.parent / "Modules")
    arguments = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "RemoteSigned",
        "-File",
        str(installer),
    ]
    if preflight:
        arguments.append("-CustodyPreflightOnly")
        result = subprocess.run(
            [str(powershell), *arguments],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        return result.returncode
    arguments.extend(["-ReleaseArchive", str(archive)])

    # A sanitized, OS-path PowerShell bridge requests UAC. The elevated child
    # inherits that bridge's minimal environment, never a provider key,
    # caller-controlled PSModulePath, proxy or runtime injection variable.
    def literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    script = (
        "$ErrorActionPreference='Stop';try{"
        "$p=Start-Process -WindowStyle Hidden -FilePath "
        + literal(str(powershell))
        + " -ArgumentList "
        + literal(subprocess.list2cmdline(arguments))
        + " -Verb RunAs -PassThru;"
        "if(-not $p.WaitForExit(1800000)){exit 3};exit $p.ExitCode}catch{exit 2}"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode == 3:
        raise ReleaseUpdateError(
            "Protected installer still running; outcome is unknown. Do not retry concurrently."
        )
    return result.returncode


def protected_installer_custody(root: Path, installer: Path) -> bool:
    """Do not execute even preflight from a user-writable installed authority."""
    from angerona.core.executable_trust import _windows_acl_protected

    return _windows_acl_protected(root) and _windows_acl_protected(installer)


def installed_release_version(
    *, paths: Callable = protected_windows_paths, custody: Callable = protected_installer_custody
) -> str:
    """Read protected installed metadata for comparison, never as install trust."""
    root, _ = paths()
    document = root / "release-authorization.json"
    if not root.is_dir():
        raise ReleaseUpdateError("Protected installed version metadata is missing.")
    discovery._safe_state_root(root)
    _regular_file(document, 256 * 1024)
    if not custody(root, document):
        raise ReleaseUpdateError("Protected installed version metadata custody is unavailable.")
    value = discovery._json(document.read_bytes(), 256 * 1024)
    statement = value.get("statement")
    if (
        not isinstance(statement, dict)
        or statement.get("schema") != "angerona.release-authorization/v2"
        or statement.get("product") != "Angerona"
    ):
        raise ReleaseUpdateError("Protected installed version metadata identity is invalid.")
    version = statement.get("version")
    discovery.version_tuple(version)
    return version.removeprefix("v")


def install_download(
    download: DownloadedRelease,
    approval: ReleaseApproval | None,
    *,
    paths: Callable[[], tuple[Path, Path]] = protected_windows_paths,
    processes: Callable[[Path], list[ProcessEvidence]] = installed_processes,
    custody: Callable[[Path, Path], bool] = protected_installer_custody,
    execute: Callable = _powershell_execute,
) -> dict:
    """Request the existing protected verifier/installer; never candidate code."""
    _require_approval(download.candidate, approval, install=True)
    parent = discovery._safe_state_root(download.directory.parent)
    if not re.fullmatch(r"release-[0-9a-f]{32}", download.directory.name):
        raise ReleaseUpdateError("The downloaded release stage identity is invalid.")
    with ExclusiveFileLease(parent / "install.lock"):
        state_path = parent / "install-state.json"
        if state_path.exists():
            _regular_file(state_path, discovery.MAX_STATE_BYTES)
            previous = discovery._json(state_path.read_bytes(), discovery.MAX_STATE_BYTES)
            if (
                previous.get("schema") != "angerona.release-install/v1"
                or previous.get("repository") != discovery.CANONICAL_REPOSITORY
            ):
                raise ReleaseUpdateError(
                    "Previous installation state is invalid; explicit operator recovery review is required."
                )
            if previous.get("status") != "restart_requested":
                raise ReleaseUpdateError(
                    "A previous protected installation has a pending, unknown or recovery-required outcome; explicit operator recovery review is required before retry."
                )
        return _install_locked(
            download,
            approval,
            state_path,
            paths=paths,
            processes=processes,
            custody=custody,
            execute=execute,
        )


def _install_locked(
    download: DownloadedRelease,
    approval: ReleaseApproval,
    state_path: Path,
    *,
    paths: Callable,
    processes: Callable,
    custody: Callable,
    execute: Callable,
) -> dict:
    root, powershell = paths()
    installer = root / "Install-Angerona-Release.ps1"
    if not installer.is_file():
        raise ReleaseUpdateError(
            "Protected installed upgrade authority is missing. First install requires the signed Angerona MSIX; no downloaded script can establish trust."
        )
    discovery._safe_state_root(root)  # Reject aliased Program Files ancestry.
    _regular_file(installer, 1024 * 1024)
    _regular_file(powershell, 64 * 1024 * 1024)
    if not custody(root, installer):
        raise ReleaseUpdateError(
            "Protected installed authority ownership/ACL verification failed before executing preflight."
        )
    actual_version = installed_release_version(paths=lambda: (root, powershell), custody=custody)
    if discovery.version_tuple(download.candidate.tag) <= discovery.version_tuple(actual_version):
        raise ReleaseUpdateError(
            "The reviewed release is no longer newer than the protected installed version."
        )
    if _verify_download(download.candidate, download.directory) != download.archive_sha256:
        raise ReleaseUpdateError("The staged release changed after download.")
    if execute(powershell, installer, download.archive, preflight=True) != 0:
        raise ReleaseUpdateError("Protected installed custody preflight failed before elevation.")
    running = processes(root)
    if running:
        evidence = "; ".join(
            f"PID {item.pid}, created {item.created_at:.6f}, executable {item.executable}"
            for item in running
        )
        raise ReleaseUpdateError(
            "Close installed Angerona components before upgrading. Observed: " + evidence
        )
    state = {
        "schema": "angerona.release-install/v1",
        "repository": discovery.CANONICAL_REPOSITORY,
        "status": "pending",
        "candidate_identity": download.candidate.identity,
        "tag": download.candidate.tag,
        "requested_at": time.time(),
        "runtime_health": "unverified",
    }
    discovery._write_state(state_path, state)
    try:
        code = execute(powershell, installer, download.archive, preflight=False)
    except BaseException:
        # This receipt is not an installation/recovery authority. Leave it
        # pending if interruption prevents a durable unknown-outcome write.
        state["status"] = "unknown"
        discovery._write_state(state_path, state)
        raise
    if code != 0:
        # A nonzero exit does not prove that the installer left its protected
        # destination untouched. In the absence of an authenticated no-mutation
        # receipt, every attempted install failure requires recovery review.
        state["status"] = "recovery_required"
        discovery._write_state(state_path, state)
        raise ReleaseUpdateError(
            "The protected installer did not complete successfully; destination mutation is unknown. Explicit operator recovery review is required before retry."
        )
    state["status"] = "restart_requested"
    discovery._write_state(state_path, state)
    return {
        "status": "restart_requested",
        "tag": download.candidate.tag,
        "candidate_identity": download.candidate.identity,
        "runtime_health": "unverified",
        "message": "Protected installer returned success and requested startup; health has not been observed.",
    }
