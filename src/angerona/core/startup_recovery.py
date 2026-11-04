"""Closed startup outcomes and private, verified child scratch directories.

This module never repairs an interpreter or starts an application. The source
launch supervisor owns the one repair attempt, outside every venv process.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import re
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
from typing import Callable


REPAIR_EXIT_CODES = {81: "Runtime", 82: "Dependencies", 83: "GuiRuntime"}
MINIMUM_FREE_BYTES = 128 * 1024 * 1024


def write_read_proof(directory: Path) -> None:
    """Flush and read back only a new, exclusively created disposable file."""
    expected = secrets.token_bytes(32)
    fd, name = tempfile.mkstemp(prefix="startup-check-", dir=directory)
    try:
        with os.fdopen(fd, "w+b") as stream:
            stream.write(expected)
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(0)
            if stream.read() != expected:
                raise OSError("Startup storage readback did not match the flushed bytes.")
    finally:
        Path(name).unlink(missing_ok=True)


def _windows_security(path: Path, *, create: bool, allow_inherited: bool = False) -> bool:
    """Atomically create, or independently verify, a current-user private dir."""
    from ctypes import wintypes as w

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = w.HANDLE()
    kernel.GetCurrentProcess.restype = w.HANDLE
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = w.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [w.LPVOID, ctypes.POINTER(w.BOOL), ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = w.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID)]
    advapi.GetNamedSecurityInfoW.restype = w.DWORD
    advapi.EqualSid.argtypes = [w.LPVOID, w.LPVOID]
    advapi.EqualSid.restype = w.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [w.LPVOID, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = w.BOOL
    kernel.LocalFree.argtypes = [w.LPVOID]
    kernel.LocalFree.restype = w.LPVOID
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    sid_text = w.LPWSTR()
    expected_sd = w.LPVOID()
    actual_sd = w.LPVOID()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        user = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, user, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        user_sid = ctypes.cast(user, ctypes.POINTER(w.LPVOID))[0]
        if not advapi.ConvertSidToStringSidW(user_sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = sid_text.value
        sddl = f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(expected_sd), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if create:
            class Attributes(ctypes.Structure):
                _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

            attrs = Attributes(ctypes.sizeof(Attributes), expected_sd, False)
            kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, ctypes.POINTER(Attributes)]
            kernel.CreateDirectoryW.restype = w.BOOL
            if not kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)):
                raise ctypes.WinError(ctypes.get_last_error())
        owner, actual_acl, expected_acl = w.LPVOID(), w.LPVOID(), w.LPVOID()
        if advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(actual_acl), None, ctypes.byref(actual_sd)):
            return False
        present, defaulted = w.BOOL(), w.BOOL()
        control, revision = w.WORD(), w.DWORD()
        if not (
            owner and actual_acl and advapi.EqualSid(owner, user_sid)
            and advapi.GetSecurityDescriptorControl(actual_sd, ctypes.byref(control), ctypes.byref(revision))
            and (allow_inherited or control.value & 0x1000)
            and advapi.GetSecurityDescriptorDacl(expected_sd, ctypes.byref(present), ctypes.byref(expected_acl), ctypes.byref(defaulted))
            and present and expected_acl
        ):
            return False
        # Compare every complete ACE independently of the OS's canonical ACE
        # ordering. Extra/inherited rights and null DACLs remain rejected.
        def acl_entries(pointer):
            count = ctypes.cast(pointer.value + 4, ctypes.POINTER(w.WORD))[0]
            offset = 8
            entries = []
            for _ in range(count):
                length = ctypes.cast(pointer.value + offset + 2, ctypes.POINTER(w.WORD))[0]
                entry = ctypes.string_at(pointer.value + offset, length)
                if allow_inherited:
                    # Files inherit the same full-control principals from the
                    # private scratch parent; normalize only inheritance bits.
                    entry = entry[:1] + bytes([entry[1] & ~0x13]) + entry[2:]
                entries.append(entry)
                offset += length
            return sorted(entries)

        return acl_entries(actual_acl) == acl_entries(expected_acl)
    finally:
        for allocation in (sid_text, expected_sd, actual_sd):
            if allocation:
                kernel.LocalFree(allocation)
        if token:
            kernel.CloseHandle(token)


def private_directory(path: Path, *, create: bool) -> bool:
    if os.name == "nt":
        return _windows_security(path, create=create)
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    return (
        stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
    )


def private_repair_file(path: Path) -> bool:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return False
    if os.name == "nt":
        return _windows_security(path, create=False, allow_inherited=True)
    return info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077


def select_temporary(storage: Path, installation: Path, *,
                     validate: Callable[[Path], None],
                     fixed: Callable[[Path], bool],
                     inherited: dict[str, str], critical_directory: Path | None = None) -> Path:
    """Select only owned scratch; never alter the caller's environment.

    The caller must first prove private persistent storage and actual I/O.
    Ordinary paths retain the free-space reserve. A kernel-validated critical
    workspace makes that recommendation advisory and keeps bounded admission.
    """
    bases = (storage / "tmp", installation / ".tmp")
    if critical_directory is not None:
        candidate = Path(critical_directory)
        if candidate.parent not in bases or candidate.name != "startup-temp.critical-preflight":
            raise OSError("Critical temporary storage is outside the fixed preflight workspaces.")
        validate(candidate)
        if not fixed(Path(candidate.anchor)) or not private_directory(candidate, create=False):
            raise OSError("Critical temporary storage lacks private fixed-drive custody.")
        count = 0
        total = 0
        for entry in candidate.iterdir():
            count += 1
            if count > 128:
                raise OSError("Critical temporary storage exceeds its bounded flat inventory.")
            validate(entry)
            info = entry.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
                raise OSError("Critical temporary storage contains an unknown or redirected entry.")
            total += info.st_size
            if total > 32 * 1024 * 1024:
                raise OSError("Critical temporary storage exceeds its 32 MiB working budget.")
        write_read_proof(candidate)
        return candidate
    # Reuse a supervisor's fresh private scratch only after all the same native
    # custody, fixed-volume, capacity and real I/O checks. No environment flag
    # is itself authority to skip a check.
    for name in ("TEMP", "TMP"):
        raw = inherited.get(name)
        if not raw:
            continue
        try:
            candidate = Path(raw)
            if candidate.parent not in bases or not candidate.name.startswith("startup-temp."):
                continue
            validate(candidate)
            if not fixed(Path(candidate.anchor)) or shutil.disk_usage(candidate).free < MINIMUM_FREE_BYTES:
                continue
            if private_directory(candidate, create=False):
                write_read_proof(candidate)
                return candidate
        except (OSError, ValueError, RuntimeError):
            continue
    for base in bases:
        try:
            validate(base)
            if not fixed(Path(base.anchor)):
                continue
            base.mkdir(parents=True, exist_ok=True)
            validate(base)
            if not base.is_dir() or shutil.disk_usage(base).free < MINIMUM_FREE_BYTES:
                continue
            candidate = base / f"startup-temp.{secrets.token_hex(16)}"
            validate(candidate)
            if not private_directory(candidate, create=True):
                continue
            validate(candidate)
            write_read_proof(candidate)
            return candidate
        except (OSError, ValueError, RuntimeError):
            continue
    raise OSError("No verified private startup temporary directory has 128 MB free. Free space on the local data or installation drive and retry; settings and evidence were preserved.")


# Source-user updates derive these two generated outputs with the ORIGINAL
# capsule code. No candidate module, generator, hook or command is executed.
RECOVERY_MANIFEST_PATH = "assets/startup-recovery-manifest.json"
RECOVERY_BATCH_PATH = "start-angerona.bat"
RECOVERY_VERIFIER_PATH = "tools/verify_startup_recovery_bundle.ps1"
RECOVERY_COHERENCE_FILES = (
    "Repair-Angerona-Python.ps1",
    "constraints-release.txt",
    "pyproject.toml",
    "requirements-bootstrap-pip.txt",
    "requirements-release-hashed.txt",
    "src/angerona/__main__.py",
    "src/angerona/core/_source_tomli/LICENSE",
    "src/angerona/core/_source_tomli/__init__.py",
    "src/angerona/core/_source_tomli/_parser.py",
    "src/angerona/core/_source_tomli/_re.py",
    "src/angerona/core/_source_tomli/_types.py",
    "src/angerona/core/file_lease.py",
    "src/angerona/core/source_activation.py",
    "src/angerona/core/source_activation_broker.py",
    "src/angerona/core/source_activation_file.py",
    "src/angerona/core/source_activation_storage.py",
    "src/angerona/core/source_activation_workspace.py",
    "src/angerona/core/startup_diagnostics.py",
    "src/angerona/core/startup_recovery.py",
    "src/angerona/resilience/component_status.py",
    "src/angerona/resilience/heartbeat.py",
    "src/angerona/startup.py",
    "src/angerona/updater/github_updater.py",
    "src/angerona/updater/source_git.py",
    "src/angerona/updater/source_stage.py",
    "tools/Invoke-AngeronaSourceStartup.ps1",
    "tools/Invoke-AngeronaStartupRepair.ps1",
    "tools/Resume-AngeronaSourceActivation.ps1",
    "tools/Show-AngeronaStartupRecovery.ps1",
    "tools/activate_source_update.py",
    "tools/angerona_recovery.py",
    "tools/build_srt_compat_wheel.py",
    "tools/publication_git_runtime_profile.json",
    "tools/publication_transport.py",
    "tools/source_trust_preflight.py",
    "tools/startup_assistant_capture.ps1",
    "tools/startup_repair_common.ps1",
    "tools/startup_source_recovery.py",
    "tools/windows_publication_runtime.py",
)
_RECOVERY_FILE_LIMIT = 2 * 1024**2
_RECOVERY_MANIFEST_LIMIT = 128 * 1024
_RECOVERY_MARKER = b":__ANGERONA_PINNED_BOOTSTRAP__"
_RECOVERY_PIN_FIELDS = ((b"manifestSha", 64), (b"manifestBlob", 40),
                        (b"verifierSha", 64), (b"verifierBlob", 40))


class RecoveryCoherenceError(ValueError):
    """The fixed source recovery profile cannot be derived or verified."""


def _recovery_canonical(raw, limit=_RECOVERY_FILE_LIMIT):
    if type(raw) is not bytes or len(raw) > 2 * limit + 3:
        raise RecoveryCoherenceError("Recovery input exceeds its fixed byte profile")
    try:
        text = raw.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeError as error:
        raise RecoveryCoherenceError("Recovery input is not supported UTF-8 text") from error
    if "\r" in text or "\0" in text:
        raise RecoveryCoherenceError("Recovery input contains a lone CR or NUL")
    result = text.encode("utf-8")
    if len(result) > limit:
        raise RecoveryCoherenceError("Recovery canonical text exceeds its fixed limit")
    return result


def _recovery_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _recovery_encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n").encode("utf-8")


def _recovery_unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise RecoveryCoherenceError("Recovery manifest has duplicate metadata")
        result[name] = value
    return result


def validate_recovery_manifest_profile(raw):
    """Recognize generated metadata only; stale hashes are not code conflicts."""
    canonical = _recovery_canonical(raw, _RECOVERY_MANIFEST_LIMIT)
    try:
        value = json.loads(canonical, object_pairs_hook=_recovery_unique_pairs)
    except (ValueError, TypeError, RecursionError) as error:
        raise RecoveryCoherenceError("Recovery manifest is not supported canonical metadata") from error
    if (type(value) is not dict
            or set(value) != {"schema", "repository", "canonical_text", "files"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["repository"] != "Ag3nt47/AngeronaSuite"
            or value["canonical_text"] != "utf8-lf-no-bom"
            or type(value["files"]) is not list
            or len(value["files"]) != len(RECOVERY_COHERENCE_FILES)):
        raise RecoveryCoherenceError("Recovery manifest has an unknown schema or member profile")
    total = 0
    for row, name in zip(value["files"], RECOVERY_COHERENCE_FILES):
        if (type(row) is not dict or set(row) != {"path", "bytes", "sha256", "git_blob_sha1"}
                or row["path"] != name or type(row["bytes"]) is not int
                or not 0 <= row["bytes"] <= _RECOVERY_FILE_LIMIT
                or type(row["sha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
                or type(row["git_blob_sha1"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", row["git_blob_sha1"]) is None):
            raise RecoveryCoherenceError("Recovery manifest has an unknown entry profile")
        total += row["bytes"]
    if total > 32 * 1024**2 or canonical != _recovery_encoded(value):
        raise RecoveryCoherenceError("Recovery manifest is noncanonical or exceeds its aggregate limit")


def _recovery_batch_fields(raw):
    _recovery_canonical(raw)
    lines = raw.splitlines(keepends=True)
    markers = [index for index, line in enumerate(lines)
               if line.rstrip(b"\r\n") == _RECOVERY_MARKER]
    if len(markers) != 1:
        raise RecoveryCoherenceError("Recovery batch requires one exact bootstrap marker")
    spans, values = {}, {}
    for name, length in _RECOVERY_PIN_FIELDS:
        matches = []
        offset = 0
        declaration = re.compile(rb"^\$" + name + rb"(?:\s|=|$)")
        pattern = re.compile(rb"\$" + name + rb"='([0-9a-f]{" + str(length).encode() + rb"})'")
        for index, line in enumerate(lines):
            body = line.rstrip(b"\r\n")
            if declaration.match(body):
                match = pattern.fullmatch(body)
                if match is None or index <= markers[0]:
                    raise RecoveryCoherenceError("Recovery batch has an unsupported pin declaration")
                matches.append((offset + match.start(1), offset + match.end(1), match.group(1)))
            offset += len(line)
        if len(matches) != 1:
            raise RecoveryCoherenceError("Recovery batch requires four unique literal pin values")
        start, end, value = matches[0]
        spans[name], values[name] = (start, end), value
    return spans, values


def _rewrite_recovery_batch(raw, values):
    spans, _previous = _recovery_batch_fields(raw)
    result = bytearray(raw)
    for name, length in _RECOVERY_PIN_FIELDS:
        value = values[name]
        if type(value) is not bytes or len(value) != length or re.fullmatch(rb"[0-9a-f]+", value) is None:
            raise RecoveryCoherenceError("Recovery batch pin output is invalid")
        start, end = spans[name]
        result[start:end] = value
    return bytes(result)


def mask_recovery_batch_pins(raw):
    """Mask only four exact hash value spans, retaining every other raw byte."""
    return _rewrite_recovery_batch(raw, {name: b"0" * length for name, length in _RECOVERY_PIN_FIELDS})


def restore_recovery_batch_pins(masked, reference):
    """Give a merged raw stage valid placeholder pins without rewriting code."""
    _spans, values = _recovery_batch_fields(reference)
    return _rewrite_recovery_batch(masked, values)


def _validate_recovery_verifier_profile(canonical):
    lines = canonical.decode("utf-8").splitlines()
    headers = [index for index, line in enumerate(lines)
               if re.match(r"^\$script:BundleFiles\s*=", line)]
    if len(headers) != 1 or re.fullmatch(r"\$script:BundleFiles\s*=\s*@\(", lines[headers[0]]) is None:
        raise RecoveryCoherenceError("Recovery verifier has an unknown member declaration")
    paths = []
    for line in lines[headers[0] + 1:]:
        if line == ")":
            break
        match = re.fullmatch(r"\s*'([^']+)'[,]?\s*", line)
        if match is None or len(paths) >= len(RECOVERY_COHERENCE_FILES):
            raise RecoveryCoherenceError("Recovery verifier has an unsupported member profile")
        paths.append(match.group(1))
    else:
        raise RecoveryCoherenceError("Recovery verifier member declaration is incomplete")
    if tuple(paths) != RECOVERY_COHERENCE_FILES:
        raise RecoveryCoherenceError("Recovery verifier member profile differs from the supported 39 files")


def derive_recovery_coherent_tree(files):
    """Derive generated metadata from approved merged bytes, never from code execution.

    The raw stage may contain generated placeholders. Its authentic hashes and
    explicit conflict choices must be validated by the caller before derivation.
    No source file, Git state, preference, trust root or baseline is written here.
    """
    if type(files) is not dict or len(files) > 8192:
        raise RecoveryCoherenceError("Recovery derivation requires a bounded concrete source tree")
    if (any(type(name) is not str or type(raw) is not bytes or len(raw) > 16 * 1024**2
            for name, raw in files.items())
            or sum(len(raw) for raw in files.values()) > 256 * 1024**2):
        raise RecoveryCoherenceError("Recovery derivation source tree exceeds its byte/type bounds")
    required = (*RECOVERY_COHERENCE_FILES, RECOVERY_MANIFEST_PATH,
                RECOVERY_VERIFIER_PATH, RECOVERY_BATCH_PATH)
    if any(name not in files for name in required):
        raise RecoveryCoherenceError("Recovery derivation is missing a required known-profile member")
    validate_recovery_manifest_profile(files[RECOVERY_MANIFEST_PATH])
    entries = []
    for name in RECOVERY_COHERENCE_FILES:
        raw = _recovery_canonical(files[name])
        entries.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                        "git_blob_sha1": _recovery_blob(raw)})
    if sum(row["bytes"] for row in entries) > 32 * 1024**2:
        raise RecoveryCoherenceError("Recovery derivation exceeds the 32 MiB member limit")
    verifier = _recovery_canonical(files[RECOVERY_VERIFIER_PATH])
    _validate_recovery_verifier_profile(verifier)
    manifest = _recovery_encoded({"schema": 1, "repository": "Ag3nt47/AngeronaSuite",
        "canonical_text": "utf8-lf-no-bom", "files": entries})
    if len(manifest) > _RECOVERY_MANIFEST_LIMIT:
        raise RecoveryCoherenceError("Derived recovery manifest exceeds its fixed limit")
    pins = {b"manifestSha": hashlib.sha256(manifest).hexdigest().encode("ascii"),
            b"manifestBlob": _recovery_blob(manifest).encode("ascii"),
            b"verifierSha": hashlib.sha256(verifier).hexdigest().encode("ascii"),
            b"verifierBlob": _recovery_blob(verifier).encode("ascii")}
    batch = _rewrite_recovery_batch(files[RECOVERY_BATCH_PATH], pins)
    effective = dict(files)
    effective[RECOVERY_MANIFEST_PATH], effective[RECOVERY_BATCH_PATH] = manifest, batch
    if sum(len(raw) for raw in effective.values()) > 256 * 1024**2:
        raise RecoveryCoherenceError("Derived effective source tree exceeds its byte limit")
    proof = {"schema": 1, "profile": "angerona-operational39/v1",
        "generated_files": {name: {"sha256": hashlib.sha256(effective[name]).hexdigest(),
                                   "bytes": len(effective[name])}
                            for name in (RECOVERY_MANIFEST_PATH, RECOVERY_BATCH_PATH)},
        "derived_paths": [name for name in (RECOVERY_MANIFEST_PATH, RECOVERY_BATCH_PATH)
                          if files[name] != effective[name]],
        "manifest_sha256": pins[b"manifestSha"].decode("ascii"),
        "manifest_blob_sha1": pins[b"manifestBlob"].decode("ascii"),
        "verifier_sha256": pins[b"verifierSha"].decode("ascii"),
        "verifier_blob_sha1": pins[b"verifierBlob"].decode("ascii"),
        "candidate_code_executed": False}
    return effective, proof


def verify_recovery_coherence(files):
    """Require actual installed bytes to equal the deterministic generated pair."""
    effective, proof = derive_recovery_coherent_tree(files)
    if any(files[name] != effective[name] for name in (RECOVERY_MANIFEST_PATH, RECOVERY_BATCH_PATH)):
        raise RecoveryCoherenceError("Recovery manifest or batch pins differ from the effective source tree")
    return proof
