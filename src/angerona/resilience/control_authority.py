"""control_authority.py — administrator-gated, replay-resistant STOP/RESUME.

Threat closed: in an unelevated source run the legacy stand-down HMAC key lives
in the user's data directory, so any same-user process could forge a persistent
operator STOP, or replay an old one, and halt every respawn while looking like
an authorized stand-down.

Once provisioned (an elevated, one-time step):
    * STOP and RESUME are Ed25519-signed by a private key readable only by
      Administrators and SYSTEM. The unelevated core holds only the public key,
      so it can verify commands but never mint them.
    * Commands live in ``<ProgramData>\\Angerona\\control`` which only
      Administrators/SYSTEM can write (Users: read). Malware running as the user
      cannot plant, replay or delete them; issuing one needs a visible UAC
      consent (``request_elevated``).
    * Every command is bound to the current signed epoch. RESUME advances the
      epoch, so a captured STOP from an earlier epoch never verifies again.
    * The legacy user-directory HMAC stand-down is refused (see
      ``shutdown_token``), so it cannot be used to bypass this gate.
    * If the authority is present but unverifiable (missing epoch, bad public
      key, user-writable directory) no STOP is honoured and ``status()``
      reports ``compromised``: tampering can never be converted into a STOP.

The ProgramData location comes from the Windows known-folder API, never from
the ``ProgramData`` environment variable (HKCU-writable).
"""
from __future__ import annotations

import ctypes
import json
import math
import os
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SCHEMA = 1
_KINDS = ("operator-stop", "maintenance")
_MAX_FILE = 4096
_MAX_MAINTENANCE_S = 3600.0
_FUTURE_SKEW_S = 30.0
EXIT_OK, EXIT_NOT_ADMIN, EXIT_UNPROVISIONED, EXIT_FAILED = 0, 5, 6, 1


class AdminApprovalRequired(RuntimeError):
    """STOP/RESUME needs administrator approval that was not granted."""


def _known_program_data() -> Path:
    if os.name != "nt":
        return Path("/etc")
    # FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
    class GUID(ctypes.Structure):
        _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16),
                    ("d", ctypes.c_ubyte * 8)]
    folder = GUID(0x62AB5D82, 0xFDC1, 0x4DC3, (ctypes.c_ubyte * 8)(0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97))
    out = ctypes.c_wchar_p()
    shell32, ole32 = ctypes.windll.shell32, ctypes.windll.ole32
    if shell32.SHGetKnownFolderPath(ctypes.byref(folder), 0, None, ctypes.byref(out)) != 0:
        raise OSError("ProgramData known folder is unavailable")
    try:
        return Path(out.value)
    finally:
        ole32.CoTaskMemFree(out)


def control_dir(root: Optional[Path] = None) -> Path:
    if root is not None:
        return Path(root)
    base = _known_program_data()
    return base / ("Angerona" if os.name == "nt" else "angerona") / "control"


@dataclass(frozen=True)
class Paths:
    root: Path

    @property
    def public(self) -> Path:
        return self.root / "stop-authority.pub"

    @property
    def private(self) -> Path:
        return self.root / "stop-authority.key"

    @property
    def epoch(self) -> Path:
        return self.root / "epoch.json"

    @property
    def command(self) -> Path:
        return self.root / "stop.cmd"


def _paths(root: Optional[Path]) -> Paths:
    return Paths(control_dir(root))


def _authority_residues(paths: Paths) -> tuple[Path, ...]:
    return (paths.public, paths.private, paths.epoch, paths.command,
            paths.root / "deadman.json", paths.public.with_name(paths.public.name + ".tmp"))


def provisioned(root: Optional[Path] = None) -> bool:
    try:
        paths = _paths(root)
        for leaf in _authority_residues(paths):
            try:
                leaf.lstat()  # A dangling/inaccessible residue is not absence.
                return True
            except FileNotFoundError:
                pass
        if root is None:
            _verified_production_paths(paths, require_root=False)
        return False
    except Exception:
        return root is None  # Unknown production custody cannot reopen legacy STOP.


# ── crypto helpers ───────────────────────────────────────────────────────────
def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _public_key(paths: Paths):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    raw = bytes.fromhex(paths.public.read_text(encoding="ascii").strip())
    if len(raw) != 32:
        raise ValueError("stop authority public key is malformed")
    return Ed25519PublicKey.from_public_bytes(raw)


def _private_key(paths: Paths):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(paths.private.read_bytes(), password=None)


def _read_signed(path: Path, public) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_FILE + 1)
    if len(raw) > _MAX_FILE:
        raise ValueError("signed control file exceeds its bound")
    document = json.loads(raw)
    signature = bytes.fromhex(str(document.pop("sig")))
    public.verify(signature, _canonical(document))
    if document.get("schema") != SCHEMA:
        raise ValueError("unsupported control schema")
    return document


def _write_signed(path: Path, body: dict, private, *, enforce_acl: bool = False) -> dict:
    document = dict(body, schema=SCHEMA)
    document["sig"] = private.sign(_canonical(document)).hex()
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    _create_authority_file(temporary, raw, enforce_acl=enforce_acl, public_read=True)
    os.replace(temporary, path)
    return document


# ── ACL posture ──────────────────────────────────────────────────────────────
_WRITE_MASK = 0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000
_SECRET_READ_MASK = 0x0001 | 0x80000000 | 0x10000000
_ANCESTOR_REPLACE_MASK = 0x0040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000
_TRUSTED_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}


def user_writable(path: Path, *, _mask: int = _WRITE_MASK) -> Optional[bool]:
    """True if any non-admin principal may write ``path``; None if unknown."""
    if os.name != "nt":
        try:
            st = path.stat()
            return st.st_uid != 0 or bool(st.st_mode & (0o077 if _mask == _SECRET_READ_MASK else 0o022))
        except OSError:
            return None
    try:
        import win32security  # type: ignore
    except ImportError:
        return None
    try:
        descriptor = win32security.GetNamedSecurityInfo(
            str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
        owner = descriptor.GetSecurityDescriptorOwner()
        if owner is None or win32security.ConvertSidToStringSid(owner) not in _TRUSTED_SIDS:
            return True  # Owners retain WRITE_DAC even when the DACL looks restricted.
        dacl = descriptor.GetSecurityDescriptorDacl()
        if dacl is None:
            return True  # NULL DACL grants everyone full access.
        for index in range(dacl.GetAceCount()):
            (ace_type, _flags), mask, sid = dacl.GetAce(index)[:3]
            if _flags & 0x08:  # INHERIT_ONLY does not grant rights on this object.
                continue
            if ace_type == 1:  # Denials cannot add authority; allowed rights stay conservative.
                continue
            if ace_type != 0:
                return None  # Object/callback/unknown ACE evaluation is unavailable.
            if mask & _mask and win32security.ConvertSidToStringSid(sid) not in _TRUSTED_SIDS:
                return True
        return False
    except Exception:
        return None


def _plain_authority_path(path: Path) -> bool:
    """Inspect the lexical name; never resolve an attacker-selected reparse point."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("control authority contains a redirected path")
    if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError("control authority requires plain single-link files")
    return True


def _verified_production_paths(paths: Paths, *, require_root: bool = True) -> None:
    base = _known_program_data().absolute()
    expected = base / ("Angerona" if os.name == "nt" else "angerona") / "control"
    if paths.root.absolute() != expected:
        raise ValueError("control authority is outside the fixed known-folder namespace")
    for ancestor in reversed((base, *base.parents)):
        if not _plain_authority_path(ancestor) or user_writable(
                ancestor, _mask=_ANCESTOR_REPLACE_MASK) is not False:
            raise ValueError("control authority namespace owner or replacement rights are unsafe or unknown")
    for current in (expected.parent, expected):
        exists = _plain_authority_path(current)
        if not exists:
            if require_root:
                raise ValueError("control authority directory is missing")
            continue
        if not current.is_dir() or user_writable(current) is not False:
            raise ValueError("control authority directory owner or ACL is unsafe or unknown")


def _windows_authority_attributes(*, directory: bool, public_read: bool):
    import pywintypes
    import win32security
    inheritance = "OICI" if directory else ""
    users = "(A;;0x1200a9;;;BU)" if directory else "(A;;FR;;;BU)" if public_read else ""
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "O:BAG:BAD:P" + f"(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)" + users,
        win32security.SDDL_REVISION_1)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def _prepare_production_directory(paths: Paths) -> None:
    _verified_production_paths(paths, require_root=False)
    for directory in (paths.root.parent, paths.root):
        if not _plain_authority_path(directory):
            if os.name == "nt":
                import win32file
                win32file.CreateDirectory(str(directory), _windows_authority_attributes(
                    directory=True, public_read=True))
            else:
                directory.mkdir(mode=0o755)
        _verified_production_paths(paths, require_root=False)
    _verified_production_paths(paths)


def _create_authority_file(path: Path, raw: bytes, *, enforce_acl: bool, public_read: bool) -> None:
    if enforce_acl and os.name == "nt":
        import win32con
        import win32file
        handle = win32file.CreateFile(str(path), win32con.GENERIC_WRITE, 0,
            _windows_authority_attributes(directory=False, public_read=public_read),
            win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL | win32con.FILE_FLAG_OPEN_REPARSE_POINT, None)
        try:
            _error, written = win32file.WriteFile(handle, raw)
            if _error != 0 or written != len(raw):
                raise OSError("control authority write was incomplete")
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        return
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                 0o644 if public_read else 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _verified_issuer(paths: Paths, *, enforce: bool) -> None:
    if enforce:
        _verified_production_paths(paths)
        for leaf in (paths.private, paths.public, paths.epoch):
            if not _plain_authority_path(leaf) or user_writable(leaf) is not False:
                raise ValueError("control authority signing-file owner or ACL is unsafe or unknown")
        if user_writable(paths.private, _mask=_SECRET_READ_MASK) is not False:
            raise ValueError("control authority private key read access is unsafe or unknown")


# ── verification (unelevated core) ───────────────────────────────────────────
def status(root: Optional[Path] = None) -> dict:
    """Describe authority posture. Never raises."""
    try:
        paths = _paths(root)
        if not provisioned(root):
            return {"state": "unprovisioned", "stop_active": False}
    except Exception as exc:
        return {"state": "compromised", "stop_active": False, "error": type(exc).__name__}
    try:
        # Callers cannot redirect the production root (no environment input);
        # explicit roots are test fixtures and skip the host ACL judgement.
        if root is None:
            _verified_production_paths(paths)
        checked = (paths.root, paths.public, paths.epoch) + ((paths.command,) if paths.command.exists() else ())
        acl = ([user_writable(p) if _plain_authority_path(p) else None for p in checked]
               if root is None else [False])
        if any(value is not False for value in acl):
            raise ValueError("control authority ownership or ACL could not be verified")
        public = _public_key(paths)
        epoch = _read_signed(paths.epoch, public)
        if epoch.get("kind") != "epoch" or not isinstance(epoch.get("epoch"), int):
            raise ValueError("epoch record is malformed")
        stop = _active_stop(paths, public, epoch["epoch"])
        return {"state": "protected", "acl_verified": all(v is False for v in acl), "epoch": epoch["epoch"],
                "stop_active": stop is not None, "stop": stop}
    except Exception as exc:
        return {"state": "compromised", "stop_active": False, "error": type(exc).__name__,
                "detail": str(exc)[:200]}


def _active_stop(paths: Paths, public, epoch: int) -> Optional[dict]:
    if not paths.command.exists():
        return None
    command = _read_signed(paths.command, public)
    now = time.time()
    ts = float(command.get("ts", 0))
    if command.get("kind") not in _KINDS or command.get("epoch") != epoch or ts - now > _FUTURE_SKEW_S:
        return None
    if command["kind"] == "maintenance":
        expires = float(command.get("expires", 0))
        if not (now < expires <= ts + _MAX_MAINTENANCE_S):
            return None
    return {k: command[k] for k in ("kind", "nonce", "ts", "reason", "epoch") if k in command}


def stop_active(root: Optional[Path] = None) -> bool:
    return bool(status(root).get("stop_active"))


# ── issuing (elevated helper only) ───────────────────────────────────────────
def is_admin() -> bool:
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _icacls(*arguments: str) -> None:
    buffer = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260):
        raise OSError("system directory is unavailable")
    subprocess.run([str(Path(buffer.value) / "icacls.exe"), *arguments], check=True,
                   capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _restrict(paths: Paths) -> None:
    """Admins/SYSTEM inherit full control; Users may only list the directory.

    No inheritable Users ACE exists, so a newly created private key is never
    readable by Users, even transiently. Public files get explicit read grants.
    """
    if os.name != "nt":
        os.chmod(paths.root, 0o755)
        if paths.private.exists():
            os.chmod(paths.private, 0o600)
        return
    _icacls(str(paths.root), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(RX)")


def _grant_read(path: Path) -> None:
    if os.name == "nt":
        _icacls(str(path), "/grant", "*S-1-5-32-545:R")
    else:
        os.chmod(path, 0o644)


def provision(root: Optional[Path] = None, *, require_admin: bool = True) -> dict:
    """Create the key pair and epoch 1. Never rotates an existing authority."""
    if require_admin and not is_admin():
        raise AdminApprovalRequired("provisioning requires an elevated administrator")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    paths = _paths(root)
    enforce = root is None  # ACLs apply to the real ProgramData authority only.
    if enforce:
        _prepare_production_directory(paths)
    else:
        paths.root.mkdir(parents=True, exist_ok=True)
    for existing in _authority_residues(paths):
        try:
            existing.lstat()
        except FileNotFoundError:
            continue
        raise FileExistsError("stop authority or interrupted authority files already exist; they are never rotated silently")
    # Lock the directory before the private key exists: ProgramData's inherited
    # ACL grants Users read, which must never cover the key even briefly.
    if enforce:
        _restrict(paths)
        _verified_production_paths(paths)
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    _create_authority_file(paths.private, pem, enforce_acl=enforce, public_read=False)
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _write_signed(paths.epoch, {"kind": "epoch", "epoch": 1, "ts": time.time()}, private,
                  enforce_acl=enforce)
    # The public key is written last: its presence is what marks "provisioned".
    temporary = paths.public.with_name(paths.public.name + ".tmp")
    _create_authority_file(temporary, public_raw.hex().encode("ascii"),
                           enforce_acl=enforce, public_read=True)
    os.replace(temporary, paths.public)
    return status(root)


def issue(kind: str, reason: str, *, root: Optional[Path] = None, minutes: float = 0,
          require_admin: bool = True) -> dict:
    if require_admin and not is_admin():
        raise AdminApprovalRequired("STOP requires an elevated administrator")
    if kind not in _KINDS:
        raise ValueError("unknown control command kind")
    reason = str(reason).strip()
    if not reason or len(reason) > 256 or any(ord(c) < 32 for c in reason):
        raise ValueError("reason must be 1-256 printable characters")
    paths = _paths(root)
    _verified_issuer(paths, enforce=root is None)
    private, public = _private_key(paths), _public_key(paths)
    epoch = _read_signed(paths.epoch, public)["epoch"]
    now = time.time()
    body = {"kind": kind, "nonce": secrets.token_hex(16), "ts": now, "reason": reason, "epoch": epoch}
    if kind == "maintenance":
        seconds = float(minutes) * 60.0
        if not 0 < seconds <= _MAX_MAINTENANCE_S:
            raise ValueError("maintenance stand-down must be 1-60 minutes")
        body["expires"] = now + seconds
    return _write_signed(paths.command, body, private, enforce_acl=root is None)


def resume(*, root: Optional[Path] = None, require_admin: bool = True) -> dict:
    """Retire any STOP and advance the epoch so captured commands never replay."""
    if require_admin and not is_admin():
        raise AdminApprovalRequired("RESUME requires an elevated administrator")
    paths = _paths(root)
    _verified_issuer(paths, enforce=root is None)
    private, public = _private_key(paths), _public_key(paths)
    current = _read_signed(paths.epoch, public)["epoch"]
    _write_signed(paths.epoch, {"kind": "epoch", "epoch": current + 1, "ts": time.time()}, private,
                  enforce_acl=root is None)
    try:
        paths.command.unlink()
    except FileNotFoundError:
        pass
    return status(root)


# ── dead-man isolation opt-in (administrator-signed, off by default) ─────────
DEADMAN_MIN_S, DEADMAN_MAX_S = 120.0, 3600.0


def set_deadman(enabled: bool, threshold_s: float = 300.0, *, root: Optional[Path] = None,
                require_admin: bool = True) -> dict:
    """Sign the dead-man policy. Absent or unverifiable policy means disabled."""
    if require_admin and not is_admin():
        raise AdminApprovalRequired("dead-man policy requires an elevated administrator")
    threshold = float(threshold_s)
    if not DEADMAN_MIN_S <= threshold <= DEADMAN_MAX_S:
        raise ValueError("dead-man threshold must be 120-3600 seconds")
    paths = _paths(root)
    _verified_issuer(paths, enforce=root is None)
    return _write_signed(paths.root / "deadman.json",
                         {"kind": "deadman", "enabled": bool(enabled), "threshold_s": threshold,
                          "ts": time.time()}, _private_key(paths), enforce_acl=root is None)


def deadman_policy(root: Optional[Path] = None) -> Optional[dict]:
    """Return the verified enabled policy, else None. Never raises."""
    try:
        if status(root).get("state") != "protected":
            return None
        paths = _paths(root)
        policy = _read_signed(paths.root / "deadman.json", _public_key(paths))
        threshold = float(policy.get("threshold_s", 0))
        if (policy.get("kind") != "deadman" or policy.get("enabled") is not True
                or not DEADMAN_MIN_S <= threshold <= DEADMAN_MAX_S):
            return None
        return {"enabled": True, "threshold_s": threshold}
    except Exception:
        return None


# ── UAC bridge (called from the unelevated core/GUI) ─────────────────────────
def _helper_command(action: str) -> tuple[str, str]:
    if not getattr(sys, "frozen", False):
        raise AdminApprovalRequired("Administrator control requires the verified installed Windows package; source Python cannot be elevated by this control.")
    from angerona.core.windows_package_identity import (
        require_current_package_image, verify_current_msix_authority,
    )
    authority = verify_current_msix_authority()
    if not authority.trusted:
        raise AdminApprovalRequired(authority.reason)
    try:
        executable = require_current_package_image("Angerona.exe")
    except Exception as exc:
        raise AdminApprovalRequired("The installed control image could not be verified.") from exc
    if not executable.is_absolute() or executable.name.casefold() != "angerona.exe":
        raise AdminApprovalRequired("The installed control image is not the required Angerona console.")
    return str(executable), subprocess.list2cmdline(["--control-authority", action])


def request_elevated(action: str, timeout_s: float = 300.0) -> int:
    """Run the helper elevated via a visible UAC prompt and wait for it.

    Raises AdminApprovalRequired when consent is declined or not available.
    """
    if action not in {"stop", "resume", "status", "provision"}:
        raise ValueError("unsupported control action")
    if os.name != "nt":
        raise AdminApprovalRequired("run the control helper with sudo on this platform")
    if not math.isfinite(timeout_s) or not 0 < timeout_s <= 3600:
        raise ValueError("control helper timeout must be finite and within one hour")
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    executable, parameters = _helper_command(action)
    from angerona.core.privilege import sanitize_privileged_bootstrap_environment
    sanitize_privileged_bootstrap_environment()
    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW), fMask=0x00000040 | 0x00000400,
                             lpVerb="runas", lpFile=executable, lpParameters=parameters,
                             lpDirectory=str(Path(executable).parent), nShow=0)
    shell32, kernel32 = ctypes.windll.shell32, ctypes.windll.kernel32
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    # Process handles are pointer-sized; an untyped ctypes call can truncate
    # them. A failed exit query must never become the initialized success 0.
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        raise AdminApprovalRequired("administrator approval was declined")
    try:
        if kernel32.WaitForSingleObject(info.hProcess, int(timeout_s * 1000)) != 0:
            raise AdminApprovalRequired("the elevated control helper did not finish")
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
            raise AdminApprovalRequired("the elevated control helper exit could not be verified")
    finally:
        closed = kernel32.CloseHandle(info.hProcess)
    if not closed:
        raise AdminApprovalRequired("the elevated control helper handle could not be retired")
    return int(code.value)


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    action = args[0] if args else "status"
    try:
        if action == "status":
            print(json.dumps(status(), default=str))
            return EXIT_OK
        if not is_admin():
            return EXIT_NOT_ADMIN
        if action == "provision":
            provision()
        elif not provisioned():
            return EXIT_UNPROVISIONED
        elif action == "stop":
            issue("operator-stop", "dashboard STOP (administrator approved)")
        elif action == "resume":
            resume()
        elif action == "deadman-enable":
            set_deadman(True, float(args[1]) if len(args) > 1 else 300.0)
        elif action == "deadman-disable":
            set_deadman(False)
        else:
            return EXIT_FAILED
        return EXIT_OK
    except Exception:
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
