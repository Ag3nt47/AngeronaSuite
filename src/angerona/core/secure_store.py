"""OS-protected storage for Angerona credentials.

The UI needs a small persistent key/value store for optional provider tokens,
mail credentials, and connector secrets.  Keeping those values in a project
``.env`` file made them readable to every account that inherited access to the
checkout. Windows stores one current-user DPAPI blob under Angerona's
canonical runtime-data directory and applies a private ACL as a second layer. macOS stores
the same logical map as one current-user Keychain item.

Windows uses a current-user DPAPI blob with a private ACL. macOS uses one
generic-password item in the current user's Keychain through Security.framework.
Linux uses the current desktop session's Secret Service through libsecret's
``secret-tool`` without ever putting the secret on a command line.
Legacy ``.env`` files are migrated only after a protected write/read verification
succeeds; the plaintext source is then removed. Unsupported platforms fail closed
instead of silently creating another plaintext credential file.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Mapping

from angerona.core.file_lease import ExclusiveFileLease

_ENTROPY = b"Angerona-SecretStore-v1"
_FILENAME = "secrets.dpapi"
_MACOS_REFERENCE_FILENAME = "secrets.keychain-reference"
_MACOS_KEYCHAIN_SERVICE = "org.angerona.security-suite"
_MACOS_KEYCHAIN_ACCOUNT = "runtime-secrets-v1"
_LINUX_REFERENCE_FILENAME = "secrets.secret-service-reference"
_LINUX_SECRET_SERVICE = "org.angerona.security-suite"
_LINUX_SECRET_ACCOUNT = "runtime-secrets-v1"
_NON_ENVIRONMENT_SECRETS = frozenset({
    "SPYWAREGUARD_ARCHIVE_KEY",
    "ANGERONA_USB_PIN",
    # This token authorizes a loopback control plane in an elevated process.
    # Consumers must read it directly from the OS-protected store so a launcher,
    # parent process, or stale shell can never inject control authority.
    "ANGERONA_JARVIS_CONTROL_TOKEN",
    # Never republish a protected Remote Bridge key into child environments.
    # Explicit strong-key configuration remains available where launch permits.
    "ANGERONA_BRIDGE_KEY",
    # Local IPC proof material is authority and must never be inherited by a
    # child process or left as a plaintext sidecar.
    "ANGERONA_IPC_AUTH_KEY",
    # Recovery drill encryption/audit keys are read only by the backup drill;
    # they must never become ambient child-process authority.
    "ANGERONA_RECOVERY_DRILL_ENCRYPTION_KEY",
    "ANGERONA_RECOVERY_DRILL_AUDIT_KEY",
    "ANGERONA_UGCAP_WITNESS_PRIVATE_KEY",
})
_MAX_LEGACY_ENV_BYTES = 1024 * 1024
_TRANSACTION_WAIT_SECONDS = 1.0
_TRANSACTION_LOCK = threading.RLock()
_TRANSACTION_LOCAL = threading.local()
_ACTIVE_LEASE = None


class _CredentialLease(ExclusiveFileLease):
    """An inherited child closes its reference without unlocking its parent."""

    def __init__(self, path: Path) -> None:
        self._owner_pid = os.getpid()
        super().__init__(path)

    def close(self) -> None:
        if self._owner_pid == os.getpid():
            super().close()
        elif not self._closed:
            descriptor = self._descriptor
            self._descriptor, self._closed = -1, True
            # flock locks belong to the inherited open-file description. An
            # explicit LOCK_UN here would release the live parent's lease.
            os.close(descriptor)


def _reset_transaction_after_fork() -> None:
    global _TRANSACTION_LOCK, _TRANSACTION_LOCAL, _ACTIVE_LEASE
    try:
        if _ACTIVE_LEASE is not None:
            _ACTIVE_LEASE.close()
    finally:
        _ACTIVE_LEASE = None
        _TRANSACTION_LOCK = threading.RLock()
        _TRANSACTION_LOCAL = threading.local()


def _before_fork() -> None:
    # A fork in another thread must not miss a lease being opened/closed.
    _TRANSACTION_LOCK.acquire()


def _after_fork_parent() -> None:
    _TRANSACTION_LOCK.release()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_parent,
                        after_in_child=_reset_transaction_after_fork)


def _remove_environment_secrets(keys) -> None:
    """Ensure protected values never become process-global child inheritance."""
    for key in keys:
        if isinstance(key, str) and key:
            os.environ.pop(key, None)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _path_traverses_reparse(path: Path) -> bool:
    """Inspect every existing component without resolving through it."""
    current = Path(os.path.abspath(path))
    while True:
        if os.path.lexists(current) and _is_link_or_reparse(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _legacy_source_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    """Return a stable identity only for a small, ordinary plaintext file."""
    if _path_traverses_reparse(path):
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size > _MAX_LEGACY_ENV_BYTES
        or getattr(info, "st_nlink", 1) != 1
    ):
        return None
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def secure_store_path(data_root: Path | None = None) -> Path:
    if data_root is None:
        from angerona.core.data_paths import data_dir
        data_root = data_dir()
    if sys.platform == "darwin":
        filename = _MACOS_REFERENCE_FILENAME
    elif sys.platform.startswith("linux"):
        filename = _LINUX_REFERENCE_FILENAME
    else:
        filename = _FILENAME
    return Path(data_root) / filename


def _backing_store_identity(data_root: Path | None) -> tuple[str, ...]:
    if sys.platform == "darwin":
        return ("keychain", _MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ACCOUNT)
    if sys.platform.startswith("linux"):
        return ("secret-service", _LINUX_SECRET_SERVICE, _LINUX_SECRET_ACCOUNT)
    path = secure_store_path(data_root)
    if _path_traverses_reparse(path):
        raise PermissionError("Credential transaction path traverses an alias")
    return ("dpapi", os.path.normcase(os.path.realpath(path)))


def _account_lock_directory() -> Path:
    """Use the OS account home, never HOME/XDG or a caller's data root."""
    import pwd

    user_id = os.geteuid()
    home = Path(pwd.getpwuid(user_id).pw_dir)
    if not home.is_absolute() or _path_traverses_reparse(home):
        raise PermissionError("Credential account home is not a plain absolute directory")
    _private_posix_directory_chain(home, user_id)
    home_info = home.stat()
    if not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != user_id:
        raise PermissionError("Credential account home is owned by another user")
    directory = home / ".angerona-credential-locks"
    if _path_traverses_reparse(directory):
        raise PermissionError("Credential lock directory traverses an alias")
    directory.mkdir(mode=0o700, exist_ok=True)
    _private_posix_directory_chain(directory, user_id)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != user_id
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise PermissionError("Credential lock directory is not private to this user")
    return directory


def _private_posix_directory_chain(path: Path, user_id: int) -> None:
    """Reject a namespace another account can rename or replace."""
    for current in (path, *path.parents):
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, user_id}
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise PermissionError("Credential lock ancestry permits another account to replace it")


def _transaction_path(identity: tuple[str, ...]) -> Path:
    if identity[0] == "dpapi":
        path = Path(identity[1]).with_name(_FILENAME + ".lock")
        if _path_traverses_reparse(path):
            raise PermissionError("Credential lock path traverses an alias")
        path.parent.mkdir(parents=True, exist_ok=True)
        from angerona.core.hardening import ensure_sensitive_parent, key_acl_required

        ensure_sensitive_parent(path, required=key_acl_required())
        return path
    digest = hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()
    return _account_lock_directory() / (digest + ".lock")


def _assert_transaction(data_root: Path | None) -> None:
    current = getattr(_TRANSACTION_LOCAL, "record", None)
    if current != (os.getpid(), _backing_store_identity(data_root)):
        raise RuntimeError("Credential transaction is absent or belongs to another process/store")


@contextmanager
def secret_transaction(data_root: Path | None = None):
    """Serialize one backing store's read/create/write/verify operation.

    Threads wait at most one second for the local transaction. A competing process fails
    visibly through ExclusiveFileLease rather than serving a divergent key.
    Keychain and Secret Service share one account item across data roots, so
    their OS lease is account/service scoped. Cooperating writers must use this
    API; it does not constrain hostile code in the same trust boundary.
    """
    global _ACTIVE_LEASE
    identity = _backing_store_identity(data_root)
    owner_pid, lock = os.getpid(), _TRANSACTION_LOCK
    if not lock.acquire(timeout=_TRANSACTION_WAIT_SECONDS):
        raise TimeoutError("Credential store transaction is busy; credentials were not changed")
    try:
        current = getattr(_TRANSACTION_LOCAL, "record", None)
        if current is not None:
            if current != (owner_pid, identity):
                raise RuntimeError("Nested credential transactions must name the same backing store")
            yield
            _assert_transaction(data_root)
            return
        lease = _CredentialLease(_transaction_path(identity))
        _ACTIVE_LEASE = lease
        _TRANSACTION_LOCAL.record = (owner_pid, identity)
        try:
            yield
            _assert_transaction(data_root)
        finally:
            try:
                lease.close()
            finally:
                if owner_pid == os.getpid():
                    del _TRANSACTION_LOCAL.record
                    _ACTIVE_LEASE = None
    finally:
        # A forked child received a fresh lock/local state in the at-fork hook.
        # Never treat its inherited context as a current transaction.
        if owner_pid == os.getpid():
            lock.release()


def get_or_create_secret(
    name: str, factory: Callable[[], str], data_root: Path | None = None,
) -> str:
    """Return the existing value, or create and verify it exactly once.

    Existing empty/malformed values are returned for the consumer to reject;
    they never authorize automatic replacement of persistent key material.
    """
    if (not isinstance(name, str) or not name or len(name) > 256
            or any(ord(character) < 33 or ord(character) == 127 for character in name)
            or not callable(factory)):
        raise ValueError("Protected secret creation request is invalid")
    _remove_environment_secrets((*_NON_ENVIRONMENT_SECRETS, name))
    with secret_transaction(data_root):
        existing = read_secret_values((name,), data_root, strict=True)
        _assert_transaction(data_root)
        if name in existing:
            return existing[name]
        created = factory()
        _assert_transaction(data_root)
        if not isinstance(created, str) or not created:
            raise ValueError("Protected secret factory must return a nonempty string")
        write_secret_map({name: created}, data_root)
        confirmed = read_secret_values((name,), data_root, strict=True).get(name)
        _assert_transaction(data_root)
        if confirmed != created:
            raise RuntimeError("Protected secret creation did not survive readback")
        return created


def _protect_bytes(data: bytes) -> bytes | None:
    from angerona.modules.hardware_crypto import protect
    return protect(data, _ENTROPY)


def _unprotect_bytes(blob: bytes) -> bytes | None:
    from angerona.modules.hardware_crypto import unprotect
    return unprotect(blob, _ENTROPY)


def _private_acl_matches(descriptor, owner: str, trustees: frozenset[str], security) -> bool:
    """Prove the entire current DACL, rather than caching an earlier decision."""
    try:
        if security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) != owner:
            return False
        if not descriptor.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED:
            return False
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None or acl.GetAceCount() != len(trustees):
            return False
        seen = set()
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            if (len(ace) != 3 or ace[0] != (security.ACCESS_ALLOWED_ACE_TYPE, 0)
                    or ace[1] != 0x001F01FF):  # FILE_ALL_ACCESS, no inheritance flags.
                return False
            principal = security.ConvertSidToStringSid(ace[2])
            if principal not in trustees or principal in seen:
                return False
            seen.add(principal)
        return seen == trustees
    except (AttributeError, OSError, TypeError, ValueError):
        return False


class _NativeACLUnavailable(ImportError):
    """Only import-time absence can select the legacy Windows fallback."""


def _native_private_acl(path: Path) -> None:
    """Apply and freshly verify private Windows custody on one retained inode.

    Only a missing optional Windows API dependency permits the legacy fallback.
    Available native APIs rejecting an unsafe path or failed proof must never
    fall through to a less constrained path-based mutation.
    """
    try:
        import win32api
        import win32con
        import win32file
        import win32security
    except ImportError as exc:
        raise _NativeACLUnavailable("Optional native Windows ACL APIs are unavailable") from exc

    if _path_traverses_reparse(path):
        raise PermissionError("Private credential ACL path traverses a reparse point")
    handle = win32file.CreateFile(
        str(path), win32con.READ_CONTROL | win32con.WRITE_DAC,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
        win32con.OPEN_EXISTING,
        0x00200000, None,  # FILE_FLAG_OPEN_REPARSE_POINT (absent in some pywin32 builds).
    )
    try:
        before = win32file.GetFileInformationByHandle(handle)
        if before[0] & (0x10 | 0x400) or before[7] != 1:
            raise PermissionError("Private credential ACL needs an ordinary single-link file")
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        finally:
            token.Close()
        trustees = frozenset({win32security.ConvertSidToStringSid(user),
                              "S-1-5-18", "S-1-5-32-544"})
        fields = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        descriptor = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT, fields)
        owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        if owner not in trustees:
            raise PermissionError("Private credential owner is outside the current trust boundary")
        if not _private_acl_matches(descriptor, owner, trustees, win32security):
            acl = win32security.ACL()
            for principal in sorted(trustees):
                acl.AddAccessAllowedAce(
                    win32security.ACL_REVISION, 0x001F01FF,
                    win32security.ConvertStringSidToSid(principal),
                )
            win32security.SetSecurityInfo(
                handle, win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, acl, None,
            )
            descriptor = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT, fields)
        after = win32file.GetFileInformationByHandle(handle)
        if (after[0] & (0x10 | 0x400) or after[7] != 1
                or (before[4], before[8], before[9]) != (after[4], after[8], after[9])
                or _path_traverses_reparse(path)
                or not _private_acl_matches(descriptor, owner, trustees, win32security)):
            raise PermissionError("Private credential ACL readback or identity verification failed")
        # Reopen only for final leaf identity proof. Ancestor checks above are
        # snapshots, not atomic custody of the complete parent directory tree.
        current = win32file.CreateFile(
            str(path), win32con.READ_CONTROL,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
            win32con.OPEN_EXISTING, 0x00200000, None,
        )
        try:
            observed = win32file.GetFileInformationByHandle(current)
            if (observed[0] & (0x10 | 0x400) or observed[7] != 1
                    or (before[4], before[8], before[9])
                    != (observed[4], observed[8], observed[9])):
                raise PermissionError("Private credential path changed during ACL verification")
        finally:
            current.Close()
    finally:
        handle.Close()


def _private_acl(path: Path) -> None:
    """Best-effort owner/SYSTEM/admin-only ACL; DPAPI remains the hard boundary."""
    if not sys.platform.startswith("win"):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return
    try:
        _native_private_acl(Path(path))
        return
    except _NativeACLUnavailable:
        # The optional Windows extra may be absent in a source checkout.
        pass
    except Exception:
        # Preserve the best-effort API, without retrying a failed security proof
        # through the old path-based command. DPAPI remains mandatory upstream.
        return
    try:
        info = Path(path).lstat()
        if (_path_traverses_reparse(path) or not stat.S_ISREG(info.st_mode)
                or getattr(info, "st_nlink", 1) != 1):
            return
        user = os.environ.get("USERNAME", "").strip()
        domain = os.environ.get("USERDOMAIN", "").strip()
        principal = f"{domain}\\{user}" if domain and user else user
        if not principal:
            return
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        icacls = (system_root / "System32" / "icacls.exe").resolve()
        if not icacls.is_file():
            return
        subprocess.run(
            [str(icacls), str(path), "/inheritance:r", "/grant:r",
             f"{principal}:(F)", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _read_macos_secret_map(*, strict: bool = False) -> dict[str, str]:
    try:
        from angerona.platforms.macos.keychain import read_blob
        raw = read_blob(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ACCOUNT)
        if raw is None:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError("Keychain secret map has an invalid shape")
        return dict(value)
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError) as exc:
        if strict:
            raise RuntimeError(
                "macOS Keychain secrets are unreadable; refusing to overwrite them"
            ) from exc
        return {}


def _read_linux_secret_map(*, strict: bool = False) -> dict[str, str]:
    try:
        from angerona.platforms.linux.secret_service import read_blob
        raw = read_blob(_LINUX_SECRET_SERVICE, _LINUX_SECRET_ACCOUNT)
        if raw is None:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError("Linux Secret Service map has an invalid shape")
        return dict(value)
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError) as exc:
        if strict:
            raise RuntimeError(
                "Linux Secret Service secrets are unreadable; refusing to overwrite them"
            ) from exc
        return {}


def read_secret_map(
    data_root: Path | None = None, *, strict: bool = False,
) -> dict[str, str]:
    if sys.platform == "darwin":
        return _read_macos_secret_map(strict=strict)
    if sys.platform.startswith("linux"):
        return _read_linux_secret_map(strict=strict)
    path = secure_store_path(data_root)
    if not path.exists():
        return {}
    try:
        raw = _unprotect_bytes(path.read_bytes())
        if raw is None:
            raise ValueError("protected credential payload could not be decrypted")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError("protected credential map has an invalid shape")
        return {
            key: item
            for key, item in value.items()
        }
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        if strict:
            raise RuntimeError(
                "Protected credentials are unreadable; refusing to overwrite them"
            ) from exc
        return {}


def read_secret_values(
    names,
    data_root: Path | None = None,
    *,
    strict: bool = False,
) -> dict[str, str]:
    """Return only explicitly named values from protected storage.

    The encrypted payload is one OS-protected map, but callers do not need to
    receive unrelated fleet, connector, or provider authority in their local
    scope. Requests are bounded and duplicate-free.
    """
    if isinstance(names, str):
        requested = (names,)
    else:
        requested = tuple(names)
    if not 1 <= len(requested) <= 64 or any(
        not isinstance(name, str)
        or not name
        or len(name) > 256
        or any(ord(character) < 33 or ord(character) == 127 for character in name)
        for name in requested
    ):
        raise ValueError("protected credential name request is invalid")
    if len(set(requested)) != len(requested):
        raise ValueError("protected credential name request contains duplicates")
    values = (
        read_secret_map(data_root, strict=True)
        if strict
        else read_secret_map(data_root)
    )
    return {name: values[name] for name in requested if name in values}


def write_secret_map(updates: Mapping[str, object], data_root: Path | None = None) -> Path:
    _remove_environment_secrets((*_NON_ENVIRONMENT_SECRETS, *updates))
    with secret_transaction(data_root):
        return _write_secret_map_locked(updates, data_root)


def _credential_file_state(path: Path, *, missing_ok: bool = False):
    """Snapshot one ordinary file without retaining a deny-delete reader."""
    if _path_traverses_reparse(path):
        raise PermissionError("Credential publication path traverses an alias")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                             | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        if missing_ok and not os.path.lexists(path):
            return None
        raise
    try:
        before = os.fstat(descriptor)

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                    info.st_mode, info.st_nlink,
                    int(getattr(info, "st_file_attributes", 0)))

        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or int(getattr(before, "st_file_attributes", 0)) & (0x400 | 0x1)):
            raise PermissionError("Credential publication needs a writable ordinary single-link file")
        digest = hashlib.sha256()
        remaining = before.st_size + 1
        count = 0
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                break
            digest.update(block)
            count += len(block)
            remaining -= len(block)
        after, current = os.fstat(descriptor), path.lstat()
        # Windows fstat ctime and path lstat ctime can represent different
        # native timestamps. Compare that field only across descriptor reads.
        if (count != before.st_size or identity(before) != identity(after)
                or before.st_ctime_ns != after.st_ctime_ns
                or identity(after) != identity(current) or _path_traverses_reparse(path)):
            raise PermissionError("Credential publication file changed during inspection")
        return identity(after), after.st_ctime_ns, digest.digest()
    finally:
        os.close(descriptor)


def _credential_security_state(
    path: Path, *, directory: bool = False, missing_ok: bool = False,
    allow_inherited_directory: bool = False,
):
    """Read private native custody without changing an owner, DACL or flags."""
    try:
        import win32api
        import win32con
        import win32file
        import win32security
    except ImportError as exc:
        raise _NativeACLUnavailable("Native retry custody proof is unavailable") from exc
    if _path_traverses_reparse(path):
        raise PermissionError("Credential retry security path traverses an alias")
    if missing_ok and not os.path.lexists(path):
        return None
    # Share delete explicitly: these short inspection handles must not cause
    # the very rename contention they are intended to diagnose.
    handle = win32file.CreateFile(
        str(path), win32con.READ_CONTROL,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None, win32con.OPEN_EXISTING, 0x00200000 | (0x02000000 if directory else 0), None,
    )
    try:
        before = win32file.GetFileInformationByHandle(handle)
        if (before[0] & 0x400 or bool(before[0] & 0x10) != directory
                or (not directory and (before[7] != 1 or before[0] & 0x1))):
            raise PermissionError("Credential retry security object is unsafe")
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        finally:
            token.Close()
        trustees = frozenset({win32security.ConvertSidToStringSid(user),
                              "S-1-5-18", "S-1-5-32-544"})
        fields = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        descriptor = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT, fields)
        owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        control = descriptor.GetSecurityDescriptorControl()[0]
        valid = owner in trustees
        if directory:
            acl = descriptor.GetSecurityDescriptorDacl()
            valid = (valid and (allow_inherited_directory
                                or bool(control & win32security.SE_DACL_PROTECTED))
                     and acl is not None and 0 < acl.GetAceCount() <= len(trustees))
            seen = set()
            if valid:
                for index in range(acl.GetAceCount()):
                    ace = acl.GetAce(index)
                    if (len(ace) != 3 or ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE
                            or ace[0][1] & ~(0x13 if allow_inherited_directory else 0x3)
                            or ace[1] != 0x001F01FF):
                        valid = False
                        break
                    principal = win32security.ConvertSidToStringSid(ace[2])
                    if principal not in trustees or principal in seen:
                        valid = False
                        break
                    seen.add(principal)
        else:
            valid = valid and _private_acl_matches(descriptor, owner, trustees, win32security)
        if not valid:
            raise PermissionError("Credential retry owner or DACL is outside private custody")
        after = win32file.GetFileInformationByHandle(handle)
        identity = lambda info: (info[0], info[4], info[7], info[8], info[9])
        if identity(before) != identity(after) or _path_traverses_reparse(path):
            raise PermissionError("Credential retry security identity changed")
        current = win32file.CreateFile(
            str(path), win32con.READ_CONTROL,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None, win32con.OPEN_EXISTING, 0x00200000 | (0x02000000 if directory else 0), None,
        )
        try:
            if identity(win32file.GetFileInformationByHandle(current)) != identity(before):
                raise PermissionError("Credential retry security pathname changed")
        finally:
            current.Close()
        return identity(before), bytes(descriptor), control
    finally:
        handle.Close()


def _credential_parent_security_state(parent: Path):
    """Bind a trusted-only inheritance route to its first protected directory.

    Every applying ACE must be an ordinary full-access grant to this account,
    SYSTEM or administrators. Read-only outsider grants are conservatively
    refused too. No directory permissions are changed by this bounded proof.
    """
    parent = Path(os.path.abspath(parent))
    chain = []
    for component in (parent, *parent.parents)[:32]:
        state = _credential_security_state(
            component, directory=True, allow_inherited_directory=True,
        )
        chain.append((os.path.normcase(os.path.abspath(component)), state))
        if state[2] & 0x1000:  # SE_DACL_PROTECTED; no upstream inheritance route.
            return tuple(chain)
    raise PermissionError("Credential retry inheritance boundary is unavailable or too deep")


def _replace_credential_file(source: Path, destination: Path, data_root: Path | None) -> None:
    """Retry only a proven unpublished Windows sharing/access failure.

    Cooperating writers remain serialized by the credential transaction. Every
    retry also rechecks ordinary-file identities, content, ancestor topology
    and exact native private security through the first protected directory;
    replacement, aliases or an uncertain completed publication refuse retry.
    All snapshot descriptors close before rename, avoiding our own deny-delete
    reader. Seven attempts sleep at most 0.7 seconds in total.
    """
    source, destination = Path(os.path.abspath(source)), Path(os.path.abspath(destination))
    parent = source.parent
    if destination.parent != parent:
        raise ValueError("Credential publication must stay in one directory")

    def parent_state():
        chain = []
        for component in (parent, *parent.parents):
            info = component.lstat()
            attributes = int(getattr(info, "st_file_attributes", 0))
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or attributes & 0x400):
                raise PermissionError("Credential publication ancestry is unsafe")
            chain.append((os.path.normcase(os.path.abspath(component)), info.st_dev, info.st_ino,
                          info.st_mode, attributes))
        return tuple(chain)

    def security_state():
        return (_credential_security_state(source),
                _credential_security_state(destination, missing_ok=True),
                _credential_parent_security_state(parent))

    topology = parent_state()
    original_source = _credential_file_state(source)
    original_destination = _credential_file_state(destination, missing_ok=True)
    retry_security = None
    if os.name == "nt":
        try:
            retry_security = security_state()
        except Exception:
            # Preserve existing first-attempt publication policy when optional
            # APIs/private parent proof are unavailable. Such a state never
            # authorizes a retry, even for native access/sharing errors.
            pass

    def unchanged():
        _assert_transaction(data_root)
        if (parent_state() != topology or _credential_file_state(source) != original_source
                or _credential_file_state(destination, missing_ok=True) != original_destination):
            raise PermissionError("Credential publication custody changed; refusing replacement retry")
        if retry_security is not None and security_state() != retry_security:
            raise PermissionError("Credential publication security changed; refusing replacement retry")

    for attempt in range(7):
        unchanged()
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            # This fixed local marker contains no path, message or credential.
            exc.angerona_write_boundary = "credential-atomic-replace"
            if (os.name != "nt" or type(getattr(exc, "winerror", None)) is not int
                    or exc.winerror not in {5, 32} or attempt == 6 or retry_security is None):
                raise
            try:
                unchanged()
            except (OSError, RuntimeError) as changed:
                raise changed from exc
            time.sleep(min(0.2, 0.02 * (2 ** attempt)))


def _write_secret_map_locked(updates: Mapping[str, object], data_root: Path | None = None) -> Path:
    _assert_transaction(data_root)
    # Clear an inherited plaintext PIN even when this particular update does
    # not contain the PIN. It must only ever be read from protected storage.
    _remove_environment_secrets((*_NON_ENVIRONMENT_SECRETS, *updates))
    path = secure_store_path(data_root)
    values = (
        _read_macos_secret_map(strict=True)
        if sys.platform == "darwin"
        else _read_linux_secret_map(strict=True)
        if sys.platform.startswith("linux")
        else read_secret_map(data_root, strict=True)
    )
    _assert_transaction(data_root)
    removed: set[str] = set()
    for key, value in updates.items():
        key = str(key).strip()
        if not key:
            continue
        if value in (None, ""):
            values.pop(key, None)
            removed.add(key)
        else:
            values[key] = str(value)
    payload = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if sys.platform == "darwin":
        from angerona.platforms.macos.keychain import write_blob
        write_blob(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ACCOUNT, payload)
        if _read_macos_secret_map(strict=True) != values:
            raise RuntimeError(
                "macOS Keychain verification failed; credentials were not accepted"
            )
        _assert_transaction(data_root)
        _remove_environment_secrets((*values, *removed))
        # Kept as a stable API return value; no secret is written at this path.
        return path
    if sys.platform.startswith("linux"):
        from angerona.platforms.linux.secret_service import write_blob
        write_blob(_LINUX_SECRET_SERVICE, _LINUX_SECRET_ACCOUNT, payload)
        if _read_linux_secret_map(strict=True) != values:
            raise RuntimeError(
                "Linux Secret Service verification failed; credentials were not accepted"
            )
        _assert_transaction(data_root)
        _remove_environment_secrets((*values, *removed))
        return path
    blob = _protect_bytes(payload)
    if blob is None:
        raise RuntimeError(
            "No supported OS credential store is available; credentials were not written"
        )
    # Verify before replacing the previous store.  A DPAPI or account-context
    # problem must never destroy the only readable credential copy.
    if _unprotect_bytes(blob) != payload:
        raise RuntimeError("DPAPI verification failed; credentials were not written")
    _assert_transaction(data_root)
    if _path_traverses_reparse(path.parent) or (
        os.path.lexists(path) and _is_link_or_reparse(path)
    ):
        raise RuntimeError(
            "Protected credential path traverses a link or reparse point; refusing to write"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if _path_traverses_reparse(path.parent):
        raise RuntimeError(
            "Protected credential directory became unsafe; refusing to write"
        )
    descriptor: int | None = None
    tmp: Path | None = None
    try:
        # Never use a predictable PID-only temporary name here. Angerona may be
        # elevated while its data directory is writable by the desktop user; an
        # attacker must not be able to pre-place a link and redirect a secret
        # store write into an arbitrary file.
        for _ in range(16):
            candidate = path.with_name(
                f".{path.name}.{secrets.token_hex(12)}.tmp"
            )
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                tmp = candidate
                break
            except FileExistsError:
                continue
        if descriptor is None or tmp is None:
            raise RuntimeError("could not allocate a private credential temp file")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        _private_acl(tmp)
        _replace_credential_file(tmp, path, data_root)
        _private_acl(path)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
        except OSError:
            pass
    if read_secret_map(data_root, strict=True) != values:
        raise RuntimeError("DPAPI credential write did not survive readback")
    _assert_transaction(data_root)
    _remove_environment_secrets((*values, *removed))
    return path


def parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out


def load_into_environment(data_root: Path | None = None) -> None:
    """Scrub protected names from the environment without publishing values.

    Historical callers retain this startup hook, but consumers now retrieve
    only the exact credential they need from the protected store.  This keeps
    optional provider and mail functionality while preventing generic child
    processes, crash handlers, or unrelated modules from inheriting secrets.
    """
    values = read_secret_map(data_root)
    _remove_environment_secrets((*_NON_ENVIRONMENT_SECRETS, *values))


def migrate_legacy_env(paths: list[Path], data_root: Path | None = None) -> list[Path]:
    """Explicitly migrate selected plaintext files after a verified DPAPI write.

    Callers must obtain operator approval for each path. Existing protected keys
    win, preventing a stale legacy file from replacing a credential silently.
    """
    merged: dict[str, str] = {}
    sources: list[tuple[Path, tuple[int, int, int, int, int]]] = []
    seen: set[str] = set()
    for candidate in paths:
        identity = _legacy_source_identity(candidate)
        if identity is None:
            continue
        canonical = os.path.normcase(os.path.abspath(candidate))
        if canonical in seen:
            continue
        seen.add(canonical)
        values = parse_env(candidate)
        # Reject a file that changed while it was being parsed. No protected
        # update or plaintext deletion is attempted for an unstable source.
        if values and _legacy_source_identity(candidate) == identity:
            merged.update(values)
            sources.append((candidate, identity))
    if not merged:
        return []
    with secret_transaction(data_root):
        existing = read_secret_map(data_root, strict=True)
        write_secret_map({key: value for key, value in merged.items() if key not in existing},
                         data_root)
        stored = read_secret_map(data_root, strict=True)
        expected = {**merged, **existing}
        if any(stored.get(key) != value for key, value in expected.items()):
            raise RuntimeError("legacy credential migration did not verify")
    removed: list[Path] = []
    for source, identity in sources:
        # Never delete a path that was swapped, linked, or changed after the
        # protected write/read verification. Leaving plaintext behind is safer
        # than deleting an object we did not inspect.
        if _legacy_source_identity(source) != identity:
            continue
        try:
            source.unlink()
            removed.append(source)
        except OSError:
            pass
    return removed
