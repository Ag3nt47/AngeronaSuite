"""
core/hardening.py — self-hardening of Angerona's own process.

Applies a set of Windows process-mitigation policies (SetProcessMitigationPolicy)
to shrink the attack surface an in-process exploit could use for injection or
code execution. This hardens the AGENT itself; it is not a detection module and
adds no orchestrator (the 360° model forbids a control-plane module).

Design note — why not "Microsoft-signed binaries only"?
    A hardening spec often calls for BinarySignaturePolicy = MicrosoftSignedOnly
    plus Arbitrary Code Guard (ACG / ProhibitDynamicCode). For THIS process that
    is self-defeating: Angerona is a Python + PySide6 (Qt) app that must load
    third-party, non-Microsoft-signed native DLLs (Qt, pywin32, scapy). Enabling
    MicrosoftSignedOnly blocks those loads and the app dies on launch; ACG can
    break libraries that generate code at runtime. So those two are NOT applied
    by default. The genuinely safe, non-breaking mitigations below run always;
    ACG is available opt-in (ANGERONA_HARDEN_AGGRESSIVE=1) for deployments that
    have verified their DLL set tolerates it. MicrosoftSignedOnly is intentionally
    never applied to the GUI process.

Safe by default:
    * ExtensionPointDisablePolicy — blocks legacy injection vectors (AppInit_DLLs,
      Winsock LSPs, IME hooks, legacy hook DLLs).
    * ImageLoadPolicy — NoRemoteImages (no DLLs from UNC/remote) and
      NoLowMandatoryLabelImages (no low-integrity DLLs).
    * ASLRPolicy — bottom-up + high-entropy randomization.

All calls are best-effort and never raise: hardening must not stop the app from
starting.
"""
from __future__ import annotations

import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

# ProcessMitigationPolicy enum values (winnt.h).
_ASLR = 1
_DYNAMIC_CODE = 2
_EXTENSION_POINT_DISABLE = 6
_IMAGE_LOAD = 10

# Bit fields for each policy DWORD.
_ASLR_BOTTOM_UP = 0x1
_ASLR_HIGH_ENTROPY = 0x4
_EXT_DISABLE = 0x1
_IMG_NO_REMOTE = 0x1
_IMG_NO_LOW_LABEL = 0x2
_DYN_PROHIBIT = 0x1
_DYN_ALLOW_THREAD_OPT_OUT = 0x2


def secure_sensitive_file(path: Path, *, required: bool = False) -> bool:
    """Restrict a key/token file to the elevated Angerona trust boundary.

    Packaged releases and the elevated source launcher set ``required`` so an
    ACL failure is fatal. Tests and non-Windows source development retain
    owner-only POSIX permissions without requiring Windows administration.
    """
    target = Path(path)
    try:
        if os.name != "nt":
            target.chmod(stat.S_IRUSR | stat.S_IWUSR)
            return True
        # A non-elevated Windows source/test process cannot safely replace the
        # DACL with an Administrators/SYSTEM-only boundary without locking
        # itself out. The elevated launcher and packaged releases always pass
        # required=True and therefore take the hardened path below.
        if not required:
            return False
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        icacls = system_root / "System32" / "icacls.exe"
        if not icacls.is_file():
            raise RuntimeError("icacls.exe unavailable")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            [
                str(icacls), str(target), "/inheritance:r",
                "/setowner", "*S-1-5-32-544",
                "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
            creationflags=flags,
        )
        if result.returncode != 0:
            raise RuntimeError(f"icacls failed with exit {result.returncode}")
        return True
    except Exception:
        if required:
            raise PermissionError(
                f"Unable to establish protected key custody for {target}"
            )
        return False


def sensitive_file_is_protected(path: Path) -> bool:
    """Return True only when a Windows key has an admin/SYSTEM-only DACL."""
    target = Path(path)
    if os.name != "nt":
        try:
            return (target.stat().st_mode & 0o077) == 0
        except OSError:
            return False
    try:
        from angerona.core.data_paths import _admin_acl_valid
        return _admin_acl_valid(target)
    except Exception:
        return False


def ensure_sensitive_parent(path: Path, *, required: bool = False) -> None:
    """Fail before key access unless the required Windows parent is protected."""
    if not required or os.name != "nt":
        return
    target = Path(path)
    try:
        from angerona.core.data_paths import _admin_acl_valid, _is_reparse_point
        if _is_reparse_point(target.parent) or not _admin_acl_valid(target.parent):
            raise PermissionError
    except Exception as exc:
        raise PermissionError(
            f"Sensitive-key parent is outside the protected boundary: {target.parent}"
        ) from exc


def prepare_sensitive_key(path: Path, *, required: bool = False) -> bool:
    """Validate custody before key bytes are read.

    Returns True when an existing key may be consumed. Under required Windows
    hardening, an unsafe pre-created key is atomically quarantined *after* its
    protected parent has been established, forcing fresh random material.
    """
    target = Path(path)
    ensure_sensitive_parent(target, required=required)
    if not target.exists():
        return False
    if not required:
        return True
    if sensitive_file_is_protected(target):
        return True
    quarantine = target.with_name(
        f"{target.name}.rejected-{secrets.token_hex(8)}"
    )
    try:
        os.replace(target, quarantine)
    except Exception as exc:
        raise PermissionError(
            f"Refusing unsafe pre-existing key material: {target}"
        ) from exc
    return False


def key_acl_required() -> bool:
    """Whether failure to protect signing/shutdown keys must stop startup."""
    return bool(
        getattr(sys, "frozen", False)
        or os.environ.get("ANGERONA_ENFORCE_KEY_ACL", "").strip() == "1"
    )


def apply_process_mitigations(aggressive: bool | None = None) -> dict:
    """Apply process-mitigation policies to the current process. Returns a dict
    of {policy_name: True|False|"skipped"}. No-op (all "skipped") off Windows."""
    results: dict[str, object] = {}
    if os.name != "nt":
        return {"platform": "skipped (non-Windows)"}
    if aggressive is None:
        aggressive = os.getenv("ANGERONA_HARDEN_AGGRESSIVE", "0") == "1"

    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:                       # pragma: no cover
        return {"error": f"ctypes unavailable: {exc}"}

    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        SetPolicy = k32.SetProcessMitigationPolicy
        SetPolicy.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        SetPolicy.restype = wintypes.BOOL
    except Exception as exc:                        # pragma: no cover
        return {"error": f"SetProcessMitigationPolicy unavailable: {exc}"}

    def _set(name: str, policy_id: int, value: int) -> None:
        try:
            val = ctypes.c_uint32(value)
            ok = SetPolicy(policy_id, ctypes.byref(val), ctypes.sizeof(val))
            results[name] = bool(ok)
        except Exception as exc:                    # never fatal
            results[name] = f"error: {exc}"

    # Always-safe mitigations.
    _set("extension_point_disable", _EXTENSION_POINT_DISABLE, _EXT_DISABLE)
    _set("image_load", _IMAGE_LOAD, _IMG_NO_REMOTE | _IMG_NO_LOW_LABEL)
    _set("aslr", _ASLR, _ASLR_BOTTOM_UP | _ASLR_HIGH_ENTROPY)

    # Opt-in only: Arbitrary Code Guard. Can break libraries that JIT/emit code,
    # so thread opt-out is allowed and it is gated behind an explicit flag.
    if aggressive:
        _set("dynamic_code_acg", _DYNAMIC_CODE, _DYN_PROHIBIT | _DYN_ALLOW_THREAD_OPT_OUT)
    else:
        results["dynamic_code_acg"] = "skipped (set ANGERONA_HARDEN_AGGRESSIVE=1)"
    # MicrosoftSignedOnly is intentionally never applied — it would block Qt DLLs.
    results["binary_signature_microsoft_only"] = "skipped (would break Qt/PySide6)"
    return results
