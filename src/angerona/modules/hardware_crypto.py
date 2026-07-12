"""hardware_crypto.py — Hardware-rooted integrity (CODE: HWID).

Raises Angerona's secret-at-rest posture from "random file on disk" to
OS/hardware-bound protection:

1. DPAPI wrapping of the IPC key (implemented)
   The Zero-Trust IPC Guard (AUTH) stores a per-install HMAC secret at
   ``<data>/ipc_auth.key``. On its own that file is readable by anything running
   as the user. HWID wraps it with the Windows Data Protection API
   (CryptProtectData) so the ciphertext can only be unwrapped by the same
   user/machine context that Angerona runs under — a copy exfiltrated to another
   host is useless. We use ``win32crypt`` when pywin32 is present and fall back to
   a direct ``ctypes`` DPAPI call so no dependency is strictly required.

   SAFETY: HWID never mutates the file AUTH actually reads. It writes a protected
   sidecar (``ipc_auth.key.dpapi``) and verifies the round-trip, leaving the live
   key untouched so nothing breaks. ``protect()`` / ``unprotect()`` are exposed so
   AUTH can adopt DPAPI storage directly in a later change.

2. TPM 2.0 binding of the DB key (outline)
   ``bind_db_key_to_tpm()`` sketches sealing the ``flight-recorder.db`` encryption
   key to the host TPM via ``tpm2-pytss`` so the database is unreadable if copied
   off-host. The dependency is optional and imported lazily; when it is absent the
   method reports the required package rather than failing.

Degrades gracefully: on non-Windows or non-elevated hosts the module reports a
health note and stays alive; it never crashes the daemon thread.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


def _data_base() -> Path:
    base = os.environ.get("ANGERONA_DATA") or os.path.join(
        os.environ.get("LOCALAPPDATA", str(Path.home())), "Angerona"
    )
    return Path(base)


_IS_WINDOWS = sys.platform.startswith("win")


# ── DPAPI primitives (win32crypt preferred, ctypes fallback) ──────────────────
def _dpapi_ctypes(data: bytes, protect: bool, entropy: bytes = b"") -> Optional[bytes]:
    """Call CryptProtectData / CryptUnprotectData through ctypes (no pywin32).

    Returns the transformed bytes, or None on any failure. CRYPTPROTECT_LOCAL_
    MACHINE is intentionally NOT set, so only the current user context can unwrap.
    """
    if not _IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        def _blob(b: bytes) -> "DATA_BLOB":
            buf = ctypes.create_string_buffer(b, len(b))
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        in_blob = _blob(data)
        ent_blob = _blob(entropy)
        out_blob = DATA_BLOB()
        fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        ok = fn(ctypes.byref(in_blob), None, ctypes.byref(ent_blob),
                None, None, 0, ctypes.byref(out_blob))
        if not ok:
            return None
        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            kernel32.LocalFree(out_blob.pbData)
        return out
    except Exception:
        return None


def protect(data: bytes, entropy: bytes = b"") -> Optional[bytes]:
    """DPAPI-encrypt ``data`` for the current user/machine. None if unavailable."""
    try:
        import win32crypt  # type: ignore
        blob = win32crypt.CryptProtectData(data, None, entropy or None, None, None, 0)
        return blob
    except Exception:
        return _dpapi_ctypes(data, protect=True, entropy=entropy)


def unprotect(blob: bytes, entropy: bytes = b"") -> Optional[bytes]:
    """DPAPI-decrypt a blob produced by :func:`protect`. None if unavailable."""
    try:
        import win32crypt  # type: ignore
        _desc, data = win32crypt.CryptUnprotectData(blob, entropy or None, None, None, 0)
        return data
    except Exception:
        return _dpapi_ctypes(blob, protect=False, entropy=entropy)


class HardwareCrypto(BaseModule):
    """Hardware-rooted integrity: DPAPI key wrapping + TPM binding outline."""

    CODE = "HWID"
    NAME = "Hardware-Rooted Integrity"
    name = "Hardware-Rooted Integrity"
    description = ("DPAPI-wraps the IPC secret so only this user/host can unwrap it; "
                   "outlines TPM 2.0 sealing of the flight-recorder DB key.")
    category = "Integrity"
    version = "1.0.0"

    _ENTROPY = b"Angerona-HWID-v1"   # app-specific secondary entropy for DPAPI

    def __init__(self) -> None:
        super().__init__()
        self._ipc_key_path = _data_base() / "ipc_auth.key"
        self._protected_path = _data_base() / "ipc_auth.key.dpapi"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── DPAPI wrapping of the IPC key ─────────────────────────────────────────
    def wrap_ipc_key(self) -> tuple[bool, str]:
        """Create/refresh a DPAPI-protected sidecar of the IPC key and verify the
        round-trip. Non-destructive: the live key AUTH reads is never modified."""
        if not _IS_WINDOWS:
            return False, "DPAPI unavailable (non-Windows host)"
        try:
            if not self._ipc_key_path.exists():
                return False, "IPC key not present yet (AUTH creates it on first run)"
            raw = self._ipc_key_path.read_bytes()
            blob = protect(raw, self._ENTROPY)
            if not blob:
                return False, "CryptProtectData failed (DPAPI returned nothing)"
            # Verify we can unwrap to the exact original before trusting it.
            back = unprotect(blob, self._ENTROPY)
            if back != raw:
                return False, "DPAPI round-trip mismatch — not writing sidecar"
            self._protected_path.write_bytes(blob)
            try:
                os.chmod(self._protected_path, 0o600)
            except Exception:
                pass
            return True, f"IPC key DPAPI-wrapped ({len(blob)} bytes) — user/host-bound"
        except Exception as exc:
            return False, f"wrap failed: {exc}"

    def load_protected_ipc_key(self) -> Optional[bytes]:
        """Return the DPAPI-unwrapped IPC key, or None. Provided so AUTH can move
        to protected-at-rest storage without exposing plaintext on disk."""
        try:
            if self._protected_path.exists():
                return unprotect(self._protected_path.read_bytes(), self._ENTROPY)
        except Exception:
            pass
        return None

    # ── TPM 2.0 binding (outline; optional dependency) ────────────────────────
    def bind_db_key_to_tpm(self, db_key: bytes) -> tuple[bool, str]:
        """Outline: seal ``db_key`` to the host TPM so flight-recorder.db is
        unreadable if copied off-host.

        Real sealing uses tpm2-pytss: create a primary key in the owner
        hierarchy, then ``ESAPI.create``/``load`` a sealed data object holding
        ``db_key`` under a PCR policy, persisting the sealed blob. Unsealing
        requires the same physical TPM + PCR state, binding the key to this host.
        Implemented as an outline because it needs a provisioned TPM present.
        """
        try:
            import tpm2_pytss  # type: ignore  # noqa: F401
        except Exception:
            return False, ("tpm2-pytss not installed — `pip install tpm2-pytss` and a "
                           "provisioned TPM 2.0 required to seal the DB key")
        # A full implementation would ESAPI.startup(), create a primary under
        # TPM2_RH_OWNER, seal db_key under a PCR policy, and persist the blob.
        return False, "TPM present; sealing routine is an outline pending hardware review"

    # ── Daemon loop ───────────────────────────────────────────────────────────
    def run(self) -> None:
        if not _IS_WINDOWS:
            self.set_health(60, "DPAPI/TPM are Windows-only — module idle on this host")
            while not self.stopping:
                self.sleep(30)
            return

        # One-shot wrap at startup; then idle, re-checking periodically in case
        # AUTH regenerates its key.
        ok, note = self.wrap_ipc_key()
        if ok:
            self.set_health(100, note)
            self.emit(f"HWID: {note}.", Severity.INFO)
        else:
            self.set_health(70, note)
            self.emit(f"HWID: IPC key not yet hardware-wrapped — {note}.", Severity.INFO)

        tpm_ok, tpm_note = self.bind_db_key_to_tpm(b"")   # probe availability only
        self.emit(f"HWID TPM status: {tpm_note}.", Severity.INFO)

        while not self.stopping:
            self.sleep(300)
            if not self._protected_path.exists() and self._ipc_key_path.exists():
                ok, note = self.wrap_ipc_key()
                self.set_health(100 if ok else 70, note)

    def self_test(self) -> tuple[bool, str]:
        """Prove a DPAPI protect→unprotect round-trip on a throwaway secret."""
        if not _IS_WINDOWS:
            return True, "non-Windows host — DPAPI/TPM inert by design"
        probe = os.urandom(32)
        blob = protect(probe, self._ENTROPY)
        if not blob:
            return False, "DPAPI CryptProtectData unavailable"
        return (unprotect(blob, self._ENTROPY) == probe,
                "DPAPI round-trip verified" if unprotect(blob, self._ENTROPY) == probe
                else "DPAPI round-trip mismatch")


def register() -> HardwareCrypto:
    return HardwareCrypto()
