"""hardware_crypto.py — Hardware-rooted integrity (CODE: HWID).

Raises Angerona's secret-at-rest posture from "random file on disk" to
OS/hardware-bound protection:

1. OS-protected IPC key storage (implemented)
   The Zero-Trust IPC diagnostic probe (AUTH) reads its per-install HMAC secret
   directly from Angerona's OS credential store. On Windows that store uses
   current-user DPAPI; macOS/Linux use Keychain/Secret Service. HWID verifies or
   migrates the former exact 32-byte plaintext key and never creates a plaintext
   live sidecar.

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
    from angerona.core.data_paths import data_dir
    return data_dir()


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
    description = ("Verifies OS-protected IPC key storage and DPAPI primitives; "
                   "TPM database-key sealing remains an explicit unsupported outline.")
    category = "Integrity"
    version = "1.12.1"

    _ENTROPY = b"Angerona-HWID-v1"   # app-specific secondary entropy for DPAPI

    def __init__(self) -> None:
        super().__init__()
        self._ipc_key_path = _data_base() / "ipc_auth.key"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── DPAPI wrapping of the IPC key ─────────────────────────────────────────
    def wrap_ipc_key(self) -> tuple[bool, str]:
        """Verify/migrate AUTH key material into the canonical OS store."""
        try:
            from angerona.modules.ipc_guard import _load_or_create_key

            key = _load_or_create_key(self._ipc_key_path)
            if len(key) != 32 or self._ipc_key_path.exists():
                return False, "IPC key migration did not reach protected-only state"
            backend = "DPAPI" if _IS_WINDOWS else "OS credential store"
            return True, f"IPC key verified in {backend}; no plaintext sidecar"
        except Exception as exc:
            return False, f"protected-store verification failed: {exc}"

    def load_protected_ipc_key(self) -> Optional[bytes]:
        """Return only the exact protected IPC key, or None."""
        try:
            from angerona.core.secure_store import read_secret_values

            encoded = read_secret_values(
                ("ANGERONA_IPC_AUTH_KEY",), _data_base(), strict=True
            ).get("ANGERONA_IPC_AUTH_KEY", "")
            if len(encoded) == 64:
                return bytes.fromhex(encoded)
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
        if not isinstance(db_key, bytes):
            return False, "TPM sealing requires a byte-string database key"
        try:
            import tpm2_pytss  # type: ignore  # noqa: F401
        except Exception:
            return False, ("tpm2-pytss not installed — `pip install tpm2-pytss` and a "
                           "provisioned TPM 2.0 required to seal the DB key")
        # A full implementation would ESAPI.startup(), create a primary under
        # TPM2_RH_OWNER, seal db_key under a PCR policy, and persist the blob.
        return False, "TPM present; sealing routine is an outline pending hardware review"

    def _set_combined_health(
        self,
        ipc_ok: bool,
        ipc_note: str,
        tpm_ok: bool,
        tpm_note: str,
    ) -> None:
        if not ipc_ok:
            self.set_health(40, f"IPC protected-store check failed: {ipc_note}")
            return
        if not tpm_ok:
            self.set_health(
                75,
                f"IPC protected storage verified, but database-key TPM binding "
                f"is not active: {tpm_note}",
            )
            return
        self.set_health(100, f"{ipc_note}; {tpm_note}")

    # ── Daemon loop ───────────────────────────────────────────────────────────
    def run(self) -> None:
        if not _IS_WINDOWS:
            ok, note = self.wrap_ipc_key()
            self.set_health(80 if ok else 40, note)
            while not self.stopping:
                self.sleep(30)
            return

        # One-shot protected-store verification, then periodic re-check.
        ok, note = self.wrap_ipc_key()
        tpm_ok, tpm_note = self.bind_db_key_to_tpm(b"")   # probe availability only
        self._set_combined_health(ok, note, tpm_ok, tpm_note)
        if ok:
            self.emit(f"HWID: {note}.", Severity.INFO)
        else:
            self.emit(f"HWID: IPC key not yet hardware-wrapped — {note}.", Severity.INFO)
        self.emit(f"HWID TPM status: {tpm_note}.", Severity.INFO)

        while not self.stopping:
            self.sleep(300)
            ok, note = self.wrap_ipc_key()
            tpm_ok, tpm_note = self.bind_db_key_to_tpm(b"")
            self._set_combined_health(ok, note, tpm_ok, tpm_note)

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
