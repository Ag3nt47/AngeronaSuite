"""Unverified SGX/Gramine runtime hints and optional SQLCipher compatibility.

Environment variables and attestation pseudo-file presence are hints only. This
helper does not verify a quote, hardware identity, enclave measurement or the
flight-cache deployment. Its legacy active API must not grant trust authority.
The optional SQLCipher helper has no production flight-cache caller.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional


def is_confidential_compute_active() -> bool:
    """Legacy hint API; True does not establish hardware attestation."""
    try:
        # Gramine exposes the attestation pseudo-files inside the enclave.
        if Path("/dev/attestation/quote").exists() or Path("/dev/attestation/user_report_data").exists():
            return True
        # Gramine sets these in the enclave's environment.
        for k in ("GRAMINE", "IN_GRAMINE", "SGX", "GRAMINE_MANIFEST"):
            v = os.environ.get(k, "")
            if v and v not in ("0", "false", "False"):
                return True
    except Exception:
        pass
    return False


class SgxEnclaveGuard:
    """Runtime-hint awareness and optional SQLCipher compatibility helper."""

    def __init__(self) -> None:
        self._active = is_confidential_compute_active()
        self._key: Optional[bytes] = None
        self._key_lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────
    @property
    def active(self) -> bool:
        return self._active

    def enclave_key(self) -> Optional[bytes]:
        """Generate one process-memory key only when a runtime hint is present.

        This does not establish that the process or key is inside a verified TEE.
        Python key copies and forensic memory erasure are not guaranteed.
        """
        if not self._active:
            return None
        with self._key_lock:
            if self._key is None:
                self._key = os.urandom(32)
            return self._key

    def patch_memc(self, memc_conn) -> bool:
        """Attempt SQLCipher key configuration and check its version and schema.

        True reports completed connection checks, not proof of memory encryption.

        `memc_conn` is a DB-API connection (or an object exposing `.execute`).
        Without a runtime hint or a SQLCipher-capable connection, returns False.
        Success reports a SQLCipher connection check, not verified enclave custody.
        """
        if not self._active:
            return False
        key = self.enclave_key()
        if not key or memc_conn is None:
            return False
        try:
            # Plain SQLite silently ignores unknown PRAGMAs. Require an actual
            # SQLCipher version response before setting any key material.
            version = memc_conn.execute("PRAGMA cipher_version").fetchone()
            if (not version or not isinstance(version[0], str)
                    or not version[0].strip()):
                return False
            # SQLCipher expects hex key text; Python may retain temporary copies.
            hexkey = key.hex()
            memc_conn.execute(f"PRAGMA key = \"x'{hexkey}'\"")
            memc_conn.execute("PRAGMA cipher_page_size = 4096")
            # Touch the schema to force key application; harmless if already keyed.
            memc_conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return True
        except Exception:
            # pysqlcipher3 not in use / plain sqlite3 → cannot encrypt in place.
            return False

    def summary(self) -> str:
        if self._active:
            return "SGX/Gramine runtime hint detected; hardware attestation is unverified."
        return "No SGX/Gramine runtime hint detected; hardware attestation is unverified."


# Module-level singleton for convenience.
_GUARD: Optional[SgxEnclaveGuard] = None
_GUARD_LOCK = threading.Lock()


def get_guard() -> SgxEnclaveGuard:
    global _GUARD
    with _GUARD_LOCK:
        if _GUARD is None:
            _GUARD = SgxEnclaveGuard()
        return _GUARD
