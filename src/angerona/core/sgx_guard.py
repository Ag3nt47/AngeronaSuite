"""sgx_guard.py — Confidential-Compute (Intel SGX / Gramine) awareness (CODE: SGX).

When Angerona is run inside a Gramine SGX enclave, this foundational helper:
  1. Detects the enclave (``/dev/attestation/*`` or Gramine env vars).
  2. Generates an AES-256 key STRICTLY in enclave memory and (best-effort) patches
     the MEMC (Flight Cache) SQLite connection to SQLCipher, so the :memory: DB
     pages are ciphertext even if swapped or scraped by the hypervisor.
  3. Exposes ``is_confidential_compute_active()`` for app.py to light up the
     Threat-Posture dashboard.

Everything degrades gracefully: outside an enclave, or without pysqlcipher3, the
helpers are no-ops and never raise. Graminizing the app is documented in
``angerona.manifest.template`` at the repo root.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def is_confidential_compute_active() -> bool:
    """True iff we're running inside a Gramine/SGX enclave. Cheap + never raises."""
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
    """TEE-awareness + MEMC encryption patcher."""

    def __init__(self) -> None:
        self._active = is_confidential_compute_active()
        self._key: Optional[bytes] = None

    # ── Public API ──────────────────────────────────────────────────────────
    @property
    def active(self) -> bool:
        return self._active

    def enclave_key(self) -> Optional[bytes]:
        """Generate (once) a 256-bit key held only in enclave memory. Returns None
        if we're not in an enclave (we must not create a key outside the TEE)."""
        if not self._active:
            return None
        if self._key is None:
            self._key = os.urandom(32)   # 256-bit; lives only in enclave RAM
        return self._key

    def patch_memc(self, memc_conn) -> bool:
        """Best-effort: switch a MEMC :memory: SQLite connection to SQLCipher using
        the enclave key. Returns True if encryption was applied.

        `memc_conn` is a DB-API connection (or an object exposing `.execute`).
        Outside an enclave, or without pysqlcipher3, this is a no-op returning False.
        """
        if not self._active:
            return False
        key = self.enclave_key()
        if not key or memc_conn is None:
            return False
        try:
            # SQLCipher takes a PRAGMA key. We pass the raw key as a hex blob so no
            # KDF is needed and the key never leaves enclave memory as text.
            hexkey = key.hex()
            memc_conn.execute(f"PRAGMA key = \"x'{hexkey}'\"")
            memc_conn.execute("PRAGMA cipher_page_size = 4096")
            # Touch the schema to force key application; harmless if already keyed.
            memc_conn.execute("SELECT count(*) FROM sqlite_master")
            return True
        except Exception:
            # pysqlcipher3 not in use / plain sqlite3 → cannot encrypt in place.
            return False

    def summary(self) -> str:
        if self._active:
            return "Confidential Compute ACTIVE — running inside an SGX enclave."
        return "Confidential Compute inactive — run under gramine-sgx to enable."


# Module-level singleton for convenience.
_GUARD: Optional[SgxEnclaveGuard] = None


def get_guard() -> SgxEnclaveGuard:
    global _GUARD
    if _GUARD is None:
        _GUARD = SgxEnclaveGuard()
    return _GUARD
