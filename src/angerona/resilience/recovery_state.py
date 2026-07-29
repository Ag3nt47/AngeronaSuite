"""Authenticated durable state for crash-loop recovery supervisors.

The core manager and peer watchdog deliberately use separate namespaces because
they supervise some of the same sidecars.  Each supervisor persists only the
small amount of state needed to survive its own restart: recent failure times,
safe-mode timing, backoff deadline, last observed state, and the digest of the
diagnostic snapshot captured before the last restart.

No command lines, executable paths, usernames, environment values, or telemetry
payloads are stored.  The document is HMAC-authenticated with the installation's
shutdown-authority key and written atomically.  A malformed or forged existing
document raises :class:`RecoveryStateError`; callers can then fail closed into
safe mode until an authenticated manual restart clears the fault.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from angerona.core.atomic_io import replace_with_retry

_SCHEMA_VERSION = 1
_MAX_DOCUMENT_BYTES = 256 * 1024
_MAX_COMPONENTS = 32
_MAX_FAILURES_PER_COMPONENT = 64
_SAFE_NAME = re.compile(r"[^a-z0-9_.-]+")


class RecoveryStateError(RuntimeError):
    """Existing recovery state could not be authenticated or validated."""


def safe_name(value: str, *, fallback: str = "supervisor") -> str:
    normalized = _SAFE_NAME.sub("-", str(value or "").strip().casefold()).strip(".-")
    normalized = re.sub(r"\.{2,}", "-", normalized)
    normalized = re.sub(r"-{2,}", "-", normalized).strip(".-")
    return (normalized or fallback)[:48]


def _canonical(document: dict) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "hmac_sha256"}
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _finite_timestamp(value, *, maximum: float) -> float:
    parsed = float(value or 0.0)
    if not math.isfinite(parsed) or parsed < 0 or parsed > maximum:
        raise RecoveryStateError("recovery state contains an invalid timestamp")
    return parsed


class RecoveryStateStore:
    """Small HMAC-authenticated state document owned by one supervisor."""

    def __init__(
        self,
        namespace: str,
        *,
        path: Optional[Path] = None,
        key: Optional[bytes] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.namespace = safe_name(namespace)
        if path is None:
            from angerona.resilience.supervisor import _ipc_dir

            path = _ipc_dir() / f"supervisor-state.{self.namespace}.json"
        self.path = Path(path)
        self._key = bytes(key) if key is not None else None
        self._clock = clock
        self._lock = threading.RLock()

    def _authority(self) -> bytes:
        if self._key is None:
            from angerona.resilience.shutdown_token import _load_key

            key = _load_key()
        else:
            key = self._key
        if len(key) < 32:
            raise RecoveryStateError("recovery-state authority is too short")
        return key

    def _empty(self) -> dict:
        return {
            "schema_version": _SCHEMA_VERSION,
            "namespace": self.namespace,
            "updated_at": float(self._clock()),
            "components": {},
        }

    def load(self) -> dict:
        with self._lock:
            if not self.path.exists():
                return self._empty()
            try:
                if self.path.stat().st_size > _MAX_DOCUMENT_BYTES:
                    raise RecoveryStateError("recovery state exceeds its size limit")
                raw = self.path.read_bytes()
                document = json.loads(raw.decode("utf-8"))
            except RecoveryStateError:
                raise
            except Exception as exc:
                raise RecoveryStateError("recovery state is unreadable") from exc
            if not isinstance(document, dict):
                raise RecoveryStateError("recovery state is not an object")
            if document.get("schema_version") != _SCHEMA_VERSION:
                raise RecoveryStateError("unsupported recovery-state schema")
            if document.get("namespace") != self.namespace:
                raise RecoveryStateError("recovery-state namespace mismatch")
            signature = str(document.get("hmac_sha256") or "")
            expected = hmac.new(
                self._authority(), _canonical(document), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise RecoveryStateError("recovery-state authentication failed")
            components = document.get("components")
            if not isinstance(components, dict) or len(components) > _MAX_COMPONENTS:
                raise RecoveryStateError("invalid recovery-state component map")
            return document

    def component(self, name: str) -> dict:
        record = self.load()["components"].get(safe_name(name), {})
        if not isinstance(record, dict):
            raise RecoveryStateError("invalid component recovery record")
        maximum = float(self._clock()) + 7 * 24 * 3600
        failures = record.get("failures", [])
        if not isinstance(failures, list) or len(failures) > _MAX_FAILURES_PER_COMPONENT:
            raise RecoveryStateError("invalid recovery failure history")
        cleaned_failures = [
            _finite_timestamp(value, maximum=maximum) for value in failures
        ]
        digest = str(record.get("last_diagnostic_sha256") or "")
        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RecoveryStateError("invalid recovery diagnostic digest")
        return {
            "failures": cleaned_failures,
            "safe_mode": bool(record.get("safe_mode", False)),
            "safe_mode_since": _finite_timestamp(
                record.get("safe_mode_since", 0.0), maximum=maximum
            ),
            "next_restart_at": _finite_timestamp(
                record.get("next_restart_at", 0.0), maximum=maximum
            ),
            "last_state": str(record.get("last_state") or "unknown")[:24],
            "last_diagnostic_sha256": digest,
            "state_fault": bool(record.get("state_fault", False)),
        }

    def update_component(self, name: str, record: dict) -> None:
        component = safe_name(name)
        with self._lock:
            document = self.load()
            components = document["components"]
            if component not in components and len(components) >= _MAX_COMPONENTS:
                raise RecoveryStateError("recovery-state component limit reached")
            failures = [float(value) for value in list(record.get("failures", []))[-64:]]
            components[component] = {
                "failures": failures,
                "safe_mode": bool(record.get("safe_mode", False)),
                "safe_mode_since": float(record.get("safe_mode_since", 0.0)),
                "next_restart_at": float(record.get("next_restart_at", 0.0)),
                "last_state": str(record.get("last_state") or "unknown")[:24],
                "last_diagnostic_sha256": str(
                    record.get("last_diagnostic_sha256") or ""
                ),
                "state_fault": bool(record.get("state_fault", False)),
            }
            document["updated_at"] = float(self._clock())
            document["hmac_sha256"] = hmac.new(
                self._authority(), _canonical(document), hashlib.sha256
            ).hexdigest()
            encoded = json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            if len(encoded) > _MAX_DOCUMENT_BYTES:
                raise RecoveryStateError("recovery state exceeds its size limit")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_suffix(
                self.path.suffix + f".tmp.{os.getpid()}.{threading.get_ident()}"
            )
            try:
                with open(temp, "wb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                replace_with_retry(temp, self.path)
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            finally:
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass

    def clear_component(self, name: str, *, authenticated_reset: bool = False) -> None:
        cleared = {
            "failures": [],
            "safe_mode": False,
            "safe_mode_since": 0.0,
            "next_restart_at": 0.0,
            "last_state": "manual-restart",
            "last_diagnostic_sha256": "",
            "state_fault": False,
        }
        try:
            self.update_component(name, cleared)
        except RecoveryStateError:
            if not authenticated_reset:
                raise
            # A correctly authenticated operator restart is the recovery path
            # from a corrupt/forged state document. Reset the namespace and
            # immediately replace it with a fresh authenticated record.
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self.update_component(name, cleared)
