"""etw_listener.py — ETW Core Listener (Code: ETWG).

Purpose
    Capture process-creation and logon activity in-flight from Windows' own
    kernel-sourced telemetry (the ETW-backed Security channel) and republish it
    onto the AngeronaSuite EventBus so PROC/logon events feed triage, the
    provenance graph, and speculative pre-warming.

Sources (in priority order)
    1. Windows **Security** event log via ``win32evtlog`` — EID 4688 (process
       creation, with parent + command line when audit policy is on), 4624
       (successful logon), 4672 (special-privilege logon). This channel is ETW
       under the hood and is the supported user-mode capture path (no custom
       driver). Requires elevation, which the suite already runs with.
    2. Fallback: if that channel is unavailable (non-Windows, no pywin32, audit
       disabled, access denied) it degrades to psutil process-creation diffing so
       the pipeline still receives PROC events.

Safety
    Read-only consumption of local event telemetry. Nothing is written to the
    log, no policy is changed, nothing leaves the machine.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import socket
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.authorization import AuthorizationDecision, AuthorizationPolicy
from angerona.core.module_base import BaseModule, Severity

_EID = {4688: "process_created", 4624: "logon", 4672: "privileged_logon"}
_MAX_SECURITY_PAGES = 32
_MAX_SECURITY_RECORDS = 4096
_MAX_SECURITY_IDENTITY_RECORDS = 4096
_MAX_SECURITY_EVENT_INSERTS = 4096
_MAX_SECURITY_RECORD_IDENTITY_BYTES = 4 * 1024 * 1024
_MAX_SECURITY_IDENTITY_BYTES = 64 * 1024 * 1024
_MAX_SECURITY_READ_S = 1.5
_CURSOR_SCHEMA = 3
_CURSOR_CONTEXT = b"angerona-etw-security-cursor-v1"
_HIGHWATER_SCHEMA = 2
_HIGHWATER_CONTEXT = b"angerona-etw-security-highwater-v1"
_ROLLBACK_ANCHOR_SCHEMA = 2
_ROLLBACK_ANCHOR_CONTEXT = b"angerona-etw-security-rollback-anchor-v1"
_AUTHORITY_WITNESS_SCHEMA = 1
_AUTHORITY_WITNESS_CONTEXT = b"angerona-etw-security-authority-witness-v1"
_DELIVERY_OUTBOX_SCHEMA = 1
_DELIVERY_OUTBOX_CONTEXT = b"angerona-etw-security-delivery-outbox-v1"
_DELIVERY_ACK_SCHEMA = 1
_DELIVERY_ACK_CONTEXT = b"angerona-etw-security-delivery-ack-v1"
_MAX_DELIVERY_OUTBOX_BYTES = 16 * 1024 * 1024
_MAX_DELIVERY_ACK_BYTES = 16 * 1024
_HIGHWATER_GENESIS = "0" * 64
_MAX_HIGHWATER_BYTES = 64 * 1024 * 1024
_MAX_AUTHORITY_WITNESS_BYTES = 16 * 1024
_CURSOR_FIELDS = frozenset({
    "schema",
    "channel",
    "host_binding",
    "sequence",
    "generation",
    "last_record",
    "last_record_anchor",
    "oldest_observed",
    "high_watermark",
    "gap_reason",
    "enrolled_at",
    "enrollment_request_id",
    "enrollment_request_digest",
    "enrollment_reason_digest",
    "install_epoch",
    "enrollment_challenge_counter",
    "channel_identity_digest",
    "channel_identity_oldest",
    "channel_identity_high",
    "updated_at",
    "record_hmac",
})
_HIGHWATER_FIELDS = frozenset({
    "schema",
    "channel",
    "host_binding",
    "entry_sequence",
    "cursor_sequence",
    "generation",
    "last_record",
    "last_record_anchor",
    "high_watermark",
    "gap_digest",
    "cursor_record_hmac",
    "enrollment_request_id",
    "enrollment_request_digest",
    "install_epoch",
    "enrollment_challenge_counter",
    "channel_identity_digest",
    "channel_identity_oldest",
    "channel_identity_high",
    "recorded_at",
    "previous_hmac",
    "record_hmac",
})
_ROLLBACK_ANCHOR_FIELDS = frozenset({
    "schema", "host_binding", "install_epoch", "revision",
    "challenge_counter", "active_challenge_nonce", "active_state_digest",
    "active_reason_digest", "cursor_sequence", "cursor_record_hmac",
    "highwater_record_hmac", "generation", "last_record", "high_watermark",
    "enrollment_request_id", "enrollment_request_digest", "state_digest",
    "record_hmac",
})
_AUTHORITY_WITNESS_FIELDS = frozenset({
    "schema", "host_binding", "authority_fingerprint", "install_epoch",
    "anchor_revision", "cursor_sequence", "cursor_record_hmac",
    "highwater_record_hmac", "anchor_record_hmac", "record_hmac",
})
_DELIVERY_OUTBOX_FIELDS = frozenset({
    "schema", "channel", "host_binding", "base_cursor_sequence",
    "base_cursor_hmac", "target_generation", "target_last_record",
    "target_last_record_anchor", "events", "created_at", "record_hmac",
})
_DELIVERY_EVENT_FIELDS = frozenset({
    "record", "eid", "kind", "inserts", "generation", "record_anchor",
    "event_identity",
})
_DELIVERY_ACK_FIELDS = frozenset({
    "schema", "channel", "host_binding", "cursor_sequence",
    "cursor_record_hmac", "target_generation", "target_last_record",
    "target_last_record_anchor", "outbox_record_hmac", "acknowledged_at",
    "record_hmac",
})
_ENROLLMENT_SCOPE = "telemetry/security-channel"
_ENROLLMENT_MAX_AGE_S = 300.0
_ENROLLMENT_WINDOW_S = 30.0
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

_WRITER_LEASES_GUARD = threading.Lock()
_WRITER_LEASES: dict[str, threading.RLock] = {}
_WRITER_LEASE_LOCAL = threading.local()


def _shared_writer_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve(strict=False)))
    with _WRITER_LEASES_GUARD:
        return _WRITER_LEASES.setdefault(key, threading.RLock())


@contextmanager
def _exclusive_writer_lease(path: Path) -> Iterator[None]:
    """Take a re-entrant process lock plus a non-blocking OS file lease."""
    key = os.path.normcase(str(path.resolve(strict=False)))
    lock = _shared_writer_lock(path)
    if not lock.acquire(blocking=False):
        raise RuntimeError("Security cursor writer lease is already held")
    depths = getattr(_WRITER_LEASE_LOCAL, "depths", None)
    if depths is None:
        depths = {}
        _WRITER_LEASE_LOCAL.depths = depths
    depth = int(depths.get(key, 0))
    if depth:
        depths[key] = depth + 1
        try:
            yield
        finally:
            depths[key] -= 1
            lock.release()
        return

    descriptor: int | None = None
    windows_locked = False
    posix_locked = False
    try:
        from angerona.core.hardening import ensure_sensitive_parent, key_acl_required

        required = key_acl_required()
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_sensitive_parent(path, required=required)
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        attributes = int(getattr(info, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(info.st_mode)
            or int(getattr(info, "st_nlink", 1)) != 1
            or bool(attributes & 0x400)
            or info.st_size > 1
        ):
            raise RuntimeError("Security cursor writer lease object is unsafe")
        if info.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        current = os.lstat(path)
        current_attributes = int(getattr(current, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or bool(current_attributes & 0x400)
            or int(getattr(current, "st_nlink", 1)) != 1
            or current.st_dev != info.st_dev
            or current.st_ino != info.st_ino
        ):
            raise RuntimeError("Security cursor writer lease identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            windows_locked = True
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            posix_locked = True
        depths[key] = 1
        yield
    finally:
        depths.pop(key, None)
        if descriptor is not None:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if windows_locked:
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                elif posix_locked:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass
        lock.release()


class EtwListenerModule(BaseModule):
    CODE = "ETWG"
    NAME = "ETW Core Listener"
    name = "ETW Core Listener"
    description = ("Captures process-creation (4688) + logon (4624/4672) telemetry "
                   "from the Windows Security channel; psutil fallback.")
    category = "Telemetry"
    version = "1.13.0"

    _POLL = 3.0

    def __init__(
        self,
        data_root: Path | None = None,
        *,
        host_identity: str | None = None,
        rollback_anchor: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
        self._explicit_data_root = Path(data_root) if data_root is not None else None
        self._host_identity_override = host_identity
        self._rollback_anchor_override = rollback_anchor
        self._manager = None
        self.state_lock = threading.RLock()
        self._last_record = 0
        self._last_record_anchor = ""
        self._security_generation = 0
        self._security_gap = ""
        self._security_backlog = False
        self._security_high_watermark = 0
        self._security_records_read = 0
        self._security_oldest_observed = 0
        self._security_bounds_checked_at = 0.0
        self._security_bounds_checked_monotonic = 0.0
        self._cursor_state_loaded = False
        self._cursor_enrolled = False
        self._cursor_sequence = 0
        self._cursor_enrolled_at = 0.0
        self._cursor_state_error = ""
        self._cursor_record_hmac = ""
        self._last_persisted_state_digest = ""
        self._last_enrollment_request_id = ""
        self._last_enrollment_request_digest = ""
        self._last_enrollment_reason_digest = ""
        self._install_epoch = ""
        self._enrollment_challenge_counter = 0
        self._active_enrollment_challenge: dict[str, object] | None = None
        self._channel_identity_digest = ""
        self._channel_identity_oldest = 0
        self._channel_identity_high = 0
        self._highwater_entry_sequence = 0
        self._highwater_record_hmac = _HIGHWATER_GENESIS
        self._known_pids: set[int] = set()
        self._mode = "init"
        self.captured = 0

    def bind_manager(self, manager) -> None:
        self._manager = manager

    @property
    def cursor_state_path(self) -> Path | None:
        if self._explicit_data_root is not None:
            return self._explicit_data_root / "etw-security-cursor.json"
        configured = getattr(getattr(self._manager, "config", None), "data_dir", None)
        if configured is None:
            return None
        return Path(configured) / "etw-security-cursor.json"

    @property
    def cursor_highwater_path(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.with_name(
            "etw-security-cursor-highwater.jsonl"
        )

    @property
    def cursor_authority_witness_path(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.with_name(
            "etw-security-authority-witness.json"
        )

    @property
    def cursor_writer_lease_path(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.with_name(
            "etw-security-cursor.writer.lock"
        )

    @property
    def security_delivery_outbox_path(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.with_name(
            "etw-security-delivery-outbox.json"
        )

    @property
    def security_delivery_custody_path(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.with_name(
            "etw-security-delivery-outbox.ack-custody.json"
        )

    @property
    def security_delivery_ack_path(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.with_name(
            "etw-security-delivery-ack.json"
        )

    @contextmanager
    def _cursor_writer_lease(self) -> Iterator[None]:
        path = self.cursor_writer_lease_path
        if path is None:
            raise RuntimeError("Security cursor writer lease root is unavailable")
        with _exclusive_writer_lease(path):
            yield

    def _host_binding(self) -> str:
        if self._host_identity_override is not None:
            material = self._host_identity_override
        else:
            root = self.cursor_state_path
            material = json.dumps(
                {
                    "node": platform.node(),
                    "hostname": socket.gethostname(),
                    "machine": platform.machine(),
                    "system": platform.system(),
                    "mac": f"{uuid.getnode():012x}",
                    "state_root": str(root.parent.resolve(strict=False)) if root else "",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        return hashlib.sha256(material.encode("utf-8", errors="strict")).hexdigest()

    def _cursor_key(self) -> bytes | None:
        authority = getattr(self._bus, "_authority", None)
        bus_key = getattr(authority, "_key", None)
        if not isinstance(bus_key, bytes) or len(bus_key) < 32:
            return None
        return hmac.new(
            bus_key,
            _CURSOR_CONTEXT + b"\0" + self._host_binding().encode("ascii"),
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _cursor_canonical(value: dict[str, object]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _safe_cursor_file(path: Path, *, max_bytes: int = 64 * 1024) -> bool:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return False
        except OSError:
            return False
        attributes = int(getattr(info, "st_file_attributes", 0))
        return bool(
            stat.S_ISREG(info.st_mode)
            and int(getattr(info, "st_nlink", 1)) == 1
            and not stat.S_ISLNK(info.st_mode)
            and not (attributes & 0x400)
            and info.st_size <= max_bytes
        )

    @staticmethod
    def _read_pinned_regular(
        path: Path, *, max_bytes: int, missing_ok: bool = False
    ) -> bytes | None:
        """Read one exact regular file through a stable, no-follow descriptor."""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise ValueError(f"durable object is missing: {path.name}") from None
        except OSError as exc:
            raise ValueError(f"durable object is unreadable: {path.name}") from exc
        try:
            before = os.fstat(descriptor)
            attributes = int(getattr(before, "st_file_attributes", 0))
            if (
                not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_nlink", 1)) != 1
                or bool(attributes & 0x400)
                or before.st_size > max_bytes
            ):
                raise ValueError(f"durable object is unsafe: {path.name}")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            current = os.lstat(path)
            if (
                len(raw) > max_bytes
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or current.st_dev != after.st_dev
                or current.st_ino != after.st_ino
                or int(getattr(current, "st_nlink", 1)) != 1
            ):
                raise ValueError(f"durable object changed while read: {path.name}")
            return raw
        except OSError as exc:
            raise ValueError(f"durable object is unreadable: {path.name}") from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _highwater_key(self) -> bytes | None:
        key = self._cursor_key()
        if key is None:
            return None
        return hmac.new(key, _HIGHWATER_CONTEXT, hashlib.sha256).digest()

    def _rollback_anchor_key(self) -> bytes | None:
        key = self._cursor_key()
        if key is None:
            return None
        return hmac.new(key, _ROLLBACK_ANCHOR_CONTEXT, hashlib.sha256).digest()

    def _authority_witness_key(self) -> bytes | None:
        key = self._cursor_key()
        if key is None:
            return None
        return hmac.new(key, _AUTHORITY_WITNESS_CONTEXT, hashlib.sha256).digest()

    def _authority_fingerprint(self) -> str:
        key = self._cursor_key()
        if key is None:
            raise RuntimeError("Security cursor signing identity is unavailable")
        return hashlib.sha256(key).hexdigest()

    def _rollback_anchor_name(self) -> str:
        return f"ANGERONA_ETW_ROLLBACK_{self._host_binding()[:32]}"

    def _rollback_anchor_data_root(self) -> Path | None:
        cursor = self.cursor_state_path
        return None if cursor is None else cursor.parent

    def _read_rollback_anchor_value(self) -> str:
        name = self._rollback_anchor_name()
        if self._rollback_anchor_override is not None:
            return str(self._rollback_anchor_override.get(name, ""))
        root = self._rollback_anchor_data_root()
        if root is None:
            raise RuntimeError("rollback anchor data root is unavailable")
        from angerona.core.secure_store import read_secret_values

        return str(read_secret_values((name,), root, strict=True).get(name, ""))

    def _write_rollback_anchor_value(self, value: str) -> None:
        name = self._rollback_anchor_name()
        if self._rollback_anchor_override is not None:
            self._rollback_anchor_override[name] = value
        else:
            root = self._rollback_anchor_data_root()
            if root is None:
                raise RuntimeError("rollback anchor data root is unavailable")
            from angerona.core.secure_store import write_secret_map

            write_secret_map({name: value}, root)
        if not hmac.compare_digest(self._read_rollback_anchor_value(), value):
            raise RuntimeError("rollback anchor verification failed")

    def _read_authority_witness(self) -> dict[str, object] | None:
        path = self.cursor_authority_witness_path
        key = self._authority_witness_key()
        if path is None or key is None:
            raise ValueError("Security authority witness root/key is unavailable")
        raw = self._read_pinned_regular(
            path, max_bytes=_MAX_AUTHORITY_WITNESS_BYTES, missing_ok=True
        )
        if raw is None:
            return None
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, TypeError, ValueError) as exc:
            raise ValueError("Security authority witness is malformed") from exc
        if not isinstance(value, dict) or set(value) != _AUTHORITY_WITNESS_FIELDS:
            raise ValueError("Security authority witness schema mismatch")
        supplied = str(value.pop("record_hmac"))
        expected = hmac.new(
            key, self._cursor_canonical(value), hashlib.sha256
        ).hexdigest()
        cursor_sequence = int(value.get("cursor_sequence") or 0)
        cursor_hmac = str(value.get("cursor_record_hmac") or "")
        highwater_hmac = str(value.get("highwater_record_hmac") or "")
        if (
            value.get("schema") != _AUTHORITY_WITNESS_SCHEMA
            or value.get("host_binding") != self._host_binding()
            or value.get("authority_fingerprint") != self._authority_fingerprint()
            or not re.fullmatch(r"[0-9a-f]{32}", str(value.get("install_epoch") or ""))
            or int(value.get("anchor_revision") or 0) < 1
            or cursor_sequence < 0
            or bool(cursor_sequence) != bool(cursor_hmac)
            or (cursor_hmac and not _HEX64.fullmatch(cursor_hmac))
            or (
                highwater_hmac != _HIGHWATER_GENESIS
                if cursor_sequence == 0
                else not bool(_HEX64.fullmatch(highwater_hmac))
            )
            or not _HEX64.fullmatch(str(value.get("anchor_record_hmac") or ""))
            or not _HEX64.fullmatch(supplied)
            or not hmac.compare_digest(supplied, expected)
        ):
            raise ValueError("Security authority witness authentication failed")
        return {**value, "record_hmac": supplied}

    def _write_authority_witness(self, anchor: dict[str, object]) -> None:
        path = self.cursor_authority_witness_path
        key = self._authority_witness_key()
        if path is None or key is None:
            raise RuntimeError("Security authority witness root/key is unavailable")
        core: dict[str, object] = {
            "schema": _AUTHORITY_WITNESS_SCHEMA,
            "host_binding": self._host_binding(),
            "authority_fingerprint": self._authority_fingerprint(),
            "install_epoch": str(anchor["install_epoch"]),
            "anchor_revision": int(anchor["revision"]),
            "cursor_sequence": int(anchor["cursor_sequence"]),
            "cursor_record_hmac": str(anchor["cursor_record_hmac"]),
            "highwater_record_hmac": str(anchor["highwater_record_hmac"]),
            "anchor_record_hmac": str(anchor["record_hmac"]),
        }
        value = {
            **core,
            "record_hmac": hmac.new(
                key, self._cursor_canonical(core), hashlib.sha256
            ).hexdigest(),
        }
        candidate = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        descriptor: int | None = None
        try:
            from angerona.core.atomic_io import replace_with_retry
            from angerona.core.hardening import (
                ensure_sensitive_parent,
                key_acl_required,
                secure_sensitive_file,
            )

            required = key_acl_required()
            path.parent.mkdir(parents=True, exist_ok=True)
            ensure_sensitive_parent(path, required=required)
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                descriptor = None
                stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(candidate, path)
            secure_sensitive_file(path, required=required)
            observed = self._read_authority_witness()
            if observed is None or not hmac.compare_digest(
                str(observed["record_hmac"]), str(value["record_hmac"])
            ):
                raise RuntimeError("Security authority witness verification failed")
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

    def _verify_authority_witness(self, anchor: dict[str, object]) -> None:
        witness = self._read_authority_witness()
        if witness is None:
            raise ValueError(
                "Security authority witness is missing after installation enrollment"
            )
        if (
            witness["install_epoch"] != anchor["install_epoch"]
            or int(witness["anchor_revision"]) != int(anchor["revision"])
            or int(witness["cursor_sequence"]) != int(anchor["cursor_sequence"])
            or not hmac.compare_digest(
                str(witness["cursor_record_hmac"]),
                str(anchor["cursor_record_hmac"]),
            )
            or not hmac.compare_digest(
                str(witness["highwater_record_hmac"]),
                str(anchor["highwater_record_hmac"]),
            )
            or not hmac.compare_digest(
                str(witness["anchor_record_hmac"]), str(anchor["record_hmac"])
            )
        ):
            raise ValueError(
                "Security rollback anchor violates the signing-identity witness"
            )

    def _decode_rollback_anchor(self, raw: str) -> dict[str, object]:
        key = self._rollback_anchor_key()
        if key is None:
            raise ValueError("rollback anchor authority is unavailable")
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != _ROLLBACK_ANCHOR_FIELDS:
            raise ValueError("rollback anchor schema mismatch")
        supplied = str(value.pop("record_hmac"))
        expected = hmac.new(
            key, self._cursor_canonical(value), hashlib.sha256
        ).hexdigest()
        install_epoch = str(value.get("install_epoch") or "")
        active_nonce = str(value.get("active_challenge_nonce") or "")
        active_state = str(value.get("active_state_digest") or "")
        active_reason = str(value.get("active_reason_digest") or "")
        cursor_sequence = int(value.get("cursor_sequence") or 0)
        cursor_hmac = str(value.get("cursor_record_hmac") or "")
        highwater_hmac = str(value.get("highwater_record_hmac") or "")
        enrollment_id = str(value.get("enrollment_request_id") or "")
        enrollment_digest = str(value.get("enrollment_request_digest") or "")
        state_digest = str(value.get("state_digest") or "")
        if (
            value.get("schema") not in (1, _ROLLBACK_ANCHOR_SCHEMA)
            or value.get("host_binding") != self._host_binding()
            or not re.fullmatch(r"[0-9a-f]{32}", install_epoch)
            or int(value.get("revision") or 0) < 1
            or int(value.get("challenge_counter") or 0) < 0
            or cursor_sequence < 0
            or int(value.get("generation") or 0) < 0
            or int(value.get("last_record") or 0) < 0
            or int(value.get("high_watermark") or 0) < 0
            or int(value.get("last_record") or 0)
            > int(value.get("high_watermark") or 0)
            or bool(active_nonce) != bool(active_state)
            or bool(active_nonce) != bool(active_reason)
            or (active_nonce and not re.fullmatch(r"[0-9a-f]{32}", active_nonce))
            or (active_state and not _HEX64.fullmatch(active_state))
            or (active_reason and not _HEX64.fullmatch(active_reason))
            or bool(cursor_sequence) != bool(cursor_hmac)
            or (cursor_hmac and not _HEX64.fullmatch(cursor_hmac))
            or (
                highwater_hmac != _HIGHWATER_GENESIS
                if cursor_sequence == 0
                else not bool(_HEX64.fullmatch(highwater_hmac))
            )
            or bool(enrollment_id) != bool(enrollment_digest)
            or (enrollment_digest and not _HEX64.fullmatch(enrollment_digest))
            or (state_digest and not _HEX64.fullmatch(state_digest))
            or not _HEX64.fullmatch(supplied)
            or not hmac.compare_digest(supplied, expected)
        ):
            raise ValueError("rollback anchor authentication failed")
        return {**value, "record_hmac": supplied}

    def _encode_rollback_anchor(self, core: dict[str, object]) -> str:
        key = self._rollback_anchor_key()
        if key is None:
            raise RuntimeError("rollback anchor authority is unavailable")
        value = {
            **core,
            "record_hmac": hmac.new(
                key, self._cursor_canonical(core), hashlib.sha256
            ).hexdigest(),
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _initial_rollback_anchor(self) -> dict[str, object]:
        return {
            "schema": _ROLLBACK_ANCHOR_SCHEMA,
            "host_binding": self._host_binding(),
            "install_epoch": secrets.token_hex(16),
            "revision": 1,
            "challenge_counter": 0,
            "active_challenge_nonce": "",
            "active_state_digest": "",
            "active_reason_digest": "",
            "cursor_sequence": 0,
            "cursor_record_hmac": "",
            "highwater_record_hmac": _HIGHWATER_GENESIS,
            "generation": 0,
            "last_record": 0,
            "high_watermark": 0,
            "enrollment_request_id": "",
            "enrollment_request_digest": "",
            "state_digest": "",
        }

    def _rollback_anchor(
        self, *, allow_create: bool, local_state_exists: bool = False
    ) -> dict[str, object]:
        with self._cursor_writer_lease():
            raw = self._read_rollback_anchor_value()
            if not raw:
                if not allow_create or local_state_exists:
                    raise ValueError(
                        "protected rollback anchor is missing; continuity is unprovable"
                    )
                if self._read_authority_witness() is not None:
                    raise ValueError(
                        "protected rollback anchor is missing after installation enrollment"
                    )
                return self._write_rollback_anchor(self._initial_rollback_anchor())
            anchor = self._decode_rollback_anchor(raw)
            if int(anchor["schema"]) == 1:
                # Runtime state may never convert a legacy authority into
                # current telemetry authority. Missing witness state is
                # indistinguishable from witness deletion after rollback. An
                # explicit installer/operator enrollment must establish schema 2.
                raise ValueError(
                    "legacy Security rollback anchor is not runtime authority; "
                    "explicit enrollment/recovery is required"
                )
            self._verify_authority_witness(anchor)
            return anchor

    def _write_rollback_anchor(self, core: dict[str, object]) -> dict[str, object]:
        with self._cursor_writer_lease():
            current = dict(core)
            current["schema"] = _ROLLBACK_ANCHOR_SCHEMA
            encoded = self._encode_rollback_anchor(current)
            self._write_rollback_anchor_value(encoded)
            anchor = self._decode_rollback_anchor(encoded)
            self._write_authority_witness(anchor)
            return anchor

    def _advance_rollback_anchor(self, cursor: dict[str, object]) -> bool:
        try:
            with self._cursor_writer_lease():
                anchor = self._rollback_anchor(allow_create=False)
                sequence = int(cursor["sequence"])
                if sequence <= int(anchor["cursor_sequence"]):
                    raise ValueError("cursor did not advance protected rollback anchor")
                core = {
                    key: value for key, value in anchor.items() if key != "record_hmac"
                }
                core.update({
                    "revision": int(anchor["revision"]) + 1,
                    "cursor_sequence": sequence,
                    "cursor_record_hmac": str(cursor["record_hmac"]),
                    "highwater_record_hmac": self._highwater_record_hmac,
                    "generation": self._security_generation,
                    "last_record": self._last_record,
                    "high_watermark": self._security_high_watermark,
                    "enrollment_request_id": self._last_enrollment_request_id,
                    "enrollment_request_digest": self._last_enrollment_request_digest,
                    "state_digest": self._state_digest(),
                })
                self._write_rollback_anchor(core)
                return True
        except Exception as exc:
            self._mark_security_gap(
                f"protected rollback anchor update failed ({type(exc).__name__})"
            )
            return False

    def _state_digest(self) -> str:
        state = {
            "host_binding": self._host_binding(),
            "generation": self._security_generation,
            "last_record": self._last_record,
            "last_record_anchor": self._last_record_anchor,
            "oldest_observed": self._security_oldest_observed,
            "high_watermark": self._security_high_watermark,
            "gap_reason": self._security_gap,
            "enrolled_at": self._cursor_enrolled_at,
            "enrollment_request_id": self._last_enrollment_request_id,
            "enrollment_request_digest": self._last_enrollment_request_digest,
            "enrollment_reason_digest": self._last_enrollment_reason_digest,
            "install_epoch": self._install_epoch,
            "enrollment_challenge_counter": self._enrollment_challenge_counter,
            "channel_identity_digest": self._channel_identity_digest,
            "channel_identity_oldest": self._channel_identity_oldest,
            "channel_identity_high": self._channel_identity_high,
        }
        return hashlib.sha256(self._cursor_canonical(state)).hexdigest()

    def _enrollment_state_digest(self, reason_text: str) -> str:
        state = {
            "contract": "angerona-security-cursor-enrollment-v2",
            "host_binding": self._host_binding(),
            "install_epoch": self._install_epoch,
            "generation": self._security_generation,
            "cursor_sequence": self._cursor_sequence,
            "last_record": self._last_record,
            "last_record_anchor": self._last_record_anchor,
            "oldest_observed": self._security_oldest_observed,
            "high_watermark": self._security_high_watermark,
            "gap_digest": hashlib.sha256(
                self._security_gap.encode("utf-8", errors="strict")
            ).hexdigest(),
            "reason_digest": hashlib.sha256(
                reason_text.encode("utf-8", errors="strict")
            ).hexdigest(),
            "channel_identity_digest": self._channel_identity_digest,
            "channel_identity_oldest": self._channel_identity_oldest,
            "channel_identity_high": self._channel_identity_high,
        }
        return hashlib.sha256(self._cursor_canonical(state)).hexdigest()

    def security_enrollment_resource(self, reason: str) -> str:
        """Issue a one-process monotonic challenge for the exact current gap."""
        reason_text = " ".join(str(reason).split())[:500]
        with self.state_lock:
            if (
                len(reason_text) < 12
                or not self._cursor_state_loaded
                or not self._security_gap
                or self._security_generation < 1
            ):
                return ""
            state_digest = self._enrollment_state_digest(reason_text)
            reason_digest = hashlib.sha256(
                reason_text.encode("utf-8", errors="strict")
            ).hexdigest()
            active = self._active_enrollment_challenge
            if (
                active is not None
                and active.get("state_digest") == state_digest
                and active.get("reason_digest") == reason_digest
                and time.monotonic() - float(active.get("issued_monotonic", -1.0))
                <= _ENROLLMENT_MAX_AGE_S
            ):
                return str(active.get("resource") or "")
            try:
                with self._cursor_writer_lease():
                    anchor = self._rollback_anchor(allow_create=False)
                    counter = int(anchor["challenge_counter"]) + 1
                    nonce = secrets.token_hex(16)
                    core = {
                        key: value
                        for key, value in anchor.items()
                        if key != "record_hmac"
                    }
                    core.update({
                        "revision": int(anchor["revision"]) + 1,
                        "challenge_counter": counter,
                        "active_challenge_nonce": nonce,
                        "active_state_digest": state_digest,
                        "active_reason_digest": reason_digest,
                    })
                    self._write_rollback_anchor(core)
            except Exception as exc:
                self._mark_security_gap(
                    "protected rollback anchor unavailable for enrollment "
                    f"({type(exc).__name__})"
                )
                return ""
            self._install_epoch = str(anchor["install_epoch"])
            self._enrollment_challenge_counter = counter
            resource = (
                f"Security:{self._install_epoch[:16]}:{counter}:{nonce}:{state_digest}"
            )
            self._active_enrollment_challenge = {
                "resource": resource,
                "state_digest": state_digest,
                "reason_digest": reason_digest,
                "counter": counter,
                "nonce": nonce,
                "issued_monotonic": time.monotonic(),
            }
            return resource

    def _consume_enrollment_challenge(
        self, decision: AuthorizationDecision
    ) -> bool:
        active = self._active_enrollment_challenge
        if active is None:
            return False
        try:
            with self._cursor_writer_lease():
                anchor = self._rollback_anchor(allow_create=False)
                if (
                    int(anchor["challenge_counter"]) != int(active["counter"])
                    or anchor["active_challenge_nonce"] != active["nonce"]
                    or anchor["active_state_digest"] != active["state_digest"]
                    or anchor["active_reason_digest"] != active["reason_digest"]
                ):
                    raise ValueError("enrollment challenge was superseded")
                core = {
                    key: value for key, value in anchor.items() if key != "record_hmac"
                }
                core.update({
                    "revision": int(anchor["revision"]) + 1,
                    "active_challenge_nonce": "",
                    "active_state_digest": "",
                    "active_reason_digest": "",
                    "enrollment_request_id": decision.request_id,
                    "enrollment_request_digest": decision.request_digest,
                    "state_digest": self._state_digest(),
                })
                self._write_rollback_anchor(core)
            self._active_enrollment_challenge = None
            return True
        except Exception as exc:
            self._active_enrollment_challenge = None
            self._mark_security_gap(
                f"enrollment challenge consumption failed ({type(exc).__name__})"
            )
            return False

    def _read_highwater(self) -> list[dict[str, object]]:
        path = self.cursor_highwater_path
        key = self._highwater_key()
        if path is None or key is None:
            return []
        raw = self._read_pinned_regular(
            path, max_bytes=_MAX_HIGHWATER_BYTES, missing_ok=True
        )
        if raw is None:
            return []
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeError as exc:
            raise ValueError("cursor high-water encoding is invalid") from exc
        records: list[dict[str, object]] = []
        previous = _HIGHWATER_GENESIS
        expected_entry = 1
        previous_cursor_sequence = 0
        previous_generation = 0
        previous_last_record = 0
        previous_high_watermark = 0
        previous_challenge_counter = 0
        for line in lines:
            value = json.loads(line)
            if not isinstance(value, dict) or set(value) != _HIGHWATER_FIELDS:
                raise ValueError("cursor high-water schema mismatch")
            supplied = str(value.pop("record_hmac"))
            core = value
            if (
                core.get("schema") != _HIGHWATER_SCHEMA
                or core.get("channel") != "Security"
                or core.get("host_binding") != self._host_binding()
                or core.get("entry_sequence") != expected_entry
                or core.get("previous_hmac") != previous
                or not _HEX64.fullmatch(supplied)
                or not hmac.compare_digest(
                    supplied,
                    hmac.new(
                        key, self._cursor_canonical(core), hashlib.sha256
                    ).hexdigest(),
                )
            ):
                raise ValueError("cursor high-water authentication failed")
            cursor_sequence = int(core["cursor_sequence"])
            generation = int(core["generation"])
            last_record = int(core["last_record"])
            high_watermark = int(core["high_watermark"])
            recorded_at = float(core["recorded_at"])
            enrollment_request_id = str(core["enrollment_request_id"])
            enrollment_request_digest = str(core["enrollment_request_digest"])
            install_epoch = str(core["install_epoch"])
            challenge_counter = int(core["enrollment_challenge_counter"])
            identity_digest = str(core["channel_identity_digest"])
            identity_oldest = int(core["channel_identity_oldest"])
            identity_high = int(core["channel_identity_high"])
            if (
                cursor_sequence <= previous_cursor_sequence
                or generation < 1
                or generation < previous_generation
                or min(last_record, high_watermark) < 0
                or last_record > high_watermark
                or (
                    generation == previous_generation
                    and (
                        last_record < previous_last_record
                        or high_watermark < previous_high_watermark
                    )
                )
                or not math.isfinite(recorded_at)
                or recorded_at < 0
                or not _HEX64.fullmatch(str(core["gap_digest"]))
                or not _HEX64.fullmatch(str(core["cursor_record_hmac"]))
                or (
                    last_record
                    and not _HEX64.fullmatch(str(core["last_record_anchor"]))
                )
                or (not last_record and str(core["last_record_anchor"]))
                or bool(enrollment_request_id) != bool(enrollment_request_digest)
                or not re.fullmatch(r"[0-9a-f]{32}", install_epoch)
                or challenge_counter < previous_challenge_counter
                or min(identity_oldest, identity_high) < 0
                or bool(identity_digest) != bool(identity_high)
                or (identity_digest and not _HEX64.fullmatch(identity_digest))
                or (identity_high and identity_oldest > identity_high)
                or (
                    enrollment_request_digest
                    and not _HEX64.fullmatch(enrollment_request_digest)
                )
            ):
                raise ValueError("cursor high-water values are invalid")
            record = {**core, "record_hmac": supplied}
            records.append(record)
            previous = supplied
            expected_entry += 1
            previous_cursor_sequence = cursor_sequence
            previous_generation = generation
            previous_last_record = last_record
            previous_high_watermark = high_watermark
            previous_challenge_counter = challenge_counter
        return records

    def _highwater_floor(self) -> dict[str, object] | None:
        records = self._read_highwater()
        if not records:
            return None
        latest = records[-1]
        self._highwater_entry_sequence = int(latest["entry_sequence"])
        self._highwater_record_hmac = str(latest["record_hmac"])
        return latest

    def _adopt_highwater_floor(self, latest: dict[str, object] | None) -> None:
        if latest is None:
            return
        self._cursor_sequence = max(
            self._cursor_sequence, int(latest["cursor_sequence"])
        )
        self._security_generation = max(
            self._security_generation, int(latest["generation"]) + 1
        )

    def _adopt_rollback_floor(self, anchor: dict[str, object]) -> None:
        self._install_epoch = str(anchor["install_epoch"])
        self._enrollment_challenge_counter = int(anchor["challenge_counter"])
        self._cursor_sequence = max(
            self._cursor_sequence, int(anchor["cursor_sequence"])
        )
        if int(anchor["cursor_sequence"]) > 0:
            self._security_generation = max(
                self._security_generation, int(anchor["generation"]) + 1
            )

    def _append_highwater(self, cursor: dict[str, object]) -> bool:
        path = self.cursor_highwater_path
        key = self._highwater_key()
        if path is None or key is None:
            return False

        descriptor: int | None = None
        try:
            from angerona.core.hardening import (
                ensure_sensitive_parent,
                key_acl_required,
                secure_sensitive_file,
            )

            latest = self._highwater_floor()
            if latest is None and (
                self._highwater_entry_sequence != 0
                or self._highwater_record_hmac != _HIGHWATER_GENESIS
            ):
                raise ValueError("non-genesis Security high-water disappeared")
            if latest is not None and (
                int(latest["entry_sequence"]) != self._highwater_entry_sequence
                or not hmac.compare_digest(
                    str(latest["record_hmac"]), self._highwater_record_hmac
                )
            ):
                raise ValueError("Security high-water changed under another writer")
            cursor_sequence = int(cursor["sequence"])
            if latest is not None and cursor_sequence <= int(
                latest["cursor_sequence"]
            ):
                raise ValueError("cursor sequence did not advance high-water")
            core: dict[str, object] = {
                "schema": _HIGHWATER_SCHEMA,
                "channel": "Security",
                "host_binding": self._host_binding(),
                "entry_sequence": self._highwater_entry_sequence + 1,
                "cursor_sequence": cursor_sequence,
                "generation": self._security_generation,
                "last_record": self._last_record,
                "last_record_anchor": self._last_record_anchor,
                "high_watermark": self._security_high_watermark,
                "gap_digest": hashlib.sha256(
                    self._security_gap.encode("utf-8", errors="strict")
                ).hexdigest(),
                "cursor_record_hmac": str(cursor["record_hmac"]),
                "enrollment_request_id": self._last_enrollment_request_id,
                "enrollment_request_digest": self._last_enrollment_request_digest,
                "install_epoch": self._install_epoch,
                "enrollment_challenge_counter": self._enrollment_challenge_counter,
                "channel_identity_digest": self._channel_identity_digest,
                "channel_identity_oldest": self._channel_identity_oldest,
                "channel_identity_high": self._channel_identity_high,
                "recorded_at": time.time(),
                "previous_hmac": self._highwater_record_hmac,
            }
            value = {
                **core,
                "record_hmac": hmac.new(
                    key, self._cursor_canonical(core), hashlib.sha256
                ).hexdigest(),
            }
            encoded = (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode(
                "utf-8", errors="strict"
            )
            required = key_acl_required()
            path.parent.mkdir(parents=True, exist_ok=True)
            ensure_sensitive_parent(path, required=required)
            if path.exists() and not self._safe_cursor_file(
                path, max_bytes=_MAX_HIGHWATER_BYTES
            ):
                raise ValueError("cursor high-water object is unsafe")
            existing_size = path.stat(follow_symlinks=False).st_size if path.exists() else 0
            if existing_size + len(encoded) > _MAX_HIGHWATER_BYTES:
                raise ValueError("cursor high-water capacity is exhausted")
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            before = os.fstat(descriptor)
            with os.fdopen(descriptor, "ab") as stream:
                descriptor = None
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
                after = os.fstat(stream.fileno())
            current = os.lstat(path)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or current.st_dev != after.st_dev
                or current.st_ino != after.st_ino
                or int(getattr(current, "st_nlink", 1)) != 1
            ):
                raise ValueError("cursor high-water identity changed during append")
            secure_sensitive_file(path, required=required)
            self._highwater_entry_sequence += 1
            self._highwater_record_hmac = str(value["record_hmac"])
            return True
        except Exception as exc:
            self._mark_security_gap(
                "Security cursor high-water write failed "
                f"({str(exc)[:200] or type(exc).__name__})"
            )
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _authenticated_cursor_document(self) -> dict[str, object]:
        path = self.cursor_state_path
        key = self._cursor_key()
        if path is None or key is None:
            raise ValueError("durable Security cursor authority is unavailable")
        raw = self._read_pinned_regular(path, max_bytes=64 * 1024)
        assert raw is not None
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, TypeError, ValueError) as exc:
            raise ValueError("cursor document is malformed") from exc
        if not isinstance(value, dict) or set(value) != _CURSOR_FIELDS:
            raise ValueError("cursor schema mismatch")
        supplied = str(value.pop("record_hmac"))
        if not _HEX64.fullmatch(supplied) or not hmac.compare_digest(
            supplied,
            hmac.new(key, self._cursor_canonical(value), hashlib.sha256).hexdigest(),
        ):
            raise ValueError("cursor authentication failed")
        return {**value, "record_hmac": supplied}

    def _load_cursor_state(self) -> None:
        if self._cursor_state_loaded:
            return
        self._cursor_state_loaded = True
        path = self.cursor_state_path
        key = self._cursor_key()
        highwater_path = self.cursor_highwater_path
        local_state_exists = bool(
            (path is not None and path.exists())
            or (highwater_path is not None and highwater_path.exists())
        )
        try:
            rollback_anchor = self._rollback_anchor(
                allow_create=True, local_state_exists=local_state_exists
            )
            self._adopt_rollback_floor(rollback_anchor)
        except Exception as exc:
            self._cursor_state_error = (
                "protected Security rollback anchor is unavailable or unverifiable "
                f"({str(exc)[:200] or type(exc).__name__}); health cannot be complete"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        try:
            latest_highwater = self._highwater_floor()
        except Exception as exc:
            self._cursor_state_error = (
                "Security cursor high-water is unverifiable "
                f"({str(exc)[:200] or type(exc).__name__}); "
                "explicit recovery required"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        if path is None or key is None:
            self._cursor_state_error = (
                "host-bound cursor authority unavailable; explicit enrollment required"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        if not path.exists():
            self._adopt_highwater_floor(latest_highwater)
            self._cursor_state_error = (
                "durable Security cursor/high-water is missing after protected "
                "anchor enrollment; fresh distinct enrollment required"
                if int(rollback_anchor["cursor_sequence"]) > 0
                else "durable Security cursor is missing; explicit enrollment required"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        if not self._safe_cursor_file(path):
            self._adopt_highwater_floor(latest_highwater)
            self._cursor_state_error = (
                "durable Security cursor object is unsafe; explicit enrollment required"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        try:
            value = self._authenticated_cursor_document()
            supplied = str(value.pop("record_hmac"))
            if (
                value.get("schema") != _CURSOR_SCHEMA
                or value.get("channel") != "Security"
                or value.get("host_binding") != self._host_binding()
            ):
                raise ValueError("cursor host/channel binding mismatch")
            sequence = int(value["sequence"])
            generation = int(value["generation"])
            last_record = int(value["last_record"])
            oldest = int(value["oldest_observed"])
            high = int(value["high_watermark"])
            enrolled_at = float(value["enrolled_at"])
            updated_at = float(value["updated_at"])
            anchor = str(value["last_record_anchor"])
            gap = str(value["gap_reason"])
            enrollment_request_id = str(value["enrollment_request_id"])
            enrollment_request_digest = str(value["enrollment_request_digest"])
            enrollment_reason_digest = str(value["enrollment_reason_digest"])
            install_epoch = str(value["install_epoch"])
            challenge_counter = int(value["enrollment_challenge_counter"])
            identity_digest = str(value["channel_identity_digest"])
            identity_oldest = int(value["channel_identity_oldest"])
            identity_high = int(value["channel_identity_high"])
            if (
                sequence < 1
                or generation < 1
                or min(last_record, oldest, high) < 0
                or last_record > high
                or (last_record and not _HEX64.fullmatch(anchor))
                or (not last_record and anchor)
                or not all(math.isfinite(stamp) and stamp >= 0 for stamp in (
                    enrolled_at, updated_at
                ))
                or updated_at < enrolled_at
                or len(gap) > 1000
                or bool(enrollment_request_id) != bool(enrollment_request_digest)
                or bool(enrollment_request_id) != bool(enrollment_reason_digest)
                or (
                    enrollment_request_digest
                    and not _HEX64.fullmatch(enrollment_request_digest)
                )
                or (
                    enrollment_reason_digest
                    and not _HEX64.fullmatch(enrollment_reason_digest)
                )
                or install_epoch != rollback_anchor["install_epoch"]
                or challenge_counter < 0
                or min(identity_oldest, identity_high) < 0
                or bool(identity_digest) != bool(identity_high)
                or (identity_digest and not _HEX64.fullmatch(identity_digest))
                or (identity_high and identity_oldest > identity_high)
            ):
                raise ValueError("cursor values are invalid")
            if latest_highwater is None:
                raise ValueError("independent cursor high-water is missing")
            highwater_sequence = int(latest_highwater["cursor_sequence"])
            if sequence < highwater_sequence:
                raise ValueError("authenticated cursor rollback detected")
            if sequence > highwater_sequence:
                raise ValueError("cursor/high-water transaction is incomplete")
            if str(latest_highwater["cursor_record_hmac"]) != supplied:
                raise ValueError("cursor does not match authenticated high-water")
            if sequence != int(rollback_anchor["cursor_sequence"]):
                raise ValueError("protected rollback-anchor sequence mismatch")
            if supplied != rollback_anchor["cursor_record_hmac"]:
                raise ValueError("protected rollback-anchor cursor mismatch")
            if (
                str(latest_highwater["record_hmac"])
                != rollback_anchor["highwater_record_hmac"]
            ):
                raise ValueError("protected rollback-anchor high-water mismatch")
            if challenge_counter > int(rollback_anchor["challenge_counter"]):
                raise ValueError("enrollment challenge counter rollback detected")
            if (
                latest_highwater["install_epoch"] != install_epoch
                or int(latest_highwater["enrollment_challenge_counter"])
                != challenge_counter
                or latest_highwater["channel_identity_digest"] != identity_digest
                or int(latest_highwater["channel_identity_oldest"]) != identity_oldest
                or int(latest_highwater["channel_identity_high"]) != identity_high
            ):
                raise ValueError("cursor/high-water continuity identity mismatch")
        except Exception as exc:
            self._adopt_highwater_floor(latest_highwater)
            self._cursor_state_error = (
                "durable Security cursor is unverifiable "
                f"({str(exc)[:200] or type(exc).__name__}); "
                "explicit enrollment required"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        self._cursor_sequence = sequence
        self._security_generation = generation
        self._last_record = last_record
        self._last_record_anchor = anchor
        self._security_oldest_observed = oldest
        self._security_high_watermark = high
        self._cursor_enrolled_at = enrolled_at
        self._last_enrollment_request_id = enrollment_request_id
        self._last_enrollment_request_digest = enrollment_request_digest
        self._last_enrollment_reason_digest = enrollment_reason_digest
        self._install_epoch = install_epoch
        self._enrollment_challenge_counter = challenge_counter
        self._channel_identity_digest = identity_digest
        self._channel_identity_oldest = identity_oldest
        self._channel_identity_high = identity_high
        self._cursor_record_hmac = supplied
        self._security_gap = gap
        if (
            rollback_anchor["state_digest"]
            and not hmac.compare_digest(
                str(rollback_anchor["state_digest"]), self._state_digest()
            )
        ):
            self._cursor_state_error = (
                "protected rollback anchor state digest mismatch; explicit "
                "enrollment required"
            )
            self._mark_security_gap(self._cursor_state_error)
            return
        self._cursor_enrolled = True
        self._last_persisted_state_digest = self._state_digest()
        if gap:
            self._mark_security_gap(gap)

    def _live_durable_state_matches(self) -> bool:
        """Verify exact cached cursor/high-water/anchor objects before any commit."""
        path = self.cursor_state_path
        highwater_path = self.cursor_highwater_path
        if path is None or highwater_path is None:
            raise ValueError("Security cursor durable root is unavailable")
        anchor = self._rollback_anchor(allow_create=False)
        if self._cursor_sequence == 0:
            if path.exists() or highwater_path.exists():
                raise ValueError("unexpected durable Security state appeared")
            return bool(
                int(anchor["cursor_sequence"]) == 0
                and not anchor["cursor_record_hmac"]
                and anchor["highwater_record_hmac"] == _HIGHWATER_GENESIS
            )

        # Explicit recovery after local cursor/high-water loss is permitted only
        # before this instance owns a cursor HMAC. The protected anchor and its
        # signing-identity witness remain the authenticated starting floor.
        if not self._cursor_record_hmac:
            if not highwater_path.exists():
                return bool(
                    not path.exists()
                    and int(anchor["cursor_sequence"]) == self._cursor_sequence
                    and _HEX64.fullmatch(str(anchor["cursor_record_hmac"]))
                    and _HEX64.fullmatch(str(anchor["highwater_record_hmac"]))
                )
            if path.exists() and not self._safe_cursor_file(path):
                raise ValueError("untrusted Security cursor cannot be replaced")
            records = self._read_highwater()
            if not records:
                raise ValueError("recovery Security high-water is missing")
            latest = records[-1]
            return bool(
                int(latest["entry_sequence"]) == self._highwater_entry_sequence
                and hmac.compare_digest(
                    str(latest["record_hmac"]), self._highwater_record_hmac
                )
                and int(latest["cursor_sequence"]) == self._cursor_sequence
                and int(anchor["cursor_sequence"]) == self._cursor_sequence
                and hmac.compare_digest(
                    str(anchor["cursor_record_hmac"]),
                    str(latest["cursor_record_hmac"]),
                )
                and hmac.compare_digest(
                    str(anchor["highwater_record_hmac"]),
                    str(latest["record_hmac"]),
                )
            )

        document = self._authenticated_cursor_document()
        records = self._read_highwater()
        if not records:
            raise ValueError("live Security cursor high-water is missing")
        latest = records[-1]
        supplied = str(document["record_hmac"])
        if (
            int(document["sequence"]) != self._cursor_sequence
            or not hmac.compare_digest(supplied, self._cursor_record_hmac)
            or document["install_epoch"] != self._install_epoch
            or int(latest["entry_sequence"]) != self._highwater_entry_sequence
            or not hmac.compare_digest(
                str(latest["record_hmac"]), self._highwater_record_hmac
            )
            or int(latest["cursor_sequence"]) != self._cursor_sequence
            or not hmac.compare_digest(
                str(latest["cursor_record_hmac"]), self._cursor_record_hmac
            )
            or int(anchor["cursor_sequence"]) != self._cursor_sequence
            or not hmac.compare_digest(
                str(anchor["cursor_record_hmac"]), self._cursor_record_hmac
            )
            or not hmac.compare_digest(
                str(anchor["highwater_record_hmac"]), self._highwater_record_hmac
            )
        ):
            raise ValueError("live Security cursor transaction identity changed")
        return True

    def _persist_cursor_state(self) -> bool:
        if not self._cursor_enrolled:
            return False
        path = self.cursor_state_path
        key = self._cursor_key()
        if path is None or key is None:
            self._mark_security_gap("durable Security cursor authority became unavailable")
            return False
        state_digest = self._state_digest()
        try:
            with self._cursor_writer_lease():
                if not self._live_durable_state_matches():
                    raise ValueError("live Security cursor objects do not match")
                if (
                    state_digest == self._last_persisted_state_digest
                    and _HEX64.fullmatch(self._cursor_record_hmac)
                ):
                    persisted = True
                else:
                    persisted = self._commit_cursor_state(path, key, state_digest)
                outbox_path = self.security_delivery_outbox_path
                custody_path = self.security_delivery_custody_path
                delivery_pending = bool(
                    outbox_path is not None
                    and (outbox_path.exists() or outbox_path.is_symlink())
                    or custody_path is not None
                    and (custody_path.exists() or custody_path.is_symlink())
                )
                if persisted and not delivery_pending:
                    self._write_security_delivery_ack()
                return persisted
        except Exception as exc:
            self._mark_security_gap(
                "durable Security cursor transaction failed "
                f"({str(exc)[:200] or type(exc).__name__})"
            )
            return False

    def _commit_cursor_state(
        self, path: Path, key: bytes, state_digest: str
    ) -> bool:
        """Commit high-water, cursor, then protected witness under one lease."""
        core: dict[str, object] = {
            "schema": _CURSOR_SCHEMA,
            "channel": "Security",
            "host_binding": self._host_binding(),
            "sequence": self._cursor_sequence + 1,
            "generation": self._security_generation,
            "last_record": self._last_record,
            "last_record_anchor": self._last_record_anchor,
            "oldest_observed": self._security_oldest_observed,
            "high_watermark": self._security_high_watermark,
            "gap_reason": self._security_gap,
            "enrolled_at": self._cursor_enrolled_at,
            "enrollment_request_id": self._last_enrollment_request_id,
            "enrollment_request_digest": self._last_enrollment_request_digest,
            "enrollment_reason_digest": self._last_enrollment_reason_digest,
            "install_epoch": self._install_epoch,
            "enrollment_challenge_counter": self._enrollment_challenge_counter,
            "channel_identity_digest": self._channel_identity_digest,
            "channel_identity_oldest": self._channel_identity_oldest,
            "channel_identity_high": self._channel_identity_high,
            "updated_at": time.time(),
        }
        value = {
            **core,
            "record_hmac": hmac.new(
                key, self._cursor_canonical(core), hashlib.sha256
            ).hexdigest(),
        }
        candidate = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        descriptor: int | None = None
        try:
            from angerona.core.atomic_io import replace_with_retry
            from angerona.core.hardening import (
                ensure_sensitive_parent,
                key_acl_required,
                secure_sensitive_file,
            )

            required = key_acl_required()
            path.parent.mkdir(parents=True, exist_ok=True)
            ensure_sensitive_parent(path, required=required)
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                descriptor = None
                stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if not self._append_highwater(value):
                return False
            replace_with_retry(candidate, path)
            secure_sensitive_file(path, required=required)
            self._cursor_sequence += 1
            self._cursor_record_hmac = str(value["record_hmac"])
            if not self._advance_rollback_anchor(value):
                return False
            if not self._live_durable_state_matches():
                raise ValueError("completed Security cursor transaction did not verify")
            self._last_persisted_state_digest = state_digest
            return True
        except Exception as exc:
            self._mark_security_gap(
                f"durable Security cursor write failed ({type(exc).__name__})"
            )
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

    def _channel_identity(
        self, win32evtlog, handle, oldest: int, high: int
    ) -> tuple[int, int, str] | None:
        """Hash every retained record in one bounded, exact forward window."""
        if (
            oldest <= 0
            or high < oldest
            or high - oldest + 1 > _MAX_SECURITY_IDENTITY_RECORDS
        ):
            return None
        digest = hashlib.sha256()
        next_record = oldest
        observed = 0
        identity_bytes = 0
        started = time.monotonic()
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        while next_record <= high and observed <= _MAX_SECURITY_IDENTITY_RECORDS:
            if time.monotonic() - started > _MAX_SECURITY_READ_S:
                return None
            batch = win32evtlog.ReadEventLog(handle, flags, next_record) or []
            progressed = False
            for event in batch:
                record = int(getattr(event, "RecordNumber", 0))
                if record < next_record:
                    continue
                if record > high:
                    break
                if record != next_record:
                    return None
                try:
                    anchor, record_bytes = self._record_anchor_with_size(event)
                except (TypeError, UnicodeError, ValueError):
                    return None
                identity_bytes += record_bytes
                if identity_bytes > _MAX_SECURITY_IDENTITY_BYTES:
                    return None
                digest.update(f"{record}:".encode("ascii"))
                digest.update(anchor.encode("ascii"))
                digest.update(b"\n")
                next_record += 1
                observed += 1
                progressed = True
            if not progressed:
                return None
        if next_record != high + 1 or observed != high - oldest + 1:
            return None
        return oldest, high, digest.hexdigest()

    def _enrollment_identity_snapshot(self) -> tuple[int, int, str] | None:
        try:
            import win32evtlog  # type: ignore

            handle = win32evtlog.OpenEventLog(None, "Security")
            try:
                oldest, high_watermark, _count = self._channel_bounds(
                    win32evtlog, handle
                )
                if not (
                    oldest == self._security_oldest_observed
                    and high_watermark == self._security_high_watermark
                    and self._last_record == high_watermark
                    and (
                        self._last_record == 0
                        or self._validate_bookmark(win32evtlog, handle)
                    )
                ):
                    return None
                return self._channel_identity(
                    win32evtlog, handle, oldest, high_watermark
                )
            finally:
                win32evtlog.CloseEventLog(handle)
        except Exception:
            return None

    def _enrollment_bounds_match(self) -> bool:
        return self._enrollment_identity_snapshot() is not None

    def _saved_channel_identity_matches(self, win32evtlog, handle) -> bool:
        if not self._channel_identity_digest:
            return True
        identity = self._channel_identity(
            win32evtlog,
            handle,
            self._channel_identity_oldest,
            self._channel_identity_high,
        )
        return bool(
            identity is not None
            and hmac.compare_digest(identity[2], self._channel_identity_digest)
        )

    def enroll_security_cursor(
        self,
        *,
        decision: AuthorizationDecision,
        reason: str,
    ) -> dict[str, object]:
        """Acknowledge a caught-up cursor as this host's continuity baseline.

        Enrollment is deliberately impossible during backlog or without a recent
        successful channel-bounds read.  It also requires a fresh, HMAC-valid
        human policy approval bound to the exact Security channel.  This is the
        sole path that clears a missing, corrupt, or generation-gap condition.
        """
        reason_text = " ".join(str(reason).split())[:500]
        policy = getattr(
            self._manager, "telemetry_enrollment_authorization_policy", None
        )
        if (
            not isinstance(decision, AuthorizationDecision)
            or not isinstance(policy, AuthorizationPolicy)
            or len(reason_text) < 12
        ):
            return {"ok": False, "error": "authenticated enrollment approval required"}
        with self.state_lock:
            stamp = time.time()
            expected_resource = self.security_enrollment_resource(reason_text)
            active = self._active_enrollment_challenge
            try:
                verified = policy.verify_decision(decision)
            except Exception:
                verified = False
            if not (
                expected_resource
                and active is not None
                and time.monotonic() - float(active.get("issued_monotonic", -1.0))
                <= _ENROLLMENT_MAX_AGE_S
                and active.get("state_digest")
                == self._enrollment_state_digest(reason_text)
                and verified
                and decision.allowed
                and decision.principal_kind == "human"
                and decision.permission == "policy.approve"
                and decision.scope == _ENROLLMENT_SCOPE
                and decision.resource_id == expected_resource
                and decision.request_id != self._last_enrollment_request_id
                and decision.request_digest != self._last_enrollment_request_digest
            ):
                return {"ok": False, "error": "enrollment approval receipt rejected"}

            pre_identity = self._enrollment_identity_snapshot()
            safe_window = (
                self._cursor_state_loaded
                and bool(self._security_gap)
                and self.cursor_state_path is not None
                and self._cursor_key() is not None
                and self._security_bounds_checked_monotonic > 0
                and time.monotonic() - self._security_bounds_checked_monotonic
                <= _ENROLLMENT_WINDOW_S
                and not self._security_backlog
                and self._last_record == self._security_high_watermark
                and self._security_generation >= 1
                and pre_identity is not None
            )
            if not safe_window:
                return {
                    "ok": False,
                    "error": (
                        "Security cursor is not caught up inside an exact safe "
                        "enrollment window"
                    ),
                }

            previous = (
                self._security_gap,
                self._cursor_state_error,
                self._cursor_enrolled,
                self._cursor_enrolled_at,
                self._last_enrollment_request_id,
                self._last_enrollment_request_digest,
                self._last_enrollment_reason_digest,
                self._channel_identity_digest,
                self._channel_identity_oldest,
                self._channel_identity_high,
            )
            self._security_gap = ""
            self._cursor_state_error = ""
            self._cursor_enrolled = True
            self._cursor_enrolled_at = stamp
            self._last_enrollment_request_id = decision.request_id
            self._last_enrollment_request_digest = decision.request_digest
            self._last_enrollment_reason_digest = hashlib.sha256(
                reason_text.encode("utf-8", errors="strict")
            ).hexdigest()
            assert pre_identity is not None
            (
                self._channel_identity_oldest,
                self._channel_identity_high,
                self._channel_identity_digest,
            ) = pre_identity
            if not self._persist_cursor_state():
                (
                    previous_gap,
                    self._cursor_state_error,
                    self._cursor_enrolled,
                    self._cursor_enrolled_at,
                    self._last_enrollment_request_id,
                    self._last_enrollment_request_digest,
                    self._last_enrollment_reason_digest,
                    self._channel_identity_digest,
                    self._channel_identity_oldest,
                    self._channel_identity_high,
                ) = previous
                self._mark_security_gap(
                    previous_gap or "Security cursor enrollment was not durable"
                )
                return {
                    "ok": False,
                    "error": "Security cursor enrollment was not durable",
                }
            post_identity = self._enrollment_identity_snapshot()
            if post_identity != pre_identity:
                self._mark_security_gap(
                    "Security channel identity changed across enrollment commit"
                )
                self._persist_cursor_state()
                self._consume_enrollment_challenge(decision)
                return {
                    "ok": False,
                    "error": "Security channel changed during enrollment",
                }
            if not self._consume_enrollment_challenge(decision):
                self._persist_cursor_state()
                return {
                    "ok": False,
                    "error": "protected enrollment challenge was not consumed",
                }
            self.set_health(
                100,
                "Security channel continuity explicitly enrolled within the local "
                "signing-identity witness boundary: "
                f"generation={self._security_generation}, bookmark={self._last_record}",
            )
            return {
                "ok": True,
                "channel": "Security",
                "generation": self._security_generation,
                "bookmark": self._last_record,
                "reason": reason_text,
                "authorization_request_id": decision.request_id,
            }

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── ETW / Security channel ───────────────────────────────────────────────
    @staticmethod
    def _event_identity_scalar(value: object, *, timestamp: bool = False) -> bytes:
        if value is None:
            return b"null"
        if isinstance(value, bytes):
            if len(value) > _MAX_SECURITY_RECORD_IDENTITY_BYTES:
                raise ValueError("Security event binary field exceeds identity budget")
            return b"bytes\0" + value
        if type(value) is bool:
            return b"bool\0" + (b"1" if value else b"0")
        if type(value) is int:
            return b"int\0" + str(value).encode("ascii")
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("Security event contains a non-finite number")
            return b"float\0" + value.hex().encode("ascii")
        if timestamp:
            try:
                value = value.isoformat()  # type: ignore[union-attr]
            except (AttributeError, TypeError, ValueError):
                pass
        if isinstance(value, str):
            if len(value) > _MAX_SECURITY_RECORD_IDENTITY_BYTES:
                raise ValueError("Security event text field exceeds identity budget")
            return b"text\0" + value.encode("utf-8", errors="strict")
        rendered = str(value)
        if len(rendered) > _MAX_SECURITY_RECORD_IDENTITY_BYTES:
            raise ValueError("Security event rendered field exceeds identity budget")
        return b"rendered\0" + rendered.encode("utf-8", errors="strict")

    @classmethod
    def _record_anchor_with_size(cls, event: object) -> tuple[str, int]:
        """Hash every complete consumed/native event field within a hard budget."""
        digest = hashlib.sha256()
        consumed = 0

        def feed(name: str, payload: bytes) -> None:
            nonlocal consumed
            name_bytes = name.encode("ascii", errors="strict")
            framed = (
                len(name_bytes).to_bytes(4, "big")
                + name_bytes
                + len(payload).to_bytes(8, "big")
                + payload
            )
            consumed += len(framed)
            if consumed > _MAX_SECURITY_RECORD_IDENTITY_BYTES:
                raise ValueError("Security event identity exceeds the complete-record budget")
            digest.update(framed)

        fields = (
            ("RecordNumber", False),
            ("EventID", False),
            ("EventType", False),
            ("EventCategory", False),
            ("ReservedFlags", False),
            ("ClosingRecordNumber", False),
            ("TimeGenerated", True),
            ("TimeWritten", True),
            ("SourceName", False),
            ("ComputerName", False),
            ("Sid", False),
            ("Data", False),
        )
        for name, timestamp in fields:
            feed(
                name,
                cls._event_identity_scalar(
                    getattr(event, name, None), timestamp=timestamp
                ),
            )
        inserts = getattr(event, "StringInserts", None)
        if inserts is None:
            inserts = ()
        if not isinstance(inserts, (list, tuple)):
            raise ValueError("Security event insertion fields are not representable")
        if len(inserts) > _MAX_SECURITY_EVENT_INSERTS:
            raise ValueError("Security event insertion count exceeds identity budget")
        feed("StringInserts.count", str(len(inserts)).encode("ascii"))
        for index, value in enumerate(inserts):
            feed(
                f"StringInserts.{index}", cls._event_identity_scalar(value)
            )
        return digest.hexdigest(), consumed

    @classmethod
    def _record_anchor(cls, event: object) -> str:
        """Fingerprint one complete event-log record or fail incomplete."""
        return cls._record_anchor_with_size(event)[0]

    @staticmethod
    def _delivery_event_identity(
        generation: int, record: int, record_anchor: str
    ) -> str:
        return hashlib.sha256(
            f"{generation}|{record}|{record_anchor}".encode("ascii", "strict")
        ).hexdigest()

    @staticmethod
    def _delivery_insert(value: object) -> object:
        """Convert a native insertion value to one bounded JSON scalar."""
        if value is None or type(value) in {bool, int}:
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("Security event contains a non-finite insertion")
            return value
        if isinstance(value, bytes):
            if len(value) > _MAX_SECURITY_RECORD_IDENTITY_BYTES:
                raise ValueError("Security event insertion exceeds delivery budget")
            return f"bytes:{value.hex()}"
        rendered = value if isinstance(value, str) else str(value)
        encoded = rendered.encode("utf-8", errors="strict")
        if len(encoded) > _MAX_SECURITY_RECORD_IDENTITY_BYTES:
            raise ValueError("Security event insertion exceeds delivery budget")
        return rendered

    def _delivery_outbox_key(self) -> bytes:
        key = self._cursor_key()
        if key is None:
            raise ValueError("Security delivery authority is unavailable")
        return hmac.new(key, _DELIVERY_OUTBOX_CONTEXT, hashlib.sha256).digest()

    def _delivery_outbox_mac(self, core: dict[str, object]) -> str:
        return hmac.new(
            self._delivery_outbox_key(),
            self._cursor_canonical(core),
            hashlib.sha256,
        ).hexdigest()

    def _delivery_ack_key(self) -> bytes:
        key = self._cursor_key()
        if key is None:
            raise ValueError("Security delivery acknowledgement authority is unavailable")
        return hmac.new(key, _DELIVERY_ACK_CONTEXT, hashlib.sha256).digest()

    def _delivery_ack_mac(self, core: dict[str, object]) -> str:
        return hmac.new(
            self._delivery_ack_key(),
            self._cursor_canonical(core),
            hashlib.sha256,
        ).hexdigest()

    def _write_security_delivery_ack(self, outbox_record_hmac: str = "") -> None:
        path = self.security_delivery_ack_path
        if path is None:
            raise ValueError("Security delivery acknowledgement root is unavailable")
        if outbox_record_hmac and not _HEX64.fullmatch(outbox_record_hmac):
            raise ValueError("Security delivery acknowledgement batch is invalid")
        core: dict[str, object] = {
            "schema": _DELIVERY_ACK_SCHEMA,
            "channel": "Security",
            "host_binding": self._host_binding(),
            "cursor_sequence": self._cursor_sequence,
            "cursor_record_hmac": self._cursor_record_hmac,
            "target_generation": self._security_generation,
            "target_last_record": self._last_record,
            "target_last_record_anchor": self._last_record_anchor,
            "outbox_record_hmac": outbox_record_hmac,
            "acknowledged_at": time.time(),
        }
        if (
            self._cursor_sequence < 1
            or not _HEX64.fullmatch(self._cursor_record_hmac)
            or self._security_generation < 1
            or self._last_record < 0
            or bool(self._last_record) != bool(self._last_record_anchor)
            or (
                self._last_record_anchor
                and not _HEX64.fullmatch(self._last_record_anchor)
            )
        ):
            raise ValueError("Security delivery acknowledgement cursor is invalid")
        value = {**core, "record_hmac": self._delivery_ack_mac(core)}
        payload = self._cursor_canonical(value) + b"\n"
        if len(payload) > _MAX_DELIVERY_ACK_BYTES:
            raise ValueError("Security delivery acknowledgement exceeds its byte bound")
        candidate = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        descriptor: int | None = None
        try:
            from angerona.core.atomic_io import replace_with_retry
            from angerona.core.hardening import (
                ensure_sensitive_parent,
                key_acl_required,
                secure_sensitive_file,
            )

            required = key_acl_required()
            path.parent.mkdir(parents=True, exist_ok=True)
            ensure_sensitive_parent(path, required=required)
            descriptor = os.open(
                candidate,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(candidate, path)
            secure_sensitive_file(path, required=required)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_security_delivery_ack(self) -> dict[str, object] | None:
        path = self.security_delivery_ack_path
        if path is None:
            return None
        raw = self._read_pinned_regular(
            path, max_bytes=_MAX_DELIVERY_ACK_BYTES, missing_ok=True
        )
        if raw is None:
            return None
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (MemoryError, RecursionError, UnicodeError, TypeError, ValueError) as exc:
            raise ValueError("Security delivery acknowledgement is unreadable") from exc
        if not isinstance(value, dict) or set(value) != _DELIVERY_ACK_FIELDS:
            raise ValueError("Security delivery acknowledgement schema is invalid")
        supplied = value.pop("record_hmac")
        integer_fields = (
            "schema",
            "cursor_sequence",
            "target_generation",
            "target_last_record",
        )
        if any(type(value.get(field)) is not int for field in integer_fields):
            raise ValueError("Security delivery acknowledgement values are invalid")
        cursor_hmac = value.get("cursor_record_hmac")
        target_anchor = value.get("target_last_record_anchor")
        outbox_hmac = value.get("outbox_record_hmac")
        acknowledged_at = value.get("acknowledged_at")
        if (
            value.get("schema") != _DELIVERY_ACK_SCHEMA
            or value.get("channel") != "Security"
            or value.get("host_binding") != self._host_binding()
            or int(value["cursor_sequence"]) < 1
            or int(value["target_generation"]) < 1
            or int(value["target_last_record"]) < 0
            or not isinstance(cursor_hmac, str)
            or not _HEX64.fullmatch(cursor_hmac)
            or not isinstance(target_anchor, str)
            or bool(value["target_last_record"]) != bool(target_anchor)
            or bool(target_anchor) and not _HEX64.fullmatch(target_anchor)
            or not isinstance(outbox_hmac, str)
            or bool(outbox_hmac) and not _HEX64.fullmatch(outbox_hmac)
            or type(acknowledged_at) not in {int, float}
            or not math.isfinite(float(acknowledged_at))
            or float(acknowledged_at) < 0
            or not isinstance(supplied, str)
            or not _HEX64.fullmatch(supplied)
            or not hmac.compare_digest(supplied, self._delivery_ack_mac(value))
        ):
            raise ValueError("Security delivery acknowledgement authentication failed")
        return {**value, "record_hmac": supplied}

    def _security_delivery_ack_matches_cursor(self) -> bool:
        acknowledgement = self._read_security_delivery_ack()
        return bool(
            acknowledgement is not None
            and acknowledgement["cursor_sequence"] == self._cursor_sequence
            and hmac.compare_digest(
                str(acknowledgement["cursor_record_hmac"]),
                self._cursor_record_hmac,
            )
            and acknowledgement["target_generation"] == self._security_generation
            and acknowledgement["target_last_record"] == self._last_record
            and hmac.compare_digest(
                str(acknowledgement["target_last_record_anchor"]),
                self._last_record_anchor,
            )
        )

    def _delivery_event_value(self, event: dict) -> dict[str, object]:
        record = int(event["record"])
        generation = int(event["generation"])
        eid = int(event["eid"])
        anchor = str(event["record_anchor"])
        inserts = event.get("inserts", [])
        if (
            record <= 0
            or generation <= 0
            or eid not in _EID
            or not _HEX64.fullmatch(anchor)
            or not isinstance(inserts, (list, tuple))
            or len(inserts) > _MAX_SECURITY_EVENT_INSERTS
        ):
            raise ValueError("Security delivery event schema is invalid")
        values = [self._delivery_insert(value) for value in inserts]
        identity = self._delivery_event_identity(generation, record, anchor)
        return {
            "record": record,
            "eid": eid,
            "kind": _EID[eid],
            "inserts": values,
            "generation": generation,
            "record_anchor": anchor,
            "event_identity": identity,
        }

    def _write_security_delivery_outbox(self, events: list[dict]) -> None:
        path = self.security_delivery_outbox_path
        custody_path = self.security_delivery_custody_path
        if path is None:
            raise ValueError("Security delivery outbox root is unavailable")
        if (
            path.exists()
            or path.is_symlink()
            or custody_path is not None
            and (custody_path.exists() or custody_path.is_symlink())
        ):
            raise ValueError("unacknowledged Security delivery batch already exists")
        values = [self._delivery_event_value(event) for event in events]
        if not values or len(values) > _MAX_SECURITY_RECORDS:
            raise ValueError("Security delivery batch size is invalid")
        core: dict[str, object] = {
            "schema": _DELIVERY_OUTBOX_SCHEMA,
            "channel": "Security",
            "host_binding": self._host_binding(),
            "base_cursor_sequence": self._cursor_sequence,
            "base_cursor_hmac": self._cursor_record_hmac,
            "target_generation": self._security_generation,
            "target_last_record": self._last_record,
            "target_last_record_anchor": self._last_record_anchor,
            "events": values,
            "created_at": time.time(),
        }
        value = {**core, "record_hmac": self._delivery_outbox_mac(core)}
        payload = self._cursor_canonical(value) + b"\n"
        if len(payload) > _MAX_DELIVERY_OUTBOX_BYTES:
            raise ValueError("Security delivery batch exceeds its byte budget")
        candidate = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        descriptor: int | None = None
        try:
            from angerona.core.atomic_io import replace_with_retry
            from angerona.core.hardening import (
                ensure_sensitive_parent,
                key_acl_required,
                secure_sensitive_file,
            )

            required = key_acl_required()
            path.parent.mkdir(parents=True, exist_ok=True)
            ensure_sensitive_parent(path, required=required)
            descriptor = os.open(
                candidate,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(candidate, path)
            secure_sensitive_file(path, required=required)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_security_delivery_outbox_document(
        self, selected_path: Path | None = None
    ) -> tuple[list[dict], str, Path] | None:
        active_path = self.security_delivery_outbox_path
        custody_path = self.security_delivery_custody_path
        if active_path is None or custody_path is None:
            return None
        if selected_path is None:
            active_exists = active_path.exists() or active_path.is_symlink()
            custody_exists = custody_path.exists() or custody_path.is_symlink()
            if active_exists and custody_exists:
                raise ValueError("Security delivery has conflicting custody objects")
            if not active_exists and not custody_exists:
                return None
            path = active_path if active_exists else custody_path
        else:
            path = selected_path
            if path not in {active_path, custody_path}:
                raise ValueError("Security delivery custody path is invalid")
        raw = self._read_pinned_regular(
            path, max_bytes=_MAX_DELIVERY_OUTBOX_BYTES, missing_ok=True
        )
        if raw is None:
            return None
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (MemoryError, RecursionError, UnicodeError, TypeError, ValueError) as exc:
            raise ValueError("Security delivery outbox is unreadable") from exc
        if not isinstance(value, dict) or set(value) != _DELIVERY_OUTBOX_FIELDS:
            raise ValueError("Security delivery outbox schema is invalid")
        supplied = value.pop("record_hmac")
        try:
            base_sequence = int(value["base_cursor_sequence"])
            target_generation = int(value["target_generation"])
            target_record = int(value["target_last_record"])
            target_anchor = str(value["target_last_record_anchor"])
            created_at = float(value["created_at"])
            events = value["events"]
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError("Security delivery outbox values are invalid") from exc
        if (
            value["schema"] != _DELIVERY_OUTBOX_SCHEMA
            or value["channel"] != "Security"
            or value["host_binding"] != self._host_binding()
            or base_sequence < 1
            or target_generation < 1
            or target_record <= 0
            or not _HEX64.fullmatch(target_anchor)
            or not math.isfinite(created_at)
            or created_at < 0
            or not isinstance(events, list)
            or not 0 < len(events) <= _MAX_SECURITY_RECORDS
            or not isinstance(supplied, str)
            or not _HEX64.fullmatch(supplied)
            or not hmac.compare_digest(supplied, self._delivery_outbox_mac(value))
        ):
            raise ValueError("Security delivery outbox authentication failed")
        base_hmac = str(value["base_cursor_hmac"])
        if not _HEX64.fullmatch(base_hmac):
            raise ValueError("Security delivery predecessor is invalid")
        if self._cursor_sequence == base_sequence:
            if not hmac.compare_digest(self._cursor_record_hmac, base_hmac):
                raise ValueError("Security delivery predecessor changed")
        elif self._cursor_sequence == base_sequence + 1:
            if (
                self._security_generation != target_generation
                or self._last_record != target_record
                or not hmac.compare_digest(self._last_record_anchor, target_anchor)
            ):
                raise ValueError("Security delivery target does not match cursor")
        else:
            raise ValueError("Security delivery cursor is not adjacent")
        decoded: list[dict] = []
        previous_record = 0
        for event in events:
            if not isinstance(event, dict) or set(event) != _DELIVERY_EVENT_FIELDS:
                raise ValueError("Security delivery event schema is invalid")
            normalized = self._delivery_event_value(event)
            if any(event[key] != normalized[key] for key in _DELIVERY_EVENT_FIELDS):
                raise ValueError("Security delivery event authentication is invalid")
            if int(normalized["record"]) <= previous_record:
                raise ValueError("Security delivery event order is invalid")
            if int(normalized["generation"]) != target_generation:
                raise ValueError("Security delivery event generation changed")
            if int(normalized["record"]) > target_record:
                raise ValueError("Security delivery event exceeds target cursor")
            previous_record = int(normalized["record"])
            decoded.append(dict(normalized))
        return decoded, supplied, path

    def _read_security_delivery_outbox(self) -> list[dict] | None:
        document = self._read_security_delivery_outbox_document()
        return None if document is None else document[0]

    def _ack_security_delivery_outbox(self, events: list[dict]) -> None:
        path = self.security_delivery_outbox_path
        custody_path = self.security_delivery_custody_path
        if path is None or custody_path is None:
            raise ValueError("Security delivery outbox root is unavailable")
        expected = [str(event.get("event_identity") or "") for event in events]
        with self._cursor_writer_lease():
            document = self._read_security_delivery_outbox_document()
            if document is None:
                raise ValueError("Security delivery acknowledgement lost its outbox")
            pending, verified_hmac, verified_path = document
            observed = [str(event["event_identity"]) for event in pending]
            if observed != expected:
                raise ValueError("Security delivery acknowledgement batch changed")
            if verified_path == path:
                if custody_path.exists() or custody_path.is_symlink():
                    raise ValueError("Security delivery custody object already exists")
                # Claim the pathname before the final verification.  A swap of
                # the active name can only move an object that is authenticated
                # again under the custody name; it cannot count as an ack.
                os.replace(path, custody_path)
            claimed_before = os.lstat(custody_path)
            claimed = self._read_security_delivery_outbox_document(custody_path)
            if claimed is None:
                raise ValueError("Security delivery custody object disappeared")
            claimed_events, claimed_hmac, _claimed_path = claimed
            if (
                [str(event["event_identity"]) for event in claimed_events]
                != expected
                or not hmac.compare_digest(claimed_hmac, verified_hmac)
            ):
                raise ValueError("Security delivery custody object changed")
            claimed_current = os.lstat(custody_path)
            if (
                claimed_before.st_dev != claimed_current.st_dev
                or claimed_before.st_ino != claimed_current.st_ino
                or int(getattr(claimed_current, "st_nlink", 1)) != 1
            ):
                raise ValueError("Security delivery custody identity changed")
            # The durable acknowledgement precedes cleanup.  A crash after it
            # can replay the still-present custody object (at-least-once); a
            # crash before it leaves the old ack and therefore exposes a gap.
            self._write_security_delivery_ack(claimed_hmac)
            final_identity = os.lstat(custody_path)
            if (
                final_identity.st_dev != claimed_current.st_dev
                or final_identity.st_ino != claimed_current.st_ino
                or int(getattr(final_identity, "st_nlink", 1)) != 1
            ):
                raise ValueError("Security delivery custody changed before cleanup")
            os.unlink(custody_path)

    def _security_progress_snapshot(self) -> dict[str, object]:
        return {
            "generation": self._security_generation,
            "last_record": self._last_record,
            "last_record_anchor": self._last_record_anchor,
            "oldest": self._security_oldest_observed,
            "high": self._security_high_watermark,
            "identity_digest": self._channel_identity_digest,
            "identity_oldest": self._channel_identity_oldest,
            "identity_high": self._channel_identity_high,
        }

    def _restore_security_progress(self, snapshot: dict[str, object]) -> None:
        self._security_generation = int(snapshot["generation"])
        self._last_record = int(snapshot["last_record"])
        self._last_record_anchor = str(snapshot["last_record_anchor"])
        self._security_oldest_observed = int(snapshot["oldest"])
        self._security_high_watermark = int(snapshot["high"])
        self._channel_identity_digest = str(snapshot["identity_digest"])
        self._channel_identity_oldest = int(snapshot["identity_oldest"])
        self._channel_identity_high = int(snapshot["identity_high"])

    def _finalize_security_delivery(
        self, events: list[dict], snapshot: dict[str, object]
    ) -> list[dict]:
        """Prepare delivery before cursor commit; retain until publication ack."""
        if not self._cursor_enrolled:
            return events
        if events:
            try:
                with self._cursor_writer_lease():
                    self._write_security_delivery_outbox(events)
                    persisted = self._persist_cursor_state()
            except Exception as exc:
                self._restore_security_progress(snapshot)
                self._mark_security_gap(
                    "Security delivery outbox could not be committed "
                    f"({str(exc)[:160] or type(exc).__name__})"
                )
                return []
            if not persisted:
                self._mark_security_gap(
                    "Security delivery is pending while cursor commit is incomplete"
                )
            return events
        if not self._persist_cursor_state():
            self._mark_security_gap(
                "Security cursor progress could not be committed durably"
            )
        return events

    @staticmethod
    def _channel_bounds(win32evtlog, handle) -> tuple[int, int, int]:
        count = int(win32evtlog.GetNumberOfEventLogRecords(handle))
        if count < 0:
            raise RuntimeError("Security channel returned a negative record count")
        if count == 0:
            return 0, 0, 0
        oldest = int(win32evtlog.GetOldestEventLogRecord(handle))
        if oldest <= 0:
            raise RuntimeError("Security channel returned an invalid oldest record")
        return oldest, oldest + count - 1, count

    def _mark_security_gap(self, reason: str) -> None:
        normalized = " ".join(str(reason).split())[:500]
        if self._security_gap and normalized and normalized not in self._security_gap:
            self._security_gap = f"{self._security_gap}; {normalized}"[:1000]
        elif normalized:
            self._security_gap = normalized
        self.set_health(
            45,
            "Security channel continuity gap: "
            f"{self._security_gap}; generation={self._security_generation}",
        )

    def _validate_bookmark(self, win32evtlog, handle) -> bool:
        if self._last_record <= 0 or not self._last_record_anchor:
            return self._last_record <= 0
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        batch = win32evtlog.ReadEventLog(handle, flags, self._last_record) or []
        for event in batch:
            record = int(getattr(event, "RecordNumber", 0))
            if record < self._last_record:
                continue
            try:
                return (
                    record == self._last_record
                    and self._record_anchor(event) == self._last_record_anchor
                )
            except (TypeError, UnicodeError, ValueError):
                return False
        return False

    def _read_security_log(self) -> list[dict]:
        with self.state_lock:
            return self._read_security_log_locked()

    def _read_security_log_locked(self) -> list[dict]:
        import win32evtlog  # type: ignore

        self._load_cursor_state()
        if self._cursor_enrolled:
            try:
                pending = self._read_security_delivery_outbox()
            except Exception as exc:
                self._mark_security_gap(
                    "Security delivery outbox is unverifiable "
                    f"({str(exc)[:160] or type(exc).__name__})"
                )
                return []
            if pending is not None:
                self._security_backlog = True
                self.set_health(
                    min(self.health, 55),
                    "Security detections are awaiting durable EventBus "
                    f"acknowledgement: pending={len(pending)}"
                    + (
                        f"; continuity_gap={self._security_gap}"
                        if self._security_gap
                        else ""
                    ),
                )
                return pending
            try:
                acknowledged = self._security_delivery_ack_matches_cursor()
            except Exception as exc:
                self._mark_security_gap(
                    "Security delivery acknowledgement is unverifiable "
                    f"({str(exc)[:160] or type(exc).__name__})"
                )
                return []
            if not acknowledged:
                self._mark_security_gap(
                    "Security cursor advanced without a durable delivery "
                    "acknowledgement or replayable outbox"
                )
                return []
        progress_snapshot = self._security_progress_snapshot()
        events: list[dict] = []
        h = win32evtlog.OpenEventLog(None, "Security")
        try:
            oldest, high_watermark, count = self._channel_bounds(win32evtlog, h)
            self._security_oldest_observed = oldest
            self._security_high_watermark = high_watermark
            self._security_bounds_checked_at = time.time()
            self._security_bounds_checked_monotonic = time.monotonic()
            if count == 0:
                if self._last_record:
                    self._security_generation += 1
                    self._last_record = 0
                    self._last_record_anchor = ""
                    self._channel_identity_digest = ""
                    self._channel_identity_oldest = 0
                    self._channel_identity_high = 0
                    self._mark_security_gap("channel became empty or was cleared")
                else:
                    if self._security_gap:
                        self._mark_security_gap(self._security_gap)
                    else:
                        self.set_health(
                            70, "Security channel is empty; continuity unavailable"
                        )
                return self._finalize_security_delivery([], progress_snapshot)

            reset_reason = ""
            if self._last_record:
                if self._last_record < oldest:
                    reset_reason = (
                        f"retention advanced from bookmark {self._last_record} "
                        f"to oldest record {oldest}"
                    )
                elif self._last_record > high_watermark:
                    reset_reason = (
                        f"record numbers reset below bookmark {self._last_record} "
                        f"to high watermark {high_watermark}"
                    )
                elif not self._validate_bookmark(win32evtlog, h):
                    reset_reason = (
                        f"bookmark record {self._last_record} was replaced or unreadable"
                    )
                elif not self._saved_channel_identity_matches(win32evtlog, h):
                    reset_reason = (
                        "retained Security records below the bookmark were replaced "
                        "or became unverifiable"
                    )
            if self._last_record == 0:
                self._security_generation += 1
                self._last_record = oldest - 1
            elif reset_reason:
                self._security_generation += 1
                self._last_record = oldest - 1
                self._last_record_anchor = ""
                self._channel_identity_digest = ""
                self._channel_identity_oldest = 0
                self._channel_identity_high = 0
                self._mark_security_gap(reset_reason)

            next_record = self._last_record + 1
            started = time.monotonic()
            pages = 0
            records_read = 0
            while (
                next_record <= high_watermark
                and pages < _MAX_SECURITY_PAGES
                and records_read < _MAX_SECURITY_RECORDS
                and time.monotonic() - started < _MAX_SECURITY_READ_S
            ):
                flags = (
                    win32evtlog.EVENTLOG_FORWARDS_READ
                    | win32evtlog.EVENTLOG_SEEK_READ
                )
                batch = win32evtlog.ReadEventLog(h, flags, next_record) or []
                pages += 1
                progressed = False
                for ev in batch:
                    rec = int(getattr(ev, "RecordNumber", 0))
                    if rec < next_record:
                        continue
                    if rec > high_watermark:
                        break
                    if rec != next_record:
                        self._mark_security_gap(
                            f"expected record {next_record} but reader returned {rec}"
                        )
                        self._security_backlog = True
                        return self._finalize_security_delivery(
                            events, progress_snapshot
                        )
                    # Advance only after this exact record has been observed.
                    try:
                        record_anchor = self._record_anchor(ev)
                    except (TypeError, UnicodeError, ValueError) as exc:
                        self._mark_security_gap(
                            f"record {rec} identity is incomplete "
                            f"({str(exc)[:160] or type(exc).__name__})"
                        )
                        self._security_backlog = True
                        return self._finalize_security_delivery(
                            events, progress_snapshot
                        )
                    self._last_record = rec
                    self._last_record_anchor = record_anchor
                    next_record = rec + 1
                    records_read += 1
                    progressed = True
                    eid = int(ev.EventID) & 0xFFFF
                    if eid in _EID:
                        inserts = [
                            self._delivery_insert(value)
                            for value in list(
                                getattr(ev, "StringInserts", None) or []
                            )
                        ]
                        event_identity = self._delivery_event_identity(
                            self._security_generation, rec, record_anchor
                        )
                        events.append({
                            "record": rec,
                            "eid": eid,
                            "kind": _EID[eid],
                            "inserts": inserts,
                            "ts": getattr(ev, "TimeGenerated", None),
                            "generation": self._security_generation,
                            "record_anchor": record_anchor,
                            "event_identity": event_identity,
                        })
                    if records_read >= _MAX_SECURITY_RECORDS:
                        break
                if not progressed:
                    break

            self._security_records_read += records_read
            self._security_backlog = self._last_record < high_watermark
            if not self._security_backlog:
                identity = self._channel_identity(
                    win32evtlog, h, oldest, high_watermark
                )
                if identity is None:
                    self._mark_security_gap(
                        "retained Security channel identity exceeded the bounded "
                        "verification window or became discontinuous"
                    )
                else:
                    (
                        self._channel_identity_oldest,
                        self._channel_identity_high,
                        self._channel_identity_digest,
                    ) = identity
            if self._security_gap:
                self._mark_security_gap(self._security_gap)
            elif self._security_backlog:
                self.set_health(
                    70,
                    "Security channel bounded catch-up pending: "
                    f"bookmark={self._last_record}, high={high_watermark}",
                )
            else:
                self.set_health(
                    100,
                    "Security channel continuity verified within the local "
                    "signing-identity witness boundary: "
                    f"generation={self._security_generation}, bookmark={self._last_record}",
                )
            events = self._finalize_security_delivery(
                events, progress_snapshot
            )
        finally:
            win32evtlog.CloseEventLog(h)
        return events

    @staticmethod
    def _describe(ev: dict) -> tuple[str, dict, Severity]:
        ins = ev["inserts"]
        if ev["eid"] == 4688:
            # 4688 inserts vary by OS; scan for the .exe token as the new image.
            new_img = next((s for s in ins if isinstance(s, str) and s.lower().endswith(".exe")), "")
            parent = next((s for s in reversed(ins)
                           if isinstance(s, str) and s.lower().endswith(".exe") and s != new_img), "")
            pid = next((s for s in ins if isinstance(s, str) and s.startswith("0x")), "")
            new_name = os.path.basename(new_img) if new_img else ""
            parent_name = os.path.basename(parent) if parent else ""
            details = {"name": new_name, "path": new_img, "parent_name": parent_name,
                       "pid_hex": pid, "eid": 4688, "raw": ins[:12]}
            suffix = f" (parent {parent_name})" if parent_name else ""
            return (f"Process created: {new_name or 'unknown'}{suffix}",
                    details, Severity.INFO)
        if ev["eid"] in (4624, 4672):
            user = next((s for s in ins if isinstance(s, str) and s and "\\" not in s
                         and s not in ("-",) and not s.startswith("0x")), "")
            details = {"eid": ev["eid"], "user": user, "kind": ev["kind"], "raw": ins[:12]}
            sev = Severity.LOW if ev["eid"] == 4672 else Severity.INFO
            return (f"Logon event ({ev['kind']}) user={user or 'n/a'}", details, sev)
        return (f"Security event {ev['eid']}", {"eid": ev["eid"], "raw": ins[:12]}, Severity.INFO)

    # ── psutil fallback ──────────────────────────────────────────────────────
    def _poll_psutil(self) -> list[dict]:
        if psutil is None:
            return []
        out = []
        current = {}
        for p in psutil.process_iter(["pid", "ppid", "name"]):
            current[p.info["pid"]] = p.info
        new_pids = set(current) - self._known_pids
        if self._known_pids:      # skip the first baseline sweep
            for pid in new_pids:
                info = current[pid]
                out.append({"eid": 4688, "kind": "process_created",
                            "inserts": [], "psutil": info})
        self._known_pids = set(current)
        return out

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        use_etw = os.name == "nt"
        if use_etw:
            try:
                import win32evtlog  # noqa: F401
            except Exception:
                use_etw = False
        self._mode = "security-channel" if use_etw else "psutil-fallback"
        self.emit(f"ETWG online — capturing process/logon telemetry ({self._mode}).",
                  Severity.INFO)
        while not self.stopping:
            try:
                if self._mode == "security-channel":
                    try:
                        events = self._read_security_log()
                    except Exception as exc:
                        self.last_error = str(exc)
                        self._mode = "psutil-fallback"   # e.g. access denied → degrade
                        self.set_health(70, f"Security channel unavailable ({exc}); psutil fallback")
                        events = []
                    for ev in events:
                        msg, details, sev = self._describe(ev)
                        details["source"] = "ETW:Security"
                        details["security_event_identity"] = ev.get(
                            "event_identity"
                        )
                        details["security_generation"] = ev.get("generation")
                        details["security_record"] = ev.get("record")
                        self.emit(msg, sev, **details)
                        self.captured += 1
                    if (
                        events
                        and self._cursor_enrolled
                        and self.security_delivery_outbox_path is not None
                        and (
                            self.security_delivery_outbox_path.exists()
                            or self.security_delivery_custody_path is not None
                            and self.security_delivery_custody_path.exists()
                        )
                    ):
                        self._ack_security_delivery_outbox(events)
                else:
                    for ev in self._poll_psutil():
                        info = ev.get("psutil", {})
                        self.emit(f"Process created: {info.get('name','?')} (psutil)",
                                  Severity.INFO, name=info.get("name"), pid=info.get("pid"),
                                  ppid=info.get("ppid"), eid=4688, source="psutil")
                        self.captured += 1
                if self._mode == "psutil-fallback":
                    self.set_health(75, "psutil fallback (enable 4688 auditing for full fidelity)")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, "capture error")
            self.sleep(self._POLL)

    def self_test(self) -> tuple[bool, str]:
        """Verify the 4688/4624 describers produce well-formed events."""
        msg, details, sev = self._describe(
            {"eid": 4688, "kind": "process_created",
             "inserts": ["S-1-5-18", "0x3e7", "0x1a4", r"C:\Windows\System32\cmd.exe",
                         "%%1936", r"C:\Windows\explorer.exe"]})
        ok = details.get("name") == "cmd.exe" and "cmd.exe" in msg
        if os.name == "nt":
            try:
                import win32evtlog  # noqa: F401
                mode = "Security channel available"
            except Exception:
                mode = "pywin32 missing → psutil fallback"
        else:
            mode = "non-Windows → psutil fallback"
        return (ok, f"4688 decode verified ({mode})" if ok
                else f"4688 decode failed: {details}")


def register() -> EtwListenerModule:
    return EtwListenerModule()
