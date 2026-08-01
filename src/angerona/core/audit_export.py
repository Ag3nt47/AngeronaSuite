"""Signed, scoped, privacy-minimized audit export with a custody chain."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_governance import DataClass, EgressPolicy
from angerona.core.privacy import redact_text

MAX_INPUT_RECORDS = 100_000
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_EXPORT_RECORDS = 10_000
MAX_EVENT_BYTES = 64 * 1024
MAX_EXPORT_BYTES = 64 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OUTCOMES = {"success", "failure", "denied", "error", "unknown"}
_PRIVACY_KEY_VALUE = re.compile(
    r"(?i)\b(username|user|account|email|path|password|passwd|pwd|secret|token|"
    r"api[-_ ]?key|authorization)\b\s*[:=]\s*.+"
)
_TARGET_LOCKS_GUARD = threading.Lock()
_TARGET_LOCKS: dict[str, tuple[threading.Lock, int]] = {}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _privacy_safe_key(key: object) -> str:
    if not isinstance(key, str):
        raise TypeError("audit detail mapping keys must be strings")
    if "\x00" in key:
        raise ValueError("audit detail mapping key contains a null byte")
    normalized = redact_text(key, limit=128).strip()
    normalized = _PRIVACY_KEY_VALUE.sub(
        lambda match: f"{match.group(1).casefold()}=[REDACTED]",
        normalized,
    )
    return normalized or "[REDACTED_KEY]"


def _privacy_safe_keys(value: Any) -> Any:
    """Normalize privacy-bearing keys without silently overwriting records."""
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            normalized = _privacy_safe_key(key)
            if normalized in out:
                raise ValueError("audit detail mapping key normalization collision")
            out[normalized] = _privacy_safe_keys(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_privacy_safe_keys(item) for item in value]
    return value


def _redact_values(value: Any) -> Any:
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            normalized = _privacy_safe_key(key)
            if normalized in out:
                raise ValueError("audit detail mapping key normalization collision")
            out[normalized] = _redact_values(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact_values(item) for item in value]
    if isinstance(value, str):
        return redact_text(value, limit=8_192)
    return value


def _target_lock_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


@contextmanager
def _hold_target_lock(path: Path) -> Iterator[None]:
    """Serialize writers to one target while bounding the process lock registry."""
    key = _target_lock_key(path)
    with _TARGET_LOCKS_GUARD:
        lock, users = _TARGET_LOCKS.get(key, (threading.Lock(), 0))
        _TARGET_LOCKS[key] = (lock, users + 1)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _TARGET_LOCKS_GUARD:
            current_lock, users = _TARGET_LOCKS[key]
            if current_lock is lock and users == 1:
                del _TARGET_LOCKS[key]
            else:
                _TARGET_LOCKS[key] = (current_lock, users - 1)


@dataclass(frozen=True)
class AuditEvent:
    record_id: str
    tenant_id: str
    scope: str
    timestamp: float
    action: str
    outcome: str
    actor: str
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if any(not _ID.fullmatch(value) for value in (
            self.record_id, self.tenant_id, self.scope, self.action,
        )):
            raise ValueError("invalid audit event identity")
        if self.outcome not in _OUTCOMES:
            raise ValueError("invalid audit event outcome")
        if not self.actor or len(self.actor) > 500:
            raise ValueError("bounded audit actor is required")
        if not math.isfinite(float(self.timestamp)) or self.timestamp < 0:
            raise ValueError("invalid audit timestamp")
        if not isinstance(self.details, Mapping):
            raise TypeError("audit details must be a mapping")
        if len(_canonical(self.details)) > MAX_EVENT_BYTES:
            raise ValueError("audit event exceeds 64 KiB")


@dataclass(frozen=True)
class AuditExportRequest:
    request_id: str
    tenant_id: str
    scopes: tuple[str, ...]
    start_time: float
    end_time: float
    max_records: int
    requested_by: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scopes", tuple(self.scopes))
        if any(not _ID.fullmatch(value) for value in (
            self.request_id, self.tenant_id, self.requested_by,
        )):
            raise ValueError("invalid audit export identity")
        if not 1 <= len(self.scopes) <= 64 or any(
            not _ID.fullmatch(scope) for scope in self.scopes
        ):
            raise ValueError("audit export requires valid scopes")
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("audit export scopes contain duplicates")
        if (
            not math.isfinite(float(self.start_time))
            or not math.isfinite(float(self.end_time))
            or self.start_time < 0
            or self.start_time > self.end_time
        ):
            raise ValueError("invalid audit export time range")
        if not 1 <= int(self.max_records) <= MAX_EXPORT_RECORDS:
            raise ValueError("audit export record limit is invalid")


@dataclass(frozen=True)
class ExportedAuditRecord:
    record_id: str
    tenant_id: str
    scope: str
    timestamp: float
    action: str
    outcome: str
    actor_token: str
    details: Mapping[str, Any]
    previous_hash: str
    record_hash: str


@dataclass(frozen=True)
class AuditExportManifest:
    schema: str
    request_id: str
    tenant_id: str
    scopes: tuple[str, ...]
    start_time: float
    end_time: float
    requested_by_token: str
    created_at: float
    input_count: int
    exported_count: int
    truncated: bool
    chain_head: str
    records_sha256: str
    privacy_policy: str
    manifest_hmac: str


@dataclass(frozen=True)
class SignedAuditExport:
    manifest: AuditExportManifest
    records: tuple[ExportedAuditRecord, ...]

    def canonical(self) -> bytes:
        return _canonical(asdict(self))


class AuditExporter:
    def __init__(
        self, signing_key: bytes, privacy_salt: bytes, *, clock,
    ) -> None:
        if len(signing_key) < 32 or len(privacy_salt) < 16:
            raise ValueError("audit signing and privacy keys are too short")
        self._key = bytes(signing_key)
        self._salt = bytes(privacy_salt)
        self._clock = clock
        self._policy = EgressPolicy(
            maximum_class=DataClass.INTERNAL,
            allow_external=False,
            tokenize_sensitive=True,
            max_payload_bytes=MAX_EVENT_BYTES,
        )

    def export(
        self,
        events: Iterable[AuditEvent],
        request: AuditExportRequest,
    ) -> SignedAuditExport:
        matching: list[AuditEvent] = []
        input_bytes = 0
        for index, event in enumerate(events):
            if index >= MAX_INPUT_RECORDS:
                raise ValueError("audit export input exceeds 100000 records")
            if not isinstance(event, AuditEvent):
                raise TypeError("audit export input must contain AuditEvent records")
            input_bytes += len(_canonical(asdict(event)))
            if input_bytes > MAX_INPUT_BYTES:
                raise ValueError("audit export input exceeds 64 MiB")
            if (
                event.tenant_id == request.tenant_id
                and event.scope in request.scopes
                and request.start_time <= event.timestamp <= request.end_time
            ):
                matching.append(event)
        matching.sort(key=lambda item: (item.timestamp, item.record_id))
        if len({event.record_id for event in matching}) != len(matching):
            raise ValueError("audit export contains duplicate record IDs")
        truncated = len(matching) > request.max_records
        selected = matching[:request.max_records]
        records: list[ExportedAuditRecord] = []
        previous = "0" * 64
        for event in selected:
            safe_details = _privacy_safe_keys(event.details)
            preview = self._policy.preview(
                safe_details,
                purpose="audit export",
                destination="operator-reviewed local file",
                salt=self._salt,
                external=False,
            )
            if not preview.permitted:
                raise ValueError("audit event cannot be privacy-minimized")
            core = {
                "record_id": event.record_id,
                "tenant_id": event.tenant_id,
                "scope": event.scope,
                "timestamp": event.timestamp,
                "action": event.action,
                "outcome": event.outcome,
                "actor_token": self._token(event.actor),
                "details": _redact_values(dict(preview.minimized_payload)),
                "previous_hash": previous,
            }
            record_hash = hashlib.sha256(_canonical(core)).hexdigest()
            record = ExportedAuditRecord(**core, record_hash=record_hash)
            records.append(record)
            previous = record_hash
        records_digest = hashlib.sha256(
            _canonical([asdict(item) for item in records])
        ).hexdigest()
        manifest_core = {
            "schema": "angerona.audit-export/v1",
            "request_id": request.request_id,
            "tenant_id": request.tenant_id,
            "scopes": request.scopes,
            "start_time": request.start_time,
            "end_time": request.end_time,
            "requested_by_token": self._token(request.requested_by),
            "created_at": float(self._clock()),
            "input_count": len(matching),
            "exported_count": len(records),
            "truncated": truncated,
            "chain_head": previous,
            "records_sha256": records_digest,
            "privacy_policy": (
                "restricted removed; sensitive tokenized; free text redacted"
            ),
        }
        manifest = AuditExportManifest(
            **manifest_core,
            manifest_hmac=hmac.new(
                self._key, _canonical(manifest_core), hashlib.sha256
            ).hexdigest(),
        )
        export = SignedAuditExport(manifest, tuple(records))
        if len(export.canonical()) > MAX_EXPORT_BYTES:
            raise ValueError("audit export exceeds 64 MiB")
        return export

    def verify(self, export: SignedAuditExport) -> bool:
        previous = "0" * 64
        for record in export.records:
            value = asdict(record)
            digest = value.pop("record_hash")
            if value["previous_hash"] != previous:
                return False
            expected = hashlib.sha256(_canonical(value)).hexdigest()
            if not hmac.compare_digest(digest, expected):
                return False
            previous = digest
        manifest = asdict(export.manifest)
        signature = manifest.pop("manifest_hmac")
        if (
            export.manifest.schema != "angerona.audit-export/v1"
            or export.manifest.exported_count != len(export.records)
            or export.manifest.chain_head != previous
            or not _SHA256.fullmatch(export.manifest.records_sha256)
            or not hmac.compare_digest(
                export.manifest.records_sha256,
                hashlib.sha256(
                    _canonical([asdict(item) for item in export.records])
                ).hexdigest(),
            )
        ):
            return False
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(manifest), hashlib.sha256).hexdigest(),
        )

    def _token(self, value: object) -> str:
        return "tok_" + hmac.new(
            self._salt, _canonical(value), hashlib.sha256
        ).hexdigest()[:32]


def write_audit_export(path: Path, export: SignedAuditExport) -> None:
    encoded = export.canonical()
    if len(encoded) > MAX_EXPORT_BYTES:
        raise ValueError("audit export exceeds 64 MiB")
    path = Path(path)
    with _hold_target_lock(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = -1
        temporary: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
            temporary = Path(temporary_name)
            stream = os.fdopen(descriptor, "wb")
            descriptor = -1
            with stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temporary, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
