"""Safe, typed fleet hunt and collection contracts with no remote shell."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from angerona.core.atomic_io import replace_with_retry

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_STATES = {"draft", "approved", "running", "completed", "failed", "cancelled", "expired"}
_TRANSITIONS = {
    "draft": {"approved", "cancelled", "expired"},
    "approved": {"running", "cancelled", "expired"},
    "running": {"completed", "failed", "cancelled", "expired"},
}
MAX_SPEC = 64 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()


@dataclass(frozen=True)
class CollectionArtifact:
    artifact_id: str
    description: str
    privacy_class: str
    max_item_bytes: int
    supported_platforms: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.artifact_id):
            raise ValueError("invalid artifact ID")
        if self.privacy_class not in {"system", "sensitive", "restricted"}:
            raise ValueError("invalid privacy class")
        if not 1024 <= self.max_item_bytes <= 100 * 1024 * 1024:
            raise ValueError("invalid artifact byte budget")
        if not self.supported_platforms or any(
            item not in {"windows", "macos", "linux"}
            for item in self.supported_platforms
        ):
            raise ValueError("invalid artifact platforms")


SAFE_ARTIFACTS = {
    item.artifact_id: item for item in (
        CollectionArtifact(
            "process.snapshot", "Process identity and metadata snapshot",
            "sensitive", 5 * 1024 * 1024, ("windows", "macos", "linux"),
        ),
        CollectionArtifact(
            "network.connections", "Current network connection metadata",
            "sensitive", 5 * 1024 * 1024, ("windows", "macos", "linux"),
        ),
        CollectionArtifact(
            "startup.inventory", "Supported startup and persistence inventory",
            "sensitive", 10 * 1024 * 1024, ("windows", "macos", "linux"),
        ),
        CollectionArtifact(
            "security.events", "Bounded security-event metadata export",
            "restricted", 50 * 1024 * 1024, ("windows", "macos", "linux"),
        ),
        CollectionArtifact(
            "file.metadata", "Hash and metadata for policy-selected files",
            "sensitive", 10 * 1024 * 1024, ("windows", "macos", "linux"),
        ),
    )
}


@dataclass(frozen=True)
class HuntSpec:
    hunt_id: str
    artifact_ids: tuple[str, ...]
    device_ids: tuple[str, ...]
    group_ids: tuple[str, ...]
    query: Mapping[str, Any]
    max_hosts: int
    max_total_bytes: int
    max_duration_seconds: int
    created_at: float
    expires_at: float
    requested_by: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.hunt_id) or not _ID.fullmatch(self.requested_by):
            raise ValueError("invalid hunt identity")
        if not self.artifact_ids or any(
            item not in SAFE_ARTIFACTS for item in self.artifact_ids
        ):
            raise ValueError("hunt uses an unregistered artifact")
        if not self.device_ids and not self.group_ids:
            raise ValueError("hunt requires an explicit target")
        for value in (*self.device_ids, *self.group_ids):
            if not _ID.fullmatch(value):
                raise ValueError("invalid hunt target")
        if not 1 <= self.max_hosts <= 10_000:
            raise ValueError("invalid host budget")
        if not 1024 <= self.max_total_bytes <= 10 * 1024 * 1024 * 1024:
            raise ValueError("invalid byte budget")
        if not 1 <= self.max_duration_seconds <= 3600:
            raise ValueError("invalid duration budget")
        if not self.created_at < self.expires_at <= self.created_at + 86400:
            raise ValueError("hunt expiry must be within one day")
        if any(key in self.query for key in ("command", "shell", "script", "path")):
            raise ValueError("arbitrary command/path fields are forbidden")
        if len(_canonical(asdict(self))) > MAX_SPEC:
            raise ValueError("hunt specification exceeds byte budget")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class HuntReceipt:
    hunt_id: str
    hunt_digest: str
    state: str
    hosts: int
    bytes_collected: int
    result_digest: str
    recorded_at: float
    receipt_hmac: str


class HuntLifecycle:
    def __init__(
        self, audit_key: bytes, state_path: Path, *, clock=time.time
    ) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        self._key = bytes(audit_key)
        self._state_path = Path(state_path)
        self._clock = clock
        self._records: dict[str, tuple[HuntSpec, str, set[str]]] = {}
        self._load()

    def _save(self) -> None:
        records = {
            hunt_id: {
                "spec": asdict(spec), "state": state,
                "approvals": sorted(approvals),
            }
            for hunt_id, (spec, state, approvals) in sorted(self._records.items())
        }
        signature = hmac.new(
            self._key, _canonical(records), hashlib.sha256
        ).hexdigest()
        encoded = _canonical({
            "schema_version": 1, "records": records, "hmac": signature,
        })
        if len(encoded) > 8 * 1024 * 1024:
            raise ValueError("hunt state exceeds byte budget")
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self._state_path.with_suffix(
            self._state_path.suffix + f".{os.getpid()}.tmp"
        )
        try:
            with open(temp, "xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temp, self._state_path)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def _load(self) -> None:
        if not self._state_path.exists():
            return
        if self._state_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("hunt state exceeds byte budget")
        value = json.loads(self._state_path.read_text(encoding="utf-8"))
        records = value.get("records")
        signature = value.get("hmac", "")
        if value.get("schema_version") != 1 or not isinstance(records, dict):
            raise ValueError("hunt state is invalid")
        expected = hmac.new(
            self._key, _canonical(records), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("hunt state authentication failed")
        for hunt_id, record in records.items():
            raw = dict(record["spec"])
            raw["artifact_ids"] = tuple(raw["artifact_ids"])
            raw["device_ids"] = tuple(raw["device_ids"])
            raw["group_ids"] = tuple(raw["group_ids"])
            spec = HuntSpec(**raw)
            if hunt_id != spec.hunt_id or record["state"] not in _STATES:
                raise ValueError("hunt state identity is invalid")
            approvals = set(record.get("approvals", ()))
            if any(not _ID.fullmatch(item) for item in approvals):
                raise ValueError("hunt approval identity is invalid")
            self._records[hunt_id] = (spec, record["state"], approvals)

    def create(self, spec: HuntSpec) -> None:
        current = self._records.get(spec.hunt_id)
        if current and current[0].digest != spec.digest:
            raise ValueError("hunt ID conflicts with another specification")
        self._records.setdefault(spec.hunt_id, (spec, "draft", set()))
        self._save()

    def approve(self, hunt_id: str, approver: str) -> int:
        spec, state, approvals = self._get(hunt_id)
        if state != "draft" or self._clock() >= spec.expires_at:
            raise PermissionError("hunt is not approvable")
        if approver == spec.requested_by or not _ID.fullmatch(approver):
            raise PermissionError("hunt requires an independent approver")
        approvals.add(approver)
        required = 2 if any(
            SAFE_ARTIFACTS[item].privacy_class == "restricted"
            for item in spec.artifact_ids
        ) else 1
        if len(approvals) >= required:
            state = "approved"
        self._records[hunt_id] = (spec, state, approvals)
        self._save()
        return len(approvals)

    def transition(self, hunt_id: str, state: str) -> None:
        spec, current, approvals = self._get(hunt_id)
        if self._clock() >= spec.expires_at and state not in {"expired", "cancelled"}:
            state = "expired"
        if state not in _TRANSITIONS.get(current, set()):
            raise ValueError(f"invalid hunt transition {current}->{state}")
        self._records[hunt_id] = (spec, state, approvals)
        self._save()

    def receipt(
        self, hunt_id: str, *, hosts: int, bytes_collected: int,
        result_digest: str,
    ) -> HuntReceipt:
        spec, state, _approvals = self._get(hunt_id)
        if state not in {"completed", "failed", "cancelled", "expired"}:
            raise ValueError("receipt requires a terminal hunt")
        if not 0 <= hosts <= spec.max_hosts or not 0 <= bytes_collected <= spec.max_total_bytes:
            raise ValueError("hunt result exceeded an approved budget")
        if not re.fullmatch(r"[0-9a-f]{64}", result_digest):
            raise ValueError("invalid result digest")
        core = {
            "hunt_id": hunt_id, "hunt_digest": spec.digest, "state": state,
            "hosts": hosts, "bytes_collected": bytes_collected,
            "result_digest": result_digest, "recorded_at": float(self._clock()),
        }
        return HuntReceipt(
            **core, receipt_hmac=hmac.new(
                self._key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_receipt(self, receipt: HuntReceipt) -> bool:
        value = asdict(receipt)
        signature = value.pop("receipt_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    def _get(self, hunt_id: str):
        try:
            return self._records[hunt_id]
        except KeyError as exc:
            raise KeyError(hunt_id) from exc
