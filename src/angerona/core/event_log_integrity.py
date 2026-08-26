"""Strict event-log tamper parsing and authenticated continuity checkpoints."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from defusedxml import ElementTree as SafeET

from angerona.core.atomic_io import replace_with_retry
from angerona.core.independent_high_water import (
    AUDIT_DOMAIN,
    ZERO_DIGEST,
    HighWaterAssessment,
    IndependentHighWater,
    advance_high_water,
    assess_high_water,
    state_pair_digest,
    validate_installation_id,
)


_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_MAX_XML_BYTES = 1024 * 1024
_MAX_TEXT = 4096
_MAX_FIELDS = 64
_MAX_CHECKPOINT_BYTES = 64 * 1024
_MAX_CHANNELS = 16
_SCHEMA = 2
_ENROLLMENT_SCHEMA = 1
_SIGNATURE = "_angerona_hmac"
_DOMAIN = b"angerona/event-log-continuity/v1\x00"
_ENROLLMENT_DOMAIN = b"angerona/event-log-enrollment/v1\x00"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class AuditIntegrityRecord:
    channel: str
    provider: str
    event_id: int
    record_id: int
    created_at: str
    classification: str
    severity: str
    reason: str
    fields: Mapping[str, str]


@dataclass(frozen=True)
class ChannelCheckpoint:
    record_id: int
    anchor: str


@dataclass(frozen=True)
class ContinuityAssessment:
    state: str
    reason: str
    resume_after: int
    missing_start: int = 0
    missing_end: int = 0


class AuditEventRejected(ValueError):
    """Bounded rejection with an Angerona-owned reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _path_has_link_or_reparse(path: Path) -> bool:
    """Reject any existing link/reparse component; unreadable paths fail closed."""
    if not path.is_absolute():
        return True
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return True
        if _is_link_or_reparse(info):
            return True
    return False


def _safe_read_bounded(path: Path, maximum: int) -> bytes:
    """Read one stable ordinary file without following links or exceeding a cap."""
    if _path_has_link_or_reparse(path):
        raise OSError("checkpoint path is link/reparse-backed")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise OSError("checkpoint is not an ordinary bounded file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        before_identity = (
            getattr(before, "st_dev", None),
            getattr(before, "st_ino", None),
            before.st_size,
        )
        opened_identity = (
            getattr(opened, "st_dev", None),
            getattr(opened, "st_ino", None),
            opened.st_size,
        )
        if not stat.S_ISREG(opened.st_mode) or before_identity != opened_identity:
            raise OSError("checkpoint identity changed while opening")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise OSError("checkpoint exceeds its read bound")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if _is_link_or_reparse(after) or (
        getattr(before, "st_dev", None),
        getattr(before, "st_ino", None),
        before.st_size,
        getattr(before, "st_mtime_ns", None),
        getattr(before, "st_ctime_ns", None),
    ) != (
        getattr(after, "st_dev", None),
        getattr(after, "st_ino", None),
        after.st_size,
        getattr(after, "st_mtime_ns", None),
        getattr(after, "st_ctime_ns", None),
    ):
        raise OSError("checkpoint changed during read")
    return payload


@dataclass(frozen=True)
class _AuditEventSpec:
    provider: str
    classification: str
    severity: str
    reason: str
    fields: Mapping[str, str]


_EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


_EVENTS: dict[tuple[str, int], _AuditEventSpec] = {
    ("security", 1100): _AuditEventSpec(
        _EVENTLOG_PROVIDER, "logging-service-stopped", "high",
        "audit service stopped", {},
    ),
    ("security", 1102): _AuditEventSpec(
        _EVENTLOG_PROVIDER, "audit-log-cleared", "critical",
        "Security audit log cleared", {},
    ),
    ("security", 1104): _AuditEventSpec(
        _EVENTLOG_PROVIDER, "audit-log-full", "high",
        "Security audit log became full", {},
    ),
    ("security", 1108): _AuditEventSpec(
        _EVENTLOG_PROVIDER, "audit-processing-failure", "high",
        "audit service processing error", {},
    ),
    ("security", 4612): _AuditEventSpec(
        _SECURITY_PROVIDER, "audit-resource-exhaustion", "high",
        "audit queue resource exhaustion", {},
    ),
    ("security", 4719): _AuditEventSpec(
        _SECURITY_PROVIDER, "audit-policy-changed", "high",
        "system audit policy changed", {"auditpolicychanges": "audit_policy_change"},
    ),
    ("security", 4902): _AuditEventSpec(
        _SECURITY_PROVIDER, "per-user-audit-table-created", "medium",
        "per-user audit table created", {},
    ),
    ("security", 4906): _AuditEventSpec(
        _SECURITY_PROVIDER, "crash-on-audit-fail-changed", "high",
        "CrashOnAuditFail changed", {},
    ),
    ("security", 4907): _AuditEventSpec(
        _SECURITY_PROVIDER, "object-audit-policy-changed", "medium",
        "object auditing policy changed", {},
    ),
    ("security", 4912): _AuditEventSpec(
        _SECURITY_PROVIDER, "per-user-audit-policy-changed", "medium",
        "per-user audit policy changed", {},
    ),
    ("system", 104): _AuditEventSpec(
        _EVENTLOG_PROVIDER, "event-log-cleared", "critical",
        "Windows event channel cleared", {"channel": "affected_channel"},
    ),
    ("microsoft-windows-sysmon/operational", 4): _AuditEventSpec(
        _SYSMON_PROVIDER, "sysmon-service-state-changed", "high",
        "Sysmon service state changed", {"state": "service_state"},
    ),
    ("microsoft-windows-sysmon/operational", 16): _AuditEventSpec(
        _SYSMON_PROVIDER, "sysmon-configuration-changed", "high",
        "Sysmon configuration changed", {},
    ),
    ("microsoft-windows-sysmon/operational", 255): _AuditEventSpec(
        _SYSMON_PROVIDER, "sysmon-internal-error", "high",
        "Sysmon reported an internal error", {},
    ),
}


def audit_event_selectors(channel: str) -> dict[int, tuple[str, ...]]:
    """Return the fixed provider set for one fixed channel."""
    normalized = _clean_text(channel).strip().casefold()
    return {
        event_id: (spec.provider,)
        for (candidate, event_id), spec in _EVENTS.items()
        if candidate == normalized
    }


def _clean_text(value: object) -> str:
    text = str(value or "").replace("\x00", "")
    text = "".join(character if character in "\t\r\n" or ord(character) >= 32 else " "
                   for character in text)
    return text[:_MAX_TEXT]


def _local_name(tag: object) -> str:
    value = str(tag or "")
    return value.rsplit("}", 1)[-1]


def _strict_int(value: object, label: str, *, maximum: int = 2**63 - 1) -> int:
    text = _clean_text(value).strip()
    if not text or len(text) > 20 or not text.isdecimal():
        raise ValueError(f"invalid {label}")
    parsed = int(text)
    if parsed < 0 or parsed > maximum:
        raise ValueError(f"invalid {label}")
    return parsed


def _timestamp(value: object) -> str:
    text = _clean_text(value).strip()
    if not text:
        return ""
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("invalid event timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc).timestamp()
    if parsed.timestamp() > now + 300:
        raise ValueError("event timestamp is too far in the future")
    return parsed.astimezone(timezone.utc).isoformat()


def _privacy_field_value(output_key: str, value: object) -> str:
    """Admit only fixed enums; all other typed values remain redacted."""
    cleaned = _clean_text(value).strip()
    if not cleaned:
        return ""
    if output_key == "service_state":
        normalized = cleaned.casefold()
        if normalized in {"started", "stopped"}:
            return normalized
    return "[REDACTED]"


def parse_audit_integrity_xml(xml: str, channel: str) -> AuditIntegrityRecord:
    """Parse one admitted event without retaining raw XML or account identity."""
    if not isinstance(xml, str) or len(xml.encode("utf-8", "replace")) > _MAX_XML_BYTES:
        raise ValueError("event XML exceeds the admission bound")
    try:
        root = SafeET.fromstring(xml)
    except Exception as exc:
        raise ValueError("event XML is malformed") from exc
    system = root.find(f"{_NS}System")
    if system is None:
        raise ValueError("event has no System section")
    event_node = system.find(f"{_NS}EventID")
    record_node = system.find(f"{_NS}EventRecordID")
    if event_node is None or record_node is None:
        raise ValueError("event identity is incomplete")
    event_id = _strict_int(event_node.text, "event ID", maximum=65535)
    record_id = _strict_int(record_node.text, "record ID")
    provider_node = system.find(f"{_NS}Provider")
    provider = _clean_text(
        provider_node.attrib.get("Name", "") if provider_node is not None else ""
    )
    xml_channel_node = system.find(f"{_NS}Channel")
    xml_channel = _clean_text(
        xml_channel_node.text if xml_channel_node is not None else ""
    ).strip()
    normalized_channel = _clean_text(channel).strip()
    if not normalized_channel or not xml_channel:
        raise AuditEventRejected("channel-missing")
    if not hmac.compare_digest(xml_channel.casefold(), normalized_channel.casefold()):
        raise AuditEventRejected("channel-mismatch")
    spec = _EVENTS.get((normalized_channel.casefold(), event_id))
    if spec is None:
        raise AuditEventRejected("event-id-rejected")
    if not provider or not hmac.compare_digest(provider.casefold(), spec.provider.casefold()):
        raise AuditEventRejected("provider-rejected")
    time_node = system.find(f"{_NS}TimeCreated")
    created_at = _timestamp(
        time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    )

    fields: dict[str, str] = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for index, node in enumerate(list(event_data)):
            if index >= _MAX_FIELDS:
                raise AuditEventRejected("field-count-rejected")
            input_name = _clean_text(
                node.attrib.get("Name") or _local_name(node.tag) or str(index)
            ).casefold()
            output_key = spec.fields.get(input_name)
            if output_key is not None:
                fields[output_key] = _privacy_field_value(output_key, node.text)

    return AuditIntegrityRecord(
        channel=normalized_channel,
        provider=provider,
        event_id=event_id,
        record_id=record_id,
        created_at=created_at,
        classification=spec.classification,
        severity=spec.severity,
        reason=spec.reason,
        fields=fields,
    )


def assess_continuity(
    checkpoint: ChannelCheckpoint | None,
    *,
    oldest: int,
    newest: int,
    retained_anchor: str = "",
    checkpoint_status: str = "authenticated",
) -> ContinuityAssessment:
    """Determine the only safe resume point for one sampled channel generation."""
    oldest = max(0, int(oldest))
    newest = max(0, int(newest))
    if oldest > newest:
        oldest = 0
    if checkpoint_status == "untrusted":
        return ContinuityAssessment(
            "untrusted", "checkpoint authentication failed", max(0, oldest - 1)
        )
    if checkpoint is None:
        if checkpoint_status == "first-enrollment":
            # Replay progresses in bounded batches, so starting at the oldest
            # retained record does not create an unbounded allocation or WEVT
            # query.  It does prevent a still-retained clear event from being
            # skipped merely because unrelated channel traffic is newer.
            return ContinuityAssessment(
                "enrollment",
                "first enrollment requires retained-evidence replay",
                max(0, oldest - 1),
            )
        return ContinuityAssessment("baseline", "first authenticated baseline", newest)
    record_id = max(0, int(checkpoint.record_id))
    if record_id > newest:
        return ContinuityAssessment(
            "gap", "record numbering regressed or the channel was cleared",
            max(0, oldest - 1), newest + 1, record_id,
        )
    if oldest and record_id < oldest - 1:
        return ContinuityAssessment(
            "gap", "retained history begins after the authenticated cursor",
            oldest - 1, record_id + 1, oldest - 1,
        )
    anchor_is_retained = record_id > 0 and record_id <= newest and (
        oldest == 0 or record_id >= oldest
    )
    if anchor_is_retained and (
        not checkpoint.anchor
        or not retained_anchor
        or not hmac.compare_digest(checkpoint.anchor, retained_anchor)
    ):
        return ContinuityAssessment(
            "gap", "authenticated checkpoint record was replaced",
            max(0, oldest - 1), record_id, record_id,
        )
    return ContinuityAssessment("live", "continuity verified", record_id)


class AuthenticatedEventLogCheckpoint:
    """Authenticated cursor plus an independently signed enrollment epoch.

    The epoch lives outside the replaceable cursor directory.  A missing cursor
    after enrollment therefore fails closed.  Both documents carry the same
    monotonic revision, and every save compares the exact admitted file bytes
    before replacing either document.
    """

    def __init__(
        self,
        path: Path,
        authority_key: bytes | None = None,
        enrollment_path: Path | None = None,
        high_water: IndependentHighWater | None = None,
    ) -> None:
        self.path = Path(path)
        try:
            root = self.path.parents[1]
        except IndexError:
            root = self.path.parent
        self.enrollment_path = Path(enrollment_path) if enrollment_path else (
            root / "security-state" / "audit-log-enrollment.json"
        )
        self._authority_key = authority_key
        self._high_water = high_water
        self._load_state = "unloaded"
        self._enrollment_id = ""
        self._created_at = 0.0
        self._revision = 0
        self._coverage_complete = False
        self._expected_cursor_digest: str | None = None
        self._expected_enrollment_digest: str | None = None
        self._recovery_allowed = False
        self._freshness = HighWaterAssessment(
            "unassessed", "state has not been loaded", False
        )

    @property
    def coverage_complete(self) -> bool:
        return self._coverage_complete

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def freshness_status(self) -> str:
        """Independent freshness, separate from local HMAC authenticity."""
        return self._freshness.state

    @property
    def independent_freshness_verified(self) -> bool:
        return self._freshness.independently_fresh

    @property
    def freshness_reason(self) -> str:
        return self._freshness.reason

    def _first_enrollment_freshness(self) -> HighWaterAssessment:
        if self._high_water is None:
            return assess_high_water(
                None,
                domain=AUDIT_DOMAIN,
                installation_id="0" * 32,
                revision=0,
                state_digest=ZERO_DIGEST,
            )
        try:
            installation_id = validate_installation_id(self._high_water.installation_id)
        except Exception:
            return HighWaterAssessment(
                "authority-rejected",
                "independent high-water installation identity is invalid",
                False,
            )
        self._enrollment_id = installation_id
        return assess_high_water(
            self._high_water,
            domain=AUDIT_DOMAIN,
            installation_id=installation_id,
            revision=0,
            state_digest=ZERO_DIGEST,
        )

    def _assess_loaded_freshness(
        self,
        cursor_payload: bytes,
        epoch_payload: bytes,
    ) -> HighWaterAssessment:
        digest = state_pair_digest(
            domain=AUDIT_DOMAIN,
            installation_id=self._enrollment_id,
            revision=self._revision,
            primary_payload=cursor_payload,
            epoch_payload=epoch_payload,
        )
        return assess_high_water(
            self._high_water,
            domain=AUDIT_DOMAIN,
            installation_id=self._enrollment_id,
            revision=self._revision,
            state_digest=digest,
        )

    def _master_key(self) -> bytes | None:
        value = self._authority_key
        if value is None:
            try:
                raw = _safe_read_bounded(self.path.parents[1] / "bus.key", 128)
                value = bytes.fromhex(raw.decode("ascii", "strict").strip())
            except (OSError, UnicodeError, ValueError, IndexError):
                return None
        if not isinstance(value, bytes) or len(value) != 32:
            return None
        return value

    def _key(self, domain: bytes) -> bytes | None:
        master = self._master_key()
        return hmac.new(master, domain, hashlib.sha256).digest() if master else None

    @staticmethod
    def _body(document: Mapping[str, object]) -> bytes:
        unsigned = {key: value for key, value in document.items() if key != _SIGNATURE}
        return json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @staticmethod
    def _strict_json(payload: bytes) -> dict:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if not isinstance(key, str) or key in result:
                    raise ValueError("ambiguous checkpoint JSON")
                result[key] = value
            return result

        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("invalid checkpoint number")
            ),
        )
        if not isinstance(value, dict):
            raise ValueError("checkpoint document is not an object")
        return value

    @staticmethod
    def _existing_payload(path: Path) -> tuple[bytes | None, str | None]:
        try:
            payload = _safe_read_bounded(path, _MAX_CHECKPOINT_BYTES)
        except FileNotFoundError:
            return None, ""
        except OSError:
            return None, None
        return payload, hashlib.sha256(payload).hexdigest()

    def _authenticated(self, document: Mapping[str, object], domain: bytes) -> bool:
        signature = document.get(_SIGNATURE)
        key = self._key(domain)
        if key is None or not isinstance(signature, str) or len(signature) != 64:
            return False
        expected = hmac.new(key, self._body(document), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def _parse_enrollment(self, payload: bytes) -> tuple[str, float, int]:
        document = self._strict_json(payload)
        if (
            set(document) != {
                "schema", "created_at", "enrollment_id", "revision", _SIGNATURE
            }
            or document.get("schema") != _ENROLLMENT_SCHEMA
            or not isinstance(document.get("created_at"), (int, float))
            or isinstance(document.get("created_at"), bool)
            or not math.isfinite(float(document["created_at"]))
            or not isinstance(document.get("enrollment_id"), str)
            or len(document["enrollment_id"]) != 32
            or any(char not in "0123456789abcdef" for char in document["enrollment_id"])
            or type(document.get("revision")) is not int
            or not 1 <= int(document["revision"]) <= 2**63 - 1
            or not self._authenticated(document, _ENROLLMENT_DOMAIN)
        ):
            raise ValueError("event-log enrollment epoch is invalid")
        return (
            document["enrollment_id"],
            float(document["created_at"]),
            int(document["revision"]),
        )

    def _parse_cursor(
        self, payload: bytes
    ) -> tuple[str, int, bool, dict[str, ChannelCheckpoint]]:
        document = self._strict_json(payload)
        if (
            set(document) != {
                "schema", "updated_at", "enrollment_id", "revision",
                "coverage_complete", "channels", _SIGNATURE,
            }
            or document.get("schema") != _SCHEMA
            or not isinstance(document.get("updated_at"), (int, float))
            or isinstance(document.get("updated_at"), bool)
            or not math.isfinite(float(document["updated_at"]))
            or not isinstance(document.get("enrollment_id"), str)
            or len(document["enrollment_id"]) != 32
            or any(char not in "0123456789abcdef" for char in document["enrollment_id"])
            or type(document.get("revision")) is not int
            or not 1 <= int(document["revision"]) <= 2**63 - 1
            or type(document.get("coverage_complete")) is not bool
            or not isinstance(document.get("channels"), dict)
            or len(document["channels"]) > _MAX_CHANNELS
            or not self._authenticated(document, _DOMAIN)
        ):
            raise ValueError("event-log cursor is invalid")
        checkpoints: dict[str, ChannelCheckpoint] = {}
        for channel, value in document["channels"].items():
            if (
                not isinstance(channel, str)
                or not 1 <= len(channel) <= 200
                or not isinstance(value, dict)
                or set(value) != {"record_id", "anchor"}
                or type(value.get("record_id")) is not int
                or value["record_id"] < 0
                or not isinstance(value.get("anchor"), str)
            ):
                raise ValueError("event-log channel cursor is invalid")
            anchor = value["anchor"]
            if (
                (value["record_id"] == 0 and anchor)
                or (
                    value["record_id"] > 0
                    and (
                        len(anchor) != 64
                        or any(char not in "0123456789abcdef" for char in anchor)
                    )
                )
            ):
                raise ValueError("event-log channel anchor is invalid")
            checkpoints[channel] = ChannelCheckpoint(value["record_id"], anchor)
        return (
            document["enrollment_id"],
            int(document["revision"]),
            bool(document["coverage_complete"]),
            checkpoints,
        )

    def load(self) -> tuple[dict[str, ChannelCheckpoint], str]:
        self._recovery_allowed = False
        cursor_payload, cursor_digest = self._existing_payload(self.path)
        epoch_payload, epoch_digest = self._existing_payload(self.enrollment_path)
        self._expected_cursor_digest = cursor_digest
        self._expected_enrollment_digest = epoch_digest
        if cursor_digest is None or epoch_digest is None:
            self._load_state = "untrusted"
            self._freshness = HighWaterAssessment(
                "local-state-invalid", "local state could not be admitted", False
            )
            return {}, "untrusted"
        if cursor_payload is None and epoch_payload is None:
            self._load_state = "first-enrollment"
            self._revision = 0
            self._coverage_complete = False
            self._freshness = self._first_enrollment_freshness()
            self._recovery_allowed = self._high_water is None or (
                self._freshness.state == "ready-first-enrollment"
            )
            if self._freshness.state in {
                "local-behind", "fork-detected", "installation-mismatch",
                "authority-rejected",
            }:
                self._load_state = "untrusted"
                return {}, "untrusted"
            return {}, "first-enrollment"
        try:
            if epoch_payload is None:
                raise ValueError("enrollment epoch is missing")
            enrollment_id, created_at, epoch_revision = self._parse_enrollment(epoch_payload)
            self._enrollment_id = enrollment_id
            self._created_at = created_at
            self._revision = epoch_revision
            self._recovery_allowed = True
            if cursor_payload is None:
                self._load_state = "untrusted"
                return {}, "untrusted"
            cursor_id, cursor_revision, coverage_complete, checkpoints = (
                self._parse_cursor(cursor_payload)
            )
            if cursor_id != enrollment_id or cursor_revision != epoch_revision:
                raise ValueError("event-log enrollment/cursor revision mismatch")
            self._coverage_complete = coverage_complete
            self._freshness = self._assess_loaded_freshness(
                cursor_payload, epoch_payload
            )
            if self._freshness.state in {
                "local-behind", "fork-detected", "installation-mismatch",
                "authority-rejected",
            }:
                self._load_state = "untrusted"
                self._recovery_allowed = False
                return {}, "untrusted"
            if self._high_water is not None and not self._freshness.independently_fresh:
                self._load_state = "provisional"
                self._recovery_allowed = False
                return checkpoints, "provisional"
            self._load_state = "authenticated"
            return checkpoints, "authenticated"
        except (OSError, TypeError, ValueError, json.JSONDecodeError, UnicodeError):
            self._load_state = "untrusted"
            self._freshness = HighWaterAssessment(
                "local-state-invalid", "local state authentication failed", False
            )
            return {}, "untrusted"

    @staticmethod
    def _secure_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if _path_has_link_or_reparse(path.parent) or (
            path.exists() and _path_has_link_or_reparse(path)
        ):
            raise OSError("checkpoint destination is link/reparse-backed")
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        temporary = Path(temp_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, path)
            after = path.lstat()
            if not stat.S_ISREG(after.st_mode) or _is_link_or_reparse(after):
                raise OSError("checkpoint destination changed file type")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _unchanged_since_load(self) -> bool:
        _cursor, cursor_digest = self._existing_payload(self.path)
        _epoch, epoch_digest = self._existing_payload(self.enrollment_path)
        return (
            cursor_digest is not None
            and epoch_digest is not None
            and cursor_digest == self._expected_cursor_digest
            and epoch_digest == self._expected_enrollment_digest
        )

    def verify_unchanged(self) -> bool:
        """Revalidate authenticated state without rotating identical files.

        Quiescent polling still performs the same bounded, link/reparse-aware
        reads and byte-exact compare-and-swap check.  Avoiding a revision-only
        rewrite removes two durable file replacements per idle poll while an
        altered or missing member continues to fail closed.
        """
        locally_unchanged = (
            self._load_state == "authenticated"
            and self._recovery_allowed
            and self._unchanged_since_load()
        )
        if not locally_unchanged:
            return False
        if self._high_water is None:
            return True
        cursor_payload, cursor_digest = self._existing_payload(self.path)
        epoch_payload, epoch_digest = self._existing_payload(self.enrollment_path)
        if (
            cursor_payload is None
            or epoch_payload is None
            or cursor_digest != self._expected_cursor_digest
            or epoch_digest != self._expected_enrollment_digest
        ):
            return False
        self._freshness = self._assess_loaded_freshness(cursor_payload, epoch_payload)
        return self._freshness.independently_fresh

    def save(
        self,
        checkpoints: Mapping[str, ChannelCheckpoint],
        *,
        coverage_complete: bool = True,
    ) -> bool:
        if (
            len(checkpoints) > _MAX_CHANNELS
            or type(coverage_complete) is not bool
            or not self._recovery_allowed
            or self._load_state not in {"first-enrollment", "authenticated", "untrusted"}
        ):
            return False
        channels: dict[str, dict[str, object]] = {}
        for channel, checkpoint in sorted(checkpoints.items()):
            if not isinstance(channel, str) or not 1 <= len(channel) <= 200:
                return False
            record_id = int(checkpoint.record_id)
            anchor = str(checkpoint.anchor)
            if record_id < 0 or (
                (record_id == 0 and anchor)
                or (
                    record_id > 0
                    and (
                        len(anchor) != 64
                        or any(char not in "0123456789abcdef" for char in anchor)
                    )
                )
            ):
                return False
            channels[channel] = {"record_id": record_id, "anchor": anchor}
        cursor_key = self._key(_DOMAIN)
        enrollment_key = self._key(_ENROLLMENT_DOMAIN)
        if cursor_key is None or enrollment_key is None or not self._unchanged_since_load():
            return False
        now = time.time()
        enrollment_id = self._enrollment_id or secrets.token_hex(16)
        created_at = self._created_at or now
        revision = self._revision + 1
        cursor: dict[str, object] = {
            "schema": _SCHEMA,
            "updated_at": now,
            "enrollment_id": enrollment_id,
            "revision": revision,
            "coverage_complete": coverage_complete,
            "channels": channels,
        }
        cursor[_SIGNATURE] = hmac.new(
            cursor_key, self._body(cursor), hashlib.sha256
        ).hexdigest()
        enrollment: dict[str, object] = {
            "schema": _ENROLLMENT_SCHEMA,
            "created_at": created_at,
            "enrollment_id": enrollment_id,
            "revision": revision,
        }
        enrollment[_SIGNATURE] = hmac.new(
            enrollment_key, self._body(enrollment), hashlib.sha256
        ).hexdigest()
        cursor_payload = json.dumps(
            cursor, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        enrollment_payload = json.dumps(
            enrollment, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if (
            len(cursor_payload) > _MAX_CHECKPOINT_BYTES
            or len(enrollment_payload) > _MAX_CHECKPOINT_BYTES
        ):
            return False
        state_digest = state_pair_digest(
            domain=AUDIT_DOMAIN,
            installation_id=enrollment_id,
            revision=revision,
            primary_payload=cursor_payload,
            epoch_payload=enrollment_payload,
        )
        if self._high_water is not None:
            if self._freshness.state not in {"ready-first-enrollment", "verified"}:
                return False
            previous_revision = self._revision
            previous_digest = (
                self._freshness.state_digest if previous_revision else ZERO_DIGEST
            )
            previous_head = self._freshness.head if previous_revision else ZERO_DIGEST
            advanced = advance_high_water(
                self._high_water,
                domain=AUDIT_DOMAIN,
                installation_id=enrollment_id,
                previous_revision=previous_revision,
                previous_state_digest=previous_digest,
                previous_head=previous_head,
                revision=revision,
                state_digest=state_digest,
            )
            self._freshness = advanced
            if not advanced.independently_fresh:
                self._recovery_allowed = False
                return False
        try:
            # Cursor first means a crash cannot advance the enrollment epoch to
            # a state that appears complete while its matching cursor is absent.
            self._secure_write(self.path, cursor_payload)
            self._secure_write(self.enrollment_path, enrollment_payload)
        except OSError:
            if self._high_water is not None and self._freshness.independently_fresh:
                self._freshness = HighWaterAssessment(
                    "external-ahead-crash-recovery-required",
                    "independent head advanced before the local pair was durable",
                    False,
                    head=self._freshness.head,
                    state_digest=state_digest,
                )
                self._recovery_allowed = False
            return False
        self._enrollment_id = enrollment_id
        self._created_at = created_at
        self._revision = revision
        self._coverage_complete = coverage_complete
        self._load_state = "authenticated"
        self._expected_cursor_digest = hashlib.sha256(cursor_payload).hexdigest()
        self._expected_enrollment_digest = hashlib.sha256(enrollment_payload).hexdigest()
        self._recovery_allowed = True
        if self._high_water is None:
            self._freshness = HighWaterAssessment(
                "local-authenticity-only",
                "local HMAC authenticity is verified without independent freshness",
                False,
                state_digest=state_digest,
            )
        return True


__all__ = [
    "AuditEventRejected",
    "AuditIntegrityRecord",
    "AuthenticatedEventLogCheckpoint",
    "ChannelCheckpoint",
    "ContinuityAssessment",
    "assess_continuity",
    "audit_event_selectors",
    "parse_audit_integrity_xml",
]
