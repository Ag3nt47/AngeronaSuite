"""AV Telemetry Bridge — G2-G (part 1).

Bridges Windows Defender operational events into the Angerona event bus.

Monitored Event IDs (Microsoft-Windows-Windows Defender/Operational channel):
  EID 1116 — Malware detected (threat name, file path, detection source)
  EID 1117 — Malware action taken (quarantine/remove/block)
  EID 5001 — Real-time protection disabled (CRITICAL — sensor gap)

Why this matters:
  Windows Defender is always on for home/SMB users.  When it detects something,
  we want that signal on our bus so SOAR / provenance_graph / AI-triage can
  correlate it with our own sensor output.  EID 5001 is especially important —
  an attacker who disables real-time protection opens a sensor gap that our
  bus should immediately surface.

Implementation:
  Uses win32evtlog on the Defender Operational channel (same pattern as
  etw_listener and sysmon_listener).  The Defender channel is readable by
  non-admin users — no elevation required.

Fallback:
  If win32evtlog is unavailable (non-Windows / no pywin32), the module
  falls back to polling `Get-MpThreatDetection` via PowerShell every 60s.
  The PowerShell path requires Windows Defender cmdlets (present by default
  on Windows 10/11).  If neither method works, the module idles.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import ntpath
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from angerona.core.module_base import BaseModule, Severity
from angerona.core.data_paths import data_dir as canonical_data_dir
from angerona.core.durable_outbox import DurableOutbox
from angerona.core.event_log_integrity import (
    AuthenticatedEventLogCheckpoint,
    ChannelCheckpoint,
    assess_continuity,
)
from angerona.core.win import check_output_hidden

_DEFENDER_CHANNEL   = "Microsoft-Windows-Windows Defender/Operational"
_EVTLOG_SEQ_FWD     = 0x0001 | 0x0004   # SEQUENTIAL_READ | FORWARDS_READ
_EVTLOG_SEEK_FWD    = 0x0002 | 0x0004   # SEEK_READ | FORWARDS_READ
_MAX_EVENT_XML_CHARS = 1024 * 1024
_MAX_NATIVE_BATCH = 512
_MAX_FALLBACK_RECORDS = 4096
_MAX_FALLBACK_OUTPUT_BYTES = 4 * 1024 * 1024
_POLL_INTERVAL      = 30.0              # seconds between log reads (was 10 — AV events don't need sub-30s latency)
_FALLBACK_INTERVAL  = 120.0            # seconds between PowerShell polls (was 60)
_OUTBOX_KEY_DOMAIN = b"angerona/defender-delivery-outbox/v1\x00"
_OUTBOX_ENROLLMENT_DOMAIN = b"angerona/defender-outbox-enrollment/v2\x00"
_OUTBOX_ENROLLMENT_SCHEMA = "angerona.defender-outbox-enrollment.v2"
_MAX_OUTBOX_ENROLLMENT_BYTES = 16 * 1024
_OUTBOX_WITNESS_COLUMNS = (
    "item_id,payload_json,payload_sha256,signature,state,attempts,"
    "next_attempt,lease_owner,lease_until,last_error,created_at,size_bytes,"
    "state_signature"
)

# Map Defender EID → (label, Severity, MITRE)
_EID_MAP = {
    1116: ("Malware Detected",              Severity.CRITICAL, ["T1204", "T1059"]),
    1117: ("Malware Action Taken",          Severity.HIGH,     ["T1204"]),
    5001: ("Real-Time Protection Disabled", Severity.CRITICAL, ["T1562.001"]),
}

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _local_artifact_paths(value: object) -> tuple[str, ...]:
    """Return unambiguous local Windows file resources from Defender.

    Defender commonly prefixes paths with ``file:_`` and PowerShell exposes
    ``Resources`` as either one string or a list.  Unsupported resource kinds,
    mixed lists, UNC/device paths, controls and relative paths fail closed to an
    empty tuple.  Callers retain the raw value for evidence/display.
    """
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return ()
    if not items or len(items) > 64:
        return ()
    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str):
            return ()
        text = item.strip()
        if not text or len(text) > 4096 or any(ord(ch) < 32 for ch in text):
            return ()
        if text.casefold().startswith("file:_"):
            text = text[6:]
        elif ":_" in text[:32]:
            # A different Defender resource scheme (containerfile, process,
            # webfile, ...). Never reinterpret it as a local artifact.
            return ()
        windows = text.replace("/", "\\")
        if windows.startswith(("\\\\", "\\\\?\\", "\\\\.\\")):
            return ()
        drive, tail = ntpath.splitdrive(windows)
        if (
            len(drive) != 2
            or drive[1:] != ":"
            or not drive[0].isalpha()
            or not tail.startswith("\\")
        ):
            return ()
        candidate = ntpath.normpath(windows)
        if any(part == ".." for part in candidate.split("\\")):
            return ()
        normalized.append(candidate)
    return tuple(dict.fromkeys(normalized))


def _with_artifact_paths(details: dict, value: object) -> dict:
    paths = _local_artifact_paths(value)
    if paths:
        details["artifact_paths"] = list(paths)
        if len(paths) == 1:
            details["artifact_path"] = paths[0]
    return details


def _extract(root: ET.Element, name: str) -> str:
    for node in root.iter(f"{{{_NS}}}Data"):
        if node.get("Name") == name:
            return (node.text or "").strip()[:4096]
    return ""


def _parse_1116(root: ET.Element) -> tuple[str, dict]:
    threat    = _extract(root, "Threat Name")
    path      = _extract(root, "Path")
    severity  = _extract(root, "Severity Name")
    action    = _extract(root, "Action Name")
    proc      = _extract(root, "Process Name")
    msg = (
        f"Defender detected {threat!r} at {path!r} "
        f"(severity={severity}, action={action}, process={proc})"
    )
    details = _with_artifact_paths({
        "threat_name":    threat,
        "path":           path,
        "av_severity":    severity,
        "action":         action,
        "process":        proc,
        "mitre_tags":     ["T1204", "T1059"],
    }, path)
    return msg, details


def _parse_1117(root: ET.Element) -> tuple[str, dict]:
    threat  = _extract(root, "Threat Name")
    path    = _extract(root, "Path")
    action  = _extract(root, "Action Name")
    result  = _extract(root, "Action Status")
    msg = f"Defender remediated {threat!r} — {action} on {path!r} ({result})"
    details = _with_artifact_paths({
        "threat_name":    threat,
        "path":           path,
        "action":         action,
        "result":         result,
        "mitre_tags":     ["T1204"],
    }, path)
    return msg, details


def _parse_5001(root: ET.Element) -> tuple[str, dict]:
    reason = _extract(root, "Reason") or "unknown reason"
    msg    = (
        f"Windows Defender REAL-TIME PROTECTION DISABLED ({reason}) — "
        "sensor gap: threats may execute undetected (T1562.001)"
    )
    return msg, {"reason": reason, "mitre_tags": ["T1562.001"]}


_PARSERS = {1116: _parse_1116, 1117: _parse_1117, 5001: _parse_5001}


class AVTelemetryBridgeModule(BaseModule):
    CODE = "AVTB"
    NAME = "AV Telemetry Bridge"
    name = "AV Telemetry Bridge"
    version = "1.13.0"
    description = (
        "Bridges Windows Defender detection events (EID 1116/1117/5001) into "
        "the Angerona bus for cross-sensor correlation."
    )
    category = "Endpoint"

    def __init__(
        self,
        data_root: Path | None = None,
        *,
        continuity_key: bytes | None = None,
    ) -> None:
        super().__init__()
        if continuity_key is not None and (
            not isinstance(continuity_key, bytes) or len(continuity_key) != 32
        ):
            raise ValueError("Defender continuity key must contain 32 bytes")
        self._data_root = Path(data_root) if data_root is not None else None
        self._continuity_key_override = continuity_key
        self._outbox: DurableOutbox | None = None
        self._outbox_owner = f"defender-{uuid.uuid4().hex}"
        self._outbox_signing_key: bytes | None = None
        self._outbox_enrollment: dict[str, object] | None = None
        self._outbox_draining = False
        self._outbox_redrain = False
        self._checkpoint: AuthenticatedEventLogCheckpoint | None = None
        self._checkpoints: dict[str, ChannelCheckpoint] = {}
        self._checkpoint_status = "unloaded"
        self._continuity_gaps = 0
        self._persisted_gap = False
        self._expected_record_id = 0
        self._delivered = 0
        self._skipped = 0
        self._errors = 0

    @property
    def _state_root(self) -> Path:
        return self._data_root or canonical_data_dir()

    def _continuity_key(self) -> bytes | None:
        key = self._continuity_key_override
        if key is None:
            authority = getattr(self._bus, "_authority", None)
            candidate = getattr(authority, "_key", None)
            if isinstance(candidate, bytes):
                key = candidate
        if key is None:
            try:
                key = bytes.fromhex(
                    (self._state_root / "bus.key")
                    .read_text(encoding="ascii")
                    .strip()
                )
            except (OSError, ValueError):
                return None
        return key if isinstance(key, bytes) and len(key) == 32 else None

    @property
    def _outbox_path(self) -> Path:
        return self._state_root / "outbox" / "defender.sqlite3"

    @property
    def _outbox_enrollment_path(self) -> Path:
        return self._state_root / "security-state" / "defender-outbox.json"

    @staticmethod
    def _canonical_state(value: dict[str, object]) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def _outbox_state_witness(self) -> str:
        """Digest the complete authenticated SQLite authority under its lock."""
        outbox = self._outbox
        if outbox is None:
            raise RuntimeError("Defender outbox witness is unavailable")
        with outbox._lock:
            outbox._verify_if_database_changed_locked()
            rows = outbox._db.execute(
                f"SELECT {_OUTBOX_WITNESS_COLUMNS} FROM durable_outbox "
                "ORDER BY item_id"
            ).fetchall()
            for row in rows:
                outbox._verify_row(row)
            body = {
                "schema": "angerona.defender-outbox-state-witness.v1",
                "rows": [list(row) for row in rows],
            }
            return hashlib.sha256(self._canonical_state(body)).hexdigest()

    def _write_outbox_enrollment(
        self, key: bytes, core: dict[str, object]
    ) -> None:
        path = self._outbox_enrollment_path
        path.parent.mkdir(parents=True, exist_ok=True)
        signed = dict(core)
        signed["record_hmac"] = hmac.new(
            key,
            _OUTBOX_ENROLLMENT_DOMAIN + self._canonical_state(core),
            hashlib.sha256,
        ).hexdigest()
        payload = self._canonical_state(signed)
        if len(payload) > _MAX_OUTBOX_ENROLLMENT_BYTES:
            raise OSError("Defender outbox enrollment exceeded its bound")
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("Defender outbox enrollment write was incomplete")
                written += count
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, path)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _persist_outbox_enrollment(self) -> None:
        key = self._outbox_signing_key
        enrollment = self._outbox_enrollment
        if key is None or enrollment is None:
            raise RuntimeError("Defender outbox enrollment authority is unavailable")
        witness = self._outbox_state_witness()
        if hmac.compare_digest(
            str(enrollment.get("outbox_state_sha256") or ""), witness
        ):
            return
        generation = enrollment.get("state_generation")
        if type(generation) is not int or generation < 0:
            raise RuntimeError("Defender outbox enrollment generation is invalid")
        updated = {
            **enrollment,
            "state_generation": generation + 1,
            "outbox_state_sha256": witness,
        }
        self._write_outbox_enrollment(key, updated)
        self._outbox_enrollment = updated

    def _enqueue_outbox(
        self, item_id: str, payload: dict[str, object]
    ) -> bool:
        if self._outbox is None:
            raise RuntimeError("Defender delivery outbox is unavailable")
        enqueued = self._outbox.enqueue(item_id, payload)
        self._persist_outbox_enrollment()
        return enqueued

    def _verify_or_enroll_outbox(self, key: bytes, *, database_existed: bool) -> None:
        path = self._outbox_enrollment_path
        if not path.exists():
            if database_existed:
                raise RuntimeError(
                    "existing Defender outbox lacks an enrollment witness"
                )
            # Only a database created in this retained open operation may be
            # enrolled. Missing witness authority for any pre-existing SQLite
            # object is ambiguous and therefore fails closed.
            core: dict[str, object] = {
                "schema": _OUTBOX_ENROLLMENT_SCHEMA,
                "enrollment_id": secrets.token_hex(16),
                "database_name": self._outbox_path.name,
                "created_at": time.time(),
                "state_generation": 0,
                "outbox_state_sha256": self._outbox_state_witness(),
            }
            self._write_outbox_enrollment(key, core)
            self._outbox_enrollment = core
            return
        try:
            raw = path.read_bytes()
            if not raw or len(raw) > _MAX_OUTBOX_ENROLLMENT_BYTES:
                raise ValueError("enrollment size is invalid")
            value = json.loads(raw)
            if not isinstance(value, dict) or set(value) != {
                "schema",
                "enrollment_id",
                "database_name",
                "created_at",
                "state_generation",
                "outbox_state_sha256",
                "record_hmac",
            }:
                raise ValueError("enrollment schema is invalid")
            signature = value.pop("record_hmac")
            enrollment_id = value.get("enrollment_id")
            created_at = value.get("created_at")
            generation = value.get("state_generation")
            witness = value.get("outbox_state_sha256")
            if (
                value.get("schema") != _OUTBOX_ENROLLMENT_SCHEMA
                or not isinstance(enrollment_id, str)
                or len(enrollment_id) != 32
                or any(ch not in "0123456789abcdef" for ch in enrollment_id)
                or value.get("database_name") != self._outbox_path.name
                or not isinstance(created_at, (int, float))
                or isinstance(created_at, bool)
                or not math.isfinite(float(created_at))
                or type(generation) is not int
                or generation < 0
                or not isinstance(witness, str)
                or len(witness) != 64
                or any(ch not in "0123456789abcdef" for ch in witness)
                or not isinstance(signature, str)
            ):
                raise ValueError("enrollment fields are invalid")
            expected = hmac.new(
                key,
                _OUTBOX_ENROLLMENT_DOMAIN + self._canonical_state(value),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("enrollment authentication failed")
            if not database_existed:
                raise ValueError("enrolled Defender outbox database is missing")
            if not hmac.compare_digest(witness, self._outbox_state_witness()):
                raise ValueError("enrolled Defender outbox state was rolled back")
            self._outbox_enrollment = value
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Defender outbox enrollment is invalid") from exc

    def _persist_incomplete_coverage(self) -> None:
        self._persisted_gap = True
        self._continuity_gaps = max(1, self._continuity_gaps)
        checkpoint = self._checkpoint
        if checkpoint is None or self._checkpoint_status not in {
            "first-enrollment", "authenticated"
        }:
            return
        if checkpoint.save(self._checkpoints, coverage_complete=False):
            self._checkpoint_status = "authenticated"

    def _open_continuity_state(self) -> bool:
        key = self._continuity_key()
        if key is None:
            self.set_health(20, "Defender continuity authority is unavailable")
            return False
        cursor = self._state_root / "sensor-cursors" / "defender.json"
        self._checkpoint = AuthenticatedEventLogCheckpoint(
            cursor,
            key,
            enrollment_path=(
                self._state_root / "security-state" / "defender-enrollment.json"
            ),
        )
        self._checkpoints, self._checkpoint_status = self._checkpoint.load()
        if (
            self._checkpoint_status == "authenticated"
            and not self._checkpoint.coverage_complete
        ):
            self._persisted_gap = True
            self._continuity_gaps = max(1, self._continuity_gaps)
            self.set_health(
                45,
                "persisted Defender continuity gap requires explicit recovery",
            )
        outbox_key = hmac.new(key, _OUTBOX_KEY_DOMAIN, hashlib.sha256).digest()
        self._outbox_signing_key = outbox_key
        self._outbox_enrollment = None
        database_existed = self._outbox_path.exists()
        marker_existed = self._outbox_enrollment_path.exists()
        if marker_existed and not database_existed:
            self._continuity_gap(
                "Enrolled Defender outbox is missing; delivery continuity is untrusted",
                reason_code="defender.outbox.missing",
            )
            return False
        try:
            self._outbox = DurableOutbox(
                self._outbox_path,
                outbox_key,
                max_items=20_000,
                max_bytes=128 * 1024 * 1024,
                delivered_tombstones=20_000,
            )
            # Force complete row authentication before accepting or creating an
            # independent existence enrollment.
            self._outbox.stats()
            self._verify_or_enroll_outbox(
                outbox_key, database_existed=database_existed
            )
        except Exception as exc:
            if self._outbox is not None:
                self._outbox.close()
                self._outbox = None
            self._outbox_signing_key = None
            self._outbox_enrollment = None
            self._continuity_gap(
                "Defender outbox authentication/enrollment failed",
                reason_code="defender.outbox.untrusted",
                error_type=type(exc).__name__,
            )
            return False
        if self._checkpoint_status in {"untrusted", "provisional"}:
            self._continuity_gap(
                "Defender cursor authentication/freshness failed; replaying retained "
                "records without claiming complete continuity",
                reason_code="defender.cursor.untrusted",
            )
        if self._outbox is not None:
            stats = self._outbox.stats()
            if self._current_record_id() > 0 or (
                stats.pending == 1 and not stats.leased and not stats.dead_letter
            ):
                self._drain_outbox()
        return True

    def _close_continuity_state(self) -> None:
        if self._outbox is not None:
            try:
                # Also witnesses direct diagnostic/test admission through the
                # private outbox handle before releasing SQLite custody.
                self._persist_outbox_enrollment()
            except Exception as exc:
                self._errors += 1
                self._persist_incomplete_coverage()
                self.set_health(
                    20,
                    "Defender outbox witness could not be committed before close: "
                    f"{type(exc).__name__}",
                )
            self._outbox.close()
            self._outbox = None
        self._outbox_signing_key = None
        self._outbox_enrollment = None

    @staticmethod
    def _record_number(rec: object) -> int:
        try:
            return max(0, int(getattr(rec, "RecordNumber")))
        except (AttributeError, TypeError, ValueError, OverflowError):
            return 0

    @classmethod
    def _record_digest(cls, rec: object) -> str:
        try:
            inserts = getattr(rec, "StringInserts", None)
            first = inserts[0] if inserts and isinstance(inserts[0], str) else ""
        except Exception:
            first = ""
        try:
            event_id = int(getattr(rec, "EventID", 0)) & 0xFFFF
        except (TypeError, ValueError, OverflowError):
            event_id = 0
        body = json.dumps(
            {
                "channel": _DEFENDER_CHANNEL,
                "record_number": cls._record_number(rec),
                "event_id": event_id,
                "time_generated": str(getattr(rec, "TimeGenerated", ""))[:256],
                "xml_sha256": hashlib.sha256(
                    first[:_MAX_EVENT_XML_CHARS].encode("utf-8", "replace")
                ).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    def _counter_details(self) -> dict[str, int]:
        return {
            "delivered_records": self._delivered,
            "skipped_records": self._skipped,
            "delivery_errors": self._errors,
            "continuity_gaps": self._continuity_gaps,
        }

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        if self._try_evtlog_mode():
            return
        if self._try_powershell_mode():
            return
        # Both unavailable
        self.set_health(0, "Defender channel and PowerShell cmdlets unavailable")
        self.emit(
            "AV Telemetry Bridge: no telemetry path available (non-Windows or no pywin32/MpCmdRun). "
            "Module idle.",
            Severity.MEDIUM,
        )
        while not self.stopping:
            self.sleep(120.0)

    # ── win32evtlog mode ──────────────────────────────────────────────────────
    def _try_evtlog_mode(self) -> bool:
        handle = None
        try:
            import win32evtlog  # type: ignore[import]
            handle = win32evtlog.OpenEventLog(None, _DEFENDER_CHANNEL)
        except Exception:
            return False
        try:
            if not self._open_continuity_state():
                return False
            resume_after = self._native_resume_after(win32evtlog, handle)
            self._expected_record_id = max(1, resume_after + 1)
            self._drain_outbox()
            self.emit(
                f"AV Telemetry Bridge active — monitoring {_DEFENDER_CHANNEL}",
                Severity.INFO,
                channel=_DEFENDER_CHANNEL,
                continuity_state=self._checkpoint_status,
                resume_after=resume_after,
                **self._counter_details(),
            )
            first_read = True
            while not self.stopping:
                try:
                    flags = _EVTLOG_SEEK_FWD if first_read else _EVTLOG_SEQ_FWD
                    offset = resume_after + 1 if first_read else 0
                    records = tuple(
                        win32evtlog.ReadEventLog(handle, flags, offset) or ()
                    )
                    first_read = False
                    for record in records[:_MAX_NATIVE_BATCH]:
                        self._stage_native_record(record)
                        resume_after = max(
                            resume_after, self._record_number(record)
                        )
                    if len(records) > _MAX_NATIVE_BATCH:
                        # The native handle may have advanced across the whole
                        # page. Seek from the last durably consumed record on
                        # the next pass instead of dropping the page suffix.
                        first_read = True
                    self._drain_outbox()
                    self._refresh_native_health()
                except Exception as exc:
                    self._errors += 1
                    self._continuity_gap(
                        "Defender channel read/reopen failed; the delivery cursor "
                        "was not advanced",
                        reason_code="defender.channel.read_error",
                        error_type=type(exc).__name__,
                    )
                    self._close_eventlog(win32evtlog, handle)
                    handle = None
                    try:
                        handle = win32evtlog.OpenEventLog(None, _DEFENDER_CHANNEL)
                        resume_after = self._current_record_id()
                        first_read = True
                    except Exception:
                        self.set_health(25, "Defender channel reopen failed")
                self.sleep(_POLL_INTERVAL)
        finally:
            self._close_eventlog(win32evtlog, handle)
            self._close_continuity_state()
        return True

    @staticmethod
    def _close_eventlog(api: object, handle: object) -> None:
        if handle is None:
            return
        closer = getattr(api, "CloseEventLog", None)
        if callable(closer):
            try:
                closer(handle)
            except Exception:
                pass

    def _current_record_id(self) -> int:
        checkpoint = self._checkpoints.get(_DEFENDER_CHANNEL)
        return int(checkpoint.record_id) if checkpoint is not None else 0

    def _native_resume_after(self, api: object, handle: object) -> int:
        checkpoint = self._checkpoints.get(_DEFENDER_CHANNEL)
        status = self._checkpoint_status
        try:
            oldest = max(1, int(api.GetOldestEventLogRecord(handle)))
            count = max(0, int(api.GetNumberOfEventLogRecords(handle)))
            newest = oldest + count - 1 if count else 0
        except Exception:
            # The classic API range helpers may be absent in test/legacy
            # backends. A valid authenticated cursor is still safe to seek;
            # first enrollment starts with retained records instead of draining.
            return int(checkpoint.record_id) if checkpoint is not None else 0

        retained_anchor = ""
        if checkpoint is not None and oldest <= checkpoint.record_id <= newest:
            verifier = None
            try:
                verifier = api.OpenEventLog(None, _DEFENDER_CHANNEL)
                candidates = api.ReadEventLog(
                    verifier, _EVTLOG_SEEK_FWD, checkpoint.record_id
                )
                exact = next(
                    (
                        item
                        for item in candidates or ()
                        if self._record_number(item) == checkpoint.record_id
                    ),
                    None,
                )
                if exact is not None:
                    retained_anchor = self._record_digest(exact)
            except Exception:
                retained_anchor = ""
            finally:
                self._close_eventlog(api, verifier)

        assessment = assess_continuity(
            checkpoint,
            oldest=oldest,
            newest=newest,
            retained_anchor=retained_anchor,
            checkpoint_status=status,
        )
        if assessment.state in {"gap", "untrusted"}:
            self._continuity_gap(
                assessment.reason,
                reason_code="defender.channel.continuity_gap",
                missing_start=assessment.missing_start,
                missing_end=assessment.missing_end,
                oldest_retained_record=oldest,
                newest_retained_record=newest,
            )
        elif assessment.state == "enrollment":
            self.set_health(
                70,
                "first enrollment is replaying retained Defender evidence",
            )
        return assessment.resume_after

    def _decode_record(
        self, rec: object
    ) -> tuple[str, Severity, dict] | None:
        try:
            eid = int(rec.EventID & 0xFFFF)
        except Exception:
            return None
        if eid not in _EID_MAP:
            return None
        _, severity, _ = _EID_MAP[eid]
        parser = _PARSERS.get(eid)

        xml_str: Optional[str] = None
        try:
            inserts = rec.StringInserts
            if inserts and isinstance(inserts[0], str):
                xml_str = inserts[0]
        except Exception:
            pass

        if xml_str and parser and len(xml_str) <= _MAX_EVENT_XML_CHARS:
            try:
                root = ET.fromstring(xml_str)
                msg, details = parser(root)
            except (ET.ParseError, DefusedXmlException):
                msg     = f"Defender EID {eid} (XML parse error)"
                details = {}
        elif xml_str and len(xml_str) > _MAX_EVENT_XML_CHARS:
            msg = f"Defender EID {eid} (XML payload exceeded safety bound)"
            details = {"xml_status": "oversized"}
        else:
            label   = _EID_MAP[eid][0]
            msg     = f"Defender: {label} (EID {eid})"
            details = {}

        record_number = self._record_number(rec)
        digest = self._record_digest(rec)
        return msg, severity, {
            "eid": eid,
            **details,
            "channel": _DEFENDER_CHANNEL,
            "channel_record_id": record_number or None,
            "channel_record_sha256": digest,
            "delivery_semantics": "durable-at-least-once",
        }

    def _process_record(self, rec: object) -> None:
        """Compatibility entry point for one already-admitted record."""
        decoded = self._decode_record(rec)
        if decoded is not None:
            message, severity, details = decoded
            self.emit(message, severity, **details)

    def _stage_native_record(self, rec: object) -> None:
        record_number = self._record_number(rec)
        digest = self._record_digest(rec)
        if record_number and not self._current_record_id() and not self._expected_record_id:
            self._expected_record_id = record_number
        decoded = self._decode_record(rec)
        if decoded is None:
            self._skipped += 1
            if not record_number:
                self._continuity_gap(
                    "Defender record had no stable channel record identity",
                    reason_code="defender.record.identity_missing",
                    event_sha256=digest,
                )
            elif not self._save_checkpoint(record_number, digest):
                raise RuntimeError("filtered Defender cursor could not be committed")
            return
        if self._outbox is None:
            raise RuntimeError("Defender delivery outbox is unavailable")
        message, severity, details = decoded
        if not record_number:
            self._continuity_gap(
                "Defender event had no stable channel record identity",
                reason_code="defender.record.identity_missing",
                event_sha256=digest,
            )
        item_id = f"defender-event-{record_number}-{digest}"
        self._enqueue_outbox(
            item_id,
            {
                "schema": "angerona.defender-delivery.v1",
                "kind": "event",
                "message": message,
                "severity": int(severity),
                "details": details,
                "record_number": record_number,
                "record_anchor": digest,
            },
        )
        self._drain_outbox()

    def _save_checkpoint(self, record_number: int, anchor: str) -> bool:
        if (
            self._checkpoint is None
            or record_number <= 0
            or not isinstance(anchor, str)
            or len(anchor) != 64
            or any(ch not in "0123456789abcdef" for ch in anchor)
        ):
            return False
        current = self._checkpoints.get(_DEFENDER_CHANNEL)
        current_id = int(current.record_id) if current is not None else 0
        if record_number < current_id:
            return False
        if record_number == current_id:
            return current is not None and hmac.compare_digest(current.anchor, anchor)
        expected = current_id + 1 if current_id else self._expected_record_id
        if expected and record_number != expected:
            self._persist_incomplete_coverage()
            self.set_health(
                45,
                f"Defender cursor gap: expected record {expected}, received "
                f"{record_number}",
            )
            return False
        updated = dict(self._checkpoints)
        updated[_DEFENDER_CHANNEL] = ChannelCheckpoint(record_number, anchor)
        coverage_complete = not self._persisted_gap and self._continuity_gaps == 0
        if not self._checkpoint.save(
            updated,
            coverage_complete=coverage_complete,
        ):
            return False
        self._checkpoints = updated
        self._checkpoint_status = "authenticated"
        self._expected_record_id = record_number + 1
        return True

    def _checkpoint_candidate_is_admissible(
        self, record_number: int, anchor: object
    ) -> bool:
        """Reject cursor conflicts/gaps before any downstream publication."""
        if (
            record_number <= 0
            or not isinstance(anchor, str)
            or len(anchor) != 64
            or any(ch not in "0123456789abcdef" for ch in anchor)
        ):
            return False
        current = self._checkpoints.get(_DEFENDER_CHANNEL)
        current_id = int(current.record_id) if current is not None else 0
        if record_number < current_id:
            return False
        if record_number == current_id:
            if current is not None and hmac.compare_digest(current.anchor, anchor):
                return True
            self._continuity_gap(
                "Defender outbox anchor conflicts with its authenticated cursor",
                reason_code="defender.cursor.anchor_conflict",
                conflicting_record_id=record_number,
            )
            return False
        expected = current_id + 1 if current_id else self._expected_record_id
        if expected and record_number != expected:
            self._continuity_gap(
                f"Defender cursor gap: expected record {expected}, received "
                f"{record_number}",
                reason_code="defender.cursor.outbox_gap",
                expected_record_id=expected,
                received_record_id=record_number,
            )
            return False
        return True

    def _subscriber_failure_count(self) -> int:
        bus = self._bus
        metrics = getattr(bus, "subscriber_metrics", None)
        if not callable(metrics):
            return 0
        try:
            return sum(int(row.failures) for row in metrics())
        except Exception:
            # An unavailable acceptance signal cannot be treated as a durable
            # downstream acknowledgement.
            return -1

    def _refresh_native_health(self) -> None:
        checkpoint = self._checkpoint
        if self._persisted_gap or self._continuity_gaps or (
            checkpoint is not None
            and self._checkpoint_status == "authenticated"
            and not checkpoint.coverage_complete
        ):
            self.set_health(45, "Defender continuity gap remains persisted")
            return
        try:
            stats = self._outbox.stats() if self._outbox is not None else None
        except Exception:
            self._persist_incomplete_coverage()
            self.set_health(20, "Defender outbox integrity is unavailable")
            return
        if stats is None:
            self.set_health(20, "Defender delivery outbox is unavailable")
        elif stats.dead_letter:
            self.set_health(20, "Defender delivery has dead-letter evidence")
        elif stats.pending or stats.leased or self._errors:
            self.set_health(45, "Defender delivery acknowledgement is pending")
        elif self._checkpoint_status == "authenticated" and self._current_record_id() > 0:
            self.set_health(
                100,
                f"{self._delivered} Defender record(s) delivered with "
                "authenticated continuity",
            )
        else:
            self.set_health(
                70,
                "Defender channel is open; authenticated retained-history "
                "enrollment is not yet anchored",
            )

    def _drain_outbox(self) -> None:
        if self._outbox_draining:
            self._outbox_redrain = True
            return
        self._outbox_draining = True
        try:
            while True:
                self._outbox_redrain = False
                self._drain_outbox_once()
                if not self._outbox_redrain:
                    return
        finally:
            self._outbox_draining = False

    def _drain_outbox_once(self) -> None:
        if self._outbox is None:
            return
        try:
            claimed = self._outbox.claim(
                self._outbox_owner, limit=_MAX_NATIVE_BATCH, lease_seconds=30.0
            )
            # Claim admission and its independent witness are durable before a
            # single event can become visible to downstream subscribers.
            self._persist_outbox_enrollment()
        except Exception as exc:
            self._errors += 1
            self._persist_incomplete_coverage()
            self.set_health(
                20,
                "Defender outbox admission witness failed before publish: "
                f"{type(exc).__name__}",
            )
            return
        for item in claimed:
            try:
                payload = item.payload
                if payload.get("schema") != "angerona.defender-delivery.v1":
                    raise ValueError("Defender outbox payload schema is invalid")
                message = payload.get("message")
                severity = payload.get("severity")
                details = payload.get("details")
                if (
                    not isinstance(message, str)
                    or not message
                    or type(severity) is not int
                    or not 0 <= severity <= int(Severity.CRITICAL)
                    or not isinstance(details, dict)
                ):
                    raise ValueError("Defender outbox payload is invalid")
                if self._bus is None:
                    raise RuntimeError("event bus is unavailable")
                record_number = payload.get("record_number")
                record_anchor = payload.get("record_anchor")
                if type(record_number) is int and record_number > 0:
                    if not self._checkpoint_candidate_is_admissible(
                        record_number, record_anchor
                    ):
                        raise RuntimeError(
                            "Defender outbox record was refused before publication"
                        )
                before_failures = self._subscriber_failure_count()
                self.emit(message, Severity(severity), **details)
                after_failures = self._subscriber_failure_count()
                if (
                    before_failures < 0
                    or after_failures < 0
                    or after_failures > before_failures
                ):
                    raise RuntimeError(
                        "Defender event lacked downstream subscriber acknowledgement"
                    )
                if type(record_number) is int and record_number > 0:
                    if (
                        not isinstance(record_anchor, str)
                        or len(record_anchor) != 64
                        or not self._save_checkpoint(record_number, record_anchor)
                    ):
                        raise RuntimeError(
                            "Defender event was published but its cursor was not committed"
                        )
                self._outbox.acknowledge(item.item_id, self._outbox_owner)
                self._persist_outbox_enrollment()
                self._delivered += int(payload.get("kind") == "event")
            except Exception as exc:
                self._errors += 1
                try:
                    self._outbox.retry(
                        item.item_id, self._outbox_owner, str(exc)
                    )
                    self._persist_outbox_enrollment()
                except Exception as retry_exc:
                    self._persist_incomplete_coverage()
                    self.set_health(
                        20,
                        "Defender delivery retry/witness failed: "
                        f"{type(retry_exc).__name__}",
                    )
                    continue
                self.set_health(45, f"Defender delivery retry pending: {type(exc).__name__}")
        self._refresh_native_health()

    def _continuity_gap(
        self,
        message: str,
        *,
        reason_code: str,
        **details: object,
    ) -> None:
        self._continuity_gaps += 1
        self._persist_incomplete_coverage()
        self.set_health(45, str(message))
        payload_details = {
            "disposition": "health",
            "continuity_complete": False,
            "reason_code": reason_code,
            "gap_count": self._continuity_gaps,
            "response_authorized": False,
            **self._counter_details(),
            **details,
        }
        if self._outbox is None:
            self.emit(str(message), Severity.HIGH, **payload_details)
            return
        identity = hashlib.sha256(
            json.dumps(
                {
                    "message": str(message),
                    "reason_code": reason_code,
                    "details": details,
                },
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        self._enqueue_outbox(
            f"defender-gap-{identity}",
            {
                "schema": "angerona.defender-delivery.v1",
                "kind": "gap",
                "message": str(message),
                "severity": int(Severity.HIGH),
                "details": payload_details,
                "record_number": 0,
                "record_anchor": "",
            },
        )
        self._drain_outbox()

    # ── PowerShell fallback mode ──────────────────────────────────────────────
    def _try_powershell_mode(self) -> bool:
        """Use Get-MpThreatDetection if win32evtlog is unavailable."""
        try:
            retained = self._poll_ps()
        except Exception:
            return False
        try:
            if not self._open_continuity_state():
                return False
            self.emit(
                "AV Telemetry Bridge: running PowerShell Get-MpThreatDetection "
                "fallback with a durable detection outbox.",
                Severity.INFO,
                fallback=True,
                retained_replay=True,
                delivery_semantics="durable-at-least-once",
            )
            self.set_health(
                70,
                "PowerShell fallback has durable replay but no real-time EID coverage",
            )
            for threat in retained:
                self._stage_ps_detection(threat)
            while not self.stopping:
                self.sleep(_FALLBACK_INTERVAL)
                try:
                    for threat in self._poll_ps():
                        self._stage_ps_detection(threat)
                    self._drain_outbox()
                    if not self._continuity_gaps and not self._errors:
                        self.set_health(
                            70,
                            "PowerShell fallback delivery is current; real-time EID "
                            "coverage remains unavailable",
                        )
                except Exception as exc:
                    self._errors += 1
                    self._continuity_gap(
                        "PowerShell Defender polling failed; prior delivery state was "
                        "retained for replay",
                        reason_code="defender.powershell.poll_error",
                        error_type=type(exc).__name__,
                    )
        finally:
            self._close_continuity_state()
        return True

    def _stage_ps_detection(self, threat: dict) -> None:
        if not isinstance(threat, dict) or self._outbox is None:
            raise ValueError("Defender fallback record/outbox is unavailable")
        name = str(threat.get("ThreatName") or "unknown")[:1024]
        path = threat.get("Resources", "unknown")
        detection_id = str(threat.get("DetectionID") or "").strip()[:256]
        evidence_body = json.dumps(
            {
                "detection_id": detection_id,
                "threat_name": name,
                "resources": path,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        evidence_digest = hashlib.sha256(evidence_body).hexdigest()
        if not detection_id:
            self._continuity_gap(
                "Defender fallback record had no stable DetectionID",
                reason_code="defender.powershell.identity_missing",
                evidence_sha256=evidence_digest,
            )
        details = _with_artifact_paths(
            {
                "threat_name": name,
                "path": str(path)[:4096],
                "detection_id": detection_id or None,
                "detection_sha256": evidence_digest,
                "fallback": True,
                "mitre_tags": ["T1204"],
                "delivery_semantics": "durable-at-least-once",
            },
            path,
        )
        item_identity = hashlib.sha256(
            f"{detection_id}\0{evidence_digest}".encode("utf-8")
        ).hexdigest()
        self._enqueue_outbox(
            f"defender-ps-{item_identity}",
            {
                "schema": "angerona.defender-delivery.v1",
                "kind": "event",
                "message": f"Defender [PS fallback] detected {name!r} at {path!r}"[:8192],
                "severity": int(Severity.HIGH),
                "details": details,
                "record_number": 0,
                "record_anchor": "",
            },
        )
        self._drain_outbox()

    def _poll_ps(self) -> list[dict]:
        out = check_output_hidden(
            ["powershell", "-NoProfile", "-Command",
             "Get-MpThreatDetection | ConvertTo-Json -Depth 3"],
            timeout=30,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if len((out or "").encode("utf-8", "replace")) > _MAX_FALLBACK_OUTPUT_BYTES:
            raise ValueError("Defender fallback output exceeded its byte bound")
        data = json.loads(out or "[]")
        if isinstance(data, dict):
            data = [data]
        if (
            not isinstance(data, list)
            or len(data) > _MAX_FALLBACK_RECORDS
            or any(not isinstance(item, dict) for item in data)
        ):
            raise ValueError("Defender fallback output schema is invalid")
        return [dict(item) for item in data]

    def self_test(self) -> tuple[bool, str]:
        if self.health >= 80:
            return True, f"health={self.health}%"
        return False, self.health_note


def register() -> AVTelemetryBridgeModule:
    return AVTelemetryBridgeModule()
