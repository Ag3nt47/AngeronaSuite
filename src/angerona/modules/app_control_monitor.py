"""Windows App Control decision evidence sensor.

Reads Code Integrity decision/signature events through the supported modern
Windows Event Log API.  This module is passive: it never creates, changes, or
deploys an App Control policy and its events never authorize host response.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Protocol

from angerona.core.app_control_evidence import (
    AppControlRecord,
    CorrelatedDecision,
    DecisionCorrelator,
    parse_app_control_xml,
)
from angerona.core.module_base import BaseModule, Severity

_CHANNEL = "Microsoft-Windows-CodeIntegrity/Operational"
_EVENT_IDS = (3004, 3033, 3034, 3076, 3077, 3089, 3095, 3096, 3097, 3099,
              3100, 3101, 3102, 3103, 3105)
_CURSOR_SCHEMA = 2
_CURSOR_DOMAIN = b"angerona/app-control-cursor/v1\x00"
_PENDING_SCHEMA = 1
_PENDING_DOMAIN = b"angerona/app-control-pending/v1\x00"
_PATH_TOKEN_DOMAIN = b"angerona/app-control-path-token/v1\x00"
_CURSOR_SIGNATURE = "_angerona_hmac"
_MAX_CURSOR_BYTES = 4096
_MAX_PENDING_BYTES = 2 * 1024 * 1024
_MAX_BATCH = 256


class EventSource(Protocol):
    def oldest_record_id(self) -> int: ...
    def newest_record_id(self) -> int: ...
    def record_anchor(self, record_id: int) -> str: ...
    def read_after(self, record_id: int, limit: int) -> list[str]: ...
    def close(self) -> None: ...


class WindowsCodeIntegritySource:
    """Small modern-WEVT adapter kept separate for deterministic tests."""

    def __init__(self) -> None:
        import win32evtlog  # type: ignore[import]
        self._api = win32evtlog

    def _query(self, expression: str, *, reverse: bool = False):
        flags = self._api.EvtQueryChannelPath
        flags |= (
            self._api.EvtQueryReverseDirection
            if reverse
            else self._api.EvtQueryForwardDirection
        )
        return self._api.EvtQuery(_CHANNEL, flags, expression)

    def _next(self, query, count: int):
        try:
            return list(self._api.EvtNext(query, count) or ())
        except Exception as exc:
            # ERROR_NO_MORE_ITEMS is normal for a bounded Event Log query.
            args = getattr(exc, "args", ())
            fallback_code = args[0] if args else 0
            if int(getattr(exc, "winerror", fallback_code) or 0) == 259:
                return []
            raise

    def newest_record_id(self) -> int:
        query = self._query("*[System[EventRecordID >= 0]]", reverse=True)
        handles = []
        try:
            handles = self._next(query, 1)
            if not handles:
                return 0
            xml = self._api.EvtRender(handles[0], self._api.EvtRenderEventXml)
            # The parser intentionally supports only selected App Control IDs,
            # while the high watermark must consider every channel record.
            marker = "<EventRecordID>"
            start = xml.find(marker)
            end = xml.find("</EventRecordID>", start + len(marker))
            if start < 0 or end < 0:
                raise RuntimeError("Code Integrity high-watermark record has no ID")
            return max(0, int(xml[start + len(marker):end]))
        finally:
            for handle in handles:
                try:
                    self._api.EvtClose(handle)
                except Exception:
                    pass
            try:
                self._api.EvtClose(query)
            except Exception:
                pass

    def oldest_record_id(self) -> int:
        query = self._query("*[System[EventRecordID >= 0]]")
        handles = []
        try:
            handles = self._next(query, 1)
            if not handles:
                return 0
            xml = str(self._api.EvtRender(handles[0], self._api.EvtRenderEventXml))
            marker = "<EventRecordID>"
            start = xml.find(marker)
            end = xml.find("</EventRecordID>", start + len(marker))
            if start < 0 or end < 0:
                raise RuntimeError("Code Integrity oldest retained record has no ID")
            return max(0, int(xml[start + len(marker):end]))
        finally:
            for handle in handles:
                try:
                    self._api.EvtClose(handle)
                except Exception:
                    pass
            try:
                self._api.EvtClose(query)
            except Exception:
                pass

    def record_anchor(self, record_id: int) -> str:
        if int(record_id) <= 0:
            return ""
        query = self._query(
            f"*[System[EventRecordID = {max(0, int(record_id))}]]"
        )
        handles = []
        try:
            handles = self._next(query, 1)
            if not handles:
                return ""
            xml = str(self._api.EvtRender(handles[0], self._api.EvtRenderEventXml))
            return hashlib.sha256(xml.encode("utf-8", "replace")).hexdigest()
        finally:
            for handle in handles:
                try:
                    self._api.EvtClose(handle)
                except Exception:
                    pass
            try:
                self._api.EvtClose(query)
            except Exception:
                pass

    def read_after(self, record_id: int, limit: int) -> list[str]:
        ids = " or ".join(f"EventID={item}" for item in _EVENT_IDS)
        expression = (
            f"*[System[({ids}) and EventRecordID > {max(0, int(record_id))}]]"
        )
        query = self._query(expression)
        handles = []
        try:
            handles = self._next(query, max(1, min(_MAX_BATCH, int(limit))))
            return [
                str(self._api.EvtRender(handle, self._api.EvtRenderEventXml))
                for handle in handles
            ]
        finally:
            for handle in handles:
                try:
                    self._api.EvtClose(handle)
                except Exception:
                    pass
            try:
                self._api.EvtClose(query)
            except Exception:
                pass

    def close(self) -> None:
        return None


class _AuthenticatedCursor:
    def __init__(self, path: Path, authority_key: bytes | None = None) -> None:
        self.path = Path(path)
        self._authority_key = authority_key

    def _base_key(self) -> bytes | None:
        key = self._authority_key
        if key is None:
            try:
                encoded = (self.path.parents[1] / "bus.key").read_text(
                    encoding="ascii"
                ).strip()
                key = bytes.fromhex(encoded)
            except (OSError, ValueError):
                return None
        if not isinstance(key, bytes) or len(key) != 32:
            return None
        return key

    def _key(self) -> bytes | None:
        key = self._base_key()
        return hmac.new(key, _CURSOR_DOMAIN, hashlib.sha256).digest() if key else None

    def path_token(self, value: str) -> str:
        key = self._base_key()
        if key is None or not value:
            return ""
        token_key = hmac.new(key, _PATH_TOKEN_DOMAIN, hashlib.sha256).digest()
        normalized = value.replace("/", "\\").casefold().encode("utf-8", "replace")
        return hmac.new(token_key, normalized, hashlib.sha256).hexdigest()[:32]

    @staticmethod
    def _body(value: dict) -> bytes:
        unsigned = {key: item for key, item in value.items() if key != _CURSOR_SIGNATURE}
        return json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def load(self) -> tuple[int, str, str]:
        try:
            if not self.path.exists():
                return 0, "missing", ""
            if not self.path.is_file() or self.path.stat().st_size > _MAX_CURSOR_BYTES:
                return 0, "untrusted", ""
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if (
                not isinstance(value, dict)
                or set(value) != {
                    "schema", "channel", "record_id", "record_anchor",
                    "updated_at", _CURSOR_SIGNATURE
                }
                or value.get("schema") != _CURSOR_SCHEMA
                or value.get("channel") != _CHANNEL
                or not isinstance(value.get("record_id"), int)
                or isinstance(value.get("record_id"), bool)
                or value["record_id"] < 0
                or not isinstance(value.get("record_anchor"), str)
                or (
                    value["record_anchor"]
                    and (
                        len(value["record_anchor"]) != 64
                        or any(
                            character not in "0123456789abcdef"
                            for character in value["record_anchor"]
                        )
                    )
                )
                or (value["record_id"] == 0 and bool(value["record_anchor"]))
                or (value["record_id"] > 0 and not value["record_anchor"])
                or not isinstance(value.get("updated_at"), (int, float))
                or isinstance(value.get("updated_at"), bool)
                or not isinstance(value.get(_CURSOR_SIGNATURE), str)
            ):
                return 0, "untrusted", ""
            key = self._key()
            if key is None:
                return 0, "untrusted", ""
            expected = hmac.new(key, self._body(value), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(value[_CURSOR_SIGNATURE], expected):
                return 0, "untrusted", ""
            return (
                int(value["record_id"]),
                "authenticated",
                str(value["record_anchor"]),
            )
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return 0, "untrusted", ""

    def save(self, record_id: int, record_anchor: str = "") -> bool:
        key = self._key()
        if key is None:
            return False
        normalized_record_id = max(0, int(record_id))
        if (
            not isinstance(record_anchor, str)
            or (normalized_record_id == 0 and bool(record_anchor))
            or (
                normalized_record_id > 0
                and (
                    len(record_anchor) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in record_anchor
                    )
                )
            )
        ):
            return False
        document = {
            "schema": _CURSOR_SCHEMA,
            "channel": _CHANNEL,
            "record_id": normalized_record_id,
            "record_anchor": record_anchor,
            "updated_at": time.time(),
        }
        document[_CURSOR_SIGNATURE] = hmac.new(
            key, self._body(document), hashlib.sha256
        ).hexdigest()
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        temporary = self.path.with_suffix(f".tmp-{os.getpid()}-{id(self):x}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            return True
        except OSError:
            return False
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


class _AuthenticatedPendingState:
    def __init__(self, path: Path, cursor: _AuthenticatedCursor) -> None:
        self.path = Path(path)
        self._cursor = cursor

    def _key(self) -> bytes | None:
        key = self._cursor._base_key()
        return hmac.new(key, _PENDING_DOMAIN, hashlib.sha256).digest() if key else None

    @staticmethod
    def _body(value: dict) -> bytes:
        unsigned = {key: item for key, item in value.items() if key != _CURSOR_SIGNATURE}
        return json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def load(self) -> tuple[dict | None, str]:
        try:
            if not self.path.exists():
                return None, "missing"
            if not self.path.is_file() or self.path.stat().st_size > _MAX_PENDING_BYTES:
                return None, "untrusted"
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if (
                not isinstance(document, dict)
                or set(document) != {
                    "schema", "channel", "state", "updated_at", _CURSOR_SIGNATURE
                }
                or document.get("schema") != _PENDING_SCHEMA
                or document.get("channel") != _CHANNEL
                or not isinstance(document.get("state"), dict)
                or not isinstance(document.get("updated_at"), (int, float))
                or isinstance(document.get("updated_at"), bool)
                or not isinstance(document.get(_CURSOR_SIGNATURE), str)
            ):
                return None, "untrusted"
            key = self._key()
            if key is None:
                return None, "untrusted"
            expected = hmac.new(key, self._body(document), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(document[_CURSOR_SIGNATURE], expected):
                return None, "untrusted"
            return document["state"], "authenticated"
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return None, "untrusted"

    def save(self, state: dict) -> bool:
        key = self._key()
        if key is None:
            return False
        document = {
            "schema": _PENDING_SCHEMA,
            "channel": _CHANNEL,
            "state": state,
            "updated_at": time.time(),
        }
        document[_CURSOR_SIGNATURE] = hmac.new(
            key, self._body(document), hashlib.sha256
        ).hexdigest()
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(payload) > _MAX_PENDING_BYTES:
            return False
        temporary = self.path.with_suffix(f".tmp-{os.getpid()}-{id(self):x}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            return True
        except OSError:
            return False
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


class AppControlDecisionSensor(BaseModule):
    CODE = "ACDS"
    name = "App Control Decision Evidence"
    description = (
        "Reads Windows Code Integrity audit/block decisions and correlates "
        "their signature evidence by ActivityID without changing App Control policy."
    )
    category = "Integrity"
    version = "1.0.0"
    enabled_by_default = True
    supported_platforms = frozenset({"windows"})
    capability_mode = "observe"
    platform_requirements = ("Microsoft-Windows-CodeIntegrity/Operational",)
    _POLL_INTERVAL = 2.0

    def __init__(
        self,
        source: EventSource | None = None,
        data_root: Path | None = None,
        *,
        cursor_key: bytes | None = None,
        correlation_ttl: float = 15.0,
    ) -> None:
        super().__init__()
        self._source = source
        self._owns_source = source is None
        if data_root is None:
            from angerona.core.data_paths import data_dir
            data_root = data_dir()
        self._cursor = _AuthenticatedCursor(
            Path(data_root) / "sensor-cursors" / "app-control.json",
            cursor_key,
        )
        self._pending = _AuthenticatedPendingState(
            Path(data_root) / "sensor-cursors" / "app-control.pending.json",
            self._cursor,
        )
        self._cursor_value: int | None = None
        self._cursor_anchor = ""
        self._cursor_authenticated = False
        self._pending_fingerprint = ""
        self._correlator = DecisionCorrelator(ttl_seconds=correlation_ttl)
        self._parse_errors = 0
        self._events_seen = 0
        self._degraded_this_poll = False

    def _emit_decision(self, item: CorrelatedDecision) -> None:
        severity = (
            Severity.HIGH
            if item.decision.disposition in {
                "enforced-block", "invalid-signature-block", "signature-rejection-block"
            }
            else Severity.MEDIUM
        )
        details = item.details(self._cursor.path_token)
        if item.correlation_status != "complete":
            details["telemetry_quality"] = "partial"
            self._degraded_this_poll = True
            self.set_health(75, "App Control evidence flowing with incomplete signature joins")
        self.emit(item.message(), severity, **details)

    def _emit_policy(self, record: AppControlRecord) -> None:
        severity = (
            Severity.HIGH
            if record.disposition in {"refresh-failed", "activation-failed"}
            else Severity.MEDIUM
            if record.disposition in {"refresh-requires-reboot", "refresh-ignored"}
            else Severity.INFO
        )
        self.emit(
            f"App Control policy event: {record.disposition}",
            severity,
            event_id=record.event_id,
            record_id=record.record_id,
            activity_id=record.activity_id,
            disposition="health" if severity >= Severity.MEDIUM else "inventory",
            policy_state=record.disposition,
            policy_fields={
                key: value
                for key, value in record.fields.items()
                if key in {"PolicyName", "PolicyId", "PolicyGUID", "PolicyHash", "Status"}
            },
            local_sensitive_paths_omitted=True,
            raw_sensor_evidence=True,
            response_authorized=False,
            response_authority="observe-only",
        )

    def _consume_xml(self, xml: str) -> int:
        record = parse_app_control_xml(xml)
        self._events_seen += 1
        if record.is_policy_event:
            self._emit_policy(record)
        for decision in self._correlator.ingest(record):
            self._emit_decision(decision)
        return record.record_id

    @staticmethod
    def _best_effort_record_id(xml: object) -> int:
        if not isinstance(xml, str):
            return 0
        marker = "<EventRecordID>"
        start = xml.find(marker)
        end = xml.find("</EventRecordID>", start + len(marker))
        if start < 0 or end < 0:
            return 0
        try:
            return max(0, int(xml[start + len(marker):end]))
        except ValueError:
            return 0

    def _emit_checkpoint_failure(self, target: str) -> None:
        self._cursor_authenticated = False
        self._degraded_this_poll = True
        self.set_health(55, f"Code Integrity {target} authority unavailable")
        self.emit(
            f"App Control {target} could not be authenticated",
            Severity.HIGH,
            disposition="health",
            sensor_state="untrusted",
            response_authorized=False,
        )

    @staticmethod
    def _state_fingerprint(state: dict) -> str:
        stable = {
            "groups": [
                {
                    key: value
                    for key, value in group.items()
                    if key != "age_seconds"
                }
                for group in state.get("groups", [])
            ],
            "seen_records": state.get("seen_records", []),
        }
        payload = json.dumps(
            stable, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _save_checkpoint(
        self,
        record_id: int,
        *,
        expected_anchor: str | None = None,
    ) -> bool:
        # Persist correlation state first. If the process stops between these
        # two atomic writes, an older cursor will safely replay rows that the
        # restored dedupe table already knows about.
        normalized_record_id = max(0, int(record_id))
        if expected_anchor is not None:
            assert self._source is not None
            current_anchor = self._source.record_anchor(normalized_record_id)
            if not hmac.compare_digest(expected_anchor, current_anchor):
                self._mark_generation_gap(
                    "App Control visibility gap: terminal checkpoint record changed",
                    previous_record=self._cursor_value or 0,
                    reason="terminal-record-replaced",
                )
                return False
        pending_state = self._correlator.export_state()
        pending_fingerprint = self._state_fingerprint(pending_state)
        if pending_fingerprint != self._pending_fingerprint:
            if not self._pending.save(pending_state):
                self._emit_checkpoint_failure("pending correlation checkpoint")
                return False
            self._pending_fingerprint = pending_fingerprint
        if (
            self._cursor_authenticated
            and self._cursor_value == normalized_record_id
        ):
            return True
        assert self._source is not None
        try:
            anchor = self._source.record_anchor(normalized_record_id)
        except Exception:
            anchor = ""
        if expected_anchor is not None:
            if not hmac.compare_digest(expected_anchor, anchor):
                self._mark_generation_gap(
                    "App Control visibility gap: terminal record changed during checkpoint",
                    previous_record=self._cursor_value or 0,
                    reason="checkpoint-write-generation-change",
                )
                return False
            # Persist the anchor admitted with the staged snapshot. If the
            # channel clears after this comparison, the next poll/restart sees
            # a mismatch instead of blessing the replacement generation.
            anchor = expected_anchor
        if normalized_record_id > 0 and (
            len(anchor) != 64
            or any(character not in "0123456789abcdef" for character in anchor)
        ):
            self._emit_checkpoint_failure("cursor anchor")
            return False
        if not self._cursor.save(normalized_record_id, anchor):
            self._emit_checkpoint_failure("cursor")
            return False
        self._cursor_value = normalized_record_id
        self._cursor_anchor = anchor
        self._cursor_authenticated = True
        return True

    def _mark_generation_gap(
        self,
        message: str,
        *,
        previous_record: int,
        reason: str,
    ) -> None:
        self._discard_correlation("channel-gap")
        try:
            assert self._source is not None
            oldest = max(0, int(self._source.oldest_record_id()))
            newest = max(0, int(self._source.newest_record_id()))
            if oldest > newest:
                oldest = 0
        except Exception:
            oldest = 0
            newest = 0
        self._cursor_value = max(0, oldest - 1) if oldest else 0
        self._cursor_anchor = ""
        self._cursor_authenticated = False
        self._pending_fingerprint = ""
        self._degraded_this_poll = True
        self.set_health(45, "Code Integrity channel generation changed")
        self.emit(
            message,
            Severity.HIGH,
            disposition="health",
            sensor_state="gap",
            gap_reason=reason,
            previous_record=previous_record,
            oldest_retained_record=oldest,
            newest_record=newest,
            replay_from_record=self._cursor_value + 1 if oldest else 0,
            response_authorized=False,
        )

    def _discard_correlation(self, status: str) -> None:
        for decision in self._correlator.flush_all(status):
            self._emit_decision(decision)

    def _load_pending_or_replay(self, oldest: int) -> None:
        state, status = self._pending.load()
        if status == "authenticated":
            try:
                self._correlator.import_state(state)
                self._pending_fingerprint = self._state_fingerprint(state)
                return
            except (TypeError, ValueError):
                status = "untrusted"
        self._correlator.reset()
        self._pending_fingerprint = ""
        self._cursor_value = max(0, oldest - 1) if oldest else 0
        self._cursor_authenticated = False
        self._degraded_this_poll = True
        qualifier = "missing" if status == "missing" else "untrusted"
        self.set_health(
            35,
            f"App Control pending correlation checkpoint is {qualifier}; "
            "replaying retained evidence",
        )
        self.emit(
            f"App Control pending correlation checkpoint is {qualifier}; "
            "replaying retained evidence",
            Severity.HIGH,
            disposition="health",
            sensor_state="gap",
            replay_from_record=self._cursor_value + 1 if oldest else 0,
            response_authorized=False,
        )

    def poll_once(self) -> int:
        self._degraded_this_poll = False
        if self._source is None:
            self._source = WindowsCodeIntegritySource()
        oldest = max(0, int(self._source.oldest_record_id()))
        newest = max(0, int(self._source.newest_record_id()))
        # The channel can clear between these two independent WEVT snapshots.
        # A stale old low-watermark must never move the cursor above the newer
        # high-watermark or the sensor will report the same gap forever.
        if oldest > newest:
            oldest = 0
        if self._cursor_value is None:
            cursor, status, anchor = self._cursor.load()
            self._cursor_anchor = anchor
            if status == "missing":
                # Establish a tail baseline on first install; an authenticated
                # restart resumes without hiding the interval it was stopped.
                self._correlator.reset()
                if not self._save_checkpoint(newest):
                    self._cursor_value = None
                    return 0
                self.set_health(90, "Code Integrity channel available; baseline established")
                return 0
            self._cursor_value = cursor
            if status == "untrusted":
                self._cursor_authenticated = False
                self._correlator.reset()
                self._cursor_value = max(0, oldest - 1) if oldest else 0
                self._degraded_this_poll = True
                self.set_health(35, "App Control cursor is untrusted; replaying retained evidence")
                self.emit(
                    "App Control cursor authentication failed; replaying retained evidence",
                    Severity.HIGH,
                    disposition="health",
                    sensor_state="untrusted",
                    replay_from_record=self._cursor_value + 1 if oldest else 0,
                    response_authorized=False,
                )
            else:
                self._cursor_authenticated = True
                self._load_pending_or_replay(oldest)

        assert self._cursor_value is not None
        if oldest and self._cursor_value < oldest - 1:
            previous = self._cursor_value
            self._discard_correlation("channel-gap")
            self._cursor_value = oldest - 1
            self._cursor_authenticated = False
            self._degraded_this_poll = True
            self.set_health(45, "Code Integrity retained history has a visibility gap")
            self.emit(
                "App Control visibility gap: retained channel history starts after the cursor",
                Severity.HIGH,
                disposition="health",
                sensor_state="gap",
                missing_record_start=previous + 1,
                missing_record_end=oldest - 1,
                oldest_retained_record=oldest,
                response_authorized=False,
            )
        if self._cursor_value > newest:
            previous = self._cursor_value
            self._discard_correlation("channel-gap")
            self._cursor_value = (
                min(newest, max(0, oldest - 1)) if oldest else 0
            )
            self._cursor_authenticated = False
            self._degraded_this_poll = True
            self.set_health(45, "Code Integrity channel record numbering regressed")
            self.emit(
                "App Control visibility gap: channel was cleared or record numbering regressed",
                Severity.HIGH,
                disposition="health",
                sensor_state="gap",
                previous_record=previous,
                newest_record=newest,
                oldest_retained_record=oldest,
                response_authorized=False,
            )

        anchor_is_retained = (
            self._cursor_value > 0
            and self._cursor_value <= newest
            and (oldest == 0 or self._cursor_value >= oldest)
        )
        if self._cursor_authenticated and anchor_is_retained:
            current_anchor = self._source.record_anchor(self._cursor_value)
            if (
                not self._cursor_anchor
                or not current_anchor
                or not hmac.compare_digest(self._cursor_anchor, current_anchor)
            ):
                self._mark_generation_gap(
                    "App Control visibility gap: checkpoint record anchor changed",
                    previous_record=self._cursor_value,
                    reason="checkpoint-record-replaced",
                )

        admitted_cursor = self._cursor_value
        admitted_anchor = (
            self._cursor_anchor
            if self._cursor_authenticated and anchor_is_retained
            else ""
        )
        latest = admitted_cursor
        parse_errors_before = self._parse_errors
        # Stage raw rows first. They are not parsed, correlated, or emitted
        # until the prior generation anchor has been verified again.
        rows = self._source.read_after(admitted_cursor, _MAX_BATCH)
        if admitted_anchor:
            post_query_anchor = self._source.record_anchor(admitted_cursor)
            if not hmac.compare_digest(admitted_anchor, post_query_anchor):
                self._mark_generation_gap(
                    "App Control visibility gap: channel changed during event query",
                    previous_record=admitted_cursor,
                    reason="mid-poll-checkpoint-replaced",
                )
                return 0

        staged_latest = max(
            (self._best_effort_record_id(xml) for xml in rows),
            default=admitted_cursor,
        )
        if len(rows) < _MAX_BATCH:
            staged_latest = max(staged_latest, newest)
        terminal_anchor = self._source.record_anchor(staged_latest)
        if staged_latest > 0 and not terminal_anchor:
            self._mark_generation_gap(
                "App Control visibility gap: terminal record vanished during event query",
                previous_record=admitted_cursor,
                reason="mid-poll-terminal-missing",
            )
            return 0
        if admitted_anchor:
            final_admission_anchor = self._source.record_anchor(admitted_cursor)
            if not hmac.compare_digest(admitted_anchor, final_admission_anchor):
                self._mark_generation_gap(
                    "App Control visibility gap: channel changed while staging events",
                    previous_record=admitted_cursor,
                    reason="mid-poll-generation-change",
                )
                return 0

        for xml in rows:
            try:
                latest = max(latest, self._consume_xml(xml))
            except (TypeError, ValueError) as exc:
                latest = max(latest, self._best_effort_record_id(xml))
                self._parse_errors += 1
                self._degraded_this_poll = True
                self.set_health(70, f"Code Integrity parse errors: {self._parse_errors}")
                self.emit(
                    f"App Control evidence record could not be parsed: {type(exc).__name__}",
                    Severity.MEDIUM,
                    disposition="health",
                    sensor_state="degraded",
                    response_authorized=False,
                )
        for decision in self._correlator.flush_expired():
            self._emit_decision(decision)
        # A short filtered batch proves there are no more selected records up
        # to the sampled high watermark, so advancing to it avoids a false gap
        # if unrelated Code Integrity traffic later rolls out of retention.
        latest = max(latest, staged_latest)
        if not self._save_checkpoint(latest, expected_anchor=terminal_anchor):
            return len(rows)
        had_parse_error = self._parse_errors != parse_errors_before
        if (
            self._cursor_authenticated
            and not self._degraded_this_poll
            and not had_parse_error
        ):
            note = (
                f"live; {self._events_seen} relevant event(s) observed"
                if self._events_seen
                else "available and idle; policy presence is unknown"
            )
            self.set_health(100, note)
        return len(rows)

    def run(self) -> None:
        try:
            while not self.stopping:
                try:
                    self.poll_once()
                except Exception as exc:
                    self.set_health(25, f"Code Integrity channel blind: {type(exc).__name__}")
                    self.emit(
                        f"App Control evidence unavailable: {type(exc).__name__}",
                        Severity.HIGH,
                        disposition="health",
                        sensor_state="blind",
                        response_authorized=False,
                    )
                self.sleep(self._POLL_INTERVAL)
        finally:
            source = self._source
            if source is not None and self._owns_source:
                try:
                    source.close()
                except Exception:
                    pass
                finally:
                    if self._source is source:
                        self._source = None

    def self_test(self) -> tuple[bool, str]:
        fixture = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>3077</EventID><EventRecordID>7</EventRecordID>
          <Correlation ActivityID='{11111111-1111-1111-1111-111111111111}'/></System>
          <EventData><Data Name='File Name'>C:\\Windows\\System32\\probe.exe</Data>
          <Data Name='PolicyName'>probe</Data></EventData></Event>"""
        try:
            record = parse_app_control_xml(fixture)
            if record.event_id != 3077 or record.disposition != "enforced-block":
                return False, "3077 fixture semantics changed"
            if record.activity_id != "{11111111-1111-1111-1111-111111111111}":
                return False, "ActivityID parsing failed"
            signature = parse_app_control_xml(fixture.replace(
                "<EventID>3077</EventID><EventRecordID>7</EventRecordID>",
                "<EventID>3089</EventID><EventRecordID>8</EventRecordID>",
            ).replace(
                "<Data Name='PolicyName'>probe</Data>",
                "<Data Name='TotalSignatureCount'>0</Data>"
                "<Data Name='Signature'>0</Data>",
            ))
            correlator = DecisionCorrelator(ttl_seconds=1.0)
            if correlator.ingest(record, now=0):
                return False, "decision emitted before signature correlation"
            joined = correlator.ingest(signature, now=0.1)
            if len(joined) != 1 or joined[0].correlation_status != "complete":
                return False, "ActivityID signature join failed"
            return True, "bounded 3076/3077/3089 parser and ActivityID join verified"
        except Exception as exc:
            return False, str(exc)
