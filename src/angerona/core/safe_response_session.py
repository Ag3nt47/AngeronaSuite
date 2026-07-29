"""Expiring typed live-response sessions with authenticated full transcripts."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from angerona.core.atomic_io import replace_with_retry
from angerona.core.response_broker import (
    ResponseBroker, ResponseProposal, ResponseReceipt,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_QUERY = re.compile(r"^[a-z][a-z0-9_.-]{2,79}$")
_FORBIDDEN = {"command", "shell", "script", "code", "exec", "powershell", "cmd"}
_STATES = {"draft", "active", "closed", "expired"}
MAX_TRANSCRIPT = 5_000
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_VALUE_BYTES = 64 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _reject_executable_fields(value: Any, *, depth: int = 0) -> None:
    if depth > 6:
        raise ValueError("response session input exceeds nesting limit")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in _FORBIDDEN:
                raise ValueError("executable response-session fields are forbidden")
            _reject_executable_fields(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 100:
            raise ValueError("response session list exceeds item limit")
        for item in value:
            _reject_executable_fields(item, depth=depth + 1)


@dataclass(frozen=True)
class ReadOnlyQuery:
    query_id: str
    description: str
    validator: Callable[[Mapping[str, Any]], None] = field(
        repr=False, compare=False
    )
    handler: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] = field(
        repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not _QUERY.fullmatch(self.query_id) or any(
            token in self.query_id.split(".") for token in _FORBIDDEN
        ):
            raise ValueError("invalid or executable query ID")
        if not self.description.strip():
            raise ValueError("query description is required")


@dataclass(frozen=True)
class ResponseSessionSpec:
    session_id: str
    target_id: str
    requested_by: str
    query_ids: tuple[str, ...]
    response_operation_ids: tuple[str, ...]
    created_at: float
    expires_at: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "query_ids", tuple(self.query_ids))
        object.__setattr__(
            self, "response_operation_ids", tuple(self.response_operation_ids)
        )
        if any(not _ID.fullmatch(value) for value in (
            self.session_id, self.target_id, self.requested_by,
        )):
            raise ValueError("invalid response session identity")
        if not self.query_ids and not self.response_operation_ids:
            raise ValueError("response session requires a typed capability")
        values = (*self.query_ids, *self.response_operation_ids)
        if len(values) > 64 or len(set(values)) != len(values):
            raise ValueError("response session capability list is invalid")
        if any(
            not _QUERY.fullmatch(value)
            or any(token in value.split(".") for token in _FORBIDDEN)
            for value in values
        ):
            raise ValueError("response session forbids executable capabilities")
        if (
            not math.isfinite(float(self.created_at))
            or not math.isfinite(float(self.expires_at))
            or not self.created_at < self.expires_at <= self.created_at + 1800
        ):
            raise ValueError("response session expiry must be within 30 minutes")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class TranscriptEvent:
    event_id: str
    session_id: str
    kind: str
    subject_id: str
    request_sha256: str
    result_sha256: str
    outcome: str
    host_changed: bool
    timestamp: float
    previous_hash: str
    event_hash: str
    event_hmac: str


@dataclass(frozen=True)
class TranscriptReceipt:
    session_id: str
    session_digest: str
    state: str
    event_count: int
    chain_head: str
    recorded_at: float
    receipt_hmac: str


class SafeResponseSessionManager:
    def __init__(
        self,
        path: Path,
        audit_key: bytes,
        broker: ResponseBroker,
        queries: tuple[ReadOnlyQuery, ...] = (),
        *,
        clock=time.time,
    ) -> None:
        if len(audit_key) < 32:
            raise ValueError("response session key must contain at least 32 bytes")
        self._path = Path(path)
        self._key = bytes(audit_key)
        self._broker = broker
        self._clock = clock
        self._queries: dict[str, ReadOnlyQuery] = {}
        self._records: dict[str, dict[str, Any]] = {}
        self._inflight: set[tuple[str, str]] = set()
        self._lock = threading.RLock()
        for query in queries:
            self.register_query(query)
        self._load()

    def register_query(self, query: ReadOnlyQuery) -> None:
        if query.query_id in self._queries:
            raise ValueError("read-only query is already registered")
        self._queries[query.query_id] = query

    def create(self, spec: ResponseSessionSpec) -> None:
        if any(query_id not in self._queries for query_id in spec.query_ids):
            raise PermissionError("response session query is not registered")
        registered = set(self._broker.registered_operation_ids())
        if any(
            operation_id not in registered
            for operation_id in spec.response_operation_ids
        ):
            raise PermissionError("response session operation is not registered")
        with self._lock:
            current = self._records.get(spec.session_id)
            if current is not None:
                if current["spec"].digest != spec.digest:
                    raise ValueError("response session ID conflicts")
                return
            if len(self._records) >= 1_000:
                raise ValueError("response session catalog limit reached")
            self._records[spec.session_id] = {
                "spec": spec, "state": "draft", "approvals": set(),
                "transcript": [],
            }
            self._save()

    def approve(self, session_id: str, approver: str) -> int:
        if not _ID.fullmatch(approver):
            raise ValueError("invalid response-session approver")
        with self._lock:
            record = self._get(session_id)
            spec = record["spec"]
            self._expire(record)
            if record["state"] != "draft":
                raise PermissionError("response session is not approvable")
            if approver == spec.requested_by:
                raise PermissionError("requester cannot approve their own session")
            record["approvals"].add(approver)
            self._save()
            return len(record["approvals"])

    def open(self, session_id: str) -> None:
        with self._lock:
            record = self._get(session_id)
            self._expire(record)
            if record["state"] != "draft":
                raise ValueError("response session is not in draft")
            required = 2 if record["spec"].response_operation_ids else 1
            if len(record["approvals"]) < required:
                raise PermissionError(
                    f"response session requires {required} approval(s)"
                )
            record["state"] = "active"
            self._save()

    def query(
        self,
        session_id: str,
        request_id: str,
        query_id: str,
        parameters: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], TranscriptEvent]:
        if not _ID.fullmatch(request_id):
            raise ValueError("invalid query request identity")
        key = (session_id, request_id)
        with self._lock:
            record = self._active(session_id)
            spec = record["spec"]
            if query_id not in spec.query_ids:
                raise PermissionError("query is outside the session capability set")
            query = self._queries.get(query_id)
            if query is None:
                raise PermissionError("query is unavailable after restart")
            if not isinstance(parameters, Mapping) or len(parameters) > 64:
                raise ValueError("query parameters must be a bounded mapping")
            _reject_executable_fields(parameters)
            encoded = _canonical(parameters)
            if len(encoded) > MAX_VALUE_BYTES:
                raise ValueError("query parameters exceed 64 KiB")
            request_digest = hashlib.sha256(encoded).hexdigest()
            existing = self._find_event(record, request_id)
            if existing is not None:
                if (
                    existing.kind != "query"
                    or existing.subject_id != query_id
                    or existing.request_sha256 != request_digest
                ):
                    raise ValueError("query request ID conflicts")
                return {
                    "replayed": True,
                    "result_sha256": existing.result_sha256,
                }, existing
            query.validator(parameters)
            if key in self._inflight:
                raise RuntimeError("query request is already in progress")
            self._inflight.add(key)
        try:
            raw = query.handler(spec.target_id, dict(parameters))
            if not isinstance(raw, Mapping):
                raise TypeError("read-only query handler must return a mapping")
            result = dict(raw)
            result_encoded = _canonical(result)
            if len(result_encoded) > MAX_VALUE_BYTES:
                raise ValueError("read-only query result exceeds 64 KiB")
        except Exception as exc:
            with self._lock:
                self._inflight.discard(key)
                record = self._get(session_id)
                if self._find_event(record, request_id) is None:
                    self._append_event(
                        record, request_id, "query", query_id, request_digest,
                        hashlib.sha256(
                            type(exc).__name__.encode("utf-8")
                        ).hexdigest(),
                        ("failed-" + type(exc).__name__)[:80], False,
                    )
                    self._save()
            raise
        with self._lock:
            try:
                record = self._get(session_id)
                self._expire(record)
                if record["state"] != "active":
                    event = self._append_event(
                        record, request_id, "query", query_id, request_digest,
                        hashlib.sha256(result_encoded).hexdigest(),
                        ("discarded-" + str(record["state"]))[:80], False,
                    )
                    self._save()
                    raise PermissionError(
                        "response session ended while query was running"
                    )
                existing = self._find_event(record, request_id)
                if existing is not None:
                    return {
                        "replayed": True,
                        "result_sha256": existing.result_sha256,
                    }, existing
                event = self._append_event(
                    record, request_id, "query", query_id, request_digest,
                    hashlib.sha256(result_encoded).hexdigest(), "completed", False,
                )
                self._save()
                return result, event
            finally:
                self._inflight.discard(key)

    def execute_response(
        self, session_id: str, proposal: ResponseProposal,
    ) -> tuple[ResponseReceipt, TranscriptEvent]:
        with self._lock:
            record = self._active(session_id)
            spec = record["spec"]
            if (
                proposal.operation_id not in spec.response_operation_ids
                or proposal.target_id != spec.target_id
                or proposal.requested_by != spec.requested_by
            ):
                raise PermissionError("response proposal is outside the session boundary")
            receipt = self._broker.execute(proposal)
            request_digest = proposal.digest
            result_digest = hashlib.sha256(
                _canonical(asdict(receipt))
            ).hexdigest()
            event_id = "response-" + proposal.proposal_id
            existing = self._find_event(record, event_id)
            if existing is not None:
                if (
                    existing.request_sha256 != request_digest
                    or existing.result_sha256 != result_digest
                ):
                    raise ValueError("response transcript ID conflicts")
                return receipt, existing
            event = self._append_event(
                record, event_id, "response", proposal.operation_id,
                request_digest, result_digest, receipt.outcome, receipt.executed,
            )
            self._save()
            return receipt, event

    def close_session(self, session_id: str) -> TranscriptReceipt:
        with self._lock:
            record = self._get(session_id)
            self._expire(record)
            if record["state"] == "active":
                record["state"] = "closed"
                self._save()
            elif record["state"] not in {"closed", "expired"}:
                raise ValueError("only an open or expired session can close")
            return self.transcript_receipt(session_id)

    def transcript_receipt(self, session_id: str) -> TranscriptReceipt:
        with self._lock:
            record = self._get(session_id)
            self._expire(record)
            transcript: list[TranscriptEvent] = record["transcript"]
            if not self._verify_chain(session_id, transcript):
                raise ValueError("response session transcript authentication failed")
            core = {
                "session_id": session_id,
                "session_digest": record["spec"].digest,
                "state": record["state"],
                "event_count": len(transcript),
                "chain_head": (
                    transcript[-1].event_hash if transcript else "0" * 64
                ),
                "recorded_at": float(self._clock()),
            }
            return TranscriptReceipt(
                **core, receipt_hmac=hmac.new(
                    self._key, _canonical(core), hashlib.sha256
                ).hexdigest(),
            )

    def transcript(self, session_id: str) -> tuple[TranscriptEvent, ...]:
        """Return the verified privacy-minimized action transcript."""
        with self._lock:
            record = self._get(session_id)
            self._expire(record)
            events = tuple(record["transcript"])
            if not self._verify_chain(session_id, events):
                raise ValueError("response session transcript authentication failed")
            return events

    def verify_receipt(self, receipt: TranscriptReceipt) -> bool:
        value = asdict(receipt)
        signature = value.pop("receipt_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    def _append_event(
        self,
        record: dict[str, Any],
        event_id: str,
        kind: str,
        subject_id: str,
        request_digest: str,
        result_digest: str,
        outcome: str,
        host_changed: bool,
    ) -> TranscriptEvent:
        transcript: list[TranscriptEvent] = record["transcript"]
        if len(transcript) >= MAX_TRANSCRIPT:
            raise ValueError("response session transcript limit reached")
        previous = transcript[-1].event_hash if transcript else "0" * 64
        core = {
            "event_id": event_id,
            "session_id": record["spec"].session_id,
            "kind": kind,
            "subject_id": subject_id,
            "request_sha256": request_digest,
            "result_sha256": result_digest,
            "outcome": str(outcome)[:80],
            "host_changed": bool(host_changed),
            "timestamp": float(self._clock()),
            "previous_hash": previous,
        }
        event_hash = hashlib.sha256(_canonical(core)).hexdigest()
        event = TranscriptEvent(
            **core, event_hash=event_hash,
            event_hmac=hmac.new(
                self._key, event_hash.encode("ascii"), hashlib.sha256
            ).hexdigest(),
        )
        transcript.append(event)
        return event

    @staticmethod
    def _find_event(
        record: Mapping[str, Any], event_id: str,
    ) -> TranscriptEvent | None:
        return next(
            (
                event for event in record["transcript"]
                if event.event_id == event_id
            ),
            None,
        )

    def _active(self, session_id: str) -> dict[str, Any]:
        record = self._get(session_id)
        self._expire(record)
        if record["state"] != "active":
            raise PermissionError("response session is not active")
        return record

    def _expire(self, record: dict[str, Any]) -> None:
        if (
            record["state"] in {"draft", "active"}
            and float(self._clock()) >= record["spec"].expires_at
        ):
            record["state"] = "expired"
            self._save()

    def _get(self, session_id: str) -> dict[str, Any]:
        try:
            return self._records[session_id]
        except KeyError as exc:
            raise KeyError(session_id) from exc

    def _save(self) -> None:
        records = {
            session_id: {
                "spec": asdict(record["spec"]),
                "state": record["state"],
                "approvals": sorted(record["approvals"]),
                "transcript": [
                    asdict(event) for event in record["transcript"]
                ],
            }
            for session_id, record in sorted(self._records.items())
        }
        signature = hmac.new(
            self._key, _canonical(records), hashlib.sha256
        ).hexdigest()
        encoded = _canonical({
            "schema_version": 1, "records": records, "hmac": signature,
        })
        if len(encoded) > MAX_STATE_BYTES:
            raise ValueError("response session state exceeds 16 MiB")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(
            self._path.suffix + f".{os.getpid()}.tmp"
        )
        try:
            with open(temporary, "xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temporary, self._path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _verify_chain(
        self, session_id: str, transcript: tuple[TranscriptEvent, ...] | list[TranscriptEvent],
    ) -> bool:
        previous = "0" * 64
        ids: set[str] = set()
        for event in transcript:
            value = asdict(event)
            signature = value.pop("event_hmac")
            event_hash = value.pop("event_hash")
            if (
                event.session_id != session_id
                or event.event_id in ids
                or event.previous_hash != previous
                or hashlib.sha256(_canonical(value)).hexdigest() != event_hash
                or not hmac.compare_digest(
                    signature,
                    hmac.new(
                        self._key, event_hash.encode("ascii"), hashlib.sha256
                    ).hexdigest(),
                )
            ):
                return False
            ids.add(event.event_id)
            previous = event_hash
        return True

    def _load(self) -> None:
        if not self._path.exists():
            return
        if self._path.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("response session state exceeds 16 MiB")
        value = json.loads(self._path.read_text(encoding="utf-8"))
        records = value.get("records")
        if value.get("schema_version") != 1 or not isinstance(records, dict):
            raise ValueError("response session state is invalid")
        expected = hmac.new(
            self._key, _canonical(records), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(str(value.get("hmac", "")), expected):
            raise ValueError("response session state authentication failed")
        for session_id, raw in records.items():
            spec_raw = dict(raw["spec"])
            spec_raw["query_ids"] = tuple(spec_raw["query_ids"])
            spec_raw["response_operation_ids"] = tuple(
                spec_raw["response_operation_ids"]
            )
            spec = ResponseSessionSpec(**spec_raw)
            state = raw.get("state")
            approvals = set(raw.get("approvals", ()))
            transcript = [
                TranscriptEvent(**event) for event in raw.get("transcript", ())
            ]
            if (
                session_id != spec.session_id or state not in _STATES
                or any(not _ID.fullmatch(item) for item in approvals)
                or len(transcript) > MAX_TRANSCRIPT
            ):
                raise ValueError("response session record is invalid")
            if not self._verify_chain(session_id, transcript):
                raise ValueError("response session transcript authentication failed")
            self._records[session_id] = {
                "spec": spec, "state": state, "approvals": approvals,
                "transcript": transcript,
            }
