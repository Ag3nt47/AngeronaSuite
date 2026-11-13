"""Reversible, expiring acknowledgements of exact authenticated alert records.

Legacy normalized-message/class rows stay visible for review, but never suppress
active threats. Receipts use the existing per-install bus.key; no key is created
here. A process that owns that same user/key can forge or replay local receipts.
This is local authenticity and bounded scope, not same-SID or rollback defence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import stat
import threading
import time
import uuid
from pathlib import Path

from angerona.core.data_paths import data_dir

_SCHEMA = "angerona.alert-acks/v2"
_SCOPE = "exact-authenticated-record/v1"
_DOMAIN = b"Angerona.AlertAck.v2\0"
DEFAULT_TTL_S = 3600.0
MAX_TTL_S = 24 * 3600.0
_MAX_BYTES = 2 * 1024 * 1024
_MAX_RECORDS = 4096
_MAX_HISTORY = 128
_LOCK = threading.RLock()
# Retained names for diagnostic/test compatibility; authorization is not cached
# by mtime, and expiry is evaluated against the current clock on every snapshot.
_CACHE = None
_CACHE_MTIME = -1.0


def _repo_root() -> Path:
    return data_dir()


def _store_path() -> Path:
    return _repo_root() / "shared_logs" / "alert_acks.json"


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False, default=str).encode("utf-8")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate acknowledgement field")
        result[key] = value
    return result


def _read_plain(path: Path, maximum: int) -> bytes:
    for node in (*reversed(path.parents), path):
        info = node.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("acknowledgement path is redirected")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError("acknowledgement input is not bounded single-link data")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("acknowledgement input exceeds its byte bound")
    return raw


def _key_for_store(path: Path) -> bytes | None:
    try:
        key = bytes.fromhex(_read_plain(path.parent.parent / "bus.key", 128).decode("ascii").strip())
    except Exception:
        return None
    return key if len(key) == 32 else None


def signature(ev) -> str:
    """Identity of one complete EventBus record; changed evidence is a new record."""
    body = {name: getattr(ev, name, None) for name in
            ("module", "message", "severity", "ts", "details", "hmac_sig", "mesh_sig", "mesh_peer")}
    return "event-v2:" + hashlib.sha256(_canonical(body)).hexdigest()


def _rows(value) -> dict:
    if type(value) is not dict or len(value) > _MAX_RECORDS:
        raise ValueError("acknowledgement record count is invalid")
    for sig, row in value.items():
        if (type(sig) is not str or len(sig) > 128 or type(row) is not dict
                or type(row.get("history", [])) is not list or len(row.get("history", [])) > _MAX_HISTORY):
            raise ValueError("acknowledgement record is invalid")
    return value


def _load_at(path: Path, key: bytes | None) -> tuple[dict, str, bytes]:
    try:
        raw = _read_plain(path, _MAX_BYTES)
    except FileNotFoundError:
        return {}, "missing", b""
    except Exception:
        return {}, "invalid", b""
    try:
        doc = json.loads(raw, object_pairs_hook=_pairs)
        if type(doc) is not dict:
            raise ValueError("acknowledgements must be an object")
        if doc.get("schema") != _SCHEMA:
            legacy = {sig: dict(row, scope="legacy-class-review-required") for sig, row in _rows(doc).items()}
            return legacy, "legacy-review-required", raw
        if set(doc) != {"schema", "records", "updated_at", "hmac"}:
            raise ValueError("invalid acknowledgement schema")
        records = _rows(doc["records"])
        body = {name: value for name, value in doc.items() if name != "hmac"}
        expected = hmac.new(key, _DOMAIN + _canonical(body), hashlib.sha256).hexdigest() if key else ""
        if not expected or type(doc["hmac"]) is not str or not hmac.compare_digest(doc["hmac"], expected):
            return records, "unverified", raw
        return records, "verified", raw
    except Exception:
        return {}, "invalid", raw


def load() -> dict:
    path = _store_path()
    return _load_at(path, _key_for_store(path))[0]


def _new_file(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _save_at(path: Path, records: dict, key: bytes | None, previous: tuple[dict, str, bytes]) -> None:
    if key is None:
        raise ValueError("Acknowledgement signing key is unavailable; the alert remains active.")
    _rows(records)
    _old, integrity, original = previous
    if integrity in {"invalid", "unverified"}:
        raise ValueError("Existing acknowledgement integrity is unknown; preserve and review it before changes.")
    path.parent.mkdir(parents=True, exist_ok=True)
    from angerona.core.source_sandbox import _hold_plain_directories
    from angerona.core.atomic_io import replace_with_retry
    with _hold_plain_directories(path.parent):
        if integrity == "legacy-review-required":
            archive = path.with_name(path.name + ".legacy-" + hashlib.sha256(original).hexdigest() + ".json")
            if archive.exists():
                if _read_plain(archive, _MAX_BYTES) != original:
                    raise ValueError("Preserved acknowledgement history changed.")
            else:
                _new_file(archive, original)
        body = {"schema": _SCHEMA, "records": records, "updated_at": time.time()}
        doc = dict(body, hmac=hmac.new(key, _DOMAIN + _canonical(body), hashlib.sha256).hexdigest())
        encoded = _canonical(doc)
        if len(encoded) > _MAX_BYTES:
            raise ValueError("Acknowledgement storage capacity requires review; history was preserved.")
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".pending")
        try:
            _new_file(temporary, encoded)
            replace_with_retry(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def _active(sig: str, record: dict, now: float) -> bool:
    try:
        issued, expires = float(record["acked_at"]), float(record["expires_at"])
        return (sig.startswith("event-v2:") and record.get("scope") == _SCOPE and record.get("acked") is True
                and math.isfinite(issued) and math.isfinite(expires) and issued <= now + 30
                and now < expires <= issued + MAX_TTL_S)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def acked_signatures() -> set[str]:
    path = _store_path()
    records, integrity, _raw = _load_at(path, _key_for_store(path))
    now = time.time()
    return {sig for sig, record in records.items() if _active(sig, record, now)} if integrity == "verified" else set()


def is_acked(ev) -> bool:
    return signature(ev) in acked_signatures()


def _event(action: str, reason: str) -> dict:
    now = time.time()
    return {"action": action, "ts": now, "iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "reason": str(reason or "")[:1024]}


def _ack_at(ev, reason, ttl_s, path: Path, key: bytes | None) -> dict:
    if type(ttl_s) not in (int, float) or not math.isfinite(ttl_s) or not 1 <= ttl_s <= MAX_TTL_S:
        raise ValueError("Acknowledgement duration must be 1 second to 24 hours.")
    from angerona.core.eventbus import BusAuthority
    try:
        verified = key is not None and BusAuthority(key).verify(ev)
    except Exception:
        verified = False
    if not verified:
        raise ValueError("This exact alert record could not be authenticated; it remains active.")
    with _LOCK:
        previous = _load_at(path, key)
        records = previous[0]
        sig = signature(ev)
        record = dict(records.get(sig, {"module": str(ev.module), "sample": str(ev.message)[:200], "history": []}))
        if len(record["history"]) >= _MAX_HISTORY:
            raise ValueError("Acknowledgement history capacity requires review.")
        now = time.time()
        record.update(acked=True, scope=_SCOPE, acked_at=now, expires_at=now + ttl_s,
                      reason=str(reason or "")[:1024])
        record["history"] = [*record["history"], _event("ack", reason)]
        records[sig] = record
        _save_at(path, records, key, previous)
        return record


def ack(ev, reason: str = "", *, ttl_s: float = DEFAULT_TTL_S) -> dict:
    path = _store_path()
    return _ack_at(ev, reason, ttl_s, path, _key_for_store(path))


def unack(sig_or_ev, reason: str = "") -> dict:
    sig = sig_or_ev if isinstance(sig_or_ev, str) else signature(sig_or_ev)
    path = _store_path()
    with _LOCK:
        key = _key_for_store(path)
        previous = _load_at(path, key)
        records = previous[0]
        record = dict(records.get(sig, {"module": "", "sample": "", "history": []}))
        if len(record["history"]) >= _MAX_HISTORY:
            raise ValueError("Acknowledgement history capacity requires review.")
        record.update(acked=False, history=[*record["history"], _event("unack", reason)])
        records[sig] = record
        _save_at(path, records, key, previous)
        return record


def acked_records() -> list[dict]:
    path = _store_path()
    records, integrity, _raw = _load_at(path, _key_for_store(path))
    now = time.time()
    return [{**record, "module": str(record.get("module", ""))[:200],
             "sample": str(record.get("sample", ""))[:200], "reason": str(record.get("reason", ""))[:1024],
             "sig": sig, "integrity": integrity,
             "active": integrity == "verified" and _active(sig, record, now),
             "review_required": integrity != "verified" or record.get("scope") != _SCOPE}
            for sig, record in records.items() if record.get("acked")]


def filter_active(events: list) -> list:
    acknowledged = acked_signatures()
    return [event for event in events if signature(event) not in acknowledged]


def self_test() -> tuple[bool, str]:
    """Private signed-record round trip; never swaps live storage or loads a key."""
    import dataclasses
    import tempfile
    from angerona.core.eventbus import BusAuthority, Event, Severity
    key = bytes(range(32))
    event = Event("ACK self-test", "inert signed fixture", Severity.HIGH)
    event = dataclasses.replace(event, hmac_sig=BusAuthority(key).sign(event))
    later = dataclasses.replace(event, ts=event.ts + 1)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "shared_logs" / "alert_acks.json"
        _ack_at(event, "private test", 60, path, key)
        records, integrity, _raw = _load_at(path, key)
        ok = integrity == "verified" and _active(signature(event), records[signature(event)], time.time())
        ok = ok and signature(later) not in records
        return ok, "Exact authenticated alert receipt verified; changed record stays active."
