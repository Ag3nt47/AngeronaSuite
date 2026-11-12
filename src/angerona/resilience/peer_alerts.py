"""peer_alerts.py — durable, authenticated alert outbox from the peer watchdog.

The peer watchdog exists to resurrect a dead core, which means the moment it has
something important to say ("the core died unexpectedly", "restart pressure")
is exactly when the core's EventBus is unavailable. Before this outbox those
supervisor events were dropped. Now the watchdog appends each MEDIUM+ event as
one HMAC-chained JSON line; the core verifies and republishes them on start and
on every drain tick, and remembers what it already ingested.

Security properties
    * Authenticated: each record carries HMAC-SHA256 over its canonical body
      and the previous record's MAC, keyed by a context-separated derivation of
      the install's protected shutdown authority. Edited, reordered or
      interleaved records break the chain and are reported, never trusted.
    * Bounded: lines are capped at 4 KiB, the live file at 256 KiB with one
      rotation, and a drain publishes at most ``_MAX_DRAIN`` records.
    * Observe-only: ingestion publishes evidence; it grants no response or
      configuration authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

_CONTEXT = b"angerona-peer-alert-outbox-v1\0"
_GENESIS = "0" * 64
_MAX_LINE = 4096
_MAX_FILE = 256 * 1024
_MAX_DRAIN = 256
_LEVELS = ("MEDIUM", "HIGH", "CRITICAL")


def _data_dir() -> Path:
    from angerona.resilience.heartbeat import _data_dir as data_dir
    return data_dir()


def outbox_path(root: Optional[Path] = None) -> Path:
    directory = (Path(root) if root is not None else _data_dir()) / "ipc"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "peer_alerts.jsonl"


def _derive(key_raw: Optional[bytes]) -> bytes:
    if key_raw is None:
        from angerona.resilience import shutdown_token
        key_raw = shutdown_token._load_key()
    if not isinstance(key_raw, bytes) or len(key_raw) != 32:
        raise ValueError("peer alert authority must contain exactly 32 bytes")
    return hmac.new(key_raw, _CONTEXT, hashlib.sha256).digest()


def _canonical(record: dict) -> bytes:
    body = {k: record[k] for k in ("id", "ts", "source", "level", "msg", "details", "prev")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _mac(key: bytes, record: dict) -> str:
    return hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()


def _bounded_details(details: object) -> dict:
    if not isinstance(details, dict):
        return {}
    safe: dict = {}
    for name, value in list(details.items())[:24]:
        if isinstance(value, (bool, int, float)) or value is None:
            safe[str(name)[:64]] = value
        else:
            safe[str(name)[:64]] = str(value)[:256]
    return safe


def _read_lines(path: Path) -> list[bytes]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_FILE + _MAX_LINE)
    except OSError:
        return []
    return [line for line in raw.split(b"\n") if line.strip()]


class PeerAlertOutbox:
    """Single-writer append side, owned by the peer watchdog process."""

    def __init__(self, source: str = "peer-watchdog", *, key_raw: Optional[bytes] = None,
                 path: Optional[Path] = None) -> None:
        self.source = str(source)[:64]
        self._key = _derive(key_raw)
        self.path = Path(path) if path is not None else outbox_path()
        self._lock = threading.Lock()
        self._prev = self._recover_tail()

    def _recover_tail(self) -> str:
        for line in reversed(_read_lines(self.path)):
            try:
                record = json.loads(line)
                if hmac.compare_digest(_mac(self._key, record), str(record.get("mac", ""))):
                    return str(record["mac"])
            except (ValueError, KeyError, TypeError):
                continue
            break
        return _GENESIS

    def _rotate_if_needed(self, incoming: int) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size + incoming <= _MAX_FILE:
            return
        os.replace(self.path, self.path.with_suffix(".jsonl.1"))
        self._prev = _GENESIS

    def append(self, level: str, msg: str, details: Optional[dict] = None) -> Optional[dict]:
        level = str(level).upper()
        if level not in _LEVELS:
            return None
        with self._lock:
            record = {
                "id": secrets.token_hex(8),
                "ts": round(time.time(), 3),
                "source": self.source,
                "level": level,
                "msg": str(msg)[:512],
                "details": _bounded_details(details),
                "prev": self._prev,
            }
            record["mac"] = _mac(self._key, record)
            line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(line) > _MAX_LINE:
                record["details"] = {"truncated": True}
                record["mac"] = _mac(self._key, record)
                line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            self._rotate_if_needed(len(line))
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._prev = record["mac"]
            return record

    def supervisor_callback(self) -> Callable[[str, str, dict], None]:
        """Adapter for ``ProcessSupervisor(on_event=...)``; never raises."""
        def forward(level: str, msg: str, details: dict) -> None:
            try:
                self.append(level, msg, details)
            except Exception:
                pass
        return forward


class PeerAlertReader:
    """Core-side verifier. Yields each authenticated record exactly once."""

    def __init__(self, *, key_raw: Optional[bytes] = None, path: Optional[Path] = None) -> None:
        self._key = _derive(key_raw)
        self.path = Path(path) if path is not None else outbox_path()
        self._cursor_path = self.path.with_suffix(".cursor")
        self._seen = self._load_cursor()

    def _load_cursor(self) -> str:
        try:
            value = json.loads(self._cursor_path.read_text(encoding="utf-8"))
            mac, tag = str(value["mac"]), str(value["tag"])
            expected = hmac.new(self._key, b"cursor\0" + mac.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, tag):
                return mac
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return ""

    def _store_cursor(self, mac: str) -> None:
        tag = hmac.new(self._key, b"cursor\0" + mac.encode(), hashlib.sha256).hexdigest()
        temporary = self._cursor_path.with_name(self._cursor_path.name + "." + secrets.token_hex(4) + ".tmp")
        temporary.write_text(json.dumps({"mac": mac, "tag": tag}), encoding="utf-8")
        os.replace(temporary, self._cursor_path)

    def drain(self) -> list[dict]:
        """Return new authenticated records, plus one synthetic tamper record if
        the chain is broken. Advances the cursor only past verified records."""
        lines: Iterable[bytes] = (
            _read_lines(self.path.with_suffix(".jsonl.1")) + _read_lines(self.path)
        )
        verified: list[dict] = []
        broken = 0
        prev: Optional[str] = None
        for line in lines:
            try:
                record = json.loads(line)
                ok = (isinstance(record, dict)
                      and hmac.compare_digest(_mac(self._key, record), str(record.get("mac", ""))))
            except (ValueError, KeyError, TypeError):
                ok = False
            if not ok:
                broken += 1
                prev = None
                continue
            if prev is not None and record["prev"] not in (prev, _GENESIS):
                broken += 1
            prev = record["mac"]
            verified.append(record)
        start = 0
        if self._seen:
            for index, record in enumerate(verified):
                if record["mac"] == self._seen:
                    start = index + 1
                    break
        fresh = verified[start:start + _MAX_DRAIN]
        if fresh:
            self._seen = fresh[-1]["mac"]
            self._store_cursor(self._seen)
        if broken:
            fresh.append({
                "id": "tamper", "ts": round(time.time(), 3), "source": "peer-alert-outbox",
                "level": "HIGH",
                "msg": f"Peer watchdog alert outbox failed authentication ({broken} record(s))",
                "details": {"unauthenticated_records": broken, "path": str(self.path)},
            })
        return fresh


def self_test() -> tuple[bool, str]:
    import tempfile
    key = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory(prefix="peer_alerts_selftest_") as root:
        path = Path(root) / "peer_alerts.jsonl"
        outbox = PeerAlertOutbox(key_raw=key, path=path)
        outbox.append("INFO", "ignored")
        outbox.append("HIGH", "core died", {"component": "core"})
        reader = PeerAlertReader(key_raw=key, path=path)
        first = reader.drain()
        again = PeerAlertReader(key_raw=key, path=path).drain()
        with path.open("ab") as stream:
            stream.write(b'{"forged":true}\n')
        tampered = PeerAlertReader(key_raw=key, path=path).drain()
        ok = (len(first) == 1 and first[0]["msg"] == "core died" and again == []
              and any(r["id"] == "tamper" for r in tampered))
        return ok, "outbox append/verify/once/tamper verified" if ok else "peer alert outbox self-test failed"


if __name__ == "__main__":
    print(self_test())
