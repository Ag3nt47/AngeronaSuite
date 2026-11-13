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
import math
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, Optional

_CONTEXT = b"angerona-peer-alert-outbox-v1\0"
_GENESIS = "0" * 64
_MAX_LINE = 4096
_MAX_FILE = 256 * 1024
_MAX_DRAIN = 256
_MAX_SCAN_LINES = 4096
_MAX_CURSOR = 4096
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


def _read_page(path: Path) -> tuple[list[bytes], list[str]]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_FILE + _MAX_LINE + 1)
    except FileNotFoundError:
        return [], []
    except OSError:
        return [], ["unreadable-page"]
    gaps = []
    if len(raw) > _MAX_FILE:
        gaps.append("page-byte-budget")
    raw = raw[:_MAX_FILE + _MAX_LINE]
    rows = raw.split(b"\n")
    if len(rows) > _MAX_SCAN_LINES:
        gaps.append("page-line-budget")
    lines = []
    for line in rows[:_MAX_SCAN_LINES]:
        if not line.strip():
            continue
        if len(line) > _MAX_LINE:
            gaps.append("record-byte-budget")
            continue
        lines.append(line)
    return lines, gaps


def _read_lines(path: Path) -> list[bytes]:
    return _read_page(path)[0]


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
        # A crash can occur after rotation moved the live file but before the
        # next append. The retained page still owns that predecessor.
        for path in (self.path, self.path.with_suffix(".jsonl.1")):
            for line in reversed(_read_lines(path)):
                try:
                    record = json.loads(line)
                    if hmac.compare_digest(_mac(self._key, record), str(record.get("mac", ""))):
                        return str(record["mac"])
                except (ValueError, KeyError, TypeError, RecursionError, OverflowError):
                    continue
        return _GENESIS

    def _rotate_if_needed(self, incoming: int) -> bool:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return False
        if size + incoming <= _MAX_FILE:
            return False
        os.replace(self.path, self.path.with_suffix(".jsonl.1"))
        # Retain the authenticated predecessor across the file boundary.
        return True

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
    """Bounded verifier with explicit publication acknowledgement.

    A lost retained cursor is a coverage gap, never permission to replay the
    complete retained log as fresh evidence. Authenticated originals stay on disk.
    """

    def __init__(self, *, key_raw: Optional[bytes] = None, path: Optional[Path] = None) -> None:
        self._key = _derive(key_raw)
        self.path = Path(path) if path is not None else outbox_path()
        self._cursor_path = self.path.with_suffix(".cursor")
        self._seen = self._load_cursor()
        self._pending: list[dict] = []
        self._checkpoints: dict[int, str] = {}
        self._diagnostics: dict[int, str] = {}
        self._reported_diagnostic = ""

    def _load_cursor(self) -> str:
        try:
            with self._cursor_path.open("rb") as stream:
                raw = stream.read(_MAX_CURSOR + 1)
            if len(raw) > _MAX_CURSOR:
                return "!unavailable"
            value = json.loads(raw)
            mac, tag = str(value["mac"]), str(value["tag"])
            expected = hmac.new(self._key, b"cursor\0" + mac.encode(), hashlib.sha256).hexdigest()
            if len(mac) == 64 and hmac.compare_digest(expected, tag):
                return mac
        except FileNotFoundError:
            return ""
        except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
            pass
        return "!unavailable"

    def _store_cursor(self, mac: str) -> None:
        tag = hmac.new(self._key, b"cursor\0" + mac.encode(), hashlib.sha256).hexdigest()
        temporary = self._cursor_path.with_name(self._cursor_path.name + "." + secrets.token_hex(4) + ".tmp")
        try:
            temporary.write_text(json.dumps({"mac": mac, "tag": tag}), encoding="utf-8")
            os.replace(temporary, self._cursor_path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def peek(self) -> list[dict]:
        """Return a retained page; it remains pending until each publish succeeds."""
        if self._pending:
            return list(self._pending)
        verified, gaps = [], []
        broken = 0
        previous = None
        observed = set()
        fingerprint = hashlib.sha256()
        for path in (self.path.with_suffix(".jsonl.1"), self.path):
            lines, page_gaps = _read_page(path)
            gaps.extend(page_gaps)
            first = True
            for line in lines:
                fingerprint.update(line)
                try:
                    record = json.loads(line)
                    ok = (isinstance(record, dict)
                          and record.get("level") in _LEVELS
                          and type(record.get("ts")) in (int, float) and math.isfinite(record["ts"])
                          and type(record.get("details")) is dict
                          and isinstance(record.get("id"), str)
                          and isinstance(record.get("source"), str)
                          and isinstance(record.get("msg"), str)
                          and hmac.compare_digest(_mac(self._key, record), str(record.get("mac", ""))))
                except (ValueError, KeyError, TypeError, RecursionError, OverflowError):
                    ok = False
                if not ok:
                    broken += 1
                    continue
                mac, prior = record["mac"], record["prev"]
                if mac in observed:
                    broken += 1
                    continue
                if first:
                    # Rotation preserves chain continuity. Only the oldest
                    # retained page can have an unavailable predecessor.
                    if previous is not None and prior != previous:
                        broken += 1
                        continue
                    if previous is None and prior not in (_GENESIS, self._seen):
                        gaps.append("unanchored-retained-prefix")
                    first = False
                elif prior != previous:
                    broken += 1
                    continue
                observed.add(mac)
                previous = mac
                verified.append(record)
        start = 0
        checkpoint = ""
        if self._seen:
            located = next((i for i, record in enumerate(verified) if record["mac"] == self._seen), None)
            follows_cursor = (bool(verified) and verified[0]["prev"] == self._seen
                              and not broken and not gaps)
            if located is not None:
                # Earlier retained history can have an unavailable prefix, but
                # the acknowledged row anchors every validated successor.
                gaps = [gap for gap in gaps if gap != "unanchored-retained-prefix"]
                start = located + 1
            elif follows_cursor:
                # Rotation may retire the cursor row while retaining its signed
                # immediate successor. Its predecessor MAC proves continuity.
                start = 0
            else:
                gaps.append("acknowledged-cursor-not-retained")
                # Do not turn old signed rows into new events when continuity
                # is unknown. A successfully published gap may establish a new
                # checkpoint at the retained tail for subsequent fresh rows.
                checkpoint = verified[-1]["mac"] if verified else ""
                start = len(verified)
        fresh = verified[start:start + _MAX_DRAIN]
        diagnostic = fingerprint.hexdigest() + ":" + str(broken) + ":" + ",".join(sorted(set(gaps)))
        if (broken or gaps) and diagnostic != self._reported_diagnostic:
            report = {
                "id": "tamper" if broken else "gap", "ts": round(time.time(), 3),
                "source": "peer-alert-outbox", "level": "HIGH",
                "msg": (f"Peer watchdog alert outbox failed authentication/order ({broken} record(s))"
                        if broken else "Peer watchdog alert outbox coverage is incomplete"),
                "details": {"unauthenticated_records": broken, "coverage_gaps": sorted(set(gaps)),
                            "complete": False, "path": str(self.path), "response_authorized": False},
            }
            # Keep the total page budget, including the diagnostic.
            fresh = [report, *fresh[:_MAX_DRAIN - 1]]
            self._diagnostics[id(report)] = diagnostic
            if checkpoint:
                self._checkpoints[id(report)] = checkpoint
        self._pending = fresh
        return list(fresh)

    def ack(self, record: dict) -> None:
        """Advance only after this exact pending record was published successfully."""
        if not self._pending or self._pending[0] is not record:
            raise ValueError("Peer alert acknowledgement is out of order")
        mac = record.get("mac") or self._checkpoints.get(id(record))
        if mac:
            self._store_cursor(mac)
            self._seen = mac
        diagnostic = self._diagnostics.pop(id(record), None)
        if diagnostic is not None:
            self._reported_diagnostic = diagnostic
        self._checkpoints.pop(id(record), None)
        self._pending.pop(0)

    def drain(self) -> list[dict]:
        """Compatibility consumer: returning a page counts as its acknowledgement.

        Runtime publishers must use peek/ack so failed delivery remains pending.
        """
        records = self.peek()
        for record in records:
            self.ack(record)
        return records


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
