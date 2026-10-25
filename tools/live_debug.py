"""Read an explicitly enabled Angerona diagnostic pipe without elevation.

Run from a normal user terminal. This consumer writes only its own optional
rotating JSONL file; no command, code edit, or human verdict reaches the agent.
"""
from __future__ import annotations

import argparse
import hashlib
from itertools import islice
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from angerona.core.live_debug import (  # noqa: E402
    LiveDebugClient, LiveDebugError, MAX_FRAME_BYTES, PROTOCOL, endpoint_for_pid, sanitize_text,
    _decode as _decode_diagnostic_frame,
)


OUTPUT_BATCH_RECORDS = 100
OUTPUT_BATCH_BYTES = 64 * 1024
OUTPUT_FLUSH_INTERVAL = 0.1


def _output_frame(record):
    raw = json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    if len(raw) > MAX_FRAME_BYTES:
        raise LiveDebugError("Output record exceeds its bound")
    return raw


class RotatingViewLog:
    """Bounded caller-owned JSONL; validate every held append segment."""

    def __init__(self, path: Path, *, max_bytes: int = 8 * 1024 * 1024, backups: int = 2):
        self.path = Path(path).absolute()
        self.max_bytes = max(MAX_FRAME_BYTES, min(64 * 1024 * 1024, int(max_bytes)))
        self.backups = max(0, min(5, int(backups)))
        if not self.path.parent.is_dir():
            raise LiveDebugError("Output parent directory must already exist")
        self._check(self.path)

    @staticmethod
    def _safe(info):
        return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not stat.S_ISLNK(info.st_mode)
                and not getattr(info, "st_file_attributes", 0) & 0x400)

    @staticmethod
    def _identity(info):
        return info.st_dev, info.st_ino

    @classmethod
    def _check(cls, path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not cls._safe(info):
            raise LiveDebugError("Refusing unsafe diagnostic output file")
        with path.open("rb") as stream:
            held = os.fstat(stream.fileno())
            named = path.lstat()
            if (not cls._safe(held) or not cls._safe(named)
                    or cls._identity(info) != cls._identity(held)
                    or cls._identity(held) != cls._identity(named)):
                raise LiveDebugError("Output identity changed")
            cls._header(stream)
            after = path.lstat()
            if not cls._safe(after) or cls._identity(after) != cls._identity(held):
                raise LiveDebugError("Output identity changed")
        return after

    @staticmethod
    def _header(stream):
        first = stream.readline(MAX_FRAME_BYTES + 1)
        if first:
            try:
                _decode_diagnostic_frame(first)
            except LiveDebugError as exc:
                raise LiveDebugError("Existing output is not a live-debug JSONL log") from exc

    def _rotate(self):
        for index in range(self.backups, 0, -1):
            destination = self.path.with_name(self.path.name + f".{index}")
            source = self.path if index == 1 else self.path.with_name(self.path.name + f".{index - 1}")
            self._check(destination)
            present = self._check(source)
            if present is not None:
                os.replace(source, destination)
        if self.backups == 0:
            self._check(self.path)
            self.path.unlink()

    def _append_segment(self, frames, expected):
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        if expected is None:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor = os.open(self.path, flags, 0o600)
        with os.fdopen(descriptor, "a+b") as stream:
            held = os.fstat(stream.fileno())
            named = self.path.lstat()
            if (not self._safe(held) or not self._safe(named)
                    or self._identity(held) != self._identity(named)
                    or (expected is not None and (self._identity(held) != self._identity(expected)
                                                 or held.st_size != expected.st_size))
                    or (expected is None and held.st_size != 0)):
                raise LiveDebugError("Output identity changed")
            stream.seek(0)
            self._header(stream)
            before = os.fstat(stream.fileno())
            named = self.path.lstat()
            size = sum(map(len, frames))
            if (not self._safe(before) or not self._safe(named)
                    or self._identity(before) != self._identity(held)
                    or self._identity(named) != self._identity(held)
                    or before.st_size != held.st_size or before.st_size + size > self.max_bytes):
                raise LiveDebugError("Output identity or size changed")
            stream.seek(0, os.SEEK_END)
            raw = b"".join(frames)
            if stream.write(raw) != len(raw):
                raise LiveDebugError("Incomplete diagnostic output write")
            stream.flush()
            after = os.fstat(stream.fileno())
            named = self.path.lstat()
            if (not self._safe(after) or not self._safe(named)
                    or self._identity(after) != self._identity(held)
                    or self._identity(named) != self._identity(held)
                    or after.st_size != before.st_size + size or after.st_size > self.max_bytes):
                raise LiveDebugError("Output identity or size changed after append")

    def _write_frames(self, frames):
        offset = 0
        while offset < len(frames):
            # No header or metadata result is reused across held segments.
            expected = self._check(self.path)
            size = 0 if expected is None else expected.st_size
            if size + len(frames[offset]) > self.max_bytes:
                self._rotate()
                continue
            end = offset
            while end < len(frames) and size + len(frames[end]) <= self.max_bytes:
                size += len(frames[end])
                end += 1
            self._append_segment(frames[offset:end], expected)
            offset = end

    def write(self, record):
        """Append one record immediately, retaining the original public API."""
        self._write_frames((_output_frame(record),))

    def write_many(self, records):
        """Append one bounded batch; rotate only between complete frames."""
        frames = []
        size = 0
        for record in islice(iter(records), OUTPUT_BATCH_RECORDS + 1):
            if len(frames) == OUTPUT_BATCH_RECORDS:
                raise LiveDebugError("Output batch exceeds its record bound")
            raw = _output_frame(record)
            size += len(raw)
            if size > OUTPUT_BATCH_BYTES:
                raise LiveDebugError("Output batch exceeds its byte bound")
            frames.append(raw)
        if len(frames) == 1:
            self.write(json.loads(frames[0]))
        elif frames:
            self._write_frames(frames)



def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--pid", type=int, required=True, help="Angerona server PID shown in Live Debug")
    result.add_argument("--birth", type=float, help="Optional server process creation time shown in Live Debug")
    result.add_argument("--follow", action="store_true", help="Continue reading after retained history")
    result.add_argument("--duration", type=float, default=0, help="Follow for at most this many seconds; 0 has no limit")
    result.add_argument("--output", type=Path, help="Optional caller-owned rotating JSONL output")
    result.add_argument("--max-mib", type=int, default=8, choices=range(1, 65), metavar="1..64")
    result.add_argument("--backups", type=int, default=2, choices=range(0, 6), metavar="0..5")
    result.add_argument("--annotate", type=int, metavar="SEQ", help="Write a local advisory verdict for this sequence")
    result.add_argument("--verdict", choices=("threat", "false-positive", "needs-review"))
    result.add_argument("--note", default="", help="Optional redacted local annotation note")
    return result


def main(argv=None, *, client_factory=LiveDebugClient):
    arguments = parser().parse_args(argv)
    if not math.isfinite(arguments.duration) or arguments.duration < 0 or arguments.duration > 86400:
        parser().error("--duration must be between 0 and 86400 seconds")
    if arguments.annotate is not None and (arguments.annotate < 1 or not arguments.verdict):
        parser().error("--annotate requires a positive sequence and --verdict")
    if arguments.annotate is not None and not arguments.note.strip():
        parser().error("--annotate requires a nonempty --note explaining the advisory verdict")
    if arguments.verdict and arguments.annotate is None:
        parser().error("--verdict requires --annotate")
    client = None
    writer = None

    pending = []
    pending_bytes = 0
    pending_since = 0.0

    def flush_pending():
        nonlocal pending, pending_bytes, pending_since
        if not pending:
            return
        frames = pending
        # Once output begins a failed batch is never replayed or duplicated.
        pending, pending_bytes, pending_since = [], 0, 0.0
        sys.stdout.write(b"".join(frames).decode("ascii"))
        sys.stdout.flush()
        if writer is not None:
            writer.write_many(json.loads(raw) for raw in frames)

    def emit(record):
        nonlocal pending_bytes, pending_since
        raw = _output_frame(record)
        if pending and (len(pending) == OUTPUT_BATCH_RECORDS
                        or pending_bytes + len(raw) > OUTPUT_BATCH_BYTES):
            flush_pending()
        if not pending:
            pending_since = time.monotonic()
        pending.append(raw)
        pending_bytes += len(raw)
        if (record.get("kind") in {"hello", "heartbeat", "annotation", "client_error"}
                or len(pending) == OUTPUT_BATCH_RECORDS
                or pending_bytes == OUTPUT_BATCH_BYTES
                or time.monotonic() - pending_since >= OUTPUT_FLUSH_INTERVAL):
            flush_pending()

    def report_error(exc):
        nonlocal writer
        # Preserve accepted frames before reporting a read failure. A failed
        # output batch is already retired and is never replayed or duplicated.
        output_error = None
        try:
            flush_pending()
        except (LiveDebugError, OSError, ValueError) as failure:
            output_error = failure
        writer = None
        emit(dict(protocol=PROTOCOL, kind="client_error", advisory_only=True,
                  reason=sanitize_text(str(exc), 512), ts=time.time(), pid=arguments.pid))
        if output_error is not None:
            emit(dict(protocol=PROTOCOL, kind="client_error", advisory_only=True,
                      reason=sanitize_text("Pending output failed: " + str(output_error), 512),
                      ts=time.time(), pid=arguments.pid))
        return 2

    try:
        if arguments.output:
            writer = RotatingViewLog(arguments.output, max_bytes=arguments.max_mib * 1024 * 1024,
                                     backups=arguments.backups)
        client = client_factory(endpoint_for_pid(arguments.pid), arguments.pid, arguments.birth)
        client.connect()
        deadline = time.monotonic() + arguments.duration if arguments.follow and arguments.duration else None
        snapshot_deadline = time.monotonic() + 30.0 if not arguments.follow else None
        hello_deadline = time.monotonic() + 5.0
        target_cursor = None
        run_id = None
        annotated = False
        while True:
            if target_cursor is None and time.monotonic() >= hello_deadline:
                raise LiveDebugError("Diagnostic server did not provide its initial status before the deadline")
            if snapshot_deadline is not None and time.monotonic() >= snapshot_deadline:
                raise LiveDebugError("Diagnostic snapshot did not complete before its deadline")
            if deadline is not None and time.monotonic() >= deadline:
                break
            record = client.read(timeout=0.25)
            if record is None:
                flush_pending()
                continue
            emit(record)
            if record["kind"] == "hello":
                run_id = record["run_id"]
                target_cursor = record["status"]["cursor"]
                if arguments.annotate is not None:
                    if arguments.annotate > target_cursor:
                        raise LiveDebugError("Annotation sequence has not been observed in this run")
            if arguments.annotate is not None and record["kind"] not in {"hello", "heartbeat"}:
                if (record["kind"] == "gap" and record.get("reason") == "retention"
                        and arguments.annotate <= record["seq"]):
                    raise LiveDebugError("Annotation target is no longer retained; its view was not observed")
                if record.get("seq") == arguments.annotate:
                    canonical = json.dumps(record, ensure_ascii=True, sort_keys=True,
                                           separators=(",", ":"), allow_nan=False).encode("ascii")
                    emit(dict(protocol=PROTOCOL, kind="annotation", advisory_only=True,
                              run_id=run_id, target_seq=arguments.annotate,
                              target_view_sha256=hashlib.sha256(canonical).hexdigest(),
                              verdict=arguments.verdict, note=sanitize_text(arguments.note),
                              ts=time.time(), pid=arguments.pid))
                    annotated = True
                    break
            if (not arguments.follow and target_cursor is not None
                    and (target_cursor == 0 or record.get("seq", 0) >= target_cursor)):
                break
        if arguments.annotate is not None and not annotated:
            raise LiveDebugError("Annotation target was not observed before the review ended")
        flush_pending()
        return 0
    except KeyboardInterrupt:
        try:
            flush_pending()
        except BrokenPipeError:
            return 0
        except (LiveDebugError, OSError, ValueError) as exc:
            return report_error(exc)
        return 0
    except BrokenPipeError:
        return 0
    except (LiveDebugError, OSError, ValueError) as exc:
        return report_error(exc)
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
