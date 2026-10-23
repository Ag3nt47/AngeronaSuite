"""Read an explicitly enabled Angerona diagnostic pipe without elevation.

Run from a normal user terminal. This consumer writes only its own optional
rotating JSONL file; no command, code edit, or human verdict reaches the agent.
"""
from __future__ import annotations

import argparse
import hashlib
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


class RotatingViewLog:
    """Bounded caller-owned JSONL; refuse links and unrelated existing files."""

    def __init__(self, path: Path, *, max_bytes: int = 8 * 1024 * 1024, backups: int = 2):
        self.path = Path(path).absolute()
        self.max_bytes = max(MAX_FRAME_BYTES, min(64 * 1024 * 1024, int(max_bytes)))
        self.backups = max(0, min(5, int(backups)))
        if not self.path.parent.is_dir():
            raise LiveDebugError("Output parent directory must already exist")
        self._check(self.path)

    @staticmethod
    def _check(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400):
            raise LiveDebugError("Refusing unsafe diagnostic output file")
        with path.open("rb") as stream:
            first = stream.readline(MAX_FRAME_BYTES + 1)
        if first:
            try:
                _decode_diagnostic_frame(first)
            except LiveDebugError as exc:
                raise LiveDebugError("Existing output is not a live-debug JSONL log") from exc

    def write(self, record):
        raw = json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(raw) > MAX_FRAME_BYTES:
            raise LiveDebugError("Output record exceeds its bound")
        self._check(self.path)
        if self.path.exists() and self.path.stat().st_size + len(raw) > self.max_bytes:
            for index in range(self.backups, 0, -1):
                destination = self.path.with_name(self.path.name + f".{index}")
                source = self.path if index == 1 else self.path.with_name(self.path.name + f".{index - 1}")
                self._check(destination)
                self._check(source)
                if source.exists():
                    os.replace(source, destination)
            if self.backups == 0:
                self.path.unlink()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            held = os.fstat(stream.fileno())
            named = self.path.lstat()
            if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                    or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
                raise LiveDebugError("Output identity changed")
            stream.write(raw)


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

    def emit(record):
        print(json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False), flush=True)
        if writer is not None:
            writer.write(record)

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
        return 0
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:
        return 0
    except (LiveDebugError, OSError, ValueError) as exc:
        # A failed caller-owned output must not recursively fail while trying
        # to persist its own error. Standard output still carries the failure.
        writer = None
        emit(dict(protocol=PROTOCOL, kind="client_error", advisory_only=True,
                  reason=sanitize_text(str(exc), 512), ts=time.time(), pid=arguments.pid))
        return 2
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
