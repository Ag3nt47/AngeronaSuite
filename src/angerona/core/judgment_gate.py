"""Strict isolated launcher and verifier for inert Judgment canaries."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core import report_attest
from angerona.core.win import popen_hidden


RECEIPT_SCHEMA = "angerona.judgment.receipt.v2"
TEST_IDENTITY = "angerona.inert-marker-and-durable-recorder.v2"
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_MAX_OUTPUT = 64 * 1024


class JudgmentVerificationError(RuntimeError):
    """The isolated verifier did not return authentic, complete evidence."""


@dataclass(frozen=True)
class JudgmentResult:
    technique_id: str
    outcome: str
    receipt: dict[str, Any]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JudgmentVerificationError(f"duplicate receipt field: {key}")
        result[key] = value
    return result


def _stable_sha256(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        before = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise JudgmentVerificationError("verifier object is not a regular file")
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise JudgmentVerificationError("verifier object changed before hashing")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 128 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise JudgmentVerificationError("verifier object changed during hashing")
        if identity != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ):
            raise JudgmentVerificationError("verifier path changed during hashing")
        return digest.hexdigest()
    except JudgmentVerificationError:
        raise
    except OSError as exc:
        raise JudgmentVerificationError("verifier object could not be hashed") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def parse_judgment_receipt(
    raw: str,
    *,
    returncode: int,
    nonce: str,
    technique_id: str,
    verifier_sha256: str,
    launched_at: float,
    received_at: float | None = None,
) -> JudgmentResult:
    """Validate exact schema, freshness, source digest and nested event HMAC."""
    if returncode != 0:
        raise JudgmentVerificationError(f"verifier exited with status {returncode}")
    encoded = raw.encode("utf-8", "replace")
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(encoded) > _MAX_OUTPUT or len(lines) != 1:
        raise JudgmentVerificationError("verifier output is not one bounded receipt")
    try:
        document = json.loads(lines[0], object_pairs_hook=_strict_object)
    except JudgmentVerificationError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise JudgmentVerificationError("verifier output is not strict JSON") from exc
    required = {
        "schema",
        "nonce",
        "technique_id",
        "outcome",
        "test_identity",
        "verifier_sha256",
        "marker_name",
        "marker_sha256",
        "started_at",
        "completed_at",
        "events_examined",
        "event",
        report_attest.SIG_FIELD,
    }
    if not isinstance(document, dict) or set(document) != required:
        raise JudgmentVerificationError("verifier receipt schema is invalid")
    completed_now = time.time() if received_at is None else float(received_at)
    started = document["started_at"]
    completed = document["completed_at"]
    count = document["events_examined"]
    if (
        document["schema"] != RECEIPT_SCHEMA
        or document["nonce"] != nonce
        or document["technique_id"] != technique_id
        or document["outcome"] not in {"BLOCKED", "SUCCESS"}
        or document["test_identity"] != TEST_IDENTITY
        or not isinstance(document["verifier_sha256"], str)
        or not hmac.compare_digest(document["verifier_sha256"], verifier_sha256)
        or not isinstance(document["marker_name"], str)
        or nonce[:12] not in document["marker_name"]
        or not isinstance(document["marker_sha256"], str)
        or not _HEX64.fullmatch(document["marker_sha256"])
        or isinstance(started, bool)
        or not isinstance(started, (int, float))
        or not math.isfinite(float(started))
        or isinstance(completed, bool)
        or not isinstance(completed, (int, float))
        or not math.isfinite(float(completed))
        or float(started) < float(launched_at) - 3.0
        or float(completed) < float(started)
        or float(completed) > completed_now + 3.0
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
    ):
        raise JudgmentVerificationError("verifier receipt values are invalid")
    if report_attest.verify(document) != "ok":
        raise JudgmentVerificationError("verifier receipt HMAC is invalid")

    evidence = document["event"]
    if document["outcome"] == "SUCCESS":
        if evidence is not None:
            raise JudgmentVerificationError("successful bypass receipt contains ambiguity")
    else:
        if not isinstance(evidence, dict) or set(evidence) != {
            "module",
            "message",
            "severity",
            "ts",
            "details",
            "hmac_sig",
        }:
            raise JudgmentVerificationError("blocked receipt lacks exact detector evidence")
        if (
            not isinstance(evidence["details"], dict)
            or not isinstance(evidence["hmac_sig"], str)
            or not _HEX64.fullmatch(evidence["hmac_sig"])
            or document["marker_name"] not in str(evidence["message"])
        ):
            raise JudgmentVerificationError("blocked receipt detector evidence is invalid")
        try:
            event = Event(
                module=str(evidence["module"]),
                message=str(evidence["message"]),
                severity=Severity(int(evidence["severity"])),
                ts=float(evidence["ts"]),
                details=evidence["details"],
                hmac_sig=evidence["hmac_sig"],
            )
        except (TypeError, ValueError) as exc:
            raise JudgmentVerificationError("blocked receipt event is malformed") from exc
        if not float(started) - 2.0 <= event.ts <= float(completed) + 2.0:
            raise JudgmentVerificationError("detector evidence is outside this run")
        if not BusAuthority.load().verify(event):
            raise JudgmentVerificationError("detector event HMAC is invalid")
    return JudgmentResult(
        technique_id=technique_id,
        outcome=str(document["outcome"]),
        receipt=document,
    )


def _child_environment() -> dict[str, str]:
    allowed = {
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "PROGRAMDATA",
        "PATH",
        "PATHEXT",
        "ANGERONA_DATA",
        "ANGERONA_HOME",
        "ANGERONA_DATA_DRIVE",
        "XDG_STATE_HOME",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _bounded_child(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    process_factory: Callable[..., subprocess.Popen] = popen_hidden,
) -> tuple[int, str, str]:
    process = process_factory(
        command,
        cwd=str(cwd),
        env=_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    buffers: list[bytearray] = [bytearray(), bytearray()]
    overflow = [False, False]

    def drain(index: int, stream) -> None:
        while True:
            block = stream.read(4096)
            if not block:
                return
            remaining = max(0, _MAX_OUTPUT - len(buffers[index]))
            if remaining:
                buffers[index].extend(block[:remaining])
            if len(block) > remaining:
                overflow[index] = True

    threads = [
        threading.Thread(target=drain, args=(0, process.stdout), daemon=True),
        threading.Thread(target=drain, args=(1, process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=5)
        raise JudgmentVerificationError("verifier exceeded its deadline") from exc
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads) or any(overflow):
        raise JudgmentVerificationError("verifier output exceeded its bound")
    return (
        int(returncode),
        buffers[0].decode("utf-8", "replace"),
        buffers[1].decode("utf-8", "replace"),
    )


def run_judgment_verification(
    technique_id: str,
    *,
    settle: float = 40.0,
    process_factory: Callable[..., subprocess.Popen] = popen_hidden,
) -> JudgmentResult:
    """Launch the exact reviewed verifier in isolated Python and verify receipt."""
    if not isinstance(technique_id, str) or not _TECHNIQUE.fullmatch(technique_id):
        raise ValueError("invalid Judgment technique id")
    settle = float(settle)
    if not 4.0 <= settle <= 120.0:
        raise ValueError("Judgment settle interval is outside its safety bound")
    verifier = Path(__file__).resolve().parents[1] / "shark" / "verify.py"
    source_root = Path(__file__).resolve().parents[2]
    repository_root = source_root.parent
    interpreter = Path(sys.executable).resolve(strict=True)
    verifier_digest = _stable_sha256(verifier)
    interpreter_digest = _stable_sha256(interpreter)
    nonce = uuid.uuid4().hex
    bootstrap = (
        "import runpy,sys;"
        "p=sys.argv[1];r=sys.argv[2];a=sys.argv[3:];"
        "sys.path.insert(0,r);sys.argv=[p,*a];"
        "runpy.run_path(p,run_name='__main__')"
    )
    command = [
        str(interpreter),
        "-I",
        "-c",
        bootstrap,
        str(verifier),
        str(source_root),
        technique_id,
        "--verify",
        "--nonce",
        nonce,
        "--settle",
        str(settle),
    ]
    launched = time.time()
    returncode, stdout, stderr = _bounded_child(
        command,
        cwd=repository_root,
        timeout=settle + 30.0,
        process_factory=process_factory,
    )
    if stderr.strip():
        raise JudgmentVerificationError("verifier produced unexpected stderr")
    if not hmac.compare_digest(_stable_sha256(verifier), verifier_digest):
        raise JudgmentVerificationError("verifier source changed across execution")
    if not hmac.compare_digest(_stable_sha256(interpreter), interpreter_digest):
        raise JudgmentVerificationError("Python interpreter changed across execution")
    return parse_judgment_receipt(
        stdout,
        returncode=returncode,
        nonce=nonce,
        technique_id=technique_id,
        verifier_sha256=verifier_digest,
        launched_at=launched,
    )


__all__ = [
    "JudgmentResult",
    "JudgmentVerificationError",
    "RECEIPT_SCHEMA",
    "TEST_IDENTITY",
    "parse_judgment_receipt",
    "run_judgment_verification",
]
