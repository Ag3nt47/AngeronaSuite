"""self_healer.py — Self-Debugging Co-Pilot (CODE: HEAL).

A strict "Try → Heal → Stage" loop. Giving an AI autonomous write-access to live
EDR code is unacceptable, so this module NEVER overwrites a running file. It
diagnoses crashes and *stages* a proposed patch for a human to review and apply.

Three phases
------------
1. The Catch (Try)
   ``BaseModule._wrapped_run`` already writes a JSON crash bundle to
   ``diagnostics/crash_snapshots/`` when a module quarantines after 3 crashes.
   HEAL tails that directory — so it hooks the existing crash path with zero
   changes to module_base.py. Each bundle carries the module name, the exact
   exception, and the full traceback.

2. The Diagnosis (Heal)
   HEAL resolves the failing source file from the traceback, reads it, and packs
   {traceback, source} into a strictly-constrained Ollama prompt instructing the
   model to return the corrected file as raw Python only.

3. The Judgment Gate (Stage)
   The returned code is *parsed with ast* before anything is written — a patch
   that doesn't even compile is discarded. Valid patches are written to
   ``staged_patches/<MODULE>_fix_v<N>.py`` and a HIGH alert is emitted with the
   staged path. The operator reviews and applies via the GUI "Apply Patch"
   button; HEAL itself has no write access to live modules.

Scope note
----------
Whole-*process* restart (if the Python interpreter dies) is the Watchdog's job,
not this module's — HEAL operates at the module-thread layer. See the
integration guide for wiring the process-level respawn.

Standard library only (json, os, re, ast, time, threading, urllib).
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import json
import math
import os
import re
import stat
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

from angerona.core.atomic_io import replace_with_retry
from angerona.core.module_base import (
    BaseModule,
    Severity,
    verify_crash_snapshot_bundle,
)
from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    local_service_url,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import effective_keep_alive


# ── Paths (mirror module_base._get_snapshot_dir) ──────────────────────────────
def _data_base() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _snapshot_dir() -> Path:
    d = _data_base() / "diagnostics" / "crash_snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _staged_dir() -> Path:
    d = _data_base() / "staged_patches"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── LLM prompt (strict: raw Python only) ─────────────────────────────────────
_HEAL_SYSTEM_PROMPT = (
    "You are an on-call Python developer fixing a crashed module in a security "
    "product. You are given a traceback and the FULL current source of the file "
    "that crashed. Identify the logic or syntax error and return the COMPLETE "
    "corrected file.\n"
    "OUTPUT RULES — follow exactly:\n"
    "  * Output ONLY valid Python source for the whole file.\n"
    "  * No markdown, no code fences, no commentary, no explanation.\n"
    "  * Preserve all imports, class names, and public function signatures.\n"
    "  * Change only what is necessary to fix the traceback."
)

_OLLAMA_HOST    = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_OLLAMA_MODEL   = os.environ.get("ANGERONA_MODEL", "llama3")
_HEAL_TIMEOUT_S = 120.0     # code-gen is slow; HEAL runs in its own daemon thread
_MAX_SOURCE_CHARS = 24000   # guard against pathologically large files in the prompt
_MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_MAX_PATCH_CHARS = 128_000
_MAX_SNAPSHOT_BYTES = 512 * 1024
_MAX_SNAPSHOT_FILES = 512
_MAX_STATE_BYTES = 256 * 1024
_MAX_RETRIES = 3
_MAX_COMPLETED = 1_024
_MAX_DEAD_LETTERS = 128
_RETRY_BASE_SECONDS = 5.0
_RETRY_MAX_SECONDS = 300.0
_STATE_DOMAIN = b"angerona/self-healer-state/v1\x00"
_STATE_RECEIPT_DOMAIN = b"angerona/self-healer-state-receipt/v1\x00"
_MAX_STATE_RECEIPT_BYTES = 4 * 1024
_REPARSE_POINT = 0x400


def _retry_delay(attempts: int) -> float:
    """Return the exact bounded delay admitted for an authenticated attempt."""
    return min(
        _RETRY_MAX_SECONDS,
        _RETRY_BASE_SECONDS * (2 ** max(0, attempts - 1)),
    )


class SelfHealer(BaseModule):
    name = "HEAL"
    CODE = "HEAL"
    description = "Diagnoses crashed modules and stages LLM-proposed patches for operator review."
    category = "Resilience"
    version = "1.13.0"

    POLL_S = 10.0
    _source_selection = threading.local()
    _snapshot_coverage = threading.local()

    def __init__(self) -> None:
        super().__init__()
        self._completed: dict[str, float] = {}
        self._retries: dict[str, int] = {}
        self._retry_meta: dict[str, tuple[float, float]] = {}
        self._retry_monotonic_due: dict[str, float] = {}
        self._dead_letters: dict[str, str] = {}
        self._state_ready = False
        self._state_persist_failed = False
        self._staged = 0

    @staticmethod
    def _state_path() -> Path:
        return _data_base() / "diagnostics" / "self_healer_state.json"

    @staticmethod
    def _state_receipt_path() -> Path:
        """Return the separately committed witness for the latest state bytes."""
        return _data_base() / "diagnostics" / "self_healer_state.receipt.json"

    @staticmethod
    def _trusted_source_roots() -> tuple[Path, ...]:
        """Return the installed Angerona package root accepted for diagnosis."""
        try:
            return (Path(__file__).resolve(strict=True).parents[1],)
        except (OSError, RuntimeError, IndexError):
            return ()

    @staticmethod
    def _install_key() -> bytes | None:
        try:
            encoded = (_data_base() / "bus.key").read_text(encoding="ascii").strip()
            master = bytes.fromhex(encoded)
        except (OSError, UnicodeError, ValueError):
            return None
        if len(master) != 32:
            return None
        return master

    @staticmethod
    def _state_key() -> bytes | None:
        """Derive a purpose-separated state key from the per-install bus key."""
        master = SelfHealer._install_key()
        if master is None:
            return None
        return hmac.new(master, _STATE_DOMAIN, hashlib.sha256).digest()

    @staticmethod
    def _state_signature(body: dict, key: bytes) -> str:
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(key, _STATE_DOMAIN + encoded, hashlib.sha256).hexdigest()

    @staticmethod
    def _receipt_signature(body: dict, key: bytes) -> str:
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(
            key, _STATE_RECEIPT_DOMAIN + encoded, hashlib.sha256
        ).hexdigest()

    @classmethod
    def _decode_state_receipt(
        cls, raw: bytes, key: bytes
    ) -> tuple[int, str]:
        """Return an authenticated ``(generation, state digest)`` witness."""
        if not 0 < len(raw) <= _MAX_STATE_RECEIPT_BYTES:
            raise ValueError("state receipt size invalid")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
            "schema", "generation", "state_sha256", "signature",
        }:
            raise ValueError("state receipt schema invalid")
        signature = value.pop("signature")
        if (
            type(value.get("schema")) is not int
            or value.get("schema") != 1
            or type(value.get("generation")) is not int
            or not 1 <= value["generation"] <= (2**63 - 1)
            or not isinstance(value.get("state_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["state_sha256"]) is None
            or not isinstance(signature, str)
            or not hmac.compare_digest(
                signature, cls._receipt_signature(value, key)
            )
        ):
            raise ValueError("state receipt authentication failed")
        return int(value["generation"]), str(value["state_sha256"])

    @classmethod
    def _encode_state_receipt(
        cls, *, generation: int, state_bytes: bytes, key: bytes
    ) -> bytes:
        body = {
            "schema": 1,
            "generation": generation,
            "state_sha256": hashlib.sha256(state_bytes).hexdigest(),
        }
        value = dict(body)
        value["signature"] = cls._receipt_signature(body, key)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > _MAX_STATE_RECEIPT_BYTES:
            raise ValueError("state receipt exceeds its bound")
        return encoded

    def _load_state(self) -> bool:
        """Load authenticated completion/retry state, refusing forged state."""
        key = self._state_key()
        if key is None:
            self.set_health(25, "self-healer custody key unavailable")
            return False
        path = self._state_path()
        if not path.exists():
            self._state_ready = self._persist_state()
            if not self._state_ready:
                self.set_health(25, "self-healer durable state initialization failed")
            return self._state_ready
        try:
            raw = path.read_bytes()
            if not 0 < len(raw) <= _MAX_STATE_BYTES:
                raise ValueError("state size invalid")
            receipt_raw = self._state_receipt_path().read_bytes()
            _generation, witnessed_digest = self._decode_state_receipt(
                receipt_raw, key
            )
            if not hmac.compare_digest(
                witnessed_digest, hashlib.sha256(raw).hexdigest()
            ):
                # The main state and its separately replaced receipt form a
                # fail-closed pair. Replaying only an older, still-authentic
                # state therefore cannot erase a pending retry after restart.
                raise ValueError("state receipt does not match current state")
            document = json.loads(raw.decode("utf-8"))
            if not isinstance(document, dict) or set(document) != {
                "schema", "completed", "retries", "retry_meta",
                "dead_letters", "signature",
            }:
                raise ValueError("state schema invalid")
            signature = document.pop("signature")
            if (
                type(document.get("schema")) is not int
                or document.get("schema") != 2
                or not isinstance(signature, str)
                or not hmac.compare_digest(signature, self._state_signature(document, key))
            ):
                raise ValueError("state authentication failed")
            completed = document.get("completed")
            retries = document.get("retries")
            retry_meta = document.get("retry_meta")
            dead = document.get("dead_letters")
            if (
                not isinstance(completed, list)
                or not isinstance(retries, dict)
                or not isinstance(retry_meta, dict)
                or not isinstance(dead, dict)
                or len(completed) > _MAX_COMPLETED
                or len(retries) > _MAX_SNAPSHOT_FILES
                or len(retry_meta) > _MAX_SNAPSHOT_FILES
                or len(dead) > _MAX_DEAD_LETTERS
            ):
                raise ValueError("state fields invalid")
            loaded_completed: dict[str, float] = {}
            for row in completed:
                if (
                    not isinstance(row, list)
                    or len(row) != 2
                    or not isinstance(row[0], str)
                    or re.fullmatch(r"[0-9a-f]{64}", row[0]) is None
                    or row[0] in loaded_completed
                    or not isinstance(row[1], (int, float))
                    or isinstance(row[1], bool)
                    or not math.isfinite(float(row[1]))
                    or float(row[1]) < 0
                ):
                    raise ValueError("completed state is invalid")
                loaded_completed[row[0]] = float(row[1])

            loaded_retries: dict[str, int] = {}
            for item_id, attempts in retries.items():
                if (
                    not isinstance(item_id, str)
                    or re.fullmatch(r"[0-9a-f]{64}", item_id) is None
                    or type(attempts) is not int
                    or not 1 <= attempts < _MAX_RETRIES
                ):
                    # ``bool`` is an ``int`` subclass. Exact type checking is a
                    # compatibility/security requirement for authenticated state.
                    raise ValueError("retry counter is invalid")
                loaded_retries[item_id] = attempts

            if set(retry_meta) != set(loaded_retries):
                raise ValueError("retry schedule is incomplete")
            wall_now = time.time()
            monotonic_now = time.monotonic()
            loaded_meta: dict[str, tuple[float, float]] = {}
            loaded_monotonic: dict[str, float] = {}
            for item_id, value in retry_meta.items():
                if (
                    not isinstance(value, list)
                    or len(value) != 2
                    or any(
                        not isinstance(stamp, (int, float))
                        or isinstance(stamp, bool)
                        or not math.isfinite(float(stamp))
                        or float(stamp) < 0
                        for stamp in value
                    )
                    or float(value[1]) < float(value[0])
                ):
                    raise ValueError("retry schedule is invalid")
                # A wall-clock rollback must not turn a five-second delay into
                # an arbitrarily long wait. Convert the authenticated remaining
                # delay into this process's monotonic domain and clamp it.
                remaining = min(
                    _retry_delay(loaded_retries[item_id]),
                    max(0.0, float(value[1]) - wall_now),
                )
                first_seen = min(float(value[0]), wall_now)
                loaded_meta[item_id] = (first_seen, wall_now + remaining)
                loaded_monotonic[item_id] = monotonic_now + remaining

            loaded_dead: dict[str, str] = {}
            for item_id, reason in dead.items():
                if (
                    not isinstance(item_id, str)
                    or re.fullmatch(r"[0-9a-f]{64}", item_id) is None
                    or not isinstance(reason, str)
                    or len(reason) > 512
                ):
                    raise ValueError("dead-letter state is invalid")
                loaded_dead[item_id] = reason

            self._completed = loaded_completed
            self._retries = loaded_retries
            self._retry_meta = loaded_meta
            self._retry_monotonic_due = loaded_monotonic
            self._dead_letters = loaded_dead
        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            RecursionError,
            json.JSONDecodeError,
        ):
            self.set_health(20, "self-healer durable state is invalid or unauthenticated")
            return False
        self._state_ready = True
        self._state_persist_failed = False
        return True

    def _persist_state(self) -> bool:
        key = self._state_key()
        if key is None:
            self._state_persist_failed = True
            return False
        completed = sorted(self._completed.items(), key=lambda item: item[1])[-_MAX_COMPLETED:]
        retries = dict(list(self._retries.items())[-_MAX_SNAPSHOT_FILES:])
        retry_meta = {
            item_id: list(self._retry_meta[item_id])
            for item_id in retries
            if item_id in self._retry_meta
        }
        if set(retry_meta) != set(retries):
            self._state_persist_failed = True
            return False
        dead = dict(list(self._dead_letters.items())[-_MAX_DEAD_LETTERS:])
        if (
            any(
                not isinstance(item_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", item_id) is None
                or not isinstance(stamp, (int, float))
                or isinstance(stamp, bool)
                or not math.isfinite(float(stamp))
                or float(stamp) < 0
                for item_id, stamp in completed
            )
            or any(
                not isinstance(item_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", item_id) is None
                or type(attempts) is not int
                or not 1 <= attempts < _MAX_RETRIES
                for item_id, attempts in retries.items()
            )
            or any(
                not isinstance(value, list)
                or len(value) != 2
                or any(
                    not isinstance(stamp, (int, float))
                    or isinstance(stamp, bool)
                    or not math.isfinite(float(stamp))
                    or float(stamp) < 0
                    for stamp in value
                )
                or float(value[1]) < float(value[0])
                for value in retry_meta.values()
            )
            or any(
                not isinstance(item_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", item_id) is None
                or not isinstance(reason, str)
                or len(reason) > 512
                for item_id, reason in dead.items()
            )
        ):
            self._state_persist_failed = True
            return False
        body = {
            "schema": 2,
            "completed": [[item_id, stamp] for item_id, stamp in completed],
            "retries": retries,
            "retry_meta": retry_meta,
            "dead_letters": dead,
        }
        document = dict(body)
        document["signature"] = self._state_signature(body, key)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_STATE_BYTES:
            self._state_persist_failed = True
            return False
        path = self._state_path()
        receipt_path = self._state_receipt_path()
        generation = 1
        if receipt_path.exists():
            try:
                prior_generation, _prior_digest = self._decode_state_receipt(
                    receipt_path.read_bytes(), key
                )
                generation = prior_generation + 1
            except (
                OSError,
                UnicodeError,
                ValueError,
                TypeError,
                RecursionError,
                json.JSONDecodeError,
            ):
                self._state_persist_failed = True
                return False
        if generation > 2**63 - 1:
            self._state_persist_failed = True
            return False
        try:
            receipt_encoded = self._encode_state_receipt(
                generation=generation, state_bytes=encoded, key=key
            )
        except (ValueError, TypeError):
            self._state_persist_failed = True
            return False
        token = uuid.uuid4().hex
        temporary = path.with_name(f".{path.name}.{token}.tmp")
        receipt_temporary = receipt_path.with_name(
            f".{receipt_path.name}.{token}.tmp"
        )
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            with receipt_temporary.open("xb") as handle:
                handle.write(receipt_encoded)
                handle.flush()
                os.fsync(handle.fileno())
            # There is no portable two-file atomic replace. Commit state first
            # and its witness second; a crash between them causes a digest
            # mismatch on restart and therefore fails closed instead of losing
            # retry custody.
            replace_with_retry(temporary, path)
            replace_with_retry(receipt_temporary, receipt_path)
            self._state_persist_failed = False
            return True
        except OSError:
            self._state_persist_failed = True
            return False
        finally:
            for pending in (temporary, receipt_temporary):
                try:
                    pending.unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _snapshot_candidates(snap_dir: Path) -> tuple[list[Path], bool]:
        """Return bounded candidates and the legacy incomplete-coverage Boolean."""
        candidates: list[Path] = []
        status = "complete"
        try:
            with os.scandir(snap_dir) as rows:
                for row in rows:
                    if not row.name.endswith(".json"):
                        continue
                    if len(candidates) >= _MAX_SNAPSHOT_FILES:
                        status = "overflow"
                        break
                    candidates.append(Path(row.path))
        except OSError:
            SelfHealer._snapshot_coverage.status = "unreadable"
            return [], True
        candidates.sort(key=lambda path: path.name)
        SelfHealer._snapshot_coverage.status = status
        return candidates, status != "complete"

    @staticmethod
    def _read_snapshot(path: Path) -> tuple[str, bytes] | None:
        """Read one exact bounded regular file without following a link."""
        descriptor: int | None = None
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            attributes = int(getattr(before, "st_file_attributes", 0) or 0)
            if (
                not stat.S_ISREG(before.st_mode)
                or attributes & _REPARSE_POINT
                or before.st_size <= 0
                or before.st_size > _MAX_SNAPSHOT_BYTES
            ):
                return None
            chunks: list[bytes] = []
            remaining = _MAX_SNAPSHOT_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(body) != before.st_size
                or len(body) > _MAX_SNAPSHOT_BYTES
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                return None
            return hashlib.sha256(body).hexdigest(), body
        except (OSError, OverflowError):
            return None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    # ── Phase 1: catch (tail the crash-snapshot dir) ─────────────────────────
    def run(self) -> None:
        snap_dir = _snapshot_dir()
        while not self.stopping:
            try:
                self.process_snapshots_once(snap_dir, respect_backoff=True)
            except Exception as exc:
                self.set_health(70, f"poll error: {exc}")
            self.sleep(self.POLL_S)

    def process_snapshots_once(
        self,
        snap_dir: Path | None = None,
        *,
        respect_backoff: bool = False,
    ) -> int:
        """Process one bounded pass while retaining durable retry custody."""
        directory = Path(snap_dir) if snap_dir is not None else _snapshot_dir()
        if not self._state_ready and not self._load_state():
            return 0
        candidates, coverage_marker = self._snapshot_candidates(directory)
        if type(coverage_marker) is bool:
            if not coverage_marker:
                coverage = "complete"
            else:
                observed = getattr(self._snapshot_coverage, "status", "incomplete")
                coverage = (
                    observed
                    if observed in {"overflow", "unreadable"}
                    else "incomplete"
                )
        else:
            # Retain compatibility with focused tests/adapters that return the
            # richer status string directly.
            coverage = str(coverage_marker)
        if coverage != "complete":
            reason = (
                "exceeds bounded coverage"
                if coverage == "overflow"
                else "is incomplete, unavailable, or unreadable"
            )
            self.set_health(35, f"crash snapshot directory {reason}")
            self.emit(
                f"HEAL snapshot coverage is incomplete because its directory {reason}.",
                Severity.HIGH,
                disposition="health",
                coverage_status=coverage,
                response_authorized=False,
            )
        processed = 0
        unreadable = 0
        wall_now = time.time()
        monotonic_now = time.monotonic()
        for snap in candidates:
            item = self._read_snapshot(snap)
            if item is None:
                unreadable += 1
                continue
            snapshot_id, body = item
            if snapshot_id in self._completed or snapshot_id in self._dead_letters:
                continue
            retry_meta = self._retry_meta.get(snapshot_id)
            monotonic_due = self._retry_monotonic_due.get(snapshot_id)
            if retry_meta is not None and monotonic_due is None:
                remaining = min(
                    _retry_delay(self._retries.get(snapshot_id, 1)),
                    max(0.0, retry_meta[1] - wall_now),
                )
                monotonic_due = monotonic_now + remaining
                self._retry_monotonic_due[snapshot_id] = monotonic_due
            if (
                respect_backoff
                and monotonic_due is not None
                and monotonic_now < monotonic_due
            ):
                continue
            success, reason = self._handle_snapshot(snap, snapshot_id, body)
            processed += 1
            if success:
                self._completed[snapshot_id] = time.time()
                self._retries.pop(snapshot_id, None)
                self._retry_meta.pop(snapshot_id, None)
                self._retry_monotonic_due.pop(snapshot_id, None)
            else:
                attempts = self._retries.get(snapshot_id, 0) + 1
                if attempts >= _MAX_RETRIES:
                    self._retries.pop(snapshot_id, None)
                    self._retry_meta.pop(snapshot_id, None)
                    self._retry_monotonic_due.pop(snapshot_id, None)
                    self._dead_letters[snapshot_id] = reason[:512]
                    self.emit(
                        f"HEAL dead-lettered crash snapshot {snap.name} after "
                        f"{attempts} failed attempts: {reason[:240]}",
                        Severity.HIGH,
                        snapshot_id=snapshot_id,
                        disposition="health",
                        response_authorized=False,
                    )
                else:
                    self._retries[snapshot_id] = attempts
                    first_seen = (
                        min(retry_meta[0], time.time())
                        if retry_meta is not None else time.time()
                    )
                    delay = _retry_delay(attempts)
                    self._retry_meta[snapshot_id] = (
                        first_seen,
                        time.time() + delay,
                    )
                    self._retry_monotonic_due[snapshot_id] = (
                        time.monotonic() + delay
                    )
            if not self._persist_state():
                self.set_health(25, "crash snapshot state persistence failed")
                break
        # Keep all in-memory collections bounded too; durable truncation alone
        # would otherwise permit a long-running process to grow without limit.
        self._completed = dict(
            sorted(self._completed.items(), key=lambda item: item[1])[-_MAX_COMPLETED:]
        )
        self._dead_letters = dict(
            list(self._dead_letters.items())[-_MAX_DEAD_LETTERS:]
        )
        if self._state_persist_failed:
            self.set_health(25, "crash snapshot state persistence failed")
        elif unreadable:
            self.set_health(
                40,
                f"{unreadable} crash snapshot(s) could not be read safely; retry pending",
            )
        elif self._dead_letters:
            self.set_health(
                55, f"{len(self._dead_letters)} crash snapshot(s) require manual review"
            )
        elif self._retries:
            oldest = min(stamp[0] for stamp in self._retry_meta.values())
            self.set_health(
                65,
                f"{len(self._retries)} crash snapshot retry/retries pending; "
                f"oldest {max(0.0, time.time() - oldest):.1f}s",
            )
        elif coverage == "complete":
            self.set_health(100, f"{self._staged} patches staged")
        return processed

    def _handle_snapshot(
        self, snap: Path, snapshot_id: str, body: bytes,
    ) -> tuple[bool, str]:
        try:
            bundle = json.loads(body.decode("utf-8"))
            if not isinstance(bundle, dict):
                raise ValueError("snapshot must be an object")
        except Exception as exc:
            self.emit(f"HEAL could not read crash snapshot {snap.name}: {exc}",
                      Severity.LOW)
            return False, f"snapshot parse failed: {exc}"
        if not verify_crash_snapshot_bundle(bundle, key=self._install_key()):
            self.emit(
                f"HEAL refused unauthenticated crash snapshot {snap.name}.",
                Severity.HIGH,
                snapshot_id=snapshot_id,
                disposition="health",
                response_authorized=False,
            )
            return False, "crash snapshot authentication failed"

        module_name = str(bundle.get("module", "unknown"))[:128]
        tb = bundle.get("traceback", "")
        if not isinstance(tb, str) or not tb or len(tb) > 256_000:
            return False, "snapshot traceback is missing or exceeds its bound"

        src_path = self._source_from_traceback(tb)
        if not src_path:
            self.emit(f"HEAL: crash in '{module_name}' but couldn't resolve a "
                      "project source file from the traceback — skipping.",
                      Severity.LOW, module=module_name)
            return False, "traceback has no trusted Angerona source frame"

        # ── Phase 2: diagnose ───────────────────────────────────────────────
        try:
            source = self._read_trusted_source(Path(src_path))
        except (OSError, UnicodeError, ValueError) as exc:
            self.emit(f"HEAL: source '{src_path}' unreadable ({exc}) — skipping.",
                      Severity.LOW)
            return False, f"trusted source unreadable: {exc}"

        patched = self._request_fix(module_name, tb, source[:_MAX_SOURCE_CHARS])
        if not patched:
            self.emit(f"HEAL: no usable patch generated for '{module_name}'.",
                      Severity.MEDIUM, module=module_name)
            return False, "local model returned no usable patch"
        if len(patched) > _MAX_PATCH_CHARS:
            return False, "proposed patch exceeds its safety bound"

        # ── Phase 3: judgment gate (must parse) + stage ─────────────────────
        try:
            ast.parse(patched)
        except SyntaxError as exc:
            self.emit(f"HEAL: proposed patch for '{module_name}' rejected — it "
                      f"does not parse ({exc}). Not staged.",
                      Severity.MEDIUM, module=module_name)
            return False, f"proposed patch does not parse: {exc}"

        staged_path = self._stage(src_path, patched, snapshot_id=snapshot_id)
        if staged_path:
            self._staged += 1
            self.emit(
                f"Bug detected in module {module_name}. Proposed patch staged for "
                f"review: {staged_path}",
                Severity.HIGH,
                module=module_name,
                source_file=src_path,
                staged_patch=str(staged_path),
            )
            return True, "staged for operator review"
        return False, "staged patch could not be written durably"

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _source_identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_mode),
            int(info.st_size),
            int(info.st_mtime_ns),
            int(getattr(info, "st_nlink", 1)),
            int(getattr(info, "st_file_attributes", 0) or 0),
        )

    @classmethod
    def _source_from_traceback(cls, tb: str) -> Optional[str]:
        """Pick the deepest project .py frame from a traceback.

        Skips stdlib / site-packages so we heal our own code, not a library.
        """
        frames = re.findall(r'File "([^"]+\.py)", line \d+', tb)
        if not frames:
            return None
        roots: list[Path] = []
        for root in cls._trusted_source_roots():
            try:
                roots.append(Path(root).resolve(strict=True))
            except (OSError, RuntimeError):
                continue
        for raw in reversed(frames):
            try:
                chosen = Path(raw).resolve(strict=True)
                info = chosen.lstat()
            except (OSError, RuntimeError, ValueError):
                continue
            attributes = int(getattr(info, "st_file_attributes", 0) or 0)
            if (
                chosen.suffix.casefold() != ".py"
                or chosen.is_symlink()
                or attributes & _REPARSE_POINT
                or not stat.S_ISREG(info.st_mode)
                or not any(chosen == root or root in chosen.parents for root in roots)
                or int(getattr(info, "st_nlink", 1)) != 1
            ):
                continue
            cls._source_selection.path = str(chosen)
            cls._source_selection.identity = cls._source_identity(info)
            return str(chosen)
        return None

    @classmethod
    def _read_trusted_source(cls, path: Path) -> str:
        descriptor: int | None = None
        chosen: Path | None = None
        requested = str(Path(path))
        try:
            chosen = Path(path).resolve(strict=True)
            expected_path = getattr(cls._source_selection, "path", None)
            expected_identity = getattr(cls._source_selection, "identity", None)
            if (
                expected_path is not None
                and requested == expected_path
                and str(chosen) != expected_path
            ):
                raise ValueError("trusted source pathname changed after validation")
            roots: list[Path] = []
            for root in cls._trusted_source_roots():
                try:
                    roots.append(Path(root).resolve(strict=True))
                except (OSError, RuntimeError):
                    continue
            if (
                chosen.suffix.casefold() != ".py"
                or not roots
                or not any(chosen == root or root in chosen.parents for root in roots)
            ):
                raise ValueError("source is outside the trusted source root")
            path_info = chosen.lstat()
            path_identity = cls._source_identity(path_info)
            attributes = int(getattr(path_info, "st_file_attributes", 0) or 0)
            if (
                not stat.S_ISREG(path_info.st_mode)
                or chosen.is_symlink()
                or attributes & _REPARSE_POINT
                or int(getattr(path_info, "st_nlink", 1)) != 1
            ):
                raise ValueError("trusted source identity is unsafe")
            if (
                expected_path == str(chosen)
                and expected_identity is not None
                and expected_identity != path_identity
            ):
                raise ValueError("trusted source identity changed after validation")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(chosen, flags)
            before = os.fstat(descriptor)
            attributes = int(getattr(before, "st_file_attributes", 0) or 0)
            if (
                not stat.S_ISREG(before.st_mode)
                or attributes & _REPARSE_POINT
                or cls._source_identity(before) != path_identity
                or int(getattr(before, "st_nlink", 1)) != 1
                or before.st_size < 0
                or before.st_size > _MAX_SOURCE_FILE_BYTES
            ):
                raise ValueError("source is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = _MAX_SOURCE_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            final_path = chosen.lstat()
            if (
                len(raw) != before.st_size
                or len(raw) > _MAX_SOURCE_FILE_BYTES
                or cls._source_identity(before) != cls._source_identity(after)
                or cls._source_identity(after) != cls._source_identity(final_path)
            ):
                raise ValueError("source identity changed while reading")
            return raw.decode("utf-8", "strict")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            selected_path = getattr(cls._source_selection, "path", None)
            if selected_path in {requested, str(chosen) if chosen is not None else None}:
                cls._source_selection.path = None
                cls._source_selection.identity = None

    def _request_fix(self, module_name: str, tb: str, source: str) -> Optional[str]:
        user = json.dumps({
            "module": module_name,
            "traceback": tb,
            "source_code": source,
        }, default=str)
        payload = json.dumps({
            "model": _OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _HEAL_SYSTEM_PROMPT},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "keep_alive": effective_keep_alive("30m"),
        }).encode("utf-8")
        req = urllib.request.Request(
            local_service_url(_OLLAMA_HOST, "/api/chat"), data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with safe_urlopen(
                req, policy=OLLAMA_SERVICE_POLICY, timeout=_HEAL_TIMEOUT_S,
            ) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            content = (data.get("message", {}) or {}).get("content", "")
            return self._strip_fences(content)
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(50, f"Ollama unreachable for heal: {exc}")
            return None

    @staticmethod
    def _strip_fences(text: str) -> str:
        """Remove ```python … ``` fences the model may add despite instructions."""
        text = text.strip()
        m = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
        if m:
            return m.group(1).strip()
        return text

    def _stage(
        self, src_path: str, patched: str, *, snapshot_id: str,
    ) -> Optional[Path]:
        stem = Path(src_path).stem
        out = _staged_dir() / f"{stem}_fix_{snapshot_id[:16]}.py"
        try:
            header = (
                f"# HEAL staged patch for {src_path}\n"
                f"# Crash snapshot {snapshot_id} — REVIEW BEFORE APPLYING\n"
            )
            encoded = (header + patched).encode("utf-8")
            try:
                with out.open("xb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError:
                if out.is_symlink() or out.read_bytes() != encoded:
                    raise ValueError("staged output identity collision")
            return out
        except (OSError, ValueError) as exc:
            self.emit(f"HEAL: failed to write staged patch: {exc}", Severity.MEDIUM)
            return None

    def self_test(self) -> tuple[bool, str]:
        try:
            _ = _snapshot_dir(); _ = _staged_dir()
            return True, f"watching crash snapshots; {self._staged} staged this session"
        except Exception as exc:
            return False, f"path setup failed: {exc}"


def register() -> BaseModule:
    return SelfHealer()
