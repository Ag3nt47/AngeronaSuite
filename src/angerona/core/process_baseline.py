"""Conservative, operator-approved learning for normal process activity.

The learner observes authenticated Telemetry Scanner process-start events and
builds local suggestions. Observation can never suppress an alert, change
posture, or authorize response. A candidate becomes review-eligible only after
the same executable digest is seen repeatedly across separate UTC days, from a
protected installation root, with a valid Windows Authenticode signature.

Candidate state is HMAC authenticated with the EventBus authority. Tampered
state freezes learning and approval until the operator explicitly resets it.
Only executable identity metadata is retained: no command lines, usernames,
parent processes, network destinations, or file contents.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import queue
import stat
import subprocess
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Callable

from angerona.core.atomic_io import replace_with_retry
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.process_allowlist import add as add_trusted_process
from angerona.core.process_allowlist import executable_sha256

STATE_VERSION = 1
MIN_OBSERVATIONS = 3
MIN_DISTINCT_DAYS = 2
DISMISS_DAYS = 30
MAX_CANDIDATES = 1024
MAX_DISMISSED = 1024
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_QUEUE = 512
MAX_DAYS_RETAINED = 16

_STATE_FIELDS = frozenset(
    {"version", "updated_at", "candidates", "dismissed", "metrics", "signature"}
)
_CANDIDATE_FIELDS = frozenset(
    {
        "id",
        "name",
        "path",
        "sha256",
        "size",
        "mtime_ns",
        "signature_status",
        "publisher",
        "root_class",
        "trusted_root",
        "reason",
        "first_seen",
        "last_seen",
        "observations",
        "days",
    }
)
_DISMISSED_FIELDS = frozenset({"id", "until"})
_METRIC_FIELDS = frozenset(
    {
        "accepted",
        "rejected",
        "dropped",
        "dismissed",
        "write_errors",
    }
)


class BaselineIntegrityError(ValueError):
    """Raised when learned-candidate state cannot be authenticated."""


def _no_duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BaselineIntegrityError(f"duplicate process-baseline field: {key}")
        result[key] = value
    return result


def _bounded_text(value, field: str, maximum: int, *, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or "\x00" in value
        or (not empty and not value.strip())
    ):
        raise BaselineIntegrityError(f"process-baseline {field} is invalid")
    return value.strip()


def _finite_number(value, field: str, *, minimum: float = 0.0) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < minimum
    ):
        raise BaselineIntegrityError(f"process-baseline {field} is invalid")
    return float(value)


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    return path.is_symlink() or bool(
        attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _is_absolute_local_path(value: str) -> bool:
    if not value or len(value) > 1024 or "\x00" in value:
        return False
    if value.startswith(("\\\\", "//")):
        return False
    if value.casefold().startswith(("\\\\?\\", "\\\\.\\", r"\device\\")):
        return False
    if os.name == "nt":
        pure = PureWindowsPath(value)
        return pure.is_absolute() and bool(pure.drive)
    return Path(value).is_absolute()


def _within(candidate: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((str(candidate), str(root)))
        return os.path.normcase(common) == os.path.normcase(str(root))
    except (OSError, ValueError):
        return False


def _default_trusted_roots() -> tuple[tuple[str, Path], ...]:
    if os.name != "nt":
        return ()
    roots: list[tuple[str, Path]] = []
    for label, value in (
        ("windows", os.environ.get("SystemRoot", r"C:\Windows")),
        ("program_files", os.environ.get("ProgramFiles", r"C:\Program Files")),
        (
            "program_files_x86",
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ),
    ):
        try:
            resolved = Path(value).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not any(existing == resolved for _, existing in roots):
            roots.append((label, resolved))
    return tuple(roots)


def _authenticode(path: Path) -> tuple[str, str]:
    if os.name != "nt":
        return "Unsupported", ""
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    if not powershell.is_file():
        return "Unavailable", ""
    env = os.environ.copy()
    env["ANGERONA_BASELINE_EXECUTABLE"] = str(path)
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath "
        "$env:ANGERONA_BASELINE_EXECUTABLE;"
        "$p=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
        "[pscustomobject]@{status=[string]$s.Status;publisher=$p}"
        "|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            return "Unavailable", ""
        payload = json.loads(result.stdout)
        status = _bounded_text(
            payload.get("status", ""), "signature status", 64, empty=True
        )
        publisher = _bounded_text(
            payload.get("publisher", ""), "publisher", 512, empty=True
        )
        return status or "Unavailable", publisher
    except (
        BaselineIntegrityError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
        AttributeError,
    ):
        return "Unavailable", ""


@dataclass(frozen=True)
class ExecutableAssessment:
    name: str
    path: str
    sha256: str
    size: int
    mtime_ns: int
    signature_status: str
    publisher: str
    root_class: str
    trusted_root: bool
    reason: str


def assess_executable(
    value: str,
    *,
    trusted_roots: tuple[tuple[str, Path], ...] | None = None,
    signature_probe: Callable[[Path], tuple[str, str]] | None = None,
) -> ExecutableAssessment:
    """Verify one executable for baseline candidacy without executing it."""
    if not _is_absolute_local_path(value):
        raise ValueError("baseline requires an absolute local executable path")
    candidate = Path(value)
    try:
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise ValueError("baseline executable is unavailable") from exc
    if (
        not resolved.is_file()
        or _is_reparse(resolved)
        or not 0 < info.st_size <= 1024 * 1024 * 1024
    ):
        raise ValueError("baseline executable is not an ordinary bounded file")

    roots = _default_trusted_roots() if trusted_roots is None else trusted_roots
    root_class = ""
    trusted_root = False
    for label, raw_root in roots:
        try:
            root = Path(raw_root).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if _within(resolved, root):
            root_class = str(label)[:64]
            trusted_root = True
            # Refuse a path whose components traverse a link/reparse boundary.
            current = resolved.parent
            while _within(current, root):
                if _is_reparse(current):
                    trusted_root = False
                    root_class = ""
                    break
                if current == root:
                    break
                current = current.parent
            break

    probe = signature_probe or _authenticode
    signature_status, publisher = probe(resolved)
    digest = executable_sha256(resolved)
    if not trusted_root:
        reason = "outside protected Windows or Program Files roots"
    elif signature_status.casefold() != "valid":
        reason = f"Authenticode status is {signature_status or 'unavailable'}"
    else:
        reason = "stable signed executable; operator review still required"
    return ExecutableAssessment(
        name=resolved.name,
        path=str(resolved),
        sha256=digest,
        size=int(info.st_size),
        mtime_ns=int(info.st_mtime_ns),
        signature_status=str(signature_status)[:64],
        publisher=str(publisher)[:512],
        root_class=root_class,
        trusted_root=trusted_root,
        reason=reason,
    )


def _candidate_id(path: str, digest: str) -> str:
    identity = os.path.normcase(os.path.normpath(path)).encode(
        "utf-8", "surrogatepass"
    )
    return hashlib.sha256(identity + b"\0" + digest.encode("ascii")).hexdigest()[:32]


def _state_event(body: dict) -> Event:
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return Event(
        module="Process Baseline State",
        message=digest,
        severity=Severity.INFO,
        ts=0.0,
        details={"domain": "process-baseline-v1"},
    )


def _sign_state(body: dict, authority: BusAuthority) -> str:
    return authority.sign(_state_event(body))


def _validate_candidate(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _CANDIDATE_FIELDS:
        raise BaselineIntegrityError("process-baseline candidate schema is invalid")
    candidate_id = _bounded_text(value["id"], "candidate id", 32)
    if len(candidate_id) != 32 or any(ch not in "0123456789abcdef" for ch in candidate_id):
        raise BaselineIntegrityError("process-baseline candidate id is invalid")
    digest = _bounded_text(value["sha256"], "SHA-256", 64)
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise BaselineIntegrityError("process-baseline SHA-256 is invalid")
    days = value["days"]
    if (
        not isinstance(days, list)
        or not 1 <= len(days) <= MAX_DAYS_RETAINED
        or any(
            not isinstance(day, str)
            or len(day) != 10
            or day[4] != "-"
            or day[7] != "-"
            for day in days
        )
        or days != sorted(set(days))
    ):
        raise BaselineIntegrityError("process-baseline observation days are invalid")
    observations = value["observations"]
    if type(observations) is not int or not 1 <= observations <= 1_000_000_000:
        raise BaselineIntegrityError("process-baseline observation count is invalid")
    size = value["size"]
    mtime_ns = value["mtime_ns"]
    if (
        type(size) is not int
        or not 0 < size <= 1024 * 1024 * 1024
        or type(mtime_ns) is not int
        or mtime_ns < 0
    ):
        raise BaselineIntegrityError("process-baseline file metadata is invalid")
    first = _finite_number(value["first_seen"], "first_seen")
    last = _finite_number(value["last_seen"], "last_seen")
    if last < first:
        raise BaselineIntegrityError("process-baseline timestamps regress")
    trusted_root = value["trusted_root"]
    if type(trusted_root) is not bool:
        raise BaselineIntegrityError("process-baseline trusted_root is invalid")
    return {
        "id": candidate_id,
        "name": _bounded_text(value["name"], "name", 260),
        "path": _bounded_text(value["path"], "path", 1024),
        "sha256": digest,
        "size": size,
        "mtime_ns": mtime_ns,
        "signature_status": _bounded_text(
            value["signature_status"], "signature status", 64, empty=True
        ),
        "publisher": _bounded_text(
            value["publisher"], "publisher", 512, empty=True
        ),
        "root_class": _bounded_text(
            value["root_class"], "root class", 64, empty=True
        ),
        "trusted_root": trusted_root,
        "reason": _bounded_text(value["reason"], "reason", 512),
        "first_seen": first,
        "last_seen": last,
        "observations": observations,
        "days": list(days),
    }


def _validate_state(raw: object, authority: BusAuthority) -> dict:
    if not isinstance(raw, dict) or set(raw) != _STATE_FIELDS:
        raise BaselineIntegrityError("process-baseline state schema is invalid")
    if raw["version"] != STATE_VERSION:
        raise BaselineIntegrityError("process-baseline state version is unsupported")
    candidates = raw["candidates"]
    dismissed = raw["dismissed"]
    metrics = raw["metrics"]
    if not isinstance(candidates, list) or len(candidates) > MAX_CANDIDATES:
        raise BaselineIntegrityError("process-baseline candidate bound is invalid")
    if not isinstance(dismissed, list) or len(dismissed) > MAX_DISMISSED:
        raise BaselineIntegrityError("process-baseline dismissal bound is invalid")
    if not isinstance(metrics, dict) or set(metrics) != _METRIC_FIELDS:
        raise BaselineIntegrityError("process-baseline metrics schema is invalid")
    clean_candidates = [_validate_candidate(item) for item in candidates]
    candidate_ids = [item["id"] for item in clean_candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise BaselineIntegrityError("process-baseline candidate ids are duplicated")
    clean_dismissed = []
    dismissed_ids = set()
    for item in dismissed:
        if not isinstance(item, dict) or set(item) != _DISMISSED_FIELDS:
            raise BaselineIntegrityError("process-baseline dismissal schema is invalid")
        item_id = _bounded_text(item["id"], "dismissal id", 32)
        if (
            len(item_id) != 32
            or any(ch not in "0123456789abcdef" for ch in item_id)
            or item_id in dismissed_ids
        ):
            raise BaselineIntegrityError("process-baseline dismissal id is invalid")
        dismissed_ids.add(item_id)
        clean_dismissed.append(
            {"id": item_id, "until": _finite_number(item["until"], "dismissal until")}
        )
    clean_metrics = {}
    for key in _METRIC_FIELDS:
        value = metrics[key]
        if type(value) is not int or not 0 <= value <= 1_000_000_000:
            raise BaselineIntegrityError(f"process-baseline metric {key} is invalid")
        clean_metrics[key] = value
    body = {
        "version": STATE_VERSION,
        "updated_at": _finite_number(raw["updated_at"], "updated_at"),
        "candidates": clean_candidates,
        "dismissed": clean_dismissed,
        "metrics": clean_metrics,
    }
    signature = _bounded_text(raw["signature"], "signature", 64)
    if len(signature) != 64 or not hmac.compare_digest(
        signature,
        _sign_state(body, authority),
    ):
        raise BaselineIntegrityError(
            "learned process state failed authentication; reset is required"
        )
    return body


class ProcessBaselineLearner:
    """Bounded background learner and explicit approval lifecycle."""

    def __init__(
        self,
        data_dir: str | os.PathLike,
        authority: BusAuthority,
        *,
        enabled: bool = False,
        clock: Callable[[], float] = time.time,
        assessor: Callable[[str], ExecutableAssessment] = assess_executable,
        queue_size: int = MAX_QUEUE,
    ) -> None:
        if not isinstance(authority, BusAuthority):
            raise TypeError("process baseline requires the EventBus authority")
        if not 1 <= int(queue_size) <= MAX_QUEUE:
            raise ValueError("process-baseline queue size is invalid")
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "shared_logs" / "process_baseline.json"
        self.authority = authority
        self._clock = clock
        self._assessor = assessor
        self._enabled = bool(enabled)
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=int(queue_size))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._candidates: dict[str, dict] = {}
        self._dismissed: dict[str, float] = {}
        self._metrics = {key: 0 for key in _METRIC_FIELDS}
        self._integrity_error = ""
        self._assessment_cache: OrderedDict[
            str,
            tuple[tuple[int, int, int], ExecutableAssessment],
        ] = OrderedDict()
        self._load()

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._enabled = bool(enabled)
        if enabled:
            self.start()
        else:
            self.stop(timeout=1.0)

    def start(self) -> bool:
        with self._lock:
            if not self._enabled:
                return False
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            thread = threading.Thread(
                target=self._run,
                name="ProcessBaselineLearner",
                daemon=True,
            )
            self._thread = thread
            thread.start()
            return True

    def stop(self, timeout: float = 2.0) -> bool:
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        self._stop.set()
        thread.join(max(0.0, float(timeout)))
        stopped = not thread.is_alive()
        if stopped:
            with self._lock:
                if self._thread is thread:
                    self._thread = None
        return stopped

    def submit_event(self, event: Event) -> bool:
        """Non-blocking EventBus subscriber; all verification stays off-thread."""
        if not self.enabled or getattr(event, "module", "") != "Telemetry Scanner":
            return False
        details = getattr(event, "details", None)
        if (
            not isinstance(details, dict)
            or details.get("source") != "scanner"
            or details.get("sensor") != "process_creation"
            or details.get("type") != "process_creation"
        ):
            return False
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self._metric("dropped")
            return False

    def _metric(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._metrics[name] = min(
                1_000_000_000,
                self._metrics.get(name, 0) + max(0, int(amount)),
            )

    def _run(self) -> None:
        dirty = False
        last_write = time.monotonic()
        while not self._stop.is_set() or not self._queue.empty():
            try:
                event = self._queue.get(timeout=0.25)
            except queue.Empty:
                event = None
            if event is not None and self.enabled:
                dirty = self._observe(event) or dirty
            now = time.monotonic()
            if dirty and (self._queue.empty() or now - last_write >= 1.0):
                dirty = not self._write()
                last_write = now
        if dirty:
            self._write()

    def _observe(self, event: Event) -> bool:
        if self._integrity_error or not self.authority.verify(event):
            self._metric("rejected")
            return False
        details = getattr(event, "details", None)
        if (
            not isinstance(details, dict)
            or details.get("source") != "scanner"
            or details.get("sensor") != "process_creation"
            or details.get("type") != "process_creation"
            or details.get("location_status") != "resolved"
        ):
            self._metric("rejected")
            return False
        raw_path = details.get("exe")
        raw_name = details.get("name")
        if (
            not isinstance(raw_path, str)
            or not _is_absolute_local_path(raw_path)
            or not isinstance(raw_name, str)
            or not raw_name
            or len(raw_name) > 260
            or "\x00" in raw_name
        ):
            self._metric("rejected")
            return False
        try:
            assessment = self._assess_cached(raw_path)
        except (OSError, ValueError):
            self._metric("rejected")
            return False
        now = float(self._clock())
        if not math.isfinite(now) or now < 0:
            self._metric("rejected")
            return False
        candidate_id = _candidate_id(assessment.path, assessment.sha256)
        day = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
        with self._lock:
            until = self._dismissed.get(candidate_id, 0.0)
            if until > now:
                self._metrics["dismissed"] = min(
                    1_000_000_000,
                    self._metrics["dismissed"] + 1,
                )
                return False
            self._dismissed.pop(candidate_id, None)
            current = self._candidates.get(candidate_id)
            if current is None:
                current = {
                    "id": candidate_id,
                    "name": assessment.name,
                    "path": assessment.path,
                    "sha256": assessment.sha256,
                    "size": assessment.size,
                    "mtime_ns": assessment.mtime_ns,
                    "signature_status": assessment.signature_status,
                    "publisher": assessment.publisher,
                    "root_class": assessment.root_class,
                    "trusted_root": assessment.trusted_root,
                    "reason": assessment.reason,
                    "first_seen": now,
                    "last_seen": now,
                    "observations": 1,
                    "days": [day],
                }
                self._candidates[candidate_id] = current
            else:
                current["last_seen"] = max(float(current["last_seen"]), now)
                current["observations"] = min(
                    1_000_000_000,
                    int(current["observations"]) + 1,
                )
                current["days"] = sorted(
                    set(current["days"]) | {day}
                )[-MAX_DAYS_RETAINED:]
            while len(self._candidates) > MAX_CANDIDATES:
                oldest = min(
                    self._candidates.values(),
                    key=lambda item: (float(item["last_seen"]), item["id"]),
                )
                self._candidates.pop(oldest["id"], None)
            self._metrics["accepted"] = min(
                1_000_000_000,
                self._metrics["accepted"] + 1,
            )
        return True

    def _assess_cached(self, path: str) -> ExecutableAssessment:
        candidate = Path(path)
        info = candidate.stat()
        identity = (int(info.st_size), int(info.st_mtime_ns), int(info.st_ctime_ns))
        key = os.path.normcase(os.path.normpath(path))
        with self._lock:
            cached = self._assessment_cache.get(key)
            if cached is not None and cached[0] == identity:
                self._assessment_cache.move_to_end(key)
                return cached[1]
        assessment = self._assessor(path)
        with self._lock:
            self._assessment_cache[key] = (identity, assessment)
            self._assessment_cache.move_to_end(key)
            while len(self._assessment_cache) > 256:
                self._assessment_cache.popitem(last=False)
        return assessment

    def _body(self) -> dict:
        with self._lock:
            now = float(self._clock())
            return {
                "version": STATE_VERSION,
                "updated_at": now,
                "candidates": [
                    dict(item)
                    for item in sorted(
                        self._candidates.values(),
                        key=lambda row: (-float(row["last_seen"]), row["id"]),
                    )
                ],
                "dismissed": [
                    {"id": item_id, "until": until}
                    for item_id, until in sorted(self._dismissed.items())
                    if until > now
                ][-MAX_DISMISSED:],
                "metrics": dict(self._metrics),
            }

    def _write(self) -> bool:
        if self._integrity_error:
            return False
        body = self._body()
        document = dict(body)
        document["signature"] = _sign_state(body, self.authority)
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(encoded) > MAX_STATE_BYTES:
            self._metric("write_errors")
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and _is_reparse(self.path):
                raise BaselineIntegrityError(
                    "process-baseline state path is a reparse point"
                )
            temporary = self.path.with_name(
                f"{self.path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
            )
            try:
                with temporary.open("xb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                replace_with_retry(temporary, self.path)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            return True
        except Exception:
            self._metric("write_errors")
            return False

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            if _is_reparse(self.path):
                raise BaselineIntegrityError(
                    "process-baseline state path is a reparse point"
                )
            if self.path.stat().st_size > MAX_STATE_BYTES:
                raise BaselineIntegrityError("process-baseline state is oversized")
            raw = json.loads(
                self.path.read_text(encoding="utf-8"),
                object_pairs_hook=_no_duplicate_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    BaselineIntegrityError(
                        f"non-finite process-baseline value: {value}"
                    )
                ),
            )
            body = _validate_state(raw, self.authority)
            with self._lock:
                self._candidates = {
                    item["id"]: dict(item) for item in body["candidates"]
                }
                self._dismissed = {
                    item["id"]: float(item["until"])
                    for item in body["dismissed"]
                }
                self._metrics = dict(body["metrics"])
        except Exception as exc:
            self._integrity_error = str(exc)[:512]

    @staticmethod
    def _eligible(candidate: dict) -> bool:
        return (
            bool(candidate.get("trusted_root"))
            and str(candidate.get("signature_status", "")).casefold() == "valid"
            and int(candidate.get("observations", 0)) >= MIN_OBSERVATIONS
            and len(candidate.get("days", ())) >= MIN_DISTINCT_DAYS
        )

    def snapshot(self) -> dict:
        with self._lock:
            candidates = []
            for item in sorted(
                self._candidates.values(),
                key=lambda row: (-float(row["last_seen"]), row["id"]),
            ):
                copy = dict(item)
                copy["days"] = list(copy["days"])
                copy["eligible"] = self._eligible(copy)
                candidates.append(copy)
            return {
                "enabled": self._enabled,
                "integrity_error": self._integrity_error,
                "candidates": candidates,
                "metrics": dict(self._metrics),
                "thresholds": {
                    "observations": MIN_OBSERVATIONS,
                    "distinct_days": MIN_DISTINCT_DAYS,
                },
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self._queue.maxsize,
            }

    def approve(self, candidate_id: str) -> dict:
        if self._integrity_error:
            raise BaselineIntegrityError(self._integrity_error)
        with self._lock:
            candidate = dict(self._candidates.get(str(candidate_id), {}))
        if not candidate:
            raise ValueError("The learned candidate no longer exists.")
        if not self._eligible(candidate):
            raise ValueError(
                "Candidate is not mature and signed inside a protected install root."
            )
        assessment = self._assessor(candidate["path"])
        if (
            assessment.sha256 != candidate["sha256"]
            or assessment.path != candidate["path"]
            or not assessment.trusted_root
            or assessment.signature_status.casefold() != "valid"
        ):
            raise ValueError(
                "The executable changed or no longer meets the signed-root policy."
            )
        row = add_trusted_process(
            name=assessment.name,
            path=assessment.path,
            data_dir=self.data_dir,
            sha256=assessment.sha256,
            publisher=assessment.publisher,
            source="baseline",
        )
        with self._lock:
            current = self._candidates.get(candidate["id"])
            if current is not None and current.get("sha256") == assessment.sha256:
                self._candidates.pop(candidate["id"], None)
                self._dismissed.pop(candidate["id"], None)
        if not self._write():
            raise OSError("Trusted the executable, but could not persist learner cleanup.")
        return row

    def dismiss(self, candidate_id: str, *, days: int = DISMISS_DAYS) -> bool:
        if self._integrity_error:
            raise BaselineIntegrityError(self._integrity_error)
        days = int(days)
        if not 1 <= days <= 365:
            raise ValueError("Dismissal must be from 1 through 365 days.")
        with self._lock:
            candidate = self._candidates.pop(str(candidate_id), None)
            if candidate is None:
                return False
            self._dismissed[str(candidate_id)] = float(self._clock()) + days * 86400
            while len(self._dismissed) > MAX_DISMISSED:
                oldest = min(self._dismissed.items(), key=lambda item: item[1])
                self._dismissed.pop(oldest[0], None)
        if not self._write():
            raise OSError("Could not persist the learned-candidate dismissal.")
        return True

    def reset_state(self) -> None:
        """Explicitly quarantine bad/old suggestions and start a signed empty state."""
        self.stop()
        if self.path.exists():
            quarantine = self.path.with_name(
                f"{self.path.name}.quarantine.{int(self._clock())}"
            )
            replace_with_retry(self.path, quarantine)
            older = sorted(
                self.path.parent.glob(f"{self.path.name}.quarantine.*"),
                key=lambda item: item.stat().st_mtime_ns,
                reverse=True,
            )
            for item in older[3:]:
                try:
                    item.unlink()
                except OSError:
                    pass
        with self._lock:
            self._candidates.clear()
            self._dismissed.clear()
            self._metrics = {key: 0 for key in _METRIC_FIELDS}
            self._integrity_error = ""
            self._assessment_cache.clear()
        if not self._write():
            raise OSError("Could not create authenticated process-baseline state.")
        if self.enabled:
            self.start()


__all__ = [
    "BaselineIntegrityError",
    "DISMISS_DAYS",
    "ExecutableAssessment",
    "MIN_DISTINCT_DAYS",
    "MIN_OBSERVATIONS",
    "ProcessBaselineLearner",
    "assess_executable",
]
