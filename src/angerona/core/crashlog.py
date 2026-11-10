"""Crash capture.

Under `pythonw` there is no console, so an unhandled exception or a native Qt
fault leaves no trace — the window just vanishes. install() wires up:
  * sys.excepthook            — unhandled exceptions on any thread's stack
  * threading.excepthook      — exceptions in background/module/shark threads
  * faulthandler              — hard native faults (segfault / Qt C++ abort)
  * qInstallMessageHandler    — Qt Critical/Fatal messages

Python/Qt messages are appended to available logs/crash.log and
diagnostics/crash.log below the runtime data directory. faulthandler has one
selected output and captures the faulting thread only, reported separately.
Python-owned watchdog/diagnostic snapshots retain all-thread context under the
GIL; native exception handlers must not walk other threads' moving frames.
Arming observations do not guarantee
capture of every native failure or faults during interpreter teardown.
Normal appends preserve existing evidence and pause at bounded message/file/
process allowances. Native C fault output and external writers are not bounded
by those allowances; this is not an operating-system disk quota.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, replace
import faulthandler
import os
from os import fstat
import re
import stat
import sys
import threading
import traceback
from pathlib import Path

_TARGETS: list[Path] = []
_FH_FILES: list = []
_LAST_REPORT: CrashLogReport | None = None
_NORMAL_PATHS: dict[str, Path] = {}
_NORMAL_ROLES = ("logs", "diagnostics")
_NORMAL_LIMIT_BYTES = 8 * 1024 * 1024
_NORMAL_MESSAGE_BYTES = 64 * 1024
_NORMAL_PAUSED = False
_NORMAL_CONFIGURED_AT: str | None = None
_NORMAL_LOCK = threading.Lock()
_NORMAL_STATS_LOCK = threading.Lock()
_NORMAL_COUNT_GAP = False
_COUNT_MAX = (1 << 63) - 1


@dataclass
class _NormalTarget:
    role: str
    reserved: int = 0
    appended: int = 0
    blocks: int = 0
    uncertain: int = 0
    reason: str = "not-installed"
    checked_size: int | None = None
    checked_at: str | None = None


_NORMAL_ROWS = {role: _NormalTarget(role) for role in _NORMAL_ROLES}
_NORMAL_SUPPRESSIONS = {role: (0, 0, 0, "") for role in _NORMAL_ROLES}
_NORMAL_CACHE = (8 * 1024 * 1024, 64 * 1024, False, None,
                 tuple((role, 0, 0, 0, 0, "not-installed", None, None) for role in _NORMAL_ROLES))


def _normal_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _cache_normal_budget() -> None:
    global _NORMAL_CACHE
    # One immutable publication; readers never wait behind a writer doing I/O.
    _NORMAL_CACHE = (_NORMAL_LIMIT_BYTES, _NORMAL_MESSAGE_BYTES, _NORMAL_PAUSED, _NORMAL_CONFIGURED_AT,
                     tuple((r.role, r.reserved, r.appended, r.blocks, r.uncertain, r.reason,
                            r.checked_size, r.checked_at) for r in
                           (_NORMAL_ROWS[role] for role in _NORMAL_ROLES)))


def _note_suppression(roles: tuple[str, ...], reason: str, size: int | None) -> None:
    global _NORMAL_COUNT_GAP
    # Reentrant hooks must not wait for their own writer or telemetry lock.
    # A lost telemetry update is explicit; append reservations remain exact.
    if not _NORMAL_STATS_LOCK.acquire(blocking=False):
        _NORMAL_COUNT_GAP = True
        return
    try:
        for role in roles:
            count, known_bytes, unknown, _ = _NORMAL_SUPPRESSIONS[role]
            if (count == _COUNT_MAX or known_bytes + (size or 0) > _COUNT_MAX
                    or unknown + (size is None) > _COUNT_MAX):
                _NORMAL_COUNT_GAP = True
            _NORMAL_SUPPRESSIONS[role] = (min(_COUNT_MAX, count + 1),
                                         min(_COUNT_MAX, known_bytes + (size or 0)),
                                         min(_COUNT_MAX, unknown + (size is None)), reason)
    finally:
        _NORMAL_STATS_LOCK.release()


def normal_write_snapshot() -> dict:
    """Cached, role-only normal-writer observations; no I/O or waiting.

    Size is the last opened-file check, not current named-file presence. Native
    faulthandler and outside writers are exceptional/uncontrolled by this budget.
    """
    limit, message, paused, configured_at, rows = _NORMAL_CACHE
    counts = tuple(_NORMAL_SUPPRESSIONS[role] for role in _NORMAL_ROLES)
    return {
        "schema": "angerona-normal-crashlog-budget-v1",
        "limit_bytes": limit, "message_bytes": message, "paused": paused,
        "configured_at": configured_at, "suppression_counts_lower_bound": _NORMAL_COUNT_GAP,
        "observations_cached": True,
        "native_fault_bytes_limited": False, "external_writers_limited": False,
        "os_quota": False,
        "targets": tuple({
            "role": row[0], "reserved_bytes": row[1], "appended_bytes": row[2],
            "appended_blocks": row[3], "uncertain_bytes": row[4],
            "state": "held" if paused or row[5] not in ("", "not-installed") else
                     ("not-installed" if row[5] == "not-installed" else "ready"),
            "reason": "policy-paused" if paused and row[5] != "io-uncertain" else row[5],
            "checked_size_bytes": row[6], "checked_at": row[7],
            "suppressed_blocks": count[0], "suppressed_known_bytes": count[1],
            "suppressed_unknown_size_blocks": count[2], "last_suppression": count[3],
        } for row, count in zip(rows, counts)),
    }


def _opened_size(stream, row: _NormalTarget) -> int:
    details = fstat(stream.fileno())
    if (not stat.S_ISREG(details.st_mode) or type(details.st_size) is not int
            or details.st_size < 0):
        raise OSError("Normal crash log target is not a regular sized file")
    row.checked_size, row.checked_at = details.st_size, _normal_stamp()
    return details.st_size


def configure_normal_log_budget(*, limit_mib: int, message_kib: int, paused: bool) -> dict:
    """Apply validated post-Config policy without waiting for a busy writer.

    Capacity/policy holds require a fresh opened-file check on the next append. An
    uncertain append is never resumed here, and no allowance/counter is reset.
    This does not close, rotate, truncate or rearm native faulthandler streams.
    """
    global _NORMAL_LIMIT_BYTES, _NORMAL_MESSAGE_BYTES, _NORMAL_PAUSED, _NORMAL_CONFIGURED_AT
    if type(limit_mib) is not int or not 1 <= limit_mib <= 64:
        raise ValueError("limit_mib must be an integer from 1 to 64")
    if type(message_kib) is not int or not 4 <= message_kib <= 256:
        raise ValueError("message_kib must be an integer from 4 to 256")
    if type(paused) is not bool:
        raise ValueError("paused must be a boolean")
    if not _NORMAL_LOCK.acquire(blocking=False):
        return {"accepted": False, "reason": "writer-busy", "snapshot": normal_write_snapshot()}
    try:
        _NORMAL_LIMIT_BYTES, _NORMAL_MESSAGE_BYTES = limit_mib * 1024 * 1024, message_kib * 1024
        _NORMAL_PAUSED, _NORMAL_CONFIGURED_AT = paused, _normal_stamp()
        for role in tuple(_NORMAL_PATHS):
            row = _NORMAL_ROWS[role]
            if row.reason == "io-uncertain":
                continue
            if paused:
                row.reason = "policy-paused"
                continue
            row.reason = "resume-check-required"
        _cache_normal_budget()
        return {"accepted": True, "reason": "configured", "snapshot": normal_write_snapshot()}
    finally:
        _NORMAL_LOCK.release()


@dataclass(frozen=True)
class CrashLogTarget:
    role: str
    path: Path | None
    opened: bool = False
    startup_written: bool = False
    native_selected: bool = False
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class CrashLogReport:
    targets: tuple[CrashLogTarget, ...]
    main_hook: bool
    thread_hook: bool
    qt_hook: bool
    errors: tuple[str, ...] = ()
    diagnostics_written: bool = False
    diagnostics_error: str = ""
    pid: int | None = None
    birth_filetime: str | None = None
    identity_state: str = "unavailable"
    identity_error: str = "not-captured"

    @property
    def native_fault_target(self) -> Path | None:
        return next((target.path for target in self.targets if target.native_selected), None)

    @property
    def state(self) -> str:
        if not any(target.startup_written for target in self.targets):
            return "unavailable"
        if (all(target.opened and target.startup_written and not target.errors for target in self.targets)
                and self.native_fault_target is not None
                and self.main_hook and self.thread_hook and self.qt_hook and not self.errors):
            return "armed"
        return "partial"


class CrashLogInstallation(list[Path]):
    """Legacy target list with immutable observations of this arming attempt."""
    def __init__(self, report: CrashLogReport):
        super().__init__(target.path for target in report.targets if target.path is not None)
        self.report = report


def latest_report() -> CrashLogReport | None:
    """Memory-only installation evidence; no current file/native-health proof."""
    return _LAST_REPORT


def _capture_generation() -> tuple[int | None, str | None, str, str]:
    """Observe this installer once; never infer a generation from another PID.

    The native helper's FILETIME stays decimal text. A missing native birth
    leaves useful PID-only evidence without changing hook arming or startup.
    """
    try:
        pid = os.getpid()
    except Exception:
        return None, None, "unavailable", "pid-unavailable"
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        return None, None, "unavailable", "pid-unavailable"
    try:
        from angerona.core.startup_diagnostics import process_identity

        identity = process_identity()
    except Exception:
        return pid, None, "pid-only", "identity-query-failed"
    if type(identity) is not dict or not 1 <= len(identity) <= 2:
        return pid, None, "pid-only", "identity-malformed"
    identity = dict(identity)
    if any(type(key) is not str or len(key) > 14 or key not in {"pid", "birth_filetime"}
           for key in identity):
        return pid, None, "pid-only", "identity-malformed"
    observed_pid = identity.get("pid")
    if type(observed_pid) is not int or not 0 < observed_pid <= 0xFFFFFFFF:
        return pid, None, "pid-only", "identity-malformed"
    if observed_pid != pid:
        return pid, None, "pid-only", "pid-mismatch"
    birth = identity.get("birth_filetime")
    if birth is None:
        return pid, None, "pid-only", "birth-unavailable"
    if (type(birth) is not str or not 1 <= len(birth) <= 20
            or not birth.isascii() or not birth.isdecimal()
            or birth != str(int(birth)) or not 0 < int(birth) <= 0xFFFFFFFFFFFFFFFF):
        return pid, None, "pid-only", "birth-malformed"
    return pid, birth, "pid-birth-observed", ""


def _error_code(error: BaseException) -> str:
    # Arming reports expose an exception class and OS code, never raw error
    # messages, paths, credentials or a traceback on stderr.
    name = re.sub(r"[^A-Za-z0-9_]", "?", type(error).__name__)[:64]
    number = getattr(error, "winerror", None) or getattr(error, "errno", None)
    return f"{name}:{number}" if type(number) is int else name


def _data_log() -> Path:
    from angerona.core.data_paths import data_dir
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d / "crash.log"


def _repo_log() -> Path:
    # Historical helper name; this is the runtime diagnostics directory.
    from angerona.core.data_paths import data_dir
    d = data_dir() / "diagnostics"
    d.mkdir(parents=True, exist_ok=True)
    return d / "crash.log"


def _write(kind: str, text: str) -> dict[Path, str]:
    targets = tuple(_NORMAL_PATHS.items())
    roles = tuple(role for role, _ in targets)
    if not _NORMAL_LOCK.acquire(blocking=False):
        _note_suppression(roles, "lock-contention", None)
        return {path: "normal-write:lock-contention" for _, path in targets}
    try:
        # Character preflight prevents encoding a giant incoming message. The
        # bounded remainder is checked as a COMPLETE UTF-8 block, headers too.
        if type(kind) is not str or type(text) is not str:
            reason, block = "message-invalid", None
        elif len(kind) + len(text) > _NORMAL_MESSAGE_BYTES:
            reason, block = "message-limit", None
        else:
            stamp = datetime.datetime.now().isoformat(timespec="seconds")
            block = f"\n{'=' * 72}\n[{stamp}] {kind}\n{'-' * 72}\n{text}\n".encode(
                "utf-8", errors="backslashreplace")
            reason = "message-limit" if len(block) > _NORMAL_MESSAGE_BYTES else ""
        if reason:
            _note_suppression(roles, reason, len(block) if block is not None else None)
            return {path: "normal-write:" + reason for _, path in targets}
        size = len(block)
        results = {}
        for role, path in targets:
            row = _NORMAL_ROWS[role]
            reason = "policy-paused" if _NORMAL_PAUSED else row.reason
            if reason not in ("", "not-installed", "resume-check-required"):
                _note_suppression((role,), reason, size)
                results[path] = "normal-write:" + reason
                continue
            reserved = False
            try:
                # Binary append avoids platform newline expansion after the
                # byte preflight. Native C output keeps its original stream.
                with open(path, "ab", buffering=0) as stream:
                    current_size = _opened_size(stream, row)
                    reason = ("file-limit" if current_size + size > _NORMAL_LIMIT_BYTES else
                              "process-limit" if row.reserved + size > _NORMAL_LIMIT_BYTES else "")
                    if reason:
                        row.reason = reason
                    else:
                        # Reserve before I/O; never refund an uncertain short
                        # append, failed flush or close, even after replacement.
                        row.reserved += size
                        reserved = True
                        written = stream.write(block)
                        if type(written) is not int or written != size:
                            raise OSError("Crash log append made incomplete progress")
                        stream.flush()
                if reason:
                    _note_suppression((role,), reason, size)
                    results[path] = "normal-write:" + reason
                    continue
                row.appended += size
                row.blocks += 1
                row.reason = ("process-limit" if row.reserved >= _NORMAL_LIMIT_BYTES else
                              "file-limit" if current_size + size >= _NORMAL_LIMIT_BYTES else "")
                results[path] = ""
            except Exception as error:
                row.reason = "io-uncertain"
                if reserved:
                    row.uncertain += size
                _note_suppression((role,), "io-uncertain", size)
                results[path] = _error_code(error)
        return results
    finally:
        _cache_normal_budget()
        _NORMAL_LOCK.release()


def _publish_report(report: CrashLogReport) -> CrashLogReport:
    """Use the existing bounded private diagnostic writer; never block startup."""
    written, diagnostic_error = False, ""
    try:
        from angerona.core.data_paths import data_dir
        from angerona.core.startup_diagnostics import StartupDiagnostics

        diagnostics = StartupDiagnostics(data_dir())
        # Each row is bounded by the existing 256-character list-field limit.
        # Full target paths remain in the in-memory private report, not stderr.
        rows = [f"{target.role}:open={target.opened};startup={target.startup_written};"
                f"native_selected={target.native_selected};errors={','.join(target.errors)}"
                for target in report.targets]
        written = bool(diagnostics.record(
            "crash-log-arming", report.state,
            actual=rows,
            reason="Crash log arming attempt completed; startup continues.",
            coverage=f"main={report.main_hook};thread={report.thread_hook};qt={report.qt_hook};"
                     f"native_output={next((t.role for t in report.targets if t.native_selected), 'unavailable')};"
                     f"native_threads={'current' if report.native_fault_target is not None else 'unavailable'};"
                     f"identity={report.identity_state};generation observed at installation only;"
                     "one native output only; native teardown failures may remain uncaptured",
            log_error=[*report.errors, *(["identity:" + report.identity_error] if report.identity_error else [])],
            process_role="core", pid=report.pid, birth_filetime=report.birth_filetime,
        ))
        if not written:
            diagnostic_error = "private-receipt-unavailable"
    except Exception as error:
        diagnostic_error = _error_code(error)
    report = replace(report, diagnostics_written=written, diagnostics_error=diagnostic_error)
    if report.state != "armed" or not written:
        failures = [f"{target.role}:{','.join(target.errors)}" for target in report.targets if target.errors]
        failures.extend(report.errors)
        if diagnostic_error:
            failures.append("diagnostics:" + diagnostic_error)
        reason = "; ".join(failures)[:512] or "arming coverage incomplete"
        try:
            print(f"[Angerona] Crash logging {report.state}: {reason}. Startup continues.",
                  file=sys.stderr, flush=True)
        except Exception:
            # pythonw may have no stderr. The private record result above is
            # retained in latest_report even if both reporting sinks fail.
            pass
    return report


def _enable_native_current_thread(stream) -> None:
    # Windows first-chance exceptions can enter faulthandler without the GIL.
    # Raw traversal of other threads can race frame/code lifetime. Keep native
    # fault evidence, but leave all-thread snapshots to Python-owned diagnostics.
    try:
        faulthandler.enable(file=stream, all_threads=False)
    except TypeError:
        # A positional-only API/shim must retain the explicit current-thread
        # scope. Omitting the argument would silently restore default True.
        faulthandler.enable(stream, False)


def install() -> CrashLogInstallation:
    global _TARGETS, _LAST_REPORT, _NORMAL_PATHS
    _TARGETS, _LAST_REPORT = [], None
    targets, files, errors = [], {}, []
    for role, resolver in (("logs", _data_log), ("diagnostics", _repo_log)):
        try:
            path = resolver()
            if not isinstance(path, Path):
                raise TypeError("crash target resolver did not return a path")
            target = CrashLogTarget(role, path)
        except Exception as error:
            targets.append(CrashLogTarget(role, None, errors=("resolve:" + _error_code(error),)))
            continue
        try:
            stream = open(path, "a", encoding="utf-8")
            # Retain all attempted native-output files for the process lifetime
            # as before, including an enable operation whose reply was lost.
            _FH_FILES.append(stream)
            files[path] = stream
            target = replace(target, opened=True)
        except Exception as error:
            target = replace(target, errors=("open:" + _error_code(error),))
        targets.append(target)
    _TARGETS = [target.path for target in targets if target.path is not None]
    # Reinstallation changes destinations, never per-process role allowances
    # or uncertain-write holds. Only these two known roles enter the cache.
    _NORMAL_PATHS = {target.role: target.path for target in targets if target.path is not None}

    # faulthandler selects one global output. Prefer diagnostics, then logs;
    # never advertise that native stacks are mirrored across all open files.
    for index in reversed(range(len(targets))):
        target = targets[index]
        if target.path not in files:
            continue
        try:
            _enable_native_current_thread(files[target.path])
            targets[index] = replace(target, native_selected=True)
            break
        except Exception as error:
            targets[index] = replace(target, errors=(*target.errors, "faulthandler:" + _error_code(error)))

    def _excepthook(exc_type, exc, tb):
        _write("UNHANDLED EXCEPTION (main)",
               "".join(traceback.format_exception(exc_type, exc, tb)))
        sys.__excepthook__(exc_type, exc, tb)

    main_hook = False
    try:
        sys.excepthook = _excepthook
        main_hook = True
    except Exception as error:
        errors.append("main-hook:" + _error_code(error))

    def _threadhook(args):
        _write(f"THREAD EXCEPTION ({getattr(args.thread, 'name', '?')})",
               "".join(traceback.format_exception(
                   args.exc_type, args.exc_value, args.exc_traceback)))

    thread_hook = False
    try:
        threading.excepthook = _threadhook
        thread_hook = True
    except Exception as error:
        errors.append("thread-hook:" + _error_code(error))

    qt_hook = False
    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler

        def _qt_handler(mode, context, message):
            if mode in (QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
                _write(f"QT {mode.name if hasattr(mode, 'name') else mode}", str(message))

        qInstallMessageHandler(_qt_handler)
        qt_hook = True
    except Exception as error:
        errors.append("qt-hook:" + _error_code(error))

    # Keep the additional lazy import/native observation after available hooks
    # are installed. Every sink below reuses this one installation observation.
    pid, birth, identity_state, identity_error = _capture_generation()
    writes = _write("STARTUP", "Crash log STARTUP append; hook and native-output arming are reported separately.\n"
                    f"process_role=core;pid={pid if pid is not None else 'unavailable'};"
                    f"birth_filetime={birth if birth is not None else 'unavailable'};"
                    f"identity={identity_state};identity_error={identity_error or 'none'};"
                    "generation_scope=installation-observation")
    targets = [replace(target, startup_written=bool(target.path in writes and not writes[target.path]),
                       errors=(*target.errors, "startup-write:" + writes[target.path])
                       if target.path in writes and writes[target.path] else target.errors)
               for target in targets]
    _LAST_REPORT = _publish_report(CrashLogReport(
        tuple(targets), main_hook, thread_hook, qt_hook, tuple(errors),
        pid=pid, birth_filetime=birth, identity_state=identity_state, identity_error=identity_error,
    ))
    return CrashLogInstallation(_LAST_REPORT)
