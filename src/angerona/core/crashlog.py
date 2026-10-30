"""Crash capture.

Under `pythonw` there is no console, so an unhandled exception or a native Qt
fault leaves no trace — the window just vanishes. install() wires up:
  * sys.excepthook            — unhandled exceptions on any thread's stack
  * threading.excepthook      — exceptions in background/module/shark threads
  * faulthandler              — hard native faults (segfault / Qt C++ abort)
  * qInstallMessageHandler    — Qt Critical/Fatal messages

Python/Qt messages are appended to available logs/crash.log and
diagnostics/crash.log below the runtime data directory. faulthandler has one
selected output, reported separately. Arming observations do not guarantee
capture of every native failure or faults during interpreter teardown.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, replace
import faulthandler
import os
import re
import sys
import threading
import traceback
from pathlib import Path

_TARGETS: list[Path] = []
_FH_FILES: list = []
_LAST_REPORT: CrashLogReport | None = None


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
    """Memory-only arming evidence; no file or native-health attestation."""
    return _LAST_REPORT


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
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    block = f"\n{'=' * 72}\n[{stamp}] {kind}\n{'-' * 72}\n{text}\n"
    results = {}
    for p in _TARGETS:
        try:
            with open(p, "a", encoding="utf-8") as f:
                if f.write(block) != len(block):
                    raise OSError("Crash log append made incomplete progress")
                f.flush()
            results[p] = ""
        except Exception as error:
            results[p] = _error_code(error)
    return results


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
                     "one native output only; native teardown failures may remain uncaptured",
            log_error=list(report.errors), process_role="core",
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


def install() -> CrashLogInstallation:
    global _TARGETS, _LAST_REPORT
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

    # faulthandler selects one global output. Prefer diagnostics, then logs;
    # never advertise that native stacks are mirrored across all open files.
    for index in reversed(range(len(targets))):
        target = targets[index]
        if target.path not in files:
            continue
        try:
            faulthandler.enable(file=files[target.path], all_threads=True)
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

    writes = _write("STARTUP", "Crash log STARTUP append; hook and native-output arming are reported separately.")
    targets = [replace(target, startup_written=bool(target.path in writes and not writes[target.path]),
                       errors=(*target.errors, "startup-write:" + writes[target.path])
                       if target.path in writes and writes[target.path] else target.errors)
               for target in targets]
    _LAST_REPORT = _publish_report(CrashLogReport(tuple(targets), main_hook, thread_hook, qt_hook, tuple(errors)))
    return CrashLogInstallation(_LAST_REPORT)
