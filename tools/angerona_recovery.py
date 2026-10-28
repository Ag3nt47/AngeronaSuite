"""Independent, read-only startup recovery window (stdlib only).

Run this script directly with a separately checked interpreter. Application
imports, repairs and dashboard launches belong to the supervising launcher,
not to this interface. A corrupt Angerona package cannot prevent model loading.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import stat
import sys
import threading
from typing import Callable


CLOSE = 0
RETRY = 10
UI_UNAVAILABLE = 11
KEEP_WORKING = 20
RESTORE_NEXT_STARTUP = 21
MAX_STATUS_BYTES = 64 * 1024
MAX_LOG_BYTES = 128 * 1024
MAX_ATTEMPTS = 32
MAX_SOURCE_CHANGES = 32
MAX_TEXT = 4096
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SECRET = re.compile(
    r"(?i)(?:\bBearer\s+[A-Za-z0-9._~+/-]+=*|\bsk-[A-Za-z0-9_-]{8,}|"
    r"\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*[^\s,;]+)"
)


def _text(value: object, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(character for character in value[:limit]
                      if character in "\n\t" or ord(character) >= 32)
    cleaned = "".join("\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
                      for character in cleaned)
    return _SECRET.sub("[redacted]", cleaned)


def _absolute_local(path: Path) -> Path:
    path = Path(path)
    if (not path.is_absolute() or ".." in path.parts
            or str(path).startswith(("\\\\", "//"))):
        raise ValueError("Only an absolute local diagnostic path is accepted")
    return Path(os.path.abspath(path))


def _plain_path(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
            raise ValueError("Linked or redirected diagnostics are unavailable")
        if component != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError("A diagnostic parent is not a directory")


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _plain_file(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & _REPARSE):
        raise ValueError("Diagnostics require a plain, single-link regular file")


def read_diagnostic(path: Path, limit: int, *, tail: bool = False) -> tuple[bytes, bool]:
    """Read one checked file; held Windows handles deny writers and replacement.

    POSIX uses no-follow open and final identity checks. The supervising
    launcher creates and owns the private diagnostic directory. This reader
    never treats diagnostic bytes as commands or grants response authority.
    """
    path = _absolute_local(path)
    _plain_path(path)
    before = path.lstat()
    _plain_file(before)
    descriptor = -1
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        opener = kernel.CreateFileW
        opener.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        opener.restype = wintypes.HANDLE
        closer = kernel.CloseHandle
        closer.argtypes = (wintypes.HANDLE,)
        closer.restype = wintypes.BOOL
        handle = opener(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            closer(handle)
            raise
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _plain_file(opened)
        if _identity(before) != _identity(opened):
            raise ValueError("Diagnostic identity changed while opening")
        if opened.st_size > limit and not tail:
            raise ValueError("The startup report exceeds its size limit")
        omitted = bool(tail and opened.st_size > limit)
        if omitted:
            os.lseek(descriptor, opened.st_size - limit, os.SEEK_SET)
        pieces = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            pieces.append(chunk)
            remaining -= len(chunk)
        content = b"".join(pieces)
        named, final = path.lstat(), os.fstat(descriptor)
        _plain_file(named)
        _plain_file(final)
        if (_identity(before) != _identity(named) or _identity(opened) != _identity(final)
                or len(content) > limit):
            raise ValueError("Diagnostic file changed during its bounded read")
        return content, omitted
    finally:
        os.close(descriptor)


def _closed_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate report fields are not accepted")
        result[name] = value
    return result


def _log_path(value: object, root: Path) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return ""
    if any(ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("The selected diagnostic path contains invalid characters")
    candidate = _absolute_local(Path(value))
    root = _absolute_local(root)
    _plain_path(root)
    _plain_path(candidate)
    if candidate == root or not candidate.is_relative_to(root):
        raise ValueError("The diagnostic log is outside the selected log directory")
    if candidate.suffix.lower() not in {".log", ".txt", ".jsonl", ".json"}:
        raise ValueError("Only diagnostic text logs can be displayed")
    return str(candidate)


def load_model(status_file: Path, *, log_root: Path | None = None) -> dict:
    """Build bounded display data even when the report itself is unavailable."""
    model = dict(schema=1, phase="startup diagnostics", outcome="report-unavailable",
                 message="The startup report is unavailable. Retry safe recovery or inspect the launcher output.",
                 protection_status="unknown", log_path="", log_state="No diagnostic log was selected.",
                 attempts=[], report_valid=False, omitted_attempts=0)
    try:
        status_file = _absolute_local(status_file)
        root = _absolute_local(log_root if log_root is not None else status_file.parent)
        raw, _ = read_diagnostic(status_file, MAX_STATUS_BYTES)
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_closed_object)
        if not isinstance(document, dict) or type(document.get("schema")) is not int or document["schema"] != 1:
            raise ValueError("Unrecognized startup report schema")
        attempts = document.get("attempts", [])
        if not isinstance(attempts, list):
            raise ValueError("Invalid startup attempt list")
        model.update(phase=_text(document.get("phase"), 256) or "startup diagnostics",
                     outcome=_text(document.get("outcome"), 128) or "needs-review",
                     message=_text(document.get("message")) or "Normal startup has not been confirmed.",
                     protection_status=("inactive" if document.get("protection_status") == "inactive" else "unknown"),
                     report_valid=True, omitted_attempts=max(0, len(attempts) - MAX_ATTEMPTS))
        for attempt in attempts[:MAX_ATTEMPTS]:
            if not isinstance(attempt, dict):
                raise ValueError("Invalid startup attempt row")
            code = attempt.get("exit_code")
            model["attempts"].append(dict(strategy=_text(attempt.get("strategy"), 256),
                                          outcome=_text(attempt.get("outcome"), 128),
                                          exit_code=code if type(code) is int and -(2**31) <= code <= 2**32-1 else None,
                                          detail=_text(attempt.get("detail"), 1024)))
        try:
            model["log_path"] = _log_path(document.get("log_path"), root)
            if model["log_path"]:
                _plain_file(Path(model["log_path"]).lstat())
                model["log_state"] = "Diagnostic text can be viewed here without executing it."
        except FileNotFoundError:
            model["log_state"] = "The selected diagnostic log is missing; no file will be executed."
        except (OSError, ValueError):
            model["log_path"] = ""
            model["log_state"] = "The selected diagnostic log is missing, changed, unsafe or outside the selected directory."
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        model["report_valid"] = False
        model["outcome"] = "report-unavailable"
        model["message"] = "The startup report is missing, malformed, changed or unsafe. Its contents were not executed."
    return model


def _source_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("Invalid recovery source path")
    if (value.startswith(("/", "\\")) or "\\" in value or ":" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF
                   or 0x202A <= ord(char) <= 0x202E or 0x2066 <= ord(char) <= 0x2069 for char in value)
            or not value.endswith(".py")
            or not value.startswith(("src/angerona/", "src/srt/"))):
        raise ValueError("Recovery source path is outside the selected package source")
    return value


def load_source_model(status_file: Path, *, log_root: Path | None = None,
                      expected_report_id: str | None = None) -> dict:
    """Read a source-recovery notice; a decision remains the parent's action."""
    model = load_model(status_file, log_root=log_root)
    model.update(review_source=True, source_decision_allowed=False, report_id="", changed_files=[],
                 changed_file_count=0, omitted_source_changes=0, action_summary=[], startup_error="",
                 strategy="unknown", pending_decision="pending")
    try:
        if not model["report_valid"]:
            raise ValueError("The selected source recovery report is unavailable")
        raw, _ = read_diagnostic(Path(status_file), MAX_STATUS_BYTES)
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_closed_object)
        report_id = document.get("report_id")
        if not isinstance(report_id, str) or re.fullmatch(r"[0-9a-f]{32}", report_id) is None:
            raise ValueError("The selected recovery report has no bounded generation ID")
        if expected_report_id is not None and (
                re.fullmatch(r"[0-9a-f]{32}", expected_report_id) is None
                or report_id != expected_report_id):
            raise ValueError("Source recovery changed while this review was opening; review the latest report")
        changes = document.get("changed_files", [])
        if not isinstance(changes, list) or len(changes) > 256:
            raise ValueError("Invalid or excessive source recovery change list")
        paths = [_source_path(path) for path in changes]
        count = document.get("changed_file_count", len(paths))
        if type(count) is not int or not len(paths) <= count <= 100000:
            raise ValueError("Source recovery change count is inconsistent")
        summary = document.get("actions", document.get("action_summary", []))
        if isinstance(summary, str):
            summary = [summary]
        if not isinstance(summary, list) or not all(isinstance(row, str) for row in summary):
            raise ValueError("Invalid source recovery action summary")
        model.update(report_id=report_id, source_decision_allowed=True, changed_files=paths[:MAX_SOURCE_CHANGES],
                     changed_file_count=count, omitted_source_changes=max(0, count - MAX_SOURCE_CHANGES),
                     action_summary=[_text(row, 1024) for row in summary[:MAX_ATTEMPTS]],
                     startup_error=_text(document.get("startup_error") or document.get("failure_detail")),
                     strategy=_text(document.get("strategy"), 128) or "unknown",
                     pending_decision=_text(document.get("pending_decision"), 64) or "pending")
        # The full report is viewable as bounded text, never executable content.
        if not model["log_path"]:
            model["log_path"] = _log_path(str(status_file), Path(status_file).parent)
            model["log_state"] = "Open the private recovery report for additional bounded details."
        model["protection_status"] = "unknown"
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        model.update(report_valid=False, source_decision_allowed=False, outcome="source-review-unavailable",
                     message=_text(str(exc)) or "The source recovery report is unavailable; no source decision will be applied.")
    return model


def log_text(path: str) -> str:
    try:
        raw, omitted = read_diagnostic(Path(path), MAX_LOG_BYTES, tail=True)
        text = _text(raw.decode("utf-8", errors="replace"), MAX_LOG_BYTES)
        return ("[Earlier diagnostic text omitted by the 128 KiB view limit.]\n" if omitted else "") + text
    except (OSError, ValueError):
        return "The diagnostic log is missing, changed or unavailable. No file was executed."


def display_text(model: dict) -> str:
    rows = [f"Phase: {model['phase']}", f"Outcome: {model['outcome']}", "", model["message"], "",
            "Protection is not verified by this recovery interface.",
            "This window does not start sensors, approve trust or change response policy.", ""]
    if model.get("review_source"):
        rows.extend(("Source recovery strategy: " + model["strategy"],
                     "Reported original startup failure (diagnostic evidence):",
                     model["startup_error"] or "The parent report did not retain a specific original error; inspect the attempt logs.",
                     "", "Actions reported by the source recovery helper:"))
        rows.extend(model["action_summary"] or ["No detailed action summary was retained."])
        rows.extend(("", "Restored source files (suspected changed set; this does not prove which change caused the failure):"))
        rows.extend(model["changed_files"] or ["No file paths were listed in this bounded report."])
        if model["omitted_source_changes"]:
            rows.append(f"{model['omitted_source_changes']} additional paths omitted by this display's 32-path limit.")
        rows.extend(("", ("The recovery helper reports that prior source edits were preserved privately."
                          if model.get("source_decision_allowed") else
                          "Source preservation status is unavailable; no source decision is authorized here."),
                     "Keep the working version, or schedule preserved edits for the NEXT startup.",
                     "Keep working allows its resolved backup to rotate at a future recovery under bounded retention.",
                     "Unresolved failed edits are preserved; they are never deleted automatically.",
                     "Trying preserved edits next startup still requires fresh startup verification.",
                     "This window never edits running source or resets security evidence or trust.",
                     "Current source decision: " + model["pending_decision"], ""))
    for index, attempt in enumerate(model["attempts"], 1):
        code = "unknown" if attempt["exit_code"] is None else str(attempt["exit_code"])
        rows.append(f"{index}. {attempt['strategy']} — {attempt['outcome']} (exit {code})")
        if attempt["detail"]:
            rows.append(attempt["detail"])
    if model["omitted_attempts"]:
        rows.append(f"{model['omitted_attempts']} older attempt rows omitted by the display limit.")
    rows.extend(("", model["log_state"]))
    if model["log_path"]:
        rows.append(model["log_path"])
    return "\n".join(rows)


def show_window(model: dict, *, tk_module=None) -> int:
    if tk_module is None:
        # Startup must not load caller-selected Tcl libraries or per-user Tk
        # profile code before displaying recovery.
        for name in tuple(os.environ):
            if name.upper() in {"TCL_LIBRARY", "TK_LIBRARY", "TCLLIBPATH"}:
                os.environ.pop(name, None)
        import tkinter as tk_module

    tk = tk_module
    class RecoveryWindow(tk.Tk):
        def readprofile(self, _base_name, _class_name):
            pass

    window = RecoveryWindow()
    window.title("Angerona Recovery")
    window.geometry("800x540")
    result = {"code": CLOSE}
    label = tk.Label(window, text=("Review source recovery after startup" if model.get("review_source")
                                  else "Normal startup needs recovery"), anchor="w")
    label.pack(fill="x", padx=16, pady=(14, 8))
    details = tk.Text(window, wrap="word", height=20)
    details.pack(fill="both", expand=True, padx=16)
    details.insert("1.0", display_text(model))
    details.configure(state="disabled")
    actions = tk.Frame(window)
    actions.pack(fill="x", padx=16, pady=14)

    def finish(code):
        result["code"] = code
        window.destroy()

    log_job = {"window": None, "thread": None, "closed": False}
    log_results = queue.Queue(maxsize=1)

    def open_log():
        previous = log_job["window"]
        if previous is not None and not log_job["closed"]:
            previous.lift()
            return
        if log_job["thread"] is not None and log_job["thread"].is_alive():
            return  # Retain the existing reader instead of admitting more work.
        child = tk.Toplevel(window)
        log_job.update(window=child, closed=False)
        child.title("Angerona diagnostic text — read only")
        child.geometry("800x500")
        text = tk.Text(child, wrap="word")
        text.pack(fill="both", expand=True, padx=12, pady=12)
        text.insert("1.0", "Reading bounded diagnostic text…")
        text.configure(state="disabled")

        def close_log():
            log_job["closed"] = True
            child.destroy()

        def read():
            # The reader owns its file; no Tk method runs on this thread.
            log_results.put(log_text(model["log_path"]))

        def poll():
            try:
                result = log_results.get_nowait()
            except queue.Empty:
                window.after(100, poll)
                return
            log_button.configure(state="normal")
            if not log_job["closed"]:
                text.configure(state="normal")
                text.delete("1.0", "end")
                text.insert("1.0", result)
                text.configure(state="disabled")

        child.protocol("WM_DELETE_WINDOW", close_log)
        tk.Button(child, text="Close", command=close_log).pack(pady=(0, 12))
        log_button.configure(state="disabled")
        # The standalone process owns this one read-only reader. Closing the
        # whole recovery process cannot leave an application/helper child.
        thread = threading.Thread(target=read, name="RecoveryDiagnosticReader", daemon=True)
        log_job["thread"] = thread
        thread.start()
        window.after(100, poll)

    if model.get("review_source"):
        state = "normal" if model.get("source_decision_allowed") else "disabled"
        tk.Button(actions, text="Keep working version", command=lambda: finish(KEEP_WORKING), state=state).pack(side="left")
        tk.Button(actions, text="Try preserved edits NEXT startup", command=lambda: finish(RESTORE_NEXT_STARTUP),
                  state=state).pack(side="left", padx=10)
    else:
        tk.Button(actions, text="Retry safe recovery", command=lambda: finish(RETRY)).pack(side="left")
    utility_actions = actions
    if model.get("review_source"):
        utility_actions = tk.Frame(window)
        utility_actions.pack(fill="x", padx=16, pady=(0, 14))
    log_button = tk.Button(utility_actions, text="Open private recovery report" if model.get("review_source") else "Open diagnostic log", command=open_log,
                           state="normal" if model["log_path"] else "disabled")
    log_button.pack(side="left", padx=10)
    tk.Button(utility_actions, text="Review later" if model.get("review_source") else "Close",
              command=lambda: finish(CLOSE)).pack(side="right")
    window.protocol("WM_DELETE_WINDOW", lambda: finish(CLOSE))
    window.mainloop()
    return result["code"]


def main(argv=None, *, show: Callable[[dict], int] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-file", required=True, type=Path)
    parser.add_argument("--log-root", type=Path)
    parser.add_argument("--review-source", action="store_true", help="Review recovered source; decisions belong to the parent")
    parser.add_argument("--expected-report-id", help="Bind the review to one parent-selected source recovery report")
    parser.add_argument("--headless", action="store_true", help="Print bounded display data without creating a window")
    options = parser.parse_args(argv)
    model = (load_source_model(options.status_file, log_root=options.log_root,
                               expected_report_id=options.expected_report_id) if options.review_source
             else load_model(options.status_file, log_root=options.log_root))
    if options.headless:
        print(json.dumps(model, ensure_ascii=True))
        return CLOSE if model["report_valid"] else UI_UNAVAILABLE
    try:
        result = (show or show_window)(model)
        permitted = ((CLOSE, KEEP_WORKING, RESTORE_NEXT_STARTUP) if model.get("source_decision_allowed")
                     else (CLOSE,)) if options.review_source else (CLOSE, RETRY)
        return result if result in permitted else UI_UNAVAILABLE
    except Exception as exc:
        print(json.dumps(dict(phase="independent-recovery-ui", outcome="ui-unavailable",
                              exception_type=type(exc).__name__, message=_text(str(exc)))), file=sys.stderr)
        return UI_UNAVAILABLE


if __name__ == "__main__":
    raise SystemExit(main())
