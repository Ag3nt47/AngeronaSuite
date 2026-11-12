"""crash_hunter.py — bounded, read-only sweep after an unexpected core stop.

When the peer watchdog sees the core die without an authenticated stand-down,
the interval until relaunch is unobserved. This sweep records what can still
be seen from user mode at that moment so the gap is not silent:

    * processes created since the core's last known-good time,
    * their remote network endpoints,
    * script/executable files recently written to the temp directory,
    * the current Run/RunOnce autorun values (hashed for later diffing).

Properties
    * Read-only: no process, file, registry or network state is changed, and
      nothing is terminated, quarantined or blocked. Findings are evidence for
      the core's normal, authority-gated pipeline.
    * Bounded: hard caps on rows, directory entries and wall time.
    * Rate-limited: at most one sweep per ``_MIN_INTERVAL_S``.
    * It cannot identify who stopped the core; that needs kernel telemetry.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Optional

_MIN_INTERVAL_S = 60.0
_MAX_ROWS = 100
_MAX_DIR_ENTRIES = 5000
_BUDGET_S = 8.0
_LOOKBACK_S = 300.0
_DROP_SUFFIXES = {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".lnk"}
_RUN_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
)


def _new_processes(since: float, deadline: float) -> tuple[list[dict], set[int]]:
    import psutil
    rows, pids = [], set()
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time"]):
        if time.monotonic() > deadline or len(rows) >= _MAX_ROWS:
            break
        info = proc.info
        created = info.get("create_time") or 0.0
        if created >= since and info.get("pid") != os.getpid():
            pids.add(int(info["pid"]))
            rows.append({"pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name"),
                         "exe": info.get("exe"), "create_time": round(created, 3)})
    return rows, pids


def _connections(pids: set[int]) -> list[dict]:
    import psutil
    rows = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid in pids and conn.raddr and len(rows) < _MAX_ROWS:
                rows.append({"pid": conn.pid, "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                             "status": conn.status})
    except (psutil.Error, OSError):
        pass
    return rows


def _temp_drops(since: float, deadline: float, root: Optional[Path] = None) -> list[dict]:
    base = Path(root) if root is not None else Path(tempfile.gettempdir())
    rows, seen = [], 0
    stack = [(base, 0)]
    while stack and time.monotonic() <= deadline and seen < _MAX_DIR_ENTRIES and len(rows) < _MAX_ROWS:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    seen += 1
                    if seen >= _MAX_DIR_ENTRIES or len(rows) >= _MAX_ROWS:
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if depth < 2:
                                stack.append((Path(entry.path), depth + 1))
                            continue
                        stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.st_mtime >= since and Path(entry.name).suffix.lower() in _DROP_SUFFIXES:
                        rows.append({"path": entry.path, "size": stat.st_size,
                                     "mtime": round(stat.st_mtime, 3)})
        except OSError:
            continue
    return rows


def _autoruns() -> dict:
    if os.name != "nt":
        return {"available": False}
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    values = []
    for hive, key_path in _RUN_KEYS:
        try:
            with winreg.OpenKey(hives[hive], key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while len(values) < _MAX_ROWS:
                    try:
                        name, data, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    values.append(f"{hive}\\{key_path}\\{name}={str(data)[:512]}")
                    index += 1
        except OSError:
            continue
    values.sort()
    digest = hashlib.sha256("\n".join(values).encode("utf-8", "replace")).hexdigest()
    return {"available": True, "count": len(values), "sha256": digest, "values": values}


def sweep(since: Optional[float] = None, *, temp_root: Optional[Path] = None) -> dict:
    """Collect one bounded read-only report. Never raises."""
    started = time.time()
    since = float(since) if since else started - _LOOKBACK_S
    since = max(since, started - 3600.0)
    deadline = time.monotonic() + _BUDGET_S
    report: dict = {"schema": "angerona.crash-hunt.v1", "ts": round(started, 3),
                    "since": round(since, 3), "read_only": True, "errors": []}
    pids: set[int] = set()
    for name, collect in (
        ("processes", lambda: _new_processes(since, deadline)),
        ("connections", lambda: _connections(pids)),
        ("temp_drops", lambda: _temp_drops(since, deadline, temp_root)),
        ("autoruns", _autoruns),
    ):
        try:
            value = collect()
            if name == "processes":
                value, pids = value
            report[name] = value
        except Exception as exc:
            report[name] = [] if name != "autoruns" else {"available": False}
            report["errors"].append(f"{name}:{type(exc).__name__}")
    report["complete"] = not report["errors"] and time.monotonic() <= deadline
    report["duration_s"] = round(time.time() - started, 3)
    return report


class CrashHunter:
    """Rate-limited trigger used by the peer watchdog's supervisor callback."""

    def __init__(self, publish: Callable[[str, str, dict], None], *,
                 report_dir: Optional[Path] = None, clock: Callable[[], float] = time.monotonic,
                 sweeper: Callable[..., dict] = sweep, background: bool = True) -> None:
        self._publish = publish
        self._report_dir = report_dir
        self._clock = clock
        self._sweeper = sweeper
        self._background = background
        self._lock = threading.Lock()
        self._last = -_MIN_INTERVAL_S
        self._previous_autoruns = ""

    def on_supervisor_event(self, level: str, msg: str, details: dict) -> bool:
        """Start a sweep for an unexpected core stop. Returns True if started."""
        if not (isinstance(details, dict) and details.get("unexpected_stop")
                and details.get("component") == "core"):
            return False
        with self._lock:
            now = self._clock()
            if now - self._last < _MIN_INTERVAL_S:
                return False
            self._last = now
        if self._background:
            threading.Thread(target=self._run, name="crash-hunter", daemon=True).start()
        else:
            self._run()
        return True

    def _run(self) -> None:
        try:
            report = self._sweeper()
            autoruns = report.get("autoruns") or {}
            changed = bool(self._previous_autoruns and autoruns.get("sha256")
                           and autoruns["sha256"] != self._previous_autoruns)
            if autoruns.get("sha256"):
                self._previous_autoruns = autoruns["sha256"]
            path = self._write(report)
            counts = {"new_processes": len(report.get("processes") or []),
                      "remote_connections": len(report.get("connections") or []),
                      "temp_drops": len(report.get("temp_drops") or []),
                      "autoruns_changed_since_last_sweep": changed,
                      "complete": bool(report.get("complete")), "report": str(path or "")}
            notable = counts["remote_connections"] or counts["temp_drops"] or changed
            self._publish("HIGH" if notable else "MEDIUM",
                          "Crash hunter: read-only sweep after an unexpected core stop "
                          f"({counts['new_processes']} new process(es), "
                          f"{counts['remote_connections']} remote connection(s), "
                          f"{counts['temp_drops']} temp drop(s)); review the report.",
                          counts)
        except Exception:
            pass

    def _write(self, report: dict) -> Optional[Path]:
        try:
            if self._report_dir is None:
                from angerona.resilience.diagnostics import diag_dir
                directory = Path(diag_dir())
            else:
                directory = Path(self._report_dir)
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"crash_hunt_{int(report['ts'])}.json"
            path.write_text(json.dumps(report, indent=1)[:512 * 1024], encoding="utf-8")
            old = sorted(directory.glob("crash_hunt_*.json"))[:-20]
            for stale in old:
                try:
                    stale.unlink()
                except OSError:
                    pass
            return path
        except Exception:
            return None
