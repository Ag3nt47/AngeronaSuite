"""Persistent, exact-match trusted-process policy.

The policy is deliberately operator-supervised.  Angerona can discover running
executables, but it never silently teaches itself that an observed process is
safe: malware present during a baseline window must not become trusted merely
because it stayed resident for a while.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Iterable

_LOCK = threading.RLock()
_CACHE: dict[str, tuple[int, list[dict]]] = {}
_DEFAULT_DATA_DIR: Path | None = None

# Immutable normalized rows are safe to reuse for a complete evaluation batch.
# Each item is ``(case-folded basename, normalized exact path)``.
PolicySnapshot = tuple[tuple[str, str], ...]


def _data_dir(data_dir=None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    global _DEFAULT_DATA_DIR
    with _LOCK:
        if _DEFAULT_DATA_DIR is None:
            try:
                from angerona.core.config import Config
                _DEFAULT_DATA_DIR = Path(Config.load().data_dir)
            except Exception:
                from angerona.core.data_paths import data_dir as canonical_data_dir
                _DEFAULT_DATA_DIR = canonical_data_dir()
        return _DEFAULT_DATA_DIR


def policy_path(data_dir=None) -> Path:
    return _data_dir(data_dir) / "shared_logs" / "process_allowlist.json"


def _normal_path(value: str) -> str:
    value = os.path.expandvars(os.path.expanduser(str(value or "").strip().strip('"')))
    return os.path.normcase(os.path.normpath(value)) if value else ""


def _normal_name(value: str) -> str:
    return Path(str(value or "").strip().strip('"')).name.casefold()


def _load(data_dir=None) -> list[dict]:
    path = policy_path(data_dir)
    key = str(path)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = -1
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] == stamp:
            return [dict(x) for x in cached[1]]
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            rows = raw.get("entries", []) if isinstance(raw, dict) else []
            rows = [dict(x) for x in rows if isinstance(x, dict)]
        except Exception:
            rows = []
        _CACHE[key] = (stamp, rows)
        return [dict(x) for x in rows]


def _write(rows: Iterable[dict], data_dir=None) -> None:
    path = policy_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "updated_at": time.time(), "entries": list(rows)}
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    with _LOCK:
        _CACHE.pop(str(path), None)


def entries(data_dir=None) -> list[dict]:
    return _load(data_dir)


def policy_snapshot(data_dir=None) -> PolicySnapshot:
    """Return one reusable, immutable view of the current trusted policy.

    Batch consumers should call this once, then pass it to :func:`is_allowed`
    or :func:`is_event_allowed`; this avoids a policy-path stat and row cloning
    for every process/event while retaining the existing mtime invalidation at
    the start of each batch.
    """
    return tuple(
        (_normal_name(row.get("name", "")), _normal_path(row.get("path", "")))
        for row in _load(data_dir)
    )


def add(name: str = "", path: str = "", data_dir=None) -> dict:
    """Trust an exact executable path, or add a non-path basename hint.

    Basename-only entries are intentionally useful only when an event genuinely
    has no executable path.  A path-rich event must match an exact approved
    path, so a renamed executable in another directory cannot inherit trust.
    """
    clean_path = str(path or "").strip().strip('"')
    clean_name = Path(clean_path).name if clean_path else Path(str(name or "").strip()).name
    if not clean_name:
        raise ValueError("Enter a process name or select an executable.")
    if any(ch in clean_name + clean_path for ch in "*?"):
        raise ValueError("Wildcards are not allowed; trust an exact process name or path.")
    rows = _load(data_dir)
    norm_path = _normal_path(clean_path)
    norm_name = _normal_name(clean_name)
    for row in rows:
        if _normal_name(row.get("name", "")) == norm_name and _normal_path(row.get("path", "")) == norm_path:
            return row
    row = {
        "id": uuid.uuid4().hex,
        "name": clean_name,
        "path": clean_path,
        "added_at": time.time(),
    }
    rows.append(row)
    _write(rows, data_dir)
    return row


def remove(entry_id: str, data_dir=None) -> bool:
    rows = _load(data_dir)
    kept = [row for row in rows if str(row.get("id", "")) != str(entry_id)]
    if len(kept) == len(rows):
        return False
    _write(kept, data_dir)
    return True


def is_allowed(name: str = "", path: str = "", data_dir=None,
               policy: PolicySnapshot | None = None) -> bool:
    norm_name = _normal_name(name or path)
    norm_path = _normal_path(path)
    if not norm_name and not norm_path:
        return False
    rows = policy_snapshot(data_dir) if policy is None else policy
    for row_name, row_path in rows:
        if row_path:
            if norm_path and norm_path == row_path:
                return True
        # A basename-only row is a fallback for pathless telemetry, never a
        # wildcard over an observed path.  Exact-path entries (including the
        # Proton defaults) retain their existing behavior.
        elif not norm_path and norm_name and norm_name == row_name:
            return True
    return False


def event_process(event) -> tuple[str, str]:
    details = getattr(event, "details", None) or {}
    name = details.get("proc_name") or details.get("process_name") or ""
    path = (details.get("exe") or details.get("process_path")
            or details.get("image") or "")
    return str(name), str(path)


def is_event_allowed(event, data_dir=None,
                     policy: PolicySnapshot | None = None) -> bool:
    name, path = event_process(event)
    return is_allowed(name, path, data_dir, policy) if (name or path) else False


def running_processes() -> list[dict]:
    """Return exact running executable candidates for supervised learning."""
    found: dict[tuple[str, str], dict] = {}
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = str(proc.info.get("name") or "")
                path = str(proc.info.get("exe") or "")
                if not name:
                    continue
                key = (_normal_name(name), _normal_path(path))
                found.setdefault(key, {"pid": int(proc.info.get("pid") or 0),
                                       "name": name, "path": path})
            except (OSError, ValueError):
                continue
    except Exception:
        return []
    return sorted(found.values(), key=lambda x: (x["name"].casefold(), x["path"].casefold()))
