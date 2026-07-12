"""diagnostics.py — async, atomic diagnostic dumps for the BlackBox.

The BlackBox recorder is a strictly read-only, out-of-band flight recorder: it
only ever READS diagnostic files. Every live component (core / watchdog / scanner)
periodically dumps its own state here so the BlackBox can surface it without ever
touching or blocking the live process.

Files (under the repo ``diagnostics/`` directory the BlackBox already watches):
    status.json            per-component liveness + resource snapshot
    thread_dump.json       current thread stacks (deadlock forensics)
    tracemalloc.json       top memory allocations (if tracemalloc is enabled)
    selftest_failures.json appended record of any self-test failure

All writes are atomic (temp file + os.replace) so a reader never sees a torn file,
and best-effort (never raise into the caller's hot path).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Optional


def _repo_root() -> Path:
    # src/angerona/resilience/diagnostics.py → parents[3] == repo root
    return Path(__file__).resolve().parents[3]


def diag_dir() -> Path:
    # ANGERONA_DIAG_DIR lets the BlackBox diagnostics location be relocated
    # (and lets the self-test run in isolation without touching the real folder).
    override = os.environ.get("ANGERONA_DIAG_DIR")
    d = Path(override) if override else _repo_root() / "diagnostics"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return d


_LOCK = threading.Lock()


def _atomic_write_json(name: str, obj) -> bool:
    p = diag_dir() / name
    tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    try:
        with _LOCK:
            tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
            os.replace(tmp, p)
        return True
    except Exception:
        try:
            tmp.unlink()
        except Exception:
            pass
        return False


def write_status(component: str, state: str = "running", extra: Optional[dict] = None) -> bool:
    """Snapshot this process's liveness + resource footprint."""
    snap = {"component": component, "state": state, "pid": os.getpid(),
            "ts": time.time(), "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        import psutil
        p = psutil.Process()
        with p.oneshot():
            snap["rss_mb"] = round(p.memory_info().rss / 1048576, 2)
            snap["cpu_pct"] = p.cpu_percent(interval=0.0)
            snap["num_threads"] = p.num_threads()
    except Exception:
        snap["num_threads"] = threading.active_count()
    if extra:
        snap.update(extra)
    return _atomic_write_json(f"status_{component}.json", snap) and _atomic_write_json("status.json", snap)


def write_thread_dump(component: str = "core") -> bool:
    frames = sys._current_frames()
    dump = {"component": component, "pid": os.getpid(), "ts": time.time(), "threads": []}
    names = {t.ident: t.name for t in threading.enumerate()}
    for tid, frame in frames.items():
        dump["threads"].append({
            "tid": tid, "name": names.get(tid, "?"),
            "stack": [f"{fn}:{ln} {func}" for fn, ln, func, _ in traceback.extract_stack(frame)][-20:],
        })
    return _atomic_write_json("thread_dump.json", dump)


def write_tracemalloc(component: str = "core", top: int = 15) -> bool:
    out = {"component": component, "pid": os.getpid(), "ts": time.time(), "top": []}
    try:
        import tracemalloc
        if not tracemalloc.is_tracing():
            out["note"] = "tracemalloc not enabled (start with tracemalloc.start())"
        else:
            snapshot = tracemalloc.take_snapshot()
            for stat in snapshot.statistics("lineno")[:top]:
                out["top"].append({"traceback": str(stat.traceback),
                                   "size_kb": round(stat.size / 1024, 1), "count": stat.count})
    except Exception as exc:
        out["error"] = str(exc)
    return _atomic_write_json("tracemalloc.json", out)


def record_selftest_failure(name: str, detail: str, component: str = "core") -> bool:
    """Append a self-test failure record for the BlackBox to surface."""
    p = diag_dir() / "selftest_failures.json"
    rec = {"name": name, "detail": detail, "component": component, "ts": time.time(),
           "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        existing = []
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                existing = data if isinstance(data, list) else [data]
            except Exception:
                existing = []
        existing.append(rec)
        return _atomic_write_json("selftest_failures.json", existing[-200:])
    except Exception:
        return False


def self_test() -> tuple[bool, str]:
    """Verify each dump writes atomically and reads back with the right shape.
    Runs in an isolated temp diagnostics dir so it never pollutes the real one."""
    import tempfile
    _prev = os.environ.get("ANGERONA_DIAG_DIR")
    os.environ["ANGERONA_DIAG_DIR"] = tempfile.mkdtemp(prefix="diag_selftest_")
    try:
        return _self_test_body()
    finally:
        try:
            import shutil
            shutil.rmtree(os.environ["ANGERONA_DIAG_DIR"], ignore_errors=True)
        finally:
            if _prev is None:
                os.environ.pop("ANGERONA_DIAG_DIR", None)
            else:
                os.environ["ANGERONA_DIAG_DIR"] = _prev


def _self_test_body() -> tuple[bool, str]:
    comp = "selftest"
    s = write_status(comp, "testing", {"marker": "unit"})
    td = write_thread_dump(comp)
    tm = write_tracemalloc(comp)
    fail = record_selftest_failure("dummy_check", "intentional test record", comp)
    try:
        status = json.loads((diag_dir() / "status.json").read_text(encoding="utf-8"))
        dump = json.loads((diag_dir() / "thread_dump.json").read_text(encoding="utf-8"))
        fails = json.loads((diag_dir() / "selftest_failures.json").read_text(encoding="utf-8"))
        shape_ok = (status.get("component") == comp and "pid" in status
                    and isinstance(dump.get("threads"), list) and dump["threads"]
                    and isinstance(fails, list) and fails[-1]["name"] == "dummy_check")
    except Exception as exc:
        return False, f"readback failed: {exc}"
    ok = s and td and tm and fail and shape_ok
    return ok, ("status + thread_dump + tracemalloc + selftest_failures written "
                "atomically and read back OK" if ok else
                f"failed: status={s} dump={td} tm={tm} fail={fail} shape={shape_ok}")


if __name__ == "__main__":
    print(self_test())
