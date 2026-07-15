"""File Integrity Monitoring (FIM).

Baselines a set of watched directories (SHA-256 per file) and reports any
create / modify / delete against that baseline. Ported from the original
Angerona FIM worker, cleaned into a self-contained module.
"""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from angerona.core.data_paths import data_dir
from angerona.core.module_base import BaseModule, Severity
# Ring 1 interlock (direct cross-module, no orchestrator): FIM asks INTL whether
# a dropped driver is known-vulnerable / the benign drill marker.
from angerona.modules.intel_sync import is_known_bad_driver

# Sensible high-value defaults; users can extend via a watchlist file later.
DEFAULT_WATCH = [
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers", "etc"),
    os.path.join(os.environ.get("USERPROFILE", str(Path.home())), "Documents"),
    os.path.join(os.environ.get("USERPROFILE", str(Path.home())), "Downloads"),
    str(data_dir() / "drill-sandbox"),
]
_RUNTIME_WATCH: set[str] = set()
_RUNTIME_WATCH_LOCK = threading.RLock()


def register_runtime_watch(path) -> bool:
    """Add a drill-selected directory for this process lifetime only."""
    if not path:
        return False
    try:
        root = os.path.normcase(os.path.abspath(os.path.expandvars(str(path))))
    except Exception:
        return False
    if not root or any(ch in root for ch in "*?"):
        return False
    with _RUNTIME_WATCH_LOCK:
        _RUNTIME_WATCH.add(root)
    return True


def unregister_runtime_watch(path) -> None:
    if not path:
        return
    try:
        root = os.path.normcase(os.path.abspath(os.path.expandvars(str(path))))
    except Exception:
        return
    with _RUNTIME_WATCH_LOCK:
        _RUNTIME_WATCH.discard(root)


def watch_roots() -> list[str]:
    with _RUNTIME_WATCH_LOCK:
        extra = sorted(_RUNTIME_WATCH)
    roots, seen = [], set()
    for root in [*DEFAULT_WATCH, *extra]:
        key = os.path.normcase(os.path.abspath(str(root)))
        if key not in seen:
            roots.append(str(root))
            seen.add(key)
    return roots
# The kernel driver pool — watched by NAME only (cheap: no hashing of hundreds of
# MB of .sys every cycle). A new .sys appearing here is the classic BYOVD staging
# step, so it is treated as a CRITICAL Ring 1 event.
DRIVER_DIR = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers")
SKIP_EXT = {".tmp", ".log", ".lock"}


class FileIntegrityModule(BaseModule):
    name = "File Integrity Monitor"
    description = "Detects unauthorized creation, modification, or deletion of watched files."
    category = "Integrity"

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, str] = {}
        self._driver_baseline: set = set()   # basenames of *.sys in DRIVER_DIR
        # path -> (mtime_ns, size) as of the last time we actually hashed it.
        # Lets _scan() skip re-hashing files that haven't changed, instead of
        # re-reading + SHA-256'ing every watched file on every single cycle.
        self._stat_cache: Dict[str, Tuple[int, int]] = {}

    def _hash(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _stat(self, path: str) -> Optional[Tuple[int, int]]:
        try:
            st = os.stat(path)
            return (st.st_mtime_ns, st.st_size)
        except Exception:
            return None

    def _scan(self) -> Dict[str, str]:
        """Incremental scan: a file only gets re-hashed if it's new to this
        scan or its (mtime, size) changed since the last time it was hashed.
        With thousands of watched files barely ever changing between 30s
        cycles, this turns a full re-hash of everything (which was pushing
        real-world detection latency to ~2 cycles — 60-90s — on a large
        Documents folder) into "stat everything, hash only what's new or
        different" — typically a handful of files, not thousands.

        Trade-off: a file rewritten with an identical mtime AND identical
        size (rare — usually requires a tool that deliberately preserves
        both) would be missed until something else about it changes. That's
        the standard mtime/size-cache trade-off (the same one rsync/git use)
        and is worth it here for the latency win; a paranoid mode that
        always re-hashes could be added behind an env var later if needed.
        """
        snap: Dict[str, str] = {}
        new_stat_cache: Dict[str, Tuple[int, int]] = {}
        for root in watch_roots():
            if not os.path.isdir(root):
                continue
            for dirpath, _, files in os.walk(root):
                for fn in files:
                    if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                        continue
                    full = os.path.join(dirpath, fn)
                    st = self._stat(full)
                    if st is None:
                        continue
                    cached_st = self._stat_cache.get(full)
                    if cached_st == st and full in self._baseline:
                        # Unchanged since last hash — reuse the known digest.
                        digest = self._baseline[full]
                    else:
                        digest = self._hash(full)
                    if digest:
                        snap[full] = digest
                        new_stat_cache[full] = st
                if self.stopping:
                    self._stat_cache = new_stat_cache
                    return snap
        self._stat_cache = new_stat_cache
        return snap

    # ── Ring 1: driver-shield classifier + cheap driver-pool scan ────────────
    def _driver_alert(self, path: str):
        """Classify a path for the Driver-Intel Shield. Returns (Severity, msg)
        or None. Pure — no I/O — so it is unit-testable. A known-vulnerable or
        drill driver, or ANY unexpected .sys write, is CRITICAL (BYOVD staging)."""
        base = os.path.basename(str(path)).lower()
        hit = is_known_bad_driver(base)
        if hit:
            kind = "BYOVD drill marker" if hit.get("drill") else "KNOWN-VULNERABLE driver"
            return (Severity.CRITICAL, f"{kind} written: {base} — {hit['reason']}")
        if base.endswith(".sys"):
            return (Severity.CRITICAL,
                    f"Unexpected kernel driver written: {base} "
                    f"(review — possible BYOVD staging)")
        return None

    def _list_driver_names(self) -> set:
        """Names of *.sys in the driver pool — listing only, never hashed."""
        try:
            return {e.name.lower() for e in os.scandir(DRIVER_DIR)
                    if e.is_file() and e.name.lower().endswith(".sys")}
        except Exception:
            return set()

    def self_test(self) -> tuple[bool, str]:
        a = self._driver_alert(r"C:\x\rtcore64.sys")                # known-vulnerable
        b = self._driver_alert(r"C:\x\angerona_byovd_drill.sys")    # benign drill
        c = self._driver_alert(r"C:\Users\me\notes.txt")           # benign non-driver
        ok = (a and a[0] == Severity.CRITICAL
              and b and b[0] == Severity.CRITICAL and c is None)
        return (ok, "driver-shield classifier verified (known-bad + drill flagged, "
                    "benign ignored)" if ok else f"classifier failed: a={a} b={b} c={c}")

    def run(self) -> None:
        self.emit("Building file-integrity baseline…", Severity.INFO)
        self._baseline = self._scan()
        self._driver_baseline = self._list_driver_names()
        self.emit(f"Baseline armed: {len(self._baseline)} files watched, "
                  f"{len(self._driver_baseline)} drivers.", Severity.INFO)

        while not self.stopping:
            self.sleep(30)
            if self.stopping:
                break
            current = self._scan()
            active_roots = [os.path.normcase(os.path.abspath(root))
                            for root in watch_roots()]
            def _still_watched(path: str) -> bool:
                candidate = os.path.normcase(os.path.abspath(path))
                for root in active_roots:
                    try:
                        if os.path.commonpath((candidate, root)) == root:
                            return True
                    except ValueError:
                        continue
                return False
            # Removing a transient drill sandbox from the runtime watch set is
            # a policy change, not deletion of every file it contained.
            base_keys = {path for path in self._baseline if _still_watched(path)}
            cur_keys = set(current)

            for path in cur_keys - base_keys:
                alert = self._driver_alert(path)
                if alert:
                    self.emit(alert[1], alert[0], path=path)
                else:
                    self.emit(f"New file created: {path}", Severity.MEDIUM, path=path)
            for path in base_keys - cur_keys:
                self.emit(f"Watched file deleted: {path}", Severity.HIGH, path=path)
            for path in base_keys & cur_keys:
                if self._baseline[path] != current[path]:
                    alert = self._driver_alert(path)
                    if alert:
                        self.emit(alert[1], alert[0], path=path)
                    else:
                        self.emit(f"Watched file modified: {path}", Severity.HIGH, path=path)

            # Cheap, name-only sweep of the kernel driver pool for new .sys files.
            cur_drivers = self._list_driver_names()
            for name in cur_drivers - self._driver_baseline:
                alert = self._driver_alert(name)
                sev, msg = alert if alert else (Severity.HIGH, f"New driver present: {name}")
                self.emit(msg, sev, driver=name, path=os.path.join(DRIVER_DIR, name))
            self._driver_baseline = cur_drivers

            self._baseline = current
