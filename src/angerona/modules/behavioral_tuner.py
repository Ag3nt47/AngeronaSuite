"""behavioral_tuner.py — Learning Engine + Safe-Path Interceptor (CODE: TUNE)

The inverse of the Fast-Path Interceptor (FPTH). Where FPTH *escalates* hard
IOCs to a microsecond verdict, TUNE *de-escalates* known-good behaviour so it
never reaches the AI at all.

Why this speeds Angerona up
---------------------------
`ai_triage.py` reads ``bus.recent(20)`` every ~8s and only spends an Ollama
inference on events whose severity is ``HIGH`` or above. So the cheapest way to
save GPU/GIL cycles is not to make inference faster — it's to make sure trusted,
repetitive PROC/FIM/NMON noise arrives *below* HIGH. TUNE learns what "normal"
looks like on this host, then downgrades matching events to ``INFO`` before the
triage loop sees them. The EventBus backpressure (INFO dropped at >=85% fill)
then clears them from memory naturally.

Lifecycle
---------
1. Silent Audit (learning) — for a configurable window (default 7 days from
   first launch) TUNE only observes: it records trusted process hashes,
   parent->child lineage, and per-process network boundaries into the
   ``behavioral_baseline`` SQLite table. It emits nothing actionable.
2. Behavioural fingerprinting — a trusted behaviour is a 3-way match, not a
   filename allowlist: (static SHA-256) + (parent->child lineage) + (network
   boundary: remote /24 subnet + port). All three must agree.
3. Safe-Path enforcement — after the window closes, other modules (or the triage
   loop) call ``check_event()`` / ``is_known_good()`` *before* queueing for
   inference. A perfect 3-way match downgrades severity to INFO.
4. Baseline drift — if a trusted app auto-updates (hash changes but lineage and
   network behaviour are unchanged) the stored hash is refreshed silently
   instead of firing a false MODIFIED alert.

Ring-0 offload (export_wfp_rules / export_kernel_rules)
-------------------------------------------------------
Python-level filtering still costs a bus round-trip and GIL time per event. The
export methods translate the learned baseline into rule payloads that the WFP
Controller (WFPC) and the AngeronaSensor.sys kernel driver can enforce at Ring-0,
so trusted traffic and trusted process launches are handled *below* Python and
never generate a bus event in the first place. These methods only *produce* the
payloads; WFPC / the sensor bridge own the actual DeviceIoControl / filter-add
calls — TUNE never touches the driver directly.

Standard library only (sqlite3, hashlib, threading, time, json, os).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from angerona.core.module_base import BaseModule, Severity


# ── DB path resolution ────────────────────────────────────────────────────────
def _resolve_db_path() -> str:
    """Locate flight-recorder.db without hard-coding a drive.

    Honours EDR_DB_PATH first, then the canonical D:-resident data root.
    """
    explicit = os.getenv("EDR_DB_PATH")
    if explicit:
        return explicit
    from angerona.core.data_paths import data_dir
    return str(data_dir() / "flight-recorder.db")


# ── Learning window default ───────────────────────────────────────────────────
_DEFAULT_LEARN_DAYS = 7.0
_LEARN_SECONDS_ENV  = "ANGERONA_TUNE_LEARN_SECONDS"   # override for testing

# Live-instance handle so other modules (e.g. ai_triage) can consult the
# safe-path baseline via get_tuner() without a manager reference.
_INSTANCE: "Optional[BehavioralTuner]" = None


class BehavioralTuner(BaseModule):
    """Learning engine + safe-path interceptor. Module code: TUNE."""

    name = "TUNE"
    CODE = "TUNE"
    description = "Behavioural learning engine; downgrades known-good PROC/FIM/NMON noise before AI triage."
    category = "Performance"
    version = "1.0.0"

    # Modules whose events are candidates for downgrade.
    WATCHED_MODULES = {"PROC", "FIM", "NMON", "LINEAGE", "NET"}

    def __init__(self, learn_days: float = _DEFAULT_LEARN_DAYS) -> None:
        super().__init__()
        # Test hook: ANGERONA_TUNE_LEARN_SECONDS wins over learn_days if set.
        env_secs = os.getenv(_LEARN_SECONDS_ENV)
        self._learn_seconds = float(env_secs) if env_secs else learn_days * 86400.0
        self._db_path = _resolve_db_path()
        self._db_lock = threading.Lock()
        self._db: Optional[sqlite3.Connection] = None
        self._first_launch_ts: float = time.time()
        self._cursor_ts: float = 0.0          # bus read watermark
        global _INSTANCE
        _INSTANCE = self   # expose to ai_triage's safe-path check
        self._learned = 0
        self._downgraded = 0

    # ── DB lifecycle ──────────────────────────────────────────────────────────
    def _connect(self) -> None:
        """Open the DB and ensure the baseline + metadata tables exist.

        check_same_thread=False because the daemon thread and any caller of
        check_event() may differ; every access is guarded by self._db_lock.
        busy_timeout lets us ride out concurrent writers instead of raising.
        """
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._db = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS behavioral_baseline (
                   fingerprint TEXT PRIMARY KEY,   -- module|proc|parent (identity, hash-independent)
                   module      TEXT,
                   proc_name   TEXT,
                   parent_name TEXT,
                   file_hash   TEXT,               -- current trusted SHA-256 (drifts on update)
                   net_subnet  TEXT,               -- trusted remote /24, or ''
                   net_port    INTEGER,            -- trusted remote port, or 0
                   seen_count  INTEGER DEFAULT 1,
                   first_seen  REAL,
                   last_seen   REAL
               )"""
        )
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS tune_meta (
                   key TEXT PRIMARY KEY, value TEXT
               )"""
        )
        # Persist first-launch so the learning window survives restarts.
        row = self._db.execute(
            "SELECT value FROM tune_meta WHERE key='first_launch_ts'"
        ).fetchone()
        if row:
            self._first_launch_ts = float(row[0])
        else:
            self._db.execute(
                "INSERT INTO tune_meta(key, value) VALUES('first_launch_ts', ?)",
                (str(self._first_launch_ts),),
            )
        self._db.commit()

    # ── Fingerprint helpers ───────────────────────────────────────────────────
    @staticmethod
    def _subnet(ip: str) -> str:
        """Collapse an IPv4 to its /24 so DHCP churn within a subnet still matches."""
        if not ip:
            return ""
        parts = ip.split(".")
        return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ""

    @classmethod
    def _identity(cls, module: str, details: dict) -> Optional[str]:
        """Hash-independent identity for a behaviour: module|proc|parent.

        Identity deliberately excludes the file hash so an auto-update (hash
        change, same identity) resolves to the same baseline row → drift, not a
        new/unknown behaviour.
        """
        proc = str(details.get("name") or details.get("proc_name") or
                   details.get("process") or details.get("path") or "").lower()
        if not proc:
            return None
        parent = str(details.get("parent_name") or details.get("ppid_name") or
                     details.get("parent") or "").lower()
        return f"{module}|{proc}|{parent}"

    @classmethod
    def _fingerprint(cls, module: str, details: dict) -> tuple[Optional[str], dict]:
        """Return (identity, extracted_fields). Never raises on missing keys."""
        identity = cls._identity(module, details)
        fields = {
            "module":      module,
            "proc_name":   str(details.get("name") or details.get("proc_name") or
                               details.get("process") or "").lower(),
            "parent_name": str(details.get("parent_name") or details.get("parent") or "").lower(),
            "file_hash":   str(details.get("hash") or details.get("file_hash") or ""),
            "net_subnet":  cls._subnet(str(details.get("raddr") or details.get("remote_ip") or
                                           details.get("dst") or "")),
            "net_port":    int(details.get("rport") or details.get("remote_port") or 0),
        }
        return identity, fields

    # ── Learning ──────────────────────────────────────────────────────────────
    def _in_learning(self) -> bool:
        return (time.time() - self._first_launch_ts) < self._learn_seconds

    def _learn(self, module: str, details: dict) -> None:
        """Record or reinforce a trusted behaviour. Safe under SQLite lock."""
        identity, f = self._fingerprint(module, details)
        if not identity:
            return
        try:
            with self._db_lock:
                now = time.time()
                existing = self._db.execute(
                    "SELECT file_hash, net_subnet, net_port FROM behavioral_baseline WHERE fingerprint=?",
                    (identity,),
                ).fetchone()
                if existing:
                    self._db.execute(
                        """UPDATE behavioral_baseline
                               SET seen_count = seen_count + 1, last_seen = ?,
                                   file_hash  = COALESCE(NULLIF(?, ''), file_hash),
                                   net_subnet = COALESCE(NULLIF(?, ''), net_subnet),
                                   net_port   = CASE WHEN ? > 0 THEN ? ELSE net_port END
                             WHERE fingerprint = ?""",
                        (now, f["file_hash"], f["net_subnet"],
                         f["net_port"], f["net_port"], identity),
                    )
                else:
                    self._db.execute(
                        """INSERT INTO behavioral_baseline
                               (fingerprint, module, proc_name, parent_name, file_hash,
                                net_subnet, net_port, seen_count, first_seen, last_seen)
                               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                        (identity, module, f["proc_name"], f["parent_name"], f["file_hash"],
                         f["net_subnet"], f["net_port"], now, now),
                    )
                    self._learned += 1
                self._db.commit()
        except sqlite3.Error:
            # A locked/busy DB must never kill the daemon — drop this sample.
            pass

    # ── Enforcement (public API) ──────────────────────────────────────────────
    def is_known_good(self, ev: Any) -> bool:
        """True if this bus Event perfectly matches a trusted 3-way fingerprint.

        Callers pass a bus Event (module, message, severity, ts, details). During
        the learning window this always returns False so nothing is suppressed.
        """
        if self._in_learning():
            return False
        module = getattr(ev, "module", "")
        if module not in self.WATCHED_MODULES:
            return False
        details = getattr(ev, "details", None) or {}
        return self.check_event(module, details) == Severity.INFO

    def check_event(self, module: str, details: dict) -> Optional[Severity]:
        """Classify an event's details against the baseline.

        Returns:
            Severity.INFO  — trusted 3-way match; caller should downgrade.
            None           — not recognised; caller keeps original severity.

        This is the method PROC/FIM/NMON (or the triage loop) call *before*
        queueing for Ollama. Never raises.
        """
        try:
            identity, f = self._fingerprint(module, details)
            if not identity:
                return None
            with self._db_lock:
                row = self._db.execute(
                    "SELECT file_hash, net_subnet, net_port FROM behavioral_baseline WHERE fingerprint=?",
                    (identity,),
                ).fetchone()
            if not row:
                return None
            base_hash, base_subnet, base_port = row

            # ── 3-way check ──────────────────────────────────────────────────
            # 1. Static hash: must match, OR trigger drift handling below.
            hash_ok = (not f["file_hash"]) or (f["file_hash"] == base_hash)
            # 2. Lineage: identity already encodes module|proc|parent, so a row
            #    hit means lineage matched.
            # 3. Network boundary: if the event carries network fields they must
            #    fall inside the trusted subnet/port; absent = not network-bearing.
            net_ok = True
            if f["net_subnet"] or f["net_port"]:
                net_ok = (f["net_subnet"] == base_subnet and
                          (f["net_port"] == base_port or base_port == 0))

            if hash_ok and net_ok:
                self._downgraded += 1
                return Severity.INFO

            # ── Drift handler ────────────────────────────────────────────────
            # Lineage + network identical but hash changed → benign auto-update.
            # Refresh the trusted hash silently; still treat this instance as
            # known-good so it doesn't spike a false MODIFIED alert.
            if net_ok and f["file_hash"] and f["file_hash"] != base_hash:
                try:
                    with self._db_lock:
                        self._db.execute(
                            "UPDATE behavioral_baseline SET file_hash=?, last_seen=? WHERE fingerprint=?",
                            (f["file_hash"], time.time(), identity),
                        )
                        self._db.commit()
                except sqlite3.Error:
                    pass
                self._downgraded += 1
                return Severity.INFO

            return None
        except Exception:
            # Enforcement must fail *open* (return None = keep original severity)
            # so a tuner bug can never blind the pipeline to a real threat.
            return None

    # ── Ring-0 rule offload ───────────────────────────────────────────────────
    def export_wfp_rules(self) -> list[dict]:
        """Translate the trusted network baseline into WFP-ingestible rules.

        Returns a list of {proc_name, subnet, port, action} dicts the WFP
        Controller (WFPC) can add as permit filters. Once WFP permits this
        (process, subnet, port) tuple at Ring-0, the packets never surface to the
        Python sniffer/NMON, eliminating the bus event and its GIL cost entirely.
        TUNE only builds the payload; WFPC performs the actual filter-add.
        """
        rules: list[dict] = []
        try:
            with self._db_lock:
                rows = self._db.execute(
                    """SELECT proc_name, net_subnet, net_port FROM behavioral_baseline
                           WHERE net_subnet != '' AND seen_count >= 5"""
                ).fetchall()
            for proc, subnet, port in rows:
                rules.append({"proc_name": proc, "subnet": subnet,
                              "port": int(port or 0), "action": "permit"})
        except sqlite3.Error:
            pass
        return rules

    def export_kernel_rules(self) -> dict:
        """Translate trusted hashes + ancestries into a kernel-driver payload.

        Returns a JSON-serialisable dict for AngeronaSensor.sys (delivered via
        DeviceIoControl by the sensor bridge). With trusted (hash, parent->child)
        launches allow-listed in the driver, the kernel silently passes them
        without generating an ETW/ProcMon event, so Python never processes the
        safe launch. TUNE only shapes the data; the sensor bridge owns the IOCTL.
        """
        payload = {"version": 1, "generated": time.time(),
                   "trusted_hashes": [], "trusted_lineage": []}
        try:
            with self._db_lock:
                rows = self._db.execute(
                    """SELECT proc_name, parent_name, file_hash FROM behavioral_baseline
                           WHERE file_hash != '' AND seen_count >= 5"""
                ).fetchall()
            for proc, parent, fhash in rows:
                payload["trusted_hashes"].append(fhash)
                if parent:
                    payload["trusted_lineage"].append({"parent": parent, "child": proc})
        except sqlite3.Error:
            pass
        return payload

    # ── Daemon loop ───────────────────────────────────────────────────────────
    def run(self) -> None:
        """Poll the bus. During the window, learn. After it, keep the baseline
        warm (drift + newly-trusted behaviours still get recorded)."""
        try:
            self._connect()
        except Exception as exc:
            self.set_health(0, f"DB init failed: {exc}")
            self.emit(f"TUNE could not open baseline DB: {exc}", Severity.MEDIUM)
            return

        announced = False
        while not self.stopping:
            self.sleep(8)
            if self._bus is None:
                continue

            learning = self._in_learning()
            if learning and not announced:
                remaining_h = max(0.0, (self._learn_seconds -
                                        (time.time() - self._first_launch_ts)) / 3600.0)
                self.emit(f"TUNE learning mode: building trusted baseline "
                          f"(~{remaining_h:.0f}h remaining).", Severity.INFO)
                announced = True

            try:
                for ev in self._bus.recent(20):
                    if ev.ts <= self._cursor_ts:
                        continue
                    self._cursor_ts = max(self._cursor_ts, ev.ts)
                    if ev.module not in self.WATCHED_MODULES:
                        continue
                    details = getattr(ev, "details", None) or {}
                    # Learn from everything we observe (learning window records
                    # aggressively; post-window we only reinforce/track drift).
                    if learning or ev.severity < Severity.HIGH:
                        self._learn(ev.module, details)
            except Exception as exc:
                self.set_health(60, f"bus poll error: {exc}")
                continue

            if learning:
                self.set_health(100, f"learning — {self._learned} behaviours baselined")
            else:
                if announced:   # transition out of learning: announce once
                    self.emit(f"TUNE enforcement active — {self._learned} trusted "
                              f"behaviours; suppressing known-good noise pre-triage.",
                              Severity.INFO)
                    announced = False
                self.set_health(100, f"enforcing — {self._downgraded} events downgraded")

    def self_test(self) -> tuple[bool, str]:
        """Verify the baseline table is reachable."""
        if self.status != "running":
            return super().self_test()   # not started yet — graceful "stopped" status
        try:
            with self._db_lock:
                n = self._db.execute("SELECT COUNT(*) FROM behavioral_baseline").fetchone()[0]
            phase = "learning" if self._in_learning() else "enforcing"
            return True, f"{phase}; {n} baselined behaviours"
        except Exception as exc:
            return False, f"baseline DB unreachable: {exc}"


def get_tuner() -> "Optional[BehavioralTuner]":
    """Return the live BehavioralTuner instance (or None if not yet created), so
    the AI-triage loop can consult the safe-path baseline before inference."""
    return _INSTANCE


def register() -> BaseModule:
    """ModuleManager entry point — returns the module instance to bind."""
    return BehavioralTuner()
