"""Bounded durable advisory index of authenticated gaps and patch attempts.

Original AARs and remediation journals remain the evidence authorities. This
index cannot grant a mutation, declare a clean host or resist whole-root replay.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time

from angerona.core import report_attest


MAX_REPORTS = 512
MAX_GAPS = 1024
MAX_ATTEMPTS = 2048
MAX_DATABASE_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MITRE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS patch_reports (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS patch_gaps (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS patch_attempts (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS patch_memory_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), held INTEGER NOT NULL);
INSERT OR IGNORE INTO patch_memory_meta VALUES(1,0);
"""


def _text(value, limit=160):
    return " ".join(value.split())[:limit] if type(value) is str else ""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def report_classification(report):
    """Authenticity and complete benchmark eligibility remain distinct."""
    try:
        if type(report) is not dict or len(_canonical(report)) > 2 * 1024 * 1024:
            return "unverified", "report-shape-or-budget"
        if report_attest.verify(report) != "ok":
            return "unverified", "report-authentication-unavailable"
        if report.get("diagnostic_only") is True:
            return "diagnostic", "authenticated-incomplete-run"
        if report.get("coverage_score_eligible") is not True:
            return "diagnostic", "coverage-not-verified"
        if (report.get("report_kind") not in {"red_team", "shark"}
                or type(report.get("run_id")) is not str
                or not 1 <= len(report["run_id"]) <= 160
                or report["run_id"] != _text(report["run_id"])
                or type(report.get("verdicts")) is not list
                or len(report["verdicts"]) > 512):
            return "unverified", "report-contract-unavailable"
        return "verified-practice", "authenticated-complete-benchmark"
    except Exception:
        return "unverified", "report-verification-unavailable"


def reported_gaps(report):
    """Extract only complete, authenticated benchmark gaps; never host targets."""
    classification, _reason = report_classification(report)
    if classification != "verified-practice":
        return []
    grouped = {}
    for verdict in report["verdicts"]:
        if type(verdict) is not dict or verdict.get("category") != "detection":
            continue
        if verdict.get("caught") is False:
            gap_kind = "detection"
        elif verdict.get("caught") is True and verdict.get("target_containment_verified") is False:
            gap_kind = "response"
        else:
            continue
        technique = _text(verdict.get("technique_id"), 32).upper()
        if not _MITRE.fullmatch(technique):
            first = _text(verdict.get("technique"), 160).split(maxsplit=1)
            technique = first[0].upper() if first else ""
        if not _MITRE.fullmatch(technique):
            technique = "unmapped"
        identity = {"source": report["report_kind"], "technique": technique, "gap_kind": gap_kind}
        gap_id = hashlib.sha256(_canonical(identity)).hexdigest()
        row = grouped.setdefault(gap_id, {"gap_id": gap_id, **identity,
            "name": _text(verdict.get("stage") or verdict.get("technique")),
            "evidence_scope": "practice", "occurrences_in_report": 0,
            "sensor_observations": 0, "native_analytics": 0,
            "simulation_validations": 0, "verified_responses": 0})
        row["occurrences_in_report"] += 1
        row["sensor_observations"] += int(verdict.get("observed") is True)
        row["native_analytics"] += int(verdict.get("native_analytic_detected") is True)
        row["simulation_validations"] += int(verdict.get("simulation_validated") is True)
        row["verified_responses"] += int(verdict.get("target_containment_verified") is True)
    return list(grouped.values())


class PatchMemory:
    """Small signed advisory rows, bounded admission and no destructive pruning."""

    def __init__(self, root):
        self.root = Path(root)
        self.path = self.root / "patch-memory.db"
        self._lock = threading.RLock()
        self._check_path()
        with self._connect() as db:
            db.executescript(_SCHEMA)

    def _check_path(self):
        for path in (*reversed(self.path.parents), self.path):
            if not os.path.lexists(path):
                continue
            row = path.lstat()
            if stat.S_ISLNK(row.st_mode) or getattr(row, "st_file_attributes", 0) & 0x400:
                raise ValueError("Patch memory path is redirected")
            if path == self.path and (not stat.S_ISREG(row.st_mode) or row.st_nlink != 1):
                raise ValueError("Patch memory is not one ordinary file")
            if path == self.path and row.st_size > MAX_DATABASE_BYTES:
                raise ValueError("Patch memory exceeds its on-disk budget")

    def _connect(self):
        self._check_path()
        db = sqlite3.connect(self.path, timeout=2)
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
            maximum_pages = MAX_DATABASE_BYTES // page_size
            if int(db.execute(f"PRAGMA max_page_count={maximum_pages}").fetchone()[0]) > maximum_pages:
                raise ValueError("Patch memory page admission is unavailable")
        except Exception:
            db.close()
            raise
        return closing(db)

    @staticmethod
    def _encode(body):
        signed = report_attest.attest(dict(body))
        if report_attest.verify(signed) != "ok":
            raise ValueError("Authenticated patch memory signing is unavailable")
        encoded = _canonical(signed)
        if len(encoded) > 16 * 1024:
            raise ValueError("Patch memory row exceeds its budget")
        return encoded.decode("ascii")

    @staticmethod
    def _decode(encoded):
        try:
            row = json.loads(encoded)
            if type(row) is dict and report_attest.verify(row) == "ok":
                return row
        except Exception:
            pass
        return None

    @staticmethod
    def _held(db, reason):
        db.execute("UPDATE patch_memory_meta SET held=held+1 WHERE singleton=1")
        db.commit()
        return {"stored": False, "held": True, "reason": reason, "response_authorized": False}

    def remember_report(self, report):
        classification, reason = report_classification(report)
        try:
            if type(report) is not dict:
                raise ValueError("report-shape")
            raw = _canonical(report)
        except (TypeError, ValueError, RecursionError):
            return {"stored": False, "held": True, "reason": "report-shape", "response_authorized": False}
        if len(raw) > 2 * 1024 * 1024:
            return {"stored": False, "held": True, "reason": "report-budget", "response_authorized": False}
        report_id = hashlib.sha256(raw).hexdigest()
        run_id = _text(report.get("run_id"))
        run_key = hashlib.sha256(_canonical({"source": _text(report.get("report_kind"), 32),
                                            "run_id": run_id or report_id})).hexdigest()
        now = int(time.time())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM patch_reports WHERE id=?", (run_key,)).fetchone():
                return {"stored": True, "duplicate": True, "classification": classification,
                        "scope": "First indexed generation per run; refreshes do not invent recurrences",
                        "response_authorized": False}
            if db.execute("SELECT count(*) FROM patch_reports").fetchone()[0] >= MAX_REPORTS:
                return self._held(db, "report-index-capacity")
            gaps = reported_gaps(report) if classification == "verified-practice" else []
            existing_count = int(db.execute("SELECT count(*) FROM patch_gaps").fetchone()[0])
            new_count = sum(not db.execute("SELECT 1 FROM patch_gaps WHERE id=?", (gap["gap_id"],)).fetchone()
                            for gap in gaps)
            if existing_count + new_count > MAX_GAPS:
                return self._held(db, "gap-index-capacity")
            for gap in gaps:
                previous = db.execute("SELECT body FROM patch_gaps WHERE id=?", (gap["gap_id"],)).fetchone()
                old = self._decode(previous[0]) if previous else None
                if previous and old is None:
                    db.rollback()
                    return self._held(db, "gap-index-authentication")
                body = {**gap, "first_seen": old["first_seen"] if old else now,
                        "last_seen": now, "last_report": report_id,
                        "last_run_id": _text(report.get("run_id")), "status": "OPEN",
                        "occurrences": int(old.get("occurrences", 0) if old else 0) + gap["occurrences_in_report"],
                        "run_occurrences": int(old.get("run_occurrences", 0) if old else 0) + 1,
                        "recurrences_after_patch": int(old.get("recurrences_after_patch", 0) if old else 0),
                        "last_patch_status": old.get("last_patch_status", "none") if old else "none"}
                if old and old.get("last_patch_status") == "applied-verified":
                    body["recurrences_after_patch"] += gap["occurrences_in_report"]
                db.execute("INSERT INTO patch_gaps VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                           (gap["gap_id"], self._encode(body)))
            report_row = {"schema": 1, "report_id": report_id, "run_id": _text(report.get("run_id")),
                          "source": _text(report.get("report_kind"), 32), "classification": classification,
                          "reason": reason, "seen": now, "gap_classes": len(gaps),
                          "response_authorized": False}
            db.execute("INSERT INTO patch_reports VALUES(?,?)", (run_key, self._encode(report_row)))
            db.commit()
        return {"stored": True, "duplicate": False, "classification": classification,
                "gap_classes": len(gaps), "response_authorized": False}

    def record_attempt(self, attempt):
        body = dict(attempt)
        identity = body.get("attempt_id")
        if type(identity) is not str or not _HASH.fullmatch(identity):
            raise ValueError("Patch attempt needs an exact bounded identity")
        body["last_seen"] = int(time.time())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            exists = db.execute("SELECT 1 FROM patch_attempts WHERE id=?", (identity,)).fetchone()
            if not exists and db.execute("SELECT count(*) FROM patch_attempts").fetchone()[0] >= MAX_ATTEMPTS:
                return self._held(db, "attempt-index-capacity")
            db.execute("INSERT INTO patch_attempts VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                       (identity, self._encode(body)))
            if body.get("state") in {"applied-verified", "rolled-back"} and _HASH.fullmatch(str(body.get("gap_id", ""))):
                row = db.execute("SELECT body FROM patch_gaps WHERE id=?", (body["gap_id"],)).fetchone()
                gap = self._decode(row[0]) if row else None
                if gap:
                    gap["last_patch_status"] = body["state"]
                    db.execute("UPDATE patch_gaps SET body=? WHERE id=?", (self._encode(gap), body["gap_id"]))
            db.commit()
        return {"stored": True, "response_authorized": False}

    def snapshot(self):
        result = {"gaps": [], "attempts": [], "incidents": [], "unverified_rows": 0,
                  "admission_held": 0, "response_authorized": False,
                  "scope": "Bounded local advisory index; original authenticated evidence remains separate"}
        with self._lock, self._connect() as db:
            result["admission_held"] = int(db.execute("SELECT held FROM patch_memory_meta WHERE singleton=1").fetchone()[0])
            result["totals"] = {name: int(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
                for name, table in (("gaps", "patch_gaps"), ("attempts", "patch_attempts"), ("incidents", "patch_reports"))}
            for table, destination, limit in (("patch_gaps", "gaps", 128),
                                               ("patch_attempts", "attempts", 128),
                                               ("patch_reports", "incidents", 64)):
                for _identity, encoded in db.execute(f"SELECT id,body FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)):
                    row = self._decode(encoded)
                    if row is None:
                        result["unverified_rows"] += 1
                    else:
                        result[destination].append(row)
        return result
