"""
posture_hardening.py — Autonomous, self-healing Posture Hardening Loop.

Watches the red-team after-action report; any technique that SUCCEEDED (or was
caught only at LOW-DETECTION-STRENGTH) is recorded as a system weakness, drops
this module's health below 50 (orange/red on the status strip), and gets a
deterministic local-LLM–generated PowerShell/registry remediation staged for
REVIEW. Nothing is ever auto-executed — the user inspects and authorizes.
Drop-in BaseModule for AngeronaSuite; imports standalone for testing.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

from angerona.core.win import run_hidden, popen_hidden

# ── AngeronaSuite integration, with a standalone fallback for testing ────────
try:
    from angerona.core.module_base import BaseModule
    from angerona.core.eventbus import Severity
    from angerona.core.config import Config
    _HAVE_SUITE = True
except Exception:                                   # pragma: no cover
    _HAVE_SUITE = False
    class Severity:                                 # minimal stand-in
        INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    class BaseModule:
        name = "base"; description = ""; category = ""; version = "1.0.0"
        enabled_by_default = True
        def __init__(self): self.health = 100; self.health_note = ""; self.status = "stopped"
        def set_health(self, pct, note=""): self.health = max(0, min(100, int(pct))); self.health_note = note
        def emit(self, *a, **k): pass
        def sleep(self, s): time.sleep(min(s, 0.02))
        @property
        def stopping(self): return getattr(self, "_stopflag", False)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.getenv("MODEL_NAME", "llama3:latest")

# Tamper-evident structured logger (Judgment loop signs off / flags through it).
try:
    from angerona.engines import edr_logger as _edrlog
except Exception:                                   # standalone/test fallback
    _edrlog = None


def _edr(level: str, msg: str) -> None:
    try:
        if _edrlog is not None:
            getattr(_edrlog, level)("HARD", msg)
    except Exception:
        pass

# A-03 destructive-command denylist — single source of truth reused from the
# CVE fix advisor so model-authored remediations get the same scan as CVE fixes.
try:
    from angerona.core.cve_fix_advisor import scan_powershell as _scan_ps
except Exception:                                   # standalone/test fallback
    def _scan_ps(script: str) -> list:              # pragma: no cover
        return []

_SYS_REMEDIATE = (
    "You are an automated Windows Posture Hardening Engine. You are receiving a "
    "security vulnerability JSON layout successfully exploited by an adversary. "
    "Generate ONLY a safe, non-destructive, executable PowerShell or Registry "
    "command script to remediate this specific Windows vulnerability. Do not "
    "include markdown formatting wraps, code blocks, backticks, explanations, or "
    "conversational text. Output raw executable string payload only."
)
_SYS_SANDBOX = (
    "You are a secure Windows Sandbox Parser. The user has provided custom "
    "mitigation code or logic. Validate its safety, correct any syntax errors, "
    "and output ONLY a clean, runnable PowerShell script that safely achieves the "
    "user's intended target configuration. Do not include markdown wraps, "
    "formatting, or explanations."
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS system_weaknesses (
    mitre_technique_id TEXT PRIMARY KEY,
    technique_name TEXT,
    severity TEXT,
    last_tested_epoch INTEGER,
    status TEXT DEFAULT 'VULNERABLE',      -- 'VULNERABLE' or 'PATCHED'
    remediation_script_path TEXT,
    source TEXT DEFAULT 'host'
);
-- Judgment Gate: SHA-256 of every staged remediation script, stamped the moment
-- it is written. execute_remediation() re-hashes the file on disk and refuses to
-- run if it no longer matches — so a script swapped out after review never runs.
CREATE TABLE IF NOT EXISTS remediation_hashes (
    mitre_technique_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    script_path TEXT,
    stamped_epoch INTEGER
);
"""


def _default_data_dir() -> Path:
    if _HAVE_SUITE:
        try:
            return Config.load().data_dir
        except Exception:
            pass
    from angerona.core.data_paths import data_dir
    return data_dir()


def _ollama(system: str, user: str, timeout: int = 60) -> str | None:
    """Deterministic (temperature 0) local Ollama call. Returns raw text or None."""
    try:
        import requests
    except Exception:
        return None
    try:
        r = requests.post(f"{OLLAMA_HOST}/api/generate", timeout=timeout, json={
            "model": MODEL, "stream": False, "keep_alive": "30m",
            "options": {"temperature": 0}, "system": system, "prompt": user,
        })
        r.raise_for_status()
        return (r.json().get("response") or "").strip() or None
    except Exception:
        return None


class PostureHardening(BaseModule):
    name = "Posture Hardening"
    description = "Self-healing loop: turns red-team SUCCESS into staged, review-gated OS hardening."
    category = "SOAR"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self, data_dir=None) -> None:
        super().__init__()
        self.data_dir = Path(data_dir) if data_dir else _default_data_dir()
        self.db_path = self.data_dir / "agent_memory.db"
        self.remediations = self.data_dir / "remediations"
        self.aar_path = self._locate_aar()
        # Red Team drills write their AAR here (report_basename="redteam_aar");
        # Posture Hardening tails it too, so it learns from BOTH drills.
        self.redteam_aar_path = self.data_dir / "redteam_aar.json"
        self.remediations.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._seen: set[tuple] = set()
        self._ctx: dict = {}          # mitre_id -> round context, for on-demand fixes
        self._certified: set = set()  # technique_ids whose mitigation the gate has certified
        self._init_db()

    # ── 1. DB SCHEMA & STATE ─────────────────────────────────────────────────
    def _init_db(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.executescript(_SCHEMA)
            cols = {row[1] for row in c.execute("PRAGMA table_info(system_weaknesses)")}
            if "source" not in cols:
                c.execute("ALTER TABLE system_weaknesses ADD COLUMN source TEXT DEFAULT 'host'")

    def _locate_aar(self) -> Path:
        for cand in (self.data_dir / "shared_logs" / "after_action_report.json",
                     self.data_dir / "after_action_report.json"):
            if cand.exists():
                return cand
        return self.data_dir / "shared_logs" / "after_action_report.json"

    def record_weakness(self, mitre_id, name, severity, remediation_path=None,
                        source="host") -> None:
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                "INSERT INTO system_weaknesses(mitre_technique_id,technique_name,severity,"
                "last_tested_epoch,status,remediation_script_path,source) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(mitre_technique_id) DO UPDATE SET technique_name=excluded.technique_name,"
                "severity=excluded.severity,last_tested_epoch=excluded.last_tested_epoch,"
                "status='VULNERABLE',remediation_script_path=excluded.remediation_script_path,"
                "source=excluded.source",
                (mitre_id, name, severity, int(time.time()), "VULNERABLE",
                 remediation_path, source))

    def weaknesses(self, status=None, source=None) -> list[dict]:
        q = ("SELECT mitre_technique_id,technique_name,severity,last_tested_epoch,"
             "status,remediation_script_path,source FROM system_weaknesses")
        clauses, args = [], []
        if status:
            clauses.append("status=?"); args.append(status)
        if source:
            clauses.append("source=?"); args.append(source)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        with closing(sqlite3.connect(self.db_path)) as c, c:
            rows = c.execute(q, tuple(args)).fetchall()
        keys = ["mitre_id", "name", "severity", "last_tested_epoch", "status",
                "remediation_script_path", "source"]
        return [dict(zip(keys, r)) for r in rows]

    def mark_patched(self, mitre_id) -> None:
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute("UPDATE system_weaknesses SET status='PATCHED' WHERE mitre_technique_id=?", (mitre_id,))
        self._recompute_health()

    # ── JUDGMENT GATE: staged-script integrity (SHA-256) ─────────────────────
    @staticmethod
    def _sha256_file(path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _stamp_hash(self, mitre_id: str, path: str) -> str:
        """Record the SHA-256 of a freshly written remediation script. Called by
        every code path that writes a staged script, so the stored digest always
        reflects the exact bytes we intend to run later."""
        try:
            digest = self._sha256_file(path)
        except Exception as exc:
            self.last_error = f"stamp {mitre_id}: {exc}"
            return ""
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                "INSERT INTO remediation_hashes(mitre_technique_id,sha256,script_path,stamped_epoch)"
                " VALUES(?,?,?,?) ON CONFLICT(mitre_technique_id) DO UPDATE SET"
                " sha256=excluded.sha256,script_path=excluded.script_path,"
                " stamped_epoch=excluded.stamped_epoch",
                (mitre_id, digest, str(path), int(time.time())))
        return digest

    def _stored_hash(self, mitre_id: str):
        """The SHA-256 stamped for a technique's staged script, or None."""
        with closing(sqlite3.connect(self.db_path)) as c, c:
            row = c.execute("SELECT sha256 FROM remediation_hashes WHERE mitre_technique_id=?",
                            (mitre_id,)).fetchone()
        return row[0] if row else None

    def _verify_hash(self, mitre_id: str, path: str) -> tuple[bool, str]:
        """Re-hash the on-disk script and compare to the stamped digest. Returns
        (ok, detail). Missing stamp or any mismatch is treated as tampering."""
        with closing(sqlite3.connect(self.db_path)) as c, c:
            row = c.execute(
                "SELECT sha256 FROM remediation_hashes WHERE mitre_technique_id=?",
                (mitre_id,)).fetchone()
        if not row:
            return False, "no stamped hash on record (script was never staged through the gate)"
        stored = row[0]
        try:
            actual = self._sha256_file(path)
        except Exception as exc:
            return False, f"could not hash script: {exc}"
        if actual != stored:
            return False, f"hash mismatch (stamped {stored[:12]}…, on-disk {actual[:12]}…)"
        return True, actual

    # ── Attempted-fixes log (judge the AI's decisions + implementation) ──────
    def _log_attempt(self, action: str, mitre_id: str, **fields) -> None:
        """Append a structured record of a remediation decision to
        diagnostics/remediation_attempts.log so an operator can review exactly
        what the local AI proposed and whether it was staged / applied / blocked."""
        try:
            from angerona.core.data_paths import data_dir
            path = data_dir() / "diagnostics" / "remediation_attempts.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "action": action,
                   "mitre": mitre_id, **fields}
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except Exception:
            pass

    # ── 2. FILE-OBSERVER AUTOMATION ──────────────────────────────────────────
    def run(self) -> None:
        mtimes: dict = {}
        while not self.stopping:
            # Tail BOTH the shark after-action report and the Red Team AAR.
            for path, ingest in ((self.aar_path, self.ingest_report),
                                 (self.redteam_aar_path, self.ingest_redteam_report)):
                try:
                    if path.exists():
                        m = path.stat().st_mtime
                        if m != mtimes.get(str(path)):
                            mtimes[str(path)] = m
                            ingest(path)
                except Exception as exc:
                    self.last_error = str(exc)
            self.sleep(2.0)

    def ingest_report(self, path: Path) -> list[dict]:
        try:
            session = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return []
        new = []
        for r in session.get("rounds", []):
            verdict = str(r.get("verdict", "")).upper()
            low_det = r.get("detection_strength") in ("LOW", "LOW-DETECTION-STRENGTH") or \
                      r.get("first_strike") is False
            if verdict != "SUCCESS" and not low_det:
                continue
            mitre = r.get("mitre") or r.get("mitre_technique_id") or r.get("technique", "T0000")
            key = (mitre, r.get("attempts", [{}])[-1].get("attack_epoch") if r.get("attempts") else 0)
            if key in self._seen:
                continue
            self._seen.add(key)
            name = r.get("name", r.get("technique", "unknown"))
            sev = r.get("severity", "High")
            self._ctx[mitre] = r                       # remember for on-demand fix
            rpath = self._stage_placeholder(mitre, name)   # instant — NO Ollama at drill time
            self.record_weakness(mitre, name, sev, rpath, source="shark")
            new.append({"mitre": mitre, "name": name})
            self.emit(f"NEW WEAKNESS: {name} ({mitre}) exploited — staged remediation for review",
                      Severity.HIGH, mitre=mitre, remediation=rpath)
        if new:
            self._recompute_health()
            # Opt-in active patching: after a drill records weaknesses, apply the
            # VETTED, reversible remediation library automatically. Default OFF —
            # set ANGERONA_AUTO_REMEDIATE=1 to enable real host changes.
            try:
                from angerona.modules import remediation_actions as _ra
                if _ra._auto_apply_enabled():
                    self.apply_vetted_remediation(apply=True)
            except Exception:
                pass
        return new

    def ingest_redteam_report(self, path: Path) -> list[dict]:
        """Learn from a Red Team drill's AAR (redteam_aar.json): any
        'detection'-category step the defenders did NOT catch becomes a tracked
        weakness in the same system_weaknesses table, so Attempt Fix / hardening
        covers Red Team findings too. The Red Team report uses the aar_report
        'verdicts' schema (stage/technique/category/caught), not 'rounds'."""
        try:
            report = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return []
        new = []
        verified = 0
        run_id = str(report.get("run_id") or "")
        try:
            from angerona.modules.purple_guard import _read_policy
            purple_policies = _read_policy(self.data_dir).get("techniques", {})
            if not isinstance(purple_policies, dict):
                purple_policies = {}
        except Exception:
            purple_policies = {}
        for v in report.get("verdicts", []):
            if v.get("category") != "detection":
                continue
            tech = str(v.get("technique", "")).strip()
            mitre = tech.split()[0] if tech[:1].upper() == "T" else ("RT-" + str(v.get("stage", "?")))
            if v.get("caught"):
                # Proof must come from the exact installed candidate in a fresh
                # run. Re-rendering the candidate's source AAR must never
                # self-certify a fix, nor may an unrelated detector close it.
                candidate = purple_policies.get(mitre)
                candidate_run = (str(candidate.get("candidate_from_run") or "")
                                 if isinstance(candidate, dict) else "")
                fresh_candidate_proof = (
                    bool(run_id and candidate_run and run_id != candidate_run)
                    and v.get("detected_by") == "Purple Remediation Guard"
                )
                if not fresh_candidate_proof:
                    continue
                with closing(sqlite3.connect(self.db_path)) as c, c:
                    changed = c.execute(
                        "UPDATE system_weaknesses SET status='PATCHED', last_tested_epoch=? "
                        "WHERE mitre_technique_id=? AND source='redteam'",
                        (int(time.time()), mitre)).rowcount
                if changed:
                    verified += int(changed)
                    self._log_attempt("drill_fix_verified", mitre, run_id=run_id,
                                      detected_by=v.get("detected_by"),
                                      latency=v.get("detect_latency_s"))
                continue
            key = ("redteam", mitre, v.get("ts_start"))
            if key in self._seen:
                continue
            self._seen.add(key)
            name = v.get("stage") or tech or "Red Team finding"
            self._ctx[mitre] = {"objective": v.get("description", ""), "target": "Red Team"}
            self.record_weakness(mitre, name, "High", None, source="redteam")
            new.append({"mitre": mitre, "name": name})
            self.emit(f"NEW WEAKNESS (Red Team): {name} ({mitre}) slipped past detection — "
                      f"a reviewed detector candidate can be installed and verified by rerun",
                      Severity.HIGH, mitre=mitre, run_id=run_id,
                      remediation="purple-guard-candidate")
        if new or verified:
            self._recompute_health()
        if new:
            # Opt-in active patching: after a drill records weaknesses, apply the
            # VETTED, reversible remediation library automatically. Default OFF —
            # set ANGERONA_AUTO_REMEDIATE=1 to enable real host changes.
            try:
                from angerona.modules import remediation_actions as _ra
                if _ra._auto_apply_enabled():
                    self.apply_vetted_remediation(apply=True)
            except Exception:
                pass
        return new

    def resolve_redteam_report(self, path=None) -> dict:
        """Install exact detector candidates for misses; never self-certify.

        The current run's duplicate alerts are acknowledged, but its database
        weaknesses stay VULNERABLE. Only a later AAR containing a real detector
        echo can transition them to PATCHED.
        """
        report_path = Path(path or self.redteam_aar_path)
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"ok": False, "error": f"could not read drill report: {exc}"}
        findings = []
        for verdict in report.get("verdicts", []):
            if verdict.get("category") != "detection" or verdict.get("caught"):
                continue
            tech = str(verdict.get("technique", "")).strip()
            mitre = tech.split()[0] if tech[:1].upper() == "T" else (
                "RT-" + str(verdict.get("stage", "?")))
            findings.append({"mitre": mitre,
                             "name": verdict.get("stage") or tech or "Red Team finding"})
        if not findings:
            return {"ok": True, "candidates": 0, "findings": [],
                    "message": "No missed detection findings need a candidate."}

        from angerona.core import drill_resolution
        from angerona.modules.purple_guard import install_policies
        run_id = str(report.get("run_id") or "")
        # Acknowledge this run's alert burst so it no longer dominates the threat
        # banner, while retaining VULNERABLE status until a rerun proves the fix.
        acknowledged = drill_resolution.resolve(findings, run_id, self.data_dir)
        installed = install_policies(findings, run_id, self.data_dir)
        ids = list(installed.get("installed", []))
        self._recompute_health()
        self._log_attempt("install_drill_detector_candidates", "-", run_id=run_id,
                          report=str(report_path), techniques=ids,
                          unsupported=installed.get("unsupported", []))
        self.emit(f"Installed {len(ids)} reviewed Purple Guard detector candidate(s) for "
                  f"run {run_id or 'unknown'}; rerun the drill to verify them.",
                  Severity.INFO, run_id=run_id, candidate_techniques=ids)
        return {"ok": True, "candidates": len(ids), "findings": acknowledged,
                "unsupported": installed.get("unsupported", []), "run_id": run_id,
                "verification_required": True}

    def _recompute_health(self) -> None:
        vuln = len(self.weaknesses("VULNERABLE"))
        if vuln == 0:
            self.set_health(100, "posture clean")
        else:
            # any open weakness forces the module below 50 (orange/red strip)
            self.set_health(max(5, 45 - vuln * 5), f"{vuln} unremediated weakness(es)")

    # ── 3. DETERMINISTIC LOCAL LLM ORCHESTRATION ─────────────────────────────
    def _generate_remediation(self, mitre, name, severity, round_obj) -> str:
        payload = json.dumps({"mitre_technique_id": mitre, "technique_name": name,
                              "severity": severity, "objective": round_obj.get("objective", ""),
                              "target_module": round_obj.get("target", "")}, indent=2)
        script = _ollama(_SYS_REMEDIATE, payload)
        out = self.remediations / f"{mitre}.ps1"
        if not script:
            script = (f"# Ollama unavailable — staged placeholder for {mitre} ({name}).\n"
                      f"# Review the coverage gap and add a WDAC/ACL/registry hardening rule.\n")
        else:
            # A-03 gate: never stamp/stage a model-authored remediation that
            # contains destructive constructs — a poisoned model could steer a
            # wipe / AV-disable / account-add into the review-gated library.
            danger = _scan_ps(script)
            if danger:
                self._log_attempt("blocked_destructive_generate", mitre, name=name,
                                  constructs=danger, script_preview=script[:1000])
                self.emit(f"REFUSED remediation for {mitre}: local-AI output contained "
                          f"destructive constructs ({', '.join(danger)}) — nothing staged.",
                          Severity.HIGH, mitre=mitre, destructive=True)
                script = (f"# REFUSED: local-AI remediation for {mitre} ({name}) contained "
                          f"destructive/high-risk constructs ({', '.join(danger)}).\n"
                          f"# Nothing was staged. Review the coverage gap and add a vetted "
                          f"WDAC/ACL/registry hardening rule by hand.\n")
        out.write_text(script, encoding="utf-8")
        self._stamp_hash(mitre, str(out))          # Judgment Gate: stamp on write
        return str(out)

    def _stage_placeholder(self, mitre, name) -> str:
        """Instant, Ollama-free stub written at drill time. The real remediation
        is generated lazily by generate_remediation() when the user clicks
        'Attempt Fix' — so a drill never blocks on / contends for the LLM/VRAM."""
        out = self.remediations / f"{mitre}.ps1"
        if not out.exists():
            out.write_text(
                f"# Remediation for {mitre} ({name}) — click 'Attempt Fix' to have the\n"
                f"# local AI generate a reviewed hardening script for this weakness.\n",
                encoding="utf-8")
        self._stamp_hash(mitre, str(out))          # Judgment Gate: stamp on write
        return str(out)

    def generate_remediation(self, mitre_id: str, timeout: int = 45) -> dict:
        """On-demand: ask Ollama (temperature 0) for a real remediation for a
        known weakness and overwrite its staged script. Returns the script text.
        Intended to be called from a background thread (the 'Attempt Fix' button)."""
        w = next((x for x in self.weaknesses() if x["mitre_id"] == mitre_id), None)
        if not w:
            return {"ok": False, "error": "unknown weakness"}
        if w.get("source") == "redteam":
            return {"ok": False, "error": ("simulated detection gaps use deterministic report "
                                             "resolution, not host PowerShell")}
        r = self._ctx.get(mitre_id, {"objective": "", "target": ""})
        path = self._generate_remediation(mitre_id, w["name"], w["severity"], r)
        script = Path(path).read_text(encoding="utf-8")
        self._log_attempt("ai_generate", mitre_id, name=w["name"], severity=w["severity"],
                          path=path, sha256=self._verify_hash(mitre_id, path)[1],
                          script_preview=script[:1000], review_required=True)
        return {"ok": True, "mitre": mitre_id, "path": path, "script": script,
                "review_required": True}

    # ── VETTED ACTIVE REMEDIATION (real, reversible fixes; not model-authored) ─
    def apply_vetted_remediation(self, apply: bool = False) -> dict:
        """Run the vetted, reversible remediation library over the current open
        weaknesses — REAL active patching (quarantine files, disable a BYOVD
        driver service, …). Safe by default: apply=False is a dry-run PLAN;
        apply=True applies non-host actions; host-level (registry/service) changes
        also require ANGERONA_AUTO_REMEDIATE=1. Applied+verified weaknesses are
        marked PATCHED; a failed verify auto-rolls-back. See remediation_actions.py."""
        from angerona.modules import remediation_actions as ra
        weaknesses = [w for w in self.weaknesses(status="VULNERABLE")
                      if w.get("source") != "redteam"]
        if not apply:
            plan = ra.plan_remediation(weaknesses)
            self._log_attempt("vetted_plan", "-", plan=plan)
            return {"applied": 0, "skipped": len(weaknesses), "plan": plan}

        def _log(level, msg):
            self._log_attempt("vetted_" + level.lower(), "-", msg=msg)
            self.emit(msg, Severity.HIGH if level == "CRITICAL" else Severity.INFO)

        res = ra.apply_remediation(weaknesses, self.data_dir / "quarantine",
                                   apply=True, log=_log,
                                   trigger="PostureHardening",
                                   db_path=self.data_dir / "flight-recorder.db")
        for rec in res.get("records", []):
            if rec.get("verified") and rec.get("mitre"):
                self.mark_patched(rec["mitre"])   # it's actually fixed now
        return res

    # ── 4. SECURITY AUTHORIZATION GATE & SANDBOX INTERFACE ───────────────────
    def execute_remediation(self, mitre_id: str, authorized: bool = False) -> dict:
        """Review gate: a staged remediation runs ONLY when the user passes
        authorized=True after inspecting it. Never auto-executes."""
        rows = self.weaknesses()
        match = next((w for w in rows if w["mitre_id"] == mitre_id), None)
        if not match or not match["remediation_script_path"]:
            return {"ok": False, "error": "no staged remediation"}
        if match.get("source") == "redteam":
            return {"ok": False, "error": ("simulated detection gaps cannot be repaired by "
                                             "executing host PowerShell")}
        script_path = match["remediation_script_path"]
        if not authorized:
            return {"ok": False, "review_required": True,
                    "script": Path(script_path).read_text(encoding="utf-8")}
        # Judgment Gate (TOCTOU-closed, BL-08): read the bytes ONCE, verify that
        # single read against the stamped hash, then execute those EXACT bytes
        # from a fresh locked temp copy — so a swap of the on-disk .ps1 in the gap
        # between verify and execute cannot change what actually runs.
        stored = self._stored_hash(mitre_id)
        try:
            with open(script_path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            return {"ok": False, "error": f"could not read staged script: {exc}"}
        actual = hashlib.sha256(data).hexdigest()
        if not stored or actual != stored:
            detail = ("no stamped hash on record" if not stored
                      else f"hash mismatch (stamped {stored[:12]}…, on-disk {actual[:12]}…)")
            _edr("critical", f"BLOCKED remediation {mitre_id}: staged script failed "
                             f"integrity check — {detail}")
            self.emit(f"BLOCKED remediation for {mitre_id}: staged script tampered "
                      f"({detail}).", Severity.CRITICAL, mitre=mitre_id, tamper=True)
            self._log_attempt("blocked_tamper", mitre_id, path=script_path, detail=detail)
            return {"ok": False, "tamper": True,
                    "error": f"integrity check failed: {detail}"}
        # A-03 gate (applies to the single-fix AND bulk AAR _apply paths, which
        # both funnel through here): scan the EXACT verified bytes for destructive
        # constructs and refuse to run them elevated. Belt-and-suspenders with the
        # generate-time scan — catches anything staged before this gate existed.
        danger = _scan_ps(data.decode("utf-8", "ignore"))
        if danger:
            _edr("critical", f"BLOCKED remediation {mitre_id}: staged script contains "
                             f"destructive constructs ({', '.join(danger)}).")
            self.emit(f"BLOCKED remediation for {mitre_id}: destructive constructs "
                      f"({', '.join(danger)}) — refused execution.", Severity.CRITICAL,
                      mitre=mitre_id, destructive=True)
            self._log_attempt("blocked_destructive", mitre_id, path=script_path,
                              constructs=danger)
            return {"ok": False, "destructive": True,
                    "error": f"refused: destructive constructs {danger}"}
        import tempfile
        fd, run_path = tempfile.mkstemp(suffix=".ps1", dir=str(self.remediations))
        try:
            with os.fdopen(fd, "wb") as tf:
                tf.write(data)                       # run the verified bytes, not the path
            res = self._run_powershell_file(run_path)
        finally:
            try:
                os.remove(run_path)
            except Exception:
                pass
        self._log_attempt("executed", mitre_id, path=script_path,
                          returncode=res.get("returncode"),
                          verification=res.get("verification"))
        if res.get("returncode") == 0:
            # Test-Driven Defense: don't just trust that the script ran — re-attack
            # the technique and let the Judgment gate certify (or flag) the fix.
            verdict = self.verify_mitigation(mitre_id)
            res["verification"] = verdict.get("result")
        return res

    # ── JUDGMENT LOOP (Continuous Verification Gate) ─────────────────────────
    def verify_mitigation(self, technique_id: str, settle: float = 40.0) -> dict:
        """Re-run the Red Team verification for `technique_id` (hidden subprocess)
        and act on the result:
          VERIFICATION_RESULT: BLOCKED → certify the mitigation (edr_logger.info,
            mark PATCHED, health/matrix returns to certified),
          VERIFICATION_RESULT: SUCCESS → the mutated attack bypassed the fix
            (edr_logger.error operational alert)."""
        cmd = [sys.executable, "-m", "angerona.shark.verify",
               technique_id, "--verify", "--settle", str(settle)]
        try:
            proc = run_hidden(cmd, capture_output=True, text=True, timeout=settle + 30)
            buf = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except Exception as exc:
            buf = f"VERIFICATION_RESULT: ERROR ({exc})"
        result = "ERROR"
        for line in buf.splitlines():
            if "VERIFICATION_RESULT:" in line:
                result = line.split("VERIFICATION_RESULT:", 1)[1].strip().split()[0]
                break

        if result == "BLOCKED":
            _edr("info", f"[JUDGMENT] Mitigation for {technique_id} CERTIFIED — Red Team "
                         f"verification was BLOCKED. Path signed off.")
            self._certified.add(technique_id)
            self.mark_patched(technique_id)          # also recomputes health
            self.emit(f"✅ CERTIFIED: mitigation for {technique_id} verified — Red Team attack "
                      f"BLOCKED.", Severity.INFO, technique=technique_id, verified="BLOCKED")
        elif result == "SUCCESS":
            _edr("error", f"[JUDGMENT] Mitigation for {technique_id} FAILED verification — the "
                          f"mutated Red Team payload STILL bypassed the staged fix. Operator "
                          f"attention required.")
            self.emit(f"⚠ VERIFICATION FAILED: {technique_id} still exploitable after the fix — "
                      f"the staged mitigation did not stop the attack.", Severity.HIGH,
                      technique=technique_id, verified="SUCCESS")
            # Component 1: autonomous SOAR playbook tuning when a Kill Process ran
            # but the vector persisted — synthesize a network-containment block,
            # wire it into mitigation_gate.ps1, and re-test the Judgment pipeline.
            try:
                from angerona.shark.playbook_tuner import tune_containment
                pb = tune_containment(technique_id)
                if pb.get("reverify") == "BLOCKED":
                    _edr("info", f"[SOAR-TUNE] Dynamic containment playbook now BLOCKS "
                                 f"{technique_id} — path certified.")
                    self.mark_patched(technique_id)
                    self.emit(f"🧯 SOAR containment playbook certified for {technique_id}.",
                              Severity.INFO, technique=technique_id, verified="BLOCKED")
            except Exception as exc:
                self.last_error = str(exc)
        else:
            self.emit(f"Judgment gate could not verify {technique_id} ({result}).",
                      Severity.LOW, technique=technique_id, verified=result)
        return {"technique": technique_id, "result": result}

    def execute_custom_patch(self, raw_input: str, mode: str) -> dict:
        """Console/GUI hook. mode='AI-Assisted' cleans+stages via Ollama (no run);
        mode='Direct Native' runs the user's own authorized script and logs it."""
        if mode == "AI-Assisted":
            cleaned = _ollama(_SYS_SANDBOX, raw_input) or raw_input
            out = self.remediations / "custom_user_patch.ps1"
            out.write_text(cleaned, encoding="utf-8")
            return {"ok": True, "mode": mode, "staged": str(out), "script": cleaned,
                    "note": "staged for review — not executed"}
        if mode == "Direct Native":
            res = self._run_powershell_inline(raw_input)
            self._log_to_aar({"type": "custom_patch_exec", "ts": time.time(),
                              "returncode": res.get("returncode"),
                              "stdout": res.get("stdout", "")[:2000],
                              "stderr": res.get("stderr", "")[:2000]})
            return res
        return {"ok": False, "error": f"unknown mode {mode!r}"}

    def _run_powershell_inline(self, command: str) -> dict:
        return self._popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-Command", command])

    def _run_powershell_file(self, path: str) -> dict:
        return self._popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-File", path])

    def _popen(self, argv: list) -> dict:
        try:
            p = popen_hidden(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = p.communicate(timeout=120)
            return {"ok": p.returncode == 0, "returncode": p.returncode,
                    "stdout": out, "stderr": err}
        except FileNotFoundError:
            return {"ok": False, "error": "powershell not available on this platform"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _log_to_aar(self, entry: dict) -> None:
        try:
            self.aar_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.aar_path.parent / "posture_actions.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    # ── self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        # Fully ISOLATED: exercise ingest on a throwaway probe instance in a temp
        # dir so the test never touches the live module's DB, its `_seen` set, or
        # the REAL after-action report. (The previous version overwrote the real
        # report and — because the live `_seen` already held the sample key —
        # recorded 0 weaknesses, which is why the drill self-test failed.)
        import tempfile
        try:
            probe = PostureHardening(data_dir=tempfile.mkdtemp())
            sample = {"rounds": [{"technique": "persistence_implant",
                                  "name": "Persistence Implant", "mitre": "T1547.001",
                                  "severity": "High", "verdict": "SUCCESS",
                                  "objective": "run key",
                                  "attempts": [{"attack_epoch": 111}]}]}
            probe.aar_path.parent.mkdir(parents=True, exist_ok=True)
            probe.aar_path.write_text(json.dumps(sample), encoding="utf-8")
            new = probe.ingest_report(probe.aar_path)
            vuln = probe.weaknesses("VULNERABLE")
            ok = any(w["mitre_id"] == "T1547.001" for w in vuln) and probe.health < 50
            return (ok, f"probe weaknesses={len(vuln)}, health={probe.health}, staged={len(new)}")
        except Exception as exc:
            return (False, str(exc))


def register():                     # optional convenience for external loaders
    return PostureHardening()


if __name__ == "__main__":
    import tempfile
    m = PostureHardening(data_dir=tempfile.mkdtemp())
    ok, detail = m.self_test()
    print(json.dumps({"self_test_ok": ok, "detail": detail,
                      "weaknesses": m.weaknesses()}, indent=2))
    # custom patch (AI-Assisted offline just stages the raw text)
    print("custom AI-Assisted:", m.execute_custom_patch("Set-MpPreference -DisableRealtimeMonitoring \\$false", "AI-Assisted"))
