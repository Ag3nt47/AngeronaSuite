"""
posture_hardening.py — Autonomous, self-healing Posture Hardening Loop.

Watches the red-team after-action report; any technique that SUCCEEDED (or was
caught only at LOW-DETECTION-STRENGTH) is recorded as a system weakness, drops
this module's health below 50 (orange/red on the status strip), and gets a
deterministic local-LLM advisory. Model output is inert: host changes are
performed only by the separately reviewed typed remediation library.
Drop-in BaseModule for AngeronaSuite; imports standalone for testing.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

from angerona.engines import ollama_client

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

_SYS_REMEDIATE = (
    "You are a defensive Windows posture advisor. Given one security weakness, "
    "produce a concise human-readable explanation, validation steps, rollback "
    "considerations, and suggested typed controls. Never output executable code, "
    "PowerShell, registry commands, shell commands, or instructions to disable "
    "security controls. This output is inert advice and is never execution authority."
)
_SYS_SANDBOX = (
    "You are a defensive change-review assistant. Explain the submitted mitigation "
    "idea, risks, validation steps, and how to express it with reviewed typed "
    "controls. Never return runnable code or commands. The response is inert advice."
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
-- SHA-256 of every inert remediation advisory, stamped when written so later
-- review can detect replacement. Advisory hashes never grant execution authority.
CREATE TABLE IF NOT EXISTS remediation_hashes (
    mitre_technique_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    script_path TEXT,
    stamped_epoch INTEGER
);
CREATE TABLE IF NOT EXISTS posture_evidence (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    last_trusted_epoch INTEGER NOT NULL,
    source TEXT NOT NULL,
    verdict_count INTEGER NOT NULL
);
"""
_TECHNIQUE_ID = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|RT-[A-Z0-9][A-Z0-9_.-]{0,63})$")


def _safe_technique_id(value: object) -> str:
    """Return one path-safe identifier without trusting report text."""
    raw = str(value or "").strip().upper()
    first = raw.split(maxsplit=1)[0] if raw else ""
    if _TECHNIQUE_ID.fullmatch(first):
        return first
    # Preserve an actionable but unrecognized finding under a deterministic,
    # non-reversible identifier. Free text never becomes a path component.
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"RT-{digest.upper()}"


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
        result = ollama_client.analyze_telemetry(
            "Prepare the defensive remediation requested by the system policy.",
            user,
            MODEL,
            system=system,
            host=OLLAMA_HOST,
            timeout=timeout,
            options={"temperature": 0},
        )
        if result.get("error"):
            return None
        return str(result.get("response") or "").strip() or None
    except Exception:
        return None


class PostureHardening(BaseModule):
    name = "Posture Hardening"
    description = "Self-healing loop: turns red-team SUCCESS into staged, review-gated OS hardening."
    category = "SOAR"
    version = "1.12.1"
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
        self._manager = None
        # Typed, single-use in-memory receipts are the only authority the
        # Evolution Engine accepts. Event details alone are not authorization:
        # another in-process publisher can construct a similarly shaped event.
        self._judgment_receipt_key = secrets.token_bytes(32)
        self._judgment_receipt_lock = threading.RLock()
        self._judgment_receipts: dict[str, tuple[str, str, float]] = {}
        self._init_db()
        self._recompute_health()

    def bind_manager(self, manager) -> None:
        """Receive sibling-module access for bounded practice verification."""
        self._manager = manager

    def _issue_judgment_bypass_receipt(self, technique_id: str) -> tuple[str, str]:
        """Create a bounded, short-lived receipt for one verified bypass."""
        now = time.monotonic()
        receipt_id = secrets.token_hex(16)
        digest = hmac.new(
            self._judgment_receipt_key,
            f"judgment-bypass\0{receipt_id}\0{technique_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        with self._judgment_receipt_lock:
            self._judgment_receipts = {
                rid: value
                for rid, value in self._judgment_receipts.items()
                if value[2] > now
            }
            while len(self._judgment_receipts) >= 64:
                self._judgment_receipts.pop(next(iter(self._judgment_receipts)))
            self._judgment_receipts[receipt_id] = (technique_id, digest, now + 300.0)
        return receipt_id, digest

    def consume_judgment_bypass_receipt(
        self, receipt_id: str, technique_id: str, digest: str
    ) -> bool:
        """Consume an exact Judgment bypass receipt once, failing closed."""
        now = time.monotonic()
        with self._judgment_receipt_lock:
            record = self._judgment_receipts.pop(str(receipt_id), None)
        if record is None:
            return False
        expected_technique, expected_digest, expires_at = record
        return (
            expires_at > now
            and hmac.compare_digest(expected_technique, str(technique_id))
            and hmac.compare_digest(expected_digest, str(digest))
        )

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
        mitre_id = _safe_technique_id(mitre_id)
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

    def _record_trusted_evidence(self, source: str, verdict_count: int) -> None:
        bounded_source = str(source or "unknown").strip()[:64] or "unknown"
        count = max(0, min(int(verdict_count), 1_000_000))
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                "INSERT INTO posture_evidence(singleton,last_trusted_epoch,source,"
                "verdict_count) VALUES(1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET "
                "last_trusted_epoch=excluded.last_trusted_epoch,source=excluded.source,"
                "verdict_count=excluded.verdict_count",
                (int(time.time()), bounded_source, count),
            )

    def _trusted_evidence(self) -> tuple[int, str, int] | None:
        with closing(sqlite3.connect(self.db_path)) as c:
            row = c.execute(
                "SELECT last_trusted_epoch,source,verdict_count FROM posture_evidence "
                "WHERE singleton=1"
            ).fetchone()
        return (int(row[0]), str(row[1]), int(row[2])) if row else None

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
        mitre_id = _safe_technique_id(mitre_id)
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
        mitre_id = _safe_technique_id(mitre_id)
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
        mitre_id = _safe_technique_id(mitre_id)
        with closing(sqlite3.connect(self.db_path)) as c, c:
            row = c.execute("SELECT sha256 FROM remediation_hashes WHERE mitre_technique_id=?",
                            (mitre_id,)).fetchone()
        return row[0] if row else None

    def _verify_hash(self, mitre_id: str, path: str) -> tuple[bool, str]:
        """Re-hash the on-disk script and compare to the stamped digest. Returns
        (ok, detail). Missing stamp or any mismatch is treated as tampering."""
        mitre_id = _safe_technique_id(mitre_id)
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

    # ── INPUT ATTESTATION (anti-poisoning) ───────────────────────────────────
    def _aar_trusted(self, doc: dict, path) -> bool:
        """Verify an AAR's HMAC stamp before learning weaknesses from it.

        A signed report that fails verification (tampered) is always refused and
        surfaced as a HIGH alert. An unsigned/unverifiable report is refused only
        in strict mode (ANGERONA_REQUIRE_SIGNED_AAR); otherwise it's ingested with
        a one-time MEDIUM warning so legacy/first-run reports keep working. See
        core/report_attest.py for the full policy."""
        try:
            from angerona.core import report_attest
            trust, sev, reason = report_attest.classify_for_ingest(doc)
        except Exception as exc:
            # The verifier is part of the authorization boundary. Import,
            # key-access, canonicalization, or verifier failures cannot turn an
            # unauthenticated report into a trusted remediation input.
            trust, sev = False, "HIGH"
            detail = str(exc).replace("\r", " ").replace("\n", " ")[:200]
            reason = (
                f"AAR authenticity verifier failed ({type(exc).__name__}: {detail}) "
                "— refusing the report because its integrity cannot be established."
            )
            self.last_error = reason
        if sev:
            # Throttle so an unchanged unsigned report can't repeat-alert.
            warned = getattr(self, "_aar_warned", None)
            if warned is None:
                warned = self._aar_warned = set()
            wkey = (str(path), sev, reason[:40])
            if wkey not in warned:
                warned.add(wkey)
                severity = Severity.HIGH if sev == "HIGH" else Severity.MEDIUM
                self.emit(f"⚠ AAR integrity ({Path(path).name}): {reason}",
                          severity, path=str(path), fail_closed=(not trust))
                self._log_attempt("aar_integrity", "-", path=str(path),
                                  severity=sev, trusted=trust, reason=reason)
        return trust

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
        # Anti-poisoning: prove the AAR is authentic before trusting its verdicts.
        if not self._aar_trusted(session, path):
            return []
        self._record_trusted_evidence("shark", len(session.get("rounds", [])))
        new = []
        for r in session.get("rounds", []):
            verdict = str(r.get("verdict", "")).upper()
            low_det = r.get("detection_strength") in ("LOW", "LOW-DETECTION-STRENGTH") or \
                      r.get("first_strike") is False
            if verdict != "SUCCESS" and not low_det:
                continue
            mitre = _safe_technique_id(
                r.get("mitre")
                or r.get("mitre_technique_id")
                or r.get("technique", "T0000")
            )
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
                      Severity.HIGH, mitre=mitre, remediation=rpath,
                      source="shark", finding_kind="practice_gap",
                      practice_run_id=str(session.get("run_id") or ""))
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
        # Anti-poisoning: prove the AAR is authentic before trusting its verdicts.
        if not self._aar_trusted(report, path):
            return []
        self._record_trusted_evidence("redteam", len(report.get("verdicts", [])))
        from angerona.core import drill_resolution
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
        try:
            lifecycle = drill_resolution.resolution_snapshot(self.data_dir)
        except Exception:
            lifecycle = {}
        for v in report.get("verdicts", []):
            if v.get("category") != "detection":
                continue
            tech = str(v.get("technique", "")).strip()
            mitre = _safe_technique_id(
                tech if tech[:1].upper() == "T" else v.get("stage", "?")
            )
            closure = lifecycle.get(mitre.casefold(), {})
            contract_proof = (
                v.get("finding_resolved") is True
                and closure.get("state") == drill_resolution.VERIFIED_STATE
                and closure.get("contract_id") == v.get("action_contract_id")
                and closure.get("contract_digest") == v.get("action_contract_digest")
                and closure.get("verification_receipt_id")
                == v.get("verification_receipt_id")
            )
            if contract_proof:
                with closing(sqlite3.connect(self.db_path)) as c, c:
                    changed = c.execute(
                        "UPDATE system_weaknesses SET status='PATCHED', last_tested_epoch=? "
                        "WHERE mitre_technique_id=? AND source='redteam'",
                        (int(time.time()), mitre),
                    ).rowcount
                if changed:
                    verified += int(changed)
                    self._log_attempt(
                        "drill_fix_verified",
                        mitre,
                        run_id=v.get("verification_run_id") or run_id,
                        detected_by=v.get("verification_detected_by"),
                        mode=v.get("verification_mode"),
                    )
                continue
            # A successful detector echo is only half of the control.  A
            # caught marker with an explicit failed/missing response is still
            # actionable: install the exact Purple Guard candidate so a later
            # inert replay can prove detector -> recorder -> SOAR -> cleanup.
            # Older reports did not carry ``remediated``; do not reinterpret
            # those legacy caught rows as new response failures.
            response_gap = (
                v.get("caught") is True
                and v.get("remediated") is False
            )
            if v.get("caught") and not response_gap:
                # Proof must come from the exact installed candidate in a fresh
                # run. Re-rendering the candidate's source AAR must never
                # self-certify a fix, nor may an unrelated detector close it.
                candidate = purple_policies.get(mitre)
                candidate_run = (str(candidate.get("candidate_from_run") or "")
                                 if isinstance(candidate, dict) else "")
                verification_detector = (
                    v.get("verification_detected_by") or v.get("detected_by")
                )
                fresh_candidate_proof = (
                    bool(run_id and candidate_run and run_id != candidate_run)
                    and verification_detector == "Purple Remediation Guard"
                )
                caught_contract_proof = (
                    closure.get("state") == drill_resolution.VERIFIED_STATE
                    and closure.get("verified_by_run_id") == run_id
                    and closure.get("contract_id") == v.get("action_contract_id")
                    and closure.get("contract_digest")
                    == v.get("action_contract_digest")
                )
                if not fresh_candidate_proof or not caught_contract_proof:
                    continue
                with closing(sqlite3.connect(self.db_path)) as c, c:
                    changed = c.execute(
                        "UPDATE system_weaknesses SET status='PATCHED', last_tested_epoch=? "
                        "WHERE mitre_technique_id=? AND source='redteam'",
                        (int(time.time()), mitre)).rowcount
                if changed:
                    verified += int(changed)
                    self._log_attempt("drill_fix_verified", mitre, run_id=run_id,
                                      detected_by=verification_detector,
                                      latency=(v.get("verification_detect_latency_s")
                                               or v.get("detect_latency_s")))
                continue
            key = ("redteam", mitre, v.get("ts_start"))
            if key in self._seen:
                continue
            self._seen.add(key)
            name = v.get("stage") or tech or "Red Team finding"
            self._ctx[mitre] = {"objective": v.get("description", ""), "target": "Red Team"}
            self.record_weakness(mitre, name, "High", None, source="redteam")
            try:
                drill_resolution.record_findings(
                    [{"mitre": mitre, "name": name}],
                    run_id,
                    self.data_dir,
                    observed_at=float(v.get("ts_start") or time.time()),
                )
            except (
                TypeError,
                ValueError,
                drill_resolution.StateIntegrityError,
            ):
                pass
            gap_kind = "response" if response_gap else "detection"
            new.append({"mitre": mitre, "name": name})
            gap_text = (
                "was detected but had no correlated successful response"
                if response_gap else "slipped past detection"
            )
            self.emit(f"NEW WEAKNESS (Red Team): {name} ({mitre}) {gap_text} — "
                      f"a reviewed detector/response candidate can be installed and verified",
                      Severity.HIGH, mitre=mitre, run_id=run_id,
                      remediation="purple-guard-candidate", source="redteam",
                      finding_kind="practice_gap", practice_run_id=run_id,
                      gap_kind=gap_kind)
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

    def resolve_redteam_report(
        self,
        path=None,
        cleanup_count: int = 0,
        *,
        expected_run_id: str = "",
        expected_report_sha256: str = "",
    ) -> dict:
        """Install exact detector candidates for misses; never self-certify.

        The current run's duplicate alerts are acknowledged, but its database
        weaknesses stay VULNERABLE. Only a later AAR containing a real detector
        echo can transition them to PATCHED.
        """
        report_path = Path(path or self.redteam_aar_path)
        try:
            raw_report = report_path.read_bytes()
            actual_digest = hashlib.sha256(raw_report).hexdigest()
            report = json.loads(raw_report.decode("utf-8"))
        except Exception as exc:
            return {"ok": False, "error": f"could not read drill report: {exc}"}
        # Bind the authorization click to the exact signed report shown to the
        # operator.  The fixed redteam_aar.json is intentionally overwritten;
        # without both checks a newer run could replace it between review and
        # action (a classic display/action TOCTOU).
        if expected_report_sha256 and actual_digest != expected_report_sha256:
            return {
                "ok": False,
                "error": "drill report changed after it was displayed; refresh and review it again",
                "binding_failed": True,
                "fail_closed": True,
            }
        report_run_id = str(report.get("run_id") or "")
        if expected_run_id and report_run_id != str(expected_run_id):
            return {
                "ok": False,
                "error": "drill report run ID no longer matches the displayed run",
                "binding_failed": True,
                "fail_closed": True,
            }
        # Manual resolution installs detector policy and acknowledges findings,
        # so it is an authorization path, not a display-only report read. Apply
        # the same HMAC/strict-mode gate as automatic ingestion before any write.
        if not self._aar_trusted(report, report_path):
            return {
                "ok": False,
                "error": "drill report authenticity verification failed",
                "authentication_failed": True,
                "fail_closed": True,
            }
        findings = []
        for verdict in report.get("verdicts", []):
            if verdict.get("category") != "detection":
                continue
            response_gap = (
                verdict.get("caught") is True
                and verdict.get("remediated") is False
            )
            if verdict.get("caught") and not response_gap:
                continue
            tech = str(verdict.get("technique", "")).strip()
            mitre = tech.split()[0] if tech[:1].upper() == "T" else (
                "RT-" + str(verdict.get("stage", "?")))
            findings.append({
                "mitre": mitre,
                "name": verdict.get("stage") or tech or "Red Team finding",
                "gap_kind": "response" if response_gap else "detection",
            })
        if not findings:
            return {"ok": True, "candidates": 0, "findings": [],
                    "message": "No open detection or response gaps need a candidate."}

        from angerona.core import drill_resolution
        from angerona.modules.purple_guard import (
            _read_policy,
            install_policies,
            remove_policies,
        )
        run_id = report_run_id
        try:
            # Persist the open issue first. If authenticated lifecycle state is
            # unavailable/tampered, fail closed before changing detector policy.
            drill_resolution.record_findings(findings, run_id, self.data_dir)
        except drill_resolution.StateIntegrityError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "fail_closed": True,
                "candidates": 0,
            }
        previous_policy = _read_policy(self.data_dir).get("techniques", {})
        if not isinstance(previous_policy, dict):
            previous_policy = {}
        installed = install_policies(findings, run_id, self.data_dir)
        ids = list(installed.get("installed", []))
        try:
            # An installed candidate is APPLIED, never VERIFIED. The signed
            # action receipt binds exact scope, idempotency, rollback metadata,
            # and the independent rerun verifier.
            acknowledged = drill_resolution.apply_contracts(
                findings,
                run_id,
                self.data_dir,
                installed=ids,
                cleanup_count=cleanup_count,
            )
        except drill_resolution.StateIntegrityError as exc:
            # Candidate activation and its signed action contract are one
            # logical transaction. Remove newly written entries, then restore
            # any candidate versions that predated this attempt.
            remove_policies(ids, self.data_dir)
            restore = [
                {"mitre": mitre}
                for mitre in ids
                if mitre in previous_policy
            ]
            if restore:
                prior_run = str(
                    previous_policy[restore[0]["mitre"]].get("candidate_from_run")
                    or "restored"
                )
                install_policies(restore, prior_run, self.data_dir)
            return {
                "ok": False,
                "error": str(exc),
                "fail_closed": True,
                "candidates": 0,
                "policy_changed": False,
                "policy_rolled_back": bool(ids),
            }
        self._recompute_health()
        self._log_attempt("install_drill_detector_candidates", "-", run_id=run_id,
                          report=str(report_path), techniques=ids,
                          unsupported=installed.get("unsupported", []))
        self.emit(f"Installed {len(ids)} reviewed Purple Guard detector candidate(s) for "
                  f"run {run_id or 'unknown'}; rerun the drill to verify them.",
                  Severity.INFO, run_id=run_id, candidate_techniques=ids)
        return {"ok": True, "candidates": len(ids), "findings": findings,
                "contracts": acknowledged,
                "unsupported": installed.get("unsupported", []), "run_id": run_id,
                "report_sha256": actual_digest,
                "verification_required": True}

    def verify_redteam_practice(self, resolution: dict,
                                progress=None) -> dict:
        """Prove applied simulation fixes with inert positive/negative controls.

        This never claims to patch Windows. It validates the reviewed detector,
        signed recorder path, real Active Response playbook, and cleanup
        postcondition, then issues the authenticated closure receipt.
        """
        manager = self._manager
        if manager is None:
            return {"ok": False, "error": "module manager unavailable", "results": []}
        techniques = [
            str(row.get("mitre") or "")
            for row in resolution.get("contracts", [])
            if row.get("mitre")
        ]
        if not techniques:
            return {"ok": True, "verified": 0, "total": 0, "results": []}
        from angerona.core.config import Config
        from angerona.core.practice_verification import verify_practice_fixes

        result = verify_practice_fixes(
            techniques,
            source_run_id=str(resolution.get("run_id") or ""),
            data_dir=self.data_dir,
            db_path=Path(Config.load().db_path),
            bus=self._bus,
            purple_guard=manager.modules.get("Purple Remediation Guard"),
            active_response=manager.modules.get("Active Response SOAR"),
            progress=progress,
        )
        verified_ids = [
            row["mitre"] for row in result.get("results", [])
            if row.get("status") == "PRACTICE_FIX_VERIFIED"
        ]
        if verified_ids:
            with closing(sqlite3.connect(self.db_path)) as c, c:
                c.executemany(
                    "UPDATE system_weaknesses SET status='PATCHED', last_tested_epoch=? "
                    "WHERE source='redteam' AND mitre_technique_id=?",
                    [(int(time.time()), mitre) for mitre in verified_ids],
                )
            self._log_attempt(
                "practice_fix_verified",
                "-",
                source_run_id=resolution.get("run_id"),
                techniques=verified_ids,
                practice_only=True,
            )
        self._recompute_health()
        return result

    def _recompute_health(self) -> None:
        vuln = len(self.weaknesses("VULNERABLE"))
        if vuln:
            # any open weakness forces the module below 50 (orange/red strip)
            self.set_health(max(5, 45 - vuln * 5), f"{vuln} unremediated weakness(es)")
            return
        evidence = self._trusted_evidence()
        if evidence is None:
            self.set_health(
                55,
                "No trusted posture report has been ingested; a clean posture "
                "cannot be established from missing evidence.",
            )
            return
        observed_at, source, verdict_count = evidence
        try:
            max_age = max(
                1.0,
                float(os.environ.get("ANGERONA_POSTURE_EVIDENCE_MAX_AGE_HOURS", "24")),
            ) * 3600.0
        except (TypeError, ValueError):
            max_age = 24.0 * 3600.0
        age = max(0.0, time.time() - observed_at)
        if age > max_age:
            self.set_health(
                75,
                f"Last trusted {source} posture evidence is stale "
                f"({age / 3600.0:.1f}h old; {verdict_count} verdicts).",
            )
            return
        self.set_health(
            100,
            f"posture clean from trusted {source} evidence ({verdict_count} verdicts)",
        )

    # ── 3. DETERMINISTIC LOCAL LLM ORCHESTRATION ─────────────────────────────
    def _generate_remediation(self, mitre, name, severity, round_obj) -> str:
        mitre = _safe_technique_id(mitre)
        payload = json.dumps({"mitre_technique_id": mitre, "technique_name": name,
                              "severity": severity, "objective": round_obj.get("objective", ""),
                              "target_module": round_obj.get("target", "")}, indent=2)
        script = _ollama(_SYS_REMEDIATE, payload)
        out = self._advisory_path(mitre)
        if not script:
            script = (
                f"Ollama unavailable. Review the {mitre} ({name}) coverage gap and "
                "select a control from the vetted remediation plan."
            )
        advisory = (
            "# INERT LOCAL-AI ADVISORY — NEVER EXECUTED\n\n"
            "This content is untrusted analysis. It cannot authorize PowerShell, "
            "registry, service, process, firewall, or filesystem changes.\n\n"
            + script.strip()
            + "\n"
        )
        out.write_text(advisory, encoding="utf-8")
        self._stamp_hash(mitre, str(out))
        return str(out)

    def _stage_placeholder(self, mitre, name) -> str:
        """Instant, Ollama-free stub written at drill time. The real remediation
        is generated lazily by generate_remediation() when the user clicks
        'Attempt Fix' — so a drill never blocks on / contends for the LLM/VRAM."""
        mitre = _safe_technique_id(mitre)
        out = self._advisory_path(mitre)
        if not out.exists():
            out.write_text(
                f"# INERT ADVISORY PLACEHOLDER\n\n{mitre} ({name}) — click "
                "Attempt Fix to generate local analysis and a separate vetted plan.\n",
                encoding="utf-8")
        self._stamp_hash(mitre, str(out))
        return str(out)

    def _advisory_path(self, technique_id: object) -> Path:
        """Resolve a validated filename inside the dedicated advisory root."""
        safe = _safe_technique_id(technique_id)
        root = self.remediations.resolve(strict=False)
        path = (root / f"{safe}.advisory.md").resolve(strict=False)
        if path.parent != root:
            raise ValueError("remediation advisory path escaped its storage root")
        return path

    def generate_remediation(self, mitre_id: str, timeout: int = 45) -> dict:
        """On-demand: ask Ollama (temperature 0) for a real remediation for a
        known weakness and overwrite its inert advisory. Returns the advisory text.
        Intended to be called from a background thread (the 'Attempt Fix' button)."""
        w = next((x for x in self.weaknesses() if x["mitre_id"] == mitre_id), None)
        if not w:
            return {"ok": False, "error": "unknown weakness"}
        if w.get("source") == "redteam":
            return {"ok": False, "error": ("simulated detection gaps use deterministic report "
                                             "resolution, not host PowerShell")}
        r = self._ctx.get(mitre_id, {"objective": "", "target": ""})
        path = self._generate_remediation(mitre_id, w["name"], w["severity"], r)
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                "UPDATE system_weaknesses SET remediation_script_path=? "
                "WHERE mitre_technique_id=?",
                (path, mitre_id),
            )
        script = Path(path).read_text(encoding="utf-8")
        self._log_attempt("ai_generate", mitre_id, name=w["name"], severity=w["severity"],
                          path=path, sha256=self._verify_hash(mitre_id, path)[1],
                          script_preview=script[:1000], review_required=True,
                          advisory_only=True)
        return {"ok": True, "mitre": mitre_id, "path": path, "script": script,
                "review_required": True, "advisory_only": True, "executable": False}

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
                proof = rec.get("proof_receipt") or {}
                if proof.get("receipt_id"):
                    self.emit(
                        f"Verified remediation proof issued for {rec['mitre']}.",
                        Severity.INFO,
                        mitre=rec["mitre"],
                        verified=True,
                        relation="verification-proof",
                        receipt_id=proof.get("receipt_id"),
                        receipt_hash=proof.get("receipt_hash"),
                        correlation_id=proof.get("receipt_id"),
                    )
        return res

    # ── 4. SECURITY AUTHORIZATION GATE & SANDBOX INTERFACE ───────────────────
    def execute_remediation(self, mitre_id: str, authorized: bool = False) -> dict:
        """Return the inert advisory; model-authored content is never executable."""
        rows = self.weaknesses()
        match = next((w for w in rows if w["mitre_id"] == mitre_id), None)
        if not match or not match["remediation_script_path"]:
            return {"ok": False, "error": "no staged remediation"}
        if match.get("source") == "redteam":
            return {"ok": False, "error": ("simulated detection gaps cannot be repaired by "
                                             "executing host PowerShell")}
        script_path = match["remediation_script_path"]
        try:
            advisory = Path(script_path).read_text(encoding="utf-8")
        except Exception as exc:
            return {"ok": False, "error": f"could not read advisory: {exc}"}
        self._log_attempt(
            "model_advisory_execution_refused",
            mitre_id,
            path=script_path,
            authorized=bool(authorized),
        )
        return {
            "ok": False,
            "advisory_only": True,
            "executable": False,
            "review_required": not authorized,
            "script": advisory,
            "error": (
                "Local-AI advice is inert and cannot execute. Use the vetted typed "
                "remediation plan for host changes."
            ),
        }

    # ── JUDGMENT LOOP (Continuous Verification Gate) ─────────────────────────
    def verify_mitigation(self, technique_id: str, settle: float = 40.0) -> dict:
        """Run an inert canary and require an authentic, source-bound receipt.

        A BLOCKED canary is detection evidence only. It cannot mark an open
        weakness patched because this path neither installs nor verifies a host
        remediation postcondition.
        """
        try:
            from angerona.core.judgment_gate import run_judgment_verification

            judgment = run_judgment_verification(
                technique_id,
                settle=settle,
            )
            result = judgment.outcome
            receipt = judgment.receipt
        except Exception as exc:
            self.last_error = str(exc)
            result = "ERROR"
            receipt = None

        if result == "BLOCKED":
            _edr(
                "info",
                f"[JUDGMENT] Inert canary for {technique_id} was BLOCKED; "
                "no remediation was installed or certified.",
            )
            self.emit(
                f"Interception canary for {technique_id} was BLOCKED; the open "
                "weakness remains pending a typed remediation postcondition.",
                Severity.INFO,
                technique=technique_id,
                verified="BLOCKED",
                installed=False,
                patched=False,
                receipt_schema=(receipt or {}).get("schema"),
            )
        elif result == "SUCCESS":
            _edr("error", f"[JUDGMENT] Mitigation for {technique_id} FAILED verification — the "
                          f"mutated Red Team payload STILL bypassed the staged fix. Operator "
                          f"attention required.")
            receipt_id, receipt_digest = self._issue_judgment_bypass_receipt(
                technique_id
            )
            self.emit(f"⚠ VERIFICATION FAILED: {technique_id} still exploitable after the fix — "
                      f"the staged mitigation did not stop the attack.", Severity.HIGH,
                      technique=technique_id, verified="SUCCESS",
                      event_type="judgment-bypass-receipt.v1",
                      receipt_id=receipt_id, receipt_digest=receipt_digest,
                      response_authorized=False)
            # A bypass produces review evidence only. Model/script output is not
            # response authority and cannot truthfully certify an unapplied fix.
            try:
                from angerona.shark.playbook_tuner import tune_containment
                pb = tune_containment(technique_id)
                if pb.get("ok"):
                    self.emit(
                        f"Containment proposal staged for {technique_id}; no host "
                        "change or verification was performed.",
                        Severity.MEDIUM,
                        technique=technique_id,
                        proposal_id=pb.get("proposal_id"),
                        proposal_path=pb.get("proposal"),
                        executed=False,
                        verified=False,
                        response_authorized=False,
                    )
            except Exception as exc:
                self.last_error = str(exc)
        else:
            self.emit(f"Judgment gate could not verify {technique_id} ({result}).",
                      Severity.LOW, technique=technique_id, verified=result)
        return {
            "technique": technique_id,
            "result": result,
            "interception_verified": result == "BLOCKED",
            "patched": False,
            "receipt": receipt,
        }

    def execute_custom_patch(self, raw_input: str, mode: str) -> dict:
        """Convert custom text into an inert review artifact; never execute it."""
        if mode == "AI-Assisted":
            cleaned = _ollama(_SYS_SANDBOX, raw_input) or raw_input
            out = self.remediations / "custom_user_patch.advisory.md"
            out.write_text(
                "# INERT CHANGE ADVISORY — NEVER EXECUTED\n\n" + cleaned,
                encoding="utf-8",
            )
            return {"ok": True, "mode": mode, "staged": str(out), "script": cleaned,
                    "advisory_only": True, "executable": False,
                    "note": "inert advisory saved for review — never executed"}
        if mode == "Direct Native":
            self._log_to_aar({
                "type": "custom_patch_refused",
                "ts": time.time(),
                "reason": "arbitrary PowerShell execution is disabled",
            })
            return {
                "ok": False,
                "advisory_only": True,
                "executable": False,
                "error": "Direct Native arbitrary PowerShell is disabled; use typed controls.",
            }
        return {"ok": False, "error": f"unknown mode {mode!r}"}

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
            # Authenticity is exercised independently by report_attest.self_test
            # and the strict AAR regression suite. This isolated probe validates
            # the post-trust ingestion/business path without touching the live
            # installation key or changing process-wide verifier policy.
            probe._aar_trusted = lambda _doc, _path: True
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
