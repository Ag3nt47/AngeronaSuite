"""daily_briefing.py — Scheduled AI Security Briefing (Code: BRIEF).

Once a day (configurable) this module compiles what Angerona saw — alert volume
by severity, the top techniques, active incident kill-chains, and what active
defense actually did — and turns it into a short plain-English briefing. If the
local Ollama model is reachable it writes the prose; otherwise a deterministic
template is used, so a briefing is ALWAYS produced (never blocks on the LLM).

The briefing is emitted to the bus and written to shared_logs/daily_briefing.txt
(+ .json) so the dashboard, a scheduled task, or the mobile bridge can surface it.

Local-first: the only network call is to 127.0.0.1 Ollama. Read-only.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import json
import hashlib
import hmac
import os
import time
import urllib.request
from collections import Counter
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity
from angerona.core.atomic_io import replace_with_retry
from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    local_service_url,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import effective_keep_alive
from angerona.core.threat import is_active_threat

_SYSTEM_PROMPT = (
    "You are a SOC analyst writing a short daily security briefing for a single "
    "Windows endpoint. Be concise, factual, and calm. 4-8 sentences. Lead with the "
    "overall posture (quiet / notable / under attack), then the most important "
    "findings and what was done about them. Only active_by_severity represents a "
    "live hostile threat; raw by_severity also includes practice, exposure, and "
    "health evidence and must never by itself be called an active attack. No "
    "markdown headers."
)
_WINDOW_LIMIT = 10_000
_CURSOR_SCHEMA = 1
_CURSOR_HMAC = "hmac_sha256"
_CURSOR_DOMAIN = b"Angerona-Daily-Briefing-v1"
_MAX_CURSOR_BYTES = 16 * 1024
_MAX_BRIEFING_BYTES = 256 * 1024


def _shared_logs() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir() / "shared_logs"


def _summarize_events(events) -> dict:
    """Turn raw bus events into a compact, countable summary (pure function)."""
    sev_counts: Counter = Counter()
    active_sev_counts: Counter = Counter()
    tech_counts: Counter = Counter()
    modules: Counter = Counter()
    criticals: list[str] = []
    for ev in events:
        sev = (getattr(getattr(ev, "severity", None), "name", None) or str(
            getattr(ev, "severity", ""))).upper()
        sev_counts[sev] += 1
        modules[getattr(ev, "module", "?")] += 1
        det = getattr(ev, "details", None) or {}
        mit = det.get("mitre") if isinstance(det, dict) else None
        if mit:
            for t in str(mit).replace(",", "/").split("/"):
                t = t.strip()
                if t.startswith("T"):
                    tech_counts[t] += 1
        try:
            active = is_active_threat(ev)
            if active:
                active_sev_counts[sev] += 1
            if active and ev.severity >= Severity.CRITICAL:
                criticals.append((getattr(ev, "message", "") or "")[:120])
        except Exception:
            pass
    return {
        "total": sum(sev_counts.values()),
        "active_total": sum(active_sev_counts.values()),
        "by_severity": dict(sev_counts),
        "active_by_severity": dict(active_sev_counts),
        "top_techniques": tech_counts.most_common(5),
        "top_modules": modules.most_common(5),
        "criticals": criticals[:5],
    }


def _read_remediation() -> dict:
    try:
        return json.loads((_shared_logs() / "remediation_stats.json").read_text("utf-8"))
    except Exception:
        return {}


def _heuristic_briefing(summary: dict, remediation: dict, incidents: list) -> str:
    """Deterministic briefing text — used when Ollama is unavailable."""
    total = summary.get("total", 0)
    evidence_crit = summary.get("by_severity", {}).get("CRITICAL", 0)
    evidence_high = summary.get("by_severity", {}).get("HIGH", 0)
    active_crit = summary.get("active_by_severity", {}).get("CRITICAL", 0)
    active_high = summary.get("active_by_severity", {}).get("HIGH", 0)
    contained = remediation.get("contained", 0)
    if active_crit:
        posture = "UNDER ATTACK / serious activity"
    elif active_high:
        posture = "notable active threat activity"
    elif evidence_crit or evidence_high or total > 20:
        posture = "notable evidence, with no active attack classified"
    else:
        posture = "quiet"
    lines = [f"Daily security briefing — posture: {posture}.",
             f"{total} events in the review window "
             f"({evidence_crit} critical-evidence, {evidence_high} high-evidence); "
             f"active threats: {active_crit} critical, {active_high} high."]
    if summary.get("top_techniques"):
        techs = ", ".join(f"{t} (x{n})" for t, n in summary["top_techniques"])
        lines.append(f"Most-seen techniques: {techs}.")
    if incidents:
        top = incidents[0]
        prefix = "Top active incident" if (active_crit or active_high) else (
            "Top correlated evidence cluster (not classified as an active threat)"
        )
        lines.append(f"{prefix}: {top.get('actor','?')} (pid {top.get('pid')}) reached "
                     f"{top.get('progress_pct')}% of the kill-chain — {top.get('chain','')}.")
    lines.append(f"Active defense contained {contained} process(es)."
                 if contained else "No automated containment was required.")
    if summary.get("criticals"):
        lines.append("Critical items: " + " | ".join(summary["criticals"][:3]))
    return " ".join(lines)


class DailyBriefingModule(BaseModule):
    CODE = "BRIEF"
    NAME = "Scheduled AI Security Briefing"
    name = "Scheduled AI Security Briefing"
    description = ("Compiles a daily plain-English security briefing (alert volume, top "
                   "techniques, incidents, containment) via local AI with a deterministic fallback.")
    category = "Reporting"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 4.0
    version = "1.13.0"

    def __init__(self) -> None:
        super().__init__()
        self._host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self._model = os.environ.get("ANGERONA_MODEL", "llama3")
        try:
            self._interval_s = float(os.environ.get("ANGERONA_BRIEFING_INTERVAL_H", "24")) * 3600
        except Exception:
            self._interval_s = 24 * 3600
        self._last_run = 0.0
        self._count = 0
        self._recorder = None
        self._cursor_status = "not-loaded"
        self._cursor_path_override: Path | None = None
        self._cursor_key_override: bytes | None = None
        self._last_coverage_complete = False

    def bind_recorder(self, recorder) -> None:
        self._recorder = recorder

    @property
    def _cursor_path(self) -> Path:
        return self._cursor_path_override or (_shared_logs() / "daily_briefing.cursor.json")

    def _cursor_key(self) -> bytes | None:
        key = self._cursor_key_override
        if key is None:
            try:
                from angerona.core.data_paths import data_dir

                key = bytes.fromhex(
                    (data_dir() / "bus.key").read_text(encoding="ascii").strip()
                )
            except (OSError, ValueError):
                return None
        if len(key) != 32:
            return None
        return hmac.new(key, _CURSOR_DOMAIN, hashlib.sha256).digest()

    @staticmethod
    def _cursor_body(value: dict) -> bytes:
        unsigned = {key: item for key, item in value.items() if key != _CURSOR_HMAC}
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _load_cursor(self) -> tuple[float, int, str] | None:
        key = self._cursor_key()
        if key is None:
            self._cursor_status = "key-unavailable"
            return None
        try:
            raw = self._cursor_path.read_bytes()
        except FileNotFoundError:
            self._cursor_status = "new"
            return None
        except OSError:
            self._cursor_status = "unreadable"
            return None
        try:
            if len(raw) > _MAX_CURSOR_BYTES:
                raise ValueError("cursor exceeds byte limit")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "schema",
                "last_success_ts",
                "sequence",
                "report_digest",
                _CURSOR_HMAC,
            }:
                raise ValueError("cursor schema mismatch")
            last_success = float(value["last_success_ts"])
            sequence = int(value["sequence"])
            report_digest = str(value["report_digest"])
            supplied = str(value[_CURSOR_HMAC])
            if (
                value["schema"] != _CURSOR_SCHEMA
                or not 0 <= last_success <= time.time() + 300
                or sequence < 1
                or len(report_digest) != 64
                or len(supplied) != 64
            ):
                raise ValueError("cursor fields invalid")
            int(report_digest, 16)
            expected = hmac.new(
                key, self._cursor_body(value), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(supplied, expected):
                raise ValueError("cursor authentication failed")
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            self._cursor_status = "invalid"
            return None
        self._cursor_status = "ok"
        return last_success, sequence, report_digest

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        if len(payload) > _MAX_BRIEFING_BYTES:
            raise ValueError("briefing artifact exceeds byte limit")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _save_cursor(self, end_ts: float, sequence: int, report_digest: str) -> None:
        if self._cursor_status not in {"new", "ok"}:
            raise RuntimeError(
                f"refusing to overwrite {self._cursor_status} briefing cursor"
            )
        key = self._cursor_key()
        if key is None:
            self._cursor_status = "key-unavailable"
            raise RuntimeError("briefing cursor key unavailable")
        document = {
            "schema": _CURSOR_SCHEMA,
            "last_success_ts": float(end_ts),
            "sequence": int(sequence),
            "report_digest": report_digest,
        }
        document[_CURSOR_HMAC] = hmac.new(
            key, self._cursor_body(document), hashlib.sha256
        ).hexdigest()
        self._atomic_write(
            self._cursor_path,
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
        self._cursor_status = "ok"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        self.emit(f"BRIEF online — daily AI briefing every {self._interval_s/3600:.0f}h.",
                  Severity.INFO)
        # Give the suite a moment to accumulate events before the first briefing.
        self.sleep(min(60.0, self._interval_s))
        self._load_cursor()
        if self._cursor_status not in {"new", "ok"}:
            self.set_health(30, f"briefing cursor {self._cursor_status}")
        while not self.stopping:
            try:
                self._make_briefing()
                health = 100 if self._last_coverage_complete else 70
                self.set_health(
                    health,
                    f"{self._count} briefing(s) durably generated; "
                    f"coverage={'complete' if self._last_coverage_complete else 'bounded/incomplete'}",
                )
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(70, f"briefing error: {exc}")
            # sleep in small slices so shutdown is responsive
            waited = 0.0
            while not self.stopping and waited < self._interval_s:
                self.sleep(5.0)
                waited += 5.0

    def _gather(
        self, start_ts: float | None = None, end_ts: float | None = None
    ) -> tuple[dict, dict, list]:
        end_ts = time.time() if end_ts is None else float(end_ts)
        start_ts = end_ts - self._interval_s if start_ts is None else float(start_ts)
        recorder = self._recorder
        if recorder is not None and hasattr(recorder, "bounded_events_in_window"):
            events, total = recorder.bounded_events_in_window(
                start_ts, end_ts, limit=_WINDOW_LIMIT
            )
            source = "flight-recorder"
            omitted = max(0, int(total) - len(events))
            complete = omitted == 0
        else:
            recent = list(self._bus.recent(500)) if self._bus is not None else []
            events = [
                event
                for event in recent
                if start_ts <= float(getattr(event, "ts", 0.0)) <= end_ts
            ]
            total = len(events)
            omitted = None
            complete = False
            source = "eventbus-fallback"
        summary = _summarize_events(events)
        summary["window"] = {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "source": source,
            "events_returned": len(events),
            "events_total": total,
            "events_omitted": omitted,
            "complete": complete,
        }
        remediation = _read_remediation()
        incidents: list = []
        try:
            from angerona.core.incident_timeline import build_timeline, write_timeline
            incidents = build_timeline(self._bus)
            write_timeline(self._bus)      # refresh the persisted timeline too
        except Exception:
            pass
        return summary, remediation, incidents

    def _ask_ollama(self, facts: str) -> str | None:
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": facts},
            ],
            "stream": False,
            "keep_alive": effective_keep_alive("30m"),
        }).encode("utf-8")
        req = urllib.request.Request(
            local_service_url(self._host, "/api/chat"), data=payload,
            headers={"Content-Type": "application/json"})
        try:
            with safe_urlopen(req, policy=OLLAMA_SERVICE_POLICY, timeout=90) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            return ((data.get("message", {}) or {}).get("content", "") or "").strip() or None
        except Exception as exc:
            self.last_error = str(exc)
            return None

    def _make_briefing(self) -> None:
        now = time.time()
        cursor = self._load_cursor()
        if self._cursor_status not in {"new", "ok"}:
            raise RuntimeError(f"briefing cursor {self._cursor_status}")
        start_ts = cursor[0] if cursor is not None else now - self._interval_s
        sequence = (cursor[1] + 1) if cursor is not None else 1
        if start_ts > now:
            raise RuntimeError("briefing interval cursor is in the future")
        summary, remediation, incidents = self._gather(start_ts, now)
        facts = json.dumps({
            "events": summary, "remediation": remediation,
            "incidents": [{"actor": i.get("actor"), "pid": i.get("pid"),
                           "severity": i.get("severity"), "chain": i.get("chain"),
                           "progress_pct": i.get("progress_pct")}
                          for i in incidents[:5]],
        }, indent=2)
        try:
            from angerona.engines.ai_guardrail import neutralize_telemetry

            guarded_facts = neutralize_telemetry(facts)
        except Exception:
            guarded_facts = facts
        text = self._ask_ollama(guarded_facts)
        source = "AI"
        if not text:
            text = _heuristic_briefing(summary, remediation, incidents)
            source = "rules"
        text = str(text).replace("\x00", "")[:4000]
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        full = f"[{stamp}] Security Briefing ({source})\n\n{text}\n"
        sev = (Severity.HIGH if summary.get("active_by_severity", {}).get("CRITICAL")
               else Severity.INFO)
        root = _shared_logs()
        report = {
            "schema": 2,
            "generated": stamp,
            "generated_ts": now,
            "sequence": sequence,
            "source": source,
            "narrative_authority": "advisory-only",
            "text": text,
            "summary": summary,
            "remediation": remediation,
        }
        report_bytes = json.dumps(
            report, indent=2, sort_keys=True, default=str
        ).encode("utf-8")
        report_digest = hashlib.sha256(report_bytes).hexdigest()
        self._atomic_write(root / "daily_briefing.txt", full.encode("utf-8"))
        self._atomic_write(root / "daily_briefing.json", report_bytes)
        self._save_cursor(now, sequence, report_digest)
        self._count += 1
        self._last_run = now
        self._last_coverage_complete = bool(summary["window"]["complete"])
        self.emit(
            f"📋 Daily briefing ready ({source}): {text[:180]}",
            sev,
            briefing=text,
            source=source,
            events=summary.get("total", 0),
            window=dict(summary["window"]),
            report_path=str(root / "daily_briefing.json"),
            report_digest=report_digest,
            sequence=sequence,
        )

    def self_test(self) -> tuple[bool, str]:
        """Offline: verify the summary + deterministic briefing without Ollama."""
        class _Ev:
            def __init__(self, sev, module, msg, mitre):
                self.severity, self.module, self.message = sev, module, msg
                self.details = {"mitre": mitre}
        evs = [
            _Ev(Severity.CRITICAL, "CREDG", "lsass dump", "T1003.001"),
            _Ev(Severity.HIGH, "BEAC", "beacon", "T1071"),
            _Ev(Severity.HIGH, "BEAC", "beacon", "T1071"),
            _Ev(Severity.INFO, "ETW", "ok", None),
        ]
        summary = _summarize_events(evs)
        text = _heuristic_briefing(
            summary, {"contained": 2},
            [{"actor": "evil.exe", "pid": 7, "severity": "CRITICAL",
              "chain": "Cred Access → C2", "progress_pct": 85}])
        ok = (summary["total"] == 4
              and summary["by_severity"].get("CRITICAL") == 1
              and ("T1071", 2) in summary["top_techniques"]
              and "UNDER ATTACK" in text
              and "contained 2" in text)
        return ok, ("briefing builder verified (severity tally, technique ranking, "
                    "posture + containment line)" if ok else f"failed: {summary} | {text}")


def register() -> DailyBriefingModule:
    return DailyBriefingModule()
