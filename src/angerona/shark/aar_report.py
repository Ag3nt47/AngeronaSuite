"""aar_report.py — Dynamic After-Action Report (AAR) generator.

Compares the Shark Attack Engine's own ground-truth log
(``shark_history.json``) against what Angerona's real detection modules —
and the Active Response SOAR Engine — actually recorded in the
flight-recorder ledger, which is this app's single existing source of
truth for everything that happened (core/storage.py). No separate
"remediation log" file is needed: SOAR's kill+rollback actions are just
ordinary ``self.emit()`` calls like every other module, so they're already
in the ledger under the "Active Response SOAR" module name.

This is intentionally a passive, read-only report generator. It never
re-triggers anything, and it never tells the shark engine or the defense
modules anything about each other — it only looks at what already happened,
after the fact.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from angerona.core.config import Config
from angerona.core.eventbus import Event
from angerona.core.storage import FlightRecorder

WIDTH = 84

# Not every Shark Attack stage is a "did a detector notice this" test. This
# mapping is what stops the report from mislabeling structurally-expected
# non-catches as failures right next to genuine detection gaps — a real run
# once showed "0/5 detected" and read as "everything is broken", when two of
# those five were never supposed to be caught in the first place:
#
#   detection   — a real detection gap/timing question. CAUGHT is good,
#                 MISSED means either a genuine gap or a module hasn't
#                 polled yet. (Initial Access, Persistence, Exfiltration.)
#   resilience  — a false-positive resilience check. NOT being caught IS
#                 the passing outcome; if something DOES fire on it, that's
#                 a false positive worth investigating. (Noise Injection.)
#   unmonitored — no detector exists for this by design (an explicit,
#                 already-made call — see angerona.academy's Discovery
#                 entry — not a bug to chase). Purely informational; never
#                 counted as a miss. (Discovery.)
STAGE_CATEGORY = {
    "Initial Access": "detection",
    "Discovery": "unmonitored",
    "Persistence (simulated)": "detection",
    "Noise Injection": "resilience",
    "Exfiltration": "detection",
}


@dataclass
class StepVerdict:
    stage: str
    technique: str
    description: str
    ts_start: float
    ok: bool
    category: str = "detection"
    catch: Optional[Event] = None
    catch_latency: Optional[float] = None
    remediation: Optional[Event] = None
    remediation_latency: Optional[float] = None


def _load_history(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _matches(step: dict, ev: Event) -> bool:
    details = ev.details or {}
    for p in step.get("artifact_paths", []):
        name = Path(p).name
        if details.get("path") == p or name in (ev.message or ""):
            return True
    pid = step.get("pid")
    if pid is not None and details.get("pid") == pid:
        return True
    return False


def _is_remediation(ev: Event) -> bool:
    return ev.module in ("Active Response SOAR", "SOAR Automation")


def evaluate(history: dict, events: List[Event],
             stage_category: Optional[dict] = None) -> List[StepVerdict]:
    """Walk events in chronological order and, for each step, find the first
    real-module event that matches its artifact (the "catch"), then the first
    SOAR event that follows it (the "remediation"). `stage_category` overrides
    the default shark map so a different drill (e.g. Red Team) can classify its
    own stages."""
    cats = stage_category or STAGE_CATEGORY
    chrono = sorted(events, key=lambda e: e.ts)
    verdicts: List[StepVerdict] = []
    for step in history.get("steps", []):
        v = StepVerdict(stage=step["stage"], technique=step["technique"],
                        description=step["description"], ts_start=step["ts_start"],
                        ok=step.get("ok", True),
                        category=cats.get(step["stage"], "detection"))
        for ev in chrono:
            if ev.ts < step["ts_start"] - 2 or ev.module == "Console":
                continue
            if _is_remediation(ev):
                if v.catch is not None and v.remediation is None and ev.ts >= v.catch.ts and _matches(step, ev):
                    v.remediation = ev
                    v.remediation_latency = round(ev.ts - v.catch.ts, 3)
                continue
            if v.catch is None and _matches(step, ev):
                v.catch = ev
                v.catch_latency = round(ev.ts - step["ts_start"], 3)
        verdicts.append(v)
    return verdicts


def _bar(ch: str = "=") -> str:
    return ch * WIDTH


def render(history: dict, verdicts: List[StepVerdict], title: str = "SHARK ATTACK") -> str:
    lines = [_bar("="), f" ANGERONA — {title} AFTER-ACTION REPORT", _bar("=")]
    lines.append(f" Run ID     : {history.get('run_id', '?')}")
    lines.append(f" Generated  : {history.get('generated', '?')}")
    n = len(verdicts)
    caught = sum(1 for v in verdicts if v.catch)
    remediated = sum(1 for v in verdicts if v.remediation)
    detection = [v for v in verdicts if v.category == "detection"]
    det_caught = sum(1 for v in detection if v.catch)
    lines.append(f" Steps run  : {n}     Raw catches: {caught}/{n}     Remediated: {remediated}/{n}")
    lines.append(f" (\"Raw catches\" includes every step regardless of what a pass looks like for "
                 "it — see the scorecard below for the number that actually matters: detection "
                 "coverage over the steps a detector is meant to catch.)")
    lines.append(_bar("-"))
    lines.append(" TIMELINE")
    lines.append(_bar("-"))
    for v in verdicts:
        if v.category == "unmonitored":
            status = "N/A    "
        elif v.category == "resilience":
            status = "FALSE-POS" if v.catch else "PASS   "
        else:
            status = "CAUGHT " if v.catch else "MISSED "
        lines.append(f" [{status}] {v.stage} — {v.technique}")
        lines.append(f"           {v.description}")

        if v.category == "unmonitored":
            lines.append("           no detector exists for this by design — read-only process/"
                         "connection enumeration is indistinguishable from ordinary admin-tool "
                         "activity without deeper behavioral correlation (see `academy explain "
                         f"\"{v.stage}\"` for the full reasoning). Informational only — not "
                         "counted in the detection coverage rate below.")
        elif v.category == "resilience":
            if v.catch:
                lines.append(f"           ⚠ {v.catch.module} fired on this — \"{v.catch.message}\" "
                             f"— but this step is a legitimate CPU/IO-heavy task with nothing "
                             "malicious about it. That's a FALSE POSITIVE worth investigating in "
                             f"{v.catch.module}'s trigger condition, not a successful catch.")
            else:
                lines.append("           correctly generated no alert — legitimate heavy CPU/IO "
                             "work should never be treated as malicious on its own. Silence here "
                             "is the passing outcome.")
        elif v.catch:
            lines.append(f"           detected by {v.catch.module} in "
                         f"{v.catch_latency:.2f}s — \"{v.catch.message}\"")
            if v.remediation:
                lines.append(f"           remediated by {v.remediation.module} in "
                             f"{v.remediation_latency:.2f}s — \"{v.remediation.message}\"")
            else:
                lines.append(f"           not remediated — {v.catch.severity.label} severity "
                             f"didn't meet Active Response SOAR's threshold (CRITICAL by "
                             "default; it deliberately won't auto-delete a merely-suspicious "
                             "new file). See ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY to "
                             "test a more aggressive policy.")
        elif v.stage == "Exfiltration":
            lines.append("           not yet detected — Network Monitor polls every 4s, so this "
                         "is rarely a timing issue. More likely: it deliberately doesn't re-alert "
                         "on a host it already saw within its novelty window (60 min by default), "
                         "so a repeat drill against the same test host within that window won't "
                         "generate a fresh alert even though the connection WAS observed (working "
                         "as designed — see `academy explain \"Exfiltration\"`). The engine "
                         "rotates between 3 test hosts per run to avoid this; if you've run several "
                         "drills back-to-back you may have cycled through all of them. Wait a few "
                         "minutes, or set ANGERONA_SHARK_EXFIL_HOST to a custom target, for a "
                         "guaranteed-fresh test.")
        else:
            lines.append("           not yet detected — some modules poll on an interval (FIM "
                         "~30s, YARA scans Downloads every 5 min); re-run this report "
                         "(`aar` in the console) later for the fullest picture.")
        lines.append("")
    lines.append(_bar("-"))
    lines.append(" SCORECARD")
    lines.append(_bar("-"))
    lines.append(f"   Detection coverage : {det_caught}/{len(detection)}  "
                 f"({(det_caught / len(detection) * 100 if detection else 0):.0f}%)   "
                 "— Initial Access / Persistence / Exfiltration-style steps only")
    lines.append(f"   Remediation rate   : {remediated}/{n}  ({(remediated / n * 100 if n else 0):.0f}%)")
    resilience = [v for v in verdicts if v.category == "resilience"]
    if resilience:
        fps = sum(1 for v in resilience if v.catch)
        lines.append(f"   Resilience check   : {'FAIL — false positive(s), see above' if fps else 'PASS — no false alert'}")
    unmon = [v for v in verdicts if v.category == "unmonitored"]
    if unmon:
        lines.append(f"   Unmonitored (info) : {', '.join(v.stage for v in unmon)} — no detector by design")
    times = [v.catch_latency for v in detection if v.catch_latency is not None]
    if times:
        lines.append(f"   Avg detect time    : {sum(times) / len(times):.2f}s   "
                     f"(fastest {min(times):.2f}s, slowest {max(times):.2f}s)")
    rtimes = [v.remediation_latency for v in verdicts if v.remediation_latency is not None]
    if rtimes:
        lines.append(f"   Avg mitigate time  : {sum(rtimes) / len(rtimes):.2f}s")
    lines.append(_bar("="))
    return "\n".join(lines)


def _report_dirs(data_dir: Path) -> List[Path]:
    """Same dual-location pattern core/status_report.py already uses: the
    per-user data dir (%LOCALAPPDATA%\\Angerona, not always reachable from
    outside the machine) AND <cwd>/diagnostics, which sits right next to the
    app in the repo — so the report is easy to find and read directly off
    disk (by a person, or an assistant working in this folder) without
    needing to run anything through the GUI or console first."""
    dirs = [Path(data_dir)]
    try:
        dirs.append(Path.cwd() / "diagnostics")
    except Exception:
        pass
    return dirs


def _write_report(data_dir: Path, history: dict, verdicts: List[StepVerdict], text: str,
                  basename: str = "shark_aar") -> None:
    """Persist both a human-readable .txt (identical to what's printed/shown
    in the GUI) and a structured .json (easy to parse programmatically) —
    always overwritten with the latest evaluation, so the files on disk
    never go stale relative to whatever `aar` or the review window last
    computed."""
    n = len(verdicts)
    caught = sum(1 for v in verdicts if v.catch)
    remediated = sum(1 for v in verdicts if v.remediation)
    detection = [v for v in verdicts if v.category == "detection"]
    payload = {
        "run_id": history.get("run_id"),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "steps_run": n,
        "detected": caught,               # raw count, all categories — kept for backward compat
        "remediated": remediated,
        "detection_steps": len(detection),      # steps where a detector SHOULD fire
        "detection_caught": sum(1 for v in detection if v.catch),
        "verdicts": [
            {
                "stage": v.stage,
                "technique": v.technique,
                "description": v.description,
                "ts_start": v.ts_start,
                "category": v.category,   # "detection" | "resilience" | "unmonitored"
                "caught": v.catch is not None,
                "detected_by": v.catch.module if v.catch else None,
                "detect_latency_s": v.catch_latency,
                "detect_message": v.catch.message if v.catch else None,
                "remediated": v.remediation is not None,
                "remediated_by": v.remediation.module if v.remediation else None,
                "remediate_latency_s": v.remediation_latency,
                "remediate_message": v.remediation.message if v.remediation else None,
            }
            for v in verdicts
        ],
    }
    for d in _report_dirs(data_dir):
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{basename}.txt").write_text(text, encoding="utf-8")
            (d / f"{basename}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            continue  # best-effort — a write failure here should never break the report itself


def generate_aar(data_dir: Optional[Path] = None, settle_seconds: float = 0.0,
                 window: float = 3600.0, history_name: str = "shark_history.json",
                 stage_category: Optional[dict] = None, title: str = "SHARK ATTACK",
                 report_basename: str = "shark_aar") -> str:
    """Build the report text, and persist it to shark_aar.txt / shark_aar.json
    (see _write_report) so it's readable straight off disk afterward.

    Call with ``settle_seconds`` > 0 right after a run completes to give
    fast-polling modules (e.g. File Integrity Monitor, 30s) one more cycle
    before judging a step a miss. Note YARA only scans Downloads every 5
    minutes by default, so a fresh report may legitimately show a file-drop
    step as "not yet detected" — re-running the report later will pick that
    up without needing another drill.
    """
    if settle_seconds > 0:
        time.sleep(settle_seconds)
    cfg = Config.load()
    data_dir = Path(data_dir or cfg.data_dir)
    history_path = data_dir / history_name
    if not history_path.exists():
        return f"No {history_name} found — run a drill first."
    history = _load_history(history_path)
    if not history.get("steps"):
        return "Last run recorded zero steps — nothing to report."

    recorder = FlightRecorder(cfg.db_path)
    try:
        run_start = min(s["ts_start"] for s in history["steps"])
        # events_in_window() queries by time range directly — no row-count cap,
        # so drills run long before the current session won't be silently empty
        # because newer events pushed them out of recent(2000).
        events = recorder.events_in_window(run_start - 5, run_start + window)
    finally:
        recorder.close()

    verdicts = evaluate(history, events, stage_category)
    text = render(history, verdicts, title)
    _write_report(data_dir, history, verdicts, text, report_basename)
    return text


if __name__ == "__main__":
    print(generate_aar())
