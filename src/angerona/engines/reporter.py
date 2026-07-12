"""
reporter.py — Post-Mitigation Cryptographic and Behavioral Forensics Reporting Engine
"""
import os
import json
import uuid
import time
import hashlib
import psutil
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

def generate_summary_report(pid: int, name: str, mitigation_type: str, evidence_locker: str, log_module) -> dict:
    """Compiles static file hashes, runtime properties, and dynamic anomalies into a detailed JSON summary record."""
    report_path = os.path.join(evidence_locker, "incident_summary_report.json")
    
    # Pull static hashes safely
    sha256_hash = "UNKNOWN_OR_UNAVAILABLE"
    MAX_HASH_BYTES = 200 * 1024 * 1024  # 200MB cap -- avoid hanging on huge binaries
    try:
        # Direct lookup by PID instead of scanning every running process.
        exe_path = psutil.Process(pid).exe()
        if exe_path and os.path.exists(exe_path):
            hasher = hashlib.sha256()
            bytes_read = 0
            with open(exe_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= MAX_HASH_BYTES:
                        sha256_hash = f"{hasher.hexdigest()} (TRUNCATED_AT_{MAX_HASH_BYTES}_BYTES)"
                        break
                else:
                    sha256_hash = hasher.hexdigest()
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        pass
    except Exception:
        pass

    report_payload = {
        "incident_id": str(uuid.uuid4()),
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "mitigation_action": mitigation_type,
        "process_identity": {
            "target_pid": pid,
            "image_name": name,
            "sha256_checksum": sha256_hash
        },
        "dynamic_behavior_summary": {
            "canary_tampering_detected": True,
            "evidence_directory_route": evidence_locker
        }
    }
    
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=4)
        log_module.info("REPORTER", f"Compiled post-containment ledger safely stored under: {report_path}")
    except Exception as e:
        log_module.error("REPORTER", "Failed to write local ledger file to desk", data={"error": str(e)})
        
    return report_payload

def build_visual_report_panel(report_data: dict, width: int) -> Panel:
    """Formats the extracted properties summary report into an inspection dashboard layout panel component."""
    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_row("[bold cyan]INCIDENT ID :[/]", report_data["incident_id"])
    t.add_row("[bold red]MITIGATION  :[/]", report_data["mitigation_action"])
    t.add_row("[bold white]TARGET PID  :[/]", str(report_data["process_identity"]["target_pid"]))
    t.add_row("[bold white]IMAGE NAME  :[/]", report_data["process_identity"]["image_name"])
    t.add_row("[bold yellow]SHA-256     :[/]", report_data["process_identity"]["sha256_checksum"])
    t.add_row("[bold green]LOCKER PATH :[/]", report_data["dynamic_behavior_summary"]["evidence_directory_route"])
    
    return Panel(t, title="🔒 INCIDENT BRIEFING LIFE-CYCLE COMPLETE", border_style="bold green", expand=True)


# ── Continuous Benchmarking Dashboard — MTTR analytics (Component 3) ──────────
# Measures how many EVOL iterations (rounds) it takes to drive a technique from a
# VERIFICATION_RESULT: SUCCESS (bypass) back down to a certified BLOCKED state,
# and tracks whether the AI's patch-generation is improving or degrading.
from pathlib import Path as _Path
import statistics as _stats


def _shared_logs_dir() -> "_Path":
    # engines/reporter.py -> src/angerona/engines -> repo root/shared_logs
    return _Path(__file__).resolve().parents[3] / "shared_logs"


def _mttr_trend(rounds: list) -> str:
    if len(rounds) < 4:
        return "insufficient-data"
    half = len(rounds) // 2
    early = sum(rounds[:half]) / half
    late = sum(rounds[half:]) / (len(rounds) - half)
    if late < early - 0.25:
        return "improving"      # fewer rounds to certify over time = getting better
    if late > early + 0.25:
        return "degrading"
    return "stable"


def compute_mttr(history: list | None = None) -> dict:
    """Read the EVOL evolution history and compute Mean-Time-To-Remediate metrics.
    MTTR here = the number of evolution rounds (SUCCESS→…→BLOCKED) per technique."""
    sl = _shared_logs_dir()
    if history is None:
        try:
            history = json.loads((sl / "evolution_history.json").read_text(encoding="utf-8"))
        except Exception:
            history = []
    if not isinstance(history, list):
        history = []
    certified = [h for h in history if h.get("certified")]
    rounds = [int(h.get("iterations", len(h.get("attempts", [])))) for h in certified]
    total = len(history)
    analytics = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cycles": total,
        "certified": len(certified),
        "unresolved": total - len(certified),
        "success_rate_pct": round(len(certified) / total * 100, 1) if total else 0.0,
        "mttr_rounds_mean": round(_stats.mean(rounds), 2) if rounds else None,
        "mttr_rounds_best": min(rounds) if rounds else None,
        "mttr_rounds_worst": max(rounds) if rounds else None,
        "trend": _mttr_trend(rounds),
        "per_technique": [
            {"technique": h.get("technique"), "certified": bool(h.get("certified")),
             "rounds": int(h.get("iterations", len(h.get("attempts", [])))),
             "ts": h.get("ts", "")}
            for h in history[-12:]
        ],
    }
    # Persist the rollup next to the raw history (companion file; the raw
    # evolution_history.json stays a plain list that EVOL appends to).
    try:
        sl.mkdir(parents=True, exist_ok=True)
        (sl / "mttr_analytics.json").write_text(json.dumps(analytics, indent=2), encoding="utf-8")
    except Exception:
        pass
    return analytics


def build_mttr_panel(width: int = 90) -> Panel:
    """Rich panel showing per-technique MTTR history and the overall trend."""
    a = compute_mttr()
    t = Table(box=None, expand=True)
    t.add_column("Technique", style="bold cyan", no_wrap=True)
    t.add_column("Result", justify="center")
    t.add_column("MTTR (rounds)", justify="right")
    t.add_column("When", style="dim")
    if not a["per_technique"]:
        t.add_row("—", "no evolution cycles yet", "—", "")
    for row in a["per_technique"]:
        res = "[bold green]CERTIFIED[/]" if row["certified"] else "[bold red]UNRESOLVED[/]"
        t.add_row(str(row["technique"]), res, str(row["rounds"]), str(row["ts"]))
    tcol = {"improving": "green", "degrading": "red", "stable": "yellow"}.get(a["trend"], "white")
    mean = a["mttr_rounds_mean"]
    sub = (f"cycles {a['cycles']} · certified {a['certified']}/{a['cycles']} "
           f"({a['success_rate_pct']}%) · mean MTTR {mean if mean is not None else '—'} rounds "
           f"· trend [{tcol}]{a['trend']}[/]")
    return Panel(t, title="📈 MTTR — AI PATCH-GENERATION BENCHMARK", subtitle=sub,
                 border_style="cyan", expand=True)