"""core/ir_bundle.py — one-click Incident-Response triage bundle.

When something's wrong you want a snapshot of the machine RIGHT NOW, before
evidence changes or you start pulling the plug. ``collect_triage_bundle()`` grabs
the volatile forensic state — full process list (with command lines + parentage),
network connections, logged-on users, system info — plus whatever Angerona has
already recorded (remediation stats, the incident timeline, the latest briefing,
recent diagnostics) and writes it all into a single timestamped ZIP.

Hand that zip to an analyst (or keep it for the after-action) and they have the
"what was happening" picture without needing live access. Read-only collection;
no host change, no network.
"""
from __future__ import annotations

import io
import json
import platform
import time
import zipfile
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


def _shared_logs() -> Path:
    return Path(__file__).resolve().parents[3] / "shared_logs"


def _process_list() -> list[dict]:
    if psutil is None:
        return []
    procs: list[dict] = []
    for p in psutil.process_iter(["pid", "ppid", "name", "username", "create_time"]):
        row = dict(p.info)
        try:
            row["exe"] = p.exe()
        except Exception:
            row["exe"] = ""
        try:
            row["cmdline"] = " ".join(p.cmdline())
        except Exception:
            row["cmdline"] = ""
        try:
            row["mem_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
        except Exception:
            row["mem_mb"] = None
        procs.append(row)
    procs.sort(key=lambda r: (r.get("mem_mb") or 0), reverse=True)
    return procs


def _connections() -> list[dict]:
    if psutil is None:
        return []
    out: list[dict] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            out.append({
                "pid": c.pid,
                "status": c.status,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "type": "tcp" if c.type == 1 else "udp",
            })
    except Exception:
        pass
    return out


def _system_info() -> dict:
    info = {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if psutil is not None:
        try:
            info["boot_time"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(psutil.boot_time()))
        except Exception:
            pass
        try:
            info["users"] = [u.name for u in psutil.users()]
        except Exception:
            pass
        try:
            vm = psutil.virtual_memory()
            info["mem_total_mb"] = round(vm.total / (1024 * 1024))
            info["mem_percent"] = vm.percent
        except Exception:
            pass
    return info


# Angerona artifacts to fold in if they exist.
_INCLUDE_FILES = (
    "remediation_stats.json",
    "incident_timeline.json",
    "daily_briefing.txt",
    "daily_briefing.json",
)


def collect_triage_bundle(dest_dir: str | Path | None = None,
                          bus=None) -> Path:
    """Collect volatile forensic state into a timestamped ZIP; return its path."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    logs = _shared_logs()
    if dest_dir is None:
        dest_dir = logs / "ir_bundles"
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dest_dir / f"ir_triage_{stamp}.zip"

    sysinfo = _system_info()
    procs = _process_list()
    conns = _connections()

    # Optional live snapshots from the running suite.
    recent_events: list = []
    incidents: list = []
    if bus is not None:
        try:
            for ev in bus.recent(300):
                recent_events.append({
                    "ts": getattr(ev, "ts", None),
                    "module": getattr(ev, "module", None),
                    "severity": getattr(getattr(ev, "severity", None), "name", None),
                    "message": (getattr(ev, "message", "") or "")[:300],
                    "details": getattr(ev, "details", None),
                })
        except Exception:
            pass
        try:
            from angerona.core.incident_timeline import build_timeline
            incidents = build_timeline(bus)
        except Exception:
            pass

    manifest = {
        "bundle": zip_path.name,
        "generated": sysinfo["collected_at"],
        "counts": {"processes": len(procs), "connections": len(conns),
                   "events": len(recent_events), "incidents": len(incidents)},
    }

    def _proc_table_txt() -> str:
        lines = [f"{'PID':>7} {'PPID':>7} {'MEM_MB':>8}  NAME / CMDLINE"]
        for r in procs:
            lines.append(f"{r.get('pid',''):>7} {r.get('ppid',''):>7} "
                         f"{str(r.get('mem_mb','')):>8}  {r.get('name','')}  "
                         f"{r.get('cmdline','')[:160]}")
        return "\n".join(lines)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("00_MANIFEST.json", json.dumps(manifest, indent=2))
        z.writestr("01_system_info.json", json.dumps(sysinfo, indent=2, default=str))
        z.writestr("02_processes.json", json.dumps(procs, indent=2, default=str))
        z.writestr("02_processes.txt", _proc_table_txt())
        z.writestr("03_connections.json", json.dumps(conns, indent=2, default=str))
        if recent_events:
            z.writestr("04_recent_events.json",
                       json.dumps(recent_events, indent=2, default=str))
        if incidents:
            z.writestr("05_incident_timeline.json",
                       json.dumps(incidents, indent=2, default=str))
        for fname in _INCLUDE_FILES:
            fp = logs / fname
            try:
                if fp.exists():
                    z.write(fp, arcname=f"angerona/{fname}")
            except Exception:
                pass
        z.writestr("README.txt",
                   "Angerona IR triage bundle.\nCollected volatile host state at "
                   f"{sysinfo['collected_at']}.\nSee 00_MANIFEST.json for contents.\n")
    return zip_path


def self_test() -> tuple[bool, str]:
    """Build a bundle into a temp dir and verify the ZIP + core members."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = collect_triage_bundle(dest_dir=td)
        if not path.exists():
            return False, "bundle zip was not created"
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
        required = {"00_MANIFEST.json", "01_system_info.json",
                    "02_processes.json", "03_connections.json", "README.txt"}
        ok = required.issubset(names)
        return ok, (f"IR bundle built with {len(names)} members "
                    f"({path.name})" if ok else
                    f"failed: missing {required - names}")
