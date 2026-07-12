"""Status reporter — writes a live snapshot of the whole app to disk.

Every few seconds it dumps the full dashboard state (modules + statuses, recent
alerts, counts, threat level) to two files:

    diagnostics/status.json   machine-readable
    diagnostics/status.txt    human-readable (mirrors the GUI)

This is the bridge that lets a person (or an assistant) who can't see the GUI
understand exactly what's on screen — just read status.txt.

Files are written both to the per-user data dir and to ``<cwd>/diagnostics`` so
they're easy to find next to the app.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import List

from angerona import __version__
from angerona.core.eventbus import Severity
from angerona.core.privilege import is_admin

_THREAT = {Severity.INFO: "SECURE", Severity.LOW: "LOW", Severity.MEDIUM: "ELEVATED",
           Severity.HIGH: "HIGH", Severity.CRITICAL: "CRITICAL"}


class StatusReporter:
    def __init__(self, bus, storage, manager, config, interval: float = 3.0) -> None:
        self.bus, self.storage, self.manager, self.config = bus, storage, manager, config
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

        self._dirs: List[Path] = []
        for base in (config.data_dir, Path.cwd()):
            try:
                d = Path(base) / "diagnostics"
                d.mkdir(parents=True, exist_ok=True)
                self._dirs.append(d)
            except Exception:
                continue

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="StatusReporter", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._write()  # one final snapshot on shutdown

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._write()
            except Exception:
                pass
            self._stop.wait(self.interval)

    # ── Snapshot ─────────────────────────────────────────────────────────────
    def _snapshot(self) -> dict:
        from angerona.core.threat import threat_level
        events = self.bus.recent(200)
        running = sum(1 for m in self.manager.modules.values() if m.status == "running")
        mods = []
        for name, m in sorted(self.manager.modules.items()):
            mods.append({
                "name": m.name, "category": m.category, "version": m.version,
                "status": m.status, "health": m.health, "health_state": m.health_state,
                "health_note": m.health_note, "enabled": self.manager.is_enabled(name),
                "last_error": m.last_error,
            })
        return {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "app_version": __version__,
            "admin": is_admin(),
            "threat_level": _THREAT[threat_level(events)],
            "counts": {
                "modules_total": len(self.manager.modules),
                "modules_running": running,
                "alerts_24h": self.storage.count_since(time.time() - 86400),
                "critical_24h": sum(1 for e in events if e.severity == Severity.CRITICAL),
            },
            "ollama": {"host": self.config.ollama_host, "model": self.config.ollama_model},
            "modules": mods,
            "recent_events": [
                {"time": e.time_str, "module": e.module,
                 "severity": e.severity.label, "message": e.message}
                for e in self.bus.recent(60)
            ],
        }

    def _render_text(self, s: dict) -> str:
        c = s["counts"]
        lines = [
            "=" * 78,
            " ANGERONA — LIVE STATUS SNAPSHOT",
            "=" * 78,
            f" Generated : {s['generated']}     v{s['app_version']}     Admin: {s['admin']}",
            f" Threat    : {s['threat_level']}",
            f" Modules   : {c['modules_running']}/{c['modules_total']} running"
            f"     Alerts(24h): {c['alerts_24h']}     Critical(24h): {c['critical_24h']}",
            f" Ollama    : {s['ollama']['host']}  (model: {s['ollama']['model']})",
            "",
            "-" * 78,
            " MODULES",
            "-" * 78,
        ]
        for m in s["modules"]:
            flag = "x" if m["enabled"] else " "
            health = f"{m['health']:>3}% {m['health_state']:<9}"
            line = f"  [{flag}] {m['status']:<8} {health} {m['name']:<26} ({m['category']})"
            if m.get("health_note"):
                line += f"\n        note: {m['health_note']}"
            if m["last_error"]:
                line += f"\n        last error: {m['last_error']}"
            lines.append(line)
        lines += ["", "-" * 78, " RECENT EVENTS (newest first)", "-" * 78]
        for e in s["recent_events"]:
            lines.append(f"  {e['time']}  {e['severity']:<8} {e['module']:<26} {e['message']}")
        lines.append("")
        return "\n".join(lines)

    def _write(self) -> None:
        snap = self._snapshot()
        text = self._render_text(snap)
        for d in self._dirs:
            try:
                (d / "status.json").write_text(json.dumps(snap, indent=2), encoding="utf-8")
                (d / "status.txt").write_text(text, encoding="utf-8")
            except Exception:
                continue
