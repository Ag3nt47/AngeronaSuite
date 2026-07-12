"""
worldview.py — "World View" deep-transparency host telemetry engine.

Feeds the World View operations panel. Three data sources, all local & cheap:
  1. host_vs_suite_matrix — per-thread/suite resource use (RSS, CPU) vs the
     global Windows host, via psutil.
  2. eps_gauge — Events-Per-Second on Angerona's internal intake vs host
     activity; flags a "Telemetry Mismatch / Blinding" alarm when host activity
     spikes while our ingestion flatlines.
  3. ollama_diagnostics — local model VRAM footprint, tokens/sec, queue depth.

Pure engine (no GUI) so it's unit-testable; the GUI page just renders these dicts.
"""
from __future__ import annotations
import os, time

try:
    import psutil
except Exception:
    psutil = None

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")


class WorldViewEngine:
    def __init__(self):
        self._proc = psutil.Process(os.getpid()) if psutil else None
        self._eps_last_count = 0
        self._eps_last_t = time.time()
        self._host_last = None
        self._blind_strikes = 0
        self._ever_seen = False

    # ── 1. HOST-TO-SUITE COMPARISON MATRIX ───────────────────────────────────
    def host_vs_suite_matrix(self) -> dict:
        if not psutil:
            return {"available": False, "reason": "psutil not installed"}
        vm = psutil.virtual_memory()
        suite_rss = self._proc.memory_info().rss if self._proc else 0
        suite_cpu = self._proc.cpu_percent(interval=None) if self._proc else 0.0
        rows = []
        try:
            for t in (self._proc.threads() if self._proc else [])[:24]:
                rows.append({"thread_id": t.id,
                             "cpu_time_s": round(t.user_time + t.system_time, 2)})
        except Exception:
            pass
        return {
            "available": True,
            "host": {"total_ram_gb": round(vm.total / 1e9, 2),
                     "used_ram_pct": vm.percent,
                     "cpu_pct": psutil.cpu_percent(interval=None),
                     "cpu_logical": psutil.cpu_count(),
                     "processes": len(psutil.pids())},
            "suite": {"rss_mb": round(suite_rss / 1e6, 1),
                      "rss_pct_of_host": round(suite_rss / vm.total * 100, 2),
                      "cpu_pct": suite_cpu,
                      "threads": len(rows)},
            "threads": rows,
        }

    # ── 2. TELEMETRY SALIENCY & BLINDING DETECTOR ────────────────────────────
    def eps_gauge(self, internal_event_count: int) -> dict:
        now = time.time()
        dt = max(1e-6, now - self._eps_last_t)
        internal_eps = max(0.0, (internal_event_count - self._eps_last_count) / dt)
        self._eps_last_count, self._eps_last_t = internal_event_count, now
        if internal_eps > 0:
            self._ever_seen = True

        host_rate, host_live = 0.0, False
        if psutil:
            cur = psutil.cpu_stats().ctx_switches
            if self._host_last is not None:
                host_rate = max(0.0, (cur - self._host_last) / dt)
            self._host_last = cur
            host_live = host_rate > 500          # meaningful host activity

        blinding = host_live and internal_eps < 0.5
        self._blind_strikes = self._blind_strikes + 1 if blinding else 0
        # only alarm once the internal feed has proven it can flow (avoids a
        # false blinding alert before any events have been seen this session)
        alarm = self._blind_strikes >= 3 and self._ever_seen
        return {
            "internal_eps": round(internal_eps, 2),
            "host_ctx_switch_rate": round(host_rate, 0),
            "host_active": host_live,
            "blinding_suspected": blinding,
            "alarm": alarm,
            "banner": ("[CRITICAL: Telemetry Mismatch / Blinding Attack Detected]"
                       if alarm else None),
        }

    # ── 3. LOCAL AI DEEP DIAGNOSTICS ─────────────────────────────────────────
    def ollama_diagnostics(self) -> dict:
        try:
            import requests
        except Exception:
            return {"available": False, "reason": "requests not installed"}
        info = {"available": False}
        try:
            ps = requests.get(f"{OLLAMA_HOST}/api/ps", timeout=3).json()
            models = ps.get("models", [])
            if models:
                m = models[0]
                info.update(available=True, model=m.get("name"),
                            vram_mb=round(m.get("size_vram", m.get("size", 0)) / 1e6, 1),
                            queue=len(models))
        except Exception as e:
            info["reason"] = str(e)
        # quick tokens/sec probe (tiny deterministic gen)
        try:
            r = requests.post(f"{OLLAMA_HOST}/api/generate", timeout=8, json={
                "model": os.getenv("MODEL_NAME", "llama3:latest"), "prompt": "ok",
                "stream": False, "options": {"temperature": 0, "num_predict": 8}}).json()
            ec, ed = r.get("eval_count"), r.get("eval_duration")
            if ec and ed:
                info["tokens_per_sec"] = round(ec / (ed / 1e9), 1)
        except Exception:
            pass
        return info


if __name__ == "__main__":
    import json
    e = WorldViewEngine()
    print("matrix:", json.dumps(e.host_vs_suite_matrix(), indent=2)[:400])
    e.eps_gauge(0); time.sleep(0.1)
    print("eps:", json.dumps(e.eps_gauge(0), indent=2))
    print("ollama:", json.dumps(e.ollama_diagnostics(), indent=2))
