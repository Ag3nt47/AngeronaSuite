"""speculative_triage.py — Speculative Triage Pre-Warming Engine (Code: SPEC).

Purpose
    Cut local-LLM verdict latency toward sub-second by *predicting* which events
    will need triage and pre-warming the model's context before the full
    ``SecurityIncident`` payload is assembled.

How
    SPEC taps the telemetry stream at Step 1 (early markers), before behavioural
    assembly finishes. When a high-risk early signal appears — e.g. an unknown
    process spawning from a temp/AppData/Downloads directory — it speculatively:
      1. batches a raw environment snapshot snippet, and
      2. "pre-streams" it to Ollama as a low-cost predictive frame
         (``keep_alive`` load + primed prompt), so the model is resident and the
         context window is warm.
    By the time Step 3 dispatches the final structured payload, the assembled
    prompt is reused and the verdict returns with no cold-start / context-shift
    delay.

    Fully offline-safe: if Ollama is unreachable the intent is recorded and the
    module degrades gracefully rather than erroring.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import queue
import threading
import time

from angerona.core.module_base import BaseModule, Severity

_OLLAMA = os.getenv("OLLAMA_HOST", "http://localhost:11434")
_MODEL = os.getenv("MODEL_NAME", "llama3:latest")

# early, cheap-to-observe markers that a full triage is probably coming
_TEMP_HINTS = ("\\temp\\", "/temp/", "\\tmp\\", "\\appdata\\local\\temp",
               "\\downloads\\", "\\programdata\\", "%temp%")
_RISK_HINTS = ("spawn", "new process", "unsigned", "unknown process",
               "execution from", "temp dir", "child process")


class SpeculativeTriageModule(BaseModule):
    CODE = "SPEC"
    NAME = "Speculative Triage Pre-Warm"
    name = "Speculative Triage Pre-Warm"
    description = ("Detects high-risk early markers and pre-streams a snapshot to "
                   "Ollama so the final triage verdict returns with no cold start.")
    category = "Performance"
    version = "1.0.0"

    _MAX_INFLIGHT = 2          # concurrent prewarm workers
    _COOLDOWN = 8.0            # per-PID re-prewarm cooldown (s)
    _KEEP_ALIVE = "10m"        # keep the model resident between frames

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=256)
        self._primed: dict[int, dict] = {}     # pid -> {prompt, ts}
        self._last_prewarm: dict[int, float] = {}
        self._workers: list[threading.Thread] = []
        self.prewarms = 0
        self.hits = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── marker detection ─────────────────────────────────────────────────────
    @staticmethod
    def _is_high_risk(message: str, details: dict) -> bool:
        blob = (message or "").lower() + " " + " ".join(
            str(v).lower() for v in details.values())
        temp = any(h in blob for h in _TEMP_HINTS)
        risky = any(h in blob for h in _RISK_HINTS)
        return temp and risky

    def _on_event(self, event) -> None:
        try:
            if self._is_high_risk(event.message, event.details or {}):
                self.speculate({"pid": (event.details or {}).get("pid"),
                                "message": event.message,
                                "details": event.details or {}, "ts": event.ts})
        except Exception:
            pass

    def speculate(self, marker: dict) -> bool:
        """Queue a speculative prewarm for an early marker (deduped + cooled)."""
        pid = marker.get("pid") or -1
        now = time.time()
        with self.state_lock:
            if now - self._last_prewarm.get(pid, 0.0) < self._COOLDOWN:
                return False
            self._last_prewarm[pid] = now
        try:
            self._q.put_nowait(marker)
            return True
        except queue.Full:
            return False

    def get_primed(self, pid: int) -> dict | None:
        """Step-3 hook: reuse the warm frame for `pid` if one exists."""
        with self.state_lock:
            frame = self._primed.get(pid)
        if frame:
            self.hits += 1
        return frame

    # ── prewarm worker ───────────────────────────────────────────────────────
    def _snapshot(self, marker: dict) -> str:
        d = marker.get("details", {})
        return ("SPECULATIVE PRE-TRIAGE FRAME (pre-assembly). Prepare to classify a "
                "possible endpoint threat.\n"
                f"pid={marker.get('pid')} early_marker={marker.get('message')}\n"
                f"context={ {k: d[k] for k in list(d)[:8]} }")

    def _prewarm(self, marker: dict) -> None:
        prompt = self._snapshot(marker)
        pid = marker.get("pid") or -1
        primed = {"prompt": prompt, "ts": time.time(), "warmed": False}
        try:
            import requests
            requests.post(f"{_OLLAMA}/api/generate", timeout=20, json={
                "model": _MODEL, "stream": False, "keep_alive": self._KEEP_ALIVE,
                "options": {"temperature": 0, "num_predict": 1},
                "prompt": prompt})
            primed["warmed"] = True
        except Exception as exc:
            self.last_error = str(exc)      # offline: intent recorded, not warmed
        with self.state_lock:
            self._primed[pid] = primed
            self.prewarms += 1
            if len(self._primed) > 256:      # bound the cache
                oldest = min(self._primed, key=lambda k: self._primed[k]["ts"])
                self._primed.pop(oldest, None)
        self.emit(f"Pre-warmed triage frame for pid {pid} "
                  f"({'model resident' if primed['warmed'] else 'queued (Ollama offline)'}).",
                  Severity.INFO, pid=pid, warmed=primed["warmed"])

    def _worker(self) -> None:
        while not self.stopping:
            try:
                marker = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            self._prewarm(marker)

    def run(self) -> None:
        if self._bus is not None:
            try:
                self._bus.subscribe(self._on_event)
            except Exception:
                pass
        for _ in range(self._MAX_INFLIGHT):
            t = threading.Thread(target=self._worker, name="SPEC-prewarm", daemon=True)
            t.start()
            self._workers.append(t)
        self.emit("SPEC online — speculatively pre-warming the triage model.", Severity.INFO)
        while not self.stopping:
            hit_rate = (self.hits / self.prewarms * 100) if self.prewarms else 0.0
            self.set_health(100, f"{self.prewarms} prewarms, {round(hit_rate,1)}% reused")
            self.sleep(5.0)

    def self_test(self) -> tuple[bool, str]:
        """Verify marker detection fires for a temp-dir spawn and not for noise."""
        hot = self._is_high_risk("Unknown process spawn",
                                  {"path": r"C:\Users\x\AppData\Local\Temp\a.exe"})
        cold = self._is_high_risk("Routine connection", {"raddr": "1.1.1.1"})
        if hot and not cold:
            return True, "early high-risk marker detection verified"
        return False, f"marker logic off (hot={hot}, cold={cold})"


def register() -> SpeculativeTriageModule:
    return SpeculativeTriageModule()
