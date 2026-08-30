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
import weakref

from angerona.core.module_base import BaseModule, Severity
from angerona.engines import ollama_client

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
    version = "1.13.0"

    _MAX_INFLIGHT = 2          # concurrent prewarm workers
    _COOLDOWN = 8.0            # per-PID re-prewarm cooldown (s)
    _FRAME_MAX_AGE = 30.0      # never reuse context across a stale/PID-reuse window
    _KEEP_ALIVE = "10m"        # keep the model resident between frames
    _KEEP_ALIVE_SECONDS = 600.0
    _WORKER_IDLE_POLL = 0.1    # prompt stop response while the queue is idle

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=256)
        self._primed: dict[int, dict] = {}     # pid -> {prompt, ts}
        self._last_prewarm: dict[int, float] = {}
        self._last_cooldown_cleanup = 0.0
        self._workers: list[threading.Thread] = []
        self._consumer_ref: weakref.ReferenceType | None = None
        self._subscription_ready = False
        self._last_warm_succeeded: bool | None = None
        self._last_success_at = 0.0
        self.prewarms = 0
        self.successful_prewarms = 0
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
            # Keep cooldown state only for the interval in which it can affect a
            # decision. Unique short-lived PIDs otherwise accumulated forever in
            # long sessions even though their entries became inert after 8 s.
            if now - self._last_cooldown_cleanup >= self._COOLDOWN:
                cutoff = now - self._COOLDOWN
                self._last_prewarm = {
                    old_pid: stamp for old_pid, stamp in self._last_prewarm.items()
                    if stamp > cutoff
                }
                self._last_cooldown_cleanup = now
            if now - self._last_prewarm.get(pid, 0.0) < self._COOLDOWN:
                return False
            self._last_prewarm[pid] = now
        try:
            self._q.put_nowait(marker)
            return True
        except queue.Full:
            return False

    def bind_consumer(self, consumer: object) -> bool:
        """Bind the one production triage consumer this optimization serves.

        A health score for speculative work is meaningful only when the real AI
        triage path can consume it.  Bind by exact built-in type and shared bus;
        a look-alike extension cannot make this module report production reuse.
        """
        consumer_type = type(consumer)
        valid = (
            consumer_type.__module__ == "angerona.modules.ai_triage"
            and consumer_type.__name__ == "AITriageModule"
            and getattr(consumer, "name", "") == "AI Triage (Ollama)"
            and self._bus is not None
            and getattr(consumer, "_bus", None) is self._bus
        )
        with self.state_lock:
            self._consumer_ref = weakref.ref(consumer) if valid else None
        return valid

    def _consumer_ready(self) -> bool:
        with self.state_lock:
            consumer = self._consumer_ref() if self._consumer_ref is not None else None
        return bool(
            consumer is not None
            and getattr(consumer, "_bus", None) is self._bus
            and getattr(consumer, "status", "") == "running"
        )

    @staticmethod
    def _birth_identity(value: object) -> str:
        if value is None or value == "":
            return ""
        try:
            return f"{float(value):.6f}"
        except (TypeError, ValueError):
            return str(value).strip()

    def get_primed(
        self,
        pid: int,
        *,
        consumer: object | None = None,
        process_birth: object = None,
    ) -> dict | None:
        """Consume one fresh, successfully warmed frame for an exact process.

        Frames are one-shot.  Failed warms, stale frames, unbound callers and a
        mismatched process-birth identity never receive reusable context.
        """
        now = time.time()
        with self.state_lock:
            bound = self._consumer_ref() if self._consumer_ref is not None else None
            frame = self._primed.pop(pid, None) if consumer is bound else None
            if frame is None:
                return None
            fresh = 0.0 <= now - float(frame.get("ts", 0.0)) <= self._FRAME_MAX_AGE
            same_birth = self._birth_identity(process_birth) == self._birth_identity(
                frame.get("process_birth")
            )
            if not bool(frame.get("warmed")) or not fresh or not same_birth:
                return None
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
        primed = {
            "prompt": prompt,
            "ts": time.time(),
            "warmed": False,
            "process_birth": (marker.get("details") or {}).get("process_birth"),
        }
        try:
            from angerona.modules.ai_model_integrity import (
                require_fresh_model_attestation,
            )

            require_fresh_model_attestation(_MODEL)
            result = ollama_client.analyze_telemetry(
                "Pre-warm the local model for a possible endpoint triage. Return one token.",
                prompt,
                _MODEL,
                host=_OLLAMA,
                timeout=20,
                keep_alive=self._KEEP_ALIVE,
                options={"temperature": 0, "num_predict": 1},
            )
            primed["warmed"] = not bool(result.get("error"))
            if not primed["warmed"]:
                self.last_error = str(result.get("error"))
        except Exception as exc:
            self.last_error = str(exc)      # offline: intent recorded, not warmed
        with self.state_lock:
            self._primed[pid] = primed
            self.prewarms += 1
            self._last_warm_succeeded = bool(primed["warmed"])
            if primed["warmed"]:
                self.successful_prewarms += 1
                self._last_success_at = time.time()
            if len(self._primed) > 256:      # bound the cache
                oldest = min(self._primed, key=lambda k: self._primed[k]["ts"])
                self._primed.pop(oldest, None)
        self.emit(
            f"Pre-warmed triage frame for pid {pid} "
            f"({'model resident' if primed['warmed'] else 'not reusable (Ollama offline)'}).",
            Severity.INFO if primed["warmed"] else Severity.MEDIUM,
            pid=pid,
            warmed=primed["warmed"],
        )

    def _update_health(self) -> None:
        with self.state_lock:
            last_warm_succeeded = self._last_warm_succeeded
            successes = self.successful_prewarms
            prewarms = self.prewarms
            last_success_at = self._last_success_at
        if not self._subscription_ready:
            self.set_health(35, "event-bus subscription unavailable; no early markers observed")
            return
        if not self._consumer_ready():
            self.set_health(60, "production AI-triage consumer is not running/bound")
            return
        if last_warm_succeeded is False:
            self.set_health(40, f"latest model pre-warm failed: {self.last_error or 'unknown error'}")
            return
        if successes == 0:
            self.set_health(85, "consumer ready; awaiting first successful model pre-warm")
            return
        age = max(0.0, time.time() - last_success_at)
        if age > self._KEEP_ALIVE_SECONDS:
            self.set_health(75, f"last successful model pre-warm is stale ({round(age)}s old)")
            return
        hit_rate = (self.hits / prewarms * 100) if prewarms else 0.0
        self.set_health(
            100,
            f"{successes}/{prewarms} successful prewarms, {round(hit_rate, 1)}% reused",
        )

    def _worker(
        self,
        generation_stop: threading.Event,
        helper_stop: threading.Event,
    ) -> None:
        """Consume only for the generation that created this worker."""
        while not generation_stop.is_set() and not helper_stop.is_set():
            try:
                marker = self._q.get(timeout=self._WORKER_IDLE_POLL)
            except queue.Empty:
                continue
            if generation_stop.is_set() or helper_stop.is_set():
                # Preserve a marker that arrived during a stop so a later
                # generation can pre-warm it; this worker must not act after its
                # generation has been retired.
                try:
                    self._q.put_nowait(marker)
                except queue.Full:
                    pass
                return
            self._prewarm(marker)

    def run(self) -> None:
        stop_event = self.generation_stop_event()
        helper_stop = threading.Event()
        if self._bus is not None:
            try:
                self._bus.subscribe(self._on_event)
                self._subscription_ready = True
            except Exception:
                self._subscription_ready = False
        workers: list[threading.Thread] = []
        for _ in range(self._MAX_INFLIGHT):
            t = threading.Thread(
                target=self._worker,
                args=(stop_event, helper_stop),
                name="SPEC-prewarm",
                daemon=True,
            )
            t.start()
            workers.append(t)
        # Keep only the current generation's bounded worker set. BaseModule will
        # not start the next main generation until this run() has joined them.
        self._workers = workers
        self.emit("SPEC online — speculatively pre-warming the triage model.", Severity.INFO)
        try:
            while not stop_event.is_set():
                self._update_health()
                self.sleep(5.0)
        finally:
            helper_stop.set()
            # _prewarm() has a bounded HTTP timeout. Waiting here keeps the main
            # generation alive until its helpers are gone; stop() itself remains
            # non-blocking because this cleanup runs on the module thread.
            for worker in workers:
                worker.join()
            if self._workers is workers:
                self._workers = []

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
