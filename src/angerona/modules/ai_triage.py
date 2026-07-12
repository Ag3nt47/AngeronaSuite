"""AI triage module.

Subscribes to high-severity events and asks a local Ollama model to explain and
score them in plain language. This is the clean port of Angerona's core_engine
Ollama call — local-first, with the cloud path left as an opt-in extension.

Because modules are event *producers* by default, this one also taps the bus as
a consumer: the ModuleManager binds the bus, and we read recent high-severity
events on a timer to avoid recursive feedback (AI verdicts are emitted at INFO).
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional

import urllib.request

from angerona.core.module_base import BaseModule, Severity

SYSTEM_PROMPT = (
    "You are a local SOC analyst. Given a security event, respond with a single "
    "short sentence: a plain-language explanation and whether it looks benign or "
    "malicious. Be concise."
)


class AITriageModule(BaseModule):
    name = "AI Triage (Ollama)"
    description = "Explains and scores serious events using a local LLM (Ollama)."
    category = "AI"

    # ── Circuit breaker constants ────────────────────────────────────────────
    # If Ollama doesn't respond within _CB_TIMEOUT_S seconds the circuit trips.
    # The recovery pinger retries every _CB_RECOVERY_S seconds in the background.
    # Local inference (a COLD load, or CPU-only / heavily-loaded host) can take far
    # longer than 15 s for the first reply. A 15 s cap tripped the breaker on a
    # perfectly healthy Ollama and left it "unavailable". 90 s lets a cold
    # llama3:8B load + answer; once warm (keep_alive) replies are quick.
    _CB_TIMEOUT_S  = 90.0    # seconds before tripping
    _CB_RECOVERY_S = 30.0   # seconds between recovery pings while open

    def __init__(self) -> None:
        super().__init__()
        self._host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self._model = os.environ.get("ANGERONA_MODEL", "llama3")
        self._last_ts = 0.0
        # Circuit breaker — "closed" = normal, "open" = Ollama hung/dead
        self._cb_state = "closed"             # type: str
        self._cb_lock  = threading.Lock()

    def _ask(self, prompt: str) -> Optional[str]:
        """Send a prompt to Ollama, respecting the circuit breaker.

        Returns the model's response, or None if the circuit is open / request
        fails.  A failure while the circuit is CLOSED trips it and emits HIGH.
        """
        # Fast-fail — never block on a known-bad Ollama
        with self._cb_lock:
            if self._cb_state == "open":
                return None

        # BL-03: neutralize attacker-influenced telemetry so embedded instructions
        # are treated as data, not commands.
        try:
            from angerona.engines.ai_guardrail import neutralize_telemetry
            user_content = neutralize_telemetry(prompt)
        except Exception:
            user_content = prompt

        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "stream": False,
            "keep_alive": "30m",   # keep llama3 resident — avoid per-incident cold starts
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._host}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._CB_TIMEOUT_S) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return (data.get("message", {}) or {}).get("content", "").strip()
        except Exception as exc:
            self.last_error = str(exc)
            with self._cb_lock:
                if self._cb_state == "closed":
                    self._cb_state = "open"
                    self.emit(
                        f"AI circuit breaker TRIPPED — Ollama timeout/error after "
                        f"{self._CB_TIMEOUT_S}s: {exc}. Falling back to deterministic rules.",
                        Severity.HIGH,
                        cb_state="open",
                    )
            return None

    def _ping_ollama(self) -> bool:
        """Direct health-check that bypasses the circuit breaker.

        Used by the recovery pinger to test if Ollama has come back online.
        Returns True if the model responds to a simple prompt.
        """
        payload = json.dumps({
            "model": self._model,
            "messages": [{"role": "user", "content": "Reply 'ready'."}],
            "stream": False,
            "keep_alive": "30m",          # keep the model resident between checks
            "options": {"num_predict": 8},  # tiny reply → fast once loaded
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._host}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._CB_TIMEOUT_S) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return bool((data.get("message", {}) or {}).get("content", "").strip())
        except Exception:
            return False

    def _start_recovery_pinger(self) -> None:
        """Background daemon thread that closes the circuit when Ollama recovers.

        Sleeps for _CB_RECOVERY_S seconds, then pings Ollama directly (bypassing
        the circuit breaker).  On success, closes the circuit and emits INFO.
        The thread respects self.stopping for clean shutdown.
        """
        def _pinger() -> None:
            while not self.stopping:
                self._stop.wait(timeout=self._CB_RECOVERY_S)
                if self.stopping:
                    break
                with self._cb_lock:
                    circuit_open = (self._cb_state == "open")
                if not circuit_open:
                    continue   # nothing to recover, go back to sleep
                if self._ping_ollama():
                    with self._cb_lock:
                        self._cb_state = "closed"
                    self.set_health(100, "")
                    self.emit(
                        f"AI circuit breaker CLOSED — Ollama recovered ({self._model}).",
                        Severity.INFO,
                        cb_state="closed",
                    )

        threading.Thread(
            target=_pinger, name=f"{self.name}-cb-recovery", daemon=True,
        ).start()

    def run(self) -> None:
        self._check_health()
        self._start_recovery_pinger()   # background thread closes circuit when Ollama recovers
        ticks = 0
        while not self.stopping:
            self.sleep(8)
            ticks += 1
            if ticks % 8 == 0:   # ~every 64s, re-verify the model is usable
                self._check_health()
            if self._bus is None:
                continue
            for ev in self._bus.recent(20):
                if ev.ts <= self._last_ts or ev.severity < Severity.HIGH:
                    continue
                if ev.module == self.name:
                    continue   # never triage our own output (no feedback loop)
                self._last_ts = max(self._last_ts, ev.ts)
                # TUNE safe-path: skip Ollama for behaviour matching the learned
                # known-good baseline. Fail-open — a tuner error never hides a threat.
                try:
                    from angerona.modules.behavioral_tuner import get_tuner
                    _tuner = get_tuner()
                    if _tuner is not None and _tuner.is_known_good(ev):
                        continue
                except Exception:
                    pass
                # VPN-aware prompt enrichment: pass the originating interface_type so
                # the model weighs a VPN tunnel against ancestry + destination IP.
                prompt = f"Event from {ev.module}: {ev.message}"
                itype = (ev.details or {}).get("interface_type")
                if itype:
                    prompt += (f"\nOriginating network interface_type: {itype}. Weigh the "
                               "presence of a VPN interface contextually against the process "
                               "ancestry and destination IP.")
                verdict = self._ask(prompt)
                if verdict:
                    self.set_health(100, "")
                    self.emit(f"AI: {verdict}", Severity.INFO, source=ev.module)
                # If verdict is None because CB is open, the event is already on the
                # bus being processed by SOAR, attack_tracker, etc.  The CB trip
                # itself already emitted a HIGH alert — no further action needed.

    def _check_health(self) -> None:
        prev = self.health
        with self._cb_lock:
            cb_open = (self._cb_state == "open")
        # Use direct ping so health check doesn't fast-fail misleadingly when CB open
        alive = self._ping_ollama()
        if not alive:
            note = "Circuit breaker open — recovery pinger active" if cb_open \
                   else f"Ollama/model unreachable ({self.last_error})"
            self.set_health(30, note)
            # Only emit the degradation notice once (not on every 64s tick while CB open)
            if prev >= 50 and not cb_open:
                self.emit("Ollama not reachable / model missing — AI triage idle.", Severity.MEDIUM)
        else:
            self.set_health(100, "")
            if prev < 50:
                self.emit(f"AI triage online ({self._model}).", Severity.INFO)

    def self_test(self) -> tuple[bool, str]:
        verdict = self._ask("Reply 'ok'.")
        if verdict is None:
            return False, f"Ollama unreachable or model '{self._model}' missing ({self.last_error})"
        return True, f"Ollama responded (model {self._model})"
