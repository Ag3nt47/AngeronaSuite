"""AI triage module.

Subscribes to high-severity events and asks a local Ollama model to explain and
score them in plain language. This is the clean port of Angerona's core_engine
Ollama call — local-first, with the cloud path left as an opt-in extension.

Because modules are event *producers* by default, this one also taps the bus as
a consumer: the ModuleManager binds the bus, and we read recent high-severity
events on a timer to avoid recursive feedback (AI verdicts are emitted at INFO).
"""
from __future__ import annotations

SUPPORTED_PLATFORMS = ("windows", "macos", "linux")

import json
import os
import threading
import time
from typing import Optional

import urllib.request

from angerona.core.module_base import BaseModule, Severity
from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    local_service_url,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import chill_active, effective_keep_alive

SYSTEM_PROMPT = (
    "You are a local SOC analyst. Given a security event, respond with a single "
    "short sentence: a plain-language explanation and whether it looks benign or "
    "malicious. Be concise."
)


class AITriageModule(BaseModule):
    name = "AI Triage (Ollama)"
    description = "Explains and scores serious events using a local LLM (Ollama)."
    category = "AI"
    version = "1.13.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "detect"
    # Restarting this worker cannot install a model or start the external
    # Ollama service. Keep such failures out of the GUI's automatic restart.
    selftest_auto_repair = False

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
        self._model = (
            os.environ.get("ANGERONA_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or "llama3"
        )
        self._config = None
        self._manager = None
        self._speculative = None
        # Circuit breaker — "closed" = normal, "open" = Ollama hung/dead
        self._cb_state = "closed"             # type: str
        self._cb_lock  = threading.Lock()
        self._recovery_lock = threading.Lock()
        self._recovery_thread: Optional[threading.Thread] = None
        self._attestation_error = ""
        self._attestation_receipt = None

    def bind_manager(self, manager) -> None:
        """Use the operator's current local-AI settings for readiness checks."""
        self._manager = manager
        self._config = getattr(manager, "config", None)
        self._sync_config()

    def _bind_speculative_consumer(self):
        """Resolve and bind the optional pre-warmer after discovery completes."""
        manager = self._manager
        candidate = (
            getattr(manager, "modules", {}).get("Speculative Triage Pre-Warm")
            if manager is not None
            else None
        )
        binder = getattr(candidate, "bind_consumer", None)
        if candidate is not None and callable(binder) and binder(self):
            self._speculative = candidate
        else:
            self._speculative = None
        return self._speculative

    def _consume_speculative_frame(self, event) -> bool:
        speculative = self._speculative or self._bind_speculative_consumer()
        consumer = getattr(speculative, "get_primed", None)
        if not callable(consumer):
            return False
        details = event.details or {}
        try:
            pid = int(details.get("pid"))
        except (TypeError, ValueError):
            return False
        try:
            frame = consumer(
                pid,
                consumer=self,
                process_birth=details.get("process_birth"),
            )
        except Exception:
            return False
        return bool(frame)

    def _sync_config(self) -> None:
        """Apply live Settings values without requiring a suite restart."""
        config = self._config
        if config is None:
            return
        host = str(getattr(config, "ollama_host", self._host) or "").strip()
        # Preserve the deployment override read during __init__; Settings is
        # the fallback when no environment override is present.
        model = str(
            os.environ.get("ANGERONA_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or getattr(config, "ollama_model", self._model)
            or ""
        ).strip()
        if host:
            self._host = host.rstrip("/")
        if model:
            self._model = model

    def _ask(self, prompt: str) -> Optional[str]:
        """Send a prompt to Ollama, respecting the circuit breaker.

        Returns the model's response, or None if the circuit is open / request
        fails.  A failure while the circuit is CLOSED trips it and emits HIGH.
        """
        self._sync_config()
        # Fast-fail — never block on a known-bad Ollama
        with self._cb_lock:
            if self._cb_state == "open":
                return None
        if not self._attest_model():
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
            "keep_alive": effective_keep_alive("30m"),
            # Bound worst-case latency. With stream=False no bytes arrive until
            # generation finishes, so an unbounded reply that runs past the 90s
            # socket timeout ALWAYS trips the breaker. A triage verdict is a few
            # sentences — cap it so generation can't outrun the timeout.
            "options": {"num_predict": 256, "temperature": 0.2},
        }).encode("utf-8")
        req = urllib.request.Request(
            local_service_url(self._host, "/api/chat"), data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with safe_urlopen(
                req, policy=OLLAMA_SERVICE_POLICY, timeout=self._CB_TIMEOUT_S,
            ) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            return (data.get("message", {}) or {}).get("content", "").strip()
        except Exception as exc:
            self.last_error = str(exc)
            with self._cb_lock:
                if self._cb_state == "closed":
                    self._cb_state = "open"
                    # MEDIUM, not HIGH: a slow/unavailable local LLM is an infra
                    # condition, not a security threat — raising it HIGH inflated
                    # the threat level and cluttered Live Alerts. Triage simply
                    # falls back to deterministic rules until the pinger recovers it.
                    self.emit(
                        f"AI triage degraded — Ollama timeout/error after "
                        f"{self._CB_TIMEOUT_S}s: {exc}. Falling back to deterministic rules "
                        "(auto-recovers when Ollama responds).",
                        Severity.MEDIUM,
                        cb_state="open",
                    )
            return None

    def _attest_model(self) -> bool:
        """Require a fresh receipt for the exact configured tag before use."""
        self._sync_config()
        try:
            from angerona.modules.ai_model_integrity import (
                require_fresh_model_attestation,
            )

            receipt = require_fresh_model_attestation(self._model)
        except Exception as exc:
            rendered = str(exc)[:500]
            self.last_error = rendered
            self.set_health(
                20,
                "configured AI model lacks a fresh approved local attestation: "
                f"{rendered}",
            )
            if rendered != self._attestation_error:
                self._attestation_error = rendered
                self.emit(
                    "AI triage model attestation failed; deterministic defenses "
                    "remain active and LLM inference is blocked.",
                    Severity.MEDIUM,
                    model=self._model,
                    attestation_error=rendered,
                )
            self._attestation_receipt = None
            return False
        self._attestation_error = ""
        self._attestation_receipt = receipt
        return True

    def _ping_ollama(self) -> bool:
        """Check daemon/model availability without loading the model into RAM."""
        self._sync_config()
        req = urllib.request.Request(local_service_url(self._host, "/api/tags"))
        try:
            with safe_urlopen(
                req, policy=OLLAMA_SERVICE_POLICY, timeout=3.0,
            ) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            installed = [
                str(item.get("name") or item.get("model") or "")
                for item in data.get("models", [])
                if isinstance(item, dict)
            ]
            return self._model_is_installed(self._model, installed)
        except Exception:
            return False

    @staticmethod
    def _model_is_installed(configured_model: str, installed_models) -> bool:
        """Match explicit tags exactly; allow family matching only when untagged."""
        configured = str(configured_model or "").strip().casefold()
        if not configured:
            return False
        exact_tag = ":" in configured
        wanted_family = configured.split(":", 1)[0]
        for installed_model in installed_models:
            name = str(installed_model or "").strip().casefold()
            if (
                (exact_tag and name == configured)
                or (not exact_tag and name.split(":", 1)[0] == wanted_family)
            ):
                return True
        return False

    def _start_recovery_pinger(
        self,
        generation_stop: threading.Event,
        helper_stop: threading.Event,
    ) -> threading.Thread:
        """Background daemon thread that closes the circuit when Ollama recovers.

        Sleeps for _CB_RECOVERY_S seconds, then pings Ollama directly (bypassing
        the circuit breaker).  On success, closes the circuit and emits INFO.
        Both stop tokens are immutable for this run attempt, so a later module
        generation cannot revive this pinger.
        """
        def _pinger() -> None:
            while not generation_stop.is_set() and not helper_stop.is_set():
                helper_stop.wait(timeout=self._CB_RECOVERY_S)
                if generation_stop.is_set() or helper_stop.is_set():
                    break
                with self._cb_lock:
                    circuit_open = (self._cb_state == "open")
                if not circuit_open:
                    continue   # nothing to recover, go back to sleep
                recovered = self._ping_ollama()
                # Discard a late health result from a retired generation.
                if generation_stop.is_set() or helper_stop.is_set():
                    break
                if recovered:
                    with self._cb_lock:
                        self._cb_state = "closed"
                    self.set_health(
                        70,
                        "Ollama recovered; awaiting exact model attestation",
                    )
                    self.emit(
                        f"AI circuit breaker CLOSED — Ollama recovered ({self._model}); "
                        "fresh model attestation still required.",
                        Severity.INFO,
                        cb_state="closed",
                    )

        thread = threading.Thread(
            target=_pinger, name=f"{self.name}-cb-recovery", daemon=True,
        )
        with self._recovery_lock:
            self._recovery_thread = thread
        thread.start()
        return thread

    def run(self) -> None:
        generation_stop = self.generation_stop_event()
        helper_stop = threading.Event()
        pinger: Optional[threading.Thread] = None
        try:
            self._check_health()
            if generation_stop.is_set():
                return
            pinger = self._start_recovery_pinger(
                generation_stop, helper_stop
            )
            self._run_generation()
        finally:
            helper_stop.set()
            if pinger is not None:
                pinger.join()
            with self._recovery_lock:
                if self._recovery_thread is pinger:
                    self._recovery_thread = None

    def _run_generation(self) -> None:
        self._bind_speculative_consumer()
        ticks = 0
        while not self.stopping:
            self.sleep(8, cycle_complete=False)
            ticks += 1
            if self.stopping:
                break
            if ticks % 8 == 0:   # ~every 64s, re-verify the model is usable
                self._check_health()
            if self._bus is None:
                self.mark_cycle_complete()
                continue
            events, _overflow = self.poll_bus_events(priority=True)
            for ev in events:
                if ev.severity < Severity.HIGH:
                    continue
                if ev.module == self.name:
                    continue   # never triage our own output (no feedback loop)
                # Practice, passive exposure and suite-health events keep their
                # evidentiary severity but do not need a heavyweight model call.
                try:
                    from angerona.core.threat import is_active_threat
                    if not is_active_threat(ev):
                        continue
                except Exception:
                    pass
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
                reused_speculative_frame = self._consume_speculative_frame(ev)
                if reused_speculative_frame:
                    prompt += "\nA fresh model pre-warm exists for this exact process identity."
                itype = (ev.details or {}).get("interface_type")
                if itype:
                    prompt += (f"\nOriginating network interface_type: {itype}. Weigh the "
                               "presence of a VPN interface contextually against the process "
                               "ancestry and destination IP.")
                verdict = self._ask(prompt)
                if verdict:
                    self.set_health(100, "")
                    self.emit(
                        f"AI: {verdict}",
                        Severity.INFO,
                        source=ev.module,
                        speculative_frame_reused=reused_speculative_frame,
                    )
                # If verdict is None because CB is open, the event is already on the
                # bus being processed by SOAR, attack_tracker, etc.  The CB trip
                # itself already emitted a HIGH alert — no further action needed.
            self.mark_cycle_complete()

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
            attested = self._attest_model()
            if attested:
                self.set_health(100, "exact configured model attested for local inference")
            if attested and prev < 50:
                self.emit(f"AI triage online ({self._model}).", Severity.INFO)

    def self_test(self) -> tuple[bool, str]:
        # A health check must never load a multi-gigabyte model. In Chill the
        # worker is intentionally dormant, so even probing the daemon would be
        # needless background activity. Full Mode uses /api/tags, which checks
        # daemon + configured-model readiness without running inference.
        self._sync_config()
        if chill_active() or bool(getattr(self, "_chill_paused", False)):
            return True, "local AI intentionally asleep in Chill Mode (wakes on demand)"
        if not self._ping_ollama():
            return False, (
                f"Ollama daemon unreachable or configured model "
                f"'{self._model}' is not installed"
            )
        if not self._attest_model():
            return False, (
                f"Ollama ready, but model {self._model} has no fresh approved "
                "local attestation"
            )
        return True, f"Ollama ready; model {self._model} installed and attested"
