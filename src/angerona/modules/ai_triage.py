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
import math
import os
import re
import threading
import time
from dataclasses import dataclass, replace
from typing import Optional

import urllib.request

from angerona.core.module_base import BaseModule, Severity
from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    UrlPolicyError,
    local_service_url,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import (
    OllamaAttestationError,
    chill_active,
    ollama_blocked,
    effective_keep_alive,
    attest_ollama_service,
)

SYSTEM_PROMPT = (
    "You are a local SOC analyst. Given a security event, respond with a single "
    "short sentence: a plain-language explanation and whether it looks benign or "
    "malicious. Be concise."
)

AITRIAGE_ATTESTATION_DEFERRED = (
    "Ollama is ready and the installed model matches its approved manifest. "
    "Disk byte attestation is pending or stale; fresh verification is required before inference."
)

_REQUEST_PHASES = ("service-check", "model-check", "request")
_REQUEST_STAGES = frozenset((*_REQUEST_PHASES, "idle", "refused", "cancelled"))
_REQUEST_OUTCOMES = frozenset({
    "unmeasured", "in-progress", "completed", "service-refused", "model-refused",
    "transport-refused", "prompt-refused", "configuration-refused", "circuit-open",
    "chill", "stopped", "generation-changed", "configuration-changed",
})
_REQUEST_COUNTER_MAX = (1 << 63) - 1


def _request_number(value) -> bool:
    return (type(value) in (int, float) and 0 <= value <= 253402300799
            and math.isfinite(value))


def _request_clock(name):
    try:
        value = getattr(time, name)()
        return float(value) if _request_number(value) else None
    except Exception:
        return None


@dataclass(frozen=True)
class _RequestStage:
    generation: int
    attempt: int
    stage: str = "idle"
    outcome: str = "unmeasured"
    started: float | None = None
    updated: float | None = None
    phase_started: float | None = None
    phase_cpu_started: float | None = None
    entries: tuple[int, int, int] = (0, 0, 0)
    timings: tuple[tuple[str, float | None, float | None], ...] = ()

    def valid(self) -> bool:
        try:
            return (
                all(type(value) is int and 0 <= value <= _REQUEST_COUNTER_MAX
                    for value in (self.generation, self.attempt))
                and type(self.stage) is str and len(self.stage) <= 32 and self.stage in _REQUEST_STAGES
                and type(self.outcome) is str and len(self.outcome) <= 32 and self.outcome in _REQUEST_OUTCOMES
                and all(value is None or _request_number(value)
                        for value in (self.started, self.updated, self.phase_started, self.phase_cpu_started))
                and (self.started is None or self.updated is None or self.started <= self.updated)
                and type(self.entries) is tuple and len(self.entries) == 3
                and all(type(value) is int and 0 <= value <= _REQUEST_COUNTER_MAX for value in self.entries)
                and type(self.timings) is tuple and len(self.timings) <= 3
                and all(type(row) is tuple and len(row) == 3
                        and type(row[0]) is str and len(row[0]) <= 32 and row[0] in _REQUEST_PHASES
                        and all(value is None or _request_number(value) for value in row[1:])
                        for row in self.timings)
                and len({row[0] for row in self.timings}) == len(self.timings)
            )
        except Exception:
            return False


class AITriageModule(BaseModule):
    name = "AI Triage (Ollama)"
    # Cold full-byte attestation precedes the already-bounded Ollama request.
    startup_cycle_timeout = 300.0
    watchdog_work_budget_seconds = 300.0
    description = "Explains and scores serious events using a local LLM (Ollama)."
    category = "AI"
    version = "1.14.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "detect"
    # Restarting prepares the service, but cannot install or approve a model.
    # Keep model-policy failures out of the GUI's automatic repair restarts.
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
        self._attestation_failure: tuple[int, str, str] | None = None
        self._attestation_receipt = None
        self._ollama_readiness_error = ""
        self._model_readiness_error = ""
        self._request_stage_lock = threading.Lock()
        self._request_observation = _RequestStage(self._lifecycle_generation, 0)

    def _begin_request_observation(self, generation):
        now = _request_clock("monotonic")
        with self._request_stage_lock:
            previous = self._request_observation
            if type(previous) is not _RequestStage or not _RequestStage.valid(previous):
                return None
            entries = previous.entries if previous.generation == generation else (0, 0, 0)
            attempt = previous.attempt + 1
            if attempt > _REQUEST_COUNTER_MAX:
                return None
            self._request_observation = _RequestStage(generation, attempt, started=now, updated=now,
                                                       entries=entries)
            return generation, attempt

    def _record_request_stage(self, token, stage, outcome="in-progress"):
        """Publish bounded call-path timing; never hold this lock across work."""
        now, cpu = _request_clock("monotonic"), _request_clock("thread_time")
        with self._request_stage_lock:
            previous = self._request_observation
            if (token is None or type(previous) is not _RequestStage
                    or not _RequestStage.valid(previous)
                    or (previous.generation, previous.attempt) != token):
                return
            timings = dict((name, (wall, used_cpu)) for name, wall, used_cpu in previous.timings)
            if previous.stage in _REQUEST_PHASES:
                wall = (now - previous.phase_started if now is not None and previous.phase_started is not None
                        and now >= previous.phase_started else None)
                used_cpu = (cpu - previous.phase_cpu_started if cpu is not None and previous.phase_cpu_started is not None
                            and cpu >= previous.phase_cpu_started else None)
                timings[previous.stage] = wall, used_cpu
            entries = list(previous.entries)
            if stage in _REQUEST_PHASES:
                index = _REQUEST_PHASES.index(stage)
                entries[index] = min(_REQUEST_COUNTER_MAX, entries[index] + 1)
            self._request_observation = replace(previous, stage=stage, outcome=outcome, updated=now,
                phase_started=now if stage in _REQUEST_PHASES else None,
                phase_cpu_started=cpu if stage in _REQUEST_PHASES else None, entries=tuple(entries),
                timings=tuple((name, *timings[name]) for name in _REQUEST_PHASES if name in timings))

    def request_stage_snapshot(self) -> dict:
        """Cached observations of _ask only; no clock, service or model query."""
        with self._request_stage_lock:
            observed = self._request_observation
        result = {"schema": 1, "state": "unavailable", "reason_code": "invalid_observation",
                  "advisory_only": True, "response_authorized": False,
                  "scope": "Cached request-path stages; timings include inline callbacks and grant no inference authority"}
        if type(observed) is not _RequestStage or not _RequestStage.valid(observed):
            return result
        generation = self._lifecycle_generation
        if type(generation) is not int or not 0 <= generation <= _REQUEST_COUNTER_MAX:
            return result
        current = observed.generation == generation
        result.update(state="observed" if current and observed.attempt else "unmeasured",
            reason_code="" if current else "generation_changed", lifecycle_generation=generation,
            observation_generation=observed.generation, attempt_count=observed.attempt,
            stage=observed.stage if current else "idle", outcome=observed.outcome if current else "unmeasured",
            started_monotonic=observed.started, updated_monotonic=observed.updated,
            stage_entries=dict(zip(_REQUEST_PHASES, observed.entries)),
            completed_stage_timings=[{"stage": name, "wall_seconds": wall, "thread_cpu_seconds": cpu}
                                     for name, wall, cpu in observed.timings])
        if self.generation_stop_event().is_set():
            result.update(stage="cancelled", outcome="stopped")
        if generation != self._lifecycle_generation:
            result.update(state="unmeasured", reason_code="generation_changed", stage="idle", outcome="unmeasured")
        return result

    def _request_cancel_reason(self, stop_event, generation, host, model):
        if stop_event.is_set():
            return "stopped"
        if generation != self._lifecycle_generation:
            return "generation-changed"
        if ollama_blocked() or bool(getattr(self, "_chill_paused", False)):
            return "chill"
        self._sync_config()
        if self._host != host or self._model != model:
            return "configuration-changed"
        return ""

    def _request_failure(self, exc, *, service=False):
        """Keep the existing one-notice circuit transition outside callbacks."""
        self.last_error = str(exc)[:500]
        if service:
            detail = (f"Ollama listener attestation failed: {self.last_error}"
                      if isinstance(exc, OllamaAttestationError)
                      else "Configured Ollama service endpoint is unavailable or invalid")
            self._ollama_readiness_error = detail
            self.last_error = detail
            self.set_health(30, detail)
        with self._cb_lock:
            opened = self._cb_state == "closed"
            if opened:
                self._cb_state = "open"
        if opened:
            # Availability only; deterministic detector evidence remains intact.
            failure = ("local Ollama service admission refused"
                       if service else f"Ollama request failed (timeout budget {self._CB_TIMEOUT_S}s)")
            self.emit(
                f"AI triage degraded — {failure}: {exc}. Falling back to deterministic "
                "rules (auto-recovers when Ollama responds).",
                Severity.MEDIUM, cb_state="open",
            )

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

    def _configured_endpoint(self) -> tuple[str, str]:
        """Read the current service origin and model without changing worker state."""
        config = self._config
        if config is None:
            return self._host, self._model
        host = str(getattr(config, "ollama_host", self._host) or "").strip()
        # Preserve the deployment override read during __init__; Settings is
        # the fallback when no environment override is present.
        model = str(
            os.environ.get("ANGERONA_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or getattr(config, "ollama_model", self._model)
            or ""
        ).strip()
        return (host.rstrip("/") if host else self._host), (model or self._model)

    def _sync_config(self) -> None:
        """Apply live Settings values without requiring a suite restart."""
        self._host, self._model = self._configured_endpoint()

    def _ask(self, prompt: str) -> Optional[str]:
        """Send a prompt to Ollama, respecting the circuit breaker.

        Returns the model's response, or None if the circuit is open / request
        fails. A transport failure opens the circuit and emits a health notice.
        """
        stop_event = self.generation_stop_event()
        generation = self._lifecycle_generation
        token = self._begin_request_observation(generation)
        self._sync_config()
        host, model = self._host, self._model
        model_attested = False

        def cancelled():
            reason = self._request_cancel_reason(stop_event, generation, host, model)
            if reason:
                self._record_request_stage(token, "cancelled", reason)
                if model_attested:
                    self._attestation_receipt = None
                    self.set_health(
                        min(self.health, 70),
                        "AI triage request cancelled; fresh service and model "
                        "verification required before inference",
                    )
            return bool(reason)

        if cancelled():
            return None
        # Fast-fail — never block on a known-bad Ollama
        with self._cb_lock:
            circuit_open = self._cb_state == "open"
        if circuit_open:
            self._record_request_stage(token, "refused", "circuit-open")
            return None

        # A refused local listener cannot use any model. Check it before a cold
        # multi-gigabyte byte pass. This is not connection authority: transport
        # repeats its listener, Chill and redirect checks at request time.
        self._record_request_stage(token, "service-check")
        try:
            origin = local_service_url(host)
            request_url = local_service_url(origin, "/api/chat")
            attest_ollama_service(origin)
        except Exception as exc:
            if cancelled():
                return None
            self._record_request_stage(token, "refused",
                "configuration-refused" if isinstance(exc, UrlPolicyError) else "service-refused")
            self._request_failure(exc, service=True)
            return None
        if cancelled():
            return None
        self._record_request_stage(token, "model-check")
        if not self._attest_model(expected_model=model):
            if not cancelled():
                self._record_request_stage(token, "refused", "model-refused")
            return None
        model_attested = True
        # Settings and generation may change while full-byte verification runs.
        # Never apply its proof to a different host/model or retired generation.
        if cancelled():
            return None

        # BL-03: neutralize attacker-influenced telemetry so embedded instructions
        # are treated as data, not commands.
        try:
            from angerona.engines.ai_guardrail import neutralize_telemetry
            user_content = neutralize_telemetry(prompt)
        except Exception:
            # This optional narrative must never bypass its telemetry boundary
            # when a sanitizer fails. Detector evidence remains on the bus for
            # deterministic response; do not include hostile input in the error.
            self.last_error = "AI telemetry protection unavailable; request skipped"
            self.set_health(20, self.last_error)
            self._record_request_stage(token, "refused", "prompt-refused")
            return None

        payload = json.dumps({
            "model": model,
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
            request_url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            self._record_request_stage(token, "request")
            if cancelled():
                return None
            with safe_urlopen(
                req, policy=OLLAMA_SERVICE_POLICY, timeout=self._CB_TIMEOUT_S,
            ) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            if cancelled():
                return None
            result = (data.get("message", {}) or {}).get("content", "").strip()
            self._record_request_stage(token, "idle", "completed")
            return result
        except Exception as exc:
            if cancelled():
                return None
            service_failure = isinstance(exc, OllamaAttestationError)
            self._record_request_stage(token, "refused",
                "service-refused" if service_failure else "transport-refused")
            self._request_failure(exc, service=service_failure)
            return None

    def _attest_model(self, *, expected_model: str | None = None) -> bool:
        """Require a fresh receipt for the exact configured tag before use."""
        self._sync_config()
        model = self._model if expected_model is None else expected_model
        if self._model != model:
            self._attestation_receipt = None
            return False
        stop_event = self.generation_stop_event()
        generation = self.lifecycle_generation
        if stop_event.is_set():
            self._attestation_receipt = None
            return False
        self.set_health(
            min(self.health, 70),
            "configured model byte verification pending; inference is blocked until complete",
        )
        try:
            from angerona.modules.ai_model_integrity import (
                require_fresh_model_attestation,
            )

            receipt = require_fresh_model_attestation(model, stop_event=stop_event)
        except Exception as exc:
            if stop_event.is_set():
                self._attestation_receipt = None
                return False
            rendered = str(exc)[:500]
            self._attestation_failure = generation, model, rendered
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
                    model=model,
                    attestation_error=rendered,
                )
            self._attestation_receipt = None
            return False
        if stop_event.is_set():
            self._attestation_receipt = None
            return False
        self._attestation_error = ""
        self._attestation_failure = None
        self._attestation_receipt = receipt
        self.set_health(100, "exact configured model attested for local inference")
        return True

    def _ping_ollama(self) -> bool:
        """Check daemon/model availability without loading the model into RAM."""
        self._sync_config()
        model_record, detail = self._probe_model(self._host, self._model)
        if model_record is not None:
            if self.last_error == self._ollama_readiness_error:
                self.last_error = ""
            self._ollama_readiness_error = ""
            return True
        self._ollama_readiness_error = detail
        self.last_error = detail
        return False

    @staticmethod
    def _probe_model(host: str, model: str) -> tuple[dict | None, str]:
        """Read the attested listener's existing exact-tag inventory."""
        try:
            req = urllib.request.Request(local_service_url(host, "/api/tags"))
            with safe_urlopen(
                req, policy=OLLAMA_SERVICE_POLICY, timeout=3.0,
            ) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("models"), list):
                raise ValueError("invalid Ollama model-list response")
            if len(data["models"]) > 10_000 or any(
                not isinstance(item, dict) for item in data["models"]
            ):
                raise ValueError("invalid Ollama model descriptors")
            matches = [
                item for item in data["models"]
                if AITriageModule._model_is_installed(model, [item.get("name") or item.get("model") or ""])
            ]
            if len(matches) == 1:
                return matches[0], ""
            if matches:
                return None, "Ollama inventory contains ambiguous descriptors for the configured model"
            detail = (
                f"Ollama is reachable, but configured model '{model}' is not installed"
            )
        except OllamaAttestationError as exc:
            detail = f"Ollama listener attestation failed: {str(exc)[:500]}"
        except Exception as exc:
            detail = f"Ollama readiness check failed ({type(exc).__name__}): {str(exc)[:500]}"
        return None, detail

    def _ensure_ollama(self) -> bool:
        """Prepare the daemon only on explicit lifecycle operations, not idle health."""
        from angerona.core.ollama_lifecycle import ensure_ollama_service

        self._sync_config()
        stop = self.generation_stop_event()

        def progress(status):
            if not stop.is_set():
                self.set_health(
                    min(self.health, 70),
                    f"Ollama service {status.percent}% — {status.stage}: {status.detail}",
                )

        status = ensure_ollama_service(
            self._host, stop_event=stop, progress=progress, timeout=30.0,
        )
        return bool(status.daemon_ready and not stop.is_set())

    @staticmethod
    def _model_is_installed(configured_model: str, installed_models) -> bool:
        """Match the exact tag Ollama will use (an omitted tag means latest)."""
        configured = str(configured_model or "").strip().casefold()
        if not configured:
            return False
        wanted = configured if ":" in configured else configured + ":latest"
        for installed_model in installed_models:
            name = str(installed_model or "").strip().casefold()
            actual = name if ":" in name else name + ":latest"
            if actual == wanted:
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
            self._ensure_ollama()
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
            if ticks % 8 == 0:   # ~every 64s; full byte attestation runs before inference.
                self._check_health()
            if self._bus is None:
                with self._lifecycle_lock:
                    if self.stopping:
                        return
                    self.mark_cycle_complete()
                continue
            events, _overflow = self.poll_bus_events(priority=True)
            for ev in events:
                if self.stopping:
                    return
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
                with self._lifecycle_lock:
                    if self.stopping:
                        return
                    # Each completed request is real progress. A retained batch
                    # can contain several slow attestations/inferences; only
                    # finishing one advances liveness, never a hash timer.
                    self.mark_cycle_complete()
                    if verdict:
                        self.set_health(100, "")
                        self.emit(
                            f"AI: {verdict}",
                            Severity.INFO,
                            source=ev.module,
                            speculative_frame_reused=reused_speculative_frame,
                            origin="ai_narrative",
                            response_authorized=False,
                        )
                # If verdict is None because CB is open, the event is already on the
                # bus being processed by SOAR, attack_tracker, etc.  The CB trip
                # itself already emitted a health notice — no further action needed.
            with self._lifecycle_lock:
                if self.stopping:
                    return
                self.mark_cycle_complete()

    def _check_health(self) -> None:
        prev = self.health
        with self._cb_lock:
            cb_open = (self._cb_state == "open")
        # Use direct ping so health check doesn't fast-fail misleadingly when CB open
        alive = self._ping_ollama()
        if not alive:
            note = self._ollama_readiness_error or f"Ollama readiness unavailable ({self.last_error})"
            if cb_open:
                note += "; circuit breaker open — recovery pinger active"
            self.set_health(30, note)
            # Only emit the degradation notice once (not on every 64s tick while CB open)
            if prev >= 50 and not cb_open:
                self.emit(f"{note} — AI triage idle.", Severity.MEDIUM)
        else:
            # A 64-second idle timer must not expire the 60-second receipt and
            # repeatedly read every multi-gigabyte model. This check grants no
            # inference authority: _ask still requires fresh bytes.
            try:
                from angerona.modules.ai_model_integrity import check_model_readiness

                check_model_readiness(self._model)
            except Exception as exc:
                rendered = str(exc)[:500]
                self.last_error = rendered
                self.set_health(20, f"approved model configuration unavailable: {rendered}")
                if rendered != self._model_readiness_error:
                    self.emit(
                        "AI triage model configuration unavailable; inference remains blocked.",
                        Severity.MEDIUM, model=self._model, readiness_error=rendered,
                    )
                self._model_readiness_error = rendered
                return
            if self.last_error == self._model_readiness_error:
                self.last_error = ""
            self._model_readiness_error = ""
            if self._attestation_error:
                # Metadata readiness cannot erase a known byte-attestation
                # failure; only a successful mandatory verification can do so.
                self.set_health(20, f"last model attestation failed: {self._attestation_error}")
                return
            self.set_health(
                100,
                "Ollama/model available; approved configuration; "
                "fresh byte attestation required before inference",
            )
            if prev < 50:
                self.emit(f"AI triage ready ({self._model}); attestation runs before inference.", Severity.INFO)

    def self_test(self) -> tuple[bool, str]:
        """Check the existing listener, exact model, and current proof without mutation."""
        if ollama_blocked() or bool(getattr(self, "_chill_paused", False)):
            return False, "SKIP: local AI is off in Chill Mode; switch Chill off manually for an active check"
        if (not self._model_is_installed("selftest:stable", ["selftest:stable"])
                or self._model_is_installed("selftest:stable", ["selftest:preview", "unrelated:stable"])):
            return False, "The exact-model diagnostic fixture failed installed-tag selection"
        host, model = self._configured_endpoint()
        generation = self.lifecycle_generation
        stop = self.generation_stop_event()
        stopped_at_start = stop.is_set()

        def interrupted() -> bool:
            return (
                generation != self.lifecycle_generation
                or (not stopped_at_start and stop.is_set())
                or ollama_blocked() or bool(getattr(self, "_chill_paused", False))
                or (host, model) != self._configured_endpoint()
            )

        entry, error = self._probe_model(host, model)
        if interrupted():
            return False, "Ollama check interrupted by a configuration, lifecycle or Chill Mode change"
        if entry is None:
            return False, error
        digest = entry.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
            return False, "Ollama is reachable, but its configured model manifest digest is unavailable or malformed"
        digest = "sha256:" + digest.removeprefix("sha256:")
        from angerona.modules.ai_model_integrity import observe_model_attestation

        try:
            attested = observe_model_attestation(model, digest)
        except Exception as exc:
            if interrupted():
                return False, "Ollama check interrupted by a configuration, lifecycle or Chill Mode change"
            return False, f"Ollama ready, but approved model verification is unavailable: {str(exc)[:500]}"
        if interrupted():
            return False, "Ollama check interrupted by a configuration, lifecycle or Chill Mode change"
        failure = self._attestation_failure
        if failure is not None and failure[:2] == (generation, model):
            return False, f"Ollama ready, but the last disk byte attestation failed: {failure[2]}"
        if not attested:
            return False, AITRIAGE_ATTESTATION_DEFERRED
        return True, f"Ollama ready; model {model} matches its approved manifest and current disk attestation"
