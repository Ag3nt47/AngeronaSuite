"""Cloud CTI escalation (opt-in second opinion).

When a CRITICAL event fires and you've supplied your own cloud key, this module
asks a cloud model (Gemini) for a Tier-3 verdict to corroborate the local AI.
Ported from Angerona's ``cloud_fallback.py``.

Strictly opt-in and local-first: with no key, it stays idle and nothing leaves
your machine. Keys come from Angerona's Windows DPAPI credential store. Only a
bounded, identifier-redacted event summary is sent; event details stay local.
"""
from __future__ import annotations

import json
import re
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity
from angerona.core.privacy import redact_text
from angerona.core.provider_credentials import credential_values
from angerona.core.threat import is_active_threat

_SYSTEM = (
    "You are a Tier-3 SOC analyst. Review this security event triaged by a local "
    "AI. Reply as JSON: {\"verdict\":\"SAFE|SUSPICIOUS|MALICIOUS\","
    "\"confidence\":0.0-1.0,\"justification\":\"...\"}"
)


def _extract_json(text: str) -> Optional[dict]:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def _cloud_prompt(module: object, message: object) -> str:
    """Build the only event payload permitted to leave through this module."""
    safe_module = redact_text(module, limit=128)
    safe_summary = redact_text(message, limit=1200)
    return (
        "Cloud second-opinion request. Host identifiers, network addresses, "
        "local paths, URLs, and credentials were removed.\n"
        f"Module label: {safe_module}\nEvent summary: {safe_summary}"
    )


class CloudEscalationModule(BaseModule):
    name = "Cloud CTI Escalation"
    description = "Opt-in: corroborates CRITICAL events with a cloud model (uses your own key)."
    category = "AI"
    version = "1.1.0"
    enabled_by_default = False

    def __init__(self) -> None:
        super().__init__()
        self._keys = list(credential_values("gemini"))

    def _ask_gemini(self, prompt: str) -> Optional[dict]:
        try:
            from google import genai
        except Exception:
            self.emit("Cloud escalation needs 'google-genai' (pip install google-genai).", Severity.LOW)
            return None
        try:
            client = genai.Client(api_key=self._keys[0])
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={"system_instruction": _SYSTEM, "response_mime_type": "application/json"},
            )
            return _extract_json(getattr(resp, "text", ""))
        except Exception as exc:
            self.last_error = str(exc)
            return None

    def self_test(self) -> tuple[bool, str]:
        """Exercise parsing and privacy gates without credentials or egress."""
        parsed = _extract_json(
            'prefix {"verdict":"SUSPICIOUS","confidence":0.75,'
            '"justification":"bounded fixture"} suffix'
        )
        prompt = _cloud_prompt(
            "Sensor 10.2.3.4",
            r"C:\Users\Alice\secret.txt contacted https://example.test?q=token",
        )
        ok = bool(
            parsed
            and parsed.get("verdict") == "SUSPICIOUS"
            and _extract_json("not json") is None
            and "10.2.3.4" not in prompt
            and "Alice" not in prompt
            and "example.test" not in prompt
            and len(prompt) <= 1600
        )
        return (
            ok,
            "offline JSON contract and identifier-redaction gate passed"
            if ok else "cloud response parser or redaction contract failed",
        )

    def run(self) -> None:
        _calls: list[float] = []          # recent cloud-call timestamps (rate cap)
        _CAP, _WINDOW = 20, 3600.0        # BL-15: cap API use — ≤20 cloud calls/hour
        _capped = False
        announced_active: bool | None = None
        while not self.stopping:
            # Re-read the canonical registry every cycle so adding, rotating, or
            # clearing a credential takes effect without a module restart.
            self._keys = list(credential_values("gemini"))
            active = bool(self._keys)
            if active != announced_active:
                if active:
                    self.emit(
                        "Cloud CTI escalation active — CRITICAL events are sent to "
                        "Gemini for a second opinion (explicit cloud egress).",
                        Severity.INFO,
                    )
                else:
                    self.emit(
                        "Cloud escalation idle — no protected Gemini key "
                        "(local-only mode).",
                        Severity.INFO,
                    )
                announced_active = active
            self.sleep(8 if active else 30)
            self._keys = list(credential_values("gemini"))
            if bool(self._keys) != active:
                continue
            if not self._keys:
                continue
            if self._bus is None:
                continue
            events, _overflow = self.poll_bus_events(priority=True)
            for ev in events:
                if ev.severity < Severity.CRITICAL:
                    continue
                if ev.module in (self.name, "AI Triage (Ollama)"):
                    continue
                if not is_active_threat(ev):
                    continue
                now = time.time()
                _calls[:] = [t for t in _calls if now - t < _WINDOW]
                if len(_calls) >= _CAP:
                    if not _capped:
                        _capped = True
                        self.emit(f"Cloud escalation rate cap reached ({_CAP}/h) — further "
                                  "CRITICALs use the LOCAL verdict only until the window clears.",
                                  Severity.MEDIUM)
                    continue
                _capped = False
                _calls.append(now)
                verdict = self._ask_gemini(_cloud_prompt(ev.module, ev.message))
                if verdict:
                    self.emit(f"Cloud verdict: {verdict.get('verdict','?')} "
                              f"({verdict.get('confidence','?')}) — {verdict.get('justification','')}",
                              Severity.INFO, source=ev.module)
                else:
                    # BL-15: fail CLOSED — never silently drop a CRITICAL that we
                    # meant to corroborate. Surface that it went UNVERIFIED so the
                    # operator can't mistake a cloud outage for an all-clear.
                    self.emit(
                        f"⚠ Cloud escalation FAILED for CRITICAL from {ev.module} "
                        f"({self.last_error or 'unreachable/rate-limited'}) — treating as "
                        "UNVERIFIED; the local verdict stands, investigate manually.",
                        Severity.HIGH, source=ev.module, fail_closed=True)
