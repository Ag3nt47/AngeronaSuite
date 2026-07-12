"""Cloud CTI escalation (opt-in second opinion).

When a CRITICAL event fires and you've supplied your own cloud key, this module
asks a cloud model (Gemini) for a Tier-3 verdict to corroborate the local AI.
Ported from Angerona's ``cloud_fallback.py``.

Strictly opt-in and local-first: with no key, it stays idle and nothing leaves
your machine. Keys come only from the git-ignored .env (GEMINI_API_KEYS).
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from angerona.core.module_base import BaseModule, Severity

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


class CloudEscalationModule(BaseModule):
    name = "Cloud CTI Escalation"
    description = "Opt-in: corroborates CRITICAL events with a cloud model (uses your own key)."
    category = "AI"
    enabled_by_default = False

    def __init__(self) -> None:
        super().__init__()
        self._last_ts = 0.0
        self._keys = [k.strip() for k in os.getenv("GEMINI_API_KEYS", "").split(",") if k.strip()]

    def _ask_gemini(self, prompt: str) -> Optional[dict]:
        try:
            from google import genai
        except Exception:
            self.emit("Cloud escalation needs 'google-genai' (pip install google-genai).", Severity.LOW)
            return None
        try:
            client = genai.Client()  # reads GEMINI_API_KEY/credentials from env
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={"system_instruction": _SYSTEM, "response_mime_type": "application/json"},
            )
            return _extract_json(getattr(resp, "text", ""))
        except Exception as exc:
            self.last_error = str(exc)
            return None

    def run(self) -> None:
        if not self._keys:
            self.emit("Cloud escalation idle — no GEMINI_API_KEYS in .env (local-only mode).",
                      Severity.INFO)
            # Stay alive but dormant so the user can add a key without a restart.
            while not self.stopping:
                self.sleep(30)
                self._keys = [k.strip() for k in os.getenv("GEMINI_API_KEYS", "").split(",") if k.strip()]
                if self._keys:
                    self.emit("Cloud escalation key detected — now active.", Severity.INFO)
                    break
            if self.stopping:
                return

        self.emit("Cloud CTI escalation active.", Severity.INFO)
        while not self.stopping:
            self.sleep(8)
            if self._bus is None:
                continue
            for ev in self._bus.recent(15):
                if ev.ts <= self._last_ts or ev.severity < Severity.CRITICAL:
                    continue
                if ev.module in (self.name, "AI Triage (Ollama)"):
                    continue
                self._last_ts = max(self._last_ts, ev.ts)
                verdict = self._ask_gemini(f"Event from {ev.module}: {ev.message}")
                if verdict:
                    self.emit(f"Cloud verdict: {verdict.get('verdict','?')} "
                              f"({verdict.get('confidence','?')}) — {verdict.get('justification','')}",
                              Severity.INFO, source=ev.module)
