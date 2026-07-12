"""security_academy.py — The Interactive AI Guided Walkthrough Engine
("Flight Instructor Mode").

FlightInstructor talks to the same local Ollama instance
modules/ai_triage.py already uses (identical host/model resolution and HTTP
call shape), but does a completely different job: ai_triage.py scores real
events as benign/malicious; FlightInstructor never scores anything — it only
teaches, either narrating a live Shark Attack drill in real time, or
coaching a Socratic post-mortem walkthrough afterward.

Two capabilities, per the spec:

  * Live Narrative Mode   — narrate_event(): given one raw narration line
    from the Shark Attack Engine's on_event stream, explain WHY that
    specific action is a meaningful signal, grounded in the real
    explainer_dictionary entry for that stage (not improvised).
  * Forensic Post-Mortem Coach — coach_post_mortem(): given the "verdicts"
    list from shark_aar.json, and for every MISSED step, generates guiding
    analytical questions rather than the answer outright — the point is for
    the user to find the blind spot themselves.

Both degrade gracefully to the static explainer dictionary if Ollama is
unreachable, instead of going silent.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from enum import Enum
from typing import List, Optional

from angerona.academy.explainer_dictionary import lookup

# ── Prompt engineering ──────────────────────────────────────────────────────
# Each system prompt fixes: persona, exact input shape, exact output shape
# (length + register), and an explicit "don't do this" guardrail. Keeping
# these separate (rather than one mega-prompt with a mode flag) makes each
# one easy to read, tune, and unit-test independently.

_NARRATIVE_SYSTEM_TECHNICAL = (
    "You are Flight Instructor, Angerona's embedded cybersecurity coach. A "
    "live, non-destructive adversary-simulation drill (the Shark Attack "
    "Engine) is running against this machine's real defense modules. You "
    "will be given grounding context plus one raw narration line describing "
    "what the simulated attacker just did. Respond with 1-2 SHORT, precise "
    "technical sentences explaining WHY this specific action is a "
    "meaningful detection-engineering signal, referencing the underlying "
    "OS/network mechanism. Do not restate the input line. Do not use "
    "analogies. Be concise."
)

_NARRATIVE_SYSTEM_ANALOGY = (
    "You are Flight Instructor, Angerona's embedded cybersecurity coach, "
    "teaching a complete beginner. A live, non-destructive adversary-"
    "simulation drill is running against this machine's real defense "
    "modules. You will be given grounding context plus one raw narration "
    "line describing what the simulated attacker just did. Respond with "
    "1-2 SHORT sentences using one simple, vivid real-world analogy (no "
    "jargon, no acronyms) that makes the underlying security concept click "
    "for someone with zero cybersecurity background. Do not restate the "
    "input line."
)

_COACH_SYSTEM = (
    "You are Flight Instructor, Angerona's embedded cybersecurity coach, "
    "running a Socratic after-action debrief on ONE detection that was "
    "MISSED during a drill. You will be given the technique, what it did, "
    "and which real module's territory it fell in. Do NOT state the answer "
    "outright. Instead write exactly 2-3 short, pointed analytical "
    "questions that guide the user to discover the blind spot themselves — "
    "e.g. what data source would have been needed, what threshold or list "
    "excluded it, what timing window it slipped through. End with one line "
    "starting 'Hint:' that nudges them closer without fully solving it. Keep "
    "the whole reply under 80 words."
)

_STAGE_RE = re.compile(r"STAGE:\s*([^—]+)—")


def _extract_stage(narration_line: str) -> Optional[str]:
    """Pulls the stage name out of a '▶ STAGE: <name> — ...' line (the only
    narration-line shape worth commenting on — jitter/done/intro/outro lines
    don't carry enough to teach from, and skipping them keeps this from
    burning an LLM call every couple of seconds during a drill)."""
    m = _STAGE_RE.search(narration_line)
    if not m:
        return None
    candidate = m.group(1).strip().lower()
    from angerona.academy.explainer_dictionary import TECHNIQUE_LIBRARY
    for key in TECHNIQUE_LIBRARY:
        if key.split(" (")[0].lower() in candidate:
            return key
    return None


class ExplainerStyle(str, Enum):
    TECHNICAL = "technical"
    ANALOGY = "analogy"


class FlightInstructor:
    def __init__(self, config, style: str = "analogy") -> None:
        self.config = config
        self._host = os.environ.get("OLLAMA_HOST", config.ollama_host).rstrip("/")
        self._model = config.ollama_model
        self.last_error = ""
        self.style: ExplainerStyle = ExplainerStyle.ANALOGY
        self.set_style(style)

    # ── Complexity Level Command ────────────────────────────────────────
    def set_style(self, style: str) -> None:
        """set_style("technical" | "analogy") — swaps which register every
        subsequent narrate_event()/coach_post_mortem() call uses."""
        try:
            self.style = ExplainerStyle(str(style).lower())
        except ValueError:
            raise ValueError(f"style must be 'technical' or 'analogy', got {style!r}")

    # ── Ollama call (same shape as modules/ai_triage.py, factored out) ──
    def _ollama_chat(self, system: str, user: str, timeout: float = 60.0) -> Optional[str]:
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(f"{self._host}/api/chat", data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = (data.get("message", {}) or {}).get("content", "").strip()
            return text or None
        except Exception as exc:
            self.last_error = str(exc)
            return None

    # ── 1a. Live Narrative Mode ──────────────────────────────────────────
    def narrate_event(self, raw_line: str) -> Optional[str]:
        """Given one raw Shark Attack narration line, return one short
        coaching explanation in the current style — or None if the line
        isn't a stage-start line worth commenting on."""
        stage = _extract_stage(raw_line)
        if stage is None:
            return None
        edu = lookup(stage)
        grounding = (
            f"Technique: {stage} ({edu.attck_ref or 'no ATT&CK mapping'})\n"
            f"Real-world attacker intent: {edu.attacker_intent}\n"
            f"What Angerona's defense actually watches for here: {edu.defense_architecture}\n"
        )
        system = (_NARRATIVE_SYSTEM_TECHNICAL if self.style is ExplainerStyle.TECHNICAL
                 else _NARRATIVE_SYSTEM_ANALOGY)
        user = f"{grounding}\nRaw drill narration just logged: \"{raw_line}\""
        reply = self._ollama_chat(system, user)
        if reply:
            return f"\U0001F393 {reply}"
        # Ollama unreachable — degrade to the static dictionary rather than
        # going silent (mirrors ai_triage.py's own health-check philosophy:
        # an outage should degrade, not disappear).
        fallback = edu.technical if self.style is ExplainerStyle.TECHNICAL else edu.analogy
        return f"\U0001F393 (offline fallback — {self.last_error or 'Ollama unreachable'}) {fallback}"

    # ── 1b. Forensic Post-Mortem Coach ───────────────────────────────────
    def coach_post_mortem(self, verdicts: List[dict]) -> List[str]:
        """Given the "verdicts" list from shark_aar.json, produce a Socratic
        coaching block for every genuinely MISSED step. Returns a list of
        ready-to-print blocks, one per missed step (empty list only if
        there were no steps at all).

        Only "detection"-category steps are eligible — Noise Injection not
        being caught is its PASS state (nothing to debrief), and Discovery
        has no detector by design (already explained via `academy explain`,
        not a blind spot to Socratically hunt for). Coaching on either would
        be nonsensical: there's no missing detector to go find when none
        was ever meant to exist. Older verdicts (pre-category field) fall
        back to "detection" so this doesn't crash on a stale shark_aar.json."""
        missed = [v for v in verdicts
                 if v.get("category", "detection") == "detection" and not v.get("caught")]
        if not verdicts:
            return ["No verdicts to debrief — run a Shark Attack drill first."]
        if not missed:
            return ["Nothing to debrief — every detection-test step was caught this run "
                   "(Noise Injection staying quiet and Discovery having no detector are "
                   "both expected, not misses). Try lowering a threshold or widening a "
                   "watch list, then run another drill to see if you can find a new "
                   "blind spot."]
        out = []
        for v in missed:
            stage = v.get("stage", "")
            edu = lookup(stage)
            grounding = (
                f"Technique: {stage} ({edu.attck_ref or 'no ATT&CK mapping'})\n"
                f"What it did: {v.get('description')}\n"
                f"Which module's territory this falls in, and what it watches "
                f"for: {edu.defense_architecture}\n"
            )
            reply = self._ollama_chat(_COACH_SYSTEM, grounding)
            if not reply:
                reply = (
                    "(offline fallback) Ask yourself: what data source would "
                    f"have needed to see this happen? {edu.defense_architecture} "
                    "Hint: check that module's watch list, port list, or poll "
                    "interval for exactly what this technique slipped through."
                )
            out.append(f"[{stage}]\n{reply}")
        return out
