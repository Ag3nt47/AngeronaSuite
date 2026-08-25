"""Transient, opt-in conversational awareness for ARIA.

This module gives the voice/UI layer the small amount of local state needed for
natural follow-ups without turning ambient speech into durable surveillance.
It keeps a short, redacted, in-memory rolling window; detects ARIA's name
anywhere in an utterance; opens a bounded follow-up window after a reply; and
suppresses likely echoes of ARIA's own speech.

Nothing in this module opens a microphone, persists a transcript, calls a model,
or invokes a tool.  The caller must explicitly enable it and ARIA's existing
READ/WRITE gate remains the only path to host actions.
"""
from __future__ import annotations

import difflib
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Iterable

from angerona.core.privacy import redact_text


PERSONA_INSTRUCTIONS = {
    "aria": (
        "Use ARIA's balanced, clear security-coach voice. Be concise, calm, and "
        "explicit about evidence and confirmation boundaries."
    ),
    "friday": (
        "Use the Friday presentation profile: warm, efficient, pragmatic, and "
        "comfortable with concise conversational follow-ups. This changes tone only."
    ),
    "ultron": (
        "Use the Ultron incident-analysis presentation profile: terse, analytical, "
        "risk-ranked, and direct. This is a defensive presentation style only: never "
        "claim autonomy, expand authority, or bypass operator confirmation."
    ),
}


def normalize_persona(value: object) -> str:
    """Return a supported presentation profile, failing closed to ARIA."""
    selected = str(value or "aria").strip().casefold()
    return selected if selected in PERSONA_INSTRUCTIONS else "aria"


def persona_instruction(value: object) -> str:
    return PERSONA_INSTRUCTIONS[normalize_persona(value)]


@dataclass(frozen=True)
class ConversationTurn:
    ts: float
    speaker: str
    text: str


@dataclass(frozen=True)
class VoiceDecision:
    accepted: bool
    text: str = ""
    source: str = "ambient"
    interrupt: bool = False
    echo: bool = False


class ConversationAwareness:
    """Bounded, transient context and conversational voice-mode state."""

    INTERRUPT_PHRASES = frozenset({
        "stop", "wait", "cancel", "quiet", "be quiet", "shut up", "enough",
        "never mind", "nevermind", "hold on",
    })

    def __init__(
        self,
        *,
        enabled: bool = False,
        always_listen: bool = False,
        follow_up_seconds: float = 12.0,
        context_seconds: float = 300.0,
        max_turns: int = 24,
        wake_words: Iterable[str] = ("hey aria", "okay aria", "aria"),
    ) -> None:
        self.enabled = bool(enabled)
        self.always_listen = bool(always_listen) and self.enabled
        self.follow_up_seconds = max(0.0, min(60.0, float(follow_up_seconds)))
        self.context_seconds = max(10.0, min(1800.0, float(context_seconds)))
        self._turns: deque[ConversationTurn] = deque(maxlen=max(4, min(100, int(max_turns))))
        self._wake_words = tuple(
            sorted({str(word).strip().casefold() for word in wake_words if str(word).strip()},
                   key=len, reverse=True)
        )
        self._wake_patterns = tuple(
            (word, re.compile(rf"(?<!\w){re.escape(word)}(?!\w)", re.I))
            for word in self._wake_words
        )
        self._hot_until = 0.0
        self._recent_replies: deque[str] = deque(maxlen=3)
        self._lock = threading.RLock()

    @property
    def follow_up_active(self) -> bool:
        with self._lock:
            return self.enabled and time.monotonic() <= self._hot_until

    def cancel_follow_up(self) -> None:
        with self._lock:
            self._hot_until = 0.0

    @staticmethod
    def _normal(text: object) -> str:
        return " ".join(re.findall(r"[a-z0-9']+", str(text or "").casefold()))

    def is_interrupt(self, text: object) -> bool:
        return self._normal(text).strip(" .!?") in self.INTERRUPT_PHRASES

    def is_echo(self, text: object) -> bool:
        candidate = self._normal(text)
        if len(candidate) < 4:
            return False
        with self._lock:
            replies = tuple(self._recent_replies)
        for reply in replies:
            if candidate == reply:
                return True
            if len(candidate) >= 12 and (candidate in reply or reply in candidate):
                return True
            if len(candidate) >= 12 and difflib.SequenceMatcher(
                None, candidate, reply, autojunk=False
            ).ratio() >= 0.86:
                return True
        return False

    def strip_wake(self, text: object) -> tuple[str, bool]:
        """Remove the first wake phrase wherever it occurs."""
        original = str(text or "").strip()
        for _word, pattern in self._wake_patterns:
            match = pattern.search(original)
            if match is None:
                continue
            cleaned = (original[:match.start()] + " " + original[match.end():]).strip()
            cleaned = re.sub(r"\s+", " ", cleaned).strip(" ,:;-?!.")
            return cleaned, True
        return original, False

    def _remember(self, speaker: str, text: object, *, now: float | None = None) -> None:
        if not self.enabled:
            return
        clean = redact_text(text, limit=600).strip()
        if not clean:
            return
        stamp = time.monotonic() if now is None else float(now)
        with self._lock:
            self._prune_locked(stamp)
            if self._turns:
                latest = self._turns[-1]
                if latest.speaker == speaker and latest.text == clean:
                    return
            self._turns.append(ConversationTurn(stamp, speaker, clean))

    def observe_ambient(self, text: object, *, now: float | None = None) -> None:
        self._remember("room", text, now=now)

    def record_user(self, text: object, *, now: float | None = None) -> None:
        self._remember("operator", text, now=now)

    def record_reply(self, text: object, *, now: float | None = None) -> None:
        if not self.enabled:
            return
        stamp = time.monotonic() if now is None else float(now)
        clean = self._normal(text)
        with self._lock:
            if clean:
                self._recent_replies.append(clean[:800])
            self._hot_until = stamp + self.follow_up_seconds
        self._remember("aria", text, now=stamp)

    def resolve_voice(self, text: object, *, now: float | None = None) -> VoiceDecision:
        """Classify one local transcript without executing anything."""
        raw = str(text or "").strip()
        if not self.enabled or not raw:
            return VoiceDecision(False)
        stamp = time.monotonic() if now is None else float(now)
        if self.is_echo(raw):
            return VoiceDecision(False, source="echo", echo=True)
        if self.is_interrupt(raw):
            self.cancel_follow_up()
            return VoiceDecision(False, source="interrupt", interrupt=True)

        cleaned, directed = self.strip_wake(raw)
        with self._lock:
            follow_up = stamp <= self._hot_until
        if directed:
            if cleaned:
                self.record_user(cleaned, now=stamp)
            return VoiceDecision(True, cleaned, source="wake")
        if follow_up:
            self.record_user(raw, now=stamp)
            return VoiceDecision(True, raw, source="follow-up")
        if self.always_listen and len(self._normal(raw).split()) >= 2:
            self.record_user(raw, now=stamp)
            return VoiceDecision(True, raw, source="always-listen")

        self.observe_ambient(raw, now=stamp)
        return VoiceDecision(False, source="ambient")

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.context_seconds
        while self._turns and self._turns[0].ts < cutoff:
            self._turns.popleft()

    def context(self, *, limit: int = 1600, now: float | None = None) -> str:
        """Render bounded recent discussion for a local model prompt."""
        if not self.enabled:
            return ""
        stamp = time.monotonic() if now is None else float(now)
        with self._lock:
            self._prune_locked(stamp)
            lines = [f"{turn.speaker}: {turn.text}" for turn in self._turns]
        text = "\n".join(lines)
        bound = max(0, min(8000, int(limit)))
        return text[-bound:]

    def self_test(self) -> tuple[bool, str]:
        try:
            off = ConversationAwareness()
            assert not off.resolve_voice("aria status").accepted
            assert off.context() == ""

            aware = ConversationAwareness(enabled=True, follow_up_seconds=10)
            aware.observe_ambient("We should check the firewall before lunch", now=100)
            decision = aware.resolve_voice("What do you think, ARIA?", now=101)
            assert decision.accepted and decision.source == "wake"
            assert decision.text.casefold() == "what do you think"
            aware.record_reply("I would verify the firewall policy first.", now=102)
            follow = aware.resolve_voice("And the endpoint rules?", now=103)
            assert follow.accepted and follow.source == "follow-up"
            assert aware.resolve_voice(
                "I would verify the firewall policy first.", now=104
            ).echo
            assert aware.resolve_voice("stop", now=105).interrupt
            assert not aware.follow_up_active
            assert "firewall" in aware.context(now=106).casefold()

            always = ConversationAwareness(enabled=True, always_listen=True)
            assert always.resolve_voice("show posture", now=1).source == "always-listen"
            assert normalize_persona("ULTRON") == "ultron"
            assert normalize_persona("unknown") == "aria"
            return True, (
                "OK — opt-in gate, wake-anywhere, transient room context, follow-up "
                "window, echo suppression, interruption, always-listen, and persona "
                "authority boundaries passed."
            )
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = ConversationAwareness().self_test()
    print(f"[conversation_awareness] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
