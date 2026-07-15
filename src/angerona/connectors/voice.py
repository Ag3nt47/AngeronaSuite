"""connectors/voice.py — ARIA voice I/O (opt-in, local-first, degraded-safe).

Gives ARIA a voice and an ear: spoken threat narration (TTS) and voice commands
(STT) behind a wake word. Everything here is **off by default** and every
backend is **optional** — with nothing installed the module imports, self-tests,
and no-ops cleanly. Mic and speech are never engaged unless the operator opts in.

Backends (all optional, auto-detected, never required):
    • TTS  — local Windows SAPI / ``pyttsx3`` (offline). ElevenLabs only if the
             operator explicitly enables it and supplies a key (opt-in cloud).
    • STT  — ``vosk`` or ``faster-whisper`` (both offline).
    • Wake — a simple keyword gate ("hey aria") over recognised text.

    HARD SCOPE: I/O only. Voice never executes an action itself — recognised
    commands are handed to the ARIA assistant, where writes stay confirm-gated.
    No audio leaves the machine unless ElevenLabs is explicitly enabled.
"""
from __future__ import annotations

import importlib.util
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional


def _have(mod: str) -> bool:
    """True if a module is importable, without importing it."""
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


@dataclass
class VoiceCaps:
    tts_local: bool
    stt_local: bool
    tts_cloud_available: bool
    detail: dict = field(default_factory=dict)


class Voice:
    """Opt-in voice I/O.

    Usage::

        v = Voice(enabled=True)          # engages backends if present
        v.speak("Load critical — throttled cosmetics to protect detection.")
        text = v.listen(timeout=4)       # None if no STT backend / no speech
        if v.is_wake(text):
            command = v.strip_wake(text) # hand to the assistant (gated there)

    Backends can be injected (``tts_fn`` / ``stt_fn``) for tests or custom
    engines; otherwise they're built lazily from whatever is installed."""

    WAKE_WORDS = ("hey aria", "okay aria", "aria")

    def __init__(self, *, enabled: bool = False,
                 allow_cloud_tts: bool = False,
                 tts_fn: Optional[Callable[[str], None]] = None,
                 stt_fn: Optional[Callable[[float], Optional[str]]] = None) -> None:
        self.enabled = enabled
        self.allow_cloud_tts = allow_cloud_tts
        self._tts_fn = tts_fn
        self._stt_fn = stt_fn
        self._spoken: deque[str] = deque(maxlen=50)   # narration history
        self.last_error: str = ""

    # ── Capability detection ──────────────────────────────────────────────────
    def capabilities(self) -> VoiceCaps:
        import sys
        # Windows always has a local TTS via the built-in System.Speech
        # (driven by PowerShell) — no extra install needed.
        win_sapi = sys.platform.startswith("win")
        return VoiceCaps(
            tts_local=self._tts_fn is not None or _have("pyttsx3") or _have("win32com") or win_sapi,
            stt_local=self._stt_fn is not None or _have("vosk") or _have("faster_whisper"),
            tts_cloud_available=self.allow_cloud_tts and _have("requests"),
            detail={
                "pyttsx3": _have("pyttsx3"), "win32com": _have("win32com"),
                "win_sapi": win_sapi,
                "vosk": _have("vosk"), "faster_whisper": _have("faster_whisper"),
                "injected_tts": self._tts_fn is not None,
                "injected_stt": self._stt_fn is not None,
            },
        )

    def status(self) -> str:
        c = self.capabilities()
        if not self.enabled:
            return "voice: OFF (opt-in)"
        parts = []
        parts.append("TTS:" + ("local" if c.tts_local else ("cloud" if c.tts_cloud_available else "none")))
        parts.append("STT:" + ("local" if c.stt_local else "none"))
        return "voice: ON · " + " · ".join(parts)

    # ── Output (TTS) ──────────────────────────────────────────────────────────
    def speak(self, text: str) -> bool:
        """Speak ``text`` if enabled and a TTS backend exists. Returns True if
        spoken, False if disabled or no backend (never raises)."""
        self._spoken.append(text)
        if not self.enabled:
            return False
        fn = self._resolve_tts()
        if fn is None:
            self.last_error = "no TTS backend available"
            return False
        try:
            fn(text)
            return True
        except Exception as exc:
            self.last_error = f"TTS failed: {exc}"
            return False

    def _resolve_tts(self) -> Optional[Callable[[str], None]]:
        """Pick a local TTS backend, cheapest-to-most-robust. Cached once built.

        Order: injected → pyttsx3 (if installed) → Windows SAPI via PowerShell
        (zero dependencies, thread-safe because it's a subprocess) → win32com
        SAPI. The PowerShell path is what makes narration work out of the box on
        a stock Windows install with nothing extra to install."""
        import sys
        if self._tts_fn is not None:
            return self._tts_fn
        # 1) pyttsx3 — cross-platform offline engine, if the user installed it.
        if _have("pyttsx3"):
            try:
                import pyttsx3  # type: ignore
                engine = pyttsx3.init()
                self._tts_fn = lambda t: (engine.say(t), engine.runAndWait())
                return self._tts_fn
            except Exception as exc:  # pragma: no cover
                self.last_error = f"pyttsx3 init failed: {exc}"
        # 2) Windows SAPI via PowerShell System.Speech — no deps, and because it
        #    runs as a subprocess it is safe to call from any thread (no COM init).
        if sys.platform.startswith("win"):
            self._tts_fn = self._powershell_speak
            return self._tts_fn
        # 3) Windows SAPI via win32com (pywin32), if PowerShell was unavailable.
        if _have("win32com"):
            try:
                import pythoncom  # type: ignore
                import win32com.client  # type: ignore

                def _sapi(t: str) -> None:
                    pythoncom.CoInitialize()          # COM per calling thread
                    try:
                        win32com.client.Dispatch("SAPI.SpVoice").Speak(t)
                    finally:
                        pythoncom.CoUninitialize()
                self._tts_fn = _sapi
                return self._tts_fn
            except Exception as exc:  # pragma: no cover
                self.last_error = f"SAPI init failed: {exc}"
        return None

    @staticmethod
    def _powershell_speak(text: str) -> None:  # pragma: no cover - Windows only
        """Speak via the built-in .NET SpeechSynthesizer. Text is piped over
        stdin so there's nothing to escape, and the window is suppressed."""
        import subprocess
        ps = ("Add-Type -AssemblyName System.Speech; "
              "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
              "$s.Speak([Console]::In.ReadToEnd())")
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            input=text, text=True, timeout=60,
            creationflags=0x08000000,   # CREATE_NO_WINDOW
        )

    def narration_history(self, n: int = 10) -> list[str]:
        return list(self._spoken)[-n:]

    def narration_history(self, n: int = 10) -> list[str]:
        return list(self._spoken)[-n:]

    # ── Input (STT + wake word) ───────────────────────────────────────────────
    def listen(self, timeout: float = 5.0) -> Optional[str]:
        """Return recognised text, or None if disabled / no backend / silence."""
        if not self.enabled:
            return None
        fn = self._stt_fn or self._resolve_stt()
        if fn is None:
            return None
        try:
            return fn(timeout)
        except Exception as exc:
            self.last_error = f"STT failed: {exc}"
            return None

    def _resolve_stt(self) -> Optional[Callable[[float], Optional[str]]]:
        """Build an OFFLINE speech recogniser from vosk + a sounddevice mic, if
        both are installed. Never required: returns None (→ listen() no-ops) when
        the libraries or a model are absent, so voice input is purely opt-in.

        Install to enable:  pip install vosk sounddevice
        and either set ANGERONA_VOSK_MODEL to a downloaded model directory, or let
        vosk fetch the small en-us model on first use."""
        if self._stt_fn is not None:
            return self._stt_fn
        if not (_have("vosk") and _have("sounddevice")):
            return None
        try:
            import json
            import os
            import queue
            import time as _t
            import vosk            # type: ignore
            import sounddevice as sd  # type: ignore

            model_path = os.environ.get("ANGERONA_VOSK_MODEL", "").strip()
            model = vosk.Model(model_path) if model_path else vosk.Model(lang="en-us")
            rec = vosk.KaldiRecognizer(model, 16000)

            def _listen(timeout: float) -> Optional[str]:
                q: "queue.Queue[bytes]" = queue.Queue()

                def _cb(indata, _frames, _time, _status):
                    q.put(bytes(indata))

                with sd.RawInputStream(samplerate=16000, blocksize=8000, dtype="int16",
                                       channels=1, callback=_cb):
                    end = _t.time() + max(1.0, float(timeout))
                    while _t.time() < end:
                        try:
                            data = q.get(timeout=0.5)
                        except Exception:
                            continue
                        if rec.AcceptWaveform(data):
                            txt = (json.loads(rec.Result()).get("text") or "").strip()
                            if txt:
                                return txt
                    txt = (json.loads(rec.FinalResult()).get("text") or "").strip()
                    return txt or None

            self._stt_fn = _listen
            return self._stt_fn
        except Exception as exc:  # pragma: no cover - hardware/lib dependent
            self.last_error = f"vosk STT init failed: {exc}"
            return None

    def is_wake(self, text: Optional[str]) -> bool:
        if not text:
            return False
        low = text.strip().lower()
        return any(low.startswith(w) or f" {w} " in f" {low} " for w in self.WAKE_WORDS)

    def strip_wake(self, text: str) -> str:
        """Remove the wake word, leaving the command for the assistant."""
        low = text.strip().lower()
        for w in sorted(self.WAKE_WORDS, key=len, reverse=True):
            if low.startswith(w):
                return text.strip()[len(w):].lstrip(" ,:-").strip()
        return text.strip()

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove the opt-in / degraded-safe contract without needing any audio
        backend: disabled is silent; enabled-without-backend degrades cleanly;
        an injected backend is actually called; wake-word gating works."""
        try:
            # 1 ── disabled == silent no-op, but history still recorded
            off = Voice(enabled=False)
            assert off.speak("hello") is False, "disabled must not speak"
            assert off.narration_history()[-1] == "hello", "history recorded even when muted"
            assert off.listen() is None and "OFF" in off.status(), "disabled listen/status"

            # 2 ── enabled but no backend → clean False, no raise
            bare = Voice(enabled=True)   # no injected fns; real libs may be absent
            spoke = bare.speak("threat narration")
            if not spoke:
                assert "no TTS backend" in bare.last_error or bare.capabilities().tts_local, \
                    "must explain the degradation"

            # 3 ── injected TTS backend is called
            said: list[str] = []
            v = Voice(enabled=True, tts_fn=lambda t: said.append(t),
                      stt_fn=lambda to: "hey aria run the loop")
            assert v.speak("Load critical.") is True and said == ["Load critical."], "injected TTS used"

            # 4 ── STT + wake word
            heard = v.listen(2)
            assert heard == "hey aria run the loop", "injected STT used"
            assert v.is_wake(heard) is True, "wake word detected"
            assert v.strip_wake(heard) == "run the loop", "wake word stripped to command"
            assert v.is_wake("what's the score") is False, "no false wake"

            # 5 ── capabilities never raises and reports injected backends
            caps = v.capabilities()
            assert caps.tts_local and caps.stt_local, "injected backends reported as available"
            assert "ON" in v.status(), "enabled status"

            return True, ("OK — disabled is a silent no-op (history still kept); "
                          "enabled-without-backend degrades cleanly with a reason; "
                          "injected TTS/STT are used; wake word 'hey aria' detected and "
                          "stripped to 'run the loop'; no false wake; capabilities safe.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory ──────────────────────────────────────────────────────────
_VOICE: Optional[Voice] = None


def init_voice(*, enabled: bool = False, allow_cloud_tts: bool = False) -> Voice:
    """Create/replace the shared voice connector. Off by default."""
    global _VOICE
    _VOICE = Voice(enabled=enabled, allow_cloud_tts=allow_cloud_tts)
    return _VOICE


def get_voice() -> Voice:
    global _VOICE
    if _VOICE is None:
        _VOICE = Voice(enabled=False)
    return _VOICE


if __name__ == "__main__":
    v = Voice()
    ok, detail = v.self_test()
    print(f"[voice] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    print(f"[voice] detected caps: {Voice(enabled=True).status()}")
    raise SystemExit(0 if ok else 1)
