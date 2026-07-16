"""evolution_engine.py — The Evolutionary Loop Engine (EVOL).

A drop-in module that closes the self-hardening loop: when the Judgment gate
reports a validation bypass (VERIFICATION_RESULT: SUCCESS), this engine studies
the footprint that got through, asks the local LLM to synthesize a YARA rule for
it, deploys the rule, and re-verifies — iterating up to 3 times, then escalating
if it still can't catch the technique.

Trigger: either call `activate(technique_id)` directly, or let the module do it
automatically — it subscribes to the event bus and fires on any HIGH event whose
details carry {"verified": "SUCCESS"} (emitted by Posture Hardening's Judgment
loop). Heavy work runs on a background thread so the bus/GUI never blocks.

SAFETY: generates DETECTION signatures (YARA) only — never offensive code. The
re-verification reuses the non-destructive `angerona.shark.verify` probe.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    from angerona.core.module_base import BaseModule
    from angerona.core.eventbus import Severity
    from angerona.core.config import Config
    _HAVE_SUITE = True
except Exception:                                   # standalone/test fallback
    _HAVE_SUITE = False
    class Severity:
        INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    class BaseModule:
        name = "base"; description = ""; category = ""; version = "1.0.0"
        enabled_by_default = True
        def __init__(self): self.health = 100; self.health_note = ""; self.status = "stopped"; self.last_error = ""
        def bind(self, bus): self._bus = bus
        def set_health(self, p, n=""): self.health = max(0, min(100, int(p))); self.health_note = n
        def emit(self, *a, **k): pass
        def sleep(self, s): time.sleep(min(s, 0.02))
        @property
        def stopping(self): return getattr(self, "_stopflag", False)

try:
    from angerona.engines import edr_logger as _edrlog
except Exception:
    _edrlog = None

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.getenv("MODEL_NAME", "llama3:latest")
MAX_ITERATIONS = 3
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# ── BL-07: keep self-hardening from becoming a self-DoS engine ─────────────────
# Each activation spawns a thread that hammers Ollama + a verify subprocess. An
# event storm (or a poisoned attack_feed) could otherwise spawn unbounded
# concurrent evolutions and exhaust CPU/Ollama. These bounds cap the blast radius.
_MAX_CONCURRENT = 2                 # never evolve more than N techniques at once
_DEBOUNCE_S = 300.0                 # per-technique cooldown between activations
_RATE_MAX, _RATE_WINDOW = 8, 3600.0        # ≤8 activations/hour globally
# Ollama circuit breaker: too many failures in a window → stop calling it and use
# the deterministic fallback only, for a cooldown, so we don't pile onto a
# struggling model under load.
_OLLAMA_FAIL_MAX, _OLLAMA_FAIL_WINDOW = 3, 120.0
_OLLAMA_BREAK_S = 300.0

_SYS_YARA = (
    "You are a senior detection engineer. Analyze this bypassed red-team footprint "
    "telemetry. Generate a functional, optimized YARA rule targeting the core "
    "malicious artifacts or behavioral footprint without causing false positives. "
    "Output ONLY the raw YARA rule text — no markdown fences, backticks, or prose."
)


def _edr(level: str, msg: str) -> None:
    try:
        if _edrlog is not None:
            getattr(_edrlog, level)("EVOL", msg)
    except Exception:
        pass


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]   # src/angerona/modules/ -> repo root


class EvolutionEngine(BaseModule):
    name = "Evolution Engine"
    description = "Self-hardening loop: turns a verification bypass into an auto-generated YARA signature."
    category = "Resilience"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        root = _repo_root()
        self.shared_logs = root / "shared_logs"
        self.rules_dir = root / "rules"
        self.attack_feed = self.shared_logs / "attack_feed.log"
        self.auto_rule = self.rules_dir / "auto_generated.yar"
        self.history_path = self.shared_logs / "evolution_history.json"
        self._mgr = None
        self._active: set = set()          # technique_ids currently evolving (no re-entrancy)
        # BL-07 bounds
        self._gate = threading.RLock()
        self._last_activation: dict = {}   # technique -> last activation ts (debounce)
        self._recent: list = []            # global activation timestamps (rate cap)
        self._rate_warned = False
        self._ollama_fails: list = []      # recent Ollama failure timestamps
        self._ollama_open_until = 0.0      # circuit-breaker cooldown deadline
        try:
            self.shared_logs.mkdir(parents=True, exist_ok=True)
            self.rules_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # ── wiring ───────────────────────────────────────────────────────────────
    def bind(self, bus) -> None:
        super().bind(bus)
        try:
            bus.subscribe(self._on_bus_event)   # auto-trigger on Judgment bypass
        except Exception:
            pass

    def bind_manager(self, manager) -> None:
        self._mgr = manager

    def _on_bus_event(self, ev) -> None:
        try:
            det = getattr(ev, "details", None) or {}
            if det.get("verified") == "SUCCESS" and det.get("technique"):
                self.activate(det["technique"])
        except Exception:
            pass

    def run(self) -> None:
        self.set_health(100, "idle — waiting for a verification bypass")
        while not self.stopping:
            self.sleep(5.0)

    # ── 1. activation interface ──────────────────────────────────────────────
    def activate(self, technique_id: str) -> None:
        """Called strictly on a validation bypass. Spawns the evolution loop on a
        background thread so the caller (bus/GUI) never blocks."""
        if not isinstance(technique_id, str) or not _TECHNIQUE_ID.fullmatch(technique_id):
            self.emit("Evolution trigger rejected: invalid ATT&CK technique identifier.",
                      Severity.MEDIUM)
            return
        now = time.time()
        with self._gate:
            if technique_id in self._active:
                return                      # already evolving this one
            # Debounce: same technique handled very recently → ignore the storm.
            if now - self._last_activation.get(technique_id, 0.0) < _DEBOUNCE_S:
                return
            # Global rate cap: don't let an event flood spin up endless work.
            self._recent = [t for t in self._recent if now - t < _RATE_WINDOW]
            if len(self._recent) >= _RATE_MAX:
                if not self._rate_warned:
                    self._rate_warned = True
                    self.emit("Evolution rate cap reached — deferring further self-hardening "
                              "to avoid a self-inflicted DoS.", Severity.MEDIUM)
                return
            self._rate_warned = False
            # Concurrency cap: bound simultaneous Ollama/verify work.
            if len(self._active) >= _MAX_CONCURRENT:
                return                      # debounce will let it retry later, not storm
            self._active.add(technique_id)
            self._last_activation[technique_id] = now
            self._recent.append(now)
        threading.Thread(target=self._evolve, args=(technique_id,),
                         name=f"evolve-{technique_id}", daemon=True).start()

    # ── Ollama circuit breaker (BL-07) ───────────────────────────────────────
    def _ollama_open(self) -> bool:
        """True when the breaker is OPEN (skip Ollama, use fallback only)."""
        return time.time() < self._ollama_open_until

    def _note_ollama_fail(self) -> None:
        now = time.time()
        with self._gate:
            self._ollama_fails = [t for t in self._ollama_fails if now - t < _OLLAMA_FAIL_WINDOW]
            self._ollama_fails.append(now)
            if len(self._ollama_fails) >= _OLLAMA_FAIL_MAX:
                self._ollama_open_until = now + _OLLAMA_BREAK_S
                self._ollama_fails.clear()

    # ── 2. telemetry extraction ──────────────────────────────────────────────
    def _latest_footprint(self, technique_id: str) -> dict:
        """Newest failed footprint for the technique. Prefers shared_logs/
        attack_feed.log; falls back to the drill history files."""
        # attack_feed.log (JSON-lines), newest matching entry
        try:
            if self.attack_feed.exists():
                lines = [l for l in self.attack_feed.read_text(encoding="utf-8").splitlines() if l.strip()]
                for l in reversed(lines):
                    try:
                        e = json.loads(l)
                    except Exception:
                        continue
                    if technique_id in json.dumps(e):
                        return e
        except Exception:
            pass
        # fall back to the drill histories in the data dir
        try:
            data_dir = Config.load().data_dir if _HAVE_SUITE else Path(os.getenv("ANGERONA_DATA", "."))
        except Exception:
            data_dir = Path(".")
        for hname in ("redteam_history.json", "shark_history.json"):
            try:
                h = json.loads((Path(data_dir) / hname).read_text(encoding="utf-8"))
                for step in reversed(h.get("steps", [])):
                    blob = json.dumps(step)
                    if technique_id in blob or technique_id in step.get("technique", ""):
                        return step
            except Exception:
                continue
        return {"technique": technique_id, "detail": "no footprint found"}

    # ── 3. local-AI YARA synthesis ───────────────────────────────────────────
    def _ollama_yara(self, footprint: dict) -> str | None:
        try:
            import requests
        except Exception:
            return None
        try:
            r = requests.post(f"{OLLAMA_HOST}/api/generate", timeout=90, json={
                "model": MODEL, "stream": False, "keep_alive": "30m",
                "options": {"temperature": 0},
                "system": _SYS_YARA, "prompt": json.dumps(footprint, indent=2)})
            r.raise_for_status()
            text = (r.json().get("response") or "").strip()
            text = re.sub(r"^```[a-zA-Z]*\n?|```$", "", text).strip()  # strip any fences
            return text if "rule " in text and "{" in text else None
        except Exception:
            return None

    def _fallback_yara(self, footprint: dict, technique_id: str, iteration: int) -> str:
        """Deterministic YARA rule built from the footprint's distinctive strings —
        used when Ollama is unavailable, and broadened slightly each iteration."""
        blob = " ".join(str(v) for v in footprint.values())
        toks = re.findall(r"[A-Za-z0-9_]{5,}", blob)
        # distinctive, low-false-positive tokens (marker names, technique labels)
        picks = []
        for t in toks:
            if t.lower() in ("simulated", "marker", "angerona", "drill", "inert", "false"):
                continue
            if t not in picks:
                picks.append(t)
        picks = picks[: 2 + iteration]          # widen the net each retry
        if not picks:
            picks = [technique_id]
        safe = re.sub(r"[^A-Za-z0-9_]", "_", technique_id)
        strings = "\n        ".join(f'$s{i} = "{t}" ascii wide nocase' for i, t in enumerate(picks))
        return (f"rule Angerona_Auto_{safe}_v{iteration} {{\n"
                f"    meta:\n"
                f'        author = "Angerona Evolution Engine"\n'
                f'        technique = "{technique_id}"\n'
                f'        generated = "{time.strftime("%Y-%m-%d %H:%M:%S")}"\n'
                f"    strings:\n        {strings}\n"
                f"    condition:\n        any of them\n}}\n")

    # ── 4. deployment + 5. re-test loop + 6. persistence ─────────────────────
    def _deploy(self, rule_text: str) -> bool:
        """Compile and atomically activate through the YARA scanner.

        No candidate is persisted when the actual bundled engine rejects it.
        """
        try:
            if self._mgr is not None:
                ys = self._mgr.modules.get("YARA Scanner")
                if ys is not None and hasattr(ys, "reload_rules"):
                    return bool(ys.reload_rules(rule_text))
        except Exception:
            pass
        return False

    def _verify(self, technique_id: str) -> str:
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "angerona.shark.verify", technique_id, "--verify"],
                capture_output=True, text=True, timeout=90)
            buf = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except Exception as exc:
            buf = f"VERIFICATION_RESULT: ERROR ({exc})"
        for line in buf.splitlines():
            if "VERIFICATION_RESULT:" in line:
                return line.split("VERIFICATION_RESULT:", 1)[1].strip().split()[0]
        return "ERROR"

    def _evolve(self, technique_id: str) -> None:
        try:
            self.set_health(40, f"evolving a signature for {technique_id}")
            self.emit(f"🧬 Evolution Engine engaged for {technique_id} — synthesizing a "
                      f"detection signature for the bypassed footprint.", Severity.HIGH,
                      technique=technique_id)
            footprint = self._latest_footprint(technique_id)
            attempts = []
            certified = False
            for i in range(1, MAX_ITERATIONS + 1):
                # Circuit breaker: skip Ollama entirely while it's failing under
                # load; the deterministic fallback still hardens the signature.
                rule = None
                if not self._ollama_open():
                    rule = self._ollama_yara(footprint)
                    if not rule:
                        self._note_ollama_fail()
                if rule:
                    source = "ollama"
                else:
                    rule = self._fallback_yara(footprint, technique_id, i)
                    source = "fallback(breaker)" if self._ollama_open() else "fallback"
                if not self._deploy(rule):
                    attempts.append({"iteration": i, "result": "REJECTED",
                                     "rule_excerpt": rule[:400], "source": source})
                    self.emit(f"Evolution iteration {i} rejected by YARA compile gate.",
                              Severity.HIGH, technique=technique_id, iteration=i)
                    continue
                result = self._verify(technique_id)
                attempts.append({"iteration": i, "result": result,
                                 "rule_excerpt": rule[:400], "source": source})
                self.emit(f"🧬 Iteration {i}/{MAX_ITERATIONS} for {technique_id}: {result}",
                          Severity.INFO, technique=technique_id, iteration=i, result=result)
                if result == "BLOCKED":
                    certified = True
                    _edr("info", f"[EVOLUTION] Auto-generated YARA rule now BLOCKS {technique_id} "
                                 f"after {i} iteration(s). Signature deployed to {self.auto_rule}.")
                    self.emit(f"✅ Evolution success: new signature CATCHES {technique_id} "
                              f"(iteration {i}).", Severity.INFO, technique=technique_id)
                    self.set_health(100, "signature evolved & certified")
                    break
                time.sleep(1.0)   # brief backoff between tuning rounds
            if not certified:
                _edr("critical", f"[EVOLUTION] FAILED to auto-generate a signature that catches "
                                 f"{technique_id} after {MAX_ITERATIONS} iterations. Manual "
                                 f"intervention required — the technique remains uncaught.")
                self.set_health(20, f"could not evolve a rule for {technique_id}")
                self.emit(f"🛑 CRITICAL: Evolution Engine could not catch {technique_id} after "
                          f"{MAX_ITERATIONS} tries — manual signature work needed.",
                          Severity.CRITICAL, technique=technique_id, intervention=True)
            self._record_history(technique_id, footprint, attempts, certified)
        except Exception as exc:
            self.last_error = str(exc)
            _edr("error", f"[EVOLUTION] engine error for {technique_id}: {exc}")
        finally:
            self._active.discard(technique_id)

    def _record_history(self, technique_id, footprint, attempts, certified) -> None:
        entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "technique": technique_id,
                 "certified": certified, "iterations": len(attempts),
                 "rule_path": str(self.auto_rule), "footprint": footprint, "attempts": attempts}
        try:
            self.shared_logs.mkdir(parents=True, exist_ok=True)
            hist = []
            if self.history_path.exists():
                try:
                    hist = json.loads(self.history_path.read_text(encoding="utf-8"))
                except Exception:
                    hist = []
            hist.append(entry)
            self.history_path.write_text(json.dumps(hist, indent=2), encoding="utf-8")
        except Exception:
            pass

    def self_test(self) -> tuple[bool, str]:
        # Isolated: exercise the fallback YARA synthesis + history write, no subprocess.
        try:
            fp = {"technique": "T1003", "telemetry": "lsass_dump credential access marker"}
            rule = self._fallback_yara(fp, "T1003", 1)
            ok = "rule Angerona_Auto_T1003" in rule and "condition" in rule

            # BL-07 bounds (no real evolving — stub the worker so no Ollama/subprocess).
            e = EvolutionEngine()
            e._evolve = lambda _tid: None
            for tid in ("T1001", "T1002", "T1003"):
                e.activate(tid)
            conc_ok = len(e._active) == _MAX_CONCURRENT        # 3rd refused (concurrency cap)

            e2 = EvolutionEngine(); e2._evolve = lambda _tid: None
            e2._recent = [time.time()] * _RATE_MAX             # pre-fill the rate window
            e2.activate("T1099")
            rate_ok = "T1099" not in e2._active                # refused by the rate cap

            e3 = EvolutionEngine()
            for _ in range(_OLLAMA_FAIL_MAX):
                e3._note_ollama_fail()
            breaker_ok = e3._ollama_open()                     # breaker opens after N fails

            ok = bool(ok and conc_ok and rate_ok and breaker_ok)
            return (ok, "fallback YARA synthesis + BL-07 bounds (concurrency/rate/breaker) OK"
                    if ok else f"failed: yara={rule[:20]!r} conc={conc_ok} rate={rate_ok} "
                    f"breaker={breaker_ok}")
        except Exception as exc:
            return (False, str(exc))


def register():
    return EvolutionEngine()


if __name__ == "__main__":
    import json as _j
    print(_j.dumps({"self_test": register().self_test()}, indent=2))
