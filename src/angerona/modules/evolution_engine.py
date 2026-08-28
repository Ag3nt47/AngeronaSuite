"""evolution_engine.py — The Evolutionary Loop Engine (EVOL).

A drop-in module that closes the review loop: when the Judgment gate reports a
validation bypass (VERIFICATION_RESULT: SUCCESS), this engine studies the
footprint, asks the local LLM to synthesize a YARA candidate, and stages that
candidate for operator review. Generated content is never activated
automatically.

Trigger: either call `activate(technique_id)` directly, or let the module do it
automatically — it subscribes to the event bus and accepts only a typed,
single-use receipt issued by Posture Hardening's Judgment loop. Heavy work runs
on a tracked background thread so the bus/GUI never blocks.

SAFETY: generates inert DETECTION proposals (YARA) only — never offensive code,
never activates a generated rule, and never claims an inactive proposal was
certified.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from angerona.engines import ollama_client
from angerona.shark.run_manifest import (
    DrillHistoryIntegrityError,
    load_verified_history,
)

try:
    from angerona.core.module_base import BaseModule
    from angerona.core.eventbus import Severity, is_remote_observe_only
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
    def is_remote_observe_only(_event):
        return False

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
    from angerona.core.data_paths import data_dir
    return data_dir()


def _reverse_lines(path: Path, block_size: int = 64 * 1024):
    """Yield UTF-8 lines newest-first without loading the whole file.

    ``attack_feed.log`` is append-only and can be large after a long-running
    deployment.  Reading it into a list made one evolution activation allocate
    several times the complete file size.  Working backward in fixed blocks
    preserves the exact newest-match semantics with bounded scratch memory.
    """
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        position = stream.tell()
        carry = b""
        while position > 0:
            size = min(max(1, int(block_size)), position)
            position -= size
            stream.seek(position)
            parts = (stream.read(size) + carry).split(b"\n")
            carry = parts[0]
            for raw in reversed(parts[1:]):
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                yield raw.decode("utf-8")
        if carry:
            if carry.endswith(b"\r"):
                carry = carry[:-1]
            yield carry.decode("utf-8")


class EvolutionEngine(BaseModule):
    name = "Evolution Engine"
    description = ("Review-gated hardening: turns a typed Judgment bypass receipt "
                   "into an inert YARA proposal; never auto-activates it.")
    category = "Resilience"
    version = "1.1.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        root = _repo_root()
        self.shared_logs = root / "shared_logs"
        self.rules_dir = root / "rules"
        self.attack_feed = self.shared_logs / "attack_feed.log"
        self.auto_rule = self.rules_dir / "auto_generated.yar"
        self.proposals_dir = self.rules_dir / "proposals"
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
        self._workers: set[threading.Thread] = set()
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
            # An authenticated fleet peer may report evidence about its own
            # endpoint, but it has no authority to mutate this endpoint's YARA
            # policy.  Only a receiver-local, verified hardening receipt can
            # activate the self-evolution loop.
            if is_remote_observe_only(ev):
                return
            det = getattr(ev, "details", None) or {}
            if (
                getattr(ev, "module", "") != "Posture Hardening"
                or getattr(ev, "severity", Severity.INFO) != Severity.HIGH
                or det.get("event_type") != "judgment-bypass-receipt.v1"
                or det.get("verified") != "SUCCESS"
            ):
                return
            hardening = (
                getattr(self._mgr, "modules", {}).get("Posture Hardening")
                if self._mgr is not None else None
            )
            consume = getattr(hardening, "consume_judgment_bypass_receipt", None)
            technique = str(det.get("technique") or "")
            if not callable(consume) or not consume(
                str(det.get("receipt_id") or ""),
                technique,
                str(det.get("receipt_digest") or ""),
            ):
                self.emit(
                    "Evolution trigger rejected: missing, forged, expired, or replayed "
                    "Judgment receipt.",
                    Severity.MEDIUM,
                    finding_code="evolution.untrusted_trigger",
                    response_authorized=False,
                )
                return
            self.activate(technique)
        except Exception:
            pass

    def run(self) -> None:
        self.set_health(100, "proposal-only — waiting for a typed Judgment bypass")
        # Activation is delivered synchronously by the EventBus subscription in
        # ``bind()``; this module has no periodic work.  The old five-second
        # sleep loop woke 17,280 times/day merely to discover that it was still
        # idle.  Publish readiness once, then park interruptibly until stop().
        self.mark_cycle_complete()
        stop_event = self.generation_stop_event()
        stop_event.wait()
        gate = getattr(self, "_gate", None)
        if gate is None:
            return
        with gate:
            workers = tuple(getattr(self, "_workers", ()))
        for worker in workers:
            worker.join(timeout=0.25)

    # ── 1. activation interface ──────────────────────────────────────────────
    def activate(self, technique_id: str) -> None:
        """Called strictly on a validation bypass. Spawns the evolution loop on a
        background thread so the caller (bus/GUI) never blocks."""
        if not isinstance(technique_id, str) or not _TECHNIQUE_ID.fullmatch(technique_id):
            self.emit("Evolution trigger rejected: invalid ATT&CK technique identifier.",
                      Severity.MEDIUM)
            return
        if self.status != "running":
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
        generation = self.lifecycle_generation
        stop_event = self.generation_stop_event()
        worker = threading.Thread(
            target=self._evolve,
            args=(technique_id, generation, stop_event),
            name=f"evolve-{technique_id}",
            daemon=True,
        )
        with self._gate:
            self._workers.add(worker)
        try:
            worker.start()
        except Exception:
            with self._gate:
                self._workers.discard(worker)
                self._active.discard(technique_id)
            raise

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
                for l in _reverse_lines(self.attack_feed):
                    if not l.strip():
                        continue
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
                h = load_verified_history(Path(data_dir) / hname)
                for step in reversed(h.get("steps", [])):
                    blob = json.dumps(step)
                    if technique_id in blob or technique_id in step.get("technique", ""):
                        return step
            except (DrillHistoryIntegrityError, OSError, TypeError, ValueError):
                continue
        return {"technique": technique_id, "detail": "no footprint found"}

    # ── 3. local-AI YARA synthesis ───────────────────────────────────────────
    def _ollama_yara(self, footprint: dict) -> str | None:
        try:
            result = ollama_client.analyze_telemetry(
                "Create the defensive YARA signature requested by the system policy.",
                json.dumps(footprint, indent=2),
                MODEL,
                system=_SYS_YARA,
                host=OLLAMA_HOST,
                timeout=90,
                options={"temperature": 0},
            )
            if result.get("error"):
                return None
            text = str(result.get("response") or "").strip()
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

    # ── 4. proposal staging + 5. persistence ─────────────────────────────────────
    def _stage_proposal(
        self, technique_id: str, rule_text: str, source: str
    ) -> Path:
        """Atomically persist an inert JSON review artifact, never a live rule."""
        self.proposals_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", technique_id)
        target = self.proposals_dir / f"{safe}-{int(time.time() * 1000)}.json"
        candidate = target.with_suffix(".candidate")
        document = {
            "schema": "angerona.yara-proposal.v1",
            "technique": technique_id,
            "source": source,
            "rule_text": rule_text,
            "status": "PROPOSED_NOT_ACTIVE",
            "active_rule_path": str(self.auto_rule),
            "requires_operator_review": True,
            "response_authorized": False,
        }
        with candidate.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(candidate, target)
        return target

    def _evolve(
        self,
        technique_id: str,
        generation: int | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        try:
            if generation is None:
                generation = self.lifecycle_generation
            if stop_event is None:
                stop_event = self.generation_stop_event()
            self.set_health(70, f"drafting an inert signature proposal for {technique_id}")
            self.emit(f"🧬 Evolution Engine engaged for {technique_id} — synthesizing a "
                      f"review-only detection proposal for the bypassed footprint.",
                      Severity.HIGH, technique=technique_id)
            footprint = self._latest_footprint(technique_id)
            rule = None
            if not self._ollama_open():
                rule = self._ollama_yara(footprint)
                if not rule:
                    self._note_ollama_fail()
            source = "ollama" if rule else (
                "fallback(breaker)" if self._ollama_open() else "fallback"
            )
            rule = rule or self._fallback_yara(footprint, technique_id, 1)
            if (
                stop_event.is_set()
                or generation != self.lifecycle_generation
                or self.status != "running"
            ):
                return
            proposal = self._stage_proposal(technique_id, rule, source)
            attempts = [{
                "iteration": 1,
                "result": "PROPOSED_NOT_ACTIVE",
                "rule_excerpt": rule[:400],
                "source": source,
                "proposal_path": str(proposal),
            }]
            self._record_history(technique_id, footprint, attempts, False)
            self.set_health(100, "YARA proposal staged; operator review required")
            self.emit(
                f"Evolution staged an inert YARA proposal for {technique_id}; no rule "
                "was activated or certified.",
                Severity.MEDIUM,
                technique=technique_id,
                proposal_path=str(proposal),
                executed=False,
                verified=False,
                response_authorized=False,
            )
        except Exception as exc:
            self.last_error = str(exc)
            _edr("error", f"[EVOLUTION] engine error for {technique_id}: {exc}")
        finally:
            with self._gate:
                self._active.discard(technique_id)
                self._workers.discard(threading.current_thread())

    def _record_history(self, technique_id, footprint, attempts, certified) -> None:
        entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "technique": technique_id,
                 "certified": certified, "iterations": len(attempts),
                 "rule_path": "", "active_rule_unchanged": str(self.auto_rule),
                 "footprint": footprint, "attempts": attempts}
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
            e.status = "running"
            e._evolve = lambda *_args: None
            for tid in ("T1001", "T1002", "T1003"):
                e.activate(tid)
            conc_ok = len(e._active) == _MAX_CONCURRENT        # 3rd refused (concurrency cap)

            e2 = EvolutionEngine(); e2.status = "running"; e2._evolve = lambda *_args: None
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
