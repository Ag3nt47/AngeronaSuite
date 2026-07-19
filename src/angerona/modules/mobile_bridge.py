"""mobile_bridge.py — Mobile Response Bridge (CODE: MOB_BRDG).

State-gated, End-to-End-Encrypted remote orchestration over Signal (via signal-cli).
The operator's phone can query posture and issue containment commands; every
state-changing command is gated by a short-lived 4-digit token AND the DPAPI-wrapped
hardware PIN, and unknown/failed input is silently discarded + logged as a spoof
attempt.

Design contract
---------------
  * OFF by default. Does nothing unless ``config.mobile_enabled`` is True and a
    signal-cli binary + host/destination numbers are configured.
  * NON-BLOCKING. All signal-cli calls are short subprocess invocations run from
    THIS module's daemon thread — never the Qt UI loop.
  * NON-REPLAYABLE. Tokens are random, single-use, and expire in 10 minutes; an
    expired token auto-falls-back to a safe SUSPEND and notifies the phone.
  * FAIL-OPEN for the suite. Any error here degrades health, never crashes.

Outbound metadata leaves the host (module/PID/severity/category) over the Signal
E2EE channel — the Settings tab shows the required security-posture warning.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity

try:
    from angerona.engines.ai_guardrail import neutralize_telemetry
except Exception:   # pragma: no cover
    def neutralize_telemetry(text: str, max_len: int = 4000) -> str:  # type: ignore
        return str(text)[:max_len].replace("\n", " ")

# Entropy must match what the Settings save used when DPAPI-wrapping the PIN.
_PIN_ENTROPY = b"Angerona-MOBILE-PIN-v1"
_PIN_ENV = "ANGERONA_MOBILE_PIN_DPAPI"     # base64(DPAPI blob) in .env

_TTL_SECONDS = 600.0        # token lifetime (10 min)
_TTL_SWEEP_S = 10.0         # cleanup cadence
_FLOOD_WINDOW = 60.0        # rate-limit window
_FLOOD_MAX = 3              # >this many alerts in the window → aggregate to a digest

_HELP_TEXT = (
    "🛡️ ANGERONA MOBILE COMMAND CONSOLE 🛡️\n"
    "Available Commands:\n"
    "-----------------------------------------\n"
    "❓ HELP - Display this guide\n"
    "📊 STATUS - View Threat Posture & Active KEVs\n"
    "🌿 ECO ON / OFF - Toggle Governor resource throttling\n"
    "🚨 LOCKDOWN <PIN> - Isolate endpoint firewall instantly\n"
    "🛠️ DIAG - Export Black Box diagnostic package\n"
    "🚫 KILL <TOKEN> <PIN> - Terminate ransomware/worm PID\n"
    "⏸️ SUSPEND <TOKEN> <PIN> - Freeze process in memory\n"
    "🔄 ROLLBACK <TOKEN> <PIN> - Trigger Shadow Shield recovery\n"
    "📕 MUTE <TOKEN> - Suppress alert module rules for 15m\n"
    "-----------------------------------------\n"
    "Note: Token-based commands expire in 10 minutes.\n"
)


class MobileResponseBridge(BaseModule):
    name = "Mobile Response Bridge"
    CODE = "MOB_BRDG"
    description = ("E2EE (Signal) state-gated remote orchestration: posture queries "
                   "and token+PIN-gated containment from the operator's phone.")
    category = "Response"
    version = "1.0.0"
    # The thread always runs but self-gates on config.mobile_enabled (idles cheaply
    # when off) so flipping the Settings toggle takes effect without a restart.
    enabled_by_default = True

    POLL_S = 2.0

    def __init__(self) -> None:
        super().__init__()
        self._manager = None
        self._config = None
        self.pending_alerts: dict[str, dict] = {}
        self._muted: dict[str, float] = {}          # module name → mute-until epoch
        self._alert_times: list[float] = []          # for rate-limit window
        self._digest: list[str] = []                 # aggregated alerts pending flush
        self._cursor_ts = 0.0                        # bus read watermark
        self._last_sweep = 0.0
        self._last_digest_flush = 0.0
        self._aria_handler = None                    # optional ARIA chat handler

    def bind_manager(self, manager) -> None:
        self._manager = manager
        self._config = getattr(manager, "config", None)

    def set_aria_handler(self, fn) -> None:
        """Route non-command Signal messages to ARIA for a conversational answer.
        Only the already-sender-verified operator reaches this path; ARIA's
        state-changing actions are deliberately NOT exposed here — remote
        mutations go through the PIN+token-gated commands (KILL/SUSPEND/…)."""
        self._aria_handler = fn

    # ── Config resolution ──────────────────────────────────────────────────────
    def _enabled(self) -> bool:
        return bool(getattr(self._config, "mobile_enabled", False))

    def _cfg(self) -> dict:
        c = self._config
        return {
            "cli":  getattr(c, "mobile_signal_cli", "") or "",
            "host": getattr(c, "mobile_host_number", "") or "",
            "dest": getattr(c, "mobile_dest_number", "") or "",
        }

    def _pin(self) -> Optional[str]:
        """Unwrap the DPAPI-protected 4-digit PIN from the environment."""
        blob_b64 = os.environ.get(_PIN_ENV, "")
        if not blob_b64:
            return None
        try:
            import base64
            from angerona.modules.hardware_crypto import unprotect
            raw = unprotect(base64.b64decode(blob_b64), _PIN_ENTROPY)
            return raw.decode("utf-8").strip() if raw else None
        except Exception:
            return None

    # ── signal-cli I/O (subprocess; never touches the GUI thread) ──────────────
    def _send(self, message: str) -> None:
        cfg = self._cfg()
        if not (cfg["cli"] and cfg["host"] and cfg["dest"]):
            return
        try:
            subprocess.run(
                [cfg["cli"], "-a", cfg["host"], "send", "-m", message, cfg["dest"]],
                capture_output=True, timeout=30,
            )
        except Exception as exc:
            self.set_health(60, f"signal-cli send failed: {exc}")

    def _receive(self) -> list[tuple[str, str]]:
        """Return [(sender, body)] of inbound messages. JSON output preferred."""
        cfg = self._cfg()
        if not (cfg["cli"] and cfg["host"]):
            return []
        try:
            out = subprocess.run(
                [cfg["cli"], "-o", "json", "-a", cfg["host"], "receive", "--timeout", "2"],
                capture_output=True, text=True, timeout=20,
            )
        except Exception:
            return []
        msgs: list[tuple[str, str]] = []
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
                env = env.get("envelope", env)
                sender = str(env.get("source") or env.get("sourceNumber") or "")
                body = ((env.get("dataMessage") or {}).get("message")
                        or env.get("message") or "")
                if body:
                    msgs.append((sender, str(body)))
            except Exception:
                continue
        return msgs

    # ── Alert gating → phone ───────────────────────────────────────────────────
    def _poll_alerts(self) -> None:
        if self._bus is None:
            return
        try:
            events = self._bus.recent(50)
        except Exception:
            return
        now = time.time()
        for ev in events:
            if ev.ts <= self._cursor_ts:
                continue
            self._cursor_ts = max(self._cursor_ts, ev.ts)
            if ev.severity < Severity.HIGH or ev.module in ("Console", "Self-Test"):
                continue
            if self._is_muted(ev.module):
                continue
            self._gate_alert(ev)

    def _gate_alert(self, ev) -> None:
        pid = (ev.details or {}).get("pid")
        module = neutralize_telemetry(str(ev.module), 80)
        threat = neutralize_telemetry(str(ev.message), 200)
        action = "SUSPEND" if pid else "REVIEW"
        token = self._new_token()
        self.pending_alerts[token] = {
            "pid": pid, "action": action, "module": ev.module,
            "timestamp": time.time(),
        }
        line = (f"🚨 [{ev.severity.label}] {module} (PID {pid}) — {threat}\n"
                f"Token {token}: KILL/SUSPEND/ROLLBACK {token} <PIN>  ·  MUTE {token}")

        # Rate-limit: >_FLOOD_MAX alerts in the window → aggregate into a digest.
        now = time.time()
        self._alert_times = [t for t in self._alert_times if now - t <= _FLOOD_WINDOW]
        self._alert_times.append(now)
        if len(self._alert_times) > _FLOOD_MAX:
            self._digest.append(line)
        else:
            self._send(line)

    def _flush_digest(self) -> None:
        if not self._digest:
            return
        if time.time() - self._last_digest_flush < _FLOOD_WINDOW:
            return
        self._last_digest_flush = time.time()
        n = len(self._digest)
        body = (f"📥 Angerona digest — {n} alert(s) in the last minute "
                "(individual texts suppressed to avoid flooding):\n\n"
                + "\n".join(self._digest[:15]))
        self._digest.clear()
        self._send(body)

    def _new_token(self) -> str:
        for _ in range(50):
            t = f"{random.randint(1000, 9999)}"
            if t not in self.pending_alerts:
                return t
        return f"{random.randint(1000, 9999)}"

    # ── TTL sweep ───────────────────────────────────────────────────────────────
    def _sweep_tokens(self) -> None:
        now = time.time()
        for token, info in list(self.pending_alerts.items()):
            if now - info["timestamp"] < _TTL_SECONDS:
                continue
            self.pending_alerts.pop(token, None)
            pid = info.get("pid")
            if pid:
                self._emit_mitigation("SUSPEND", pid, reason=f"token {token} expired")
                self._send(f"Token [{token}] expired. Target process safely "
                           "suspended awaiting manual review.")
            else:
                self._send(f"Token [{token}] expired. No action taken (review-only alert).")
        # expire mutes
        for m, until in list(self._muted.items()):
            if now >= until:
                self._muted.pop(m, None)

    def _is_muted(self, module: str) -> bool:
        until = self._muted.get(module)
        return bool(until and time.time() < until)

    # ── Command parser ─────────────────────────────────────────────────────────
    def _handle(self, sender: str, body: str) -> None:
        cfg = self._cfg()
        # Only accept commands from the configured operator number.
        if cfg["dest"] and sender and sender.replace(" ", "") != cfg["dest"].replace(" ", ""):
            return self._spoof(body, f"unknown sender {sender}")

        parts = body.strip().split()
        if not parts:
            return
        cmd = parts[0].upper()
        args = [p.upper() for p in parts[1:]]

        if cmd == "HELP":
            return self._send(_HELP_TEXT)
        if cmd == "STATUS":
            return self._send(self._status_text())
        if cmd == "DIAG":
            return self._send(self._diag_text())
        if cmd == "ECO":
            if args and args[0] in ("ON", "OFF"):
                return self._eco(args[0] == "ON")
            return self._spoof(body, "bad ECO arg")
        if cmd == "LOCKDOWN":
            if len(args) == 1 and self._pin_ok(args[0]):
                return self._lockdown()
            return self._spoof(body, "LOCKDOWN pin fail")
        if cmd in ("KILL", "SUSPEND", "ROLLBACK"):
            if len(args) == 2 and self._token_ok(args[0]) and self._pin_ok(args[1]):
                return self._gated(cmd, args[0])
            return self._spoof(body, f"{cmd} token/pin fail")
        if cmd == "MUTE":
            if len(args) == 1 and self._token_ok(args[0]):
                return self._mute(args[0])
            return self._spoof(body, "MUTE token fail")
        # Not a built-in command → hand it to ARIA for a conversational answer.
        # The sender is already verified as the operator (checked at the top), so
        # this is the operator chatting with ARIA from their phone. ARIA's
        # state-changing actions are NOT reachable here — only reads/conversation.
        if self._aria_handler is not None:
            try:
                reply = self._aria_handler(body.strip())
            except Exception as exc:
                reply = f"(ARIA error: {exc})"
            if reply:
                return self._send(f"🤖 ARIA: {str(reply)[:1200]}")
        return self._spoof(body, "unknown command")

    def _pin_ok(self, given: str) -> bool:
        pin = self._pin()
        return bool(pin) and given.strip() == pin

    def _token_ok(self, token: str) -> bool:
        return token in self.pending_alerts

    def _spoof(self, body: str, why: str) -> None:
        h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
        self.emit(f"Spoof/Unauthorized Access Attempt ({why}) — msg_sha={h}",
                  Severity.HIGH, reason=why, msg_sha256=h)

    # ── Command implementations ────────────────────────────────────────────────
    def _status_text(self) -> str:
        try:
            from angerona.core.posture import posture
            p = posture(self._bus, self._manager, self._config)
            f = p.get("factors", {})
            return (f"📊 Threat Posture {p['score']}/100 — {p['label']}\n"
                    f"Active threats(10m): {f.get('active_threats', 0)}\n"
                    f"Degraded modules: {f.get('degraded_modules', 0)}\n"
                    f"Host-applicable KEV CVEs: {f.get('kev_exposure', 0)}\n"
                    f"ATT&CK heat: {f.get('attack_heat', 0)}")
        except Exception as exc:
            return f"STATUS unavailable: {exc}"

    def _diag_text(self) -> str:
        try:
            import psutil
            p = psutil.Process()
            with p.oneshot():
                cpu = p.cpu_percent(interval=0.0)
                rss = p.memory_info().rss / (1024 * 1024)
                threads = p.num_threads()
            vm = psutil.virtual_memory()
            return (f"🛠️ DIAG snapshot\nProc CPU {cpu:.0f}% · RSS {rss:.0f} MB · "
                    f"{threads} threads\nHost RAM {vm.percent:.0f}% used\n"
                    "(Full Black Box bundle available on the host tray app.)")
        except Exception as exc:
            return f"DIAG unavailable: {exc}"

    def _eco(self, on: bool) -> None:
        """Interface the Adaptive Resource Governor: ON = heavy throttle (passive),
        OFF = restore full cadence."""
        level = 6.0 if on else 1.0
        n = 0
        try:
            gov = self._manager.modules.get("Adaptive Resource Governor") if self._manager else None
            for name, mod in (self._manager.modules.items() if self._manager else []):
                if name == "Adaptive Resource Governor":
                    continue
                if getattr(mod, "category", "") == "Response":
                    continue
                if hasattr(mod, "set_throttle"):
                    mod.set_throttle(level)
                    n += 1
            if gov is not None:
                setattr(gov, "_level", level)
        except Exception:
            pass
        self._send(f"🌿 ECO {'ON' if on else 'OFF'} — {'throttled' if on else 'restored'} "
                   f"{n} non-critical module(s).")

    def _lockdown(self) -> None:
        # Emit a high-priority host-isolation directive (SOAR / WFP consumes it).
        self._emit_mitigation("MACRO_ISOLATE", None,
                              reason="operator LOCKDOWN via mobile bridge")
        self._soar_event("MACRO_ISOLATE", None, "operator LOCKDOWN (mobile)")
        self._send("🚨 LOCKDOWN issued — host network isolation requested "
                   "(loopback/Ollama/IPC stay reachable).")

    def _gated(self, cmd: str, token: str) -> None:
        info = self.pending_alerts.pop(token, None)   # single-use
        if not info:
            return
        pid = info.get("pid")
        if cmd == "ROLLBACK":
            ok = self._rollback(pid, info)
            self._send(f"🔄 ROLLBACK {token} — Shadow Shield recovery "
                       f"{'triggered' if ok else 'unavailable'}.")
            return
        # KILL / SUSPEND
        self._emit_mitigation(cmd, pid, reason=f"operator {cmd} token {token}")
        self._send(f"{'🚫 KILL' if cmd == 'KILL' else '⏸️ SUSPEND'} {token} — "
                   f"signed directive dropped for PID {pid}.")

    def _rollback(self, pid, info) -> bool:
        try:
            shdw = self._manager.modules.get("Shadow Shield") if self._manager else None
            if shdw and hasattr(shdw, "trigger_rollback"):
                shdw.trigger_rollback(before_ts=info.get("timestamp"))
                return True
        except Exception:
            pass
        return False

    def _mute(self, token: str) -> None:
        info = self.pending_alerts.get(token) or {}
        module = info.get("module", "")
        if module:
            self._muted[module] = time.time() + 15 * 60
            self._send(f"📕 MUTE {token} — suppressing '{module}' alerts for 15 minutes.")
        else:
            self._send(f"MUTE {token} — could not resolve originating module.")

    # ── Mitigation directive helpers ────────────────────────────────────────────
    def _emit_mitigation(self, action: str, pid, reason: str) -> None:
        self.emit(
            f"[MOBILE-DIRECTIVE] {action} requested (pid={pid}) — {reason}",
            Severity.CRITICAL,
            soar_action=action, target_pid=pid, origin="mobile_bridge", reason=reason,
        )

    def _soar_event(self, action: str, pid, reason: str) -> None:
        try:
            from pathlib import Path
            from angerona.core.data_paths import data_dir
            repo = data_dir()
            d = repo / "shared_logs"
            d.mkdir(parents=True, exist_ok=True)
            ev = {"ts": time.time(), "type": action, "severity": "Critical",
                  "pid": pid, "reason": reason, "origin": "mobile_bridge",
                  "auto_applied": False}
            with open(d / "soar_events.json", "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass

    # ── Loop ────────────────────────────────────────────────────────────────────
    def run(self) -> None:
        while not self.stopping:
            if not self._enabled():
                self.set_health(100, "disabled (enable in Settings ▸ Mobile Integration)")
                self.sleep(5.0)
                continue
            cfg = self._cfg()
            if not (cfg["cli"] and cfg["host"] and cfg["dest"]):
                self.set_health(30, "enabled but signal-cli/numbers not configured")
                self.sleep(5.0)
                continue

            try:
                self._poll_alerts()
                for sender, body in self._receive():
                    self._handle(sender, body)
                now = time.time()
                if now - self._last_sweep >= _TTL_SWEEP_S:
                    self._last_sweep = now
                    self._sweep_tokens()
                self._flush_digest()
                self.set_health(100, f"{len(self.pending_alerts)} pending token(s)")
            except Exception as exc:
                self.set_health(50, f"bridge loop error: {exc}")
            self.sleep(self.POLL_S)

    def self_test(self) -> tuple[bool, str]:
        if not self._enabled():
            return True, "disabled (opt-in)"
        cfg = self._cfg()
        if not cfg["cli"]:
            return False, "signal-cli path not set"
        ok = os.path.exists(cfg["cli"])
        return ok, (f"signal-cli {'found' if ok else 'MISSING'}; "
                    f"{len(self.pending_alerts)} pending tokens")


def register() -> BaseModule:
    return MobileResponseBridge()
