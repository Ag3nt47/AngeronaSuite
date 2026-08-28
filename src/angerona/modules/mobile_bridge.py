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
    expired token is audit-only and notifies the phone without authorizing action.
  * FAIL-OPEN for the suite. Any error here degrades health, never crashes.

Outbound metadata leaves the host (module/PID/severity/category) over the Signal
E2EE channel — the Settings tab shows the required security-posture warning.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time
from typing import Optional

from angerona.core.eventbus import Event, is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity

try:
    import psutil
except Exception:  # pragma: no cover - commands fail closed without identity data
    psutil = None

try:
    from angerona.engines.ai_guardrail import neutralize_telemetry
except Exception:   # pragma: no cover
    def neutralize_telemetry(text: str, max_len: int = 4000) -> str:  # type: ignore
        return str(text)[:max_len].replace("\n", " ")

# Entropy must match what the Settings save used when DPAPI-wrapping the PIN.
_PIN_ENTROPY = b"Angerona-MOBILE-PIN-v1"
_PIN_ENV = "ANGERONA_MOBILE_PIN_DPAPI"     # legacy base64(DPAPI blob) from OS store
_PORTABLE_PIN_ENV = "ANGERONA_MOBILE_PIN"  # delivered by the protected OS store

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
    "🚨 LOCKDOWN <PIN> - Request receipt-verified Combat host isolation\n"
    "🛠️ DIAG - Export Black Box diagnostic package\n"
    "🚫 KILL <TOKEN> <PIN> - Terminate an exact bound process instance\n"
    "⏸️ SUSPEND <TOKEN> <PIN> - Suspend an exact bound process instance\n"
    "🔄 ROLLBACK <TOKEN> <PIN> - Restore one exact Shadow Shield version\n"
    "📕 MUTE <TOKEN> - Suppress alert module rules for 15m\n"
    "-----------------------------------------\n"
    "Note: Token-based commands expire in 10 minutes.\n"
)


def _signal_identity(value: object) -> str:
    """Canonicalize the configured phone identity or fail closed.

    The end-user setup contract accepts an international phone number. Signal's
    JSON envelope may add spaces, dashes, or parentheses; no missing/ambiguous
    sender identity is ever treated as the configured operator.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    compact = re.sub(r"[\s().-]+", "", text)
    if not re.fullmatch(r"\+[1-9][0-9]{6,14}", compact):
        return ""
    return compact


class MobileResponseBridge(BaseModule):
    name = "Mobile Response Bridge"
    CODE = "MOB_BRDG"
    description = ("E2EE (Signal) state-gated remote orchestration: posture queries "
                   "and token+PIN-gated containment from the operator's phone.")
    category = "Response"
    version = "1.1.0"
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
        # A digest renders only its first 15 samples. Keep those plus a scalar
        # total instead of retaining every full alert line during a flood.
        self._digest: list[str] = []
        self._digest_count = 0
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
        """Read a four-digit PIN delivered by the protected OS credential store.

        The legacy nested-DPAPI value remains readable for existing Windows
        installations. Linux Secret Service and macOS Keychain use the canonical
        value so the mobile gate has the same semantics on every platform.
        """
        portable = os.environ.get(_PORTABLE_PIN_ENV, "").strip()
        if re.fullmatch(r"[0-9]{4}", portable):
            return portable
        blob_b64 = os.environ.get(_PIN_ENV, "")
        if not blob_b64:
            return None
        try:
            import base64
            from angerona.modules.hardware_crypto import unprotect
            raw = unprotect(base64.b64decode(blob_b64), _PIN_ENTROPY)
            value = raw.decode("utf-8").strip() if raw else ""
            return value if re.fullmatch(r"[0-9]{4}", value) else None
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
            events, _overflow = self.poll_bus_events(priority=True)
        except Exception:
            return
        now = time.time()
        for ev in events:
            if ev.severity < Severity.HIGH or ev.module in ("Console", "Self-Test"):
                continue
            if self._is_muted(ev.module):
                continue
            self._gate_alert(ev)

    def _gate_alert(self, ev) -> None:
        details = ev.details if isinstance(ev.details, dict) else {}
        pid = details.get("pid")
        module = neutralize_telemetry(str(ev.module), 80)
        threat = neutralize_telemetry(str(ev.message), 200)
        process_target = self._bind_process_target(pid, details)
        rollback_artifact = self._prepare_rollback_artifact(ev)
        response_eligible = (
            not is_remote_observe_only(ev)
            and self._bus is not None
            and getattr(self._bus, "integrity_enabled", False)
        )
        if response_eligible:
            try:
                response_eligible = bool(self._bus.verify(ev))
            except Exception:
                response_eligible = False
        action = "RESPOND" if response_eligible and (process_target or rollback_artifact) else "REVIEW"
        token = self._new_token()
        self.pending_alerts[token] = {
            "pid": process_target.get("pid") if process_target else None,
            "process_create_time": (
                process_target.get("process_create_time") if process_target else None
            ),
            "exe": process_target.get("exe") if process_target else None,
            "process_name": process_target.get("name") if process_target else None,
            "rollback_artifact": rollback_artifact,
            "response_eligible": response_eligible,
            "source_event_hmac": str(getattr(ev, "hmac_sig", "") or ""),
            "action": action,
            "module": ev.module,
            "timestamp": time.time(),
        }
        commands = []
        if response_eligible and process_target:
            commands.extend(("KILL", "SUSPEND"))
        if response_eligible and rollback_artifact:
            commands.append("ROLLBACK")
        command_text = (
            "/".join(commands) + f" {token} <PIN>"
            if commands
            else "REVIEW ONLY — no exact response target"
        )
        line = (f"🚨 [{ev.severity.label}] {module} (PID {pid}) — {threat}\n"
                f"Token {token}: {command_text}  ·  MUTE {token}")

        # Rate-limit: >_FLOOD_MAX alerts in the window → aggregate into a digest.
        now = time.time()
        self._alert_times = [t for t in self._alert_times if now - t <= _FLOOD_WINDOW]
        self._alert_times.append(now)
        if len(self._alert_times) > _FLOOD_MAX:
            self._digest_count += 1
            if len(self._digest) < 15:
                self._digest.append(line)
        else:
            self._send(line)

    def _flush_digest(self) -> None:
        if not self._digest:
            return
        if time.time() - self._last_digest_flush < _FLOOD_WINDOW:
            return
        self._last_digest_flush = time.time()
        n = self._digest_count
        body = (f"📥 Angerona digest — {n} alert(s) in the last minute "
                "(individual texts suppressed to avoid flooding):\n\n"
                + "\n".join(self._digest))
        self._digest.clear()
        self._digest_count = 0
        self._send(body)

    def _new_token(self) -> str:
        for _ in range(50):
            t = str(secrets.randbelow(9000) + 1000)
            if t not in self.pending_alerts:
                return t
        return str(secrets.randbelow(9000) + 1000)

    # ── TTL sweep ───────────────────────────────────────────────────────────────
    def _sweep_tokens(self) -> None:
        now = time.time()
        for token, info in list(self.pending_alerts.items()):
            if now - info["timestamp"] < _TTL_SECONDS:
                continue
            self.pending_alerts.pop(token, None)
            pid = info.get("pid")
            if pid:
                self._emit_mitigation(
                    "SUSPEND",
                    pid,
                    reason=f"token {token} expired",
                    directive_authorized=False,
                    event_type="mobile_token_expiry",
                )
                self._send(
                    f"Token [{token}] expired. No action taken; request a fresh "
                    "alert token before responding."
                )
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
        # Only accept commands from an explicit, unambiguous configured operator
        # identity. Missing sender metadata must never inherit operator authority.
        expected_sender = _signal_identity(cfg["dest"])
        actual_sender = _signal_identity(sender)
        if (
            not expected_sender
            or not actual_sender
            or not hmac.compare_digest(actual_sender, expected_sender)
        ):
            return self._spoof(body, "missing or unauthorized sender identity")

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
        return bool(pin) and hmac.compare_digest(given.strip(), pin)

    def _token_ok(self, token: str) -> bool:
        return token in self.pending_alerts

    def _spoof(self, body: str, why: str) -> None:
        h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
        self.emit(
            f"Spoof/Unauthorized Access Attempt ({why}) — msg_sha={h}",
            Severity.HIGH,
            reason=why,
            msg_sha256=h,
            disposition="health",
            event_type="mobile_auth_failure",
            response_authorized=False,
            audit_only=True,
        )

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

    @staticmethod
    def _bind_process_target(pid, details: dict) -> dict | None:
        """Capture one live PID/create-time/executable identity or fail closed."""
        if not isinstance(pid, int) or pid <= 0 or psutil is None:
            return None
        try:
            process = psutil.Process(pid)
            created = float(process.create_time())
            exe = os.path.normcase(os.path.realpath(str(process.exe() or "")))
            name = str(process.name() or "")
            if not exe:
                return None
            supplied_created = details.get("process_create_time")
            if supplied_created is not None and abs(float(supplied_created) - created) > 0.001:
                return None
            supplied_exe = details.get("exe") or details.get("process_path") or details.get("image")
            if supplied_exe:
                expected_exe = os.path.normcase(os.path.realpath(str(supplied_exe)))
                if expected_exe != exe:
                    return None
            if abs(float(process.create_time()) - created) > 0.001:
                return None
        except Exception:
            return None
        return {
            "pid": pid,
            "process_create_time": created,
            "exe": exe,
            "name": name,
        }

    def _prepare_rollback_artifact(self, ev) -> dict | None:
        if is_remote_observe_only(ev):
            return None
        details = ev.details if isinstance(ev.details, dict) else {}
        raw_path = details.get("path") or details.get("artifact_path")
        if not isinstance(raw_path, str) or not raw_path:
            return None
        try:
            shadow = (
                getattr(self._manager, "modules", {}).get("Shadow Shield")
                if self._manager is not None
                else None
            )
            prepare = getattr(shadow, "prepare_rollback_artifact", None)
            if not callable(prepare):
                return None
            artifact = prepare(raw_path, before_ts=float(ev.ts))
            return dict(artifact) if isinstance(artifact, dict) else None
        except Exception:
            return None

    def _combat_consumer(self):
        try:
            combat = (
                getattr(self._manager, "modules", {}).get("Adversary Combat")
                if self._manager is not None
                else None
            )
        except Exception:
            combat = None
        if combat is None or getattr(combat, "status", "stopped") != "running":
            return None
        if not callable(getattr(combat, "list_actions", None)):
            return None
        return combat

    def _source_event_valid(self, info: dict) -> bool:
        """Rebind a mobile token to its still-live authenticated source alert."""
        source_hmac = str(info.get("source_event_hmac") or "")
        if (
            self._bus is None
            or not getattr(self._bus, "integrity_enabled", False)
            or not re.fullmatch(r"[0-9a-f]{64}", source_hmac)
        ):
            return False
        try:
            events = self._bus.recent(500)
        except Exception:
            return False
        for event in events:
            if not hmac.compare_digest(str(event.hmac_sig or ""), source_hmac):
                continue
            try:
                if not self._bus.verify(event) or is_remote_observe_only(event):
                    return False
            except Exception:
                return False
            details = event.details if isinstance(event.details, dict) else {}
            return details.get("pid") == info.get("pid")
        return False

    @staticmethod
    def _receipt_ids(combat, *, trigger_ts: float, expected_action: str) -> set[str]:
        found: set[str] = set()
        try:
            rows = combat.list_actions(limit=250)
        except Exception:
            return found
        for row in rows:
            try:
                same_ts = abs(float(row.get("trigger_ts")) - trigger_ts) < 0.000001
            except (TypeError, ValueError, OverflowError):
                same_ts = False
            if (
                same_ts
                and row.get("trigger_module") == "Mobile Response Bridge"
                and row.get("action") == expected_action
                and row.get("status") == "applied"
                and row.get("integrity_status") == "verified"
                and row.get("details", {}).get("postcondition_verified") is True
            ):
                action_id = str(row.get("action_id") or "")
                if action_id:
                    found.add(action_id)
        return found

    def _execute_combat(self, cmd: str, info: dict) -> tuple[bool, str]:
        """Publish one authenticated exact contract and await its Combat receipt."""
        combat = self._combat_consumer()
        if combat is None:
            return False, "authenticated Combat consumer unavailable"
        if self._bus is None or not getattr(self._bus, "integrity_enabled", False):
            return False, "EventBus response authentication is unavailable"

        if cmd == "LOCKDOWN":
            try:
                policy = combat.policy()
            except Exception:
                return False, "Combat policy unavailable"
            if not policy.isolate_host or policy.mode != "maximum":
                return False, "Combat policy does not authorize host isolation"
            expected_action = "isolate_host"
            details = {
                "active_attack": True,
                "operator_authenticated": True,
                "response_authorized": True,
                "response_contract": {
                    "version": 1,
                    "actions": [expected_action],
                    "targets": {"host": "local"},
                },
            }
        else:
            if info.get("response_eligible") is not True:
                return False, "alert is not eligible for local response"
            if not self._source_event_valid(info):
                return False, "source alert authentication expired or changed"
            bound = self._bind_process_target(info.get("pid"), info)
            if bound is None:
                return False, "process identity changed or PID was reused"
            try:
                policy = combat.policy()
            except Exception:
                return False, "Combat policy unavailable"
            if cmd == "KILL":
                if policy.process_action != "terminate" or policy.mode == "contain":
                    return False, "Combat policy does not authorize termination"
                expected_action = "terminate_process"
            elif cmd == "SUSPEND":
                if policy.process_action != "suspend" and policy.mode != "contain":
                    return False, "Combat policy does not authorize suspension"
                expected_action = "suspend_process"
            else:
                return False, "unsupported mobile response command"
            details = {
                "pid": bound["pid"],
                "process_create_time": bound["process_create_time"],
                "exe": bound["exe"],
                "operator_authenticated": True,
                "source_event_hmac": str(info.get("source_event_hmac") or ""),
                "response_authorized": True,
                "response_contract": {
                    "version": 1,
                    "actions": [expected_action],
                    "targets": {
                        "pid": bound["pid"],
                        "process_create_time": bound["process_create_time"],
                    },
                },
            }

        trigger_ts = time.time()
        before = self._receipt_ids(
            combat, trigger_ts=trigger_ts, expected_action=expected_action
        )
        try:
            self._bus.publish(Event(
                self.name,
                f"Authenticated mobile {cmd} request for exact local target.",
                Severity.CRITICAL,
                trigger_ts,
                details,
            ))
        except Exception as exc:
            return False, f"directive publication failed ({exc})"

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            current = self._receipt_ids(
                combat, trigger_ts=trigger_ts, expected_action=expected_action
            )
            created = current - before
            if created:
                return True, sorted(created)[0]
            time.sleep(0.05)
        return False, "no verified Combat completion receipt"

    def _lockdown(self) -> None:
        ok, receipt = self._execute_combat("LOCKDOWN", {})
        if ok:
            self._soar_event(
                "MACRO_ISOLATE", None, "operator LOCKDOWN (mobile)",
                applied=True, receipt_id=receipt,
            )
            self._send(
                f"🚨 LOCKDOWN applied and postcondition-verified "
                f"(Combat receipt {receipt})."
            )
        else:
            self._soar_event(
                "MACRO_ISOLATE", None, "operator LOCKDOWN rejected",
                applied=False, error=receipt,
            )
            self._send(f"🚨 LOCKDOWN rejected — no host action: {receipt}.")

    def _gated(self, cmd: str, token: str) -> None:
        info = self.pending_alerts.pop(token, None)   # single-use
        if not info:
            return
        pid = info.get("pid")
        if cmd == "ROLLBACK":
            ok, result = self._rollback(info)
            if ok:
                self._send(
                    f"🔄 ROLLBACK {token} — one exact Shadow Shield version "
                    f"restored ({result})."
                )
            else:
                self._send(f"🔄 ROLLBACK {token} rejected — no file restored: {result}.")
            return
        # KILL / SUSPEND
        ok, result = self._execute_combat(cmd, info)
        label = "🚫 KILL" if cmd == "KILL" else "⏸️ SUSPEND"
        if ok:
            self._soar_event(
                cmd, pid, f"operator {cmd} token {token}",
                applied=True, receipt_id=result,
            )
            self._send(
                f"{label} {token} — applied and postcondition-verified "
                f"(Combat receipt {result})."
            )
        else:
            self._soar_event(
                cmd, pid, f"operator {cmd} rejected",
                applied=False, error=result,
            )
            self._send(f"{label} {token} rejected — no process action: {result}.")

    def _rollback(self, info: dict) -> tuple[bool, str]:
        if info.get("response_eligible") is not True:
            return False, "alert is not eligible for local rollback"
        if not self._source_event_valid(info):
            return False, "source alert authentication expired or changed"
        artifact = info.get("rollback_artifact")
        if not isinstance(artifact, dict):
            return False, "token has no exact authorized rollback artifact"
        try:
            shdw = self._manager.modules.get("Shadow Shield") if self._manager else None
            restore = getattr(shdw, "restore_rollback_artifact", None)
            if not callable(restore):
                return False, "scoped Shadow Shield consumer unavailable"
            result = restore(dict(artifact))
        except Exception as exc:
            return False, f"scoped Shadow Shield failure ({exc})"
        restored = result.get("restored") if isinstance(result, dict) else None
        failed = result.get("failed") if isinstance(result, dict) else None
        expected = str(artifact.get("source_path") or "")
        if restored == [expected] and not failed:
            return True, str(artifact.get("artifact_id") or "")
        return False, "exact artifact postcondition was not verified"

    def _mute(self, token: str) -> None:
        info = self.pending_alerts.get(token) or {}
        module = info.get("module", "")
        if module:
            self._muted[module] = time.time() + 15 * 60
            self._send(f"📕 MUTE {token} — suppressing '{module}' alerts for 15 minutes.")
        else:
            self._send(f"MUTE {token} — could not resolve originating module.")

    # ── Mitigation directive helpers ────────────────────────────────────────────
    def _emit_mitigation(
        self,
        action: str,
        pid,
        reason: str,
        *,
        directive_authorized: bool,
        event_type: str = "mobile_response_directive",
    ) -> None:
        # This bus record is an audit/directive envelope, not detector evidence.
        # Its authority is deliberately scoped to an exact directive consumer;
        # generic response tiers must not turn KILL/SUSPEND into host isolation.
        self.emit(
            f"[MOBILE-DIRECTIVE] {action} requested (pid={pid}) — {reason}",
            Severity.CRITICAL,
            soar_action=action,
            target_pid=pid,
            origin="mobile_bridge",
            reason=reason,
            disposition="health" if not directive_authorized else "directive",
            event_type=event_type,
            response_authorized=False,
            directive_authorized=directive_authorized,
            response_scope="mobile-directive-only",
        )

    def _soar_event(
        self,
        action: str,
        pid,
        reason: str,
        *,
        applied: bool = False,
        receipt_id: str = "",
        error: str = "",
    ) -> None:
        try:
            from pathlib import Path
            from angerona.core.data_paths import data_dir
            repo = data_dir()
            d = repo / "shared_logs"
            d.mkdir(parents=True, exist_ok=True)
            ev = {"ts": time.time(), "type": action, "severity": "Critical",
                  "pid": pid, "reason": reason, "origin": "mobile_bridge",
                  "auto_applied": bool(applied), "receipt_id": receipt_id,
                  "error": error[:500]}
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
