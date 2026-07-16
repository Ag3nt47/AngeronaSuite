"""self_integrity.py — Runtime Self-Integrity Monitor (Code: SINT).

Part of BL-01 ("terminate / suspend / monkeypatch the agent"). The suspension +
termination halves are already covered by the out-of-process watchdog/supervisor
(a frozen or dead heartbeat is restarted). This module covers the third vector:
**in-memory tampering** — an attacker with code execution at our integrity level
monkeypatching Angerona's own enforcement functions (guardrail, event bus, threat
scoring, the console control path, the heartbeat) so the interpreter keeps running
but no longer actually enforces anything.

How
    At arm time it fingerprints a set of critical callables — module, qualname,
    and a SHA-256 of the function's bytecode (``__code__.co_code``). Every cycle it
    re-resolves each target and compares: a reassigned function (``mod.fn = evil``)
    changes identity/qualname, and an in-place bytecode patch changes the code
    hash. Either is a CRITICAL runtime-tamper signal.

Scope / honesty
    This raises the bar against user-mode monkeypatching; it is NOT kernel
    protection. True tamper-proofing (PPL / anti-malware protected process, kernel
    ETW-TI) needs a signed ELAM/kernel driver, which is out of scope for the
    interpreter. Pure detection — it never modifies another process.

Drop-in: BaseModule subclass + register(). Stdlib only; self-tested.
"""
from __future__ import annotations

import hashlib
import importlib
import time

from angerona.core.module_base import BaseModule, Severity

# "module.path:attr[.subattr]" — the agent's load-bearing enforcement callables.
# Unresolvable targets (renamed/absent) are skipped, so this list is safe to keep
# broad across versions.
_TARGETS = (
    "angerona.engines.ai_guardrail:process_request",   # every model call's guardrail
    "angerona.core.eventbus:EventBus.publish",          # the signed event pipeline
    "angerona.core.threat:threat_level",                # posture/threat scoring
    "angerona.core.commands:CommandConsole.run",        # console control path
    "angerona.resilience.heartbeat:HeartbeatWriter.beat",  # liveness attestation
    "angerona.core.process_allowlist:is_allowed",       # trust decisions
)


def _resolve(spec: str):
    """Resolve 'module:attr.sub' to the live object, or None if unavailable."""
    try:
        mod_path, attr_path = spec.split(":", 1)
        obj = importlib.import_module(mod_path)
        for part in attr_path.split("."):
            obj = getattr(obj, part)
        return obj
    except Exception:
        return None


def _fingerprint(obj) -> str:
    """Stable identity of a callable: module + qualname + bytecode hash. A
    reassignment changes qualname/module; an in-place patch changes the bytecode."""
    fn = getattr(obj, "__func__", obj)          # unwrap bound/staticmethods
    mod = getattr(fn, "__module__", "?")
    qual = getattr(fn, "__qualname__", repr(fn))
    code = getattr(fn, "__code__", None)
    if code is not None:
        digest = hashlib.sha256(bytes(code.co_code)).hexdigest()[:16]
    else:
        digest = "no-code"
    return f"{mod}:{qual}:{digest}"


class SelfIntegrityEngine:
    """Pure engine (no Qt / BaseModule) so it is unit-testable."""

    def __init__(self, targets=_TARGETS) -> None:
        self._targets = tuple(targets)
        self._baseline: dict[str, str] = {}

    def arm(self) -> int:
        self._baseline = {}
        for spec in self._targets:
            obj = _resolve(spec)
            if obj is not None:
                self._baseline[spec] = _fingerprint(obj)
        return len(self._baseline)

    def check(self) -> list[str]:
        """Return human-readable descriptions of any tampered targets."""
        tampered: list[str] = []
        for spec, base in self._baseline.items():
            obj = _resolve(spec)
            if obj is None:
                tampered.append(f"{spec} — enforcement target vanished (unloaded/replaced)")
                continue
            now = _fingerprint(obj)
            if now != base:
                tampered.append(f"{spec} — code changed at runtime (was {base}, now {now})")
        return tampered

    def self_test(self) -> "tuple[bool, str]":
        try:
            import angerona.core.threat as _t
            eng = SelfIntegrityEngine(("angerona.core.threat:threat_level",))
            armed = eng.arm()
            assert armed == 1 and eng.check() == [], "clean baseline, no tamper"
            original = _t.threat_level
            try:
                _t.threat_level = lambda *a, **k: None    # monkeypatch the enforcement fn
                hits = eng.check()
            finally:
                _t.threat_level = original                # restore
            assert hits and "threat_level" in hits[0], "monkeypatch detected"
            assert eng.check() == [], "restore clears the alert"
            return True, ("runtime tamper detection verified — clean baseline is silent, a "
                          "monkeypatched enforcement function is flagged, restore clears it.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


class SelfIntegrityMonitor(BaseModule):
    name = "Self-Integrity Monitor"
    CODE = "SINT"
    description = ("Detects in-memory tampering (monkeypatching) of Angerona's own "
                   "enforcement functions — the third BL-01 vector after terminate/suspend.")
    category = "Integrity"
    version = "1.0.0"
    enabled_by_default = True

    _INTERVAL = 15.0

    def __init__(self) -> None:
        super().__init__()
        self._engine = SelfIntegrityEngine()
        self._alerted: set[str] = set()

    def run(self) -> None:
        armed = self._engine.arm()
        self.emit(f"Self-integrity baseline armed — watching {armed} enforcement "
                  "function(s) for runtime tampering.", Severity.INFO, watched=armed)
        self.set_health(100, f"{armed} targets baselined")
        while not self.stopping:
            self.sleep(self._INTERVAL)
            if self.stopping:
                break
            try:
                tampered = self._engine.check()
            except Exception as exc:
                self.set_health(60, f"check error: {exc}")
                continue
            for desc in tampered:
                if desc in self._alerted:
                    continue          # one CRITICAL per distinct tamper, not a storm
                self._alerted.add(desc)
                self.emit(f"🚨 RUNTIME TAMPER: {desc}. An enforcement function was "
                          "modified in memory — possible agent monkeypatching (T1562).",
                          Severity.CRITICAL, target=desc.split(" ")[0], tamper=True,
                          mitre_tags=["T1562", "T1055"])
            if tampered:
                self.set_health(10, f"{len(tampered)} enforcement function(s) tampered")
            elif not self._alerted:
                self.set_health(100, "enforcement core intact")

    def self_test(self) -> "tuple[bool, str]":
        return self._engine.self_test()


def register() -> SelfIntegrityMonitor:
    return SelfIntegrityMonitor()


if __name__ == "__main__":
    ok, detail = SelfIntegrityEngine().self_test()
    print(f"[self_integrity] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
