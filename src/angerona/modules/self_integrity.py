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
    the complete marshalled code object, defaults, and closure values. Every
    cycle it re-resolves each target and compares. Reassignment, constants-only
    patches, referenced-name changes, and modified defaults/closures all produce
    a CRITICAL runtime-tamper signal.

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
import marshal
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Mapping

from angerona.core.module_base import BaseModule, Severity

# ── Privilege / ACL audit ─────────────────────────────────────────────────────
# The whole authenticated-command model (signed stand-down/restart, the bus HMAC)
# assumes only Administrators/SYSTEM can read or write Angerona's state directory.
# If a broad principal (Everyone / BUILTIN\Users / Authenticated Users) has write
# there — common when the app lives on a custom drive like D:\ that inherited loose
# ACLs — a NON-admin can read bus.key to forge signed commands (kill the EDR), or
# drop a settings.json to redirect the AI host / push URL. Running elevated on top
# of a world-writable state dir is the escalation combo we flag here.
_BROAD_PRINCIPALS = ("everyone", "\\users", "authenticated users", "builtin\\users",
                     "interactive", "\\everyone")
_WRITE_RIGHTS = ("(F)", "(M)", "(W)", "(WD)", "(RX,W)", "(GW)")


def _is_elevated() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_icacls_weaknesses(icacls_output: str) -> list[str]:
    """Lines granting a broad principal write-class rights on the state dir."""
    hits: list[str] = []
    for line in (icacls_output or "").splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        if any(p in low for p in _BROAD_PRINCIPALS) and any(r in s for r in _WRITE_RIGHTS):
            hits.append(s)
    return hits


def audit_state_dir_status() -> dict[str, object]:
    """Collect state-directory ACL evidence without conflating failure and clean."""
    result: dict[str, object] = {
        "status": "collection-failed",
        "findings": [],
        "path": "",
        "reason": "ACL collection did not complete",
    }
    if not sys.platform.startswith("win"):
        result.update(status="not-applicable", reason="Windows ACLs not applicable")
        return result
    data_dir = None
    for getter in ("angerona.core.config._data_dir", "angerona.core.data_paths.data_dir"):
        try:
            mod_path, fn = getter.rsplit(".", 1)
            data_dir = str(getattr(importlib.import_module(mod_path), fn)())
            break
        except Exception:
            continue
    if not data_dir or not os.path.isdir(data_dir):
        result["reason"] = "state directory is unresolved or unavailable"
        return result
    result["path"] = data_dir
    try:
        from angerona.core.privilege import trusted_windows_directories

        _windows, system = trusted_windows_directories()
        executable = system / "icacls.exe"
        if not executable.is_file():
            result["reason"] = "trusted System32 icacls.exe is unavailable"
            return result
        completed = subprocess.run(
            [str(executable), data_dir],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=0x08000000,
            check=False,
        )
        out = completed.stdout
        if completed.returncode != 0 or not out.strip():
            result["reason"] = (
                f"icacls collection failed with exit {completed.returncode}"
            )
            return result
    except Exception as exc:
        result["reason"] = f"ACL collection failed: {exc}"
        return result
    weak = parse_icacls_weaknesses(out)
    if weak:
        prefix = "Angerona is ELEVATED but its" if _is_elevated() else "Angerona's"
        finding = (
            f"{prefix} state directory ({data_dir}) is writable by a broad principal — a "
            "standard user could read bus.key to FORGE signed stand-down/restart commands "
            "(kill the EDR), or inject settings.json to redirect the AI host / exfil URL. "
            "Lock it down: icacls \"" + data_dir + "\" /inheritance:r /grant:r "
            "Administrators:(OI)(CI)F SYSTEM:(OI)(CI)F  [" + "; ".join(weak[:2]) + "]")
        result.update(status="weak", findings=[finding], reason="broad write ACL detected")
        return result
    result.update(status="ok", reason="ACL collection complete; no broad writer found")
    return result


def audit_state_dir() -> list[str]:
    """Compatibility wrapper returning only confirmed ACL weaknesses."""
    return list(audit_state_dir_status()["findings"])

# "module.path:attr[.subattr]" — the agent's load-bearing enforcement callables.
# Every listed target and dependency is mandatory. Missing coverage is a health
# failure, never a reason to silently shrink the watched set.
_TARGETS = (
    "angerona.engines.ai_guardrail:process_request",   # every model call's guardrail
    "angerona.core.eventbus:EventBus.publish",          # the signed event pipeline
    "angerona.core.threat:threat_level",                # posture/threat scoring
    "angerona.core.commands:CommandConsole.run",        # console control path
    "angerona.resilience.heartbeat:HeartbeatWriter.beat",  # liveness attestation
    "angerona.core.process_allowlist:is_allowed",       # trust decisions
)

_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "angerona.engines.ai_guardrail:process_request": (
        "angerona.engines.ai_guardrail:scan_input",
        "angerona.engines.ai_guardrail:wrap_system",
        "angerona.engines.ai_guardrail:effective_keep_alive",
    ),
    "angerona.core.eventbus:EventBus.publish": (
        "angerona.core.eventbus:BusAuthority.sign",
    ),
    "angerona.core.threat:threat_level": (
        "angerona.core.threat:active_threat_events",
        "angerona.core.threat:is_active_threat",
    ),
    "angerona.core.commands:CommandConsole.run": (
        "angerona.core.commands:CommandConsole.__init__",
        "angerona.core.commands:CommandConsole._ai",
    ),
    "angerona.resilience.heartbeat:HeartbeatWriter.beat": (
        "angerona.resilience.heartbeat:proof_for",
    ),
    "angerona.core.process_allowlist:is_allowed": (
        "angerona.core.process_allowlist:_normal_name",
        "angerona.core.process_allowlist:_normal_path",
        "angerona.core.process_allowlist:policy_snapshot",
        "angerona.core.process_allowlist:executable_sha256",
    ),
}


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


def _source_evidence(obj) -> dict[str, object] | None:
    """Return exact source path/line and a digest of its containing file."""
    fn = getattr(obj, "__func__", obj)
    code = getattr(fn, "__code__", None)
    if code is None:
        return None
    try:
        source = Path(code.co_filename).resolve(strict=True)
        body = source.read_bytes()
    except (OSError, RuntimeError):
        return None
    return {
        "source_file": str(source),
        "source_line": max(1, int(code.co_firstlineno)),
        "file_sha256": hashlib.sha256(body).hexdigest(),
    }


def _integrity_bytes(value, *, depth: int = 0) -> bytes:
    """Return a bounded, deterministic representation for callable metadata.

    ``marshal`` is deliberately used for Python code objects because ``co_code``
    alone omits constants, referenced global names, exception tables, and other
    execution-relevant fields.  Defaults and closure cells are included too so
    changing a policy function without changing its bytecode still trips the
    monitor.  This is a local hash input only; values are never persisted or
    emitted.
    """
    if depth >= 6:
        return b"<depth-limit>"
    if value is None or isinstance(value, (bool, int, float, complex, str, bytes)):
        try:
            return marshal.dumps(value)[:65536]
        except (TypeError, ValueError):
            pass
    if isinstance(value, tuple):
        return b"(" + b"|".join(
            _integrity_bytes(item, depth=depth + 1) for item in value[:128]
        ) + b")"
    if isinstance(value, list):
        return b"[" + b"|".join(
            _integrity_bytes(item, depth=depth + 1) for item in value[:128]
        ) + b"]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value, key=lambda item: (type(item).__name__, repr(item)))[:128]:
            items.append(
                _integrity_bytes(key, depth=depth + 1)
                + b"="
                + _integrity_bytes(value[key], depth=depth + 1)
            )
        return b"{" + b"|".join(items) + b"}"
    if isinstance(value, (set, frozenset)):
        items = sorted(_integrity_bytes(item, depth=depth + 1) for item in value)
        return b"<set>" + b"|".join(items[:128])
    code = getattr(value, "__code__", None)
    if code is not None:
        try:
            return b"<code>" + marshal.dumps(code)[:262144]
        except (TypeError, ValueError):
            pass
    type_id = f"{type(value).__module__}.{type(value).__qualname__}".encode(
        "utf-8", "backslashreplace"
    )
    try:
        rendered = repr(value).encode("utf-8", "backslashreplace")[:4096]
    except Exception:
        rendered = f"<id:{id(value)}>".encode("ascii")
    return type_id + b":" + rendered


def _fingerprint(obj) -> str:
    """Stable identity of a callable including all executable code metadata."""
    fn = getattr(obj, "__func__", obj)          # unwrap bound/staticmethods
    mod = getattr(fn, "__module__", "?")
    qual = getattr(fn, "__qualname__", repr(fn))
    code = getattr(fn, "__code__", None)
    if code is not None:
        hasher = hashlib.sha256()
        hasher.update(marshal.dumps(code))
        hasher.update(_integrity_bytes(getattr(fn, "__defaults__", None)))
        hasher.update(_integrity_bytes(getattr(fn, "__kwdefaults__", None)))
        closure = getattr(fn, "__closure__", None) or ()
        for cell in closure[:128]:
            try:
                value = cell.cell_contents
            except ValueError:
                value = "<empty-cell>"
            hasher.update(_integrity_bytes(value))
        digest = hasher.hexdigest()[:24]
    else:
        digest = "no-code"
    return f"{mod}:{qual}:{digest}"


class SelfIntegrityEngine:
    """Pure engine (no Qt / BaseModule) so it is unit-testable."""

    def __init__(
        self,
        targets=_TARGETS,
        *,
        approved_manifest: Mapping[str, Mapping[str, object]] | None = None,
        dependencies: Mapping[str, tuple[str, ...]] | None = None,
    ) -> None:
        primary = tuple(targets)
        dependency_map = (
            _DEPENDENCIES if dependencies is None and primary == _TARGETS
            else (dependencies or {})
        )
        closure: list[str] = []
        for spec in primary:
            for member in (spec, *dependency_map.get(spec, ())):
                if member not in closure:
                    closure.append(member)
        self._primary_targets = primary
        self._targets = tuple(closure)
        self._approved_manifest = (
            {str(key): dict(value) for key, value in approved_manifest.items()}
            if approved_manifest is not None else None
        )
        self._baseline: dict[str, dict[str, object]] = {}
        self._unresolved: dict[str, str] = {}
        self._manifest_status = "not-checked"

    @property
    def expected_count(self) -> int:
        return len(self._targets)

    @property
    def watched_count(self) -> int:
        return len(self._baseline)

    @property
    def unresolved(self) -> dict[str, str]:
        return dict(self._unresolved)

    @property
    def manifest_status(self) -> str:
        return self._manifest_status

    def evidence(self, spec: str) -> dict[str, object]:
        return dict(self._baseline.get(spec, {}))

    def arm(self) -> int:
        self._baseline = {}
        self._unresolved = {}
        for spec in self._targets:
            obj = _resolve(spec)
            if obj is None:
                self._unresolved[spec] = "mandatory enforcement target is unresolved"
                continue
            source = _source_evidence(obj)
            if source is None:
                self._unresolved[spec] = "source file/line evidence is unavailable"
                continue
            self._baseline[spec] = {
                "fingerprint": _fingerprint(obj),
                **source,
            }
        if self._approved_manifest is None:
            self._manifest_status = "tofu-unapproved"
        elif set(self._approved_manifest) != set(self._targets):
            self._manifest_status = "invalid-coverage"
        else:
            self._manifest_status = "verified"
            for spec, live in self._baseline.items():
                approved = self._approved_manifest.get(spec, {})
                if (
                    set(approved) != {"fingerprint", "file_sha256"}
                    or approved.get("fingerprint") != live["fingerprint"]
                    or approved.get("file_sha256") != live["file_sha256"]
                ):
                    self._manifest_status = "mismatch"
                    break
            if self._unresolved:
                self._manifest_status = "invalid-coverage"
        return len(self._baseline)

    def check(self) -> list[str]:
        """Return human-readable descriptions of any tampered targets."""
        tampered: list[str] = []
        for spec in self._targets:
            base = self._baseline.get(spec)
            if base is None:
                reason = self._unresolved.get(spec, "target was absent from baseline")
                tampered.append(f"{spec} — mandatory coverage unavailable: {reason}")
                continue
            obj = _resolve(spec)
            if obj is None:
                tampered.append(f"{spec} — enforcement target vanished (unloaded/replaced)")
                continue
            source = _source_evidence(obj)
            location = f"{base['source_file']}:{base['source_line']}"
            if source is None:
                tampered.append(f"{spec} — source evidence vanished [{location}]")
                continue
            now = _fingerprint(obj)
            if now != base["fingerprint"]:
                tampered.append(
                    f"{spec} — code changed at runtime [{source['source_file']}:"
                    f"{source['source_line']}; expected {base['source_file']}:"
                    f"{base['source_line']}] (was {base['fingerprint']}, now {now})"
                )
            elif source["file_sha256"] != base["file_sha256"]:
                tampered.append(
                    f"{spec} — containing source file changed [{source['source_file']}:"
                    f"{source['source_line']}]"
                )
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
                   "enforcement functions with mandatory dependency/source coverage and "
                   "an explicitly approved baseline boundary.")
    category = "Integrity"
    version = "1.12.1"
    enabled_by_default = True

    _INTERVAL = 15.0

    def __init__(self) -> None:
        super().__init__()
        self._engine = SelfIntegrityEngine()
        self._alerted: set[str] = set()
        self._acl_alerted: set[str] = set()

    @staticmethod
    def _collect_acl_assurance() -> dict[str, object]:
        """Recollect and normalize ACL evidence; collector failure is non-green."""
        try:
            observed = audit_state_dir_status()
        except Exception as exc:
            return {
                "status": "collection-failed",
                "findings": [],
                "path": "",
                "reason": f"ACL collector raised {type(exc).__name__}: {exc}",
            }
        if not isinstance(observed, Mapping):
            return {
                "status": "collection-failed",
                "findings": [],
                "path": "",
                "reason": "ACL collector returned a non-mapping result",
            }
        findings = observed.get("findings", [])
        if not isinstance(findings, (list, tuple)):
            return {
                "status": "collection-failed",
                "findings": [],
                "path": str(observed.get("path", ""))[:4096],
                "reason": "ACL collector returned invalid findings evidence",
            }
        return {
            "status": str(observed.get("status", "collection-failed"))[:128],
            "findings": [str(item)[:8192] for item in findings[:128]],
            "path": str(observed.get("path", ""))[:4096],
            "reason": str(observed.get("reason", "ACL state is unknown"))[:8192],
        }

    def _report_acl_assurance(self, acl: Mapping[str, object]) -> None:
        """Emit each distinct weak/unknown ACL observation once."""
        status = str(acl.get("status", "collection-failed"))
        for finding in acl.get("findings", []):
            description = str(finding)
            token = f"finding:{description}"
            if token in self._acl_alerted:
                continue
            self._acl_alerted.add(token)
            self.emit(
                "🔒 PRIVILEGE WEAKNESS: " + description,
                Severity.HIGH,
                hardening=True,
                mitre_tags=["T1222", "T1548"],
            )
        if status not in {"ok", "not-applicable", "weak"}:
            reason = str(acl.get("reason", "ACL state is unknown"))
            token = f"status:{status}:{reason}"
            if token not in self._acl_alerted:
                self._acl_alerted.add(token)
                self.emit(
                    f"Self-integrity ACL evidence unavailable: {reason}",
                    Severity.HIGH,
                    disposition="health",
                    acl_status=status,
                    acl_path=acl.get("path", ""),
                )

    def _assurance_health(self, acl: Mapping[str, object]) -> tuple[int, str]:
        degradations: list[tuple[int, str]] = []
        if self._engine.unresolved:
            degradations.append(
                (20, f"{len(self._engine.unresolved)} mandatory target(s) unresolved")
            )
        if self._engine.manifest_status != "verified":
            score = 60 if self._engine.manifest_status == "tofu-unapproved" else 25
            degradations.append(
                (score, f"integrity baseline {self._engine.manifest_status}")
            )
        acl_status = str(acl.get("status", "collection-failed"))
        if acl_status == "collection-failed":
            degradations.append(
                (35, f"state ACL collection failed: {acl.get('reason', 'unknown')}")
            )
        elif acl_status == "weak":
            degradations.append((20, "state directory ACL permits a broad writer"))
        elif acl_status not in {"ok", "not-applicable"}:
            degradations.append(
                (35, f"ACL collector state is unknown: {acl_status}")
            )
        if degradations:
            return min(degradations, key=lambda row: row[0])
        return 100, "approved enforcement core and dependencies intact"

    def run(self) -> None:
        armed = self._engine.arm()
        self.emit(
            f"Self-integrity coverage armed — watching {armed}/"
            f"{self._engine.expected_count} mandatory enforcement target/dependency function(s).",
            Severity.INFO,
            watched=armed,
            expected=self._engine.expected_count,
            unresolved=self._engine.unresolved,
            baseline_status=self._engine.manifest_status,
        )
        # ACL posture is mutable after enrollment. Recollect it now and on every
        # cycle so a stale clean observation cannot keep the module green.
        acl = self._collect_acl_assurance()
        self._report_acl_assurance(acl)
        if self._engine.manifest_status == "tofu-unapproved":
            self.emit(
                "Self-integrity is observing a live TOFU baseline; no independent approved "
                "manifest was supplied, so health is deliberately capped.",
                Severity.MEDIUM,
                disposition="health",
                baseline_status=self._engine.manifest_status,
            )
        base_health, base_reason = self._assurance_health(acl)
        self.set_health(base_health, base_reason)
        while not self.stopping:
            self.sleep(self._INTERVAL)
            if self.stopping:
                break
            acl = self._collect_acl_assurance()
            self._report_acl_assurance(acl)
            try:
                tampered = self._engine.check()
            except Exception as exc:
                self.set_health(60, f"check error: {exc}")
                continue
            for desc in tampered:
                if desc in self._alerted:
                    continue          # one CRITICAL per distinct tamper, not a storm
                self._alerted.add(desc)
                spec = desc.split(" ", 1)[0]
                evidence = self._engine.evidence(spec)
                self.emit(f"🚨 RUNTIME TAMPER: {desc}. An enforcement function was "
                          "modified in memory — possible agent monkeypatching (T1562).",
                          Severity.CRITICAL, target=spec, tamper=True,
                          source_file=evidence.get("source_file", ""),
                          source_line=evidence.get("source_line", 0),
                          mitre_tags=["T1562", "T1055"])
            if tampered:
                self.set_health(10, f"{len(tampered)} enforcement function(s) tampered")
            elif not self._alerted:
                base_health, base_reason = self._assurance_health(acl)
                self.set_health(base_health, base_reason)

    def self_test(self) -> "tuple[bool, str]":
        return self._engine.self_test()


def register() -> SelfIntegrityMonitor:
    return SelfIntegrityMonitor()


if __name__ == "__main__":
    ok, detail = SelfIntegrityEngine().self_test()
    print(f"[self_integrity] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
