"""AMSI Bridge — G2-E.

What is AMSI?
  The Windows Antimalware Scan Interface (AMSI) is a Microsoft API that lets
  security software scan content (scripts, PowerShell, VBA, etc.) before it
  executes.  Scripts call AmsiScanBuffer(); AV registers as a provider and
  scores the content; the integrating host decides whether to block execution.

What this module does — CONSUMER, not provider:
  We do NOT register as an AMSI provider (a COM provider DLL, subject to the
  host's Authenticode policy). Instead we act as a *consumer* of already
  observed content, not a pre-execution interception or blocking hook:

  1. The controlled compatibility option loads amsi.dll and calls
     AmsiInitialize / AmsiOpenSession. Normal startup keeps this in observation
     mode because native scans have crashed the deployed Python runtime.
  2. We periodically send synthetic probe payloads (known-safe test strings)
     through the interface and parse the result code.  This tells us:
       a. Whether AMSI is functional (any registered AV is scanning).
       b. Whether the EICAR test string triggers AMSI_RESULT_DETECTED — a
          quick check that AV signatures are live.

  3. We subscribe to the bus and watch for script-execution events emitted by
     other modules (ETWR process-start command lines and Sysmon EID1).
     Explicit script_block fields are accepted when a separate producer
     supplies them; the current ETW Core Listener does not collect EID4104.
     For each such event
     we push the command-line text through AmsiScanBuffer and emit an alert
     if the result is DETECTED.

Why this is safe:
  AmsiScanBuffer on a detected string does NOT execute the content — it just
  returns a numeric score.  The scanning side-channel we use is the same one
  any security tool uses.

Blocking restriction:
  AMSI In-Process Patching (overwriting AmsiScanBuffer with NOPs to bypass AV)
  is an offensive bypass technique and is NOT implemented here.

Fallback:
  If amsi.dll cannot be loaded (non-Windows, sandboxed environment, or AMSI
  disabled via policy), the module runs in observation-only mode: it watches
  the bus for sysmon/etw PowerShell events and emits a MEDIUM notice that AMSI
  scanning was skipped due to unavailability.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import hashlib
import math
import ntpath
import os
import re
import threading
import time
from typing import Optional

from angerona.core.assurance_receipts import (
    DetectorReceiptIssuer,
    assurance_target_digest,
)
from angerona.core.module_base import BaseModule, Severity
from angerona.core.eventbus import Event, is_remote_observe_only
from angerona.core.kernel_telemetry_probe import ProviderReceipt
from angerona.core.threat import event_disposition

# ── AMSI constants ────────────────────────────────────────────────────────────
AMSI_RESULT_CLEAN           = 0
AMSI_RESULT_NOT_DETECTED    = 1
AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384
AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479
AMSI_RESULT_DETECTED        = 32768   # ≥ this = malicious

# EICAR test string — always detected by AV; safe to scan (not a real payload)
_EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# Known-safe probe for AMSI availability check (returns CLEAN)
_SAFE_PROBE = b"Hello AMSI"
_MAX_SCRIPT_CONTENT_CHARS = 64 * 1024

# How often to run the EICAR availability check (seconds)
_HEALTH_CHECK_INTERVAL = 120.0

# Dedup TTL — don't re-alert the same script hash within this window
_DEDUP_TTL = 60.0
_ETWR_MODULE = "ETW Real-Time Process Sensor"
_WINDOWS_EPOCH = 116444736000000000


def _finite_seconds(value: object) -> bool:
    return (type(value) in (int, float) and 0 < value <= 253402300799
            and math.isfinite(value))


def _result_label(code: int) -> str:
    if code == AMSI_RESULT_CLEAN:
        return "CLEAN"
    if code == AMSI_RESULT_NOT_DETECTED:
        return "NOT_DETECTED"
    if AMSI_RESULT_BLOCKED_BY_ADMIN_START <= code <= AMSI_RESULT_BLOCKED_BY_ADMIN_END:
        return "BLOCKED_BY_ADMIN"
    if code >= AMSI_RESULT_DETECTED:
        return "DETECTED"
    return f"UNKNOWN({code})"


# ── AMSI ctypes interface ─────────────────────────────────────────────────────

class _AMSI:
    """Thin ctypes wrapper around amsi.dll."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._lib = ctypes.WinDLL("amsi")
        
        # ── FIX: Explicitly define C-signatures to prevent memory access violations ──
        
        # HRESULT AmsiInitialize([in] LPCWSTR appName, [out] HAMSICONTEXT *amsiContext)
        self._lib.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        self._lib.AmsiInitialize.restype = ctypes.HRESULT
        
        # HRESULT AmsiOpenSession([in] HAMSICONTEXT amsiContext, [out] HAMSISESSION *amsiSession)
        self._lib.AmsiOpenSession.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self._lib.AmsiOpenSession.restype = ctypes.HRESULT
        
        # HRESULT AmsiScanBuffer([in] HAMSICONTEXT amsiContext, [in] PVOID buffer, [in] ULONG length, 
        #                        [in] LPCWSTR contentName, [in] HAMSISESSION amsiSession, [out] AMSI_RESULT *result)
        self._lib.AmsiScanBuffer.argtypes = [
            ctypes.c_void_p,                        # amsiContext
            ctypes.c_char_p,                        # buffer (receives Python bytes)
            ctypes.c_ulong,                         # length
            ctypes.c_wchar_p,                       # contentName (receives Python str)
            ctypes.c_void_p,                        # amsiSession
            ctypes.POINTER(ctypes.wintypes.DWORD)   # result
        ]
        self._lib.AmsiScanBuffer.restype = ctypes.HRESULT
        
        self._lib.AmsiCloseSession.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._lib.AmsiCloseSession.restype = None
        
        self._lib.AmsiUninitialize.argtypes = [ctypes.c_void_p]
        self._lib.AmsiUninitialize.restype = None
        # ─────────────────────────────────────────────────────────────────────────────

        self._hAmsi     = ctypes.c_void_p()
        self._hSession  = ctypes.c_void_p()
        self._ok        = False
        self._init()

    def _init(self) -> None:
        # ctypes will now automatically and safely convert this to LPCWSTR
        hr = self._lib.AmsiInitialize("AngeronaBridge", ctypes.byref(self._hAmsi))
        if hr != 0:
            raise OSError(f"AmsiInitialize failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")
            
        hr = self._lib.AmsiOpenSession(self._hAmsi, ctypes.byref(self._hSession))
        if hr != 0:
            self._lib.AmsiUninitialize(self._hAmsi)
            raise OSError(f"AmsiOpenSession failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")
        self._ok = True

    def scan(self, content: bytes, content_name: str = "script") -> int:
        """Call AmsiScanBuffer and return the result code."""
        with self._lock:
            return self._scan_locked(content, content_name)

    def _scan_locked(self, content: bytes, content_name: str) -> int:
        if not self._ok:
            raise RuntimeError("AMSI scan unavailable: session is closed")
            
        result = ctypes.wintypes.DWORD(0)
        hr = self._lib.AmsiScanBuffer(
            self._hAmsi,
            content,                # Safely mapped to c_char_p
            len(content),           # Safely mapped to c_ulong
            content_name,           # Safely mapped to c_wchar_p
            self._hSession,
            ctypes.byref(result),
        )
        if hr != 0:
            raise OSError(f"AmsiScanBuffer failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")
        return result.value

    def close(self) -> None:
        # A self-test can scan concurrently with worker shutdown. The native
        # session must remain alive until the last scan returns.
        with self._lock:
            if self._ok:
                try:
                    self._lib.AmsiCloseSession(self._hAmsi, self._hSession)
                    self._lib.AmsiUninitialize(self._hAmsi)
                except Exception:
                    pass
                self._ok = False


# ── Module ────────────────────────────────────────────────────────────────────

class AMSIBridgeModule(BaseModule):
    CODE = "AMSI"
    NAME = "AMSI Bridge"
    name = "AMSI Bridge"
    description = (
        "AMSI scanning consumer — pushes PowerShell/script content from bus "
        "events through AmsiScanBuffer after observation; no pre-execution "
        "interception. Native scanning requires the controlled compatibility option."
    )
    category = "Endpoint"
    version = "1.14.0"

    _POLL_INTERVAL = 5.0   # how often to drain the bus for new script events

    def __init__(self) -> None:
        super().__init__()
        self._amsi:      Optional[_AMSI] = None
        self._fallback:  bool = False
        self._last_health_check: float = 0.0
        # (hash of content) → last_alert_ts
        self._seen: dict[tuple, float] = {}
        self._assurance_issuer: DetectorReceiptIssuer | None = None
        self._manager = None

    def bind_manager(self, manager) -> None:
        self._manager = manager

    def _native_context(self, ev: object, content: bytes) -> tuple[dict, str]:
        """Bind a new AMSI verdict to an already authenticated native event.

        This reads the collector's cached receipt only. It never opens the PID,
        infers native ticks from seconds, or turns a raw INFO observation into
        a verdict. A positive scan of these exact bytes is separately required.
        """
        bus = self._bus
        if (type(ev) is not Event or bus is None or bus.mesh_required is not True
                or bus.integrity_enabled is not True or bus.verify(ev) is not True
                or is_remote_observe_only(ev) or ev.module != _ETWR_MODULE):
            return {}, "live native source authentication unavailable"
        details = ev.details
        if (type(details) is not dict or details.get("event_type") != "process_creation"
                or details.get("source") != "ETW:Kernel-Process" or details.get("fallback") is True
                or any(details.get(key) is True for key in ("drill", "self_test", "selftest", "simulation", "practice"))
                or event_disposition(ev) == "practice"):
            return {}, "native process-start evidence is unavailable or practice scoped"
        now = time.time()
        generation, pid, image = (details.get(key) for key in ("collection_generation", "pid", "image"))
        if (not _finite_seconds(now) or not _finite_seconds(ev.ts) or not -1 <= now - ev.ts <= 30
                or type(pid) is not int or not 4 < pid <= 0xFFFFFFFF
                or type(generation) is not str or re.fullmatch(r"[0-9a-f]{32}", generation) is None
                or type(image) is not str or not 1 <= len(image) <= 32767 or "\0" in image
                or not ntpath.isabs(image) or not ntpath.splitdrive(image)[0]):
            return {}, "native source age, PID, image or generation is invalid"
        # ETWR currently emits cmdline, never a script_block. Equal spelling
        # aliases are harmless; conflicting text must not name another buffer.
        texts = [details[key] for key in ("cmdline", "command_line") if key in details]
        if (not texts or "script_block" in details
                or any(type(text) is not str or not 0 < len(text) <= _MAX_SCRIPT_CONTENT_CHARS
                       or text != texts[0] for text in texts)
                or type(content) is not bytes or texts[0].encode("utf-8", errors="replace") != content):
            return {}, "scanned bytes are not the original bounded native command line"
        ticks, wire = [], []
        for field in ("process_birth_ticks", "native_birth_ticks"):
            if field not in details:
                continue
            original = value = details[field]
            if type(value) is str:
                if (not 1 <= len(value) <= 20 or not value.isascii() or not value.isdecimal()
                        or value != str(int(value))):
                    return {}, "original native birth text is not canonical"
                value = int(value)
            if type(value) is not int or not _WINDOWS_EPOCH < value <= 0xFFFFFFFFFFFFFFFF:
                return {}, "original native birth is invalid"
            ticks.append(value)
            wire.append({"field": field, "type": type(original).__name__, "value": original})
        if not ticks or len(set(ticks)) != 1:
            return {}, "original native birth aliases are unavailable or conflict"
        seconds = (ticks[0] - _WINDOWS_EPOCH) / 10_000_000
        if seconds > ev.ts + 0.001:
            return {}, "original process birth is later than the source evidence"
        legacy = {}
        for field in ("create_time", "process_create_time", "start_time"):
            if field in details:
                value = details[field]
                if (not _finite_seconds(value)
                        or abs(value - seconds) > max(math.ulp(seconds) * 16, 0.000004)):
                    return {}, "original seconds annotation conflicts with raw native birth"
                legacy[field] = value
        modules = getattr(self._manager, "modules", {})
        source = modules.get(_ETWR_MODULE) if type(modules) is dict else None
        if (source is None or (type(source).__module__, type(source).__name__) != (
                "angerona.modules.etw_realtime_sensor", "EtwRealtimeSensorModule")
                or source._bus is not bus or source.status != "running" or source.stopping):
            return {}, "current native collector owner is unavailable"
        try:
            receipt = ProviderReceipt.from_snapshot("kernel-etw", source.collection_snapshot(), now=time.monotonic())
        except Exception:
            return {}, "current native collector receipt is unavailable"
        if not receipt.available or receipt.generation != generation:
            return {}, "native collector receipt is stale, lossy, unavailable or a different generation"
        # All copied values are immutable primitives. Retain exact wire spelling
        # and signatures; no mutable reference back into source.details escapes.
        origin = dict(schema="angerona.amsi.native-etwr-origin.v1", module=ev.module,
                      source=details["source"], collection_generation=generation, ts=ev.ts,
                      pid=pid, image=image, source_hmac=ev.hmac_sig, source_mesh_sig=ev.mesh_sig,
                      source_mesh_peer=ev.mesh_peer, wire_birth=wire, wire_seconds=legacy,
                      identity_inferred=False, seconds_derived_from_raw_ticks=True,
                      scope="Positive AMSI scan of observed command text; no pre-execution or response authority")
        return dict(pid=pid, image=image, process_birth_ticks=ticks[0], process_create_time=seconds,
                    native_origin=origin, scan_content_sha256=hashlib.sha256(content).hexdigest()), ""

    def bind_assurance_receipt_issuer(self, issuer: DetectorReceiptIssuer) -> None:
        self._assurance_issuer = issuer

    def _publish_assurance_receipts(self) -> None:
        issuer = self._assurance_issuer
        if issuer is None or self._amsi is None or self.stopping:
            return
        evidence_digest = hashlib.sha256(_EICAR).hexdigest()
        target_digest = assurance_target_digest(
            "amsi", "eicar-health-check", evidence_digest
        )
        for challenge in issuer.active(self, "amsi"):
            try:
                result = self._amsi.scan(_EICAR, "angerona_assurance_eicar")
            except Exception as exc:
                self.last_error = str(exc)
                continue
            if result < AMSI_RESULT_DETECTED:
                continue
            receipt = issuer.issue(
                self,
                challenge.probe_id,
                observation="content_signature_observed",
                observed_target_digest=target_digest,
            )
            if receipt is not None:
                self.emit(
                    "AMSI object-bound assurance receipt: EICAR detection observed.",
                    Severity.INFO,
                    **receipt,
                )

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        amsi = self._try_init_amsi()
        self._amsi = amsi
        self._fallback = amsi is None
        try:
            if self.stopping:
                return
            if self._fallback:
                self.set_health(50, "AMSI unavailable — observation-only mode")
                self.emit(
                    "AMSI Bridge: amsi.dll not available (non-Windows or disabled). "
                    "Running in observation-only mode — watching bus for script events.",
                    Severity.MEDIUM,
                    fallback=True,
                )
            else:
                self.set_health(100, "")
                self.emit("AMSI Bridge active — AmsiScanBuffer connected.", Severity.INFO)
                # Verify EICAR is detected (proves AV provider is registered)
                self._check_eicar_health()
                self._publish_assurance_receipts()

            while not self.stopping:
                self.sleep(self._POLL_INTERVAL)
                if self.stopping:
                    break
                self._drain_bus()
                self._publish_assurance_receipts()

                now = time.time()
                if not self._fallback and (now - self._last_health_check >= _HEALTH_CHECK_INTERVAL):
                    self._check_eicar_health()
                    self._last_health_check = now

                self._evict_stale_dedup()
        finally:
            # Cleanup belongs to the worker generation, not the GUI's stop()
            # caller: a native scan may still be in flight when stop is signalled.
            if amsi is not None:
                amsi.close()
            if self._amsi is amsi:
                self._amsi = None

    def _try_init_amsi(self) -> Optional[_AMSI]:
        # Direct ctypes calls into AmsiScanBuffer caused repeated native access
        # violations on the deployed Python/Windows build (21 crash-log hits).
        # Native faults bypass Python exception handling and terminate the suite,
        # so keep safe ETW/Sysmon observation mode as the default. The legacy
        # consumer can be enabled only for controlled compatibility testing.
        if os.environ.get("ANGERONA_AMSI_INPROCESS", "0").strip().lower() not in {
            "1", "true", "yes", "on"
        }:
            self.last_error = (
                "direct AmsiScanBuffer disabled for process stability; "
                "using ETW/Sysmon observation mode"
            )
            return None
        try:
            return _AMSI()
        except Exception as exc:
            self.last_error = str(exc)
            return None

    def _check_eicar_health(self) -> None:
        """Scan EICAR test string — verifies AV provider is alive and detecting."""
        if self._amsi is None:
            return
        try:
            result = self._amsi.scan(_EICAR, "eicar_health_check")
            if result >= AMSI_RESULT_DETECTED:
                self.set_health(100, "EICAR detected — AV provider active")
            else:
                self.set_health(
                    60,
                    f"EICAR not detected (result={_result_label(result)}) — "
                    "AV provider may be inactive or signatures stale",
                )
                self.emit(
                    f"AMSI health check: EICAR returned {_result_label(result)} "
                    "(expected DETECTED). AV provider may be degraded.",
                    Severity.MEDIUM,
                    eicar_result=result,
                    eicar_label=_result_label(result),
                )
        except Exception as exc:
            self.set_health(40, f"EICAR scan error: {exc}")

    def _drain_bus(self) -> None:
        """Read recent bus events and scan any script/command-line content."""
        if self._bus is None:
            return

        events, _overflow = self.poll_bus_events()
        for ev in events:
            if self.stopping:
                break
            if self._bus.integrity_enabled and self._bus.verify(ev) is not True:
                continue
            content = self._extract_script_content(ev)
            if not content:
                continue

            content_bytes = content.encode("utf-8", errors="replace")
            context, _held = self._native_context(ev, content_bytes)
            key = (hashlib.sha256(content_bytes).digest(),
                   context.get("pid"), context.get("process_birth_ticks"))
            now = time.time()
            if now - self._seen.get(key, 0.0) < _DEDUP_TTL:
                continue
            self._seen[key] = now

            if self._fallback:
                # Observation only — no AMSI scan, just log the script event
                self.emit(
                    f"Script event observed (AMSI unavailable): {content[:200]}",
                    Severity.INFO,
                    source_module=ev.module,
                    content_preview=content[:200],
                    fallback=True,
                )
            else:
                self._scan_and_alert(content_bytes, ev)

    def _extract_script_content(self, ev: object) -> Optional[str]:
        """Pull script content out of a bus event, if present.

        Looks at:
          • details["command_line"] — Sysmon EID1
          • details["cmdline"] — ETW Real-Time Process Sensor
          • details["script_block"] — a separate explicit script producer

        This is post-observation text inspection. No alias or scan result
        establishes that a script was intercepted before execution.
        """
        details = getattr(ev, "details", None)
        if not isinstance(details, dict):
            return None
        content = None
        for field in ("script_block", "command_line", "cmdline"):
            value = details.get(field)
            if type(value) is str and 0 < len(value) <= _MAX_SCRIPT_CONTENT_CHARS:
                content = value
                break
        if content is None:
            return None

        # Only care about LOLBin / scripting engine events
        lower = content.lower()
        indicators = (
            "powershell", "pwsh", "wscript", "cscript", "mshta",
            "invoke-expression", "iex", "encodedcommand", "downloadstring",
        )
        if not any(ind in lower for ind in indicators):
            return None

        return content

    def _scan_and_alert(self, content: bytes, ev: object) -> None:
        if self._amsi is None:
            return
        context, held = self._native_context(ev, content)
        try:
            result = self._amsi.scan(content, "angerona_script_scan")
            if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
                raise ValueError("AMSI returned an invalid native result")
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(40, f"AMSI scan error: {exc}")
            return

        label = _result_label(result)

        if result >= AMSI_RESULT_DETECTED:
            current, reason = self._native_context(ev, content)
            if not context or current != context:
                context = {}
                held = reason or held or "source evidence changed while AMSI was scanning"
            preview = content[:300].decode("utf-8", errors="replace")
            self.emit(
                f"AMSI DETECTED malicious script from {getattr(ev, 'module', '?')}: "
                f"result={label} ({result}). Content preview: {preview}",
                Severity.CRITICAL,
                amsi_result=result,
                amsi_label=label,
                source_module=getattr(ev, "module", ""),
                content_preview=preview,
                mitre_tags=["T1059.001", "T1059.005", "T1059.007"],
                **context,
                amsi_post_observation=True,
                active_attack=bool(context),
                disposition="active" if context else "observation",
                forensic_coverage="eligible for opt-in native revalidation" if context else "held",
                forensic_hold_reason=held,
                response_authorized=False,
            )
        elif result == AMSI_RESULT_BLOCKED_BY_ADMIN_START or (
            AMSI_RESULT_BLOCKED_BY_ADMIN_START <= result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END
        ):
            self.emit(
                f"AMSI: script blocked by administrator policy (result={label})",
                Severity.HIGH,
                amsi_result=result,
                amsi_label=label,
                source_module=getattr(ev, "module", ""),
                disposition="observation", active_attack=False, response_authorized=False,
            )

    def _evict_stale_dedup(self) -> None:
        cutoff = time.time() - _DEDUP_TTL
        stale  = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]

    def self_test(self) -> tuple[bool, str]:
        from types import SimpleNamespace

        from angerona.core.eventbus import Event, EventBus

        positive = "powershell # angerona-inert-amsi-sample"
        clean = "powershell # angerona-clean-control"
        probe = AMSIBridgeModule()
        bus = EventBus()
        probe.bind(bus)
        probe._amsi = SimpleNamespace(scan=lambda content, _label: (
            AMSI_RESULT_DETECTED if content == positive.encode("ascii") else AMSI_RESULT_CLEAN
        ))
        for text in (clean, positive):
            event = Event("AMSI self-test fixture", "inert script text", Severity.INFO,
                          details={"command_line": text})
            extracted = probe._extract_script_content(event)
            if extracted != text:
                return False, "AMSI fixture command-line extraction failed"
            probe._scan_and_alert(extracted.encode("ascii"), event)
        alerts = bus.recent(2)
        if (len(alerts) != 1 or alerts[0].severity is not Severity.CRITICAL
                or alerts[0].details.get("amsi_result") != AMSI_RESULT_DETECTED):
            return False, "AMSI fixture did not keep the clean result quiet and flag the detected result"
        detail = "Offline AMSI sample: mock-provider clean result quiet and detected result flagged. "
        if self.status != "running":
            return True, detail + "Live provider was not exercised."
        if self._fallback:
            return True, detail + "AMSI unavailable — observation-only mode active."
        if self._amsi is None:
            return False, detail + f"AMSI init failed: {self.last_error}"
        try:
            result = self._amsi.scan(_SAFE_PROBE, "self_test")
        except Exception as exc:
            return False, detail + f"AmsiScanBuffer failed: {exc}"
        return True, detail + f"Live AmsiScanBuffer functional — benign probe result={_result_label(result)}"


def register() -> AMSIBridgeModule:
    return AMSIBridgeModule()
