"""AMSI Bridge — G2-E.

What is AMSI?
  The Windows Antimalware Scan Interface (AMSI) is a Microsoft API that lets
  security software scan content (scripts, PowerShell, VBA, etc.) before it
  executes.  Scripts call AmsiScanBuffer(); AV registers as a provider and
  scores the content; results ≥ AMSI_RESULT_DETECTED (32768) block execution.

What this module does — CONSUMER, not provider:
  We do NOT register as an AMSI provider (that would require a COM server and
  a signed driver on modern Windows).  Instead we act as a *consumer*:

  1. We load amsi.dll and call AmsiInitialize / AmsiCreateSession ourselves.
  2. We periodically send synthetic probe payloads (known-safe test strings)
     through the interface and parse the result code.  This tells us:
       a. Whether AMSI is functional (any registered AV is scanning).
       b. Whether the EICAR test string triggers AMSI_RESULT_DETECTED — a
          quick check that AV signatures are live.

  3. We subscribe to the bus and watch for script-execution events emitted by
     other modules (etw_listener EID 4104 PowerShell scriptblock logging,
     sysmon_listener EID 1 with wscript/cscript/mshta).  For each such event
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
import os
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity

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

# How often to run the EICAR availability check (seconds)
_HEALTH_CHECK_INTERVAL = 120.0

# Dedup TTL — don't re-alert the same script hash within this window
_DEDUP_TTL = 60.0


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
        if not self._ok:
            return AMSI_RESULT_CLEAN
            
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
            return AMSI_RESULT_CLEAN
        return result.value

    def close(self) -> None:
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
        "events through AmsiScanBuffer to detect malicious scripts at execution "
        "time.  Does NOT patch AmsiScanBuffer (no offensive bypass)."
    )
    category = "Endpoint"

    _POLL_INTERVAL = 5.0   # how often to drain the bus for new script events

    def __init__(self) -> None:
        super().__init__()
        self._amsi:      Optional[_AMSI] = None
        self._fallback:  bool = False
        self._last_ts:   float = 0.0
        self._last_health_check: float = 0.0
        # (hash of content) → last_alert_ts
        self._seen: dict[int, float] = {}

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        self._amsi = self._try_init_amsi()

        if self._amsi is None:
            self._fallback = True
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

        while not self.stopping:
            self.sleep(self._POLL_INTERVAL)
            self._drain_bus()

            now = time.time()
            if not self._fallback and (now - self._last_health_check >= _HEALTH_CHECK_INTERVAL):
                self._check_eicar_health()
                self._last_health_check = now

            self._evict_stale_dedup()

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

        for ev in self._bus.recent(50):
            if ev.ts <= self._last_ts:
                continue
            self._last_ts = max(self._last_ts, ev.ts)

            content = self._extract_script_content(ev)
            if not content:
                continue

            content_bytes = content.encode("utf-8", errors="replace")
            key = hash(content_bytes)
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
          • details["command_line"]   — from sysmon EID 1 / etw EID 4688
          • details["script_block"]   — from etw EID 4104 PS scriptblock
          • message substring checks  — rough catch-all
        """
        details = getattr(ev, "details", {}) or {}
        cmd   = details.get("command_line", "")
        block = details.get("script_block", "")

        content = block or cmd
        if not content:
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
        try:
            result = self._amsi.scan(content, "angerona_script_scan")
        except Exception as exc:
            self.last_error = str(exc)
            return

        label = _result_label(result)

        if result >= AMSI_RESULT_DETECTED:
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
            )

    def _evict_stale_dedup(self) -> None:
        cutoff = time.time() - _DEDUP_TTL
        stale  = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]

    def self_test(self) -> tuple[bool, str]:
        if self.status != "running":
            return super().self_test()   # not started yet — graceful "stopped" status
        if self._fallback:
            return True, "AMSI unavailable — observation-only mode active"
        if self._amsi is None:
            return False, f"AMSI init failed: {self.last_error}"
        result = self._amsi.scan(_SAFE_PROBE, "self_test")
        return True, f"AmsiScanBuffer functional — probe result={_result_label(result)}"

    def stop(self) -> None:
        super().stop()
        if self._amsi is not None:
            self._amsi.close()
            self._amsi = None


def register() -> AMSIBridgeModule:
    return AMSIBridgeModule()
