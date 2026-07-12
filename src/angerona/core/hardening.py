"""
core/hardening.py — self-hardening of Angerona's own process.

Applies a set of Windows process-mitigation policies (SetProcessMitigationPolicy)
to shrink the attack surface an in-process exploit could use for injection or
code execution. This hardens the AGENT itself; it is not a detection module and
adds no orchestrator (the 360° model forbids a control-plane module).

Design note — why not "Microsoft-signed binaries only"?
    A hardening spec often calls for BinarySignaturePolicy = MicrosoftSignedOnly
    plus Arbitrary Code Guard (ACG / ProhibitDynamicCode). For THIS process that
    is self-defeating: Angerona is a Python + PySide6 (Qt) app that must load
    third-party, non-Microsoft-signed native DLLs (Qt, pywin32, scapy). Enabling
    MicrosoftSignedOnly blocks those loads and the app dies on launch; ACG can
    break libraries that generate code at runtime. So those two are NOT applied
    by default. The genuinely safe, non-breaking mitigations below run always;
    ACG is available opt-in (ANGERONA_HARDEN_AGGRESSIVE=1) for deployments that
    have verified their DLL set tolerates it. MicrosoftSignedOnly is intentionally
    never applied to the GUI process.

Safe by default:
    * ExtensionPointDisablePolicy — blocks legacy injection vectors (AppInit_DLLs,
      Winsock LSPs, IME hooks, legacy hook DLLs).
    * ImageLoadPolicy — NoRemoteImages (no DLLs from UNC/remote) and
      NoLowMandatoryLabelImages (no low-integrity DLLs).
    * ASLRPolicy — bottom-up + high-entropy randomization.

All calls are best-effort and never raise: hardening must not stop the app from
starting.
"""
from __future__ import annotations

import os

# ProcessMitigationPolicy enum values (winnt.h).
_ASLR = 1
_DYNAMIC_CODE = 2
_EXTENSION_POINT_DISABLE = 6
_IMAGE_LOAD = 10

# Bit fields for each policy DWORD.
_ASLR_BOTTOM_UP = 0x1
_ASLR_HIGH_ENTROPY = 0x4
_EXT_DISABLE = 0x1
_IMG_NO_REMOTE = 0x1
_IMG_NO_LOW_LABEL = 0x2
_DYN_PROHIBIT = 0x1
_DYN_ALLOW_THREAD_OPT_OUT = 0x2


def apply_process_mitigations(aggressive: bool | None = None) -> dict:
    """Apply process-mitigation policies to the current process. Returns a dict
    of {policy_name: True|False|"skipped"}. No-op (all "skipped") off Windows."""
    results: dict[str, object] = {}
    if os.name != "nt":
        return {"platform": "skipped (non-Windows)"}
    if aggressive is None:
        aggressive = os.getenv("ANGERONA_HARDEN_AGGRESSIVE", "0") == "1"

    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:                       # pragma: no cover
        return {"error": f"ctypes unavailable: {exc}"}

    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        SetPolicy = k32.SetProcessMitigationPolicy
        SetPolicy.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        SetPolicy.restype = wintypes.BOOL
    except Exception as exc:                        # pragma: no cover
        return {"error": f"SetProcessMitigationPolicy unavailable: {exc}"}

    def _set(name: str, policy_id: int, value: int) -> None:
        try:
            val = ctypes.c_uint32(value)
            ok = SetPolicy(policy_id, ctypes.byref(val), ctypes.sizeof(val))
            results[name] = bool(ok)
        except Exception as exc:                    # never fatal
            results[name] = f"error: {exc}"

    # Always-safe mitigations.
    _set("extension_point_disable", _EXTENSION_POINT_DISABLE, _EXT_DISABLE)
    _set("image_load", _IMAGE_LOAD, _IMG_NO_REMOTE | _IMG_NO_LOW_LABEL)
    _set("aslr", _ASLR, _ASLR_BOTTOM_UP | _ASLR_HIGH_ENTROPY)

    # Opt-in only: Arbitrary Code Guard. Can break libraries that JIT/emit code,
    # so thread opt-out is allowed and it is gated behind an explicit flag.
    if aggressive:
        _set("dynamic_code_acg", _DYNAMIC_CODE, _DYN_PROHIBIT | _DYN_ALLOW_THREAD_OPT_OUT)
    else:
        results["dynamic_code_acg"] = "skipped (set ANGERONA_HARDEN_AGGRESSIVE=1)"
    # MicrosoftSignedOnly is intentionally never applied — it would block Qt DLLs.
    results["binary_signature_microsoft_only"] = "skipped (would break Qt/PySide6)"
    return results
