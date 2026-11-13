"""posture.py — plain-language protection posture for the Watchdog monitor.

Pure presentation data: each row is ``{key, label, text, tone}`` with tone in
``ok / warn / alert / off``. Reads only; it grants and changes nothing.
"""
from __future__ import annotations

import time
from typing import Optional

_CACHE: dict = {"until": 0.0, "service": None}


def _stop_row(authority_status: dict) -> dict:
    state = authority_status.get("state")
    if state == "protected":
        if authority_status.get("stop_active"):
            return _row("stop", "STOP protection", "Stopped by an administrator. Resume needs "
                        "administrator approval.", "warn")
        return _row("stop", "STOP protection", "On. Stopping or resuming Angerona needs "
                    "administrator approval.", "ok")
    if state == "compromised":
        return _row("stop", "STOP protection", "Needs review: the administrator STOP records could "
                    "not be verified, so no STOP is accepted.", "alert")
    return _row("stop", "STOP protection", "Not set up. Any program running as you can stop "
                "Angerona.", "warn")


def _pressure_row(watchdog_status: dict) -> dict:
    pressure = watchdog_status.get("restart_pressure") or {}
    restarts = watchdog_status.get("restarts") or {}
    level = str(pressure.get("core", "")) if isinstance(pressure, dict) else ""
    count = restarts.get("core", 0) if isinstance(restarts, dict) else 0
    if level == "attack":
        return _row("pressure", "Restart pressure", "Restart-loop attack suspected. Angerona is "
                    "restarting with its key sensors first.", "alert")
    if level == "elevated":
        return _row("pressure", "Restart pressure", "Elevated: several unexpected stops in the "
                    "last 10 minutes.", "warn")
    if not watchdog_status:
        return _row("pressure", "Restart pressure", "Unknown: the watchdog has not reported yet.", "off")
    return _row("pressure", "Restart pressure", f"Normal. Core restarts this session: {count}.", "ok")


def _deadman_row(policy: Optional[dict], watchdog_status: dict) -> dict:
    state = str(watchdog_status.get("deadman", ""))
    if state == "engaged":
        return _row("deadman", "Network hold", "Engaged: remote network traffic is blocked until "
                    "Angerona is running again.", "alert")
    if not policy:
        return _row("deadman", "Network hold", "Off. The network is not blocked if Angerona stays "
                    "down.", "off")
    minutes = policy["threshold_s"] / 60.0
    if state == "not_elevated":
        return _row("deadman", "Network hold", "Enabled, but the watchdog is not running as "
                    "administrator, so it cannot block the network.", "warn")
    return _row("deadman", "Network hold", f"Armed: blocks remote traffic if Angerona stays down "
                f"for {minutes:g} minutes.", "ok")


def _service_row(service: dict) -> dict:
    state = service.get("state")
    if state == "configured":
        return _row("service", "Windows service recovery", "On. Windows restarts the protection "
                    "service if it fails.", "ok")
    if state == "missing_recovery":
        return _row("service", "Windows service recovery", "Service installed, but Windows is not "
                    "set to restart it after a failure.", "warn")
    if state == "not_installed":
        return _row("service", "Windows service recovery", "Not installed. Available with the "
                    "signed Angerona package.", "off")
    return _row("service", "Windows service recovery", "Unavailable on this system.", "off")


def _native_watchdog_row(status: Optional[dict]) -> dict:
    state = status.get("state") if isinstance(status, dict) else None
    if state in {"active-unsigned", "active-reduced"}:
        return _row("watchdog3", "Native third watchdog", "Active ordinary-user observation with reduced "
                    "protection. Signature status is separate from liveness. It shares Core's failure domain "
                    "and has no independent restart, response or service authority.", "warn")
    if state == "disabled":
        return _row("watchdog3", "Native third watchdog", "Optional ordinary-user monitor is off. "
                    "Signed installed supervision is configured separately.", "off")
    if state == "observed":
        return _row("watchdog3", "Native third watchdog", "Core reports an authenticated native "
                    "heartbeat. Recovery behavior and installer trust are not verified here.", "ok")
    if state in {"unverified", "stale", "unavailable"}:
        return _row("watchdog3", "Native third watchdog", "Needs review: a current authenticated "
                    "native heartbeat is not verified. No launch or repair was attempted.", "warn")
    if state == "stopped":
        return _row("watchdog3", "Native third watchdog", "The native writer reported stopping. "
                    "Only the verified STOP controls authorize stand-down.", "warn")
    if state in {"source-disabled", "not-packaged"}:
        return _row("watchdog3", "Native third watchdog", "Not auto-started in this build. The "
                    "signed installer owns native-watchdog registration and startup.", "off")
    return _row("watchdog3", "Native third watchdog", "No current native heartbeat is reported. "
                "Existing recovery controls are unchanged; no new protection is inferred.", "off")


def _row(key: str, label: str, text: str, tone: str) -> dict:
    return {"key": key, "label": label, "text": text, "tone": tone}


def protection_posture(watchdog_status: Optional[dict] = None, *,
                       native_watchdog_status: Optional[dict] = None) -> list[dict]:
    """Return read-only posture rows; no row grants launch/response authority."""
    status = watchdog_status if isinstance(watchdog_status, dict) else {}
    try:
        from angerona.resilience import control_authority
        authority, policy = control_authority.status(), control_authority.deadman_policy()
    except Exception:
        authority, policy = {"state": "unprovisioned"}, None
    now = time.monotonic()
    if now >= _CACHE["until"] or _CACHE["service"] is None:
        try:
            from angerona.core import service_recovery
            _CACHE["service"] = service_recovery.verify()
        except Exception:
            _CACHE["service"] = {"state": "unavailable"}
        _CACHE["until"] = now + 30.0
    return [_stop_row(authority), _pressure_row(status), _deadman_row(policy, status),
            _service_row(_CACHE["service"]), _native_watchdog_row(native_watchdog_status)]
