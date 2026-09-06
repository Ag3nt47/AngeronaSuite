"""Read-only drill response diagnostics; these snapshots grant no authority."""
from __future__ import annotations

import time
from typing import Any

from angerona.core.eventbus import Severity


def _text(value: object, fallback: str, limit: int = 500) -> str:
    if not isinstance(value, str):
        return fallback
    return " ".join(value[:2000].split())[:limit] or fallback


def _policy_fields(policy: object) -> dict[str, object]:
    """Copy only the non-secret policy values needed by the inert drill."""
    threshold = getattr(policy, "min_severity", None)
    if isinstance(threshold, Severity):
        minimum = threshold.name
    elif type(threshold) is int and threshold in Severity._value2member_map_:
        minimum = Severity(threshold).name
    elif isinstance(threshold, str) and threshold.strip().upper() in Severity.__members__:
        minimum = threshold.strip().upper()
    else:
        minimum = "UNKNOWN"
    process_action = getattr(policy, "process_action", None)
    process_action = (
        process_action.strip().lower()
        if isinstance(process_action, str) else "unknown"
    )
    if process_action not in {"none", "suspend", "terminate"}:
        process_action = "unknown"
    return {
        "enabled": getattr(policy, "enabled", None) is True,
        "quarantine_files": getattr(policy, "quarantine_files", None) is True,
        "process_action": process_action,
        "min_severity": minimum,
    }


def assess_drill_response(manager: object, *, require_process: bool = False) -> dict[str, Any]:
    """Describe whether Combat can attempt the drill's containment checks.

    Only the worker's memory snapshot and effective policy are consulted. This
    does not call ``response_ready()``, inspect a journal, change policy, or
    authorize an action. Readiness is transient; successful containment still
    needs exact authenticated evidence and a verified action postcondition.
    """
    result: dict[str, Any] = {
        "ready": False,
        "state": "UNAVAILABLE",
        "reason": "Adversary Combat is unavailable in this module manager.",
        "checked_at": float(time.time()),
        "policy": {},
    }
    try:
        modules = getattr(manager, "modules", None)
        module = modules.get("Adversary Combat") if isinstance(modules, dict) else None
        snapshot_reader = getattr(module, "response_snapshot", None)
        policy_reader = getattr(module, "policy", None)
        if not callable(snapshot_reader) or not callable(policy_reader):
            return result
        snapshot = snapshot_reader()
    except Exception:
        result.update(state="ERROR", reason="Combat response status could not be read.")
        return result
    if not isinstance(snapshot, dict) or type(snapshot.get("ready")) is not bool:
        result.update(state="UNKNOWN", reason="Combat returned an invalid response status.")
        return result

    policy_error = False
    try:
        result["policy"] = _policy_fields(policy_reader())
    except Exception:
        policy_error = True
    if snapshot["ready"] is not True:
        result.update(
            state=_text(snapshot.get("state"), "NOT READY", 64),
            reason=_text(snapshot.get("reason"), "Combat is not ready for automatic response."),
        )
        return result
    if snapshot.get("state") != "ARMED":
        result.update(state="UNKNOWN", reason="Combat returned an inconsistent response status.")
        return result
    if policy_error:
        result.update(state="ERROR", reason="Combat response policy could not be read.")
        return result

    policy = result["policy"]
    if not policy["enabled"]:
        result.update(state="DISABLED", reason="Automatic response is disabled in Combat policy.")
    elif not policy["quarantine_files"]:
        result.update(
            state="POLICY RESTRICTED",
            reason="Combat policy disables file quarantine, which this inert-marker drill requires.",
        )
    elif policy["min_severity"] == "UNKNOWN":
        result.update(state="POLICY RESTRICTED", reason="Combat's response severity is unknown.")
    elif Severity[policy["min_severity"]] > Severity.HIGH:
        result.update(
            state="POLICY RESTRICTED",
            reason="Combat's response threshold exceeds HIGH; the drill's evidence cannot qualify.",
        )
    elif require_process and policy["process_action"] not in {"suspend", "terminate"}:
        result.update(
            state="POLICY RESTRICTED",
            reason="This drill requires Combat policy to permit process suspension or termination.",
        )
    else:
        result.update(
            ready=True,
            state="ARMED",
            reason=(
                "Combat is armed for the drill's containment checks. Each action still requires "
                "authenticated evidence and a verified postcondition."
            ),
        )
    return result
