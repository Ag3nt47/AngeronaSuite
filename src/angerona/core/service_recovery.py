"""service_recovery.py — Windows SCM recovery for the AngeronaProtection service.

The Service Control Manager is a supervisor that does not depend on Python and
is not part of Angerona's own process tree, so killing the Python pair does not
also remove it. The signed package installer registers ``AngeronaProtection``;
this module is the installer step that gives it restart-on-failure recovery,
and a read-only verifier the posture views use to report when it is missing.

Policy: restart after 5 s, 5 s, then 30 s for every later failure; the failure
count resets after 24 h. ``FailureActionsOnNonCrashFailures`` is enabled so a
service that stops with an error status (not only a crash) is also restarted.
A STOP through the service manager is a normal stop and is never "recovered".
"""
from __future__ import annotations

import sys

SERVICE_NAME = "AngeronaProtection"
RESET_PERIOD_S = 86400
# (action type, delay ms). SC_ACTION_RESTART == 1.
ACTIONS = ((1, 5000), (1, 5000), (1, 30000))
_SERVICE_CONFIG_FAILURE_ACTIONS = 2
_SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4


def _require_windows():
    if sys.platform != "win32":
        raise OSError("SCM recovery applies to Windows only")
    import win32service
    return win32service


def apply(service_name: str = SERVICE_NAME) -> dict:
    """Configure recovery on an installed service. Requires an administrator."""
    from angerona.resilience.control_authority import AdminApprovalRequired, is_admin
    if not is_admin():
        raise AdminApprovalRequired("SCM recovery configuration requires an administrator")
    win32service = _require_windows()
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        service = win32service.OpenService(
            manager, service_name,
            win32service.SERVICE_CHANGE_CONFIG | win32service.SERVICE_START
            | win32service.SERVICE_QUERY_CONFIG)
        try:
            win32service.ChangeServiceConfig2(service, _SERVICE_CONFIG_FAILURE_ACTIONS, {
                "ResetPeriod": RESET_PERIOD_S, "RebootMsg": None, "Command": None,
                "Actions": list(ACTIONS),
            })
            win32service.ChangeServiceConfig2(service, _SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, True)
        finally:
            win32service.CloseServiceHandle(service)
    finally:
        win32service.CloseServiceHandle(manager)
    return verify(service_name)


def verify(service_name: str = SERVICE_NAME) -> dict:
    """Read-only posture: installed / recovery configured / non-crash flag."""
    try:
        win32service = _require_windows()
    except (OSError, ImportError) as exc:
        return {"state": "unavailable", "detail": type(exc).__name__}
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except Exception as exc:
        return {"state": "unavailable", "detail": type(exc).__name__}
    try:
        try:
            service = win32service.OpenService(manager, service_name, win32service.SERVICE_QUERY_CONFIG)
        except Exception:
            return {"state": "not_installed"}
        try:
            failure = win32service.QueryServiceConfig2(service, _SERVICE_CONFIG_FAILURE_ACTIONS) or {}
            flag = bool(win32service.QueryServiceConfig2(service, _SERVICE_CONFIG_FAILURE_ACTIONS_FLAG))
        finally:
            win32service.CloseServiceHandle(service)
    finally:
        win32service.CloseServiceHandle(manager)
    actions = [tuple(a) for a in (failure.get("Actions") or [])]
    restarts = bool(actions) and all(kind == 1 for kind, _delay in actions)
    configured = restarts and flag
    return {"state": "configured" if configured else "missing_recovery",
            "actions": actions, "reset_period_s": failure.get("ResetPeriod"),
            "non_crash_failures": flag}


def main(argv=None) -> int:
    import json
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["verify"]:
        print(json.dumps(verify()))
        return 0
    if args == ["apply"]:
        try:
            print(json.dumps(apply()))
            return 0
        except Exception as exc:
            print(json.dumps({"state": "failed", "detail": type(exc).__name__}))
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
