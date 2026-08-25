"""Strict builders for exact-target autonomous response authorization.

Detection severity is not mutation authority.  A detector must bind every
requested action to the exact path, process instance, address, or local host
that it observed.  These helpers keep that contract identical across reviewed
semantic detectors and return an empty mapping when the evidence is incomplete.
"""
from __future__ import annotations

import ipaddress
import math
import os
from pathlib import Path
from typing import Iterable


_ACTIONS = frozenset({
    "block_remote_ip",
    "isolate_program",
    "suspend_process",
    "terminate_process",
    "quarantine_file",
    "isolate_host",
    "activate_honeypots",
})


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value <= 0xFFFFFFFF else None


def _positive_clock(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    clock = float(value)
    return clock if math.isfinite(clock) and clock > 0.0 else None


def authorize_response(
    actions: Iterable[str],
    *,
    path: object = None,
    pid: object = None,
    process_create_time: object = None,
    remote_ips: Iterable[object] = (),
    local_host: bool = False,
    deception: bool = False,
) -> dict[str, object]:
    """Build a v1 response envelope, or ``{}`` when any binding is unsafe.

    No input is coerced into authority: PIDs must already be integers, process
    clocks numeric and finite, IPs literal addresses, and paths absolute.
    """
    requested = list(actions)
    if (
        not requested
        or any(not isinstance(action, str) for action in requested)
        or len(set(requested)) != len(requested)
        or not set(requested).issubset(_ACTIONS)
    ):
        return {}

    targets: dict[str, object] = {}
    process_actions = set(requested).intersection({
        "isolate_program", "suspend_process", "terminate_process",
    })
    if process_actions:
        exact_pid = _positive_int(pid)
        exact_clock = _positive_clock(process_create_time)
        if exact_pid is None or exact_clock is None:
            return {}
        targets["pid"] = exact_pid
        targets["process_create_time"] = exact_clock

    if "quarantine_file" in requested:
        if not isinstance(path, (str, os.PathLike)):
            return {}
        try:
            exact_path = Path(path).expanduser()
            if not exact_path.is_absolute():
                return {}
            targets["path"] = str(exact_path.resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            return {}

    if "block_remote_ip" in requested:
        exact_ips: list[str] = []
        try:
            for value in remote_ips:
                if isinstance(value, bool):
                    return {}
                address = str(ipaddress.ip_address(str(value)))
                if address not in exact_ips:
                    exact_ips.append(address)
        except (TypeError, ValueError):
            return {}
        if not exact_ips:
            return {}
        targets["remote_ips"] = exact_ips

    if "isolate_host" in requested:
        if local_host is not True:
            return {}
        targets["host"] = "local"

    if "activate_honeypots" in requested:
        if deception is not True:
            return {}
        targets["deception"] = "Smart Deception"

    return {
        "response_authorized": True,
        "response_contract": {
            "version": 1,
            "actions": requested,
            "targets": targets,
        },
    }


def process_response(
    pid: object,
    process_create_time: object,
    *,
    isolate_program: bool = False,
    escalate_host: bool = False,
    activate_deception: bool = True,
) -> dict[str, object]:
    """Authorize exact process containment with explicitly requested escalation.

    A semantic process signal never inherits program-wide firewall isolation or
    whole-host isolation merely because its event severity is high.  Callers
    must opt into those broader mutations after their own evidence policy has
    established that authority.
    """
    actions: list[str] = []
    if isolate_program:
        actions.append("isolate_program")
    actions.extend(("suspend_process", "terminate_process"))
    if escalate_host:
        actions.append("isolate_host")
    if activate_deception:
        actions.append("activate_honeypots")
    return authorize_response(
        actions,
        pid=pid,
        process_create_time=process_create_time,
        local_host=escalate_host,
        deception=activate_deception,
    )


def process_and_remote_response(
    pid: object,
    process_create_time: object,
    remote_ip: object,
    *,
    isolate_program: bool = False,
    escalate_host: bool = False,
    activate_deception: bool = True,
) -> dict[str, object]:
    """Authorize an exact beacon peer, plus its process when fully identified."""
    actions = ["block_remote_ip"]
    if isolate_program:
        actions.append("isolate_program")
    actions.extend(("suspend_process", "terminate_process"))
    if escalate_host:
        actions.append("isolate_host")
    if activate_deception:
        actions.append("activate_honeypots")
    combined = authorize_response(
        actions,
        pid=pid,
        process_create_time=process_create_time,
        remote_ips=(remote_ip,),
        local_host=escalate_host,
        deception=activate_deception,
    )
    if combined:
        return combined
    # Failure to obtain a trustworthy process birth time must not discard the
    # independently exact literal peer address.  The process stays untouched.
    return authorize_response(("block_remote_ip",), remote_ips=(remote_ip,))


def deception_response() -> dict[str, object]:
    """Authorize the one named local deception module, without host mutation."""
    return authorize_response(
        ("activate_honeypots",),
        deception=True,
    )


def maximum_host_response() -> dict[str, object]:
    """Authorize Maximum-mode host isolation for a reviewed critical signal."""
    return authorize_response(
        ("isolate_host", "activate_honeypots"),
        local_host=True,
        deception=True,
    )
