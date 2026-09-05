"""Bounded, one-way dashboard readiness for the separate startup helper.

The endpoint is a loopback port and a per-launch nonce. It never specifies a
filesystem location, executable, or command, and carries no privilege authority.
"""
from __future__ import annotations

import json
import os
import re
import socket


_OPTION = "--startup-ready"
_ENDPOINT = re.compile(r"([1-9][0-9]{3,4}):([0-9a-f]{64})", re.ASCII)
_SOCKET_TIMEOUT = 0.5


def _parse_endpoint(endpoint: str) -> tuple[int, str]:
    match = _ENDPOINT.fullmatch(endpoint)
    if match is None or not 1024 <= int(match[1]) <= 65535:
        raise ValueError("invalid startup readiness endpoint")
    return int(match[1]), match[2]


def parse_startup_arguments(argv: list[str]) -> tuple[list[str], str | None]:
    """Remove a single validated helper option without changing ``sys.argv``.

    Keeping the original arguments intact lets Windows UAC pass the nonce to
    the elevated child even when the privileged launcher clears environment.
    """
    clean: list[str] = []
    endpoint: str | None = None
    for argument in argv:
        if argument == _OPTION:
            raise ValueError("startup readiness requires --startup-ready=port:token")
        if argument.startswith(_OPTION + "="):
            if endpoint is not None:
                raise ValueError("duplicate startup readiness endpoint")
            candidate = argument[len(_OPTION) + 1:]
            _parse_endpoint(candidate)
            endpoint = candidate
        else:
            clean.append(argument)
    return clean, endpoint


def notify_dashboard_ready(endpoint: str) -> bool:
    """Send this process's ready notice, with bounded work and no response read."""
    try:
        port, token = _parse_endpoint(endpoint)
        payload = json.dumps(
            {"token": token, "pid": os.getpid()}, separators=(",", ":")
        ).encode("ascii") + b"\n"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(_SOCKET_TIMEOUT)
            connection.connect(("127.0.0.1", port))
            connection.sendall(payload)
        return True
    except (OSError, ValueError):
        # Startup readiness is advisory. A closed helper must never interrupt
        # dashboard operation or become an automatic restart trigger.
        return False
