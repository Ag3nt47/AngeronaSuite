"""Pure result policy for the headless self-check harness.

The harness deliberately discovers modules without starting live sensors.  A
small number of readiness-style self-tests therefore report an expected idle
state.  Keep that exception policy structured and narrow so a timeout, crash,
or unrelated failure can never be accepted through a substring allowlist.
"""
from __future__ import annotations

import re


_EXPECTED_STOPPED_MODULES = frozenset({
    "AMSI Bridge",
    "Active Deception",
    "Adversary Combat",
    "Dynamic Resource Governor",
    "Memory Injection Scanner",
    "Network Monitor",
    "Process Monitor",
    "SOAR Automation",
    "Sysmon Event Bridge",
    "TUNE",
    "WFP Controller",
})

_UNAVAILABLE_OLLAMA_LISTENER = (
    "ollama listener attestation failed: local ollama listener ownership "
    "is unavailable or ambiguous"
)


def no_tcp_listener_on_port(connections, port: int) -> bool:
    """Interpret one successful listener-table read, including unknown PIDs."""
    if type(port) is not int or not 1 <= port <= 65535:
        return False
    for connection in connections:
        status = str(getattr(connection, "status", "")).upper()
        if not status:
            return False
        if status != "LISTEN":
            continue
        address = getattr(connection, "laddr", None)
        if not address:
            return False
        try:
            listener_port = int(address.port if hasattr(address, "port") else address[1])
        except (AttributeError, IndexError, TypeError, ValueError):
            return False
        # Every address on this port counts, including wildcard binds and
        # listeners with unknown owners. Neither is an absent daemon.
        if listener_port == port:
            return False
    return True


def is_expected_unstarted_failure(
    module: str,
    detail: str,
    *,
    allow_unapproved_model_baseline: bool = False,
    confirmed_absent_ollama_listener: bool = False,
) -> bool:
    """Return whether *detail* is an expected result of not starting sensors.

    This function must never classify timeouts or exceptions as expected.  It
    is intentionally independent from Qt and Angerona imports so its failure
    semantics can be regression-tested without running the full application.
    """
    name = str(module).strip()
    normalized = " ".join(str(detail).casefold().split())
    if "timed out" in normalized or normalized.startswith("error:"):
        return False
    if name in _EXPECTED_STOPPED_MODULES and "status=stopped" in normalized:
        return True
    if name == "AI Triage (Ollama)":
        if "ollama daemon unreachable" in normalized:
            return True
        if normalized == _UNAVAILABLE_OLLAMA_LISTENER:
            return confirmed_absent_ollama_listener
        # Only the disposable harness may classify an absent approval as an
        # optional prerequisite. A present-but-invalid baseline, lost key,
        # timeout, or other attestation failure remains actionable.
        return allow_unapproved_model_baseline and re.fullmatch(
            r"ollama ready, but model [^\s]{1,256} has no fresh approved local "
            r"attestation: approved model baseline unavailable \(approval-required\)",
            normalized,
        ) is not None
    if name == "Active Response SOAR":
        return "idle" in normalized and "angerona_soar_kill_and_rollback" in normalized
    if name == "Anti-Suspension Heartbeat":
        return "watchdog binary absent" in normalized
    return False
