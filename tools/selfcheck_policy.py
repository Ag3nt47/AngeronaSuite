"""Pure result policy for the headless self-check harness.

The harness deliberately discovers modules without starting live sensors.  A
small number of readiness-style self-tests therefore report an expected idle
state.  Keep that exception policy structured and narrow so a timeout, crash,
or unrelated failure can never be accepted through a substring allowlist.
"""
from __future__ import annotations


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


def is_expected_unstarted_failure(module: str, detail: str) -> bool:
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
        return "ollama daemon unreachable" in normalized
    if name == "Active Response SOAR":
        return "idle" in normalized and "angerona_soar_kill_and_rollback" in normalized
    if name == "Anti-Suspension Heartbeat":
        return "watchdog binary absent" in normalized
    return False
