"""deadman.py — opt-in network hold while the core stays down.

If the core is unexpectedly down for longer than an administrator-chosen
threshold, an attacker has an unobserved host. With an administrator-signed
opt-in (``control_authority.set_deadman``) the peer watchdog then applies one
fixed, reversible containment: two named Windows Firewall block rules
(inbound and outbound, all profiles). Loopback is not filtered by Windows
Firewall, so local IPC and a loopback Ollama keep working.

Boundaries
    * Off by default. No policy, an unverifiable policy or a compromised
      control authority all mean "disabled".
    * Fixed action only: exact rule names, the system ``netsh.exe``, readback
      verification, and rollback if either rule is missing. No scripts, no
      caller-supplied targets.
    * Needs elevation. An unelevated watchdog reports that it is armed but
      cannot act; it never attempts the change.
    * Never engages during an authenticated stand-down, and releases after
      the core has been alive again for ``_RELEASE_AFTER_S``.
    * This is a hold, not a verdict: it blocks traffic, it does not terminate
      or quarantine anything.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

RULES = (("Angerona-DeadMan-out", "out"), ("Angerona-DeadMan-in", "in"))
_RELEASE_AFTER_S = 15.0


def _netsh(arguments: list[str]) -> bool:
    if os.name != "nt":
        return False
    buffer = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260):
        return False
    try:
        result = subprocess.run([str(Path(buffer.value) / "netsh.exe"), *arguments],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _default_policy() -> Optional[dict]:
    from angerona.resilience import control_authority
    return control_authority.deadman_policy()


def _default_is_admin() -> bool:
    from angerona.resilience import control_authority
    return control_authority.is_admin()


class DeadMan:
    def __init__(self, publish: Callable[[str, str, dict], None], *,
                 policy: Callable[[], Optional[dict]] = _default_policy,
                 is_admin: Callable[[], bool] = _default_is_admin,
                 runner: Callable[[list[str]], bool] = _netsh,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._publish = publish
        self._policy = policy
        self._is_admin = is_admin
        self._run = runner
        self._clock = clock
        self._down_since: Optional[float] = None
        self._alive_since: Optional[float] = None
        self._notified_unelevated = False
        self._failed = False
        # Rules survive a watchdog restart; adopt them so they can be released.
        self.engaged = self._present()

    def _show(self, name: str) -> bool:
        return self._run(["advfirewall", "firewall", "show", "rule", f"name={name}"])

    def _present(self) -> bool:
        try:
            return all(self._show(name) for name, _ in RULES)
        except Exception:
            return False

    def _delete(self) -> bool:
        ok = True
        for name, _direction in RULES:
            if self._show(name):
                ok = self._run(["advfirewall", "firewall", "delete", "rule", f"name={name}"]) and ok
        return ok and not any(self._show(name) for name, _ in RULES)

    def _engage(self, down_for: float, threshold: float) -> None:
        for name, direction in RULES:
            self._run(["advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                       "action=block", "remoteip=any", "enable=yes", "profile=any"])
        if self._present():
            self.engaged = True
            self._publish("CRITICAL", "Dead-man isolation engaged: the core has been down for "
                          f"{down_for:.0f}s (threshold {threshold:.0f}s). Remote network traffic is "
                          "blocked until the core is back; loopback is unaffected.",
                          {"deadman": "engaged", "down_for_s": round(down_for, 1),
                           "rules": [name for name, _ in RULES]})
            return
        rolled_back = self._delete()
        self._failed = True  # Do not retry every tick; a new outage re-arms.
        self._publish("HIGH", "Dead-man isolation could not be verified and was rolled back.",
                      {"deadman": "failed", "rolled_back": rolled_back})

    def release(self, reason: str) -> bool:
        if not self.engaged:
            return True
        if self._delete():
            self.engaged = False
            self._publish("HIGH", f"Dead-man isolation released ({reason}).", {"deadman": "released"})
            return True
        self._publish("CRITICAL", "Dead-man isolation rules could not be removed; remove firewall "
                      "rules named Angerona-DeadMan-out and Angerona-DeadMan-in manually.",
                      {"deadman": "release_failed"})
        return False

    def tick(self, core_state: str, standdown: bool = False) -> str:
        now = self._clock()
        if standdown:
            self._down_since = None
            if self.engaged:
                self.release("authenticated stand-down")
            return "standdown"
        if core_state == "alive":
            self._down_since = None
            self._failed = False
            self._notified_unelevated = False
            if self._alive_since is None:
                self._alive_since = now
            if self.engaged and now - self._alive_since >= _RELEASE_AFTER_S:
                self.release("core is running again")
            return "engaged" if self.engaged else "idle"
        self._alive_since = None
        if core_state not in ("dead", "suspended"):
            return "engaged" if self.engaged else "idle"  # starting/unknown: no claim.
        if self._down_since is None:
            self._down_since = now
        if self.engaged or self._failed:
            return "engaged" if self.engaged else "failed"
        policy = self._policy()
        if not policy:
            return "disabled"
        down_for = now - self._down_since
        if down_for < policy["threshold_s"]:
            return "armed"
        if not self._is_admin():
            if not self._notified_unelevated:
                self._notified_unelevated = True
                self._publish("HIGH", "Dead-man isolation is enabled and its threshold passed, but "
                              "this watchdog is not elevated, so no network hold was applied.",
                              {"deadman": "not_elevated", "down_for_s": round(down_for, 1)})
            return "not_elevated"
        self._engage(down_for, policy["threshold_s"])
        return "engaged" if self.engaged else "failed"
