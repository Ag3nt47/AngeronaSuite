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

import base64
import ctypes
import json
import math
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

RULES = (("Angerona-DeadMan-out", "out"), ("Angerona-DeadMan-in", "in"))
_RELEASE_AFTER_S = 15.0
_CLEANUP_RETRY_S = 15.0
_UNKNOWN_QUERY_RETRY_S = 300.0
_CLEANUP_NOTICE_REPEAT_S = 900.0
PRESENT, ABSENT, UNAVAILABLE = "present", "absent", "unavailable"
_QUERY_TIMEOUT_S = 5.0
_MAX_QUERY_BYTES = 1024


def _netsh(arguments: list[str], *, timeout: float = 20.0) -> bool:
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        return False
    if os.name != "nt":
        return False
    buffer = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260):
        return False
    try:
        result = subprocess.run([str(Path(buffer.value) / "netsh.exe"), *arguments],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=min(timeout, 20.0),
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0



# Only fixed local PersistentStore rules written by netsh are queried. Successful
# complete enumeration proves absence; any provider error/budget hit is unknown.
_RULE_QUERY = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$PSModuleAutoLoadingPreference='None'
try {
    $modules=[IO.Path]::Combine($PSHOME,'Modules')
    Microsoft.PowerShell.Core\Import-Module ([IO.Path]::Combine($modules,'CimCmdlets','CimCmdlets.psd1')) -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module ([IO.Path]::Combine($modules,'NetSecurity','NetSecurity.psd1')) -ErrorAction Stop
    $script:out='absent'; $script:in='absent'; $script:count=0
    $script:outCount=0; $script:inCount=0
    NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
        Microsoft.PowerShell.Core\ForEach-Object {
            if (++$script:count -gt 4096) { throw 'owned-rule query budget exceeded' }
            if ([string]::Equals([string]$_.DisplayName,'Angerona-DeadMan-out',[StringComparison]::OrdinalIgnoreCase)) {
                if (++$script:outCount -gt 1) { throw 'ambiguous owned outbound rule' }
                $script:out='present'
            }
            if ([string]::Equals([string]$_.DisplayName,'Angerona-DeadMan-in',[StringComparison]::OrdinalIgnoreCase)) {
                if (++$script:inCount -gt 1) { throw 'ambiguous owned inbound rule' }
                $script:in='present'
            }
        }
    [Console]::Out.Write('{"schema":1,"states":{"Angerona-DeadMan-out":"'+$script:out+'","Angerona-DeadMan-in":"'+$script:in+'"}}')
    exit 0
} catch {
    exit 1
}
"""



def _unique_query_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate rule-query field")
        value[key] = item
    return value


def _query_owned_rules(*, timeout: float = _QUERY_TIMEOUT_S) -> dict[str, str]:
    """Read structured local rule presence; native unavailability is not absence.

    No caller input or ambient module search selects code. This checks local
    persistence only, not effective GPO merge, filter correctness or enforcement.
    """
    unknown = {name: UNAVAILABLE for name, _direction in RULES}
    if (os.name != "nt" or type(timeout) not in (int, float)
            or not math.isfinite(timeout) or timeout <= 0):
        return unknown
    try:
        from angerona.core.privilege import sanitized_child_environment, trusted_powershell_path

        host = trusted_powershell_path()
        environment = sanitized_child_environment()
        environment["PSModulePath"] = str(host.parent / "Modules")
        result = subprocess.run(
            [str(host), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
             base64.b64encode(_RULE_QUERY.encode("utf-16-le")).decode("ascii")],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=environment, timeout=min(timeout, _QUERY_TIMEOUT_S),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
        if result.returncode != 0 or not isinstance(result.stdout, bytes) or len(result.stdout) > _MAX_QUERY_BYTES:
            return unknown
        value = json.loads(result.stdout.decode("utf-8-sig"), object_pairs_hook=_unique_query_object)
        states = value.get("states") if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 1 else None
        if (type(states) is not dict or set(states) != set(unknown)
                or any(state not in (PRESENT, ABSENT) for state in states.values())):
            return unknown
        return states
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        return unknown


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
                 runner: Optional[Callable[[list[str]], bool]] = None,
                 probe: Optional[Callable[[], dict[str, str]]] = None,
                 engage_allowed: Optional[Callable[[], bool]] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._publish = publish
        self._policy = policy
        self._is_admin = is_admin
        self._run = _netsh if runner is None else runner
        # Boolean show results remain only an injected legacy test seam.
        self._probe = probe if probe is not None else (_query_owned_rules if runner is None else self._legacy_probe)
        self._clock = clock
        self._engage_allowed = engage_allowed or (lambda: True)
        self._down_since: Optional[float] = None
        self._alive_since: Optional[float] = None
        self._notified_unelevated = False
        self._failed = False
        # Any surviving owned rule needs retirement, including a partial apply.
        self._last_cleanup_attempt = None
        self._standdown_observed = False
        self._policy_cleanup_requested = False
        self._owned_rule_evidence = False
        self._cleanup_notice_key = None
        self._cleanup_notice_at = None
        self._cleanup_notice_suppressed = 0
        self._native_probe_pending = probe is None and runner is None
        # Construction may run on a GUI/startup path. Only injected probes run
        # synchronously here; default native measurement belongs to the first
        # watchdog-owner tick. Until then presence is explicitly unmeasured.
        initial = ({name: UNAVAILABLE for name, _direction in RULES}
                   if self._native_probe_pending else self._presence())
        self._cleanup_pending = any(state != ABSENT for state in initial.values())
        self.engaged = all(state == PRESENT for state in initial.values())

    def _legacy_probe(self) -> dict[str, str]:
        """Adapter for existing inert bool runners, never the production probe."""
        states = {}
        for name, _direction in RULES:
            try:
                value = self._run(["advfirewall", "firewall", "show", "rule", f"name={name}"])
                states[name] = PRESENT if value is True else ABSENT if value is False else UNAVAILABLE
            except Exception:
                states[name] = UNAVAILABLE
        return states

    def _presence(self) -> dict[str, str]:
        self._native_probe_pending = False
        unknown = {name: UNAVAILABLE for name, _direction in RULES}
        try:
            states = self._probe()
            if (type(states) is dict and set(states) == set(unknown)
                    and all(type(state) is str and state in (PRESENT, ABSENT, UNAVAILABLE)
                            for state in states.values())):
                if any(state == PRESENT for state in states.values()):
                    self._owned_rule_evidence = True
                return states
        except Exception:
            pass
        return unknown

    def _present(self) -> bool:
        return all(state == PRESENT for state in self._presence().values())

    def _delete(self, before=None) -> bool:
        before = self._presence() if before is None else before
        if not any(state == PRESENT for state in before.values()):
            return all(state == ABSENT for state in before.values())
        ok = True
        for name, _direction in RULES:
            if before[name] == UNAVAILABLE:
                ok = False  # Uncertainty grants no deletion authority.
            elif before[name] == PRESENT:
                try:
                    ok = self._run(["advfirewall", "firewall", "delete", "rule", f"name={name}"]) is True and ok
                except Exception:
                    ok = False
        after = self._presence()
        # Both exact names need a successful absence observation. Even a
        # successful delete followed by a failed query remains cleanup pending.
        return ok and all(state == ABSENT for state in after.values())

    def _engage(self, down_for: float, threshold: float) -> None:
        self._cleanup_pending = True
        self._cleanup_notice_key = None
        self._cleanup_notice_at = None
        self._cleanup_notice_suppressed = 0
        for name, direction in RULES:
            if not self._engage_allowed():
                break
            self._owned_rule_evidence = True  # Own dispatched effects require verified retirement.
            try:
                self._run(["advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                           "action=block", "remoteip=any", "enable=yes", "profile=any"])
            except Exception:
                pass  # Readback and rollback still run for both exact owned names.
        if self._engage_allowed() and self._present() and self._engage_allowed():
            self.engaged = True
            self._publish("CRITICAL", "Dead-man local block rules configured: the core has been down for "
                          f"{down_for:.0f}s (threshold {threshold:.0f}s). Effective platform enforcement "
                          "is not independently verified.",
                          {"deadman": "engaged", "down_for_s": round(down_for, 1),
                           "rules": [name for name, _ in RULES], "enforcement_verified": False,
                           "disposition": "observation", "response_authorized": False})
            return
        rolled_back = self._delete()
        self._cleanup_pending = not rolled_back
        self._owned_rule_evidence = not rolled_back
        self._last_cleanup_attempt = self._clock()
        if not rolled_back:
            self._cleanup_notice_key = (True, "cleanup-unverified")
            self._cleanup_notice_at = self._last_cleanup_attempt
        self._failed = True  # Do not add again every tick; cleanup remains retryable.
        self._publish("HIGH" if rolled_back else "CRITICAL",
                      "Dead-man isolation could not be verified; rollback completed." if rolled_back else
                      "Dead-man isolation could not be verified; owned firewall-rule cleanup remains unverified.",
                      {"deadman": "failed", "rolled_back": rolled_back})

    def _cleanup_notice(self, cause: str) -> None:
        now = self._clock()
        key = (self._owned_rule_evidence, cause)
        if (key == self._cleanup_notice_key and self._cleanup_notice_at is not None
                and 0 <= now - self._cleanup_notice_at < _CLEANUP_NOTICE_REPEAT_S):
            self._cleanup_notice_suppressed += 1
            return
        repeats = self._cleanup_notice_suppressed if key == self._cleanup_notice_key else 0
        self._cleanup_notice_key, self._cleanup_notice_at = key, now
        self._cleanup_notice_suppressed = 0
        known = self._owned_rule_evidence
        self._publish("CRITICAL" if known else "MEDIUM",
                      "Owned dead-man rule cleanup remains unverified; review the fixed firewall rules." if known else
                      "Dead-man rule presence is unavailable; cleanup ownership is unestablished. Read-only checks will retry.",
                      {"deadman": "release_failed" if known else "coverage_unavailable",
                       "cleanup_pending": True, "owned_rule_evidence": known, "cause": cause,
                       "repeats_since_last_report": repeats, "repeat_unit": "notification-opportunities",
                       "enforcement_verified": False, "disposition": "health", "response_authorized": False})

    def release(self, reason: str) -> bool:
        if not self.engaged and not self._cleanup_pending:
            return True
        self._last_cleanup_attempt = self._clock()
        before = self._presence()
        if all(state == ABSENT for state in before.values()):
            verified_absence = True
        elif not any(state == PRESENT for state in before.values()):
            self._cleanup_notice("query-unavailable")
            return False
        elif not self._is_admin():
            self._cleanup_notice("elevation-unavailable")
            return False
        else:
            verified_absence = self._delete(before)
        if verified_absence:
            known = self._owned_rule_evidence
            self.engaged = False
            self._cleanup_pending = False
            self._owned_rule_evidence = False
            self._cleanup_notice_key = None
            self._cleanup_notice_at = None
            self._cleanup_notice_suppressed = 0
            self._publish("HIGH" if known else "MEDIUM",
                          f"Dead-man isolation released ({reason})." if known else
                          "Dead-man coverage check recovered: both fixed local rule names are absent.",
                          {"deadman": "released" if known else "coverage_available",
                           "disposition": "observation", "response_authorized": False})
            return True
        self._cleanup_notice("cleanup-unverified")
        return False

    def _retry_release(self, reason: str, now: float) -> bool:
        retry = _CLEANUP_RETRY_S if self._owned_rule_evidence else _UNKNOWN_QUERY_RETRY_S
        if (self._last_cleanup_attempt is None or now < self._last_cleanup_attempt
                or now - self._last_cleanup_attempt >= retry):
            return self.release(reason)
        if self.engaged or self._cleanup_pending:
            cause = self._cleanup_notice_key[1] if self._cleanup_notice_key else "query-unavailable"
            self._cleanup_notice(cause)
        return not (self.engaged or self._cleanup_pending)

    def observe_alive_boundary(self) -> None:
        """Preserve an observed alive transition even when later states coalesce."""
        self._down_since = None
        self._alive_since = None
        self._failed = False
        self._notified_unelevated = False

    def tick(self, core_state: str, standdown: bool = False) -> str:
        now = self._clock()
        if standdown:
            self._down_since = None
            if not self._standdown_observed:
                self._standdown_observed = True
                self.release("authenticated stand-down")
            else:
                self._retry_release("authenticated stand-down", now)
            return "failed" if self.engaged or self._cleanup_pending else "standdown"
        self._standdown_observed = False
        if self._native_probe_pending:
            measured = self._presence()
            self._cleanup_pending = any(state != ABSENT for state in measured.values())
            self.engaged = all(state == PRESENT for state in measured.values())
            if self._cleanup_pending and not self._owned_rule_evidence:
                self._last_cleanup_attempt = now
                self._policy_cleanup_requested = True
                self._cleanup_notice("query-unavailable")
        policy = self._policy()
        if not policy and (self.engaged or self._cleanup_pending):
            if not self._policy_cleanup_requested:
                self._policy_cleanup_requested = True
                self.release("administrator policy is disabled or unavailable")
            else:
                self._retry_release("administrator policy is disabled or unavailable", now)
            return "failed" if self.engaged or self._cleanup_pending else "disabled"
        if policy:
            self._policy_cleanup_requested = False
        if core_state == "alive":
            self._down_since = None
            self._failed = False
            self._notified_unelevated = False
            if self._alive_since is None:
                self._alive_since = now
            if (self.engaged or self._cleanup_pending) and now - self._alive_since >= _RELEASE_AFTER_S:
                self._retry_release("core is running again", now)
            return "engaged" if self.engaged else "failed" if self._cleanup_pending else "idle"
        self._alive_since = None
        if self._cleanup_pending and not self.engaged:
            self._retry_release("partial or failed isolation", now)
            return "failed"
        if core_state not in ("dead", "suspended"):
            return "engaged" if self.engaged else "idle"  # starting/unknown: no claim.
        if self._down_since is None:
            self._down_since = now
        if self.engaged or self._failed:
            return "engaged" if self.engaged else "failed"
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


class DeadManOwner:
    """One bounded worker; callers submit state without native I/O or waiting.

    STOP is terminal. Already dispatched native calls may finish after the fence;
    their exact fixed-rule compensation stays on this owner until verified or the
    shutdown budget expires. Native timeouts retain subprocess.run's kill/wait
    handling. Neither worker completion nor local presence attests enforcement.
    """

    def __init__(self, publish, *, factory=DeadMan, runner=None, probe=None,
                 clock=time.monotonic, stop_budget_s=60.0, state_max_age_s=10.0):
        if not 0 < stop_budget_s <= 60.0 or not 0 < state_max_age_s <= 30.0:
            raise ValueError("invalid dead-man owner budget")
        self._publish = publish
        self._factory, self._runner, self._probe_reader = factory, runner, probe
        self._clock = clock
        self._stop_budget_s, self._state_max_age_s = stop_budget_s, state_max_age_s
        self._lock = threading.Lock()
        self._wake, self._stop, self._done = threading.Event(), threading.Event(), threading.Event()
        self._latest = None
        self._alive_serial = 0
        self._work_epoch = None
        self._deadline = None
        self._reason = "watchdog shutdown"
        self._thread = None
        self._cached = {"state": "unmeasured", "cleanup_pending": True,
                        "owned_rule_evidence": False, "native_work": "idle",
                        "worker_retired": False, "enforcement_verified": False}

    def _now(self):
        try:
            now = self._clock()
            return now if type(now) in (int, float) and math.isfinite(now) and now >= 0 else None
        except Exception:
            return None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="deadman-owner", daemon=True)
            self._thread.start()

    def submit(self, core_state):
        state = core_state if type(core_state) is str and len(core_state) <= 64 else "unknown"
        now = self._now()
        with self._lock:
            if self._stop.is_set() or self._done.is_set():
                return False
            previous = self._latest
            epoch = previous[1] if previous is not None else 0
            if previous is None or previous[0] != state:
                epoch += 1
                if state == "alive":
                    self._alive_serial += 1
            self._latest = (state, epoch, self._alive_serial, now)
        self._wake.set()
        return True

    def request_stop(self, reason="watchdog shutdown"):
        with self._lock:
            if not self._stop.is_set():
                now = self._now()
                self._deadline = now + self._stop_budget_s if now is not None else 0.0
                self._reason = str(reason)[:80]
                self._stop.set()
        self._wake.set()

    def snapshot(self):
        return dict(self._cached)

    @property
    def done(self):
        return self._done.is_set()

    def shutdown_expired(self, grace=0.0):
        now = self._now()
        return self._stop.is_set() and (now is None or now >= self._deadline + grace)

    def join(self, timeout=0.0):
        if self._thread is not None:
            self._thread.join(timeout=max(0.0, min(float(timeout), 2.0)))
        return self.done

    def _timeout(self, maximum):
        if not self._stop.is_set():
            return maximum
        now = self._now()
        if now is None or now >= self._deadline:
            raise TimeoutError("dead-man shutdown work budget expired")
        return min(maximum, self._deadline - now)

    def _may_engage(self):
        latest, now = self._latest, self._now()
        return (not self._stop.is_set() and latest is not None and now is not None
                and latest[0] in ("dead", "suspended") and latest[1] == self._work_epoch
                and latest[3] is not None and 0 <= now - latest[3] <= self._state_max_age_s)

    def _mutate(self, arguments):
        if arguments[2] == "add" and not self._may_engage():
            return False
        timeout = self._timeout(20.0)
        if self._runner is not None:
            return self._runner(arguments)
        return _netsh(arguments, timeout=timeout)

    def _query(self):
        timeout = self._timeout(_QUERY_TIMEOUT_S)
        return self._probe_reader() if self._probe_reader is not None else _query_owned_rules(timeout=timeout)

    def _update(self, value, state, work="idle"):
        self._cached = {"state": state, "cleanup_pending": bool(value._cleanup_pending),
                        "owned_rule_evidence": bool(value._owned_rule_evidence),
                        "native_work": work, "worker_retired": False,
                        "enforcement_verified": False}

    def _report_unresolved(self, value, cause):
        details = {"deadman": "cleanup_unresolved", "cleanup_pending": True,
                   "owned_rule_evidence": bool(value and value._owned_rule_evidence),
                   "cause": cause, "enforcement_verified": False,
                   "disposition": "health", "response_authorized": False}
        self._cached = dict(details, state="cleanup-unresolved", native_work="idle", worker_retired=False)
        try:
            self._publish("CRITICAL" if details["owned_rule_evidence"] else "MEDIUM",
                          "Dead-man owner stopped without verified rule absence; cleanup remains unresolved.", details)
        except Exception:
            pass

    def _run(self):
        value = None
        handled_alive = 0
        try:
            while True:
                self._wake.wait(timeout=1.0 if self._stop.is_set() else None)
                self._wake.clear()
                if self.shutdown_expired():
                    self._report_unresolved(value, "shutdown-budget-expired")
                    return
                latest = self._latest
                if latest is None and not self._stop.is_set():
                    continue
                self._work_epoch = latest[1] if latest is not None else None
                if value is None:
                    self._cached = dict(self._cached, native_work="active")
                    value = self._factory(self._publish, runner=self._mutate, probe=self._query,
                                          engage_allowed=self._may_engage, clock=self._clock)
                if self._stop.is_set():
                    self._update(value, "cleanup-pending", "active")
                    result = value.tick("stopped", standdown=True)
                    self._update(value, result)
                    if not value._cleanup_pending and not value.engaged:
                        return
                    continue
                # A state change during factory/probe work invalidates old work.
                if latest != self._latest:
                    self._wake.set()
                    continue
                if latest[2] != handled_alive:
                    value.observe_alive_boundary()
                    handled_alive = latest[2]
                self._update(value, self._cached["state"], "active")
                result = value.tick(latest[0])
                self._update(value, result)
                if self._stop.is_set():
                    self._wake.set()
        except Exception as exc:
            self._report_unresolved(value, type(exc).__name__)
        finally:
            self._cached = dict(self._cached, native_work="retired", worker_retired=True)
            self._done.set()
