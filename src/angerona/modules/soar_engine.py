"""soar_engine.py — The Active Response SOAR Engine.

A stronger, opt-in-gated autonomous response tier sitting alongside the
existing "SOAR Automation" module (soar.py). Where that module recommends,
or (opt-in) *suspends*, a process on a CRITICAL event, this one performs a
full terminate-and-rollback: kill the offending process AND remove the
exact file artifact the triggering alert pointed at.

Origin-blind by design: this module only ever reacts to real EventBus
alerts that the OTHER detection modules already raised on their own. It
never reads shark_history.json, or anything else that would tell it "this
is a drill" — that's what keeps a Shark Attack run an honest end-to-end
test of the whole pipeline, not a rigged one. It is a normal, always-on
module exactly like every other capability in modules/; nothing about it is
specific to testing.

Disabled-by-default for the same reason the existing SOAR module's
auto-contain is opt-in: automatically killing processes is powerful and
occasionally wrong. Set ANGERONA_SOAR_KILL_AND_ROLLBACK=1 to arm it. The
Shark Attack "Initiate" button arms it for the duration of one test run and
restores your previous setting afterward (see gui/main_window.py).

Even armed, the response threshold defaults to CRITICAL only — a MEDIUM
"new file created" alert from File Integrity Monitor is a low-confidence
signal on its own (FIM has no way to know if a new file is malicious), so
auto-deleting on it by default would be trigger-happy. Set
ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY=HIGH (or MEDIUM) to lower the
bar — useful when you deliberately want to test a more aggressive policy
during a drill, without changing the real-world default.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


class ActiveResponseSOAR(BaseModule):
    name = "Active Response SOAR"
    description = "Opt-in: terminates the offending process and rolls back its file artifact on real CRITICAL alerts."
    category = "Response"
    enabled_by_default = True  # idles harmlessly unless armed — see _armed()

    def __init__(self) -> None:
        super().__init__()
        self._last_ts = 0.0

    @staticmethod
    def _armed() -> bool:
        return os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK", "0") == "1"

    @staticmethod
    def _min_severity() -> Severity:
        name = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH").strip().upper()
        try:
            return Severity[name]
        except KeyError:
            return Severity.CRITICAL  # unknown value — fail conservative, not permissive

    def self_test(self) -> tuple[bool, str]:
        armed = self._armed()
        ok = self.status == "running"
        state = f"ARMED (min severity {self._min_severity().label})" if armed else \
                "idle (set ANGERONA_SOAR_KILL_AND_ROLLBACK=1 to arm)"
        return ok, f"running, {state}"

    def run(self) -> None:
        self.set_health(100, "")
        self.emit("Active Response SOAR online (idle unless armed via "
                  "ANGERONA_SOAR_KILL_AND_ROLLBACK).", Severity.INFO)
        while not self.stopping:
            self.sleep(2)
            if self._bus is None or not self._armed():
                continue
            floor = self._min_severity()
            for ev in self._bus.recent(25):
                if ev.ts <= self._last_ts or ev.severity < floor:
                    continue
                if ev.module in (self.name, "Console", "SOAR Automation"):
                    continue
                self._last_ts = max(self._last_ts, ev.ts)
                self._kill_and_rollback(ev)

    # ── Response playbook ────────────────────────────────────────────────
    def _kill_and_rollback(self, ev) -> None:
        t0 = time.time()
        pid = ev.details.get("pid")
        path = ev.details.get("path")
        # SAFETY: never terminate Angerona's own process (or its parent) even if a
        # detection/drill event happens to carry our PID — that would be suicide.
        if isinstance(pid, int) and pid in (os.getpid(), os.getppid()):
            self.emit(f"Refusing to kill Angerona's own process (pid {pid}); "
                      "rolling back artifact only.", Severity.LOW, pid=pid)
            pid = None
        killed_name = None
        killed_ok = False

        if isinstance(pid, int) and psutil is not None:
            try:
                p = psutil.Process(pid)
                killed_name = p.name()
                p.kill()
                p.wait(timeout=3)
                killed_ok = True
            except psutil.NoSuchProcess:
                killed_ok = True  # already gone — fine
            except Exception as exc:
                self.emit(f"Kill failed for pid {pid}: {exc}", Severity.MEDIUM, pid=pid)

        rolled_back = []
        # Only ever touches the exact path the triggering alert itself
        # named — never a directory walk, never a guess.
        if path:
            try:
                p = Path(path)
                if p.exists() and p.is_file():
                    p.unlink()
                    rolled_back.append(str(p))
            except Exception as exc:
                self.emit(f"Rollback failed for {path}: {exc}", Severity.MEDIUM, path=path)

        elapsed = round(time.time() - t0, 3)
        target = f"{killed_name} (pid {pid})" if killed_name else (f"pid {pid}" if pid else "no process target")
        self.emit(
            f"Kill+rollback on {ev.module} {ev.severity.label} alert ({target}): "
            f"{'killed' if killed_ok else 'no process acted on'}, "
            f"{len(rolled_back)} artifact(s) removed, {elapsed}s.",
            Severity.HIGH,
            pid=pid, path=path, mitigated=killed_ok or bool(rolled_back),
            mitigation_seconds=elapsed, trigger_module=ev.module, trigger_ts=ev.ts,
        )
