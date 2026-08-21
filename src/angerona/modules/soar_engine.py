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
import re
import time
import zipfile
from pathlib import Path

from angerona.core.archive_safety import read_bounded_member, validate_zip_members
from angerona.core.eventbus import is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity
from angerona.core.process_allowlist import (
    is_event_allowed as _process_event_allowed,
    policy_snapshot as _process_policy_snapshot,
)

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
        name = os.environ.get(
            "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "CRITICAL"
        ).strip().upper()
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
            process_policy = _process_policy_snapshot()
            # Drills can emit 50+ marker detections in one FIM cycle. This path
            # is reached only while explicitly armed, so retain enough history
            # to remediate the whole batch rather than only the newest 25.
            for ev in self._bus.recent(250):
                if ev.ts <= self._last_ts or ev.severity < floor:
                    continue
                if ev.module in (self.name, "Console", "SOAR Automation"):
                    continue
                self._last_ts = max(self._last_ts, ev.ts)
                if is_remote_observe_only(ev):
                    continue
                if _process_event_allowed(ev, policy=process_policy):
                    continue
                if not self._event_in_response_scope(ev):
                    continue
                self._kill_and_rollback(ev)

    # ── Response playbook ────────────────────────────────────────────────
    @staticmethod
    def _event_path(ev) -> str:
        details = getattr(ev, "details", {}) or {}
        for key in ("path", "artifact_path", "exe", "process_path", "image"):
            value = details.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _scope_roots() -> tuple[Path, ...]:
        raw = os.environ.get("ANGERONA_SOAR_RESPONSE_SCOPE", "").strip()
        if not raw:
            return ()
        roots = []
        for value in raw.split(os.pathsep):
            try:
                roots.append(Path(value.strip()).expanduser().resolve(strict=False))
            except (OSError, RuntimeError, ValueError):
                continue
        return tuple(roots)

    @staticmethod
    def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
        try:
            resolved = path.resolve(strict=False)
            return any(resolved == root or root in resolved.parents for root in roots)
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _is_known_drill_artifact(path: Path) -> bool:
        """Prove a scoped file is one of Angerona's inert drill markers."""
        name = path.name.casefold()
        if name.startswith(("_redteam_", "_shark_")):
            return True
        try:
            if path.suffix.casefold() == ".zip":
                with zipfile.ZipFile(path) as archive:
                    members = validate_zip_members(
                        archive.infolist(),
                        max_files=20,
                        max_member_bytes=262_144,
                        max_total_bytes=5 * 1024 * 1024,
                        max_ratio=100,
                    )
                    for member in members:
                        sample = read_bounded_member(
                            archive,
                            member,
                            max_bytes=262_144,
                        )
                        if b"Angerona Shark Attack drill sample" in sample:
                            return True
                return False
            if path.stat().st_size > 262_144:
                return False
            sample = path.read_bytes()
        except (OSError, ValueError, zipfile.BadZipFile):
            return False
        return any(
            marker in sample
            for marker in (
                b"Angerona Shark Attack drill sample",
                b"simulated persistence artifact",
                b"ANGERONA custom drill marker",
                b"simulated BYOVD driver drop",
            )
        )

    def _event_in_response_scope(self, ev) -> bool:
        """Constrain temporary drill arming to proven drill evidence."""
        roots = self._scope_roots()
        if not roots:
            return True
        details = getattr(ev, "details", {}) or {}
        command = str(details.get("cmdline") or details.get("command_line") or "")
        if re.search(r"\bANGERONA_REDTEAM_[0-9a-f]{8}\b", command, re.I):
            return True
        raw_path = self._event_path(ev)
        if not raw_path:
            return False
        path = Path(raw_path)
        return self._inside(path, roots) and self._is_known_drill_artifact(path)

    def _event_integrity_ok(self, ev) -> bool:
        """Re-verify authenticated evidence immediately before host mutation."""
        bus = self._bus
        if bus is None or not getattr(bus, "integrity_enabled", False):
            return True
        try:
            return bool(bus.verify(ev))
        except Exception:
            return False

    def _kill_and_rollback(self, ev) -> None:
        if not self._event_integrity_ok(ev):
            self.emit(
                "Refusing kill/rollback: event integrity verification failed.",
                Severity.HIGH,
            )
            return
        if is_remote_observe_only(ev):
            self.emit(
                "Refusing local kill/rollback for observe-only cross-host evidence.",
                Severity.INFO,
            )
            return
        if not self._event_in_response_scope(ev):
            self.emit(
                "Refusing kill/rollback: event is outside the authorized response scope.",
                Severity.INFO,
            )
            return
        t0 = time.time()
        pid = ev.details.get("pid")
        path = self._event_path(ev) or None
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
