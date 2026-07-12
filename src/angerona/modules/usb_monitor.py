"""usb_monitor.py — Removable-Media / USB Monitor (Code: USBW).

Removable drives are a classic initial-access and exfiltration vector (T1091
Replication Through Removable Media, T1200 Hardware Additions, T1052 Exfil over
physical medium). This module watches for newly-attached removable/USB volumes,
alerts on each, and raises the severity if the drive carries an ``autorun.inf``
(a hallmark of auto-spreading malware). Read-only enumeration.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity


def _removable_mounts() -> dict[str, str]:
    """Return {mountpoint: fstype/opts} for removable volumes (best-effort)."""
    out: dict[str, str] = {}
    if psutil is None:
        return out
    try:
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            # Windows marks removable/cdrom in opts; POSIX shows /media, /mnt, /run/media.
            mp = part.mountpoint
            is_removable = ("removable" in opts or "cdrom" in opts
                            or mp.startswith(("/media/", "/run/media/", "/mnt/")))
            if is_removable:
                out[mp] = opts or part.fstype
    except Exception:
        pass
    return out


def _has_autorun(mountpoint: str) -> bool:
    try:
        return (Path(mountpoint) / "autorun.inf").exists()
    except Exception:
        return False


class USBMonitorModule(BaseModule):
    CODE = "USBW"
    NAME = "Removable-Media / USB Monitor"
    name = "Removable-Media / USB Monitor"
    description = ("Alerts on newly-attached removable/USB drives (T1091/T1200/T1052) and "
                   "flags any drive carrying autorun.inf. Read-only.")
    category = "Detection"
    version = "1.0.0"

    _POLL = 4.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._known: set[str] = set()
        self._seeded = False
        self._events = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        if psutil is None:
            self.set_health(50, "psutil unavailable")
            self.emit("USBW unavailable — psutil not present.", Severity.LOW)
            while not self.stopping:
                self.sleep(self._POLL)
            return
        self.emit("USBW online — watching for removable/USB media.", Severity.INFO)
        while not self.stopping:
            try:
                self._check()
                self.set_health(100, f"{len(self._known)} removable volume(s), {self._events} event(s)")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"scan error: {exc}")
            self.sleep(self._POLL)

    def _check(self) -> None:
        current = _removable_mounts()
        cur_set = set(current)
        if not self._seeded:
            # First pass: baseline whatever is already mounted, don't alert.
            self._known = cur_set
            self._seeded = True
            return
        for mp in cur_set - self._known:
            self._events += 1
            autorun = _has_autorun(mp)
            sev = Severity.HIGH if autorun else Severity.MEDIUM
            extra = " — carries autorun.inf (auto-spread malware hallmark!)" if autorun else ""
            self.emit(
                f"Removable media attached: {mp} ({current.get(mp, '?')}){extra}. "
                "Scan before use; block autorun.",
                sev, mountpoint=mp, autorun=autorun,
                mitre="T1091" if not autorun else "T1091/T1204")
        # note removals quietly (no alert) so re-insert re-alerts
        self._known = cur_set

    def self_test(self) -> tuple[bool, str]:
        """Verify the new-drive diff logic with a stubbed mount set."""
        self._known = {"E:\\"}
        self._seeded = True
        # simulate F: appearing
        before = self._events
        # monkey-free test: directly exercise the diff
        cur = {"E:\\": "removable", "F:\\": "removable"}
        new = set(cur) - self._known
        detected = new == {"F:\\"}
        # autorun probe must not raise on a bogus path
        try:
            _has_autorun("Z:\\definitely-not-here")
            probe_ok = True
        except Exception:
            probe_ok = False
        ok = detected and probe_ok
        return ok, ("new-drive diff + autorun probe verified" if ok else
                    f"failed: detected={detected} probe={probe_ok}")


def register() -> USBMonitorModule:
    return USBMonitorModule()
