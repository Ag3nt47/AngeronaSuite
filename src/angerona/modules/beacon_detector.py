"""beacon_detector.py — C2 Beacon Detector (Code: BEAC).

Command-and-control malware "beacons": it calls out to its C2 server on a
regular cadence (every N seconds/minutes, often with a little jitter). Angerona
already sees outbound connections; this module watches, per (process → remote
host), the timing of repeated NEW connections and flags a destination whose
callbacks are suspiciously regular — the signature of automated beaconing
(T1071 / T1571) rather than normal bursty human/app traffic.

Heuristic: collect the timestamps at which a process opens a NEW connection to a
given remote IP. Once there are enough callbacks, if the inter-arrival intervals
are tight (low coefficient of variation) and in a plausible beacon band, raise an
alert. Read-only; no host change.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import threading
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity

# Beacon band + regularity thresholds.
_MIN_CALLBACKS   = 4       # need at least this many callbacks to judge
_MIN_INTERVAL_S  = 3.0     # ignore sub-3s chatter
_MAX_INTERVAL_S  = 3600.0  # ignore >1h (too slow to distinguish here)
_MAX_CV          = 0.25    # coefficient of variation below this ⇒ "regular"
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fe80:")


def _is_external(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("172."):
        try:
            return not (16 <= int(ip.split(".")[1]) <= 31)
        except Exception:
            return True
    return not ip.startswith(_PRIVATE_PREFIXES)


def _beacon_score(timestamps: list[float]) -> tuple[bool, float, float]:
    """Given callback timestamps, return (is_beacon, mean_interval, cv)."""
    if len(timestamps) < _MIN_CALLBACKS:
        return False, 0.0, 1.0
    ts = sorted(timestamps)
    intervals = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(intervals) < _MIN_CALLBACKS - 1:
        return False, 0.0, 1.0
    mean = sum(intervals) / len(intervals)
    if mean < _MIN_INTERVAL_S or mean > _MAX_INTERVAL_S:
        return False, mean, 1.0
    var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    cv = (var ** 0.5) / mean if mean else 1.0
    return (cv <= _MAX_CV), mean, cv


class BeaconDetectorModule(BaseModule):
    CODE = "BEAC"
    NAME = "C2 Beacon Detector"
    name = "C2 Beacon Detector"
    description = ("Flags regular-interval outbound callbacks (command-and-control "
                   "beaconing, T1071/T1571) by timing per-process connections to a host.")
    category = "Detection"
    version = "1.0.0"

    _POLL = 5.0
    _HISTORY = 12          # keep up to this many callback timestamps per (name,ip)
    _EVICT_AFTER = 2 * 3600.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._seen_last: set[tuple] = set()          # (pid, ip) seen on the previous poll
        self._callbacks: dict[tuple, list[float]] = {}   # (name, ip) -> [ts, ...]
        self._alerted: set[tuple] = set()
        self._detections = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        if psutil is None:
            self.set_health(50, "psutil unavailable")
            self.emit("BEAC unavailable — psutil not present.", Severity.LOW)
            while not self.stopping:
                self.sleep(self._POLL)
            return
        self.emit("BEAC online — watching for C2 beaconing cadence.", Severity.INFO)
        while not self.stopping:
            try:
                self._poll_once()
                self.set_health(100, f"{self._detections} beacon pattern(s) flagged")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"scan error: {exc}")
            self.sleep(self._POLL)

    def _poll_once(self) -> None:
        now = time.time()
        current: set[tuple] = set()
        names: dict[int, str] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        for c in conns:
            if not c.raddr or c.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            ip = getattr(c.raddr, "ip", "")
            if not _is_external(ip) or not c.pid:
                continue
            current.add((c.pid, ip))
            if c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except Exception:
                    names[c.pid] = "?"
        # A NEW connection = present now but not on the previous poll.
        for (pid, ip) in current - self._seen_last:
            key = (names.get(pid, "?"), ip)
            hist = self._callbacks.setdefault(key, [])
            hist.append(now)
            if len(hist) > self._HISTORY:
                del hist[:-self._HISTORY]
            is_b, mean, cv = _beacon_score(hist)
            if is_b and key not in self._alerted:
                self._alerted.add(key)
                self._detections += 1
                self.emit(
                    f"⚠ Possible C2 beacon: {key[0]} → {ip} — {len(hist)} callbacks at a "
                    f"regular ~{mean:.0f}s cadence (jitter cv={cv:.2f}). Investigate the "
                    "destination; block if it is an unknown external host.",
                    Severity.HIGH, name=key[0], remote=ip, interval_s=round(mean, 1),
                    cv=round(cv, 3), mitre="T1071")
        self._seen_last = current
        # evict stale history
        for key, hist in list(self._callbacks.items()):
            if hist and now - hist[-1] > self._EVICT_AFTER:
                del self._callbacks[key]
                self._alerted.discard(key)

    def self_test(self) -> tuple[bool, str]:
        # Regular cadence (every 60s) → beacon; jittery human traffic → not.
        beacon = [1000 + 60 * i for i in range(6)]
        human = [1000, 1063, 1090, 1400, 1405, 2000]
        b_ok, mean, cv = _beacon_score(beacon)
        h_ok, _, _ = _beacon_score(human)
        ext_ok = _is_external("8.8.8.8") and not _is_external("192.168.1.5") \
            and not _is_external("10.0.0.1")
        ok = b_ok and not h_ok and ext_ok
        return ok, (f"beacon cadence detected (mean={mean:.0f}s cv={cv:.2f}), human traffic "
                    "ignored, external-IP test OK" if ok else
                    f"failed: beacon={b_ok} human_flagged={h_ok} ext={ext_ok}")


def register() -> BeaconDetectorModule:
    return BeaconDetectorModule()
