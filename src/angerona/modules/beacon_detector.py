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
from dataclasses import dataclass

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity
from angerona.core.response_contract import process_and_remote_response
from angerona.modules.intel_sync import is_ip_flagged
from angerona.telemetry.sensors import list_connections

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


@dataclass(frozen=True)
class BeaconPollReceipt:
    complete: bool
    observed: int
    identity_failures: int
    error: str = ""


class BeaconDetectorModule(BaseModule):
    CODE = "BEAC"
    NAME = "C2 Beacon Detector"
    name = "C2 Beacon Detector"
    description = ("Flags regular-interval outbound callbacks (command-and-control "
                   "beaconing, T1071/T1571) by timing per-process connections to a host.")
    category = "Detection"
    version = "1.13.0"

    _POLL = 5.0
    _HISTORY = 12          # keep up to this many callback timestamps per (name,ip)
    _EVICT_AFTER = 2 * 3600.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._seen_last: set[tuple] = set()          # (pid, ip) seen on the previous poll
        # Exact process instance + peer. Name-only grouping lets unrelated
        # same-name processes fabricate one apparent cadence, and PID-only
        # grouping crosses Windows PID reuse.
        self._callbacks: dict[tuple, list[float]] = {}
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
                receipt = self._poll_once()
                if receipt.complete:
                    self.set_health(
                        100,
                        f"complete snapshot ({receipt.observed} rows); "
                        f"{self._detections} beacon pattern(s) flagged",
                    )
                else:
                    self.set_health(
                        65,
                        "connection coverage incomplete: "
                        f"{receipt.error or 'identity evidence unavailable'}; "
                        f"rows={receipt.observed}, identity_failures="
                        f"{receipt.identity_failures}",
                    )
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"scan error: {exc}")
            self.sleep(self._POLL)

    def _poll_once(self) -> BeaconPollReceipt:
        now = time.time()
        current: set[tuple] = set()
        names: dict[int, str] = {}
        create_times: dict[int, float] = {}
        identity_attempted: set[int] = set()
        try:
            # Reuse the suite's short-lived connection snapshot. Network
            # Monitor and Counter-Agentic inspect the same OS table on nearby
            # cadences; independently enumerating it is expensive on Windows.
            conns = list_connections()
        except Exception as exc:
            return BeaconPollReceipt(False, 0, 0, str(exc)[:500])
        snapshot = getattr(conns, "receipt", None)
        snapshot_complete = bool(getattr(snapshot, "complete", True))
        snapshot_error = str(getattr(snapshot, "error", "") or "")[:500]
        identity_failures = 0
        for c in conns:
            raddr = c.get("raddr") or ""
            if not raddr or c.get("status") not in ("ESTABLISHED", "SYN_SENT"):
                continue
            ip = raddr.rsplit(":", 1)[0]
            pid = c.get("pid")
            if not _is_external(ip) or not pid:
                continue
            current.add((pid, ip))
            if pid not in identity_attempted:
                identity_attempted.add(pid)
                try:
                    process = psutil.Process(pid)
                    created = float(process.create_time())
                    name = str(process.name() or "?")[:260]
                    if float(process.create_time()) != created:
                        raise ValueError("process generation changed during lookup")
                    names[pid] = name
                    create_times[pid] = created
                except Exception:
                    identity_failures += 1
        # A NEW connection = present now but not on the previous poll.
        for (pid, ip) in current - self._seen_last:
            created = create_times.get(pid)
            if created is None:
                # A cadence without a process birth time cannot be bound to one
                # process instance and therefore cannot authorize containment.
                continue
            key = (pid, created, names.get(pid, "?"), ip)
            hist = self._callbacks.setdefault(key, [])
            hist.append(now)
            if len(hist) > self._HISTORY:
                del hist[:-self._HISTORY]
            is_b, mean, cv = _beacon_score(hist)
            if is_b and key not in self._alerted:
                self._alerted.add(key)
                self._detections += 1
                corroborated = is_ip_flagged(ip)
                response = (
                    process_and_remote_response(pid, created, ip)
                    if corroborated
                    else {}
                )
                self.emit(
                    f"⚠ Possible C2 beacon: {key[2]} → {ip} — {len(hist)} callbacks at a "
                    f"regular ~{mean:.0f}s cadence (jitter cv={cv:.2f}). Investigate the "
                    "destination; block if it is an unknown external host.",
                    Severity.HIGH, name=key[2], pid=pid,
                    process_create_time=created, remote=ip,
                    interval_s=round(mean, 1), cv=round(cv, 3), mitre="T1071",
                    active_attack=True,
                    threat_intel_corroborated=corroborated,
                    detector_policy=(
                        "cadence-plus-threat-intel"
                        if corroborated
                        else "cadence-indicator-alert-only"
                    ),
                    **response)
        # An incomplete table must not be mistaken for closed sockets; retain
        # the previous complete state so recovery does not fabricate "new"
        # callbacks from rows that were merely absent during a failed scan.
        if snapshot_complete:
            self._seen_last = current
        # evict stale history
        for key, hist in list(self._callbacks.items()):
            if hist and now - hist[-1] > self._EVICT_AFTER:
                del self._callbacks[key]
                self._alerted.discard(key)
        errors = [value for value in (snapshot_error,) if value]
        if identity_failures:
            errors.append(f"{identity_failures} process identity lookup(s) failed")
        return BeaconPollReceipt(
            snapshot_complete and identity_failures == 0,
            len(conns),
            identity_failures,
            "; ".join(errors)[:500],
        )

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
