"""Bounded private attempt receipt for automatic spyware scans.

The caller owns readiness, idle admission, cancellation and scan execution.
Both operations are synchronous and belong on the existing scanner worker.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
import json
from pathlib import Path
import time

from angerona.core.config import SPYWARE_SCAN_AUTO_SCOPES
from angerona.core.curated_tools import ToolError, _json, _read
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError
from angerona.core.recorder_metadata_custody import open_private_metadata
from angerona.core.source_sandbox import _atomic_bytes_write, _hold_plain_directories
from angerona.core.startup_recovery import private_directory


AUTOMATIC_SCAN_INTERVAL_SECONDS = 24 * 60 * 60
_MAX_UTC_SECONDS = 253402300799
_MAX_STATE_BYTES = 512


@dataclass(frozen=True, slots=True)
class AutomaticScanDecision:
    status: str
    reason: str
    next_due: int | None = None


def _valid_timestamp(value: object) -> bool:
    return type(value) is int and 0 < value <= _MAX_UTC_SECONDS - AUTOMATIC_SCAN_INTERVAL_SECONDS


class AutomaticSpywareScanSchedule:
    """One receipt per canonical data root, independent of scope or scanner choice."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._directory = self._root / "spyware-scan-schedule"
        self._state = self._directory / "attempt.json"
        self._lock = self._directory / "claim.lock"

    def _decide(self, now: int) -> AutomaticScanDecision:
        try:
            self._state.lstat()
        except FileNotFoundError:
            return AutomaticScanDecision("due", "first-attempt")
        record = _json(_read(self._state, _MAX_STATE_BYTES, private=True))
        if (type(record) is not dict or set(record) != {"schema", "scope", "attempted_at"}
                or type(record["schema"]) is not int or record["schema"] != 1
                or type(record["scope"]) is not str or record["scope"] not in SPYWARE_SCAN_AUTO_SCOPES
                or not _valid_timestamp(record["attempted_at"])):
            return AutomaticScanDecision("held", "invalid-attempt-receipt")
        attempted_at = record["attempted_at"]
        next_due = attempted_at + AUTOMATIC_SCAN_INTERVAL_SECONDS
        if now < attempted_at:
            return AutomaticScanDecision("held", "clock-before-last-attempt", next_due)
        if now < next_due:
            return AutomaticScanDecision("cooldown", "recent-attempt", next_due)
        return AutomaticScanDecision("due", "daily-interval-elapsed", next_due)

    def check(self, *, now: int | None = None) -> AutomaticScanDecision:
        """Read eligibility without creating files. A due result does not grant admission."""
        return self._evaluate(scope=None, now=now)

    def claim(self, *, scope: str, now: int | None = None) -> AutomaticScanDecision:
        """Return claimed only after a new attempt receipt has been persisted and verified."""
        if type(scope) is not str or scope not in SPYWARE_SCAN_AUTO_SCOPES:
            return AutomaticScanDecision("held", "invalid-scope")
        return self._evaluate(scope=scope, now=now)

    def _evaluate(self, *, scope: str | None, now: int | None) -> AutomaticScanDecision:
        if (not self._root.is_absolute() or ".." in self._root.parts
                or str(self._root).startswith(("\\\\", "//"))):
            return AutomaticScanDecision("held", "invalid-data-root")
        if now is not None and not _valid_timestamp(now):
            return AutomaticScanDecision("held", "invalid-clock")
        try:
            if scope is None:
                now = int(time.time()) if now is None else now
                if not _valid_timestamp(now):
                    return AutomaticScanDecision("held", "invalid-clock")
            with _hold_plain_directories(self._root):
                try:
                    self._directory.lstat()
                except FileNotFoundError:
                    if scope is None:
                        return AutomaticScanDecision("due", "first-attempt")
                    try:
                        if not private_directory(self._directory, create=True):
                            return AutomaticScanDecision("held", "unverified-private-directory")
                    except FileExistsError:
                        pass  # A competing first claimant may have created it.
                with _hold_plain_directories(self._directory):
                    if not private_directory(self._directory, create=False):
                        return AutomaticScanDecision("held", "unverified-private-directory")
                    lease = nullcontext() if scope is None else ExclusiveFileLease(
                        self._lock, opener=open_private_metadata,
                    )
                    with lease:
                        stamp = int(time.time()) if now is None else now
                        if not _valid_timestamp(stamp):
                            return AutomaticScanDecision("held", "invalid-clock")
                        decision = self._decide(stamp)
                        if scope is None or decision.status != "due":
                            return decision
                        record = {"schema": 1, "scope": scope, "attempted_at": stamp}
                        raw = json.dumps(record, separators=(",", ":")).encode("ascii")
                        _atomic_bytes_write(self._state, raw, root=self._directory, private=True)
                        if _read(self._state, _MAX_STATE_BYTES, private=True) != raw:
                            return AutomaticScanDecision("held", "attempt-write-unverified")
                    return AutomaticScanDecision(
                        "claimed", "attempt-recorded", stamp + AUTOMATIC_SCAN_INTERVAL_SECONDS,
                    )
        except ExclusiveFileLeaseError:
            return AutomaticScanDecision("held", "claim-lock-unavailable")
        except (OSError, ToolError, ValueError, OverflowError):
            return AutomaticScanDecision("held", "schedule-state-unavailable")
