"""Compose optional recorder witnessing without blocking protection startup."""
from __future__ import annotations

import time

from .eventbus import Event, Severity
from .recorder_epoch_worker import RecorderEpochStatus, RecorderEpochWorker


class RecorderIntegrityRuntime:
    """Retained optional owner; status reads perform no disk or network work."""

    def __init__(self, config, bus, provider):
        self.bus = bus
        from .recorder_enrollment import RecorderEnrollmentOwner
        self.enrollment = RecorderEnrollmentOwner(config.data_dir)
        self.worker = None
        self._last_event = None
        self._status = RecorderEpochStatus(state="disabled", reason="Independent recorder witness is disabled")
        if getattr(config, "recorder_witness_enabled", False) is True:
            # Keep ownership before starting. A failed Thread.start must never
            # discard an owner whose retirement is uncertain.
            self.worker = RecorderEpochWorker(db_path=config.db_path,
                archive_dir=config.data_dir / "integrity" / "recorder-epochs",
                client=provider, on_status=self._observe,
                archive_limit_bytes=getattr(config, "recorder_witness_archive_mib", 16) * 1024 * 1024)

    def latest_status(self):
        return self.worker.latest_status() if self.worker is not None else self._status

    def start(self):
        if self.worker is None:
            return False
        return self.worker.start()

    def request_stop(self):
        try:
            self.enrollment.request_stop()
        finally:
            if self.worker is not None:
                self.worker.request_stop()

    def stop(self, timeout=3.0):
        deadline = time.monotonic() + max(0.0, timeout)
        drained = True
        # Retire both owners independently, including a failed Thread.start.
        for owner in (self.enrollment, self.worker):
            if owner is not None:
                try:
                    retired = owner.stop(timeout=max(0.0, deadline - time.monotonic())) is True
                except BaseException:
                    retired = False
                drained = retired and drained
        return drained

    def _observe(self, status):
        self._status = status
        # Report transitions, not every scan cycle, to avoid turning optional
        # history verification into an unbounded stream of its own records.
        key = (status.state, bool(status.changed_rows), bool(status.unexpected_rows), bool(status.known_missing_rows))
        if key == self._last_event:
            return
        self._last_event = key
        severity = Severity.HIGH if status.changed_rows or status.unexpected_rows else (
            Severity.MEDIUM if status.state not in {"current", "disabled", "starting", "stopped"} else Severity.INFO)
        self.bus.publish(Event(module="Recorder Integrity", severity=severity,
            message=f"Independent recorder witness: {status.state}. {status.reason}",
            details={"category": "integrity-coverage", "state": status.state,
                "changed_rows": status.changed_rows, "missing_rows": status.known_missing_rows,
                "archive_bytes": status.archive_bytes, "archive_limit_bytes": status.archive_limit_bytes,
                "verification_backlog_epochs": status.verification_backlog_epochs,
                "producer_authenticity_verified": False, "physical_independence_verified": False,
                "active_attack": False, "disposition": "observation",
                "response_authorized": False, "response_authority": "unattributed-advisory"}))
