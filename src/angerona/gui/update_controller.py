"""One nonblocking controller for manual and optional daily update checks."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal
from shiboken6 import isValid

from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.updater.github_updater import UpdateReport, check_installed_updates
from angerona.updater.source_stage import prepare_source_update


@dataclass(frozen=True)
class _Delivery:
    report: UpdateReport
    origin: str
    epoch: int
    serial: int


def _revoke(event: threading.Event, *_args) -> None:
    """Destruction callback retains only plain cancellation state, never Qt."""
    event.set()


def _read_check(state: Path, root: Path, origin: str, epoch: int, serial: int) -> _Delivery:
    return _Delivery(check_installed_updates(state, root, force=origin == "manual"), origin, epoch, serial)


def _read_stage(root: Path, staging: Path, target: str, cancelled: threading.Event) -> dict:
    try:
        return {"ok": True, "result": prepare_source_update(root, staging, target, cancelled=cancelled.is_set)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "error_type": type(exc).__name__}


class UpdateController(QObject):
    report_ready = Signal(object)
    update_available = Signal(object)
    candidate_ready = Signal(object)
    status_changed = Signal(str)
    check_busy_changed = Signal(bool)

    def __init__(self, config, source_root: Path, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._source_root = Path(source_root)
        self._last_report: UpdateReport | None = None
        self._last_origin = ""
        self._last_epoch = -1
        self._serial = 0
        self._last_serial = -1
        self._origin = "daily"
        self._epoch = 0
        self._manual_claimed = False
        self._daily_allowed = bool(getattr(config, "github_daily_check_enabled", False))
        self._target = ""
        self._closed = False
        self._cancelled = threading.Event()
        self.destroyed.connect(partial(_revoke, self._cancelled))
        self._check = AsyncSnapshot(self, self._prepare_check, self._apply_report,
                                    name="GitHub Update Check", status=self._check_status)
        self._download = AsyncSnapshot(self, self._prepare_download, self._apply_candidate,
                                       name="GitHub Source Candidate", status=self._download_status)
        self._timer = QTimer(self)
        self._timer.setInterval(60 * 60 * 1000)
        self._timer.timeout.connect(self.check_daily)
        self._initial = QTimer(self)
        self._initial.setSingleShot(True)
        self._initial.setInterval(5000)
        self._initial.timeout.connect(self.check_daily)
        if self._daily_allowed:
            self._timer.start()
            self._initial.start()

    def alive(self) -> bool:
        return not self._closed and not self._cancelled.is_set() and isValid(self)

    def set_daily_preference(self, enabled: bool) -> None:
        """Suspend automatic delivery immediately while an opt-out is staged."""
        if not self.alive():
            return
        enabled = enabled is True
        if enabled != self._daily_allowed:
            self._epoch += 1
            self._daily_allowed = enabled
        if enabled:
            if not self._timer.isActive():
                self._timer.start()
        else:
            self._timer.stop()
            self._initial.stop()

    def preferences_changed(self, *, check_due: bool = True) -> None:
        if not self.alive():
            return
        self.set_daily_preference(bool(getattr(self._config, "github_daily_check_enabled", False)))
        if check_due:
            self.check_daily()

    def check_daily(self) -> None:
        if (self.alive() and self._daily_allowed
                and bool(getattr(self._config, "github_daily_check_enabled", False)) and not self._check.busy):
            self._origin = "daily"
            self._manual_claimed = False
            self._check.request()

    def check_now(self) -> None:
        if not self.alive():
            return
        if self._check.busy:
            self._manual_claimed = True
            return
        self._origin = "manual"
        self._manual_claimed = True
        self._check.request()

    def _prepare_check(self):
        self._serial += 1
        return partial(_read_check, Path(self._config.data_dir) / "github-updates",
                       self._source_root, self._origin, self._epoch, self._serial)

    def prompt_eligible(self, report: UpdateReport) -> bool:
        return (self.alive() and report is self._last_report and self._last_serial == self._serial
                and (self._last_origin == "manual" or (
                    self._last_epoch == self._epoch and self._daily_allowed
                    and bool(getattr(self._config, "github_daily_check_enabled", False)))))

    def manual_report(self, report: UpdateReport) -> bool:
        return self.prompt_eligible(report) and self._last_origin == "manual"

    def _apply_report(self, delivery: _Delivery) -> None:
        if not self.alive() or delivery.serial != self._serial:
            return
        self.check_busy_changed.emit(False)
        if not self.alive() or delivery.serial != self._serial:
            return  # A reentrant receiver started a newer operation or closed us.
        manual = self._manual_claimed or delivery.origin == "manual"
        self._manual_claimed = False
        if manual and delivery.origin == "daily" and delivery.report.status == "not_due":
            # The automatic operation did not fetch. Honor the manual intent
            # through ONE normal force=True attempt, retaining the 60s floor.
            self._origin = "manual"
            self._manual_claimed = True
            self._check.request(invalidate=True)
            return
        if not manual and (delivery.epoch != self._epoch or not self._daily_allowed
                           or not bool(getattr(self._config, "github_daily_check_enabled", False))):
            if not self._download.busy:
                self.status_changed.emit("Automatic update check completed after opt-out; no report or prompt was delivered.")
            return
        report = delivery.report
        self._last_report = report
        self._last_origin = "manual" if manual else "daily"
        self._last_epoch = delivery.epoch
        self._last_serial = delivery.serial
        self.status_changed.emit(report.summary())
        if not self.prompt_eligible(report):
            return
        self.report_ready.emit(report)
        if self.prompt_eligible(report) and report.available:
            self.update_available.emit(report)

    def download_source_candidate(self, revision: str) -> None:
        if not self.alive() or self._download.busy:
            return
        report = self._last_report
        if (report is None or not self.prompt_eligible(report)
                or revision != report.remote_revision or report.source_status != "different"):
            self.status_changed.emit("No observed source revision is eligible for preparation.")
            return
        self._target = revision
        self._download.request()

    def _prepare_download(self):
        return partial(_read_stage, self._source_root,
                       Path(self._config.data_dir) / "github-updates" / "stages",
                       self._target, self._cancelled)

    def _apply_candidate(self, value: dict) -> None:
        if self.alive():
            self.candidate_ready.emit(value)

    def _check_status(self, status: str) -> None:
        if not self.alive():
            return
        if status == "updating":
            serial = self._serial
            self.check_busy_changed.emit(True)
            if self.alive() and serial == self._serial:
                self.status_changed.emit("Checking canonical GitHub metadata in the background…")
        elif status == "unavailable":
            serial = self._serial
            self.check_busy_changed.emit(False)
            if self.alive() and serial == self._serial:
                self.status_changed.emit("The update check could not complete; update status is unknown.")

    def _download_status(self, status: str) -> None:
        if not self.alive():
            return
        if status == "updating":
            self.status_changed.emit("Preparing an isolated source candidate and preserving user edits…")
        elif status == "unavailable":
            self.status_changed.emit("Source preparation failed; the original installation is unchanged.")

    def close(self, *_args) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancelled.set()
        for timer in (self._timer, self._initial):
            if isValid(timer):
                timer.stop()
        self._check.close()
        self._download.close()
