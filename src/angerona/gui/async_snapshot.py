"""Bounded background reads for Qt presentation, with no Qt work in workers."""
from __future__ import annotations

import queue
import threading

from PySide6.QtCore import QTimer


def _snapshot_loop(jobs, results, stopped) -> None:
    """Reuse one sleeping worker without retaining the owner between reads."""
    while not stopped.is_set():
        job = jobs.get()
        if job is None or stopped.is_set():
            return
        generation, read = job
        try:
            result = (generation, True, read())
        except Exception:
            result = (generation, False, None)
        if stopped.is_set():
            return
        results.put_nowait(result)
        # An idle worker must not pin its previous reader or result payload.
        job = read = result = None


class AsyncSnapshot:
    """One reader, one result and one coalesced follow-up per owner.

    ``prepare`` runs on Qt and returns a zero-argument reader with detached
    inputs. ``apply`` runs on Qt only for successful reads. Failure preserves
    the previous view and the next request retries. Closing never waits for IO.
    """

    def __init__(self, owner, prepare, apply, *, name: str, status=None) -> None:
        self._prepare = prepare
        self._apply = apply
        self._name = name
        self._status = status
        self._results: queue.Queue = queue.Queue(maxsize=1)
        self._requests: queue.Queue = queue.Queue(maxsize=1)
        self._stopped = threading.Event()
        self._pending = False
        self._closed = False
        self._generation = 0
        self.busy = False
        self.thread: threading.Thread | None = None
        self._timer = QTimer(owner)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._poll)
        owner.destroyed.connect(self.close)

    def request(self, *, invalidate: bool = False) -> None:
        if self._closed:
            return
        if invalidate:
            self._generation += 1
        if self.busy:
            self._pending = True
            return
        try:
            read = self._prepare()
        except Exception:
            self._set_status("unavailable")
            return
        try:
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(
                    target=_snapshot_loop,
                    args=(self._requests, self._results, self._stopped),
                    name=self._name, daemon=True,
                )
                self.thread.start()
            self._requests.put_nowait((self._generation, read))
        except Exception:
            self.busy = False
            self.thread = None
            self._set_status("unavailable")
            return
        self.busy = True
        self._set_status("updating")
        self._timer.start()

    def _poll(self) -> None:
        if self._closed:
            return
        try:
            generation, success, value = self._results.get_nowait()
        except queue.Empty:
            return
        self._timer.stop()
        self.busy = False
        pending, self._pending = self._pending, False
        try:
            if success and generation == self._generation:
                self._apply(value)
                self._set_status("current")
            elif not success:
                self._set_status("unavailable")
        except Exception:
            self._set_status("unavailable")
        finally:
            if pending and not self._closed:
                self.request()

    def _set_status(self, state: str) -> None:
        if self._status is not None and not self._closed:
            try:
                self._status(state)
            except RuntimeError:
                # The owner may have been disposed by its apply callback.
                self.close()

    def close(self, *_args) -> None:
        self._closed = True
        self._pending = False
        self._stopped.set()
        try:
            self._requests.put_nowait(None)
        except queue.Full:
            pass  # The queued request observes _stopped before reading.
        # Parent destruction may have already disposed the timer's C++ object.
        try:
            self._timer.stop()
        except RuntimeError:
            pass
        self._prepare = self._apply = self._status = None
