"""Qt worker lifecycle helpers.

Qt aborts the entire process when a running ``QThread`` is destroyed. That is
easy to trigger when a ``WA_DeleteOnClose`` tool window owns (or is the last
Python owner of) a worker blocked in a bounded network/native call.

``defer_close_until_threads`` makes closing such a window non-blocking and
safe: the window disappears immediately, remains alive until every worker has
finished, and then completes the original close without replaying the UI close
animation.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from PySide6.QtCore import QTimer


def _is_running(worker: Any) -> bool:
    if worker is None:
        return False
    try:
        return bool(worker.isRunning())
    except RuntimeError:
        return False


def _running_workers(owner: Any) -> list[Any]:
    workers = getattr(owner, "_angerona_close_workers", ())
    return [worker for worker in workers if _is_running(worker)]


def _retry_deferred_close(owner: Any) -> None:
    """Finish a deferred close once its last worker leaves ``run()``."""
    try:
        if _running_workers(owner):
            return
        owner._angerona_deferred_close = False
        owner._angerona_close_wait_connected = False
        owner._angerona_close_workers = ()
        owner._angerona_close_bypass = True
        QTimer.singleShot(0, owner.close)
    except RuntimeError:
        return


def defer_close_until_threads(owner: Any, event: Any, workers: Iterable[Any]) -> bool:
    """Hide *owner* and defer destruction while any supplied QThread runs."""
    running = [worker for worker in workers if _is_running(worker)]
    if not running:
        owner._angerona_deferred_close = False
        owner._angerona_close_workers = ()
        return False

    event.ignore()
    owner._angerona_deferred_close = True
    owner._angerona_close_workers = tuple(running)
    owner.hide()

    if not getattr(owner, "_angerona_close_wait_connected", False):
        owner._angerona_close_wait_connected = True
        for worker in running:
            try:
                worker.requestInterruption()
                # Some Angerona workers intentionally shadow QThread.finished
                # with a result-bearing signal (for example AnalysisWorker's
                # ``finished(dict)``). Swallow every payload so it can never
                # replace the captured owner and strand a hidden dialog.
                worker.finished.connect(
                    lambda *_args, _owner=owner: _retry_deferred_close(_owner)
                )
            except RuntimeError:
                continue
        # Close the tiny race where a worker can finish between ``isRunning``
        # above and connecting its ``finished`` signal.
        QTimer.singleShot(0, lambda _owner=owner: _retry_deferred_close(_owner))
    return True
