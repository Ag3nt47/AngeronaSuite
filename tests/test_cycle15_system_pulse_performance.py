from __future__ import annotations

import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.gui.system_pulse import SystemPulseCard


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _VisiblePulseCard(SystemPulseCard):
    def isVisible(self) -> bool:  # noqa: N802 - Qt signature
        return True


def test_system_pulse_reuses_one_sampler_thread_and_wakes_it_on_shutdown() -> None:
    _app()
    card = _VisiblePulseCard(interval_ms=60_000)
    card._timer.stop()
    worker = card._sample_worker
    completed = threading.Event()
    sampler_threads: list[int] = []

    def fake_sample() -> None:
        sampler_threads.append(threading.get_ident())
        card._busy.clear()
        completed.set()

    card._sample = fake_sample
    for _index in range(3):
        completed.clear()
        card.request_sample()
        assert completed.wait(timeout=1.0)

    assert card._sample_worker is worker
    assert worker.is_alive()
    assert sampler_threads == [worker.ident, worker.ident, worker.ident]

    card.shutdown()
    worker.join(timeout=1.0)
    assert not worker.is_alive()
    card.close()
