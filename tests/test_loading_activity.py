from __future__ import annotations

import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_global_loading_indicator_reference_counts_overlapping_work() -> None:
    from PySide6.QtWidgets import QApplication

    from angerona.gui.animations import (
        GlobalLoadingIndicator,
        begin_loading,
        finish_loading,
        update_loading,
    )

    app = QApplication.instance() or QApplication([])
    indicator = GlobalLoadingIndicator()
    indicator.set_compact(True, 36)
    indicator._REVEAL_DELAY_MS = 1
    first = begin_loading("Starting modules…", done=0, total=2)
    second = begin_loading("Retrieving alerts…")
    app.processEvents()

    assert indicator.active_count == 2
    assert "Retrieving alerts" in indicator.current_text
    assert "(+1)" in indicator.current_text
    assert indicator.minimumWidth() == 36
    assert indicator.maximumWidth() == 36
    assert indicator._label.isHidden()
    assert "Retrieving alerts" in indicator.toolTip()

    update_loading(first, "Starting Network Monitor…", done=1, total=2)
    finish_loading(second)
    app.processEvents()

    assert indicator.active_count == 1
    assert "Network Monitor" in indicator.current_text
    assert "1/2" in indicator.current_text

    finish_loading(first)
    app.processEvents()
    assert indicator.active_count == 0
    assert indicator.isHidden()
    indicator.deleteLater()
    app.processEvents()


def test_fast_loading_activity_finishes_without_forcing_visible_flicker() -> None:
    from PySide6.QtWidgets import QApplication

    from angerona.gui.animations import (
        GlobalLoadingIndicator,
        begin_loading,
        finish_loading,
    )

    app = QApplication.instance() or QApplication([])
    indicator = GlobalLoadingIndicator()
    token = begin_loading("Fast local read…")
    finish_loading(token)
    app.processEvents()

    assert indicator.active_count == 0
    assert indicator.isHidden()
    indicator.deleteLater()
    app.processEvents()


def test_loading_updates_from_worker_threads_reach_the_gui_safely() -> None:
    from PySide6.QtWidgets import QApplication

    from angerona.gui.animations import (
        GlobalLoadingIndicator,
        begin_loading,
        finish_loading,
        update_loading,
    )

    app = QApplication.instance() or QApplication([])
    indicator = GlobalLoadingIndicator()
    worker_started = threading.Event()
    worker_may_finish = threading.Event()

    def worker() -> None:
        token = begin_loading("Discovering modules…")
        update_loading(token, "Bringing Network Monitor online…", done=3, total=8)
        worker_started.set()
        worker_may_finish.wait(timeout=2)
        finish_loading(token)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert worker_started.wait(timeout=2)
    app.processEvents()
    assert indicator.active_count == 1
    assert "Network Monitor" in indicator.current_text
    assert "3/8" in indicator.current_text

    worker_may_finish.set()
    thread.join(timeout=2)
    app.processEvents()
    assert indicator.active_count == 0
    indicator.deleteLater()
    app.processEvents()
