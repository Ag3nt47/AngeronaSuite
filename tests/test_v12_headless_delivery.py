from __future__ import annotations

import inspect

from angerona.core import headless


def test_headless_uses_bounded_recorder_and_safe_shutdown_order() -> None:
    source = inspect.getsource(headless.run_headless)
    subscribe = source.index("bus.subscribe(recorder_worker.submit)")
    stop_modules = source.index("manager.stop_all()")
    drain = source.index("recorder_worker.stop", stop_modules)
    close = source.index("storage.close()", drain)

    assert "bus.subscribe(storage.record_bus)" not in source
    assert subscribe < stop_modules < drain < close
    assert "if recorder_drained" in source
