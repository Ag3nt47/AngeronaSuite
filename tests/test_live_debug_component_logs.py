"""Scanner/watchdog/Black Box failures must reach the same live review surface."""
from pathlib import Path
import time

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.live_debug import LOG_SOURCES, LiveDebugService


@pytest.mark.parametrize("source", [
    "diagnostics/resilience_scanner_crash.log", "diagnostics/resilience_watchdog_crash.log",
    "diagnostics/blackbox_startup.log", "diagnostics/blackbox_not_responding.log",
    "blackbox_startup.log",
])
def test_sidecar_crash_and_stall_logs_are_read_only_incremental_views(tmp_path, source):
    assert source in LOG_SOURCES
    path = tmp_path / source
    path.parent.mkdir(parents=True, exist_ok=True)
    before = b"Fixture sidecar error: --password supersecret123\n"
    path.write_bytes(before)
    service = LiveDebugService(EventBus(), tmp_path)
    deadline = time.monotonic() + 3
    rows = []
    while not rows and time.monotonic() < deadline:
        service._tail_log(source)
        snapshot = service.recent()
        rows = [row for row in snapshot["records"] if row["kind"] == "diagnostic"]
    assert len(rows) == 1 and "supersecret123" not in rows[0]["message"]
    assert rows[0]["source"] == source
    assert path.read_bytes() == before
    service._tail_log(source)
    assert service.recent(snapshot["cursor"])["records"] == []


def test_blackbox_independent_recorder_deduplicates_aliases_and_covers_sidecars():
    import blackbox_recorder as blackbox
    assert len(blackbox.LogTailWorker._SNAP_DIRS) == len(set(blackbox.LogTailWorker._SNAP_DIRS))
    tails = {Path(path).name for path, _ in blackbox.LogTailWorker._TAIL_FILES}
    assert {"resilience_scanner_crash.log", "resilience_watchdog_crash.log",
            "blackbox_startup.log", "blackbox_not_responding.log"} <= tails
