"""The finite recorder benchmark must load the current handoff dependencies."""
from pathlib import Path

from tools.benchmark_chill_recorder import measure


def test_current_recorder_extracts_and_retires_with_signed_ordered_delivery():
    source = (Path(__file__).resolve().parents[1] / "src/angerona/core/storage.py").read_text(
        encoding="utf-8"
    )
    result = measure(source, idle_seconds=0.1)
    assert result["ordered_events"] == 14
    assert result["order_verified"] is result["hmac_verified"] is True
    assert result["unfinished_workers"] == 0
