"""Explicit long runtime allowances never rewrite saved scanner preferences."""
from __future__ import annotations

import time

import pytest

from angerona.gui import curated_tools as ui
from test_curated_tools_ui import ready, wait_until

pytest_plugins = ("test_curated_tools_ui",)


def test_long_run_reaches_real_operation_constructor_and_keeps_preferences_byte_identical(controller, tmp_path, monkeypatch):
    from angerona.core import curated_tools as tools
    from angerona.core.config import Config

    service = ready(controller)
    config = Config(data_dir=tmp_path)
    config.github_tools_timeout_seconds = 300
    config.save()
    before = config.settings_path.read_bytes()
    controller.manager.cfg = config
    backend = ui._backend()
    backend.ToolOperation = tools.ToolOperation
    observed = []

    def scan(_request, operation, *, progress):
        assert type(operation) is tools.ToolOperation
        observed.append((operation.timeout_seconds, operation.deadline - time.monotonic()))
        return {"state": "complete", "findings": []}

    service.scan = scan
    monkeypatch.setattr(config, "save", lambda: pytest.fail("A per-run allowance must not save preferences"))
    assert controller.priority_scan(native_enabled=False, zero_breach_enabled=True, timeout_seconds=14400)
    wait_until(lambda: not controller.snapshot()["busy"])
    assert observed and observed[0][0] == 14400 and observed[0][1] > 14390
    assert config.github_tools_timeout_seconds == 300
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("value", [14401, 29, True, False, float("nan"), float("inf"), 14400.0, "14400"])
def test_invalid_runtime_allowance_is_rejected_before_any_scan(controller, value):
    service = ready(controller)
    assert not controller.priority_scan(native_enabled=False, zero_breach_enabled=True, timeout_seconds=value)
    assert not service.requests and controller.snapshot()["busy"] is False
    assert "30 and 14400" in controller.snapshot()["message"]
