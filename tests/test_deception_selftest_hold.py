"""PW27 known-held diagnostics use inert objects; no native canary or host work."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import selftest
from angerona.core.eventbus import Severity
from angerona.modules import deception


class _Bus:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)


class _Manager:
    platform = "windows"

    def __init__(self, module):
        self.modules = {module.name: module}
        self.restart_calls = []

    def is_enabled(self, _name):
        return True

    def restart_module_generation(self, *args):
        self.restart_calls.append(args)
        pytest.fail("A capability hold must not request lifecycle recovery")


@pytest.fixture
def held_module(monkeypatch):
    # Replace module-local platform views, never global os.name/pathlib behavior.
    # Construction creates no paths, probes, real canaries or running workers.
    monkeypatch.setattr(deception, "os", SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(selftest, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(deception, "_repo_root", lambda: Path("private-inert-deception"))
    module = deception.DeceptionModule()

    def unexpected(*_args, **_kwargs):
        pytest.fail("Known Windows creation hold must precede all disposable/native work")

    monkeypatch.setattr(deception.tempfile, "TemporaryDirectory", unexpected)
    monkeypatch.setattr(deception.DeceptionModule, "_plant", unexpected)
    monkeypatch.setattr(deception.deception_io, "create_canary", unexpected)
    monkeypatch.setattr(deception.deception_io, "snapshot", unexpected)
    return module


def _runner(module, monkeypatch):
    manager, bus = _Manager(module), _Bus()
    runner = selftest.SelfTestRunner(manager, bus)
    runner._pipeline_check = lambda: (True, "inert delivery fixture")
    runner._worker_budget = lambda: (1, "inert one-worker fixture", 1)
    runner._write_failure_log = lambda *_args: True
    # This suite tests result classification, not the separate injected verifier.
    # Keep the production accounting reconciliation and module-call validator.
    monkeypatch.setattr(selftest, "verify_harness", lambda _runner: (True, "inert verifier", []))
    return runner, manager, bus


def _module_record(runner, module):
    return next(row for row in runner.last_results
                if row["kind"] == "module" and row["module"] == module.name)


def test_windows_native_selftest_returns_exact_hold_before_disposable_work(held_module):
    before = (held_module._base, held_module._canaries, held_module._canary_evidence,
              held_module._thread, held_module.lifecycle_generation, held_module._stop,
              held_module.health, held_module.health_note)
    assert held_module.self_test() == (False, deception.DECEPTION_WINDOWS_CREATION_HELD)
    assert not deception.DECEPTION_WINDOWS_CREATION_HELD.startswith("SKIP:")
    assert (held_module._base, held_module._canaries, held_module._canary_evidence,
            held_module._thread, held_module.lifecycle_generation, held_module._stop,
            held_module.health, held_module.health_note) == before
    assert not held_module._canaries and not held_module._canary_evidence


def test_suite_reports_typed_windows_hold_as_skip_without_repair_or_critical(
    held_module, monkeypatch,
):
    runner, manager, bus = _runner(held_module, monkeypatch)
    report = runner.run(names=[held_module.name], timeout=2)
    row = _module_record(runner, held_module)
    assert row["status"] == "SKIP" and row["detail"] == deception.DECEPTION_WINDOWS_CREATION_HELD
    assert next(check for check in row["checks"] if check["check"] == "active_test")["status"] == "SKIP"
    assert not any(check["status"] == "FAIL" for check in row["checks"])
    assert runner.last_skips == [{"module": held_module.name,
                                  "detail": deception.DECEPTION_WINDOWS_CREATION_HELD}]
    assert not runner.last_failures and not runner.last_repairs and not manager.restart_calls
    assert row["runtime"]["status"] == "stopped" and row["scope"] == "module diagnostic"
    assert "0 failed, 1 skipped" in report
    assert not any(event.severity == Severity.CRITICAL for event in bus.events)
    assert all(event.details.get("response_authorized") is False for event in bus.events)
    assert runner.last_verification["status"] == "PASS"


def test_known_hold_keeps_running_coverage_health_and_generation_visible(held_module, monkeypatch):
    worker = SimpleNamespace(is_alive=lambda: True)
    held_module._thread = worker
    held_module._status = "running"
    held_module._lifecycle_generation = 7
    held_module.set_health(0, "No canaries admitted; native creation held")
    runner, manager, _bus = _runner(held_module, monkeypatch)
    runner.run(names=[held_module.name], timeout=2)
    row = _module_record(runner, held_module)
    assert row["status"] == "SKIP"
    assert row["runtime"]["status"] == "running" and row["runtime"]["thread_alive"] is True
    assert row["runtime"]["health"] == 0 and row["runtime"]["health_state"] == "failed"
    assert "No canaries admitted" in row["runtime"]["health_note"]
    assert row["runtime"]["lifecycle_generation"] == 7
    assert held_module._thread is worker and held_module.lifecycle_generation == 7
    assert held_module.health == 0 and not runner.last_repairs and not manager.restart_calls


def test_direct_check_marks_only_completed_typed_hold_as_skip(held_module):
    assert selftest.run_module_selftest(held_module, timeout=2) == (
        False, "SKIP: " + deception.DECEPTION_WINDOWS_CREATION_HELD,
    )


@pytest.mark.parametrize("case", ["subclass", "lookalike", "different_detail", "portable", "ordinary_failure"])
def test_lookalikes_other_platforms_and_other_failures_cannot_gain_typed_skip(
    held_module, monkeypatch, case,
):
    module = held_module
    if case == "subclass":
        class OtherDeception(deception.DeceptionModule):
            pass

        module = OtherDeception()
    elif case == "lookalike":
        module = SimpleNamespace(name=held_module.name, supported_platforms={"windows"},
                                 self_test=lambda: (False, deception.DECEPTION_WINDOWS_CREATION_HELD))
    elif case == "different_detail":
        monkeypatch.setattr(module, "self_test", lambda: (False, deception.DECEPTION_WINDOWS_CREATION_HELD + "; changed"))
    elif case == "portable":
        monkeypatch.setattr(selftest, "os", SimpleNamespace(name="posix"))
    else:
        monkeypatch.setattr(module, "self_test", lambda: (False, "canary count contract failed"))
    ok, detail = selftest.run_module_selftest(module, timeout=2)
    assert ok is False and not detail.startswith("SKIP:")
    runner, _manager, _bus = _runner(module, monkeypatch)
    runner.run(names=[module.name], timeout=2)
    assert _module_record(runner, module)["status"] == "FAIL"
    assert any(row["module"] == module.name for row in runner.last_failures)
    assert not runner.last_skips


@pytest.mark.parametrize("fault", [
    "contract", "invalid_result", "crash", "lifecycle_error", "lifecycle_exit", "lifecycle_deadline",
])
def test_contract_crash_result_and_worker_faults_still_fail_with_known_hold(
    held_module, monkeypatch, fault,
):
    if fault == "contract":
        held_module.version = ""
    elif fault == "invalid_result":
        monkeypatch.setattr(held_module, "self_test", lambda: ("false", deception.DECEPTION_WINDOWS_CREATION_HELD))
    elif fault == "crash":
        def crash():
            raise RuntimeError(deception.DECEPTION_WINDOWS_CREATION_HELD)

        monkeypatch.setattr(held_module, "self_test", crash)
    else:
        # Inert local lifecycle evidence; no process/thread query or start.
        held_module._status = "error" if fault == "lifecycle_error" else "running"
        held_module.last_error = "inert preexisting worker fault"
        if fault == "lifecycle_deadline":
            held_module._thread = SimpleNamespace(is_alive=lambda: True)
            held_module._watchdog_deadline_at = 1e-12
    ok, detail = selftest.run_module_selftest(held_module, timeout=2)
    assert ok is False and not detail.startswith("SKIP:")
    if fault.startswith("lifecycle_"):
        expected_fault = {"lifecycle_error": "error", "lifecycle_exit": "thread_exit",
                          "lifecycle_deadline": "deadline"}[fault]
        assert "worker_lifecycle" in detail and expected_fault in detail
    runner, _manager, _bus = _runner(held_module, monkeypatch)
    runner.run(names=[held_module.name], timeout=2)
    row = _module_record(runner, held_module)
    assert row["status"] == "FAIL" and not runner.last_skips
    assert any(check["status"] == "FAIL" for check in row["checks"])
    if fault.startswith("lifecycle_"):
        assert any(check["check"] == "worker_lifecycle" and check["status"] == "FAIL"
                   for check in row["checks"])


def test_direct_known_hold_without_completed_result_evidence_is_not_skip(
    held_module, monkeypatch,
):
    monkeypatch.setattr(selftest.SelfTestRunner, "_test_module", staticmethod(
        lambda *_args, **_kwargs: (False, deception.DECEPTION_WINDOWS_CREATION_HELD),
    ))
    assert selftest.run_module_selftest(held_module, timeout=2) == (
        False, deception.DECEPTION_WINDOWS_CREATION_HELD,
    )


def test_bounded_call_timeout_cannot_be_reclassified_as_native_hold(held_module, monkeypatch):
    monkeypatch.setattr(selftest, "_bounded_call", lambda *_args, **_kwargs: (
        False, "timed out after 0.1s; the call is still running", None,
    ))
    ok, detail = selftest.run_module_selftest(held_module, timeout=0.1)
    assert ok is False and detail.startswith("test timed out")
    assert "SKIP:" not in detail
