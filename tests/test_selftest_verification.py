"""Controlled defects must be detected, reported and persisted without live I/O."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from angerona.core import selftest
from angerona.core.eventbus import EventBus
from angerona.core.selftest_verification import verify_accounting, verify_harness


def module(result=(True, "ready"), name="Fixture"):
    return SimpleNamespace(name=name, supported_platforms=("windows",), self_test=lambda: result)


@pytest.fixture
def make_runner(monkeypatch, tmp_path):
    monkeypatch.setattr(selftest, "_failure_log_path", lambda: tmp_path / "report.json")

    def create(modules=(), *, enabled=True):
        manager = SimpleNamespace(platform="windows", modules={m.name: m for m in modules},
                                  is_enabled=lambda _name: enabled)
        runner = selftest.SelfTestRunner(manager, EventBus())
        runner._worker_budget = lambda: (2, "controlled test budget")
        return runner
    return create


@pytest.mark.parametrize("result", [None, True, "pass", ("False", "truthy"), (1, "truthy"),
                                   (True, ""), (False, None), (True, " " * 3), (True, "x" * 32769)])
def test_malformed_results_never_become_success_or_expected_skip(make_runner, result):
    runner = make_runner([module(result)])
    report = runner.run(expected_failure_cb=lambda *_args: "excuse everything")
    assert "[FAIL] Fixture" in report
    assert runner.last_failures[0]["detail"].startswith("error: invalid self_test result")
    assert runner.last_skips == []
    assert runner.last_verification["status"] == "PASS"


def test_each_module_has_local_checks_and_exact_saved_timing_evidence(make_runner, tmp_path):
    runner = make_runner([module(name="First"), module(name="Second")])
    report = runner.run()
    assert "[VERIFY] Harness verification" in report
    saved = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert saved["run_id"] == runner.run_id
    assert saved["schema"] == 2
    assert saved["results"] == runner.last_results
    assert saved["verification"] == runner.last_verification
    assert len(saved["verification"]["checks"]) >= 9
    assert saved["passed"] == 3 and saved["failed"] == saved["skipped"] == 0
    assert len(saved["metrics"]["slowest_modules"]) == 2
    for row in runner.last_results:
        assert row["duration_ms"] >= 0
        if row["kind"] == "module":
            assert {c["check"] for c in row["checks"]} >= {
                "identity", "self_test_callable", "health_contract", "result_contract", "active_test"}


def test_platform_skip_has_checks_without_probing_health_or_service(make_runner):
    candidate = module()
    candidate.supported_platforms = ("linux",)
    candidate.health_summary = lambda: pytest.fail("unavailable module health was probed")
    candidate.self_test = lambda: pytest.fail("unavailable module was run")
    runner = make_runner([candidate])
    runner.run()
    result = next(r for r in runner.last_results if r["kind"] == "module")
    assert result["status"] == "SKIP"
    assert len(result["checks"]) >= 3
    assert not runner.last_failures


def test_disabled_broken_module_contract_is_not_hidden_by_skip(make_runner):
    candidate = module()
    candidate.self_test = None
    runner = make_runner([candidate], enabled=False)
    runner.run()
    assert runner.last_failures[0]["detail"].startswith("contract check failed:")
    assert runner.last_skips == []


@pytest.mark.parametrize("status,health", [("error", 100), ("running", 0)])
def test_functional_success_cannot_hide_failed_runtime_health(make_runner, status, health):
    candidate = module()
    candidate.health_summary = lambda: (status, health, "failed")
    runner = make_runner([candidate])
    runner.run(expected_failure_cb=lambda *_args: "ignore")
    assert runner.last_failures[0]["detail"].startswith("contract check failed:")
    assert runner.last_skips == []


def test_kernel_only_explicit_absence_is_skip(make_runner):
    absent = module((False, "AngeronaSensor.sys driver not loaded"), "Absent kernel")
    absent.CODE = "KRNL"
    broken = module((False, "exact kernel protocol handshake failed"), "Broken kernel")
    broken.CODE = "KRNL"
    runner = make_runner([absent, broken])
    runner.run()
    assert [r["module"] for r in runner.last_skips] == [absent.name]
    assert [r["module"] for r in runner.last_failures] == [broken.name]
    assert runner.last_verification["status"] == "PASS"


def test_unknown_target_cannot_produce_an_empty_success(make_runner):
    runner = make_runner([module()])
    report = runner.run(names=["Misspelled"])
    assert "[FAIL] Module selection" in report
    assert runner.last_failures[0]["module"] == "Module selection"
    terminal = [e for e in runner.bus.recent(20) if e.message.startswith("Drill complete:")]
    assert len(terminal) == 1 and "1 failed" in terminal[0].message


def test_verifier_failure_is_in_terminal_notification_and_saved_counts(make_runner, monkeypatch, tmp_path):
    monkeypatch.setattr(selftest, "verify_harness", lambda _type: (
        False, "controlled verifier defect", [{"check": "fixture", "status": "FAIL"}]))
    runner = make_runner([module()])
    report = runner.run()
    assert "Result: 2 passed, 1 failed, 0 skipped." in report
    terminal = [e for e in runner.bus.recent(20) if e.message.startswith("Drill complete:")]
    assert len(terminal) == 1 and "1 failed" in terminal[0].message
    saved = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert saved["failed"] == len(saved["failures"]) == 1
    assert sum(r["status"] == "FAIL" for r in saved["results"]) == 1


def test_verifier_detects_a_broken_failure_classifier(monkeypatch):
    production = selftest.SelfTestRunner._test_module

    def broken(candidate, *args, **kwargs):
        ok, detail = production(candidate, *args, **kwargs)
        return (True, detail) if detail == "canary defect" else (ok, detail)

    monkeypatch.setattr(selftest.SelfTestRunner, "_test_module", staticmethod(broken))
    ok, _detail, checks = verify_harness(selftest.SelfTestRunner)
    assert not ok
    assert next(c for c in checks if c["check"] == "failure canary")["status"] == "FAIL"


def test_report_persistence_failure_remains_actionable(make_runner, monkeypatch, tmp_path):
    parent_file = tmp_path / "file"
    parent_file.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(selftest, "_failure_log_path", lambda: parent_file / "report.json")
    runner = make_runner([module()])
    report = runner.run()
    assert "[FAIL] Report persistence" in report
    assert runner.last_failures[-1]["module"] == "Report persistence"
    assert "Result: 2 passed, 1 failed, 0 skipped." in report
    terminal = [e for e in runner.bus.recent(20) if e.message.startswith("Drill complete:")]
    assert len(terminal) == 1 and "1 failed" in terminal[0].message
    assert sum(r["status"] == "FAIL" for r in runner.last_results) == 1


def test_one_worker_budget_retains_capacity_for_a_timed_out_actual_call(make_runner):
    release = threading.Event()
    entered = threading.Event()
    second_entered = threading.Event()

    def blocks():
        entered.set()
        assert release.wait(5.0)
        return True, "released"

    first, second = module(name="A first"), module(name="B second")
    first.self_test = blocks
    second.self_test = lambda: (second_entered.set() or True, "second")
    runner = make_runner([first, second])
    runner._worker_budget = lambda: (1, "controlled one-worker budget")
    try:
        report = runner.run(timeout=0.02)
        assert entered.is_set() and not second_entered.is_set(), report
        assert runner.last_failures[0]["detail"].startswith("test timed out")
        assert runner.last_failures[1]["detail"].startswith("test not started")
    finally:
        release.set()
        acquired = 0
        try:
            for _ in range(6):
                assert selftest._MODULE_CALLS.acquire(timeout=2.0)
                acquired += 1
        finally:
            for _ in range(acquired):
                selftest._MODULE_CALLS.release()


def test_inconsistent_health_state_is_detected_without_excusing_it(make_runner):
    candidate = module()
    candidate.health_summary = lambda: ("error", 100, "ok")
    runner = make_runner([candidate])
    report = runner.run(expected_failure_cb=lambda *_args: "ignore")
    assert "inconsistent health state" in report
    assert runner.last_failures and not runner.last_skips


def test_mismatched_registry_identity_is_detected_by_reconciliation(make_runner):
    runner = make_runner([module()])
    runner.manager.modules["Alias"] = runner.manager.modules.pop("Fixture")
    report = runner.run()
    assert "module result coverage differs from requested inventory" in report
    assert runner.last_verification["status"] == "FAIL"


def test_reconciliation_rejects_missing_or_corrupted_module_evidence():
    row = {"module": "A", "kind": "module", "status": "PASS", "duration_ms": 1, "checks": []}
    assert verify_accounting([row], ["A"], 1, 0, 0)[0]
    assert not verify_accounting([row], ["A", "B"], 1, 0, 0)[0]
    assert not verify_accounting([row], ["A"], 0, 1, 0)[0]
    assert not verify_accounting([row, row], ["A", "A"], 2, 0, 0)[0]
    row["checks"] = [{"check": "active_test", "status": "FAIL"}]
    assert not verify_accounting([row], ["A"], 1, 0, 0)[0]


@pytest.mark.parametrize("cores,available,factor,expected", [
    (1, 16_000_000_000, 1, 1), (4, 16_000_000_000, 1, 2),
    (32, 16_000_000_000, 1, 6), (32, 300_000_000, 1, 1),
    (32, 16_000_000_000, 8, 1),
])
def test_worker_budget_follows_cpu_ram_and_existing_pressure(monkeypatch, cores, available, factor, expected):
    import psutil
    from angerona.core import background_pacing
    monkeypatch.setattr(selftest.os, "cpu_count", lambda: cores)
    monkeypatch.setattr(psutil, "virtual_memory", lambda: SimpleNamespace(available=available))
    monkeypatch.setattr(background_pacing, "get_pacing_controller", lambda: SimpleNamespace(multiplier=lambda: factor))
    runner = selftest.SelfTestRunner(SimpleNamespace(), None)
    assert runner._worker_budget()[0] == expected
