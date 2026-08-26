from tools.selfcheck_policy import is_expected_unstarted_failure

from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.selftest import SelfTestRunner


class _ResultModule(BaseModule):
    name = "Result Module"
    supported_platforms = frozenset({"windows", "linux", "macos"})

    def __init__(self, detail: str) -> None:
        super().__init__()
        self._detail = detail

    def self_test(self) -> tuple[bool, str]:
        return False, self._detail


class _Manager:
    platform = "windows"

    def __init__(self, module: BaseModule) -> None:
        self.modules = {module.name: module}

    @staticmethod
    def is_enabled(_name: str) -> bool:
        return True


def test_selfcheck_accepts_only_narrow_unstarted_prerequisites() -> None:
    assert is_expected_unstarted_failure(
        "Network Monitor", "status=stopped, health=100%",
    )
    assert is_expected_unstarted_failure(
        "Adversary Combat", "MAXIMUM status=stopped; Low+; queue drops=0",
    )
    assert is_expected_unstarted_failure(
        "AI Triage (Ollama)",
        "Ollama daemon unreachable or configured model is not installed",
    )
    assert is_expected_unstarted_failure(
        "Active Response SOAR",
        "running, idle (set ANGERONA_SOAR_KILL_AND_ROLLBACK=1 to arm)",
    )


def test_selfcheck_never_accepts_timeout_exception_or_unrelated_idle_text() -> None:
    assert not is_expected_unstarted_failure(
        "Network Monitor", "test timed out after 12s",
    )
    assert not is_expected_unstarted_failure(
        "Network Monitor", "error: background worker crashed",
    )
    assert not is_expected_unstarted_failure(
        "Unknown Module", "idle worker unexpectedly exited",
    )
    assert not is_expected_unstarted_failure(
        "Unknown Module", "status=stopped, health=0% — crashed during startup",
    )
    assert not is_expected_unstarted_failure(
        "Unknown Module", "Ollama integrity validation failed",
    )


def test_runner_reports_expected_failure_as_skip_without_masking_timeout() -> None:
    stopped = _ResultModule("status=stopped, health=100%")
    stopped.name = "Network Monitor"
    stopped_runner = SelfTestRunner(_Manager(stopped), EventBus())
    stopped_runner._write_failure_log = lambda *_args, **_kwargs: None
    report = stopped_runner.run(
        expected_failure_cb=lambda name, detail: (
            "not started by harness"
            if is_expected_unstarted_failure(name, detail)
            else None
        ),
    )
    assert "[SKIP] Network Monitor — not started by harness" in report
    assert "Result: 1 passed, 0 failed, 1 skipped." in report
    assert stopped_runner.last_failures == []

    timed_out = _ResultModule("test timed out after 12s")
    timed_out.name = "Network Monitor"
    timeout_runner = SelfTestRunner(_Manager(timed_out), EventBus())
    timeout_runner._write_failure_log = lambda *_args, **_kwargs: None
    report = timeout_runner.run(
        expected_failure_cb=lambda name, detail: (
            "not started by harness"
            if is_expected_unstarted_failure(name, detail)
            else None
        ),
    )
    assert "[FAIL] Network Monitor — test timed out after 12s" in report
    assert "Result: 1 passed, 1 failed, 0 skipped." in report
    assert len(timeout_runner.last_failures) == 1
