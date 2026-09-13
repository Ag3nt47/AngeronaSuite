import pytest
from types import SimpleNamespace

from tools.selfcheck_policy import is_expected_unstarted_failure, no_tcp_listener_on_port

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


_MISSING_APPROVAL = (
    "Ollama ready, but model llama3 has no fresh approved local attestation: "
    "approved model baseline unavailable (approval-required)"
)


def test_missing_model_approval_requires_explicit_disposable_harness_context() -> None:
    assert not is_expected_unstarted_failure("AI Triage (Ollama)", _MISSING_APPROVAL)
    assert is_expected_unstarted_failure(
        "AI Triage (Ollama)", _MISSING_APPROVAL,
        allow_unapproved_model_baseline=True,
    )
    assert not is_expected_unstarted_failure(
        "Unknown Module", _MISSING_APPROVAL,
        allow_unapproved_model_baseline=True,
    )


def test_missing_listener_requires_successful_independent_absence_evidence() -> None:
    detail = (
        "Ollama listener attestation failed: local Ollama listener ownership "
        "is unavailable or ambiguous"
    )
    assert not is_expected_unstarted_failure("AI Triage (Ollama)", detail)
    assert is_expected_unstarted_failure(
        "AI Triage (Ollama)", detail, confirmed_absent_ollama_listener=True,
    )
    assert not is_expected_unstarted_failure(
        "AI Triage (Ollama)",
        "Ollama listener attestation failed: local Ollama executable is not trusted",
        confirmed_absent_ollama_listener=True,
    )
    assert not is_expected_unstarted_failure(
        "AI Triage (Ollama)",
        "Ollama readiness check failed (ValueError): invalid model-list response",
        confirmed_absent_ollama_listener=True,
    )


def _listener(host="127.0.0.1", port=11434, pid=99):
    return SimpleNamespace(status="LISTEN", laddr=(host, port), pid=pid)


@pytest.mark.parametrize("connections", [
    [_listener()],
    [_listener(pid=None)],
    [_listener(host="0.0.0.0", pid=None)],
    [_listener(host="::", pid=None)],
    [_listener(), _listener(host="::1", pid=100)],
    [SimpleNamespace(status="LISTEN", laddr=None)],
    [None],
])
def test_listener_table_never_calls_owned_ambiguous_or_unknown_listener_absent(connections):
    assert not no_tcp_listener_on_port(connections, 11434)


def test_successful_empty_listener_table_confirms_absence_only_for_requested_port():
    assert no_tcp_listener_on_port([], 11434)
    assert no_tcp_listener_on_port([_listener(port=11435)], 11434)
    assert not no_tcp_listener_on_port([], 0)


@pytest.mark.parametrize("detail", [
    _MISSING_APPROVAL.replace("approval-required", "invalid"),
    _MISSING_APPROVAL.replace("approval-required", "unreadable"),
    _MISSING_APPROVAL.replace("approval-required", "key-unavailable"),
    _MISSING_APPROVAL.replace("approval-required", "missing"),
    _MISSING_APPROVAL + "; digest mismatch",
    "error: " + _MISSING_APPROVAL,
    "test timed out after 12s: " + _MISSING_APPROVAL,
    "Ollama ready, but model llama3 has no fresh approved local attestation",
])
def test_disposable_harness_never_masks_other_model_attestation_failures(detail) -> None:
    assert not is_expected_unstarted_failure(
        "AI Triage (Ollama)", detail,
        allow_unapproved_model_baseline=True,
    )


def test_runner_reports_disposable_missing_model_approval_as_skip() -> None:
    module = _ResultModule(_MISSING_APPROVAL)
    module.name = "AI Triage (Ollama)"
    runner = SelfTestRunner(_Manager(module), EventBus())
    runner._write_failure_log = lambda *_args, **_kwargs: None
    report = runner.run(
        expected_failure_cb=lambda name, detail: (
            "disposable harness has no approved model baseline"
            if is_expected_unstarted_failure(
                name, detail, allow_unapproved_model_baseline=True,
            )
            else None
        ),
    )
    assert "[SKIP] AI Triage (Ollama)" in report
    assert "Result: 1 passed, 0 failed, 1 skipped." in report
    assert runner.last_failures == []


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
