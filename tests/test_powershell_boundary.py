import subprocess
import time

import pytest

from angerona.core.powershell_boundary import (
    ApprovalToken, PowerShellBoundary, PowerShellRequest,
)


KEY = b"k" * 32


def test_request_is_closed_typed_and_rejects_injection():
    request = PowerShellRequest(
        "service_restart", (("service_name", "WinDefend"),)
    )
    with pytest.raises(ValueError, match="unsupported"):
        PowerShellRequest("arbitrary_script", ())
    with pytest.raises(ValueError, match="invalid service"):
        PowerShellRequest(
            "service_restart", (("service_name", "x'; Remove-Item C:\\*"),)
        )
    with pytest.raises(ValueError, match="exactly"):
        PowerShellRequest("service_restart", ())
    with pytest.raises(Exception):
        request.arguments[0] = ("service_name", "other")


def test_preview_is_default_and_uses_fixed_argv():
    boundary = PowerShellBoundary(KEY)
    request = PowerShellRequest(
        "defender_custom_scan", (("path", "C:\\safe folder\\file.exe"),)
    )
    result = boundary.run(request)
    argv = boundary.preview(request)
    assert result.preview and not result.executed
    assert argv[:3] == ("powershell.exe", "-NoProfile", "-NonInteractive")
    assert argv[-2] == "-Command"
    assert "'C:\\safe folder\\file.exe'" in argv[-1]


def test_approval_is_bound_to_request_and_expiry():
    boundary = PowerShellBoundary(KEY)
    one = PowerShellRequest("restore_point_create")
    two = PowerShellRequest("service_restart", (("service_name", "Spooler"),))
    token = boundary.issue_approval(one, expires_at=time.time() + 30)
    assert boundary.verify_approval(one, token)
    assert not boundary.verify_approval(two, token)
    expired = ApprovalToken(token.request_hash, time.time() - 1, token.signature)
    assert not boundary.verify_approval(one, expired)


def test_execution_disabled_by_default():
    called = []
    boundary = PowerShellBoundary(KEY, runner=lambda *a, **k: called.append(a))
    request = PowerShellRequest("restore_point_create")
    token = boundary.issue_approval(request, expires_at=time.time() + 30)
    result = boundary.run(request, approval=token, execute=True)
    assert not result.executed
    assert "disabled" in result.error
    assert not called


def test_injected_execution_receives_list_and_bounds_output():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "x" * 70000, "")

    boundary = PowerShellBoundary(KEY, execution_enabled=True, runner=runner)
    request = PowerShellRequest(
        "firewall_rule_remove", (("rule_name", "Angerona-Dyn-test"),),
        timeout_seconds=4,
    )
    token = boundary.issue_approval(request, expires_at=time.time() + 30)
    result = boundary.run(request, approval=token, execute=True)
    assert result.executed and result.success and result.output_truncated
    assert len(result.stdout.encode()) == 64 * 1024
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert kwargs["timeout"] == 4
    assert kwargs["capture_output"] and kwargs["text"]


def test_timeout_is_structured():
    def runner(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("powershell", 1, output="partial")

    boundary = PowerShellBoundary(KEY, execution_enabled=True, runner=runner)
    request = PowerShellRequest("restore_point_create", timeout_seconds=1)
    token = boundary.issue_approval(request, expires_at=time.time() + 30)
    result = boundary.run(request, approval=token, execute=True)
    assert result.executed and not result.success
    assert result.error == "execution timed out"
    assert result.stdout == "partial"
