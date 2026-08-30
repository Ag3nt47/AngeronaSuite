from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_launchers_pin_cmd_owned_windows_root_before_redirect_or_local_code():
    canonical = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")
    guarded = (ROOT / "start-angerona-guarded.bat").read_text(encoding="utf-8")

    trust = canonical.index('set "SAFE_SYSTEM32=%__APPDIR__%"')
    redirect = canonical.index('cd /d "%~dp0"')
    assert trust < redirect
    assert 'set "SystemRoot=%SAFE_WINDOWS%"' in canonical
    assert 'set "ComSpec=%SAFE_SYSTEM32%cmd.exe"' in canonical
    assert 'set "PYTHONPATH="' in canonical
    assert 'set "ANGERONA_CORE_CMD="' in canonical
    assert 'set "ANGERONA_FLEET_SERVICE_KEY="' in canonical

    admin_refusal = canonical.index(
        "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    for fragment in (
        'set "PYTHONPATH="',
        'set "ANGERONA_CORE_CMD="',
        'set "ANGERONA_EXTERNAL_WATCHDOG="',
        'set "ANGERONA_FLEET_SERVICE_KEY="',
        'set "OPENAI_API_KEY="',
    ):
        assert canonical.index(fragment) < admin_refusal

    assert 'set "ANGERONA_JARVIS_CONTROL_TOKEN="' in canonical
    assert canonical.index('set "ANGERONA_JARVIS_CONTROL_TOKEN="') < admin_refusal
    assert '"%SystemRoot%\\System32' not in canonical
    assert '"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive' in canonical
    assert 'call "%~dp0start-angerona.bat" --bootstrap-selftest' in guarded
    assert "ANGERONA_DATA" not in guarded
    assert "ANGERONA_ENFORCE_KEY_ACL" not in guarded
    assert "watchdog" not in guarded.casefold()
    for text in (canonical, guarded):
        lowered = text.casefold()
        assert "-verb runas" not in lowered
        assert "net.exe\" session" not in lowered


def test_canonical_launcher_refuses_an_unreviewed_existing_venv_before_launch():
    canonical = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")

    abi_gate = canonical.index(
        "sys.version_info[:2] == (3, 12) and "
        "sysconfig.get_platform() == 'win-amd64'"
    )
    pip_gate = canonical.index("m.version('pip') == '26.2.1'")
    dependency_preflight = canonical.index('"tools\\source_trust_preflight.py"')
    launch = canonical.index("Start-Process -FilePath $env:ANGERONA_PYTHON")

    assert abi_gate < pip_gate < dependency_preflight < launch
    assert "Angerona did not modify or delete it." in canonical
    assert "Repair-Angerona-Python.bat" in canonical
    assert "Install-Angerona-Release.bat" in canonical


def test_source_python_repair_is_confirmed_bounded_and_hash_locked():
    wrapper = (ROOT / "Repair-Angerona-Python.bat").read_text(encoding="utf-8")
    repair = (ROOT / "Repair-Angerona-Python.ps1").read_text(encoding="utf-8")
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "Type REPAIR to continue" in repair
    assert "[IO.Path]::GetFullPath((Join-Path $root 'venv'))" in repair
    assert "DriveType -ne [IO.DriveType]::Fixed" in repair
    assert "FileAttributes]::ReparsePoint" in repair
    assert "Python Software Foundation" in repair
    assert "Microsoft" in repair and "Find-TrustedWinget" in repair
    assert "Python.Python.3.12" in repair
    assert "--require-hashes --no-deps" in repair
    assert "requirements-bootstrap-pip.txt" in repair
    assert repair.rindex("requirements-bootstrap-pip.txt") < repair.rindex(
        "requirements-release-hashed.txt"
    )
    assert "m.version('pip') == '26.2.1'" in repair
    assert "venv.incompatible.$stamp" in repair
    assert "Remove-Item -LiteralPath $venv -Recurse -Force" in repair
    assert "Move-Item -LiteralPath $backup -Destination $venv" in repair
    assert "Set-Acl" not in repair and "icacls" not in repair.casefold()
    assert "ANGERONA_DATA" not in repair and "Config" not in repair
    assert "Repair-Angerona-Python.ps1" in wrapper
    assert "/venv.incompatible.*/" in ignored
    assert "/.tmp/repair-wheels/" in ignored


def test_push_helper_does_not_execute_commit_text_or_publish_after_commit_failure():
    helper = (ROOT / "push-to-github.bat").read_text(encoding="utf-8")

    assert 'git commit -m "%MSG%"' not in helper
    assert "$env:MSG" in helper
    assert 'git commit -F "%MSGFILE%"' in helper
    assert 'git show ":%%F" | "%GITLEAKS%" stdin --redact --no-banner' in helper
    assert "--diff-filter^=ACMR" in helper
    secret_scan = helper.index('"%GITLEAKS%" stdin --redact --no-banner')
    commit = helper.index('git commit -F "%MSGFILE%"')
    commit_failure = helper.index("if not \"%COMMIT_RC%\"==\"0\"")
    publisher = helper.index("call :publish_github", commit_failure)
    assert secret_scan < commit < commit_failure < publisher
    assert "git push" not in helper
    assert "tools\\publish_github_update.py" in helper
    assert "Commit failed. Nothing was pushed." in helper
    assert "Get-FileHash" in helper
    assert "executable_sha256.'gitleaks.exe'" in helper
    assert "credential-free HTTPS on github.com" in helper

    helper = (ROOT / "pull-from-github.bat").read_text(encoding="utf-8")

    assert "git pull" not in helper
    assert "git status --porcelain" in helper
    assert "credential-free HTTPS on github.com" in helper
    assert "Get-FileHash" in helper
    assert "executable_sha256.'gitleaks.exe'" in helper
    assert "fetch --no-tags" in helper
    assert "submodule.recurse=false" in helper
    assert "Incoming commits modify GitHub workflows" in helper
    assert '"%GITLEAKS%" git . --redact --no-banner' in helper
    scan = helper.index('"%GITLEAKS%" git . --redact --no-banner')
    merge = helper.index("merge --ff-only")
    assert scan < merge


@pytest.mark.skipif(os.name != "nt", reason="cmd.exe regression")
@pytest.mark.parametrize("launcher", (
    "start-angerona.bat",
    "start-angerona-guarded.bat",
))
def test_launcher_selftest_rejects_hostile_inherited_environment(launcher):
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    command = Path(system_root) / "System32" / "cmd.exe"
    environment = dict(os.environ)
    environment.update({
        "SystemRoot": r"C:\Users\Public\fake-windows",
        "WINDIR": r"C:\Users\Public\fake-windows",
        "ComSpec": r"C:\Users\Public\fake-cmd.exe",
        "PATH": r"C:\Users\Public\fake-bin",
        "PYTHONPATH": r"C:\Users\Public\fake-python",
        "ANGERONA_CORE_CMD": r"C:\Users\Public\fake-core.exe",
        "ANGERONA_EXTERNAL_WATCHDOG": "1",
        "ANGERONA_FLEET_SERVICE_KEY": "attacker-fleet-key",
        "ANGERONA_JARVIS_CONTROL_TOKEN": "attacker-control-token",
        "OPENAI_API_KEY": "attacker-provider-key",
    })

    result = subprocess.run(
        [str(command), "/d", "/c", launcher, "--bootstrap-selftest"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # This is an environment-sanitization contract, not a startup-speed
        # benchmark. Hosted Windows runners can spend more than ten seconds in
        # process creation and trust checks under load.
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout
    assert "ANGERONA_BOOTSTRAP_SELFTEST_OK" in result.stdout
