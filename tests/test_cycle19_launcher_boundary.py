from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_launchers_pin_cmd_owned_windows_root_before_redirect_or_elevation():
    canonical = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")
    guarded = (ROOT / "start-angerona-guarded.bat").read_text(encoding="utf-8")

    for text in (canonical, guarded):
        trust = text.index('set "SAFE_SYSTEM32=%__APPDIR__%"')
        redirect = text.index('cd /d "%~dp0"')
        assert trust < redirect
        assert 'set "SystemRoot=%SAFE_WINDOWS%"' in text
        assert 'set "ComSpec=%SAFE_SYSTEM32%cmd.exe"' in text
        assert 'set "PYTHONPATH="' in text
        assert 'set "ANGERONA_CORE_CMD="' in text
        assert 'set "ANGERONA_FLEET_SERVICE_KEY="' in text

    elevation = canonical.index('"%SAFE_SYSTEM32%net.exe" session')
    for fragment in (
        'set "PYTHONPATH="',
        'set "ANGERONA_CORE_CMD="',
        'set "ANGERONA_EXTERNAL_WATCHDOG="',
        'set "ANGERONA_FLEET_SERVICE_KEY="',
        'set "OPENAI_API_KEY="',
    ):
        assert canonical.index(fragment) < elevation
    assert '"%SystemRoot%\\System32' not in canonical
    assert '"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive' in canonical
    assert 'call "%~dp0start-angerona.bat" --bootstrap-selftest' in guarded


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
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stdout
    assert "ANGERONA_BOOTSTRAP_SELFTEST_OK" in result.stdout
