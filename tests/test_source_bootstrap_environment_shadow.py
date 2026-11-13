"""Run only an inert cmd prefix; never invoke the application or PowerShell."""
import os
from pathlib import Path
import subprocess

import pytest

from angerona.core.privilege import trusted_powershell_path

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="cmd dynamic-variable semantics")
def test_source_bootstrap_clears_shadow_with_extensions_initially_disabled(tmp_path):
    lines = (ROOT / "start-angerona.bat").read_text(encoding="utf-8").splitlines()
    end = next(i for i, line in enumerate(lines)
               if line.strip().casefold() == 'set "safe_system32=%__appdir__%"')
    # This prefix consists only of comments, setlocal and set commands.
    prefix = lines[:end + 1]
    assert all(line.strip().casefold().startswith(("@echo off", "setlocal ", "set ", "rem "))
               or line.strip().casefold() == "rem" or not line.strip() for line in prefix)
    fixture = tmp_path / "inert-bootstrap.cmd"
    fixture.write_text("\n".join(prefix) + "\necho(BOOTSTRAP=%SAFE_SYSTEM32%\nexit /b 0\n", encoding="utf-8")
    native_system = trusted_powershell_path().parents[2]
    environment = dict(os.environ, __APPDIR__=str(tmp_path / "untrusted-shadow") + "\\")
    result = subprocess.run([str(native_system / "cmd.exe"), "/d", "/e:off", "/u", "/c", str(fixture)],
                            capture_output=True, timeout=10, check=False, env=environment,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0
    output = result.stdout.decode("utf-16-le").strip()
    assert output.startswith("BOOTSTRAP=")
    observed = Path(output.removeprefix("BOOTSTRAP="))
    assert observed == native_system
    assert "untrusted-shadow" not in output
