from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "backup_to_F.bat"
SAFETY = ROOT / "tools" / "backup_to_f_safety.ps1"
SAFE_ROOT = Path("F:/Angerona-Backups")


def _run_validation(destination: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["cmd.exe", "/d", "/c", str(BATCH), destination, "--validate-only"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_backup_batch_has_fail_closed_mirror_boundary() -> None:
    source = BATCH.read_text(encoding="utf-8").lower()
    raw = BATCH.read_bytes()

    assert b"\r\n" in raw and raw.replace(b"\r\n", b"").find(b"\n") == -1
    assert "--validate-only" in source
    assert source.index("call :validate_boundary") < source.index(" /mir ")
    assert source.count("call :validate_boundary") >= 2
    assert source.count("call :scrub_private_state") >= 2
    assert "/xj" in source and "/sl" in source
    assert "if %robocopy_rc% geq 8" in source
    assert 'set "robocopy_rc=%errorlevel%"' in source
    assert 'echo [done] backup complete. robocopy status %robocopy_rc% is successful.' in source
    post_scrub = source.index("call :scrub_private_state", source.index(" /mir "))
    public_template = source.index("call :sync_public_env_example")
    assert public_template > post_scrub
    assert source.rindex('set "rc=0"') > public_template
    assert 'copy /b /y "%src%\\.env.example" "%dst%\\.env.example" >nul 2>&1' in source
    assert "/nc /ns >nul 2>&1" in source
    assert "echo   source" not in source
    assert "echo   target" not in source


def test_backup_batch_excludes_private_runtime_and_large_state() -> None:
    source = BATCH.read_text(encoding="utf-8").lower()

    required = {
        "shared_logs",
        "settings.json",
        "*.key",
        "*.token",
        "*.secret",
        "credentials.json",
        "client_secret*.json",
        "id_rsa",
        "models",
        "heartbeats",
        "ipc",
        "quarantine",
        "flight-recorder",
        "baselines",
        "remediations",
        "venv.incompatible.*",
        ".dev-tools",
        "runtime-data",
        "diagnostics",
        "build",
        "dist",
    }
    assert not required.difference(source.split())
    assert '"%src%\\.tmp"' in source
    assert '"%src%\\venv"' in source
    assert '"%src%\\runtime-data"' in source
    assert '"%src%\\shared_logs"' in source


def test_safety_helper_uses_literal_allowlisted_deletion() -> None:
    source = SAFETY.read_text(encoding="utf-8")

    assert 'Get-NormalizedPath "F:\\Angerona-Backups"' in source
    assert "Test-StrictChildPath" in source
    assert "Assert-NoReparseAncestor" in source
    assert "FileAttributes]::ReparsePoint" in source
    assert "Remove-Item -Force -Recurse -LiteralPath $candidate" in source
    assert "Remove-Item -Force -LiteralPath $candidate" in source
    assert "Remove-Item -Path" not in source
    assert "Remove-Item *" not in source


@pytest.mark.skipif(os.name != "nt", reason="Windows batch guard")
@pytest.mark.parametrize(
    "destination",
    [
        "D:/unrelated-backup",
        "F:/",
        "F:/Angerona-Backups",
        "F:/Angerona-Backups/../outside",
        "F:/Angerona-Backups/Angerona:stream",
        "F:/Angerona-Backups/CON",
        "F:/Angerona-Backups/trailing.",
        "//localhost/F$/Angerona-Backups/Angerona",
    ],
)
def test_validate_only_rejects_unsafe_destinations_without_path_disclosure(
    destination: str,
) -> None:
    result = _run_validation(destination)

    assert result.returncode >= 8
    output = (result.stdout + result.stderr).lower()
    assert "nothing was copied" in output
    assert str(ROOT).lower() not in output


@pytest.mark.skipif(
    os.name != "nt" or not SAFE_ROOT.is_dir(),
    reason="validated F: backup root is not attached",
)
def test_validate_only_accepts_safe_child_without_copying() -> None:
    result = _run_validation("F:/Angerona-Backups/Angerona")

    assert result.returncode == 0
    assert "validation only; nothing was copied" in result.stdout.lower()
    assert str(ROOT).lower() not in result.stdout.lower()


@pytest.mark.skipif(
    os.name != "nt" or not SAFE_ROOT.is_dir(),
    reason="validated F: backup root is not attached",
)
def test_scrub_removes_stale_private_state_but_preserves_public_and_git_files() -> None:
    destination = SAFE_ROOT / f"codex-backup-safety-{uuid.uuid4().hex}"
    assert destination.parent.resolve() == SAFE_ROOT.resolve()
    destination.mkdir()
    try:
        (destination / ".env").write_text("placeholder\n", encoding="utf-8")
        (destination / "shared_logs").mkdir()
        (destination / "shared_logs" / "events.json").write_text("{}", encoding="utf-8")
        (destination / "nested").mkdir()
        (destination / "nested" / "settings.json").write_text("{}", encoding="utf-8")
        (destination / "nested" / "client_secret.json").write_text("{}", encoding="utf-8")
        (destination / "nested" / "private.key").write_text("placeholder", encoding="utf-8")
        (destination / "nested" / "keychain.py").write_text("# public\n", encoding="utf-8")
        (destination / "venv.incompatible.20260822-180431").mkdir()
        (destination / "venv.incompatible.20260822-180431" / "python.exe").write_bytes(b"x")
        (destination / ".git" / "logs").mkdir(parents=True)
        (destination / ".git" / "logs" / "HEAD").write_text("public-history\n", encoding="utf-8")
        (destination / "README.md").write_text("public\n", encoding="utf-8")

        command = [
            os.environ["SystemRoot"] + r"\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SAFETY),
            "-Mode",
            "Scrub",
            "-Source",
            str(ROOT),
            "-Destination",
            str(destination),
            "-LauncherPath",
            str(BATCH),
        ]
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)

        assert result.returncode == 0, result.stderr
        assert not (destination / ".env").exists()
        assert not (destination / "shared_logs").exists()
        assert not (destination / "nested" / "settings.json").exists()
        assert not (destination / "nested" / "client_secret.json").exists()
        assert not (destination / "nested" / "private.key").exists()
        assert (destination / "nested" / "keychain.py").exists()
        assert not (destination / "venv.incompatible.20260822-180431").exists()
        assert (destination / "README.md").read_text(encoding="utf-8") == "public\n"
        assert (destination / ".git" / "logs" / "HEAD").exists()
    finally:
        resolved = destination.resolve()
        assert resolved.parent == SAFE_ROOT.resolve()
        assert resolved.name.startswith("codex-backup-safety-")
        shutil.rmtree(resolved, ignore_errors=True)
