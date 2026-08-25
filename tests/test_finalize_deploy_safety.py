from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "finalize-and-deploy.ps1"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            *arguments,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )


def test_deploy_refuses_nested_destination_before_mirror():
    destination = ROOT / "unsafe-nested-deployment"

    result = _run(
        "-Stage",
        str(ROOT),
        "-Home",
        str(destination),
        "-ConfirmMirror",
        "MIRROR ANGERONA",
    )

    assert result.returncode != 0
    assert "cannot be equal or nested" in (result.stdout + result.stderr)
    assert not destination.exists()


def test_deploy_refuses_existing_unowned_destination(tmp_path):
    destination = tmp_path / "unowned"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("must survive", encoding="utf-8")

    result = _run(
        "-Stage",
        str(ROOT),
        "-Home",
        str(destination),
        "-ConfirmMirror",
        "MIRROR ANGERONA",
    )

    assert result.returncode != 0
    assert "no Angerona ownership marker" in (result.stdout + result.stderr)
    assert sentinel.read_text(encoding="utf-8") == "must survive"


def test_deploy_requires_exact_noninteractive_confirmation(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "README.md").write_text("preview only", encoding="utf-8")
    destination = tmp_path / "new-deployment"

    result = _run(
        "-Stage",
        str(stage),
        "-Home",
        str(destination),
        "-ConfirmMirror",
        "YES",
    )

    assert result.returncode != 0
    assert "was not authorized" in (result.stdout + result.stderr)
    assert not (destination / ".angerona-deployment-owner.json").exists()
