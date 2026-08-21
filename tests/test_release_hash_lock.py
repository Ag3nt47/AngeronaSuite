from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from tools.build_release_hash_lock import build_lock
from tools.build_posix_release_locks import (
    build_lock as build_posix_lock,
    build_manifest,
    select_artifacts,
)
from tools.verify_wheelhouse import verify_wheelhouse


ROOT = Path(__file__).resolve().parents[1]


def _wheel(path: Path, name: str, version: str, payload: bytes = b"wheel") -> Path:
    target = path / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr(f"{name}-{version}.dist-info/WHEEL", payload)
    return target


def test_hash_lock_binds_exact_selected_wheel(tmp_path: Path) -> None:
    constraints = tmp_path / "constraints.txt"
    constraints.write_text("Example-Pkg==1.2.3\n", encoding="utf-8")
    artifact = _wheel(tmp_path, "example_pkg", "1.2.3")

    lock = build_lock(constraints, tmp_path)

    assert "Example-Pkg==1.2.3 \\" in lock
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() in lock
    assert "--only-binary=:all:" in lock


def test_hash_lock_fails_when_selected_wheel_is_missing(tmp_path: Path) -> None:
    constraints = tmp_path / "constraints.txt"
    constraints.write_text("missing==9.9.9\n", encoding="utf-8")

    with pytest.raises(ValueError, match="expected exactly one selected wheel"):
        build_lock(constraints, tmp_path)


def test_release_workflow_requires_committed_hash_lock() -> None:
    constraints = {
        line.strip().split("==", 1)[0].casefold().replace("_", "-")
        for line in (ROOT / "constraints-release.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    lock = (ROOT / "requirements-release-hashed.txt").read_text(encoding="utf-8")
    locked = {
        line.split("==", 1)[0].casefold().replace("_", "-")
        for line in lock.splitlines()
        if "==" in line and not line.lstrip().startswith("#")
    }
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert locked == constraints
    assert lock.count("--hash=sha256:") == len(constraints)
    assert "--require-hashes --no-deps" in workflow
    assert "-r requirements-release-hashed.txt" in workflow
    assert "--no-build-isolation --no-deps ." in workflow


def test_release_workflow_pins_and_hash_verifies_inno_compiler() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "innosetup-6.7.1.exe" in workflow
    assert "4d11e8050b6185e0d49bd9e8cc661a7a59f44959a621d31d11033124c4e8a7b0" in workflow
    assert "Get-FileHash -Algorithm SHA256 $innoInstaller" in workflow
    assert "$actualInnoHash -ne $innoSha256" in workflow
    assert "Join-Path $innoDir 'ISCC.exe'" in workflow
    assert "Get-Command ISCC.exe" not in workflow


@pytest.mark.parametrize("launcher", ["start-angerona.bat", "Install-Angerona.bat"])
def test_elevated_source_bootstrap_has_no_unhashed_dependency_path(
    launcher: str,
) -> None:
    text = (ROOT / launcher).read_text(encoding="utf-8")

    assert "--require-hashes --no-deps -r requirements-release-hashed.txt" in text
    assert "--no-build-isolation --no-deps -e ." in text
    assert "--no-deps \"%TEMP%\\wheels\\srt-0.0.0+angerona.1-py3-none-any.whl\"" in text
    assert "-c constraints-release.txt" not in text
    assert "-r requirements.txt" not in text
    assert "--upgrade \"pip==" not in text
    assert "--no-deps \"vosk==" not in text
    assert "sys.version_info[:2] == (3, 12)" in text
    assert "sysconfig.get_platform() == 'win-amd64'" in text


def test_hardened_installer_bootstraps_exact_lock_python() -> None:
    text = (ROOT / "Install-Angerona.bat").read_text(encoding="utf-8")

    assert "Python.Python.3.12" in text
    assert "Python.Python.3.10" not in text
    assert "refusing an unhashed install" in text


def test_posix_manifest_rejects_a_one_byte_wheel_mutation(tmp_path: Path) -> None:
    constraints = tmp_path / "constraints.txt"
    constraints.write_text("Example-Pkg==1.2.3\n", encoding="utf-8")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    artifact = _wheel(wheelhouse, "example_pkg", "1.2.3")
    selected = select_artifacts(constraints, wheelhouse)
    lock_path = tmp_path / "lock.txt"
    manifest_path = tmp_path / "manifest.json"
    lock_path.write_text(build_posix_lock("linux-x86_64", selected), encoding="utf-8")
    manifest_path.write_text(
        build_manifest("linux-x86_64", selected), encoding="utf-8"
    )

    assert verify_wheelhouse(
        manifest_path, lock_path, wheelhouse, "linux-x86_64"
    ) == 1
    artifact.write_bytes(artifact.read_bytes() + b"x")
    with pytest.raises(ValueError, match="size mismatch"):
        verify_wheelhouse(manifest_path, lock_path, wheelhouse, "linux-x86_64")


def test_each_posix_target_has_an_exact_complete_artifact_lock() -> None:
    pins = {
        line.split("==", 1)[0].casefold().replace("_", "-")
        for line in (ROOT / "constraints-posix-release.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    lock_root = ROOT / "release" / "locks" / "posix"
    for target in ("linux-x86_64", "macos-arm64"):
        lock = (lock_root / f"{target}.txt").read_text(encoding="utf-8")
        locked = {
            line.split("==", 1)[0].casefold().replace("_", "-")
            for line in lock.splitlines()
            if "==" in line and not line.lstrip().startswith("#")
        }
        manifest = json.loads(
            (lock_root / f"{target}.manifest.json").read_text(encoding="utf-8")
        )
        artifacts = manifest["artifacts"]

        assert locked == pins
        assert manifest["target"] == target
        assert manifest["python"] == "cp312"
        assert len(artifacts) == len(pins)
        assert len({item["filename"] for item in artifacts}) == len(pins)
        assert len({item["sha256"] for item in artifacts}) == len(pins)
        assert lock.count("--hash=sha256:") == len(pins)
        assert {item["sha256"] for item in artifacts} == {
            line.rsplit(":", 1)[1].strip()
            for line in lock.splitlines()
            if "--hash=sha256:" in line
        }


def test_posix_release_job_is_independently_hash_locked() -> None:
    import yaml

    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["build-posix"]
    scripts = [step.get("run", "") for step in job["steps"]]
    names = [step.get("name", "") for step in job["steps"]]
    combined = "\n".join(scripts)

    assert "release/locks/posix/${{ matrix.artifact }}.txt" in combined
    assert "--only-binary=:all:" in combined
    assert "--require-hashes --no-deps -r \"$lock\"" in combined
    assert "tools/verify_wheelhouse.py" in combined
    assert "--no-index --find-links \"$wheelhouse\"" in combined
    assert "--no-build-isolation --no-deps ." in combined
    assert "pip install --upgrade" not in combined
    assert "pip install --constraint" not in combined
    assert names.index("Download and verify locked platform wheels") < names.index(
        "Install verified platform dependencies offline"
    )


def test_posix_source_installer_is_independently_hash_locked() -> None:
    installer = (ROOT / "install-angerona.sh").read_text(encoding="utf-8")

    assert "linux-x86_64" in installer
    assert "macos-arm64" in installer
    assert "Intel macOS is not available" in installer
    assert "Refusing an sdist build" in installer
    assert "sys.version_info[:2] != (3, 12)" in installer
    assert "--only-binary=:all: --require-hashes --no-deps" in installer
    assert "tools/verify_wheelhouse.py" in installer
    assert '--no-index --find-links "$WHEELHOUSE" --require-hashes --no-deps' in installer
    assert '--no-build-isolation --no-deps \\\n    -e "$ROOT"' in installer
    assert "--constraint" not in installer
    assert "pip install --upgrade" not in installer
    assert installer.index("tools/verify_wheelhouse.py") < installer.index(
        '"$VENV/bin/python" -m pip install'
    )


def test_local_build_backend_is_exact_pinned() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["build-system"]["requires"] == [
        "setuptools==83.0.0",
        "wheel==0.47.0",
    ]
