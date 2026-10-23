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
PIP_BOOTSTRAP_VERSION = "26.2.2"
PIP_BOOTSTRAP_SHA256 = (
    "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
)
CERTIFI_VERSION = "2026.10.19"
# PyPI's hash for the universal wheel removing compromised emSign ECC G3 trust.
CERTIFI_SHA256 = "42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
CERTIFI_SIZE = 136464


@pytest.mark.parametrize("lock", [
    "requirements-bootstrap-pip.txt",
    "requirements-release-hashed.txt",
    "release/locks/posix/linux-x86_64.txt",
    "release/locks/posix/macos-arm64.txt",
    "release/locks/posix/source/linux-x86_64.txt",
    "release/locks/posix/source/macos-arm64.txt",
    "release/locks/posix/source/macos-x86_64-base.txt",
])
def test_pip_vendored_ca_fix_has_one_reviewed_hash_across_release_targets(lock: str) -> None:
    path = ROOT / lock
    blocks = [block for block in path.read_text(encoding="utf-8").split("\n\n")
              if any(line.startswith("pip==") for line in block.splitlines())]
    assert len(blocks) == 1
    assert blocks[0].splitlines() == [
        f"pip=={PIP_BOOTSTRAP_VERSION} \\",
        f"    --hash=sha256:{PIP_BOOTSTRAP_SHA256}",
    ]
    if lock.startswith("release/"):
        manifest = json.loads(path.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        assert [row for row in manifest["artifacts"] if row["name"] == "pip"] == [{
            "name": "pip", "version": PIP_BOOTSTRAP_VERSION,
            "filename": f"pip-{PIP_BOOTSTRAP_VERSION}-py3-none-any.whl",
            "size": 1819850, "sha256": PIP_BOOTSTRAP_SHA256,
        }]


def test_every_install_input_excludes_the_compromised_certifi_bundle() -> None:
    import ast
    import re

    from packaging.requirements import Requirement

    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = re.search(r"(?ms)^dependencies = (\[.*?^\])", project)
    assert dependencies is not None
    inputs = [ast.literal_eval(dependencies.group(1))]
    for name in (
        "requirements.txt", "requirements-posix-release.in",
        "constraints-release.txt", "constraints-posix-release.txt",
    ):
        inputs.append([
            line.split("#", 1)[0].strip()
            for line in (ROOT / name).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ])
    for requirements in inputs:
        certifi = [Requirement(line) for line in requirements
                   if Requirement(line).name.casefold() == "certifi"]
        assert len(certifi) == 1
        assert "2026.6.17" not in certifi[0].specifier
        assert "2026.10.18" not in certifi[0].specifier
        assert CERTIFI_VERSION in certifi[0].specifier


@pytest.mark.parametrize("lock", [
    "requirements-release-hashed.txt",
    "release/locks/posix/linux-x86_64.txt",
    "release/locks/posix/macos-arm64.txt",
    "release/locks/posix/source/linux-x86_64.txt",
    "release/locks/posix/source/macos-arm64.txt",
    "release/locks/posix/source/macos-x86_64-base.txt",
])
def test_certifi_security_fix_binds_the_same_universal_wheel(lock: str) -> None:
    path = ROOT / lock
    blocks = [block for block in path.read_text(encoding="utf-8").split("\n\n")
              if any(line.startswith("certifi==") for line in block.splitlines())]
    assert len(blocks) == 1
    assert blocks[0].splitlines() == [
        f"certifi=={CERTIFI_VERSION} \\", f"    --hash=sha256:{CERTIFI_SHA256}",
    ]
    if lock.startswith("release/"):
        manifest = json.loads(path.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        certifi = [row for row in manifest["artifacts"] if row["name"] == "certifi"]
        assert certifi == [{
            "name": "certifi", "version": CERTIFI_VERSION,
            "filename": f"certifi-{CERTIFI_VERSION}-py3-none-any.whl",
            "size": CERTIFI_SIZE, "sha256": CERTIFI_SHA256,
        }]


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
    requirement_blocks = []
    for block in lock.split("\n\n"):
        pins = [
            line
            for line in block.splitlines()
            if "==" in line and not line.lstrip().startswith("#")
        ]
        if not pins:
            continue
        assert len(pins) == 1
        hashes = [
            line.strip().removeprefix("--hash=sha256:").removesuffix(" \\")
            for line in block.splitlines()
            if line.strip().startswith("--hash=sha256:")
        ]
        assert hashes
        assert all(len(digest) == 64 for digest in hashes)
        assert all(set(digest) <= set("0123456789abcdef") for digest in hashes)
        requirement_blocks.append(block)
    assert len(requirement_blocks) == len(constraints)
    assert lock.count("--hash=sha256:") >= len(constraints)
    assert "--require-hashes --no-deps" in workflow
    assert "-r requirements-release-hashed.txt" in workflow
    assert "--no-build-isolation --no-deps ." in workflow


def test_windows_pip_bootstrap_is_exact_hash_locked_and_ordered() -> None:
    bootstrap = (ROOT / "requirements-bootstrap-pip.txt").read_text(
        encoding="utf-8"
    )
    main_lock = (ROOT / "requirements-release-hashed.txt").read_text(
        encoding="utf-8"
    )
    constraints = (ROOT / "constraints-release.txt").read_text(encoding="utf-8")
    pin = f"pip=={PIP_BOOTSTRAP_VERSION}"
    digest = f"--hash=sha256:{PIP_BOOTSTRAP_SHA256}"

    assert "--only-binary=:all:" in bootstrap
    assert bootstrap.count(pin) == 1
    assert bootstrap.count(digest) == 1
    assert bootstrap.count("--hash=sha256:") == 1
    assert f"{pin} \\" in main_lock
    assert digest in main_lock
    assert f"{pin}\n" in constraints

    launcher = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")
    supervisor = (ROOT / "tools" / "Invoke-AngeronaSourceStartup.ps1").read_text(encoding="utf-8")
    assert "Invoke-AngeronaSourceStartup.ps1" in launcher
    assert "Invoke-AngeronaStartupRepair.ps1" in supervisor
    assert "pip install --upgrade" not in launcher.casefold()

    installer = (ROOT / "Install-Angerona.bat").read_text(encoding="utf-8")
    assert 'call "%~dp0start-angerona.bat" --source-setup' in installer

    repair = (ROOT / "Repair-Angerona-Python.ps1").read_text(encoding="utf-8")
    bootstrap_install = repair.rindex(
        "(Join-Path $root 'requirements-bootstrap-pip.txt')"
    )
    dependency_install = repair.rindex(
        "(Join-Path $root 'requirements-release-hashed.txt')"
    )
    assert bootstrap_install < dependency_install
    assert "--require-hashes --no-deps" in repair
    assert f"m.version('pip') == '{PIP_BOOTSTRAP_VERSION}'" in repair

    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.index("-r requirements-bootstrap-pip.txt") < workflow.index(
        "-r requirements-release-hashed.txt"
    )
    assert "--require-hashes --no-deps" in workflow


def test_release_workflow_does_not_build_candidate_controlled_inno_setup() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    for forbidden in (
        "innosetup-6.7.1.exe",
        "Get-FileHash -Algorithm SHA256 $innoInstaller",
        "Join-Path $innoDir 'ISCC.exe'",
        "win64-migration-setup",
    ):
        assert forbidden not in workflow
    assert "prepared-windows-publisher-request" in workflow
    assert "finalized-windows-release-assets" in workflow


def test_unelevated_source_bootstrap_has_no_unhashed_dependency_path() -> None:
    launcher = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")
    source = (ROOT / "tools" / "Invoke-AngeronaSourceStartup.ps1").read_text(encoding="utf-8")
    text = (ROOT / "Repair-Angerona-Python.ps1").read_text(encoding="utf-8")

    assert "--require-hashes --no-deps" in text
    assert "requirements-release-hashed.txt" in text
    assert "'--no-build-isolation', '--no-deps', '-e'" in text
    assert "srt-0.0.0+angerona.1-py3-none-any.whl" in text
    assert "Invoke-AngeronaSourceStartup.ps1" in launcher
    assert "-FailureCategory $Category -Attempt 1" in source
    assert "-c constraints-release.txt" not in text
    assert "-r requirements.txt" not in text
    assert "--upgrade \"pip==" not in text
    assert "--no-deps \"vosk==" not in text
    assert "sys.version_info[:2] == (3, 12)" in source
    assert "sysconfig.get_platform() == 'win-amd64'" in source


def test_source_installer_is_an_unelevated_exact_setup_delegate() -> None:
    installer = (ROOT / "Install-Angerona.bat").read_text(encoding="utf-8")
    launcher = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")

    assert 'call "%~dp0start-angerona.bat" --source-setup' in installer
    source = (ROOT / "tools" / "Invoke-AngeronaSourceStartup.ps1").read_text(encoding="utf-8")
    assert "Invoke-AngeronaSourceStartup.ps1" in launcher
    assert "-SetupOnly" in launcher
    assert "sys.version_info[:2] == (3, 12)" in source
    assert "sysconfig.get_platform() == 'win-amd64'" in source
    for text in (installer, launcher):
        lowered = text.casefold()
        assert "-verb runas" not in lowered
        assert "net.exe\" session" not in lowered
        assert "--scope machine" not in lowered


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
    assert "--build-intel-crypto" in installer
    assert "macos-x86_64-base" in installer
    assert "tools/build_macos_intel_crypto.py" in installer
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
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10 test lane
        import tomli as tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    backend_pins = project["build-system"]["requires"]
    assert [pin.split("==", 1)[0] for pin in backend_pins] == [
        "setuptools",
        "wheel",
    ]
    assert all(pin.count("==") == 1 for pin in backend_pins)
    assert all(not any(marker in pin for marker in (">", "<", "~=", "!=", ","))
               for pin in backend_pins)
    for source in (
        "constraints-release.txt",
        "constraints-posix-release.txt",
        "requirements-posix-release.in",
    ):
        lines = (ROOT / source).read_text(encoding="utf-8").splitlines()
        source_pins = [
            line.strip()
            for line in lines
            if line.strip().split("==", 1)[0] in {"setuptools", "wheel"}
        ]
        assert source_pins == backend_pins
