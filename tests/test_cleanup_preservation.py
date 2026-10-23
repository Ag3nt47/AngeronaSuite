"""Exercise cleanup copies in owned dummy projects; never run checkout cleanup.

Each Windows host is reported separately. Missing hosts skip explicitly. Every
PowerShell invocation uses an argument list and an owned script file, with only
that host's built-in module directory in its child-process PSModulePath.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass

import pytest


EXPECTED_CANDIDATE_LF_SHA256 = (
    "c2d6f845ca9f9f87f10e869ee038525a5f39c3eb8c5b64691bd6d86ec2f39eab"
)
HOSTS = ("windows-powershell-5.1", "powershell-7")
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class PowerShellHost:
    name: str
    executable: Path


def _assert_owned_path(owned_root: Path, path: Path) -> None:
    """Reject escapes and existing links before a helper reads or writes a path."""
    assert path.is_absolute() and path.is_relative_to(owned_root), path
    for part in (path, *path.parents):
        if os.path.lexists(part):
            attributes = getattr(part.lstat(), "st_file_attributes", 0)
            assert not attributes & REPARSE_POINT, f"Helper path is linked: {part}"
        if part == owned_root:
            break


def _run_script(
    host: PowerShellHost,
    owned_root: Path,
    script: Path,
    *arguments: str,
    timeout: float = 45,
) -> subprocess.CompletedProcess[str]:
    _assert_owned_path(owned_root, script)
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.casefold() == "psmodulepath":
            del environment[name]
    environment["PSModulePath"] = str(host.executable.parent / "Modules")
    command = [
        str(host.executable), "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", str(script), *arguments,
    ]
    # The Popen object owns the exact process handle. Timeout retirement never
    # searches for or terminates another process by PID, name or command text.
    # Owned temporary capture files avoid pipe-reader threads or inherited pipe
    # handles extending the bounded wait after the direct process has retired.
    with tempfile.TemporaryFile(dir=owned_root) as output, tempfile.TemporaryFile(dir=owned_root) as errors:
        process = subprocess.Popen(
            command,
            cwd=script.parent,
            env=environment,
            stdout=output,
            stderr=errors,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                pytest.fail(
                    f"{host.name} timed out; exact owned process retired with "
                    f"exit {process.returncode}"
                )
            output.seek(0)
            errors.seek(0)
            stdout = output.read().decode("utf-8", "replace")
            stderr = errors.read().decode("utf-8", "replace")
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        finally:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
            finally:
                if os.name == "nt" and process.returncode is not None:
                    process._handle.Close()


@pytest.fixture(scope="session", params=HOSTS)
def powershell_host(request, tmp_path_factory) -> PowerShellHost:
    name = request.param
    if os.name != "nt":
        pytest.skip(f"{name}: these controls require Windows junction semantics")
    if name == "windows-powershell-5.1":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        choices = [] if not system_root else [
            Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        ]
    else:
        override = os.environ.get("ANGERONA_TEST_PWSH")
        if override:
            selected = Path(override)
            if not selected.is_absolute() or not selected.is_file():
                pytest.fail("ANGERONA_TEST_PWSH must name an existing absolute pwsh.exe")
            choices = [selected]
        else:
            discovered = shutil.which("pwsh.exe") or shutil.which("pwsh")
            choices = [Path(discovered)] if discovered else []
            program_files = os.environ.get("ProgramFiles")
            if program_files:
                choices.append(Path(program_files) / "PowerShell/7/pwsh.exe")
    executable = next((path.resolve() for path in choices if path.is_file()), None)
    if executable is None:
        detail = "; set ANGERONA_TEST_PWSH to an installed pwsh.exe" if name == "powershell-7" else ""
        pytest.skip(f"{name}: executable unavailable{detail}")
    assert (executable.parent / "Modules").is_dir(), f"{name}: built-in Modules directory missing"
    host = PowerShellHost(name, executable)
    owned_root = tmp_path_factory.mktemp(f"cleanup-host-{name}")
    probe = owned_root / "host-version.ps1"
    probe.write_text(
        "$ErrorActionPreference = 'Stop'\n$PSVersionTable.PSVersion.ToString()\n",
        encoding="utf-8",
    )
    result = _run_script(host, owned_root, probe)
    assert result.returncode == 0, result.stderr
    expected_prefix = "5.1." if name == "windows-powershell-5.1" else "7."
    assert result.stdout.strip().startswith(expected_prefix), (
        f"Unexpected engine for {name}: {result.stdout!r}"
    )
    return host


@pytest.fixture(scope="session")
def candidate_bytes() -> bytes:
    # The same relative location works in the private proposal and after review
    # in the repository. This file is read only; execution uses fixture copies.
    source = Path(__file__).resolve().parents[1] / "cleanup.ps1"
    content = source.read_bytes()
    # Git may check a text .ps1 file out with LF or CRLF. Normalize only that
    # pair for the pin; retain every source byte when making fixture copies.
    assert hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest() == EXPECTED_CANDIDATE_LF_SHA256, (
        "cleanup.ps1 differs from the reviewed candidate; review and update its pin"
    )
    return content


def _write(owned_root: Path, path: Path, content: bytes) -> None:
    _assert_owned_path(owned_root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _new_project(
    owned_root: Path, candidate: bytes, *, name: str = "project", build_as_file: bool = False,
) -> Path:
    project = owned_root / name
    _assert_owned_path(owned_root, project)
    project.mkdir()
    _write(owned_root, project / "cleanup.ps1", candidate)
    files = {
        "pyproject.toml": b"[project]\nname = 'angerona'\n",
        "src/angerona/__init__.py": b"# Dummy package; never imported.\n",
        "src/angerona.egg-info/PKG-INFO": b"Metadata-Version: 2.1\n",
        "dist/release.whl": b"Rebuildable placeholder; not an actual wheel.\n",
        "build" if build_as_file else "build/lib/module.py": b"Rebuildable fixture.\n",
    }
    for relative, content in files.items():
        _write(owned_root, project / relative, content)
    if not build_as_file:
        _write(owned_root, project / "build/data[1].txt", b"Literal path fixture.\n")
    for relative in (
        "runtime-data/alerts.db", "runtime-data/alerts.db-wal", "runtime-data/alerts.db-shm",
        "logs/core.log", "secrets/bus.key", "forensics/ledger.journal", "quarantine/sample.bin",
        "backups/state.bak", "baselines/baseline.json", "diagnostics/capture.dmp",
        "remediations/restore.json", ".tmp/receipt.json", ".env", "custom_user_patch.ps1",
        "venv/pyvenv.cfg", ".venv/pyvenv.cfg", "src/angerona/__pycache__/core.pyc",
        "tools/__pycache__/helper.pyc", "tests/__pycache__/test.pyc", "src/angerona/nested.db",
        "user_config.json", "build-other/keep.bin",
    ):
        _write(owned_root, project / relative, b"Dummy evidence: " + relative.encode("ascii"))
    return project


def _snapshot(root: Path, *, directory_mtimes: bool = True) -> dict[str, tuple]:
    """Record namespace, bytes, attributes and mtime without traversing links."""
    records = {}
    pending = [root]
    while pending:
        path = pending.pop()
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        relative = path.relative_to(root).as_posix()
        if attributes & REPARSE_POINT:
            kind, payload = "link", os.readlink(path)
        elif stat.S_ISDIR(metadata.st_mode):
            kind, payload = "directory", None
            with os.scandir(path) as children:
                pending.extend(Path(child.path) for child in children)
        else:
            kind, payload = "file", hashlib.sha256(path.read_bytes()).hexdigest()
        mtime = metadata.st_mtime_ns if kind != "directory" or directory_mtimes else None
        size = metadata.st_size if kind == "file" else None
        records[relative] = (kind, attributes, mtime, size, payload)
        assert len(records) + len(pending) <= 2000, "Dummy snapshot unexpectedly large"
    return records


def _assert_success(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"


def _assert_refused(
    host: PowerShellHost, owned_root: Path, project: Path, reason: str,
) -> None:
    before = _snapshot(project)
    result = _run_script(host, owned_root, project / "cleanup.ps1", "-IncludeDist")
    assert result.returncode != 0, "Unsafe fixture was accepted"
    assert reason in result.stdout + result.stderr, f"Unexpected refusal: {result.stdout}\n{result.stderr}"
    assert _snapshot(project) == before, "Rejected plan changed dummy project state"


def _make_junction(
    host: PowerShellHost, owned_root: Path, link: Path, target: Path,
) -> None:
    _assert_owned_path(owned_root, link)
    _assert_owned_path(owned_root, target)
    assert not os.path.lexists(link)
    assert target.is_dir()
    script = owned_root / "make-junction.ps1"
    _write(
        owned_root, script,
        b"param([string]$Link, [string]$Target)\n"
        b"$ErrorActionPreference = 'Stop'\n"
        b"$null = New-Item -ItemType Junction -Path $Link -Target $Target -ErrorAction Stop\n",
    )
    result = _run_script(host, owned_root, script, "-Link", str(link), "-Target", str(target))
    _assert_success(result)
    assert getattr(link.lstat(), "st_file_attributes", 0) & REPARSE_POINT


def test_whatif_changes_no_bytes_paths_attributes_or_mtimes(
    powershell_host, candidate_bytes, tmp_path,
):
    project = _new_project(tmp_path, candidate_bytes, name="project [literal]")
    before = _snapshot(project)
    _assert_success(_run_script(
        powershell_host, tmp_path, project / "cleanup.ps1", "-IncludeDist", "-WhatIf",
    ))
    assert _snapshot(project) == before


@pytest.mark.parametrize("include_dist", [False, True], ids=["default", "explicit-dist"])
def test_only_selected_build_directories_disappear(
    powershell_host, candidate_bytes, tmp_path, include_dist,
):
    project = _new_project(tmp_path, candidate_bytes, name="project [literal]")
    before = _snapshot(project, directory_mtimes=False)
    targets = {"build", "src/angerona.egg-info"}
    if include_dist:
        targets.add("dist")
    arguments = ("-IncludeDist",) if include_dist else ()
    _assert_success(_run_script(powershell_host, tmp_path, project / "cleanup.ps1", *arguments))
    expected = {
        name: value for name, value in before.items()
        if not any(name == target or name.startswith(target + "/") for target in targets)
    }
    # Removing a child changes parent directory mtimes. File mtimes, all bytes,
    # attributes and every unselected namespace entry must remain identical.
    assert _snapshot(project, directory_mtimes=False) == expected


def test_junction_in_final_target_refuses_entire_plan_and_preserves_external_sentinel(
    powershell_host, candidate_bytes, tmp_path,
):
    project = _new_project(tmp_path, candidate_bytes)
    external = tmp_path / "external-sentinel"
    _write(tmp_path, external / "never-delete.key", b"Outside dummy project; inside owned fixture.\n")
    _make_junction(powershell_host, tmp_path, project / "dist/linked-external", external)
    external_before = _snapshot(external)
    _assert_refused(powershell_host, tmp_path, project, "Refusing linked cleanup entry")
    assert _snapshot(external) == external_before


def test_linked_src_ancestor_refuses_before_any_removal(
    powershell_host, candidate_bytes, tmp_path,
):
    project = tmp_path / "linked-source-project"
    project.mkdir()
    external = tmp_path / "external-source"
    for path, content in (
        (project / "cleanup.ps1", candidate_bytes),
        (project / "pyproject.toml", b"[project]\nname = 'angerona'\n"),
        (project / "build/keep.txt", b"Build must survive source-ancestor refusal.\n"),
        (project / "dist/release.whl", b"Dist must survive source-ancestor refusal.\n"),
        (external / "angerona/__init__.py", b"# Dummy external marker.\n"),
        (external / "angerona.egg-info/keep.txt", b"External source must survive.\n"),
    ):
        _write(tmp_path, path, content)
    _make_junction(powershell_host, tmp_path, project / "src", external)
    external_before = _snapshot(external)
    _assert_refused(powershell_host, tmp_path, project, "Refusing nonphysical or linked path")
    assert _snapshot(external) == external_before


@pytest.mark.parametrize("relative", [
    "dist/misplaced.db", "dist/misplaced.db-wal", "dist/misplaced.log", "dist/misplaced.key",
    "dist/misplaced.journal", "dist/capture.dmp", "dist/backups/retain.bin", "dist/.tmp/receipt.json",
], ids=["database", "sqlite-wal", "log", "key", "journal", "dump", "backup", "private-temp"])
def test_evidence_in_final_target_refuses_before_earlier_targets_are_removed(
    powershell_host, candidate_bytes, tmp_path, relative,
):
    project = _new_project(tmp_path, candidate_bytes)
    _write(tmp_path, project / relative, b"Misplaced dummy evidence; all build outputs must remain.\n")
    _assert_refused(powershell_host, tmp_path, project, "Refusing possible runtime/evidence")


def test_file_named_build_is_refused_without_changes(powershell_host, candidate_bytes, tmp_path):
    project = _new_project(tmp_path, candidate_bytes, build_as_file=True)
    _assert_refused(powershell_host, tmp_path, project, "not a directory")
