"""Static contracts for compatibility wrappers; no PowerShell or daemon runs."""
from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ("tools/Start-AngeronaOllama.ps1", "pull-model-to-D.ps1")


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("relative", SCRIPTS)
def test_legacy_helpers_have_no_independent_daemon_or_download_authority(relative):
    source = _source(relative)
    forbidden = (
        r"\b(?:Get|Stop|Start)-Process\b", r"\btaskkill(?:\.exe)?\b",
        r"\b(?:Invoke-RestMethod|Invoke-WebRequest)\b", r"\bwinget(?:\.exe)?\b",
        r"\bollama\.exe\b", r"SetEnvironmentVariable", r"\$env:",
        r"\b(?:New-Item|Add-Content|Set-Content|Get-Command)\b", r"\bStart-Sleep\b",
        r"UseShellExecute", r"\bComSpec\b",
    )
    for pattern in forbidden:
        assert re.search(pattern, source, re.IGNORECASE) is None, (relative, pattern)
    assert "Upgrade Console" in source
    assert "does not" in source


@pytest.mark.parametrize("relative", SCRIPTS)
def test_explicit_launch_delegates_only_to_the_fixed_normal_source_supervisor(relative):
    source = _source(relative)
    invocations = re.findall(r"^\s*&[^\r\n]+", source, re.MULTILINE)
    assert [line.strip() for line in invocations] == ["& $startup -RepositoryRoot $repo"]
    assert "$startup = Join-Path $repo 'tools\\Invoke-AngeronaSourceStartup.ps1'" in source
    assert "$PSScriptRoot" in source
    assert "[IO.FileAttributes]::ReparsePoint" in source
    assert "$startupItem.LinkType -eq 'HardLink'" in source
    assert "[IO.Path]::GetDirectoryName($cursor)" in source
    assert "$global:LASTEXITCODE = 0" in source and "exit $LASTEXITCODE" in source
    assert not any(flag in source for flag in (
        "-SourceActivationBroker", "-ActivationDescriptorSha256", "-FreshSourceCache",
        "-SetupOnly", "-SkipVerification", "-VerifiedBoundary",
    ))


@pytest.mark.parametrize("relative", SCRIPTS)
def test_no_launch_option_returns_before_filesystem_or_ai_preflight(relative):
    source = _source(relative)
    gate = re.search(r"if \(-not \$LaunchAngerona\) \{(?P<body>.*?)\n\}", source, re.DOTALL)
    assert gate and "exit 0" in gate.group("body")
    assert gate.end() < source.index("[IO.Path]::GetFullPath")
    assert gate.end() < source.index("Get-Item -LiteralPath")
    assert "original-capsule" in source
    assert "normal verification and recovery holds" in source


def test_start_wrapper_preserves_legacy_switches_without_keeping_preparation_actions():
    source = _source(SCRIPTS[0])
    assert "[ValidateRange(30, 1800)][int]$WaitSeconds = 420" in source
    for name in ("SkipUpdate", "FixHostBinding", "LaunchAngerona"):
        assert "[switch]$" + name in source
    assert "Legacy preparation options are accepted but do not change" in source
    assert "No AI readiness or protection is asserted here" in source


def _model_pattern() -> re.Pattern[str]:
    # Exercise the exact declared PowerShell input grammar with Python's matching
    # engine; only .NET's strict end anchor is translated. No duplicate grammar.
    source = _source(SCRIPTS[1])
    match = re.search(r"^\$immutableModel = '([^']+)'$", source, re.MULTILINE)
    assert match is not None
    return re.compile(match.group(1).replace(r"\z", r"\Z"))


@pytest.mark.parametrize("name", ("llama3", "model-1.2", "a" * 64))
def test_pull_wrapper_accepts_only_the_expected_immutable_reference_syntax(name):
    assert _model_pattern().search(name + "@sha256:" + "a" * 64)


@pytest.mark.parametrize("value", (
    "llama3:8b", "llama3", "https://models.example/model", "../model@sha256:" + "a" * 64,
    "org/model@sha256:" + "a" * 64, "Model@sha256:" + "a" * 64,
    "model@sha256:" + "A" * 64, "model@sha256:" + "a" * 63,
    "model@sha256:" + "a" * 64 + "\n", " model@sha256:" + "a" * 64,
    "a" * 65 + "@sha256:" + "a" * 64, "",
))
def test_pull_wrapper_rejects_mutable_or_path_like_input(value):
    assert _model_pattern().search(value) is None


def test_pull_wrapper_checks_supplied_model_before_discovery_and_preserves_models_setting():
    source = _source(SCRIPTS[1])
    assert "[string]$Model = ''" in source and "[string]$Models = ''" in source
    validation = source.index("$Model -cnotmatch $immutableModel")
    assert "$Model.Length -gt 136" in source
    assert validation < source.index("[IO.Path]::GetFullPath")
    assert validation < source.index("& $startup -RepositoryRoot $repo")
    assert "The legacy Models option is not applied" in source
    assert "No model was installed, selected or approved" in source
    assert "llama3:8b" not in source


@pytest.mark.parametrize("relative", SCRIPTS)
def test_drive_mapping_precedes_ancestor_walk_and_leaf_discovery(relative):
    source = _source(relative)
    drive_gate = source.index("if (-not $driveGuard::IsDirectFixed($driveRoot))")
    ancestor_read = source.index("$ancestor = Get-Item -LiteralPath ($ancestors[$index])")
    leaf_read = source.index("$startupItem = Get-Item -LiteralPath $startup")
    delegation = source.index("& $startup -RepositoryRoot $repo")
    assert drive_gate < ancestor_read < leaf_read < delegation
    item_reads = list(re.finditer(r"\bGet-Item\s+-LiteralPath", source))
    assert len(item_reads) == 2 and item_reads[0].start() >= ancestor_read
    assert "$cursor = [IO.Path]::GetDirectoryName($startup)" in source
    assert "for ($index = $ancestors.Count - 1; $index -ge 0; $index--)" in source
    assert "-not $ancestor.PSIsContainer" in source
    assert "($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)" in source


def _drive_mapping_pattern(relative: str) -> re.Pattern[str]:
    source = _source(relative)
    match = re.search(r'@"([^"\n]*HarddiskVolume[^"\n]*)"', source)
    assert match is not None
    return re.compile(match.group(1).replace(r"\z", r"\Z"))


@pytest.mark.parametrize("relative", SCRIPTS)
def test_native_drive_probe_is_private_bounded_and_requires_a_single_fixed_mapping(relative):
    source = _source(relative)
    assert "[Guid]::NewGuid().ToString('N')" in source
    assert "-PassThru" in source
    assert 'EntryPoint="QueryDosDeviceW"' in source
    assert "SizeParamIndex=2" in source and "ArraySubType=UnmanagedType.U2" in source
    assert "new char[2048]" in source
    assert "written == 0 || written > (uint)target.Length" in source
    assert "mappings.Length != 1" in source
    assert "new DriveInfo(root).DriveType == DriveType.Fixed" in source
    assert "-as [type]" not in source
    probe = source.index("uint written = QueryDosDevice(")
    fixed = source.index("new DriveInfo(root).DriveType == DriveType.Fixed")
    assert probe < fixed < source.index("$ancestor = Get-Item")


@pytest.mark.parametrize("relative", SCRIPTS)
@pytest.mark.parametrize("mapping", (r"\Device\HarddiskVolume1", r"\Device\HarddiskVolume123"))
def test_declared_native_mapping_grammar_accepts_direct_volume_only(relative, mapping):
    assert _drive_mapping_pattern(relative).search(mapping)


@pytest.mark.parametrize("relative", SCRIPTS)
@pytest.mark.parametrize("mapping", (
    r"\??\C:\owned-subst", r"\Device\LanmanRedirector\server\share",
    r"\Device\HarddiskVolume1\subdirectory", r"\Device\HarddiskVolumeShadowCopy1",
    r"\Device\HarddiskVolume", "\\Device\\HarddiskVolume1\n",
))
def test_declared_native_mapping_grammar_refuses_subst_network_and_suffixes(relative, mapping):
    assert _drive_mapping_pattern(relative).search(mapping) is None
