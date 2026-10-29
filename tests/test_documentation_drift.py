from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tools.publish_github_update import (
    PublicationError,
    github_repository_from_origin,
)
from tools import validate_documentation_drift as drift
from tools.validate_documentation_drift import validate, validate_current_versions


ROOT = Path(__file__).resolve().parents[1]


def _version_fixture(root: Path, version: str = "1.14.1") -> None:
    package = root / "src/angerona"
    package.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "angerona"\nversion = "{version}"\n', encoding="utf-8",
    )
    (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "README.md").write_text(f"# Fixture\n\n## Current development: v{version}\n", encoding="utf-8")
    (root / "llms.txt").write_text(
        f"# Fixture\nVersion: {version}\n\n## LATEST (v{version} — current)\n", encoding="utf-8",
    )
    (root / "ANGERONA_CAPABILITIES.md").write_text(
        f"Current development version: **v{version}**.\n", encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(f"# Changelog\n\n## {version} — current\n", encoding="utf-8")
    (root / "tools").mkdir(exist_ok=True)
    (root / "tools/Show-AngeronaStartupRecovery.ps1").write_text(
        f"$form.Text = 'Angerona {version} - Safe Startup'\n"
        f'$brand.Text = "ANGERONA  {version}`r`nSafe Startup dashboard"\n', encoding="utf-8",
    )


def test_repository_documentation_claims_are_synchronized():
    assert validate(ROOT) == []
    assert (
        github_repository_from_origin(
            "https://github.com/Ag3nt47/AngeronaSuite.git"
        )
        == "Ag3nt47/AngeronaSuite"
    )
    try:
        github_repository_from_origin(
            "https://token@github.com/Ag3nt47/AngeronaSuite.git"
        )
    except PublicationError:
        pass
    else:
        raise AssertionError("credential-bearing GitHub origin was accepted")

    push_helper = (ROOT / "push-to-github.bat").read_text(encoding="utf-8")
    assert "tools\\publish_github_update.py" in push_helper
    assert "\ngit push\n" not in push_helper.replace("\r\n", "\n")
    publisher = (ROOT / "tools" / "publish_github_update.py").read_text(
        encoding="utf-8"
    )
    transport = (ROOT / "tools" / "publication_transport.py").read_text(
        encoding="utf-8"
    )
    assert '"--no-follow-tags"' in publisher
    assert 'f"core.hooksPath={null_path}"' in transport
    assert "null_path = os.devnull" in transport
    assert '"GIT_CONFIG_NOSYSTEM": "1"' in transport
    assert 'parser.add_argument("--repository"' not in publisher
    pull_helper = (ROOT / "pull-from-github.bat").read_text(encoding="utf-8")
    assert "[INCOMPLETE] Local branch is ahead of GitHub." in pull_helper
    assert "merge --ff-only" in pull_helper

    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert "verify_published_readme_assets.py" in ci_workflow
    assert '--repository "$ANGERONA_PUBLIC_REPOSITORY"' in ci_workflow

    release_path = ROOT / ".github" / "workflows" / "release.yml"
    release_workflow = release_path.read_text(encoding="utf-8")
    assert "verify-release-source:" in release_workflow
    assert "Fail if release source moved or left public main" in release_workflow
    workflow = yaml.safe_load(release_workflow)
    jobs = workflow["jobs"]
    assert jobs["prepare-windows"]["needs"] == "verify-release-source"
    assert jobs["build-posix"]["needs"] == "verify-release-source"
    assert "verify-release-source" in jobs["publish-release"]["needs"]
    publish_steps = jobs["publish-release"]["steps"]
    publish_names = [step.get("name", "") for step in publish_steps]
    final_gate = publish_names.index("Final immutable tag and default-main check")
    release_action = publish_names.index("Publish GitHub Release")
    assert final_gate + 1 == release_action


def test_checker_detects_marker_and_module_drift(tmp_path):
    _version_fixture(tmp_path, drift._package_version((ROOT / "src/angerona/__init__.py").read_text(encoding="utf-8")))
    (tmp_path / "src" / "angerona" / "modules").mkdir()
    (tmp_path / "src" / "angerona" / "modules" / "one.py").write_text(
        "class One(BaseModule):\n    pass\n", encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme = re.sub(
        r"tests=\d+ skips=\d+ modules=\d+",
        "tests=999 skips=2 modules=999",
        readme,
    )
    # Invalid image cases must remain present when product screenshots change.
    readme += (
        "\n![Malformed image fixture](docs/screenshots/fake.png)\n"
        "![Unsafe image fixture](../escape.png)\n"
    )
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    screenshots = tmp_path / "docs" / "screenshots"
    screenshots.mkdir(parents=True)
    (screenshots / "fake.png").write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    )

    errors = validate(tmp_path)
    assert any("final verification count disagrees" in item for item in errors)
    assert any("static discovery=1" in item for item in errors)
    assert any("image is unavailable" in item for item in errors)
    assert any("unsafe local image target" in item for item in errors)
    assert any("invalid PNG structure" in item for item in errors)


@pytest.mark.parametrize("relative,old,new", [
    ("pyproject.toml", 'version = "1.14.1"', 'version = "1.14.2"'),
    ("src/angerona/__init__.py", '"1.14.1"', '"1.14.2"'),
    ("README.md", "v1.14.1", "v1.14.0"),
    ("llms.txt", "Version: 1.14.1", "Version: 1.14.0"),
    ("llms.txt", "LATEST (v1.14.1", "LATEST (v1.14.0"),
    ("ANGERONA_CAPABILITIES.md", "v1.14.1", "v1.14.0"),
    ("CHANGELOG.md", "1.14.1", "1.14.0"),
    ("tools/Show-AngeronaStartupRecovery.ps1", "Angerona 1.14.1", "Angerona 1.14.0"),
    ("tools/Show-AngeronaStartupRecovery.ps1", "ANGERONA  1.14.1", "ANGERONA  1.14.0"),
])
def test_checker_rejects_current_version_drift(tmp_path, relative, old, new):
    _version_fixture(tmp_path)
    path = tmp_path / relative
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    errors = validate_current_versions(tmp_path)
    if relative == "pyproject.toml":
        assert any("__version__ disagrees with project.version 1.14.2" in error for error in errors)
    else:
        assert any(relative in error for error in errors)


def test_checker_keeps_historical_and_component_versions_independent(tmp_path):
    _version_fixture(tmp_path)
    for relative in ("README.md", "ANGERONA_CAPABILITIES.md", "CHANGELOG.md"):
        with (tmp_path / relative).open("a", encoding="utf-8") as stream:
            stream.write("\n## Historical 1.14.0 evidence\nUnchanged component version: 1.14.0.\n")
    with (tmp_path / "llms.txt").open("a", encoding="utf-8") as stream:
        stream.write("\n## LATEST (v1.14.0 — historical checkpoint)\nVersion: 1.14.0\n")
    modules = tmp_path / "src/angerona/modules"
    modules.mkdir()
    (modules / "legacy.py").write_text('version = "1.14.0"\n', encoding="utf-8")
    assert validate_current_versions(tmp_path) == []


@pytest.mark.parametrize("source", [
    '[project]\nversion = "1.14.1"\nversion = "1.14.1"\n',
    '[project]\nversion = "1.14.1"\n"version" = "1.14.1"\n',
    '[project]\nversion = "1.14.1"\n[project]\nversion = "1.14.1"\n',
    '[project]\nversion = "1.14.1.dev1"\n',
    '[project]\nversion = "1.14.01"\n',
    '[project]\nversion = 1.14\n',
    '[project]\n',
])
def test_checker_rejects_ambiguous_or_nonstable_project_version(tmp_path, source):
    _version_fixture(tmp_path)
    (tmp_path / "pyproject.toml").write_text(source, encoding="utf-8")
    assert any("explicit stable three-part project.version" in error for error in validate_current_versions(tmp_path))


@pytest.mark.parametrize("source", [
    '__version__ = "1.14.1"\n__version__ = "1.14.1"\n',
    '__version__ = "1.14." + "1"\n',
    '__version__ = "1.14.1"\nif something:\n    __version__ = "1.14.0"\n',
    '__version__ = "1.14.1.dev1"\n',
    '__version__ = 1\n',
    '__version__ = (\n',
    'pass\n',
])
def test_checker_rejects_ambiguous_or_nonliteral_package_version(tmp_path, source):
    _version_fixture(tmp_path)
    (tmp_path / "src/angerona/__init__.py").write_text(source, encoding="utf-8")
    assert any("literal stable three-part __version__" in error for error in validate_current_versions(tmp_path))


def test_checker_reads_package_version_without_executing_package(tmp_path):
    _version_fixture(tmp_path)
    marker = tmp_path / "must-not-run.txt"
    (tmp_path / "src/angerona/__init__.py").write_text(
        f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\n'
        '__version__: str = "1.14.1"\n', encoding="utf-8",
    )
    assert validate_current_versions(tmp_path) == []
    assert not marker.exists()


@pytest.mark.parametrize("relative", [
    "pyproject.toml", "src/angerona/__init__.py", "README.md", "llms.txt",
    "ANGERONA_CAPABILITIES.md", "CHANGELOG.md",
    "tools/Show-AngeronaStartupRecovery.ps1",
])
def test_checker_holds_missing_current_version_metadata(tmp_path, relative):
    _version_fixture(tmp_path)
    (tmp_path / relative).unlink()
    assert any(relative in error for error in validate_current_versions(tmp_path))


def test_checker_bounds_metadata_and_accepts_windows_line_endings(tmp_path, monkeypatch):
    _version_fixture(tmp_path)
    for relative in (
        "pyproject.toml", "src/angerona/__init__.py", "README.md", "llms.txt",
        "ANGERONA_CAPABILITIES.md", "CHANGELOG.md",
        "tools/Show-AngeronaStartupRecovery.ps1",
    ):
        path = tmp_path / relative
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert validate_current_versions(tmp_path) == []
    monkeypatch.setattr(drift, "MAX_VERSION_METADATA_BYTES", 128)
    (tmp_path / "src/angerona/__init__.py").write_bytes(b"#" * 129)
    assert any("unreadable or oversized" in error for error in validate_current_versions(tmp_path))
