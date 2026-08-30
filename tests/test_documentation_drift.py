from __future__ import annotations

import re
from pathlib import Path

import yaml

from tools.publish_github_update import (
    PublicationError,
    github_repository_from_origin,
)
from tools.validate_documentation_drift import validate


ROOT = Path(__file__).resolve().parents[1]


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
    (tmp_path / "src" / "angerona" / "modules").mkdir(parents=True)
    (tmp_path / "src" / "angerona" / "modules" / "one.py").write_text(
        "class One(BaseModule):\n    pass\n", encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme = re.sub(
        r"tests=\d+ skips=\d+ modules=\d+",
        "tests=999 skips=2 modules=999",
        readme,
    )
    readme = readme.replace(
        "docs/screenshots/angerona-v1.11-dashboard.png",
        "docs/screenshots/fake.png",
    )
    readme = readme.replace(
        "docs/screenshots/angerona-v1.11-soar-review.png",
        "../escape.png",
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
