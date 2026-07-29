from __future__ import annotations

from pathlib import Path

from tools.validate_documentation_drift import validate


ROOT = Path(__file__).resolve().parents[1]


def test_repository_documentation_claims_are_synchronized():
    assert validate(ROOT) == []


def test_checker_detects_marker_and_module_drift(tmp_path):
    (tmp_path / "src" / "angerona" / "modules").mkdir(parents=True)
    (tmp_path / "src" / "angerona" / "modules" / "one.py").write_text(
        "class One(BaseModule):\n    pass\n", encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme = readme.replace(
        "tests=334 skips=2 modules=65",
        "tests=999 skips=2 modules=999",
    )
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")

    errors = validate(tmp_path)
    assert any("final verification count disagrees" in item for item in errors)
    assert any("static discovery=1" in item for item in errors)
