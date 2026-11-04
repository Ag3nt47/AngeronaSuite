"""The shipped Self-Test guidance covers the complete source inventory."""
from __future__ import annotations

import ast
from pathlib import Path

from angerona.core.selftest_guidance import _BUILTIN_GUIDANCE, module_guidance


def test_every_bundled_module_has_distinct_guidance():
    modules_dir = Path(__file__).resolve().parents[1] / "src" / "angerona" / "modules"
    covered = {}
    for path in modules_dir.glob("*.py"):
        source = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for cls in source.body:
            if not isinstance(cls, ast.ClassDef):
                continue
            if not any(
                (isinstance(base, ast.Name) and base.id == "BaseModule")
                or (isinstance(base, ast.Attribute) and base.attr == "BaseModule")
                for base in cls.bases
            ):
                continue
            assert path.stem not in covered, "review shared source identities before adding guidance"
            candidate = type(cls.name, (), {"__module__": f"angerona.modules.{path.stem}"})()
            covered[path.stem] = module_guidance(candidate)

    assert covered == _BUILTIN_GUIDANCE
    assert len(set(covered.values())) == len(covered)


def test_display_name_and_code_do_not_select_builtin_guidance():
    custom = type("SpywareGuardModule", (), {
        "__module__": "angerona_ext_spyware_guard", "name": "SpywareGuard", "CODE": "SPYG",
    })()

    assert module_guidance(custom) == module_guidance(object())
    assert "publisher's documented prerequisites" in module_guidance(custom)


def test_overdrive_has_guidance_outside_discovered_sensor_inventory():
    from angerona.core.perf_governor import PerfGovernor

    assert "Overdrive" in module_guidance(PerfGovernor())
