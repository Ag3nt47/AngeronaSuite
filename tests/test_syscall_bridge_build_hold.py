"""Inert checks for the unsupported legacy bridge build entry.

These cases execute only the Python build hold with packaging/native effects
trapped. The C check verifies directive placement, not native correctness or a
successful compiler run.
"""
from __future__ import annotations

import builtins
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "syscall_bridge" / "setup.py"


@pytest.mark.parametrize("arguments", [
    [],
    ["--help"],
    ["--name"],
    ["build_ext", "--inplace"],
    ["build_ext", "--force"],
    ["install"],
    ["bdist_wheel"],
], ids=["empty", "help", "metadata", "inplace", "force", "install", "wheel"])
@pytest.mark.parametrize("override_attempt", [False, True], ids=["ordinary", "override-env"])
@pytest.mark.parametrize("run_name", ["__main__", "legacy_bridge_setup_review"])
def test_legacy_build_entry_holds_before_packaging_or_native_effects(
    monkeypatch, arguments, override_attempt, run_name,
):
    imports = []
    effects = []
    real_import = builtins.__import__

    def forbidden_effect(*args, **kwargs):
        effects.append("packaging-or-native-effect")
        raise AssertionError("The held bridge attempted packaging or native work")

    package = ModuleType("setuptools")
    package.setup = forbidden_effect
    package.Extension = forbidden_effect
    monkeypatch.setitem(sys.modules, "setuptools", package)

    def guarded_import(name, *args, **kwargs):
        if name == "setuptools" or name.startswith(("setuptools.", "distutils")):
            imports.append(name)
            raise AssertionError("The legacy build hold imported packaging helpers")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(subprocess, "Popen", forbidden_effect)
    monkeypatch.setattr(os, "system", forbidden_effect)
    monkeypatch.setattr(os, "startfile", forbidden_effect, raising=False)
    monkeypatch.setattr(sys, "argv", [str(BUILD), *arguments])
    if override_attempt:
        for key, value in {
            "ANGERONA_NATIVE_BRIDGE": "1",
            "ANGERONA_ALLOW_UNSAFE_SYSCALL_BRIDGE": "1",
            "CC": "cl.exe",
            "CFLAGS": "/DANGERONA_NATIVE_BRIDGE_BUILD_HELD=0",
        }.items():
            monkeypatch.setenv(key, value)

    with pytest.raises(SystemExit) as outcome:
        runpy.run_path(str(BUILD), run_name=run_name)

    assert isinstance(outcome.value.code, str)
    assert "ANGERONA_NATIVE_BRIDGE_BUILD_HELD" in outcome.value.code
    assert imports == []
    assert effects == []


def test_direct_c_compilation_is_unconditionally_held_before_native_headers():
    source = (ROOT / "syscall_bridge" / "syscall_bridge.c").read_text(encoding="utf-8")
    without_comments = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL).lstrip()
    first_line = without_comments.splitlines()[0]
    assert first_line.startswith("#error ")
    assert "ANGERONA_NATIVE_BRIDGE_BUILD_HELD" in first_line
    assert "#include" not in without_comments[:without_comments.index(first_line)]
