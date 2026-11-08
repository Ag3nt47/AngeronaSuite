"""Canonical peers omit implicit import roots without changing role identity."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from angerona.resilience import supervisor


@pytest.mark.parametrize("module", [
    "angerona", "angerona.resilience.watchdog", "angerona.resilience.scanner",
    "angerona.resilience.status_ui",
])
def test_only_canonical_module_launches_receive_isolation(module):
    original = [sys.executable, "-m", module, "--presentation-option"]
    assert supervisor._isolated_peer_argv(original) == [original[0], "-I", *original[1:]]
    assert original == [sys.executable, "-m", module, "--presentation-option"]


@pytest.mark.parametrize("tail", [
    ["-m", "unrelated.application"],
    ["-m", "angerona.resilience.unregistered"],
    ["-c", "print('angerona')"],
    ["-m"],
    ["-u"],
    ["-u"] * 17,
])
def test_unregistered_or_incomplete_commands_remain_unchanged(tail):
    original = [sys.executable, *tail]
    assert supervisor._isolated_peer_argv(original) == original


def test_explicit_isolation_and_other_interpreter_options_preserve_identity():
    original = [sys.executable, "-u", "-X", "utf8", "-m", "angerona.resilience.scanner"]
    isolated = supervisor._isolated_peer_argv(original)
    assert isolated == [original[0], "-I", *original[1:]]
    assert supervisor._isolated_peer_argv(isolated) == isolated
    assert supervisor._invocation_arguments_match(SimpleNamespace(), isolated,
                                                  (sys.executable, "-m", "angerona.resilience.scanner"))


def test_other_interpreter_and_frozen_commands_are_preserved(tmp_path, monkeypatch):
    other = [str(tmp_path / Path(sys.executable).name), "-m", "angerona"]
    assert supervisor._isolated_peer_argv(other) == other
    original = [sys.executable, "-m", "angerona"]
    monkeypatch.setattr(supervisor.sys, "frozen", True, raising=False)
    assert supervisor._isolated_peer_argv(original) == original


@pytest.mark.skipif(os.name != "nt", reason="Windows python/pythonw sibling selection")
def test_current_interpreter_sibling_is_isolated():
    current = Path(sys.executable)
    sibling = current.with_name("pythonw.exe" if current.name.casefold() == "python.exe" else "python.exe")
    original = [str(sibling), "-m", "angerona.resilience.watchdog"]
    assert supervisor._isolated_peer_argv(original) == [original[0], "-I", *original[1:]]


def test_only_exact_canonical_blackbox_script_is_isolated(tmp_path, monkeypatch):
    from angerona.core import data_paths

    monkeypatch.setattr(data_paths, "project_root", lambda: tmp_path)
    canonical = [sys.executable, str(tmp_path / "blackbox_recorder.py"), "--show"]
    assert supervisor._isolated_peer_argv(canonical) == [canonical[0], "-I", *canonical[1:]]
    for script in ("blackbox_recorder.py", str(tmp_path / "other" / "blackbox_recorder.py"),
                   str(tmp_path / "generic.py")):
        original = [sys.executable, script]
        assert supervisor._isolated_peer_argv(original) == original


def test_production_spawn_passes_isolated_command_and_preserves_component_argv(monkeypatch):
    captured = []
    sentinel = object()
    if os.name == "nt":
        from angerona.core import windows_child_job

        monkeypatch.setattr(windows_child_job, "launch_windows_child",
                            lambda argv, *_a, **_kw: captured.append(argv) or sentinel)
    else:
        monkeypatch.setattr(supervisor.subprocess, "Popen",
                            lambda argv, **_kw: captured.append(argv) or sentinel)
    component = supervisor.Component("scanner", [sys.executable, "-m", "angerona.resilience.scanner"])
    assert supervisor.spawn_detached(component.argv, window="hidden") is sentinel
    assert captured == [[sys.executable, "-I", "-m", "angerona.resilience.scanner"]]
    assert component.argv == [sys.executable, "-m", "angerona.resilience.scanner"]


def test_inert_owned_child_cannot_import_cwd_shadow(tmp_path, monkeypatch):
    """Test seam admits one absent module, never a Core/sensor/UI entry point.

    Production spawn, sanitized environment and retained process retirement are
    real. Only the private module allowlist receives the absent inert probe.
    The separately tested production allowlist remains closed.
    """
    probe = "angerona.resilience._isolation_probe_"
    monkeypatch.setattr(supervisor, "_ISOLATED_PEER_MODULES", frozenset({probe}))
    shadow = tmp_path / "angerona"
    shadow.mkdir()
    marker = shadow / "tripwire.txt"
    (shadow / "__init__.py").write_text(
        "from pathlib import Path\nPath(__file__).with_name('tripwire.txt').write_text('shadow-imported')\n",
        encoding="utf-8",
    )
    owner = supervisor.spawn_detached([sys.executable, "-m", probe], cwd=str(tmp_path), window="hidden")
    try:
        assert owner.wait(timeout=15.0) == 1  # The real package has no probe module.
        wait_tree = getattr(owner, "wait_tree", None)
        if callable(wait_tree):
            wait_tree(timeout=10.0)
        assert owner.poll() is not None
        assert not marker.exists()
    finally:
        try:
            if owner.poll() is None:
                owner.terminate()
                owner.wait(timeout=10.0)
            wait_tree = getattr(owner, "wait_tree", None)
            if callable(wait_tree):
                wait_tree(timeout=10.0)
        finally:
            close = getattr(owner, "close", None)
            if callable(close):
                close()
