from __future__ import annotations

import inspect
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from angerona.core.module_base import BaseModule
from angerona.core.source_sandbox import SourceSandboxWorkspace


def _directory_link(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (NotImplementedError, OSError):
        pass
    if os.name == "nt":
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return
    pytest.skip("directory symlinks/reparse points are unavailable")


def test_source_sandbox_rejects_a_reparse_source_root(tmp_path: Path) -> None:
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    redirected = tmp_path / "redirected-source"
    _directory_link(redirected, installed)

    try:
        with pytest.raises(ValueError, match="plain directory"):
            SourceSandboxWorkspace(
                "probe",
                ("probe.py",),
                source_root=redirected,
                sandbox_root=tmp_path / "runtime",
            )
    finally:
        os.rmdir(redirected)


def test_source_sandbox_rejects_parent_reparse_swap_before_save(tmp_path: Path) -> None:
    source_root = tmp_path / "installed"
    source_root.mkdir()
    (source_root / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    workspace = SourceSandboxWorkspace(
        "probe",
        ("probe.py",),
        source_root=source_root,
        sandbox_root=tmp_path / "runtime",
    )
    workspace.ensure()
    parked = tmp_path / "parked-sandbox"
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace.root.rename(parked)
    _directory_link(workspace.root, outside)
    try:
        with pytest.raises(ValueError, match="symlink or reparse point|not plain"):
            workspace.save("probe.py", "VALUE = 2\n")
        assert not (outside / "probe.py").exists()
    finally:
        os.rmdir(workspace.root)
        parked.rename(workspace.root)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory-handle gate")
def test_atomic_replace_pins_parent_against_toctou_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from angerona.core import source_sandbox

    source_root = tmp_path / "installed"
    source_root.mkdir()
    (source_root / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    workspace = SourceSandboxWorkspace(
        "probe",
        ("probe.py",),
        source_root=source_root,
        sandbox_root=tmp_path / "runtime",
    )
    workspace.ensure()
    real_token_hex = source_sandbox.secrets.token_hex
    blocked: list[bool] = []

    def attempted_swap(_nbytes: int) -> str:
        parked = workspace.root.with_name(workspace.root.name + "-swapped")
        try:
            workspace.root.rename(parked)
        except OSError:
            blocked.append(True)
        else:  # pragma: no cover - would prove the gate failed
            parked.rename(workspace.root)
            pytest.fail("sandbox parent could be renamed during atomic replace")
        return real_token_hex(12)

    monkeypatch.setattr(source_sandbox.secrets, "token_hex", attempted_swap)
    workspace.save("probe.py", "VALUE = 2\n")

    assert blocked == [True]
    assert workspace.read("probe.py") == "VALUE = 2\n"


def test_gui_editor_saves_only_a_source_sandbox_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    from angerona.gui import sandbox_editor

    installed = tmp_path / "installed" / "probe.py"
    installed.parent.mkdir()
    original = "VALUE = 1\n"
    installed.write_text(original, encoding="utf-8")

    class Probe(BaseModule):
        name = "Probe"

    probe = Probe()
    manager = SimpleNamespace(modules={"Probe": probe})
    real_workspace = SourceSandboxWorkspace

    def isolated_workspace(key, paths, *, source_root=None, sandbox_root=None):
        return real_workspace(
            key,
            paths,
            source_root=source_root,
            sandbox_root=tmp_path / "runtime",
        )

    monkeypatch.setattr(sandbox_editor, "SourceSandboxWorkspace", isolated_workspace)
    monkeypatch.setattr(sandbox_editor, "_module_source_file", lambda _mod: installed)

    app = QApplication.instance() or QApplication([])
    window = sandbox_editor.SandboxEditor(manager, bus=None, preselect="Probe")
    try:
        window.editor.setPlainText("VALUE = 2\n")
        window._apply_changes()
        workspace, relative = window._workspace_for_module("Probe", probe)

        assert installed.read_text(encoding="utf-8") == original
        assert workspace.read(relative) == "VALUE = 2\n"
        assert manager.modules["Probe"] is probe
        editor_source = inspect.getsource(sandbox_editor.SandboxEditor)
        assert "importlib.reload" not in editor_source
        assert ".write_text(" not in editor_source
    finally:
        window._close_confirmed = True
        window.close()
        app.processEvents()
