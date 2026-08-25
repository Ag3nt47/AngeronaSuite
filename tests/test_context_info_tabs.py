from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from angerona.core.data_paths import project_root
from angerona.core.menu_info import MENU_INFO, get_menu_info, validate_menu_info
from angerona.core.source_sandbox import SourceSandboxWorkspace


def test_menu_info_catalog_is_complete_and_points_to_real_sources() -> None:
    validate_menu_info()
    root = project_root()
    assert {
        "help", "dashboard", "settings", "operations", "attack-map",
        "red-team", "advanced-console",
    }.issubset(MENU_INFO)
    for topics in MENU_INFO.values():
        for topic in topics:
            assert topic.functions
            assert all((root / path).is_file() for path in topic.source_paths)
    assert get_menu_info("dashboard", "🛡 Scan Center").title == "Scan Center"
    assert get_menu_info("attack-map", "📊  Top Techniques").key == "attack-top"


def test_source_sandbox_save_and_reset_never_rewrite_installed_source(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "installed"
    source = source_root / "src" / "example.py"
    source.parent.mkdir(parents=True)
    original = "VALUE = 1\n"
    source.write_text(original, encoding="utf-8")
    workspace = SourceSandboxWorkspace(
        "example-menu",
        ("src/example.py",),
        source_root=source_root,
        sandbox_root=tmp_path / "runtime-sandboxes",
    )

    workspace.ensure()
    workspace.save("src/example.py", "VALUE = 2\n")

    assert source.read_text(encoding="utf-8") == original
    assert workspace.read("src/example.py") == "VALUE = 2\n"
    assert workspace.changed_paths() == ("src/example.py",)

    workspace.reset()
    assert source.read_text(encoding="utf-8") == original
    assert workspace.read("src/example.py") == original
    assert workspace.changed_paths() == ()


def test_source_sandbox_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe sandbox source path"):
        SourceSandboxWorkspace(
            "unsafe",
            ("../outside.py",),
            source_root=tmp_path,
            sandbox_root=tmp_path / "sandboxes",
        )


def test_settings_info_tab_tracks_the_last_settings_area(tmp_path: Path) -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QPushButton

    from angerona.core.config import Config
    from angerona.gui.pages import SettingsDialog

    app = QApplication.instance() or QApplication([])
    dialog = SettingsDialog(
        Config(data_dir=tmp_path), lambda: None, lambda _theme: None
    )
    try:
        labels = [
            dialog.tabs.tabText(index) for index in range(dialog.tabs.count())
        ]
        assert labels[-1] == "Info"
        assert dialog._select_tab("ARIA")
        assert dialog._select_tab("Info")
        info = dialog._context_info.info
        assert info.heading.text() == "About ARIA"
        assert "runtime data folder" in next(
            label.text() for label in info.findChildren(type(info.heading))
            if "Code sandbox:" in label.text()
        )
        buttons = {button.text() for button in info.findChildren(QPushButton)}
        assert {"Open Code Sandbox", "Reset Sandbox Changes"}.issubset(buttons)
        assert info.paths.rowCount() >= 3
    finally:
        dialog.close()
        app.processEvents()
