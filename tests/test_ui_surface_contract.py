"""Repository-wide, offscreen contracts for Angerona's interactive GUI surface."""
from __future__ import annotations

import ast
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import SIGNAL
from PySide6.QtWidgets import QApplication, QPushButton, QScrollArea

from angerona.core.config import Config
from angerona.core.menu_info import MENU_INFO, normalize_tab_label
from angerona.gui.attack_heatmap import AttackHeatmapWindow
from angerona.gui.pages import SettingsDialog


_ROOT = Path(__file__).resolve().parents[1]
_GUI_ROOT = _ROOT / "src" / "angerona" / "gui"


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _expression_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _expression_name(node.value)
        if owner:
            return f"{owner}.{node.attr}"
    return None


def _is_push_button_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _expression_name(node.func) in {"QPushButton", "QtWidgets.QPushButton"}


def _is_action_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _expression_name(node.func) in {"QAction", "QtGui.QAction"}


def _button_target(node: ast.AST) -> str | None:
    if isinstance(node, ast.Assign) and _is_push_button_call(node.value):
        return _expression_name(node.targets[0]) if len(node.targets) == 1 else None
    if isinstance(node, ast.AnnAssign) and _is_push_button_call(node.value):
        return _expression_name(node.target)
    return None


def _loop_button_targets(node: ast.For) -> tuple[str, ...]:
    """Return widget references aliased by ``for button, ... in (...)``."""
    if not isinstance(node.iter, (ast.Tuple, ast.List, ast.Set)):
        return ()
    references: list[str] = []
    for element in node.iter.elts:
        for candidate in ast.walk(element):
            name = _expression_name(candidate)
            if name and name.startswith("self.") and name not in references:
                references.append(name)
    return tuple(references)


def _loop_button_alias(node: ast.For) -> str | None:
    if isinstance(node.target, (ast.Tuple, ast.List)) and node.target.elts:
        return _expression_name(node.target.elts[0])
    return _expression_name(node.target)


def test_every_declared_gui_push_button_has_click_wiring() -> None:
    """Catch dead buttons at review time, including buttons created in tab builders."""
    missing: list[str] = []
    button_count = 0
    for path in sorted(_GUI_ROOT.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        button_count += sum(_is_push_button_call(node) for node in ast.walk(tree))
        functions = (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        for function in functions:
            created: list[tuple[str, int]] = []
            connected: set[str] = set()
            loop_aliases: list[tuple[str, tuple[str, ...]]] = []
            for node in ast.walk(function):
                target = _button_target(node)
                if target:
                    created.append((target, node.lineno))
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "connect"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr
                    in {"clicked", "pressed", "released", "toggled"}
                ):
                    target = _expression_name(node.func.value.value)
                    if target:
                        connected.add(target)
                if isinstance(node, ast.For):
                    alias = _loop_button_alias(node)
                    targets = _loop_button_targets(node)
                    if alias and targets:
                        loop_aliases.append((alias, targets))
            for alias, targets in loop_aliases:
                if alias in connected:
                    connected.update(targets)
            missing.extend(
                f"{path.name}:{line} {function.name} -> {target}"
                for target, line in created
                if target not in connected
            )

    # This inventory deliberately covers direct QPushButton declarations.  It
    # excludes implicit controls such as combo-box arrows and table headers.
    assert button_count >= 240
    assert not missing, "GUI buttons without a signal connection:\n" + "\n".join(missing)


def test_all_literal_tab_labels_are_visible_and_nonempty() -> None:
    tab_count = 0
    bad: list[str] = []
    for path in sorted(_GUI_ROOT.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "addTab"
            ):
                continue
            tab_count += 1
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                if not str(node.args[1].value or "").strip():
                    bad.append(f"{path.name}:{node.lineno}")
    assert tab_count >= 46
    assert not bad, "Tabs with blank literal labels: " + ", ".join(bad)


def test_every_declared_menu_action_has_signal_or_exact_menu_dispatch() -> None:
    missing: list[str] = []
    action_count = 0
    for path in sorted(_GUI_ROOT.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        action_count += sum(_is_action_call(node) for node in ast.walk(tree))
        for function in (
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ):
            created: list[tuple[str, int]] = []
            dispatched: set[str] = set()
            for node in ast.walk(function):
                if isinstance(node, ast.Assign) and _is_action_call(node.value):
                    created.extend(
                        (name, node.lineno)
                        for target in node.targets
                        if (name := _expression_name(target))
                    )
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "connect"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "triggered"
                ):
                    name = _expression_name(node.func.value.value)
                    if name:
                        dispatched.add(name)
                if isinstance(node, ast.Compare):
                    compared = {
                        name
                        for candidate in (node.left, *node.comparators)
                        if (name := _expression_name(candidate))
                    }
                    dispatched.update(compared)
            missing.extend(
                f"{path.name}:{line} {function.name} -> {name}"
                for name, line in created
                if name not in dispatched
            )
    assert action_count >= 9
    assert not missing, "Menu actions without dispatch:\n" + "\n".join(missing)


def test_contextual_info_catalog_covers_each_registered_tab_exactly_once() -> None:
    assert sum(len(topics) for topics in MENU_INFO.values()) == 32
    for surface, topics in MENU_INFO.items():
        labels = [normalize_tab_label(topic.title) for topic in topics]
        assert len(labels) == len(set(labels)), surface
        assert all(label for label in labels)


def test_settings_tabs_buttons_and_close_behavior_offscreen(tmp_path: Path) -> None:
    app = _app()
    dialog = SettingsDialog(
        Config(data_dir=tmp_path), lambda: None, lambda _theme: None
    )
    expected = [
        "Overview",
        "Information",
        "General",
        "System",
        "Adversary Combat",
        "Enterprise",
        "ARIA",
        "Trusted Processes",
        "Mobile Integration",
        "API Keys",
        "Info",
    ]
    try:
        assert dialog.isModal()
        assert dialog.minimumWidth() >= 720
        assert [
            dialog.tabs.tabText(index) for index in range(dialog.tabs.count())
        ] == expected
        for index, label in enumerate(expected[:-1]):
            dialog.tabs.setCurrentIndex(index)
            app.processEvents()
            assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == label
            assert isinstance(dialog.tabs.widget(index), QScrollArea)
            assert dialog._settings_sandbox_btn.isEnabled()
            assert label in dialog._settings_sandbox_btn.text()
            assert dialog._settings_sandbox_btn.toolTip()

        buttons = dialog.findChildren(QPushButton)
        assert len(buttons) >= 35
        for button in buttons:
            assert button.text().strip() or not button.icon().isNull()
            assert button.receivers(SIGNAL("clicked()")) > 0, button.text()

        dialog.show()
        app.processEvents()
        assert dialog.isVisible()
        dialog._btn_cancel.click()
        app.processEvents()
        assert not dialog.isVisible()
    finally:
        dialog.close()
        app.processEvents()


def test_primary_adaptation_copy_is_spelled_consistently() -> None:
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            _GUI_ROOT / "adaptation_workbench.py",
            _GUI_ROOT / "help_content.py",
            _GUI_ROOT / "main_window.py",
            _GUI_ROOT / "tour.py",
        )
    )
    for user_visible_typo in (
        '"ADAPTION"',
        '"Adaption —',
        '"Angerona Adaption"',
        '"Adaption busy"',
        '"Adaption safety model"',
        '"Adaption phases"',
        '"Adaption operation active"',
    ):
        assert user_visible_typo not in sources


def test_attack_heatmap_fits_compact_desktops_and_keeps_all_tabs_reachable() -> None:
    app = _app()
    dialog = AttackHeatmapWindow()
    try:
        dialog.resize(800, 600)
        dialog.show()
        app.processEvents()
        available = dialog.screen().availableGeometry()
        assert dialog.minimumWidth() <= available.width()
        assert dialog.minimumHeight() <= available.height()
        assert dialog.width() <= available.width()
        assert dialog.height() <= available.height()
        assert [
            normalize_tab_label(dialog._tabs.tabText(index))
            for index in range(dialog._tabs.count())
        ] == ["live heat", "coverage", "top techniques", "info"]
        for index in range(dialog._tabs.count()):
            dialog._tabs.setCurrentIndex(index)
            app.processEvents()
            assert dialog._tabs.currentIndex() == index
        for name in (
            "HeatmapExplainPosture",
            "HeatmapExportNavigator",
            "HeatmapResetCounts",
        ):
            button = dialog.findChild(QPushButton, name)
            assert button is not None and button.isVisible()
            right_edge = button.mapTo(dialog, button.rect().bottomRight()).x()
            assert right_edge <= dialog.contentsRect().right()
    finally:
        dialog.close()
        app.processEvents()
