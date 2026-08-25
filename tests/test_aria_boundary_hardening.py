from __future__ import annotations

import inspect
import os
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from angerona.core.assistant import Assistant, ToolKind
from angerona.core.source_sandbox import SourceSandboxWorkspace
from angerona.gui.main_window import MainWindow
from angerona.gui.red_team_console import RedTeamConsole


def _aria_window_with_trust_action(calls: list[str]) -> SimpleNamespace:
    aria = Assistant(enabled=True)
    aria.register(
        "trust_running",
        ToolKind.WRITE,
        lambda: calls.append("trusted") or "trusted",
        preview=lambda: "Trust running apps by exact path.",
    )
    return SimpleNamespace(aria=aria, _aria_pending_token="")


def test_trust_running_requires_the_exact_staged_token() -> None:
    calls: list[str] = []
    window = _aria_window_with_trust_action(calls)

    staged = MainWindow._aria_action(window, "trust my running apps")
    token = window._aria_pending_token
    assert "Confirmation required" in staged
    assert len(token) == 32
    assert calls == []

    for generic in ("yes", "do it", "go ahead", "proceed", "confirm"):
        refused = MainWindow._aria_action(window, generic)
        assert "exact" in refused.lower()
        assert calls == []
        assert window._aria_pending_token == token

    assert "refused" in MainWindow._aria_action(
        window, f"confirm {token[:8]}"
    ).lower()
    assert calls == []
    assert window._aria_pending_token == token

    executed = MainWindow._aria_action(
        window, f"confirm {token}", input_channel="typed_gui"
    )
    assert "Executed trust_running" in executed
    assert calls == ["trusted"]
    assert window._aria_pending_token == ""


def test_new_write_stage_revokes_the_previous_language_token() -> None:
    calls: list[str] = []
    window = _aria_window_with_trust_action(calls)

    MainWindow._aria_action(window, "trust my running apps")
    old_token = window._aria_pending_token
    MainWindow._aria_action(window, "trust current apps")
    new_token = window._aria_pending_token

    assert old_token != new_token
    assert old_token not in window.aria.pending()
    assert new_token in window.aria.pending()
    assert not window.aria.confirm(old_token).ok
    assert calls == []


def test_opening_research_sources_is_also_an_exact_token_write() -> None:
    opened: list[str] = []
    aria = Assistant(enabled=True)
    aria.register(
        "open_research_sources",
        ToolKind.WRITE,
        lambda indicator: opened.append(indicator) or 1,
        preview=lambda indicator: f"Open sources for {indicator}.",
    )
    window = SimpleNamespace(aria=aria, _aria_pending_token="")

    MainWindow._aria_action(window, "open sources for Example.COM")
    token = window._aria_pending_token
    assert opened == []
    assert "exact" in MainWindow._aria_action(window, "yes").lower()
    MainWindow._aria_action(
        window, f"confirm {token}", input_channel="typed_gui"
    )
    assert opened == ["Example.COM"]


def test_exact_token_from_voice_or_callback_cannot_confirm() -> None:
    calls: list[str] = []
    window = _aria_window_with_trust_action(calls)
    MainWindow._aria_action(window, "trust my running apps", input_channel="voice")
    token = window._aria_pending_token

    for channel in ("voice", "callback", "untrusted", ""):
        refused = MainWindow._aria_action(
            window, f"confirm {token}", input_channel=channel
        )
        assert "only when typed" in refused.lower()
        assert window._aria_pending_token == token
        assert calls == []

    executed = MainWindow._aria_action(
        window, f"confirm {token}", input_channel="typed_gui"
    )
    assert "Executed trust_running" in executed
    assert calls == ["trusted"]


def test_red_team_editor_uses_only_sandbox_reload_and_rollback(tmp_path: Path) -> None:
    source_root = tmp_path / "installed"
    installed = source_root / "src" / "angerona" / "shark" / "red_team.py"
    installed.parent.mkdir(parents=True)
    original = "VALUE = 1\n"
    installed.write_text(original, encoding="utf-8")
    workspace = SourceSandboxWorkspace(
        "red-team-console",
        ("src/angerona/shark/red_team.py",),
        source_root=source_root,
        sandbox_root=tmp_path / "runtime",
    )

    workspace.save("src/angerona/shark/red_team.py", "VALUE = 2\n")
    assert workspace.reload("src/angerona/shark/red_team.py") == "VALUE = 2\n"
    assert installed.read_text(encoding="utf-8") == original
    workspace.rollback()
    assert workspace.reload("src/angerona/shark/red_team.py") == original
    assert installed.read_text(encoding="utf-8") == original

    save_source = inspect.getsource(RedTeamConsole._save_editor)
    assert "_editor_workspace.save" in save_source
    assert ".write_text(" not in save_source


def test_self_installer_has_no_runtime_package_execution(monkeypatch) -> None:
    from angerona.core import self_installer

    monkeypatch.setattr(self_installer, "_have", lambda _name: False)
    report = self_installer.install(["voice"])
    source = inspect.getsource(self_installer.install)

    assert "no interpreter changes were made" in report
    assert "requirements-release-hashed.txt" in report
    assert "subprocess" not in source
    assert '"-m", "pip"' not in source
    assert not self_installer.capabilities_ready(["voice"])
