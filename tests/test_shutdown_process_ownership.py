from __future__ import annotations

from pathlib import Path

from angerona.gui.main_window import _is_owned_angerona_process


class _Process:
    def __init__(self, exe: Path, command: list[str], cwd: Path) -> None:
        self._exe = exe
        self._command = command
        self._cwd = cwd

    def exe(self) -> str:
        return str(self._exe)

    def cmdline(self) -> list[str]:
        return list(self._command)

    def cwd(self) -> str:
        return str(self._cwd)


def test_shutdown_owns_exact_suite_interpreter(tmp_path):
    root = tmp_path / "AngeronaSuite"
    interpreter = root / "venv" / "Scripts" / "python.exe"
    process = _Process(interpreter, [str(interpreter), "-m", "angerona"], root)

    assert _is_owned_angerona_process(process, root) is True


def test_shutdown_owns_only_canonical_script_under_project(tmp_path):
    root = tmp_path / "AngeronaSuite"
    system_python = tmp_path / "Python" / "python.exe"
    owned = _Process(
        system_python,
        [str(system_python), str(root / "src" / "angerona" / "__main__.py")],
        root,
    )
    unrelated = _Process(
        system_python,
        [str(system_python), str(tmp_path / "tools" / "not_angerona.py"), str(root)],
        tmp_path,
    )

    assert _is_owned_angerona_process(owned, root) is True
    assert _is_owned_angerona_process(unrelated, root) is False


def test_shutdown_rejects_name_and_argument_substring_matches(tmp_path):
    root = tmp_path / "AngeronaSuite"
    system_python = tmp_path / "Python" / "python.exe"

    for command in (
        [str(system_python), "-m", "jupyter", "--notebook-dir", str(root)],
        [str(system_python), "-c", "print('angerona')"],
        [str(system_python), str(tmp_path / "angerona-helper.py")],
        [str(root / "venv" / "Scripts" / "python.exe"), "-m", "pytest"],
        [str(root / "venv" / "Scripts" / "python.exe"), "-m", "jupyter"],
    ):
        assert _is_owned_angerona_process(
            _Process(system_python, command, tmp_path), root
        ) is False
