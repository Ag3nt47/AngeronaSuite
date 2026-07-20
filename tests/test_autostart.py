from types import SimpleNamespace

from angerona.core import autostart
from angerona.core import data_paths


def test_source_autostart_uses_windowed_python_and_project_working_directory(
        tmp_path, monkeypatch):
    python = tmp_path / "venv" / "Scripts" / "python.exe"
    pythonw = python.with_name("pythonw.exe")
    pythonw.parent.mkdir(parents=True)
    python.write_bytes(b"")
    pythonw.write_bytes(b"")

    monkeypatch.setattr(autostart.sys, "executable", str(python))
    monkeypatch.setattr(autostart.sys, "frozen", False, raising=False)
    monkeypatch.setattr(data_paths, "project_root", lambda: tmp_path)

    executable, arguments, working_directory = autostart._target_action()
    assert executable == str(pythonw)
    assert arguments == "-m angerona"
    assert working_directory == str(tmp_path)


def test_enable_autostart_registers_hidden_resilient_task(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(autostart.sys, "platform", "win32")
    monkeypatch.setattr(
        autostart, "_target_action",
        lambda: (r"D:\Angerona\venv\Scripts\pythonw.exe", "-m angerona", r"D:\Angerona"),
    )
    monkeypatch.setattr(autostart, "_current_user", lambda: r"HOST\Operator")
    monkeypatch.setattr(autostart.subprocess, "run", fake_run)

    assert autostart.enable_autostart() is True
    assert captured["argv"][0] == str(autostart._POWERSHELL)
    assert captured["kwargs"]["check"] is True
    env = captured["kwargs"]["env"]
    assert env["ANGERONA_AUTOSTART_EXE"].endswith("pythonw.exe")
    assert env["ANGERONA_AUTOSTART_CWD"] == r"D:\Angerona"
    script = captured["argv"][-1]
    assert "-WorkingDirectory" in script
    assert "-Hidden" in script
    assert "-AllowStartIfOnBatteries" in script
    assert "-DontStopIfGoingOnBatteries" in script
    assert "-RestartCount 3" in script
    assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in script
