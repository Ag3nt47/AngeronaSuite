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
    assert arguments == "-m angerona --chill"
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
    assert "-RunLevel Limited" in script


def _windows_task_xml(
    *,
    command=r"D:\Angerona\venv\Scripts\pythonw.exe",
    arguments="-m angerona",
    working_directory=r"D:\Angerona",
    trigger="LogonTrigger",
    trigger_enabled="true",
    run_level="LeastPrivilege",
    logon_type="InteractiveToken",
    task_enabled="true",
    extra_action="",
) -> str:
    run_level_xml = (
        f"<RunLevel>{run_level}</RunLevel>" if run_level is not None else ""
    )
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <{trigger}><Enabled>{trigger_enabled}</Enabled></{trigger}>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1-2-3-1001</UserId>
      <LogonType>{logon_type}</LogonType>
      {run_level_xml}
    </Principal>
  </Principals>
  <Settings><Enabled>{task_enabled}</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{working_directory}</WorkingDirectory>
    </Exec>
    {extra_action}
  </Actions>
</Task>"""


def test_windows_is_enabled_rejects_stale_or_weakened_task(monkeypatch):
    expected = (
        r"D:\Angerona\venv\Scripts\pythonw.exe",
        "-m angerona",
        r"D:\Angerona",
    )
    calls = []
    response = SimpleNamespace(returncode=0, stdout=_windows_task_xml())

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return response

    monkeypatch.setattr(autostart.sys, "platform", "win32")
    monkeypatch.setattr(autostart, "_target_action", lambda: expected)
    monkeypatch.setattr(autostart.subprocess, "run", fake_run)

    assert autostart.is_enabled() is True
    assert "/xml" in calls[0][0]

    stale_definitions = (
        _windows_task_xml(command=r"D:\Angerona\venv\Scripts\python.exe"),
        _windows_task_xml(arguments=""),
        _windows_task_xml(working_directory=r"C:\OldAngerona"),
        _windows_task_xml(trigger="TimeTrigger"),
        _windows_task_xml(trigger_enabled="false"),
        _windows_task_xml(logon_type="Password", run_level=None),
        _windows_task_xml(run_level="HighestAvailable"),
        _windows_task_xml(task_enabled="false"),
        _windows_task_xml(extra_action="<Exec><Command>cmd.exe</Command></Exec>"),
    )
    for payload in stale_definitions:
        response.stdout = payload
        assert autostart.is_enabled() is False


def test_windows_limited_task_accepts_live_xml_with_omitted_run_level(
    monkeypatch,
):
    """Windows serializes Limited as an omitted schema-default RunLevel."""
    monkeypatch.setattr(autostart, "_target_action", lambda: (
        r"D:\Angerona\venv\Scripts\pythonw.exe",
        "-m angerona",
        r"D:\Angerona",
    ))

    live_xml = _windows_task_xml(run_level=None)
    assert "<LogonType>InteractiveToken</LogonType>" in live_xml
    assert "<RunLevel>" not in live_xml
    assert autostart._windows_task_xml_is_current(live_xml)

    assert not autostart._windows_task_xml_is_current(
        _windows_task_xml(run_level="HighestAvailable")
    )


def test_windows_is_enabled_fails_closed_on_invalid_or_oversized_xml(monkeypatch):
    monkeypatch.setattr(autostart, "_target_action", lambda: (
        r"D:\Angerona\venv\Scripts\pythonw.exe",
        "-m angerona",
        r"D:\Angerona",
    ))

    assert not autostart._windows_task_xml_is_current("not XML")
    assert not autostart._windows_task_xml_is_current(
        "x" * (autostart._MAX_TASK_XML_CHARS + 1)
    )
