"""An unrelated process mentioning a helper must not suppress its launch."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.resilience.supervisor import cached_cmdline_probe


class Process:
    pid = 101

    def __init__(self, argv, *, executable=None, cwd=None, fresh=None):
        self.info = {"cmdline": argv}
        self.argv = fresh if fresh is not None else argv
        self.executable = executable or argv[0]
        self.directory = cwd or os.getcwd()
        self.alive = True
        self.exe_queries = 0

    def exe(self):
        self.exe_queries += 1
        return self.executable

    def cmdline(self):
        return self.argv

    def cwd(self):
        return self.directory

    def is_running(self):
        return self.alive

    def create_time(self):
        return 100.0


class Table:
    STATUS_ZOMBIE = "zombie"

    def __init__(self, processes):
        self.processes, self.scans = processes, 0

    def process_iter(self, _attrs):
        self.scans += 1
        return self.processes


def probe(table, expected):
    return cached_cmdline_probe("blackbox_recorder.py", psutil_module=table,
                                expected_argv=expected)


@pytest.mark.parametrize("kind", ["code-mention", "wrong-script", "wrong-interpreter", "stale-info"])
def test_arbitrary_mentions_and_other_installations_are_not_adopted(tmp_path, kind):
    expected = [str(tmp_path / "python.exe"), str(tmp_path / "blackbox_recorder.py")]
    if kind == "code-mention":
        process = Process([expected[0], "-c", "print('blackbox_recorder.py')"])
    elif kind == "wrong-script":
        process = Process([expected[0], str(tmp_path / "other" / "blackbox_recorder.py")])
    elif kind == "wrong-interpreter":
        process = Process(expected, executable=str(tmp_path / "other" / "python.exe"))
    else:
        process = Process(expected, fresh=[expected[0], "-c", "print('blackbox_recorder.py')"])
    assert not probe(Table([process]), expected)()


def test_canonical_relative_script_and_extra_presentation_flag_are_adopted(tmp_path):
    expected = [str(tmp_path / "python.exe"), str(tmp_path / "blackbox_recorder.py")]
    process = Process([expected[0], "blackbox_recorder.py", "--show"], cwd=str(tmp_path))
    table = Table([process])
    check = probe(table, expected)
    assert check()
    queries = process.exe_queries
    for _ in range(100):
        assert check()
    assert table.scans == 1
    assert process.exe_queries == queries
    process.alive = False
    table.processes = []
    assert not check()
    assert table.scans == 2


def test_interpreter_presentation_options_do_not_create_duplicate_helper_launches(tmp_path):
    expected = [str(tmp_path / "python.exe"), str(tmp_path / "blackbox_recorder.py")]
    valid = Process([expected[0], "-u", "-X", "utf8", expected[1], "--show"])
    assert probe(Table([valid]), expected)()
    assert not probe(Table([Process([expected[0], "-u", "-c", expected[1]])]), expected)()


@pytest.mark.parametrize("actual", [
    ["-c", "print('angerona.resilience.status_ui watchdog')"],
    ["-m", "angerona.resilience.status_ui", "scanner", "--title", "watchdog"],
    ["-m", "different.angerona.resilience.status_ui", "watchdog"],
])
def test_monitor_role_must_be_the_actual_module_positional_argument(tmp_path, actual):
    executable = str(tmp_path / "python.exe")
    expected = [executable, "-m", "angerona.resilience.status_ui", "watchdog"]
    table = Table([Process([executable, *actual])])
    assert not probe(table, expected)()
    valid = Process(expected + ["--title", "Angerona - Watchdog"])
    table.processes.append(valid)
    assert probe(table, expected)()


def test_one_denied_candidate_does_not_hide_a_later_valid_helper(tmp_path):
    expected = [str(tmp_path / "python.exe"), str(tmp_path / "blackbox_recorder.py")]
    denied = Process(expected)
    denied.exe = lambda: (_ for _ in ()).throw(PermissionError())
    assert probe(Table([denied, Process(expected)]), expected)()


def test_packaged_recorder_is_identified_by_actual_executable(tmp_path):
    executable = str(tmp_path / "AngeronaBlackBox.exe")
    good = Process([executable, "--show"])
    bad = Process([str(tmp_path / "python.exe"), "-c", executable])
    assert probe(Table([good]), [executable])()
    assert not probe(Table([bad]), [executable])()


@pytest.mark.parametrize("disabled", ["0", "false", "no", "off"])
def test_peer_watchdog_respects_blackbox_disable_setting(tmp_path, monkeypatch, disabled):
    from angerona.resilience import watchdog
    components = {}
    supervisor = SimpleNamespace(
        components=components,
        add=lambda name, *_args, **_kwargs: components.update({name: SimpleNamespace()}),
        start=lambda: None, stop=lambda **_kwargs: None,
    )
    writer = SimpleNamespace(beat=lambda: None, close=lambda: None)
    monkeypatch.setenv("ANGERONA_BLACKBOX_ENABLED", disabled)
    monkeypatch.delenv("ANGERONA_WATCHDOG_TOKEN", raising=False)
    monkeypatch.delenv("ANGERONA_CORE_CMD", raising=False)
    monkeypatch.setattr(watchdog.hb, "HeartbeatWriter", lambda *_: writer)
    monkeypatch.setattr(watchdog, "ProcessSupervisor", lambda **_: supervisor)
    monkeypatch.setattr(watchdog, "_blackbox_script", lambda: Path(tmp_path / "blackbox_recorder.py"))
    monkeypatch.setattr(watchdog, "_standdown_requested", lambda: True)
    monkeypatch.setattr(watchdog.diag, "write_status", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(watchdog.signal, "signal", lambda *_: None)
    assert watchdog.main([]) == 0
    assert "scanner" in components
    assert "blackbox" not in components
