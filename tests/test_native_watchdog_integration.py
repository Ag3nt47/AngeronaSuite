"""Installed third-watchdog boundary and read-only Python integration."""
from __future__ import annotations

import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

from angerona.resilience import heartbeat as hb
from angerona.resilience import native_watchdog as native


KEY = bytes(range(32))
WALL = 1_800_000_000_000_000_000


def config_body(tmp_path):
    install = tmp_path / "installed"
    return {"schema": 2, "data_dir": str(tmp_path / "data"),
            "launcher_path": str(install / "Angerona.exe"),
            "launcher_sha256": "b" * 64, "launcher_args": ["--engine-service"],
            "working_directory": str(install)}


def encode_body(body):
    return json.dumps(body, separators=(",", ":")).encode()


@pytest.mark.skipif(os.name != "nt", reason="Installer uses canonical Windows paths")
def test_reviewed_config_roundtrips_without_pinning_current_files(tmp_path):
    body = config_body(tmp_path)
    raw = native.build_install_config(data_dir=body["data_dir"],
        launcher_path=body["launcher_path"], launcher_sha256=body["launcher_sha256"],
        working_directory=body["working_directory"])
    assert native.parse_install_config(raw) == body
    assert not (tmp_path / "installed").exists()


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("schema", 1), ("schema", 3), ("launcher_sha256", ""),
    ("launcher_sha256", "A" * 64), ("launcher_args", ["--chill", "--other"]),
    ("launcher_args", "--engine-service"), ("launcher_args", ["--chill"]),
    ("launcher_args", ["--engine-service", "--chill"]),
    ("launcher_args", ["powershell", "-Command"]),
    ("launcher_path", r"C:\installed\other.exe"),
    ("working_directory", r"C:\other"),
    ("data_dir", r"\\server\share\data"),
    ("data_dir", r"\\?\C:\data"), ("data_dir", r"C:\data\..\other"),
    ("data_dir", r"C:\data:stream"), ("data_dir", "C:\\data\\trailing. "),
    ("data_dir", "C:\\data\x01hidden"), ("data_dir", r"relative\data"),
    ("data_dir", r"C:\data\\duplicate"), ("data_dir", "C:/data"),
    ("data_dir", "C:\\" + "a" * 2048),
])
def test_unsafe_or_unsupported_installer_intent_is_rejected(field, value):
    body = {"schema": 2, "data_dir": r"C:\data", "launcher_path": r"C:\installed\Angerona.exe",
            "launcher_sha256": "b" * 64, "launcher_args": ["--engine-service"],
            "working_directory": r"C:\installed"}
    body[field] = value
    with pytest.raises(native.NativeWatchdogError):
        native.parse_install_config(encode_body(body))


@pytest.mark.parametrize("raw", [b"", b"[]", b"{}", b"x" * (16 * 1024 + 1),
    b'{"schema":1,"schema":1}', b"\xff", b'{"schema":1}{}'])
def test_config_parser_is_bounded_and_rejects_duplicate_or_incomplete_json(raw):
    with pytest.raises(native.NativeWatchdogError):
        native.parse_install_config(raw)


def test_known_program_data_is_not_an_environment_override(monkeypatch, tmp_path):
    from angerona.resilience import control_authority
    monkeypatch.setenv("ProgramData", str(tmp_path / "untrusted"))
    monkeypatch.setattr(control_authority, "_known_program_data", lambda: tmp_path / "known")
    assert native.installed_config_path() == tmp_path / "known" / "Angerona" / "watchdog3" / "config.json"


def test_source_admission_is_denied_before_any_native_trust_or_file_access(monkeypatch):
    from angerona.core import executable_trust
    monkeypatch.setattr(native, "_installed_mode", lambda: False)
    monkeypatch.setattr(executable_trust, "acquire_pinned_executable", lambda *_a, **_kw:
                        pytest.fail("Source checkout attempted native admission"))
    monkeypatch.setattr(native, "installed_config_path", lambda:
                        pytest.fail("Source checkout read installed configuration"))
    with pytest.raises(native.NativeWatchdogError, match="Source"):
        native.acquire_installed_watchdog()


def test_missing_release_pins_hold_installed_admission_before_file_access(monkeypatch):
    monkeypatch.setattr(native, "_installed_mode", lambda: True)
    monkeypatch.setattr(native, "_release_pins", lambda: ("", ""))
    monkeypatch.setattr(native, "installed_config_path", lambda: pytest.fail("Missing pins reached files"))
    with pytest.raises(native.NativeWatchdogError, match="pins"):
        native.acquire_installed_watchdog()


@pytest.fixture
def install_boundary(monkeypatch, tmp_path):
    from angerona.core import executable_trust, source_activation_file
    body, held, acquired, closed = config_body(tmp_path), [], [], []
    config_path = tmp_path / "protected" / "config.json"

    class Config:
        def __init__(self, path):
            self.path = path
            held.append(self)
        def read(self, limit):
            assert limit == 16 * 1024 + 1
            return encode_body(body)
        def check(self):
            pass
        def close(self):
            closed.append("config")

    class Executable:
        def __init__(self, path):
            self.path = path
        def still_valid(self, *, rehash):
            assert rehash is True
            return True
        def close(self):
            closed.append(self.path.name)

    def acquire(path, **pins):
        acquired.append((path, pins))
        return Executable(path)

    monkeypatch.setattr(native, "_installed_mode", lambda: True)
    monkeypatch.setattr(native, "_release_pins", lambda: ("a" * 64, "CN=fixture"))
    monkeypatch.setattr(native, "installed_config_path", lambda: config_path)
    monkeypatch.setattr(native, "_config_protected", lambda _path: True)
    monkeypatch.setattr(native, "_private_native_root", lambda _path: True)
    monkeypatch.setattr(native.sys, "executable", body["launcher_path"])
    monkeypatch.setattr(hb, "_data_dir", lambda: pytest.fail("Native intent followed Core's ambient data root"))
    monkeypatch.setattr(source_activation_file, "RetainedFile", Config)
    monkeypatch.setattr(executable_trust, "acquire_pinned_executable", acquire)
    return body, config_path, held, acquired, closed


@pytest.mark.skipif(os.name != "nt", reason="Installer uses canonical Windows paths")
def test_install_admission_keeps_exact_config_and_both_pinned_executables(install_boundary):
    body, config_path, held, acquired, closed = install_boundary
    with native.acquire_installed_watchdog() as admitted:
        assert admitted.body == body and len(held) == 1
        assert admitted.argv == (str(Path(body["launcher_path"]).parent / "watchdog3.exe"),
                                 "--config", str(config_path))
        assert acquired == [
            (Path(body["launcher_path"]).parent / "watchdog3.exe",
             {"expected_sha256": "a" * 64, "expected_publisher": "CN=fixture"}),
            (Path(body["launcher_path"]),
             {"expected_sha256": "b" * 64, "expected_publisher": "CN=fixture"}),
        ]
        assert not closed
    assert closed == ["config", "Angerona.exe", "watchdog3.exe"]


@pytest.mark.skipif(os.name != "nt", reason="Installer uses canonical Windows paths")
def test_admission_failure_releases_only_its_own_receipts(monkeypatch, install_boundary):
    _body, _path, _held, _acquired, closed = install_boundary
    calls = []
    def protected(_path):
        calls.append(1)
        return len(calls) < 3
    monkeypatch.setattr(native, "_config_protected", protected)
    with pytest.raises(native.NativeWatchdogError, match="custody"):
        native.acquire_installed_watchdog()
    assert closed == ["config", "Angerona.exe", "watchdog3.exe"]


@pytest.mark.skipif(os.name != "nt", reason="Installer uses canonical Windows paths")
def test_wrong_installed_launcher_never_reaches_executable_admission(install_boundary):
    body, _path, _held, acquired, closed = install_boundary
    body["launcher_path"] = str(Path(body["launcher_path"]).parent / "other.exe")
    with pytest.raises(native.NativeWatchdogError):
        native.acquire_installed_watchdog()
    assert acquired == [] and closed == ["config"]


@pytest.mark.skipif(os.name != "nt", reason="Installer uses canonical Windows paths")
def test_native_private_root_is_verified_independently_of_core_data(monkeypatch, install_boundary):
    _body, _path, _held, acquired, closed = install_boundary
    monkeypatch.setattr(native, "_private_native_root", lambda _path: False)
    with pytest.raises(native.NativeWatchdogError, match="own state root"):
        native.acquire_installed_watchdog()
    assert acquired == [] and closed == ["config"]


@pytest.mark.parametrize("administrator", [False, True])
def test_frozen_service_entry_reaches_dispatcher_without_uac_or_data_configuration(monkeypatch, administrator):
    from types import SimpleNamespace
    from angerona import __main__ as entry
    from angerona.core import config, data_paths, engine_windows_service, privilege, windows_package_identity
    calls = []
    monkeypatch.setattr(entry, "_source_activation_pending_guard", lambda: False)
    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(entry.sys, "argv", ["Angerona.exe", "--engine-service"])
    monkeypatch.setattr(privilege, "is_admin", lambda: administrator)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("SCM entry requested UAC"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority", lambda:
        SimpleNamespace(trusted=True, reason="fixture trusted package"))
    monkeypatch.setattr(engine_windows_service, "run_dispatcher", lambda: calls.append("dispatcher") or 37)
    monkeypatch.setattr(config.Config, "load", lambda: pytest.fail("Entry loaded desktop settings"))
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda:
                        pytest.fail("Entry selected a data root before SCM admission"))
    before = dict(os.environ)
    assert entry.main() == 37 and calls == ["dispatcher"]
    assert dict(os.environ) == before


@pytest.mark.parametrize("arguments,trusted", [(["--engine-service"], False), (["--chill"], True)])
def test_frozen_service_recovery_keeps_package_guard_and_rejects_legacy_chill(monkeypatch, arguments, trusted):
    from types import SimpleNamespace
    from angerona import __main__ as entry
    from angerona.core import engine_windows_service, privilege, windows_package_identity
    monkeypatch.setattr(entry, "_source_activation_pending_guard", lambda: False)
    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(entry.sys, "argv", ["Angerona.exe", *arguments])
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("Rejected route requested UAC"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority", lambda:
        SimpleNamespace(trusted=trusted, reason="fixture package refused"))
    monkeypatch.setattr(engine_windows_service, "run_dispatcher", lambda:
                        pytest.fail("Rejected entry reached SCM dispatcher"))
    assert entry.main() == 2


@pytest.fixture
def observer_case(monkeypatch, tmp_path):
    clock = {"now": 100.0, "wall": WALL}
    process = native.ObservedProcess(4242, native._WINDOWS_EPOCH + (WALL - 2_000_000_000) // 100,
                                     str(tmp_path / "installed" / "watchdog3.exe"))
    probes = []
    def probe(pid):
        probes.append(pid)
        return process
    monkeypatch.setattr(native, "_installed_mode", lambda: True)
    monkeypatch.setattr(native, "_release_pins", lambda: ("a" * 64, "CN=fixture"))
    monkeypatch.setattr(native.sys, "executable", str(tmp_path / "installed" / "Angerona.exe"))
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda _root: KEY)
    path = tmp_path / "heartbeats" / "watchdog3.hb"
    path.parent.mkdir()
    observer = native.NativeWatchdogObserver(_data_dir=tmp_path, _clock=lambda: clock["now"],
        _time_ns=lambda: clock["wall"], _probe=probe)

    def write(counter=1, *, stamp=None, flags=0x80000001, name="watchdog3", pid=4242):
        stamp = clock["wall"] if stamp is None else stamp
        proof = hb.proof_for(hb._component_key(name, KEY), name, stamp, pid, counter, flags)
        path.write_bytes(struct.pack(hb._FMT, hb._MAGIC, stamp, pid, proof, counter, flags))
    write()
    return observer, clock, path, write, probes, process


def test_observer_uses_authenticated_native_generation_without_launching(observer_case):
    observer, _clock, _path, _write, probes, _process = observer_case
    result = observer.snapshot()
    assert result["state"] == "observed" and result["pid"] == 4242
    assert "recovery is not verified" in result["reason"]
    assert probes == [4242]


@pytest.mark.parametrize("kind", ["proof", "component", "extra", "flags", "truncated"])
def test_invalid_heartbeat_never_reaches_a_process_query(observer_case, kind):
    observer, _clock, path, write, probes, _process = observer_case
    if kind == "component":
        write(name="core")
    elif kind == "flags":
        write(flags=0x80000003)
    else:
        raw = bytearray(path.read_bytes())
        if kind == "proof":
            raw[16] ^= 1
        elif kind == "extra":
            raw += b"x"
        else:
            raw = raw[:-1]
        path.write_bytes(raw)
    assert observer.snapshot()["state"] != "observed"
    assert probes == []


def test_counter_regression_is_rejected_and_wrap_is_accepted(observer_case):
    observer, clock, _path, write, _probes, _process = observer_case
    write(counter=5)
    assert observer.snapshot()["state"] == "observed"
    clock["wall"] += 1_000_000_000
    write(counter=4)
    assert observer.snapshot()["state"] == "unverified"
    write(counter=0xFFFFFFFE)
    assert observer.snapshot()["state"] == "observed"
    clock["wall"] += 1_000_000_000
    write(counter=2)
    assert observer.snapshot()["state"] == "observed"


def test_reused_pid_cannot_borrow_old_heartbeat_but_new_generation_can_start(observer_case):
    observer, clock, _path, write, _probes, process = observer_case
    assert observer.snapshot()["state"] == "observed"
    newer = native.ObservedProcess(process.pid, process.birth_ticks + 30_000_000, process.image)
    observer._probe = lambda _pid: newer
    assert observer.snapshot()["state"] == "unverified"
    clock["wall"] += 2_000_000_000
    write(counter=1)
    assert observer.snapshot()["state"] == "observed"


def test_changing_timestamp_without_counter_progress_is_stale(observer_case):
    observer, clock, _path, write, _probes, _process = observer_case
    assert observer.snapshot()["state"] == "observed"
    clock["now"] += 11
    clock["wall"] += 11_000_000_000
    write(counter=1)
    assert observer.snapshot()["state"] == "stale"


def test_future_clock_record_cannot_poison_later_genuine_progress(observer_case):
    observer, clock, _path, write, _probes, _process = observer_case
    assert observer.snapshot()["state"] == "observed"
    write(counter=2, stamp=clock["wall"] + 60_000_000_000)
    assert observer.snapshot()["state"] == "stale"
    clock["wall"] += 1_000_000_000
    write(counter=2)
    assert observer.snapshot()["state"] == "observed"


def test_stopped_flag_is_a_report_not_standdown_authority(observer_case):
    observer, _clock, _path, write, _probes, _process = observer_case
    write(flags=0x80000000)
    result = observer.snapshot()
    assert result["state"] == "stopped" and "only verified STOP" in result["reason"]


def test_missing_or_wrong_image_process_is_not_observed(observer_case):
    observer, _clock, _path, _write, _probes, process = observer_case
    observer._probe = lambda _pid: None
    assert observer.snapshot()["state"] == "absent"
    observer._probe = lambda _pid: native.ObservedProcess(process.pid, process.birth_ticks, "wrong.exe")
    assert observer.snapshot()["state"] == "unverified"


def test_native_query_cleanup_failure_is_visible_as_unavailable(observer_case):
    observer, _clock, _path, _write, _probes, _process = observer_case
    def held(_pid):
        raise OSError("query handle close failed")
    observer._probe = held
    assert observer.snapshot()["state"] == "unavailable"


def test_native_query_has_no_termination_rights_and_failed_close_is_never_retried(monkeypatch):
    from types import SimpleNamespace
    from angerona.core import windows_process_lease
    calls = []
    class Query:
        def open(self, pid, rights, inherit):
            calls.append((pid, rights, inherit))
            return 77
        def identity(self, handle):
            assert handle == 77
            return SimpleNamespace(pid=4242, birth_ticks=native._WINDOWS_EPOCH + 1, image="fixture.exe")
        def wait(self, handle, milliseconds):
            assert (handle, milliseconds) == (77, 0)
            return False
        def close(self, handle):
            calls.append(("close", handle))
            raise OSError("fixture close failure")
    monkeypatch.setattr(windows_process_lease, "_Native", Query)
    monkeypatch.setattr(native, "_QUERY_CLOSE_HOLDS", [])
    with pytest.raises(native.NativeWatchdogError, match="cleanup remains held"):
        native._query_process(4242)
    with pytest.raises(native.NativeWatchdogError, match="prior"):
        native._query_process(4242)
    assert calls == [(4242, 0x1000 | 0x00100000, False), ("close", 77)]
    assert len(native._QUERY_CLOSE_HOLDS) == 1


def test_source_observer_does_not_read_keys_or_create_any_files(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_installed_mode", lambda: False)
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda *_args:
                        pytest.fail("Source observer read installed authority"))
    root = tmp_path / "not-created"
    result = native.NativeWatchdogObserver().snapshot()
    assert result["state"] == "source-disabled" and not root.exists()


def test_source_native_alert_consumer_is_denied_before_installed_intent_read(monkeypatch):
    monkeypatch.setattr(native, "_installed_mode", lambda: False)
    monkeypatch.setattr(native, "installed_config_path", lambda:
                        pytest.fail("Source consumer read native installer configuration"))
    with pytest.raises(native.NativeWatchdogError, match="Source"):
        native.NativeAlertReader()


def test_observer_uses_current_protected_native_intent_and_never_core_environment(monkeypatch, observer_case):
    from types import SimpleNamespace
    _fixture, clock, path, _write, _probes, process = observer_case
    retired = []
    root = path.parent.parent
    held = SimpleNamespace(check=lambda: retired.append("check"), close=lambda: retired.append("close"))
    monkeypatch.setattr(native, "_acquire_configuration", lambda: (held, {"data_dir": str(root)}))
    monkeypatch.setattr(hb, "_data_dir", lambda: pytest.fail("Observer followed Core's ambient data root"))
    observer = native.NativeWatchdogObserver(_clock=lambda: clock["now"], _time_ns=lambda: clock["wall"],
                                             _probe=lambda _pid: process)
    assert observer.snapshot()["state"] == "observed"
    assert retired == ["check", "close"]
    def lost():
        raise PermissionError("fixture installed intent unavailable")
    monkeypatch.setattr(native, "_acquire_configuration", lost)
    assert observer.snapshot()["state"] == "unavailable"  # no cached-root fallback


def test_installed_native_alert_consumer_uses_its_separate_protected_root(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from angerona.resilience.peer_alerts import PeerAlertOutbox
    root, ambient = tmp_path / "native", tmp_path / "core"
    path = native.alert_path(root)
    path.parent.mkdir(parents=True)
    PeerAlertOutbox(source="watchdog3", key_raw=KEY, path=path).append("HIGH", "Native SCM fixture")
    held = SimpleNamespace(check=lambda: None, close=lambda: None)
    monkeypatch.setattr(native, "_installed_mode", lambda: True)
    monkeypatch.setattr(native, "_acquire_configuration", lambda: (held, {"data_dir": str(root)}))
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda selected:
                        KEY if selected == root else pytest.fail("Wrong native authority root"))
    monkeypatch.setattr(hb, "_data_dir", lambda: pytest.fail("Native alerts followed Core's root"))
    monkeypatch.setenv("ANGERONA_DATA", str(ambient))
    assert [row["msg"] for row in native.NativeAlertReader().drain()] == ["Native SCM fixture"]
    assert not ambient.exists()


def test_native_outbox_uses_separate_cursor_and_reports_tampering(monkeypatch, tmp_path):
    from angerona.resilience.peer_alerts import PeerAlertOutbox, PeerAlertReader
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda _root: KEY)
    path = native.alert_path(tmp_path)
    path.parent.mkdir()
    default = tmp_path / "ipc" / "peer_alerts.jsonl"
    default.parent.mkdir()
    PeerAlertOutbox(key_raw=KEY, path=default).append("HIGH", "Python peer fixture")
    outbox = PeerAlertOutbox(source="watchdog3", key_raw=KEY, path=path)
    outbox.append("HIGH", "Native fixture", {"core_state": "dead", "watchdog_state": "dead"})
    reader = native.NativeAlertReader(_data_dir=tmp_path)
    assert [row["msg"] for row in reader.drain()] == ["Native fixture"]
    assert reader.drain() == []
    assert [row["msg"] for row in PeerAlertReader(key_raw=KEY, path=default).drain()] == ["Python peer fixture"]
    with path.open("ab") as stream:
        stream.write(b'{"forged":true}\n')
    assert reader.drain()[-1]["id"] == "tamper"


@pytest.mark.skipif(os.name != "nt", reason="Native Windows directory junction")
def test_native_alert_reader_refuses_junction_before_authority_or_cursor_write(monkeypatch, tmp_path):
    from angerona.core.privilege import trusted_windows_directories
    from angerona.core.source_activation_file import ActivationFileError
    root, outside = tmp_path / "data", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    linked = root / "diagnostics"
    _windows, system = trusted_windows_directories()
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda _root:
                        pytest.fail("Redirected outbox reached authority read"))
    try:
        made = subprocess.run([str(system / "cmd.exe"), "/d", "/c", "mklink", "/J",
            str(linked), str(outside)], capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        assert made.returncode == 0, made.stderr.decode(errors="replace")
        with pytest.raises(ActivationFileError):
            native.NativeAlertReader(_data_dir=root).drain()
        assert sentinel.read_bytes() == b"untouched"
        assert not (outside / "watchdog3-peer-alerts.cursor").exists()
    finally:
        if os.path.lexists(linked):
            assert linked.parent.resolve() == root.resolve()
            assert root.resolve().is_relative_to(tmp_path.resolve())
            assert linked.lstat().st_file_attributes & 0x400
            os.rmdir(linked)


def test_broken_python_peer_outbox_does_not_block_native_alert_ingestion(monkeypatch, tmp_path):
    from angerona.resilience.manager import ResilienceManager
    from angerona.resilience.peer_alerts import PeerAlertOutbox
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda _root: KEY)
    path = native.alert_path(tmp_path)
    path.parent.mkdir()
    PeerAlertOutbox(source="watchdog3", key_raw=KEY, path=path).append("HIGH", "Both peers unavailable")
    manager = ResilienceManager.__new__(ResilienceManager)
    class Broken:
        def peek(self):
            raise OSError("fixture Python chain held")
    manager._peer_alerts = Broken()
    manager._native_peer_alerts = native.NativeAlertReader(_data_dir=tmp_path)
    published = []
    def publish(*args):
        published.append(args)
        return True
    manager._publish = publish
    manager._drain_peer_alerts()
    assert len(published) == 1 and published[0][:3] == (
        "Native Third Watchdog", "Both peers unavailable", "HIGH")
    assert published[0][3]["native_watchdog"] is True
    assert manager._native_peer_alerts.peek() == []


def test_native_posture_row_never_confuses_observation_with_recovery_proof():
    from angerona.resilience.posture import _native_watchdog_row
    row = _native_watchdog_row({"state": "observed"})
    assert row["tone"] == "ok" and "not verified" in row["text"]
    assert _native_watchdog_row({"state": "stale"})["tone"] == "warn"
    assert _native_watchdog_row({"state": "source-disabled"})["tone"] == "off"
    assert _native_watchdog_row(None)["tone"] == "off"
