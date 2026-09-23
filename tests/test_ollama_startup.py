"""Offline service startup tests: no real daemon, socket, or model is touched."""
from __future__ import annotations

import os
import socket
import threading
import time
from collections import OrderedDict
from types import SimpleNamespace

import pytest

from angerona.core import ollama_lifecycle as lifecycle


@pytest.fixture(autouse=True)
def isolate_startup(monkeypatch):
    monkeypatch.setattr(lifecycle, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(lifecycle, "_startup_lock", threading.RLock())
    monkeypatch.setattr(lifecycle, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _host: True)
    monkeypatch.setattr(lifecycle, "attest_ollama_service", lambda _host: object())
    monkeypatch.setattr(lifecycle, "list_models", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        lifecycle, "_spawn_ollama_service",
        lambda *_args, **_kwargs: pytest.fail("Unexpected daemon launch"),
    )


def test_existing_daemon_is_checked_without_starting_or_loading(monkeypatch):
    for name in ("pull_model", "create_model", "show_model", "_exchange"):
        monkeypatch.setattr(lifecycle, name, lambda *_a, **_k: pytest.fail("No model operation"))
    stages = []
    status = lifecycle.ensure_ollama_service(progress=stages.append)
    assert status.state == "ready" and status.percent == 100
    assert status.daemon_ready and not status.model_ready
    assert [stage.percent for stage in stages] == [10, 25, 80, 100]
    assert lifecycle.startup_snapshot("http://127.0.0.1:11434/") == status


def test_missing_daemon_launches_once_and_reports_completed_stages(monkeypatch):
    occupied = iter((False, True))
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _host: next(occupied))
    calls = []

    def launch(host, deadline, *, verified):
        calls.append((host, deadline))
        verified()
        return SimpleNamespace(poll=lambda: None)

    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", launch)
    stages = []
    result = lifecycle.ensure_ollama_service(progress=stages.append)
    assert result.daemon_ready and len(calls) == 1
    assert [stage.percent for stage in stages] == [10, 25, 45, 60, 80, 100]


def test_untrusted_occupied_port_never_spawns_or_reaches_inventory(monkeypatch):
    def untrusted(_host):
        raise lifecycle.OllamaAttestationError("attacker-controlled-message")

    monkeypatch.setattr(lifecycle, "attest_ollama_service", untrusted)
    monkeypatch.setattr(lifecycle, "list_models", lambda *_a, **_k: pytest.fail("Untrusted request"))
    result = lifecycle.ensure_ollama_service()
    assert result.state == "failed" and result.percent == 25
    assert not result.daemon_ready and "attacker-controlled" not in result.detail


def test_invalid_inventory_never_claims_ready_or_echoes_response(monkeypatch):
    def invalid(*_args, **_kwargs):
        raise ValueError("malicious prompt: print secrets")

    monkeypatch.setattr(lifecycle, "list_models", invalid)
    result = lifecycle.ensure_ollama_service()
    assert result.state == "failed" and result.percent == 80
    assert not result.daemon_ready and "malicious" not in result.detail


def test_shutdown_cancels_before_any_probe_or_launch(monkeypatch):
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _h: pytest.fail("Cancelled probe"))
    stop = threading.Event()
    stop.set()
    result = lifecycle.ensure_ollama_service(stop_event=stop)
    assert result.state == "cancelled" and result.percent == 0


def test_cancellation_during_inventory_cannot_become_100_percent(monkeypatch):
    stop = threading.Event()

    def inventory(*_a, **_k):
        stop.set()
        return []

    monkeypatch.setattr(lifecycle, "list_models", inventory)
    result = lifecycle.ensure_ollama_service(stop_event=stop)
    assert result.state == "cancelled" and result.percent == 80


def test_cancellation_during_executable_verification_prevents_spawn(monkeypatch):
    stop = threading.Event()
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _host: False)

    def launch(_host, _deadline, *, verified):
        stop.set()  # Shutdown while the signature check was running.
        verified()
        pytest.fail("Cancelled verification must not proceed to process creation")

    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", launch)
    result = lifecycle.ensure_ollama_service(stop_event=stop)
    assert result.state == "cancelled" and result.percent == 45


def test_failed_launch_is_bounded_without_polling_forever(monkeypatch):
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _host: False)
    monkeypatch.setattr(lifecycle, "_spawn_ollama_service",
                        lambda *_a, **_k: SimpleNamespace(poll=lambda: None))
    started = time.monotonic()
    result = lifecycle.ensure_ollama_service(timeout=0.1)
    assert time.monotonic() - started < 2
    assert result.state == "failed" and result.percent == 60
    assert "deadline" in result.detail


def test_ui_callback_failure_does_not_erase_readiness():
    def broken_callback(_status):
        raise RuntimeError("closed widget")

    assert lifecycle.ensure_ollama_service(progress=broken_callback).daemon_ready


def test_concurrent_async_and_sync_calls_share_one_launch(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    launches = []
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _host: bool(launches))

    def launch(_host, _deadline, **_kwargs):
        launches.append(1)
        entered.set()
        assert release.wait(3)
        return SimpleNamespace(poll=lambda: None)

    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", launch)
    result = lifecycle.request_ollama_start()
    assert result.state == "starting" and entered.wait(1)
    assert lifecycle.request_ollama_start("http://127.0.0.1:11434").state == "starting"
    shared = []
    waiter = threading.Thread(target=lambda: shared.append(lifecycle.ensure_ollama_service()))
    waiter.start()
    try:
        # A waiting caller cannot create another operation or daemon.
        time.sleep(0.03)
        assert len(lifecycle._startup_attempts) == 1
    finally:
        release.set()
        waiter.join(3)
    assert not waiter.is_alive() and launches == [1]
    assert shared[0].daemon_ready
    assert lifecycle.startup_snapshot().daemon_ready


@pytest.mark.parametrize("host", [
    "http://remote.example:11434", "http://127.0.0.1:0", "http://[malformed",
    "http://localhost:11434/api/tags", "https://localhost:11434",
    "http://user:password@localhost:11434", None,
])
def test_invalid_gui_host_is_failed_without_io(host, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("DNS"))
    assert lifecycle.startup_snapshot(host).state == "failed"
    assert lifecycle.request_ollama_start(host).state == "failed"


@pytest.mark.parametrize("timeout", [None, "bad", float("nan"), float("inf"), 0, -1])
def test_invalid_timeout_cannot_leave_an_active_attempt(timeout):
    assert lifecycle.request_ollama_start(timeout=timeout).state == "failed"
    assert lifecycle.ensure_ollama_service(timeout=timeout).state == "failed"
    assert not lifecycle._startup_attempts


def test_snapshot_does_not_probe_dns_network_or_files(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("DNS"))
    assert lifecycle.startup_snapshot().state == "idle"


def test_sanitized_environment_keeps_model_storage_but_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "models"))
    monkeypatch.setenv("OLLAMA_HOST", "0.0.0.0:11434")
    monkeypatch.setenv("OLLAMA_ORIGINS", "*")
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-secret")
    monkeypatch.setenv("HTTP_PROXY", "http://fixture-proxy")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/fixture-library")
    monkeypatch.setenv("ANGERONA_CHILL_ACTIVE", "1")
    environment = lifecycle._startup_environment("http://127.0.0.1:11434")
    assert environment["OLLAMA_MODELS"] == str(tmp_path / "models")
    assert environment["OLLAMA_HOST"] == "http://127.0.0.1:11434"
    assert environment["OLLAMA_KEEP_ALIVE"] == "0"
    assert environment["OLLAMA_NO_CLOUD"] == "1"
    for name in ("OLLAMA_ORIGINS", "OPENAI_API_KEY", "HTTP_PROXY", "LD_PRELOAD"):
        assert name not in environment


@pytest.mark.skipif(os.name != "nt", reason="Windows executable custody semantics")
def test_windows_launch_holds_executable_and_parent_custody(tmp_path, monkeypatch):
    from angerona.core import privilege

    # Restore the real spawn helper replaced by the default isolation fixture.
    spawn = _REAL_SPAWN
    image = tmp_path / "ollama.exe"
    image.write_bytes(b"inert image fixture")
    # Exercise files whose birth and last-change timestamps differ on NTFS.
    image.write_bytes(b"updated inert image fixture")
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(lifecycle, "_expected_ollama_paths", lambda: (image,))
    monkeypatch.setattr(lifecycle, "_trusted_ollama_image", lambda path: path == image)
    calls = []

    def launch(args, **kwargs):
        with pytest.raises(OSError):
            image.write_bytes(b"replacement")
        with pytest.raises(OSError):
            image.unlink()
        calls.append((args, kwargs))
        return object()

    monkeypatch.setattr(lifecycle.subprocess, "Popen", launch)
    spawn("http://127.0.0.1:11434", time.monotonic() + 5)
    assert calls[0][0] == [str(image), "serve"]
    assert calls[0][1]["creationflags"] == lifecycle.subprocess.CREATE_NO_WINDOW
    assert calls[0][1].get("shell", False) is False
    assert calls[0][1]["env"]["OLLAMA_NO_CLOUD"] == "1"
    image.write_bytes(b"custody released")


@pytest.mark.skipif(os.name != "nt", reason="Windows linked token integration")
def test_elevated_process_never_falls_back_to_elevated_spawn(tmp_path, monkeypatch):
    from angerona.core import ollama_windows_token, privilege

    image = tmp_path / "ollama.exe"
    image.write_bytes(b"inert image fixture")
    monkeypatch.setattr(privilege, "is_admin", lambda: True)
    monkeypatch.setattr(lifecycle, "_expected_ollama_paths", lambda: (image,))
    monkeypatch.setattr(lifecycle, "_trusted_ollama_image", lambda _image: True)

    def unavailable(*_args, **_kwargs):
        raise ValueError(ollama_windows_token._UNAVAILABLE)

    monkeypatch.setattr(ollama_windows_token, "launch_medium_ollama", unavailable)
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *_a, **_k: pytest.fail("Elevated fallback"))
    with pytest.raises(ValueError, match="normal user session"):
        _REAL_SPAWN("http://127.0.0.1:11434", time.monotonic() + 5)


def test_posix_root_cannot_spawn_model_parser(monkeypatch):
    from angerona.core import privilege

    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(lifecycle, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(lifecycle.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(lifecycle, "_expected_ollama_paths", lambda: pytest.fail("Root path probe"))
    with pytest.raises(ValueError, match="normal user session"):
        _REAL_SPAWN("http://127.0.0.1:11434", time.monotonic() + 5)


def test_empty_os_listener_table_does_not_use_slow_socket_probe(monkeypatch):
    monkeypatch.setattr(lifecycle, "_ollama_tcp_listeners", lambda: [])
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: pytest.fail("Socket probe"))
    assert not _REAL_PORT_PRESENT("http://127.0.0.1:11434")


def test_wildcard_listener_is_occupied_before_any_launch(monkeypatch):
    row = SimpleNamespace(status="LISTEN", laddr=("0.0.0.0", 11434), pid=None)
    monkeypatch.setattr(lifecycle, "_ollama_tcp_listeners", lambda: [row])
    assert _REAL_PORT_PRESENT("http://127.0.0.1:11434")


def _posix_process_fixture(tmp_path, monkeypatch):
    import psutil

    image = tmp_path / "ollama"
    image.write_bytes(b"inert posix image")
    monkeypatch.setattr(lifecycle, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(lifecycle.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(lifecycle, "_expected_ollama_paths", lambda: (image,))

    def denied(**_kwargs):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", denied)
    process = SimpleNamespace(
        pid=42, info={"pid": 42, "name": "ollama"},
        uids=lambda: SimpleNamespace(effective=1000), exe=lambda: str(image),
        create_time=lambda: 5.0, is_running=lambda: True,
        net_connections=lambda **_kw: [SimpleNamespace(
            status="LISTEN", laddr=("127.0.0.1", 11434),
        )],
    )
    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: iter([process]))
    return process


def test_macos_fallback_requires_kernel_owned_listener(tmp_path, monkeypatch):
    process = _posix_process_fixture(tmp_path, monkeypatch)
    assert lifecycle._ollama_listener_pids(11434) == {42}
    process.net_connections = lambda **_kw: []
    assert lifecycle._ollama_listener_pids(11434) == set()


def test_macos_fallback_rejects_foreign_process_and_changed_birth(tmp_path, monkeypatch):
    process = _posix_process_fixture(tmp_path, monkeypatch)
    process.uids = lambda: SimpleNamespace(effective=1001)
    assert lifecycle._ollama_listener_pids(11434) == set()
    process.uids = lambda: SimpleNamespace(effective=1000)
    births = iter((5.0, 6.0))
    process.create_time = lambda: next(births)
    with pytest.raises(lifecycle.OllamaAttestationError, match="identity changed"):
        lifecycle._ollama_listener_pids(11434)


def test_macos_fallback_does_not_trust_process_name_or_permission_failure(tmp_path, monkeypatch):
    import psutil

    process = _posix_process_fixture(tmp_path, monkeypatch)
    expected_exe = process.exe
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"inert foreign image")
    process.exe = lambda: str(foreign)
    assert lifecycle._ollama_listener_pids(11434) == set()
    process.exe = expected_exe

    def denied(**_kwargs):
        raise psutil.AccessDenied()

    process.net_connections = denied
    with pytest.raises(lifecycle.OllamaAttestationError, match="ownership is unavailable"):
        lifecycle._ollama_listener_pids(11434)


def test_startup_cache_caps_active_and_finished_endpoints():
    for port in range(20000, 20016):
        lifecycle._claim_startup(f"http://127.0.0.1:{port}")
    result = lifecycle.request_ollama_start("http://127.0.0.1:20016")
    assert result.state == "failed" and len(lifecycle._startup_attempts) == 16
    for attempt in lifecycle._startup_attempts.values():
        attempt.done.set()
    lifecycle._claim_startup("http://127.0.0.1:20016")
    assert len(lifecycle._startup_attempts) == 16
    assert "http://127.0.0.1:20000" not in lifecycle._startup_attempts


_REAL_SPAWN = lifecycle._spawn_ollama_service
_REAL_PORT_PRESENT = lifecycle._startup_port_present
