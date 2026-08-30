from __future__ import annotations

import hashlib
import io
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

import angerona.modules.mem_inject_scanner as memory_module
import angerona.modules.mobile_bridge as mobile_module
from angerona.core.eventbus import EventBus, Severity
from angerona.modules.mem_inject_scanner import (
    MemInjectScannerModule,
    PAGE_EXECUTE_READWRITE,
    ProcessCoverage,
    _PidScanResult,
    _ProcessEnumeration,
)
from angerona.modules.mobile_bridge import (
    MobileResponseBridge,
    _CliIdentity,
    _CliResult,
    _SealedCli,
)


def test_memory_scanner_never_skips_a_jit_basename(monkeypatch) -> None:
    scanner = MemInjectScannerModule()
    scanner._self_pid = 999
    monkeypatch.setattr(
        scanner,
        "_get_active_processes",
        lambda: _ProcessEnumeration(
            {101: "chrome.exe", 102: "python.exe", 103: "payload.exe"}, True
        ),
    )
    monkeypatch.setattr(memory_module, "_process_policy_snapshot", lambda: ())
    scanned: list[tuple[int, str]] = []

    def scan(pid: int, name: str, _policy) -> _PidScanResult:
        scanned.append((pid, name))
        return _PidScanResult(True, True, "scanned")

    monkeypatch.setattr(scanner, "_scan_pid", scan)
    receipt = scanner._scan_all_pids()

    assert scanned == [
        (101, "chrome.exe"),
        (102, "python.exe"),
        (103, "payload.exe"),
    ]
    assert receipt == ProcessCoverage(
        enumerated=3,
        opened=3,
        scanned=3,
        denied=0,
        failed=0,
        skipped=0,
        enumeration_complete=True,
        enumeration_error="",
    )
    assert receipt.health == 100


def test_memory_scanner_health_reports_incomplete_coverage(monkeypatch) -> None:
    scanner = MemInjectScannerModule()
    scanner._self_pid = 999
    monkeypatch.setattr(
        scanner,
        "_get_active_processes",
        lambda: _ProcessEnumeration(
            {999: "angerona.exe", 1: "denied.exe", 2: "failed.exe", 3: "ok.exe"},
            True,
        ),
    )
    monkeypatch.setattr(memory_module, "_process_policy_snapshot", lambda: ())
    outcomes = {
        1: _PidScanResult(False, False, "denied"),
        2: _PidScanResult(True, False, "failed"),
        3: _PidScanResult(True, True, "scanned"),
    }
    monkeypatch.setattr(
        scanner, "_scan_pid", lambda pid, _name, _policy: outcomes[pid]
    )

    receipt = scanner._scan_all_pids()

    assert receipt.enumerated == 4
    assert receipt.opened == 2
    assert receipt.scanned == 1
    assert receipt.denied == 1
    assert receipt.failed == 1
    assert receipt.skipped == 1
    assert receipt.health == 33
    assert "denied=1" in receipt.detail
    assert "failed=1" in receipt.detail


def test_jit_damper_requires_exact_path_and_digest(monkeypatch) -> None:
    path = os.path.normcase(os.path.normpath(r"C:\Program Files\Browser\chrome.exe"))
    digest = "a" * 64
    monkeypatch.setattr(memory_module, "_executable_sha256", lambda _path: digest)

    assert not MemInjectScannerModule._trusted_jit_image(
        "chrome.exe", path, digest, (("chrome.exe", "", digest),)
    )
    assert not MemInjectScannerModule._trusted_jit_image(
        "chrome.exe", path, digest, (("chrome.exe", path, ""),)
    )
    assert MemInjectScannerModule._trusted_jit_image(
        "chrome.exe", path, digest, (("chrome.exe", path, digest),)
    )


def test_bound_jit_damper_still_emits_an_event(monkeypatch) -> None:
    scanner = MemInjectScannerModule()
    bus = EventBus()
    scanner.bind(bus)
    path = os.path.normcase(os.path.normpath(r"C:\Program Files\Browser\chrome.exe"))
    digest = "b" * 64
    monkeypatch.setattr(scanner, "_enrich_process", lambda _pid: {})

    scanner._alert(
        801,
        "chrome.exe",
        [(0x1000, 8192, PAGE_EXECUTE_READWRITE)],
        (("chrome.exe", path, digest),),
        bound_image={
            "exe": path,
            "image_sha256": digest,
            "image_identity_bound": True,
            "process_create_time": 123.0,
        },
    )

    event = bus.recent(1)[0]
    assert event.severity == Severity.MEDIUM
    assert event.details["exact_identity_jit_damper"] is True


def _configured_bridge() -> MobileResponseBridge:
    bridge = MobileResponseBridge()
    bridge._config = SimpleNamespace(
        mobile_enabled=True,
        mobile_signal_cli=r"C:\Program Files\SignalCli\signal-cli.exe",
        mobile_host_number="+13035550100",
        mobile_dest_number="+13035550101",
        mobile_signal_cli_sha256="a" * 64,
        mobile_signal_cli_publisher="CN=Trusted Signal CLI Publisher",
    )
    return bridge


def _sealed() -> _SealedCli:
    return _SealedCli(
        _CliIdentity(
            r"C:\Program Files\SignalCli\signal-cli.exe",
            "a" * 64,
            "CN=Trusted Signal CLI Publisher",
            (1, 2, 3, 4),
        ),
        0,
    )


def test_mobile_bridge_requires_digest_and_publisher_pins() -> None:
    bridge = MobileResponseBridge()
    cfg = {
        "cli": r"C:\signal-cli.exe",
        "host": "+13035550100",
        "dest": "+13035550101",
        "sha256": "",
        "publisher": "",
    }
    assert "sha256" in bridge._trust_config_error(cfg).casefold()
    cfg["sha256"] = "a" * 64
    assert "publisher" in bridge._trust_config_error(cfg).casefold()


def test_mobile_cli_receipt_binds_nonce_return_code_and_output(monkeypatch) -> None:
    bridge = _configured_bridge()
    sealed = _sealed()
    monkeypatch.setattr(bridge, "_acquire_cli", lambda _cfg: sealed)
    monkeypatch.setattr(
        bridge,
        "_launch_cli",
        lambda _seal, _args, _timeout: ("complete", 0, b'{"ok":true}\n'),
    )
    monkeypatch.setattr(bridge, "_seal_still_valid", lambda _seal: True)

    result = bridge._invoke_cli("receive", ["receive"], timeout=2.0)

    assert bridge._result_valid(result, "receive")
    assert len(result.receipt.nonce) == 64
    assert result.receipt.returncode == 0
    assert result.receipt.output_sha256 == hashlib.sha256(result.output).hexdigest()
    forged_receipt = replace(result.receipt, returncode=7)
    assert not bridge._receipt_valid(forged_receipt)
    forged_output = _CliResult(b"forged", result.receipt, True)
    assert not bridge._result_valid(forged_output, "receive")


def test_mobile_cli_nonzero_return_code_is_never_accepted(monkeypatch) -> None:
    bridge = _configured_bridge()
    monkeypatch.setattr(bridge, "_acquire_cli", lambda _cfg: _sealed())
    monkeypatch.setattr(
        bridge,
        "_launch_cli",
        lambda _seal, _args, _timeout: ("complete", 9, b'{"envelope":{}}\n'),
    )
    monkeypatch.setattr(bridge, "_seal_still_valid", lambda _seal: True)

    result = bridge._invoke_cli("receive", ["receive"], timeout=2.0)

    assert not result.verified
    assert "code 9" in result.error
    assert bridge._cli_failures["receive"] == result.error


def test_mobile_health_does_not_overwrite_a_send_failure(monkeypatch) -> None:
    bridge = _configured_bridge()
    bridge._record_cli_result("send", False, "send receipt failed")
    bridge._record_cli_result("receive", True)
    monkeypatch.setattr(bridge, "_poll_alerts", lambda: None)
    monkeypatch.setattr(bridge, "_receive", lambda: [])
    monkeypatch.setattr(bridge, "_sweep_tokens", lambda: None)
    monkeypatch.setattr(bridge, "_flush_digest", lambda: None)
    monkeypatch.setattr(bridge, "sleep", lambda _seconds: bridge._stop.set())

    bridge.run()

    assert bridge.health == 40
    assert "send receipt failed" in bridge.health_note


def test_mobile_launch_uses_secret_free_environment_and_bounded_custody(
    monkeypatch,
) -> None:
    bridge = _configured_bridge()
    captured: dict[str, object] = {}

    class FakeProcess:
        def __init__(self, argv, **kwargs) -> None:
            captured["argv"] = argv
            captured.update(kwargs)
            self.stdout = io.BytesIO(b"version 1\n")
            self.returncode = 0
            self.pid = 1234
            self._handle = 1

        def wait(self, timeout=None):
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setenv(mobile_module._PORTABLE_PIN_ENV, "4821")
    monkeypatch.setenv(mobile_module._PIN_ENV, "secret-blob")
    monkeypatch.setattr(mobile_module.subprocess, "Popen", FakeProcess)
    import angerona.resilience._selftest_environment as selftest_environment

    monkeypatch.setattr(
        selftest_environment, "_assign_windows_kill_job", lambda _process: (1, lambda _job: 1)
    )
    monkeypatch.setattr(selftest_environment, "_resume_windows_process", lambda _process: None)
    monkeypatch.setattr(
        selftest_environment, "_stop_process_custody", lambda _process, _job: None
    )

    state, returncode, output = bridge._launch_cli(_sealed(), ["--version"], 2.0)

    assert (state, returncode, output) == ("complete", 0, b"version 1\n")
    environment = captured["env"]
    assert mobile_module._PORTABLE_PIN_ENV not in environment
    assert mobile_module._PIN_ENV not in environment
    assert captured["close_fds"] is True
    assert captured["cwd"] == r"C:\Program Files\SignalCli"


def test_mobile_seal_rejects_hard_link_before_execution(tmp_path, monkeypatch) -> None:
    if os.name != "nt":
        pytest.skip("Windows hard-link handle assertion")
    executable = tmp_path / "signal-cli.exe"
    executable.write_bytes(b"inert-test-binary")
    alias = tmp_path / "signal-cli-alias.exe"
    os.link(executable, alias)
    monkeypatch.setattr(mobile_module, "_has_link_or_reparse", lambda _path: False)
    monkeypatch.setattr(mobile_module, "_windows_fixed_volume", lambda _path: True)
    monkeypatch.setattr(mobile_module, "_trusted_path_acl", lambda _path: True)
    cfg = {
        "cli": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "publisher": "CN=Test",
    }

    with pytest.raises(PermissionError, match="single-link"):
        MobileResponseBridge._acquire_cli(cfg)
