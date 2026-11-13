"""Ollama admission tests use private files and fake trust/native boundaries only."""
from __future__ import annotations

import os
import threading
from collections import OrderedDict
from types import SimpleNamespace

import pytest

from angerona.core import ollama_lifecycle as lifecycle
from angerona.core import ollama_model_paths as model_paths
from angerona.core import ollama_package_custody as package_custody
from angerona.core import privilege


# Retain the real orchestration before conftest installs its automatic-start
# guard. Only individual tests restore it after every effect path is inert.
_REAL_ENSURE_OLLAMA_SERVICE = lifecycle.ensure_ollama_service


@pytest.fixture
def image(tmp_path, monkeypatch):
    candidate = tmp_path / "Ollama" / "ollama.exe"
    candidate.parent.mkdir()
    candidate.write_bytes(b"inert package fixture")
    monkeypatch.setattr(lifecycle, "sys", SimpleNamespace(platform="win32", modules={}))
    monkeypatch.setattr(lifecycle, "_expected_ollama_paths", lambda: (candidate,))
    monkeypatch.setattr(lifecycle, "_IMAGE_ADMISSION_CACHE", OrderedDict())
    monkeypatch.setattr(lifecycle, "_SIGNATURE_CACHE_CHECKED_AT", 0.0)
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: False)
    monkeypatch.setattr(lifecycle, "_windows_image_location", lambda _path: True)
    return candidate


def test_writable_package_cannot_borrow_a_valid_signer_name(image, monkeypatch):
    monkeypatch.setattr(package_custody, "assess_package", lambda _p: package_custody.PackageCustody(False, "untrusted-owner"))
    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", lambda *_: pytest.fail("unprotected package reached signer probe"))
    assert lifecycle._trusted_ollama_image(image) is False
    assert "settings and models were not changed" in lifecycle._image_admission_issue()


@pytest.mark.parametrize("signed", [False, True])
def test_protected_package_still_requires_machine_signing_evidence(image, monkeypatch, signed):
    monkeypatch.setattr(package_custody, "assess_package", lambda _p: package_custody.PackageCustody(True, "protected-snapshot", 2))
    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", lambda *_: signed)
    assert lifecycle._trusted_ollama_image(image) is signed


def test_gui_never_walks_package_or_runs_a_signature_probe(image, monkeypatch):
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: True)
    monkeypatch.setattr(package_custody, "assess_package", lambda _p: pytest.fail("GUI walked package"))
    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", lambda *_: pytest.fail("GUI ran signature process"))
    assert lifecycle._trusted_ollama_image(image) is False
    assert "pending on a worker" in lifecycle._image_admission_issue()


def test_gui_reuses_only_a_bounded_matching_worker_snapshot(image, monkeypatch):
    now, walks = [100.0], []
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(package_custody, "assess_package", lambda p: walks.append(p) or package_custody.PackageCustody(True, "protected-snapshot", 2))
    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", lambda *_: True)
    assert lifecycle._trusted_ollama_image(image)
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: True)
    assert lifecycle._trusted_ollama_image(image)
    now[0] += lifecycle._IMAGE_ADMISSION_TTL + 1
    assert not lifecycle._trusted_ollama_image(image)
    assert walks == [image.resolve()]


def test_machine_signer_policy_requires_machine_roots_and_code_signing_eku(tmp_path, monkeypatch):
    powershell = tmp_path / "powershell.exe"
    powershell.write_bytes(b"not executable")
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: powershell)
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path, tmp_path))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {})
    calls = []
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)) or SimpleNamespace(returncode=1))
    lifecycle._windows_image_signature_valid.cache_clear()
    assert not lifecycle._windows_image_signature_valid(str(tmp_path / "ollama.exe"), 1, 2, 3, 4, 5)
    script = calls[0][0][-1]
    assert "X509Chain]::new($true)" in script
    assert "X509Store]::new('Root','LocalMachine')" in script
    assert "1.3.6.1.5.5.7.3.3" in script and "$chain.Build" in script
    assert "$s.Status -ne 'Valid'" in script and "rootHash" in script
    assert "$PSModuleAutoLoadingPreference='None'" in script
    assert "Microsoft.PowerShell.Core\\Import-Module -Name $security" in script
    assert "Microsoft.PowerShell.Security.psd1" in script
    assert "$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')" in script
    assert calls[0][1]["env"] == {"ANGERONA_NATIVE_PATH": str(tmp_path / "ollama.exe"),
                                      "PSModulePath": str(tmp_path / "Modules")}
    assert calls[0][1]["cwd"] == str(tmp_path)
    lifecycle._windows_image_signature_valid.cache_clear()


@pytest.mark.parametrize("value", [r"\\attacker\models", r"\\?\C:\models", "relative-models", "bad\x00path"])
def test_bad_explicit_model_path_is_visible_and_never_replaced(tmp_path, monkeypatch, value):
    # The OS correctly refuses a NUL environment value. Feed the actual parser
    # through an inert local mapping instead of attempting a real setenv.
    environment = {"OLLAMA_MODELS": value}
    monkeypatch.setattr(lifecycle, "os", SimpleNamespace(environ=environment))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {"USERPROFILE": str(tmp_path), "HOME": str(tmp_path)})
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path, tmp_path))
    with pytest.raises(model_paths.ModelDirectoryError):
        lifecycle._startup_environment("http://127.0.0.1:11434")
    assert environment["OLLAMA_MODELS"] == value


def test_windows_ollama_path_excludes_interpreter_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "sys", SimpleNamespace(platform="win32", modules={}))
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "models"))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {"PATH": "untrusted-interpreter", "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)})
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path / "Windows", tmp_path / "System32"))
    monkeypatch.setattr(model_paths, "validate_model_directory", lambda value: value)
    environment = lifecycle._startup_environment("http://127.0.0.1:11434")
    assert environment["PATH"] == str(tmp_path / "System32")
    assert environment["OLLAMA_HOST"] == "http://127.0.0.1:11434"


def test_provider_hold_reports_a_fixed_message_and_never_installs_or_downloads(monkeypatch):
    monkeypatch.setattr(lifecycle, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(lifecycle, "_startup_lock", threading.RLock())
    monkeypatch.setattr(lifecycle, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(lifecycle, "_owned_services", {})
    monkeypatch.setattr(lifecycle, "ollama_blocked", lambda: False)
    monkeypatch.setattr(lifecycle, "_require_ollama_allowed", lambda: None)
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _: False)
    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", lambda *_a, **_k: (_ for _ in ()).throw(lifecycle.OllamaProviderUnavailable("package")))
    for name in ("pull_model", "create_model", "show_model", "list_models",
                 "attest_ollama_service", "_exchange", "local_json_request"):
        monkeypatch.setattr(lifecycle, name, lambda *_a, **_k: pytest.fail("provider hold performed model I/O"))
    # All launch/listener/transport paths above are now inert; this test alone
    # exercises the real coordinator rather than conftest's offline result.
    monkeypatch.setattr(lifecycle, "ensure_ollama_service", _REAL_ENSURE_OLLAMA_SERVICE)
    status = lifecycle.ensure_ollama_service(timeout=1)
    assert status.state == "failed" and not status.daemon_ready
    assert "Per-user writable installations" in status.detail
    assert "preserved" in status.detail


def test_rejected_windows_image_location_never_reaches_filesystem(monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(lifecycle, "sys", SimpleNamespace(platform="win32", modules={}))
    monkeypatch.setattr(lifecycle, "_windows_image_location", lambda _path: False)
    monkeypatch.setattr(lifecycle, "_unredirected_image", lambda _path: pytest.fail("rejected location reached metadata"))
    assert lifecycle._trusted_ollama_image(Path(r"\\attacker\share\ollama.exe")) is False


def test_parent_reparse_is_rejected_before_child_metadata(tmp_path, monkeypatch):
    from pathlib import Path
    candidate = tmp_path / "redirected" / "ollama.exe"
    seen = []
    original = Path.lstat

    def observe(path, *args, **kwargs):
        seen.append(path)
        if path == candidate.parent:
            return SimpleNamespace(st_mode=0o040000, st_file_attributes=0x400)
        if path == candidate:
            pytest.fail("child metadata followed a rejected parent")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", observe)
    assert lifecycle._unredirected_image(candidate) is False
    assert candidate.parent in seen and candidate not in seen


def test_fresh_package_pass_cannot_extend_older_signer_evidence(image, monkeypatch):
    from functools import lru_cache
    now, signature_checks = [100.0], []
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(package_custody, "assess_package", lambda _p: package_custody.PackageCustody(True, "inert-snapshot", 2))

    @lru_cache(maxsize=16)
    def signing(*_identity):
        signature_checks.append(now[0])
        return True

    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", signing)
    assert lifecycle._trusted_ollama_image(image)
    now[0] = 129.0
    assert lifecycle._trusted_ollama_image(image)
    assert signature_checks == [100.0]
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: True)
    now[0] = 131.0
    assert not lifecycle._trusted_ollama_image(image)


def test_listener_reported_image_is_admitted_before_any_resolve(monkeypatch):
    from pathlib import Path
    import psutil

    monkeypatch.setattr(lifecycle, "_ollama_listener_pids", lambda *_: {42})
    process = SimpleNamespace(create_time=lambda: 100.0, exe=lambda: r"\\attacker\share\ollama.exe")
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)
    monkeypatch.setattr(lifecycle, "_trusted_ollama_image", lambda _path: False)
    monkeypatch.setattr(Path, "resolve", lambda *_a, **_k: pytest.fail("rejected provider path was resolved"))
    with pytest.raises(lifecycle.OllamaProviderUnavailable):
        lifecycle.attest_ollama_service("http://127.0.0.1:11434")


def test_changed_reported_image_is_rejected_before_resolving_the_new_path(tmp_path, monkeypatch):
    from pathlib import Path
    import psutil

    local = tmp_path / "inert-ollama.exe"
    local.write_bytes(b"inert")
    remote = Path(r"\\attacker\share\ollama.exe")
    images = iter((str(local), str(remote)))
    process = SimpleNamespace(create_time=lambda: 100.0, exe=lambda: next(images), is_running=lambda: True)
    monkeypatch.setattr(lifecycle, "_ollama_listener_pids", lambda *_: {42})
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)
    monkeypatch.setattr(lifecycle, "_trusted_ollama_image", lambda _path: True)
    original = Path.resolve

    def resolve(path, *args, **kwargs):
        if path == remote:
            pytest.fail("changed provider path was resolved")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(lifecycle.OllamaAttestationError, match="identity changed"):
        lifecycle.attest_ollama_service("http://127.0.0.1:11434")


def test_posix_default_model_home_comes_from_account_not_inherited_home(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "sys", SimpleNamespace(platform="linux", modules={}))
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    monkeypatch.setenv("HOME", "/untrusted-inherited-home")
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {"HOME": "/untrusted-inherited-home"})
    account_home = str(tmp_path / "account-home")
    monkeypatch.setattr(lifecycle, "_account_model_home", lambda: account_home)
    selected = []
    monkeypatch.setattr(model_paths, "default_model_directory", lambda environment: selected.append(dict(environment)) or str(tmp_path / "models"))
    environment = lifecycle._startup_environment("http://127.0.0.1:11434")
    assert selected[0]["HOME"] == account_home
    assert environment["HOME"] == account_home
    assert os.environ["HOME"] == "/untrusted-inherited-home"


def test_concurrent_epoch_advance_cannot_relabel_an_old_proof(image, monkeypatch):
    from functools import lru_cache

    now, signing_epochs = [100.0], []
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(package_custody, "assess_package", lambda _p: package_custody.PackageCustody(True, "inert-snapshot", 2))

    @lru_cache(maxsize=16)
    def signing(*identity_and_epoch):
        epoch = identity_and_epoch[-1]
        signing_epochs.append(epoch)
        if epoch == 100.0:
            # Model a different worker completing a newer epoch while this
            # older native verification is still in flight.
            now[0] = 131.0
            assert lifecycle._trusted_ollama_image(image)
        return True

    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", signing)
    assert not lifecycle._trusted_ollama_image(image)
    assert signing_epochs == [100.0, 131.0]
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: True)
    now[0] = 132.0
    assert lifecycle._trusted_ollama_image(image)
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: False)
    assert lifecycle._trusted_ollama_image(image)
    assert signing_epochs == [100.0, 131.0]
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: True)
    now[0] = 162.0
    assert not lifecycle._trusted_ollama_image(image)


def test_completed_signer_probe_cannot_extend_expired_package_observation(image, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: now[0])

    def package(_image):
        now[0] = 102.0
        return package_custody.PackageCustody(True, "inert-snapshot", 2)

    monkeypatch.setattr(package_custody, "assess_package", package)
    monkeypatch.setattr(lifecycle, "_windows_image_signature_valid", lambda *_: True)
    assert lifecycle._trusted_ollama_image(image)
    monkeypatch.setattr(lifecycle, "_on_gui_thread", lambda: True)
    now[0] = 130.5
    assert not lifecycle._trusted_ollama_image(image)


@pytest.mark.parametrize("linked_token_wrapper", [False, True])
def test_model_path_failure_stays_visible_through_normal_and_linked_launch(monkeypatch, linked_token_wrapper):
    monkeypatch.setattr(lifecycle, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(lifecycle, "_startup_lock", threading.RLock())
    monkeypatch.setattr(lifecycle, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(lifecycle, "_owned_services", {})
    monkeypatch.setattr(lifecycle, "ollama_blocked", lambda: False)
    monkeypatch.setattr(lifecycle, "_require_ollama_allowed", lambda: None)
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _: False)

    def rejected(*_args, **_kwargs):
        error = model_paths.ModelDirectoryError("untrusted detailed path from settings")
        if linked_token_wrapper:
            raise ValueError("linked user token unavailable") from error
        raise error

    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", rejected)
    for name in ("pull_model", "create_model", "show_model", "list_models",
                 "attest_ollama_service", "_exchange", "local_json_request"):
        monkeypatch.setattr(lifecycle, name, lambda *_a, **_k: pytest.fail("held model path performed external I/O"))
    # Restore only after the native/launch/network seams are all inert.
    monkeypatch.setattr(lifecycle, "ensure_ollama_service", _REAL_ENSURE_OLLAMA_SERVICE)
    status = lifecycle.ensure_ollama_service(timeout=1)
    assert status.state == "failed" and status.stage == "Model storage held"
    assert "setting was preserved" in status.detail
    assert "untrusted detailed path" not in status.detail
