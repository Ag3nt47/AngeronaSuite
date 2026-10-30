"""The packaged telemetry probe must never enter application startup."""
from __future__ import annotations

import builtins
from contextlib import contextmanager
import sys
import time
from types import SimpleNamespace

import pytest

from angerona import __main__ as entry
from angerona.core import kernel_telemetry_probe as probe
from angerona.core import windows_package_identity as package

TAG = "DRILLCANARY_ABCDEF0123456789"
FLAG = "--kernel-telemetry-canary"


@contextmanager
def deny_application_imports(monkeypatch):
    original = builtins.__import__
    imported = []

    def guarded(name, *args, **kwargs):
        imported.append(name)
        if name.startswith(("angerona.", "PySide6", "shiboken")) and name != "angerona.core.windows_package_identity":
            pytest.fail("inert helper imported application component: " + name)
        return original(name, *args, **kwargs)

    # Scope the tripwire to the helper call; repository Qt cleanup has its
    # own legitimate imports after the helper has already returned.
    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "__import__", guarded)
        yield imported


@pytest.mark.parametrize("arguments", [
    [FLAG], [FLAG, TAG, "--automatic-start"], ["--automatic-start", FLAG, TAG],
    [FLAG + "=" + TAG], [FLAG + "x", TAG], [FLAG, TAG.lower()],
    [FLAG, TAG + "0"], [FLAG, TAG + "\n"], [FLAG, TAG, FLAG],
])
def test_invalid_helper_arguments_never_enter_startup_or_mutate_environment(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["Angerona.exe", *arguments])
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(time, "sleep", lambda *_a: pytest.fail("malformed helper slept"))
    original_environment = dict(entry.os.environ)
    with deny_application_imports(monkeypatch) as imports:
        assert entry.main() == 2
    assert dict(entry.os.environ) == original_environment
    assert "angerona.core.windows_package_identity" not in imports


@pytest.mark.parametrize("frozen", [False, True])
def test_valid_helper_is_only_fixed_wait_and_optional_package_admission(monkeypatch, frozen):
    monkeypatch.setattr(sys, "argv", ["Angerona.exe", FLAG, TAG])
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    waits, admissions = [], []
    monkeypatch.setattr(time, "sleep", waits.append)
    monkeypatch.setattr(package, "verify_current_msix_authority",
                        lambda: admissions.append(True) or package.PackageAuthority(True, "modeled enrolled package"))
    original_environment = dict(entry.os.environ)
    with deny_application_imports(monkeypatch):
        assert entry.main() == 0
    assert waits == [2.0] and admissions == ([True] if frozen else [])
    assert dict(entry.os.environ) == original_environment


def test_unenrolled_packaged_helper_is_held_before_wait_without_uac(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["Angerona.exe", FLAG, TAG])
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(time, "sleep", lambda *_a: pytest.fail("unadmitted package slept"))
    monkeypatch.setattr(package, "verify_current_msix_authority",
                        lambda: package.PackageAuthority(False, "immutable publisher pin unavailable"))
    with deny_application_imports(monkeypatch):
        assert entry.main() == 2


@pytest.mark.parametrize("frozen", [False, True])
def test_owned_probe_uses_interpreter_flags_only_for_source_runtime(monkeypatch, frozen):
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(probe, "os", SimpleNamespace(name="nt", environ={}))
    captured = []

    def do_not_launch(command, _environment, **_kwargs):
        captured.append(command)
        raise RuntimeError("modeled launch boundary; no child created")

    with pytest.raises(RuntimeError, match="modeled launch boundary"):
        probe.OwnedCanaryProcess(TAG, _launch=do_not_launch, _native=SimpleNamespace())
    command, = captured
    if frozen:
        assert command == [sys.executable, FLAG, TAG]
    else:
        assert command == [sys.executable, "-I", "-S", "-B", "-c", "import time;time.sleep(2)",
                           "--angerona-canary=" + TAG]
