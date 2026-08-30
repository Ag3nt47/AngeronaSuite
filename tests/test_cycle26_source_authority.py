from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_every_source_entrypoint_is_unelevated_and_machine_non_mutating() -> None:
    names = (
        "Install-Angerona.bat",
        "start-angerona.bat",
        "start-angerona-guarded.bat",
        "run.bat",
    )
    forbidden = (
        "-verb runas",
        "net.exe\" session",
        "--scope machine",
        "harden_trust_root",
        "protect-key-custody.ps1",
        "icacls.exe",
        "set-acl",
    )
    for name in names:
        lowered = _text(name).casefold()
        for fragment in forbidden:
            assert fragment not in lowered, f"{name} retained {fragment}"


def test_delegates_and_desktop_shortcut_reach_only_canonical_source_launcher() -> None:
    canonical = _text("start-angerona.bat")
    assert "Refusing to execute mutable Angerona source with Administrator rights" in canonical
    assert "--require-hashes --no-deps -r requirements-bootstrap-pip.txt" in canonical
    assert "--require-hashes --no-deps -r requirements-release-hashed.txt" in canonical

    assert 'call "%~dp0start-angerona.bat" --source-setup' in _text(
        "Install-Angerona.bat"
    )
    assert 'call "%~dp0start-angerona.bat"' in _text("run.bat")
    assert 'call "%~dp0start-angerona.bat"' in _text("start-angerona-guarded.bat")
    shortcut = _text("create-blackbox-launcher.ps1")
    assert "$launcher = Join-Path $root 'start-angerona.bat'" in shortcut
    assert "unelevated" in shortcut.casefold()


def test_python_entrypoint_requires_package_authority_before_elevation() -> None:
    main = _text("src/angerona/__main__.py")
    frozen_branch = main.index('if frozen and sys.platform == "win32":')
    package_proof = main.index("verify_current_msix_authority()", frozen_branch)
    elevation = main.index("ensure_admin()", frozen_branch)
    source_refusal = main.index('elif sys.platform == "win32" and is_admin():')
    assert frozen_branch < package_proof < elevation < source_refusal
    assert main.count("verify_current_msix_authority()") == 2
    assert "Refusing elevated source execution" in main


def test_elevated_mutable_python_source_is_refused(monkeypatch) -> None:
    import angerona.__main__ as entry
    from angerona.core import privilege

    monkeypatch.delattr(entry.sys, "frozen", raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(privilege, "is_admin", lambda: True)
    monkeypatch.setattr(
        privilege,
        "ensure_admin",
        lambda: pytest.fail("source execution attempted the installed elevation path"),
    )
    assert entry.main() == 2


def test_unpinned_frozen_entrypoint_never_requests_elevation(monkeypatch) -> None:
    import angerona.__main__ as entry
    from angerona.core import privilege

    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(
        privilege,
        "ensure_admin",
        lambda: pytest.fail("untrusted frozen code attempted the UAC path"),
    )
    assert entry.main() == 2


def test_exact_package_authority_is_rechecked_after_elevation(monkeypatch) -> None:
    import angerona.__main__ as entry
    from angerona.core import privilege, windows_package_identity

    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    decisions = iter(
        (
            windows_package_identity.PackageAuthority(True, "trusted"),
            windows_package_identity.PackageAuthority(False, "identity changed"),
        )
    )
    calls = []
    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: next(decisions),
    )
    monkeypatch.setattr(privilege, "ensure_admin", lambda: calls.append("uac"))

    assert entry.main() == 2
    assert calls == ["uac"]


@pytest.mark.parametrize("state", ("cancelled", "failed"))
def test_failed_uac_never_continues_frozen_runtime(monkeypatch, state: str) -> None:
    import angerona.__main__ as entry
    from angerona.core import privilege, windows_package_identity

    result_state = (
        privilege.ElevationState.CANCELLED_OR_DENIED
        if state == "cancelled"
        else privilege.ElevationState.FAILED
    )
    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: windows_package_identity.PackageAuthority(True, "trusted"),
    )
    monkeypatch.setattr(
        privilege,
        "ensure_admin",
        lambda: privilege.ElevationResult(result_state, "inert UAC failure"),
    )
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    assert entry.main() == 2


def test_typed_elevation_result_cannot_replace_effective_token_proof(
    monkeypatch,
) -> None:
    import angerona.__main__ as entry
    from angerona.core import privilege, windows_package_identity

    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: windows_package_identity.PackageAuthority(True, "trusted"),
    )
    monkeypatch.setattr(
        privilege,
        "ensure_admin",
        lambda: privilege.ElevationResult(
            privilege.ElevationState.EFFECTIVE_ADMINISTRATOR,
            "inert claimed success",
        ),
    )
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    assert entry.main() == 2


def test_uac_cancellation_returns_a_typed_fail_closed_result(monkeypatch) -> None:
    from angerona.core import privilege

    class _CancelledShellExecute:
        argtypes = None
        restype = None

        def __call__(self, *_args) -> int:
            return 5

    monkeypatch.setattr(privilege.sys, "platform", "win32")
    monkeypatch.setattr(privilege.sys, "frozen", True, raising=False)
    monkeypatch.setattr(privilege.sys, "argv", ["Angerona.exe"])
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(
        privilege,
        "sanitize_privileged_bootstrap_environment",
        lambda: None,
    )
    monkeypatch.setattr(
        privilege.ctypes,
        "windll",
        SimpleNamespace(
            shell32=SimpleNamespace(ShellExecuteW=_CancelledShellExecute())
        ),
    )
    result = privilege.ensure_admin()
    assert isinstance(result, privilege.ElevationResult)
    assert result.state is privilege.ElevationState.CANCELLED_OR_DENIED
    assert result.effective_administrator is False


def test_exact_package_authority_can_reach_uac(monkeypatch) -> None:
    import angerona.__main__ as entry
    from angerona.core import privilege, windows_package_identity

    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: windows_package_identity.PackageAuthority(True, "trusted"),
    )

    def _installed_authority() -> None:
        raise SystemExit(73)

    monkeypatch.setattr(privilege, "ensure_admin", _installed_authority)
    with pytest.raises(SystemExit, match="73"):
        entry.main()


def test_msix_authority_requires_exact_family_and_publisher() -> None:
    from angerona.core.windows_package_identity import (
        NativePackageIdentity,
        verify_current_msix_authority,
    )

    expected_family = "AngeronaProject_7x7examplepublisher"
    expected_publisher = "7x7examplepublisher"
    observed = NativePackageIdentity(
        full_name="AngeronaProject_1.12.1.0_x64__7x7examplepublisher",
        family_name=expected_family,
    )
    accepted = verify_current_msix_authority(
        query=lambda: observed,
        expected_family_name=expected_family,
        expected_publisher_id=expected_publisher,
    )
    assert accepted.trusted is True

    wrong_publisher = NativePackageIdentity(
        full_name="AngeronaProject_1.12.1.0_x64__attacker",
        family_name="AngeronaProject_attacker",
    )
    refused = verify_current_msix_authority(
        query=lambda: wrong_publisher,
        expected_family_name=expected_family,
        expected_publisher_id=expected_publisher,
    )
    assert refused.trusted is False
    assert "not trusted" in refused.reason


def test_msix_authority_defaults_fail_closed_until_external_pin_exists() -> None:
    from angerona.core.windows_package_identity import verify_current_msix_authority

    result = verify_current_msix_authority(
        query=lambda: pytest.fail("unprovisioned authority queried native identity")
    )
    assert result.trusted is False
    assert "not provisioned" in result.reason


def test_public_install_truth_keeps_signed_msix_as_first_install() -> None:
    contract = _text("installer/windows-install-contract.json")
    readme = _text("README.md")
    editions = _text("docs/enterprise/SUPPORTED_EDITIONS.md")
    assert '"artifact":"signed-msix"' in contract
    assert "no public classic Setup first-install path" in readme
    assert "Source checkouts are unelevated Observe/development only" in readme
    assert "Full Windows Protect coverage requires the OS-validated signed MSIX" in editions
