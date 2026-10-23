"""Offline packaging diagnostics cannot substitute for observed runtime custody."""
from __future__ import annotations

import itertools
import sys

import pytest

from angerona.modules import hermetic_packager as packaging


@pytest.mark.parametrize("protected,signed,trusted", tuple(itertools.product((False, True), repeat=3)))
def test_incomplete_proof_never_becomes_complete_packaging(protected, signed, trusted):
    score = packaging._frozen_windows_posture(protected, signed, trusted)
    assert (score == 100) is (protected and signed and trusted)
    assert score == (100 if protected and signed and trusted else 75 if protected and signed
                     else 60 if protected else 40)


def test_offline_diagnostic_never_enters_live_assessment_or_changes_health(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline self-test entered live OS assessment")
    module = packaging.HermeticPackagerModule()
    module.set_health(35, "fixture: runtime custody unavailable")
    before = (module.health, module.health_note, module._sig_status, module._image_authority,
              module._is_hermetic, module._binary, list(module._build_jobs))
    monkeypatch.setattr(module, "_assess", forbidden)
    for name in ("_check_signature", "_image_path_protected", "_find_binary", "_current_process_image"):
        monkeypatch.setattr(packaging, name, forbidden)
    ok, detail = module.self_test()
    assert ok is True and "were not assessed" in detail
    assert before == (module.health, module.health_note, module._sig_status, module._image_authority,
                      module._is_hermetic, module._binary, list(module._build_jobs))


def test_selftest_rejects_a_classifier_that_launders_missing_proof(monkeypatch):
    monkeypatch.setattr(packaging, "_frozen_windows_posture", lambda *_args: 100)
    assert packaging.HermeticPackagerModule().self_test()[0] is False


def test_runtime_unhealthy_sensor_cannot_borrow_offline_diagnostic_success():
    from angerona.core.selftest import SelfTestRunner
    module = packaging.HermeticPackagerModule()
    module.status = "running"
    module.set_health(0, "fixture: runtime observation failed")
    ok, detail = SelfTestRunner._test_module(module, 1.0)
    assert ok is False and "lifecycle/health reports failure" in detail


def test_runtime_assessment_still_uses_real_observation_providers(monkeypatch, tmp_path):
    if sys.platform != "win32":
        pytest.skip("Windows runtime observation branch")
    from types import SimpleNamespace
    from angerona.core import windows_package_identity
    image = tmp_path / "owned-fixture.exe"
    calls = []
    monkeypatch.setattr(packaging, "_is_frozen", lambda: True)
    monkeypatch.setattr(packaging, "_current_process_image", lambda: calls.append("os-image") or image)
    monkeypatch.setattr(packaging, "_image_path_protected", lambda path: calls.append("custody") or True)
    monkeypatch.setattr(packaging, "_check_signature", lambda path:
                        calls.append("signature") or (True, "Valid", "fixture", "fixture"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority", lambda:
                        calls.append("package") or SimpleNamespace(trusted=False, reason="held fixture"))
    score, _note = packaging.HermeticPackagerModule()._assess()
    assert calls == ["os-image", "custody", "signature", "package"]
    assert score == 75  # Signed image alone cannot attest an independent package.
