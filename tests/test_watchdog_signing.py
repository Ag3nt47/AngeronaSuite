"""Signing inspection never becomes execution or enrollment authority."""
from __future__ import annotations

import copy
import json

import pytest

from angerona.core.watchdog_signing import (
    SigningInspection, WatchdogSigningError, export_signing_request,
    inspect_candidate, parse_inspection, prepare_signing_update, signing_indicator,
)

CANDIDATE = r"C:\review\watchdog3.exe"
IMAGE = "a" * 64
CERTIFICATE = "b" * 64
PUBLISHER = "CN=Reviewed <Literal>,O=Example,C=US"
EXPIRY = "2030-11-13T09:00:00Z"


def diagnostic(**changes):
    value = dict(schema=1, signature_valid=True, watchdog_sha256=IMAGE,
                 certificate_sha256=CERTIFICATE, publisher=PUBLISHER,
                 not_after=EXPIRY, reason="verified-machine-code-signing-chain",
                 activation_eligible=False, mode_state="diagnostic",
                 activation_status="not-assessed-by-diagnostic")
    value.update(changes)
    return value


def status(**changes):
    value = dict(state="active-unsigned", heartbeat_verified=True,
                 image_sha256=IMAGE, watchdog_sha256=IMAGE,
                 signature_verified=True, certificate_sha256=CERTIFICATE,
                 publisher=PUBLISHER, not_after=EXPIRY,
                 activation_enrolled=False, reduced_protection=True)
    value.update(changes)
    return value


def test_inspector_only_receives_the_selected_file_as_data(monkeypatch):
    from angerona.resilience import native_watchdog
    calls = []

    def inspect(path):
        calls.append(path)
        return diagnostic()

    monkeypatch.setattr(native_watchdog, "inspect_watchdog_candidate", inspect)
    result = inspect_candidate(CANDIDATE)
    assert calls == [CANDIDATE]
    assert result == SigningInspection(CANDIDATE, True, IMAGE, CERTIFICATE,
                                       PUBLISHER, EXPIRY, "verified-machine-code-signing-chain")


@pytest.mark.parametrize("path", [
    "watchdog3.exe", r"\\server\share\watchdog3.exe", r"\\?\C:\review\watchdog3.exe",
    r"C:\review\..\watchdog3.exe", r"C:\review\watchdog3.exe:stream",
    r"C:\review\other.exe", "C:/review/watchdog3.exe",
    "C:\\review\\watchdog3.exe\n", 1, None,
])
def test_invalid_selected_paths_are_held_before_inspector_call(monkeypatch, path):
    from angerona.resilience import native_watchdog
    monkeypatch.setattr(native_watchdog, "inspect_watchdog_candidate",
                        lambda *_args: pytest.fail("Invalid selection reached inspector"))
    with pytest.raises(WatchdogSigningError):
        inspect_candidate(path)


@pytest.mark.parametrize("change", [
    {"schema": True}, {"schema": 2}, {"signature_valid": 1},
    {"activation_eligible": True}, {"mode_state": "operational"},
    {"activation_status": "enrolled"}, {"extra": "not allowed"},
    {"watchdog_sha256": "A" * 64}, {"watchdog_sha256": ""},
    {"certificate_sha256": "invalid"}, {"publisher": ""},
    {"publisher": "CN=bad\nsubject"}, {"publisher": "x" * 1025},
    {"not_after": "2030-11-13"}, {"not_after": "not a date"},
    {"reason": "x" * 513},
])
def test_signature_metadata_cannot_manufacture_a_valid_inspection(change):
    with pytest.raises(WatchdogSigningError):
        parse_inspection(CANDIDATE, diagnostic(**change))


def test_unverified_inspection_retains_image_digest_without_signer_claim():
    checked = parse_inspection(CANDIDATE, diagnostic(
        signature_valid=False, certificate_sha256="", publisher="", not_after="",
        reason="signature-unavailable-or-invalid"))
    assert checked.watchdog_sha256 == IMAGE and not checked.signature_valid
    with pytest.raises(WatchdogSigningError, match="verified"):
        prepare_signing_update(checked)
    with pytest.raises(WatchdogSigningError, match="Unverified"):
        parse_inspection(CANDIDATE, diagnostic(signature_valid=False))


def test_prepared_update_is_untrusted_and_cannot_activate_anything(tmp_path):
    request = prepare_signing_update(parse_inspection(CANDIDATE, diagnostic()))
    assert request["trusted"] is False and request["activation_allowed"] is False
    assert request["runtime_compatibility_verified"] is False
    assert request["candidate_path"] == CANDIDATE
    assert request["activation_record"] == dict(
        schema=1, enabled=True, watchdog_sha256=IMAGE,
        certificate_sha256=CERTIFICATE, publisher=PUBLISHER)
    destination = tmp_path / "signing-review.json"
    export_signing_request(destination, request)
    assert json.loads(destination.read_text()) == request
    assert sorted(path.name for path in tmp_path.iterdir()) == ["signing-review.json"]
    before = destination.read_bytes()
    with pytest.raises(FileExistsError):
        export_signing_request(destination, request)
    assert destination.read_bytes() == before


@pytest.mark.parametrize("name", ["activation.json", "ACTIVATION.JSON", "config.json"])
def test_export_cannot_write_protected_activation_or_configuration_name(tmp_path, name):
    request = prepare_signing_update(parse_inspection(CANDIDATE, diagnostic()))
    with pytest.raises(WatchdogSigningError):
        export_signing_request(tmp_path / name, request)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(schema=True),
    lambda value: value.update(trusted=True),
    lambda value: value.update(activation_allowed=True),
    lambda value: value.update(runtime_compatibility_verified=True),
    lambda value: value.update(next_step="Enroll automatically"),
    lambda value: value["activation_record"].update(schema=True),
    lambda value: value["activation_record"].update(enabled=1),
    lambda value: value["activation_record"].update(extra="unknown"),
    lambda value: value["activation_record"].update(watchdog_sha256="invalid"),
])
def test_changed_preparation_is_rejected_before_any_export(tmp_path, mutation):
    request = copy.deepcopy(prepare_signing_update(parse_inspection(CANDIDATE, diagnostic())))
    mutation(request)
    with pytest.raises(WatchdogSigningError):
        export_signing_request(tmp_path / "review.json", request)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", [
    {"signature_verified": 1}, {"signature_verified": False},
    {"watchdog_sha256": "c" * 64}, {"image_sha256": ""},
    {"certificate_sha256": ""}, {"publisher": ""},
    {"not_after": "2030-11-13"},
])
def test_signature_marker_needs_exact_verified_image_and_complete_signer(change):
    view = signing_indicator(status(**change))
    assert not view.verified and view.label == "Signature unverified"
    assert "Signer: Unavailable" in view.tooltip
    assert "Active · Signature unverified · Reduced protection" in view.tooltip


def test_signature_and_liveness_are_independent_and_unenrolled_is_explicit():
    view = signing_indicator(status(state="stale", heartbeat_verified=False))
    assert view.verified and view.label == "Signature verified"
    assert "Third watchdog: Not responding" in view.tooltip
    assert "Not enrolled" in view.tooltip and "privileged" in view.tooltip
    assert "Active" not in view.tooltip
    unsigned = signing_indicator(status(signature_verified=False, signature_state="unsigned"))
    assert unsigned.label == "Unsigned"
    assert "Active · Unsigned · Reduced protection" in unsigned.tooltip
    missing = signing_indicator(None)
    assert not missing.verified and "Third watchdog: Unavailable" in missing.tooltip


@pytest.mark.parametrize("state", ["active-reduced", "active-unsigned"])
def test_live_signed_observer_projects_active_reduced_mode(state):
    view = signing_indicator(status(state=state))
    assert view.verified and view.label == "Signature verified"
    assert view.tooltip.splitlines()[0] == "Third watchdog: Active · Reduced protection"
    assert "Not enrolled" in view.tooltip


@pytest.mark.parametrize("state", ["active-reduced", "active-unsigned"])
@pytest.mark.parametrize("heartbeat", [False, None, 1, "true"])
def test_observer_mode_requires_explicit_verified_heartbeat(state, heartbeat):
    view = signing_indicator(status(state=state, heartbeat_verified=heartbeat))
    assert view.verified  # Signature does not establish liveness.
    assert view.tooltip.splitlines()[0] == "Third watchdog: Unavailable"


def test_stale_signed_observer_never_projects_active_mode():
    view = signing_indicator(status(state="stale", heartbeat_verified=True))
    assert view.verified
    assert view.tooltip.splitlines()[0] == "Third watchdog: Not responding"
