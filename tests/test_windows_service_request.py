"""An onboarding request is inert data, never installation/signing authority."""
from __future__ import annotations

import json
import subprocess

import pytest

from tools import prepare_windows_service_request as request


COMMIT = "0123456789abcdef" * 2 + "01234567"


@pytest.mark.parametrize("value", [None, True, b"a" * 40, "", "a" * 39, "a" * 41,
    "A" * 40, "g" * 40, "a" * 40 + "\n", "a" * 39 + "\x00", "https://example.invalid/commit"])
def test_commit_is_strict_bounded_metadata(value):
    with pytest.raises(ValueError, match="40 lowercase"):
        request.build_request(value)


def test_request_is_canonical_deterministic_and_always_untrusted():
    first = request.request_bytes(COMMIT)
    assert first == request.request_bytes(COMMIT)
    assert first.endswith(b"\n") and len(first) <= 16 * 1024
    body = json.loads(first)
    assert first == json.dumps(body, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    assert body["schema"] == "angerona.windows-service-review-request/v1"
    assert body["classification"] == "UNTRUSTED_REVIEW_REQUEST" and body["planning_only"] is True
    assert body["source"] == {"repository": "Ag3nt47/AngeronaSuite", "commit": COMMIT,
                               "identity_verified": False}
    assert body["authorization"] and not any(body["authorization"].values())


def test_fixed_service_profiles_do_not_substitute_builtin_engine_account():
    body = request.build_request(COMMIT)
    engine, watchdog = body["requested_services"]
    assert (engine["name"], engine["image_package_relative"], engine["image_arguments"],
            engine["account"], engine["service_type"], engine["service_sid_type"]) == (
        "AngeronaProtection", "Angerona.exe", ["--engine-service"],
        "NT SERVICE\\AngeronaProtection", 0x10, 3)
    assert engine["restricted_virtual_service_sid_required"] is True
    assert engine["token_user_and_owner_must_equal_service_sid"] is True
    assert (watchdog["name"], watchdog["image_package_relative"], watchdog["image_arguments"],
            watchdog["account"], watchdog["service_type"], watchdog["service_sid_type"]) == (
        "AngeronaWatchdog3", "watchdog3.exe", ["--service"], "LocalSystem", 0x10, 0)
    assert watchdog["account_sid"] == "S-1-5-18"
    assert not engine["registration_and_runtime_verified"]
    assert not watchdog["registration_and_runtime_verified"]


def test_request_keeps_v2_public_bootstrap_and_migration_boundary():
    contract = request.build_request(COMMIT)["windows_install_contract"]
    assert contract["schema"] == "angerona.windows-install-contract/v2"
    assert contract["public_first_install"] == "signed-msix"
    assert contract["public_windows_install_artifacts"] == ["signed-msix", "threshold-authorized-zip"]
    assert contract["protected_upgrade_requires_prior_authority"]
    assert contract["classic_setup_role"] == "approved-installation-migration-only"
    assert contract["classic_setup_public_trust_bootstrap"] is False
    assert contract["classic_setup_public_release_asset"] is False
    assert contract["enterprise_clean_install_requires_separate_governed_artifact"] is True


def test_missing_publisher_provisioner_and_platform_acceptance_are_explicit():
    body = request.build_request(COMMIT)
    blockers = body["integration_blockers"]
    assert "independent_release_authority_not_provisioned" in blockers
    assert "approved_service_profile_provisioner_not_integrated" in blockers
    assert "msix_builtin_service_accounts_do_not_match_protection_virtual_account_profile" in blockers
    assert "current_msix_capability_contract_does_not_declare_packaged_services" in blockers
    assert "isolated_vm_install_upgrade_uninstall_and_stop_acceptance_not_completed" in blockers
    assert body["proposed_native_layout"]["layout_provisioned_or_accepted"] is False
    assert body["required_msix_identity"]["independently_enrolled"] is False
    assert all(pin["sha256"] is None and pin["publisher_subject"] is None
               and pin["independently_verified"] is False for pin in body["required_final_signed_pins"])


def test_release_threshold_and_windows_publisher_roles_remain_separate():
    authority = request.build_request(COMMIT)["release_authority_requirements"]
    assert authority["provisioned"] is False
    assert authority["candidate_repository_is_signing_authority"] is False
    assert authority["candidate_code_execution_by_authority_permitted"] is False
    assert authority["threshold_role"]["statement_schema"] == "angerona.release-authorization/v2"
    assert authority["threshold_role"]["algorithm"] == "Ed25519"
    assert authority["threshold_role"]["signed_message"] == "canonical statement bytes"
    assert authority["threshold_role"]["signature_threshold"] == 2
    assert authority["threshold_role"]["independently_administered_non_exportable_signers_required"]
    publisher = authority["windows_publisher_role"]
    assert publisher["separate_non_exportable_identity_required"]
    assert publisher["publisher_certificate_sha256"] is None
    assert publisher["repository_runner_receives_private_key_material"] is False
    assert publisher["signed_startup_helper_then_rebuilt_and_signed_safestart_required"]


def test_candidate_bytes_and_environment_cannot_enroll_any_pin(monkeypatch, tmp_path):
    candidate = tmp_path / "Angerona.exe"
    candidate.write_bytes(b"untrusted candidate one")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path / "do-not-create"))
    monkeypatch.setenv("WATCHDOG3_SHA256", "f" * 64)
    monkeypatch.setenv("PUBLISHER_SUBJECT", "CN=Untrusted environment")
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k:
                        pytest.fail("Planning request executed a command"))
    before = request.request_bytes(COMMIT)
    candidate.write_bytes(b"different untrusted candidate")
    assert request.request_bytes(COMMIT) == before
    assert not (tmp_path / "do-not-create").exists()


def test_output_is_new_canonical_file_and_does_not_create_other_state(tmp_path):
    output = tmp_path / "review.json"
    request.write_request(COMMIT, output)
    assert output.read_bytes() == request.request_bytes(COMMIT)
    assert set(tmp_path.iterdir()) == {output}


def test_existing_output_and_invalid_commit_never_overwrite_or_create(tmp_path):
    output = tmp_path / "existing.json"
    output.write_bytes(b"preserve existing artifact")
    with pytest.raises(FileExistsError):
        request.write_request(COMMIT, output)
    assert output.read_bytes() == b"preserve existing artifact"
    absent = tmp_path / "absent.json"
    with pytest.raises(ValueError):
        request.write_request("A" * 40, absent)
    assert not absent.exists()


def test_missing_output_parent_is_not_created(tmp_path):
    output = tmp_path / "missing" / "review.json"
    with pytest.raises(OSError):
        request.write_request(COMMIT, output)
    assert not output.parent.exists()


@pytest.mark.parametrize("name", ["review.json:stream", "trailing.", "space ", "NUL", "CON.json",
    "AUX.log", "PRN", "CLOCK$.json", "CONIN$", "CONOUT$", "COM1.txt", "LPT9.txt",
    "COM\u00b9.txt", "LPT\u00b3.txt", "wild*.json", "bad|name", "bad\x00name"])
def test_output_rejects_ads_devices_reserved_names_and_ambiguous_components(tmp_path, name):
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError):
        request.write_request(COMMIT, tmp_path / name)
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("name", ["C:relative.json", "\\rooted.json", "\\\\?\\C:\\review.json",
    "\\\\.\\NUL", "\\\\server\\share\\review.json"])
def test_output_rejects_drive_relative_remote_and_device_names_on_every_platform(name):
    from pathlib import Path
    with pytest.raises(ValueError):
        request._plain_output(Path(name))


def test_redirected_parent_is_refused_without_touching_target(tmp_path):
    outside, linked = tmp_path / "outside", tmp_path / "linked"
    outside.mkdir()
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlink creation is unavailable on this host")
    with pytest.raises(ValueError, match="plain directory"):
        request.write_request(COMMIT, linked / "review.json")
    assert not list(outside.iterdir())


def test_cli_reports_only_request_creation_not_installation_readiness(tmp_path, capsys):
    output = tmp_path / "review.json"
    assert request.main(["--source-commit", COMMIT, "--output", str(output)]) == 0
    text = capsys.readouterr().out
    assert "UNTRUSTED" in text and "remain unverified" in text
    assert request.main(["--source-commit", COMMIT, "--output", str(output)]) != 0


@pytest.mark.parametrize("extra", [["--pfx", "DO_NOT_ECHO_SECRET"],
    ["--token", "DO_NOT_ECHO_SECRET"], ["--install"], ["--source", COMMIT]])
def test_cli_rejects_authority_or_abbreviated_options_without_echoing_values(tmp_path, capsys, extra):
    output = tmp_path / "review.json"
    with pytest.raises(SystemExit) as stopped:
        request.main(["--source-commit", COMMIT, "--output", str(output), *extra])
    assert stopped.value.code == 2
    captured = capsys.readouterr()
    assert "DO_NOT_ECHO_SECRET" not in captured.err + captured.out
    assert not output.exists()
