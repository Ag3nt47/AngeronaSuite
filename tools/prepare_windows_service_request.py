"""Prepare inert, untrusted service-integration input for an external reviewer.

This tool does not inspect executables, learn pins, validate a publisher, enroll
keys, install services, or delegate signing authority. Exit zero means only that
a new planning request was written. The independent release authority must not
execute this candidate-controlled tool as part of its production trust decision.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys


SCHEMA = "angerona.windows-service-review-request/v1"
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_REQUEST = 16 * 1024


def build_request(source_commit: str) -> dict:
    """Return a deterministic, planning-only contract without host observations."""
    if type(source_commit) is not str or not _COMMIT.fullmatch(source_commit):
        raise ValueError("Source commit must contain exactly 40 lowercase hexadecimal characters")
    return {
        "schema": SCHEMA,
        "product": "Angerona",
        "classification": "UNTRUSTED_REVIEW_REQUEST",
        "planning_only": True,
        "source": {"repository": "Ag3nt47/AngeronaSuite", "commit": source_commit,
                   "identity_verified": False},
        "authorization": {
            "installation_authorized": False,
            "service_registration_authorized": False,
            "signing_authorized": False,
            "runtime_trust_enrolled": False,
            "virtual_machine_acceptance_verified": False,
        },
        "windows_install_contract": {
            "schema": "angerona.windows-install-contract/v2",
            "public_first_install": "signed-msix",
            "public_windows_install_artifacts": ["signed-msix", "threshold-authorized-zip"],
            "protected_upgrade_requires_prior_authority": True,
            "classic_setup_role": "approved-installation-migration-only",
            "classic_setup_public_trust_bootstrap": False,
            "classic_setup_public_release_asset": False,
            "enterprise_clean_install_requires_separate_governed_artifact": True,
        },
        "requested_services": [
            {
                "name": "AngeronaProtection",
                "image_package_relative": "Angerona.exe",
                "image_arguments": ["--engine-service"],
                "account": "NT SERVICE\\AngeronaProtection",
                "service_type": 16,
                "service_sid_type": 3,
                "session_id": 0,
                "restricted_virtual_service_sid_required": True,
                "token_user_and_owner_must_equal_service_sid": True,
                "state_known_folder": "FOLDERID_ProgramData",
                "state_relative_path": "Angerona/Protection",
                "private_service_sid_acl_required": True,
                "registration_and_runtime_verified": False,
            },
            {
                "name": "AngeronaWatchdog3",
                "image_package_relative": "watchdog3.exe",
                "image_arguments": ["--service"],
                "account": "LocalSystem",
                "account_sid": "S-1-5-18",
                "service_type": 16,
                "service_sid_type": 0,
                "session_id": 0,
                "native_scm_host": True,
                "no_python_runtime_required": True,
                "registration_and_runtime_verified": False,
            },
        ],
        "proposed_native_layout": {
            "known_folder": "FOLDERID_ProgramData",
            "config_relative_path": "Angerona/watchdog3/config.json",
            "config_schema": 2,
            "config_admin_only_writers_required": True,
            "state_relative_path": "Angerona/watchdog3/state",
            "state_is_separate_from_protection_service_state": True,
            "shutdown_key_installer_provisioning_required": True,
            "control_authority_relative_path": "Angerona/control",
            "layout_provisioned_or_accepted": False,
        },
        "native_recovery_contract": {
            "fixed_target_service": "AngeronaProtection",
            "dispatch": "native StartService on an existing verified SCM registration",
            "direct_service_executable_launch_permitted": False,
            "clean_operator_stop_recovered": False,
            "admin_stop_must_be_verified": True,
            "source_checkout_auto_start": False,
            "owner_or_administrator_termination_resistance": False,
            "scm_process_presence_is_heartbeat_or_protection_proof": False,
        },
        "required_final_signed_pins": [
            {"image": name, "sha256": None, "publisher_subject": None,
             "independently_verified": False}
            for name in ("Angerona.exe", "watchdog3.exe", "AngeronaStartup.exe", "AngeronaSafeStart.exe")
        ],
        "required_msix_identity": {
            "package_name": None, "publisher_dn": None,
            "package_family_name": None, "publisher_id": None,
            "independently_enrolled": False,
        },
        "release_authority_requirements": {
            "provisioned": False,
            "candidate_repository_is_signing_authority": False,
            "immutable_external_implementation_required": True,
            "candidate_code_execution_by_authority_permitted": False,
            "oidc_invocation_binding_required": [
                "issuer", "audience", "repository", "workflow_identity", "workflow_revision",
                "tag", "source_commit", "event", "approved_environment",
            ],
            "threshold_role": {
                "statement_schema": "angerona.release-authorization/v2",
                "algorithm": "Ed25519",
                "signed_message": "canonical statement bytes",
                "signature_threshold": 2,
                "independently_administered_non_exportable_signers_required": True,
                "independently_enrolled_root_policy_required": True,
            },
            "windows_publisher_role": {
                "separate_non_exportable_identity_required": True,
                "publisher_certificate_sha256": None,
                "repository_runner_receives_private_key_material": False,
                "approved_publisher_subject_must_match_msix_manifest": True,
                "signed_startup_helper_then_rebuilt_and_signed_safestart_required": True,
                "final_signed_payload_manifest_catalog_and_statement_recomputed": True,
            },
        },
        "integration_blockers": [
            "independent_release_authority_not_provisioned",
            "final_windows_publisher_identity_and_signed_pins_not_enrolled",
            "runtime_msix_family_and_publisher_pins_not_enrolled",
            "approved_service_profile_provisioner_not_integrated",
            "current_msix_capability_contract_does_not_declare_packaged_services",
            "msix_builtin_service_accounts_do_not_match_protection_virtual_account_profile",
            "service_state_acl_token_and_process_profiles_require_independent_review",
            "isolated_vm_install_upgrade_uninstall_and_stop_acceptance_not_completed",
        ],
        "independent_review_required": [
            "Preserve the v2 MSIX-first installation and prior-authority migration boundary.",
            "Resolve the packaged-service account/capability mismatch without weakening runtime custody.",
            "Provision and review both service profiles and the native supervisor's separate private state.",
            "Obtain the Windows publisher identity and two separately administered release signers.",
            "Review final signed bytes and complete isolated VM acceptance before authorizing installation.",
        ],
        "references": [
            "docs/enterprise/RELEASE_SIGNING_BOUNDARY.md",
            "https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart",
            "https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-prepare",
            "https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations",
        ],
    }


def request_bytes(source_commit: str) -> bytes:
    encoded = json.dumps(build_request(source_commit), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    if len(encoded) > _MAX_REQUEST:
        raise ValueError("Review request exceeds its fixed byte budget")
    return encoded


def _plain_output(output: Path) -> Path:
    raw = str(output)
    if (not raw or len(raw) > 4096 or any(ord(character) < 32 for character in raw)
            or raw.startswith(("\\\\", "//")) or ".." in output.parts):
        raise ValueError("Output must name a new local file without traversal")
    windows = PureWindowsPath(raw)
    if windows.drive:
        if (not re.fullmatch(r"[A-Za-z]:", windows.drive) or not windows.is_absolute()
                or os.name != "nt"):
            raise ValueError("Output cannot use a device, remote or drive-relative name")
    elif raw.startswith("\\"):
        raise ValueError("Output cannot use a drive-relative rooted name")
    if os.name != "nt" and "\\" in raw:
        raise ValueError("Windows output separators are not supported on this host")
    for index, part in enumerate(re.split(r"[\\/]", raw)):
        if not part or (index == 0 and part == windows.drive):
            continue
        if (part in {".", ".."} or any(character in '<>:"|?*' for character in part)
                or part.endswith((".", " "))):
            raise ValueError("Output contains a non-ordinary filename component")
        stem = part.split(".", 1)[0].upper()
        if (stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
                or (len(stem) == 4 and stem[:3] in {"COM", "LPT"}
                    and stem[3] in "123456789\u00b9\u00b2\u00b3")):
            raise ValueError("Output cannot use a reserved device filename")
    output = output.absolute()
    ancestors = (*reversed(output.parent.parents), output.parent)
    if len(ancestors) > 128:
        raise ValueError("Output path exceeds its ancestor budget")
    for directory in ancestors:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or int(getattr(info, "st_file_attributes", 0)) & 0x400):
            raise ValueError("Output parent must be an existing plain directory")
    return output


def write_request(source_commit: str, output: Path) -> None:
    """Create a new report only; never overwrite, create parents, or install."""
    encoded = request_bytes(source_commit)
    output = _plain_output(Path(output))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("New review request is not one regular file")
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


class _RequestParser(argparse.ArgumentParser):
    def error(self, _message):
        # Do not echo accidentally supplied credential/unsupported-option values.
        self.print_usage(sys.stderr)
        self.exit(2, "Only --source-commit and --output are accepted; both are required.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _RequestParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source-commit", required=True, help="Unverified metadata: 40 lowercase hex characters")
    parser.add_argument("--output", type=Path, required=True, help="New planning-request file; parent must already exist")
    args = parser.parse_args(argv)
    try:
        write_request(args.source_commit, args.output)
    except FileExistsError:
        print("Output already exists; choose a new review-request filename.", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("Request creation did not complete; verify the commit format and a plain existing output parent.", file=sys.stderr)
        return 1
    print("UNTRUSTED planning request created. Signing, installation and service readiness remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
