from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from tools.validate_workflow_policy import validate


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _workflow() -> tuple[str, dict]:
    text = WORKFLOW.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert isinstance(parsed, dict)
    return text, parsed


def _mutated_workflows(tmp_path: Path, mutate) -> Path:
    workflow_root = tmp_path / ".github" / "workflows"
    shutil.copytree(ROOT / ".github" / "workflows", workflow_root)
    release = workflow_root / "release.yml"
    original = release.read_text(encoding="utf-8")
    changed = mutate(original)
    assert changed != original
    release.write_text(changed, encoding="utf-8")
    return tmp_path


def test_repository_workflow_never_receives_exportable_signing_secrets() -> None:
    text, parsed = _workflow()

    forbidden = (
        "ANGERONA_RELEASE_SIGNER_A",
        "ANGERONA_RELEASE_SIGNER_B",
        "ANGERONA_RELEASE_ROOT_POLICY_B64",
        "ANGERONA_RELEASE_ROOT_POLICY_SHA256",
        "release-signer-a",
        "release-signer-b",
        "witness-release-a",
        "witness-release-b",
        "ANGERONA_WINDOWS_SIGNING_PFX_B64",
        "ANGERONA_WINDOWS_SIGNING_PASSWORD",
        "ANGERONA_WINDOWS_SIGNING_CERT_SHA256",
        "Import-PfxCertificate",
        "signtool.exe",
    )
    for marker in forbidden:
        assert marker not in text

    jobs = parsed["jobs"]
    assert "sign-release-a" not in jobs
    assert "sign-release-b" not in jobs
    authority = jobs["finalize-release-authority"]
    assert authority["permissions"] == {}
    assert authority["needs"] == "package-windows"

    encoded = yaml.safe_dump(authority, sort_keys=True)
    assert "actions/checkout" not in encoded
    assert "actions/setup-python" not in encoded
    assert "actions/download-artifact" not in encoded
    assert "secrets." not in encoded
    assert "python " not in encoded.casefold()
    assert "exit 1" in encoded


def test_prepared_statement_is_preserved_but_cannot_reach_publication() -> None:
    text, parsed = _workflow()
    jobs = parsed["jobs"]

    prepare = yaml.safe_dump(jobs["prepare-windows"], sort_keys=True)
    authority = yaml.safe_dump(
        jobs["finalize-release-authority"], sort_keys=True
    )
    package = yaml.safe_dump(jobs["package-windows"], sort_keys=True)
    publisher = yaml.safe_dump(jobs["publish-release"], sort_keys=True)
    assert "prepared-release-signing-request" in prepare
    assert "dist/Angerona/release-statement.json" in prepare
    assert "release-payload-unsigned.cat" in prepare
    assert "prepared-windows-payload" in package
    assert "prepared-windows-publisher-request" in package
    assert "-unsigned.msix" in package
    assert "-unsigned.zip" in package
    assert "untrusted requests" in authority

    assert jobs["package-windows"]["needs"] == "prepare-windows"
    assert jobs["finalize-release-authority"]["needs"] == "package-windows"
    publish_needs = jobs["publish-release"]["needs"]
    assert "package-windows" in publish_needs
    assert "finalize-release-authority" in publish_needs
    assert "finalized-windows-release-assets" in publisher
    assert "prepared-windows-publisher-request" not in publisher
    assert "always()" not in text
    assert "continue-on-error: true" not in text


def test_repository_policy_enforces_fail_closed_release_boundary() -> None:
    assert validate(ROOT) == []


def test_repository_policy_rejects_exportable_signing_secret_in_any_workflow(
    tmp_path: Path,
) -> None:
    workflow_root = tmp_path / ".github" / "workflows"
    shutil.copytree(ROOT / ".github" / "workflows", workflow_root)
    security = workflow_root / "security.yml"
    security_text = security.read_text(encoding="utf-8")
    changed = security_text.replace(
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "          SIGNING_PFX: ${{ secrets.COMPANY_CODE_SIGNING_PFX }}",
        1,
    )
    assert changed != security_text
    security.write_text(changed, encoding="utf-8")

    errors = validate(tmp_path)
    assert any("exportable signing secret COMPANY_CODE_SIGNING_PFX" in e for e in errors)


@pytest.mark.parametrize(
    "expression",
    (
        "${{ secrets['CI_BLOB'] }}",
        "${{ secrets[vars.CI_BLOB_NAME] }}",
    ),
)
def test_release_policy_rejects_every_secrets_context_form(
    tmp_path: Path, expression: str
) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "          ANGERONA_RELEASE_EVENT: ${{ github.event_name }}",
            "          ANGERONA_RELEASE_EVENT: ${{ github.event_name }}\n"
            f"          CANDIDATE_SECRET: {expression}",
            1,
        ),
    )
    assert any("accesses the secrets context" in error for error in validate(root))


@pytest.mark.parametrize(
    "expression",
    (
        "${{ secrets.RENAMED_AUTHORITY_INPUT }}",
        "${{ secrets[vars.RENAMED_AUTHORITY_ALIAS] }}",
    ),
)
def test_release_policy_rejects_workflow_level_secret_context(
    tmp_path: Path, expression: str
) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\n\nenv:\n"
            f"  RELEASE_AUTHORITY_INPUT: {expression}",
            1,
        ),
    )
    errors = validate(root)
    assert any("release workflow accesses the secrets context" in error for error in errors)


def test_release_policy_parses_comments_and_inert_prose_structurally(
    tmp_path: Path,
) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "name: Build & Release",
            "# ${{ secrets.COMMENT_ONLY }}\n"
            "name: Build & Release\n"
            "run-name: Policy documentation mentions secrets.PROSE_ONLY",
            1,
        ),
    )
    errors = validate(root)
    assert not any("secrets context" in error for error in errors)


@pytest.mark.parametrize("scope", ("workflow", "job", "step"))
def test_release_policy_rejects_whole_secrets_context_serialization(
    tmp_path: Path, scope: str
) -> None:
    def _mutate(text: str) -> str:
        if scope == "workflow":
            return text.replace(
                "permissions:\n  contents: read",
                "permissions:\n  contents: read\n\nenv:\n"
                "  RELEASE_CONTEXT: ${{ toJSON(secrets) }}",
                1,
            )
        if scope == "job":
            return text.replace(
                "  package-windows:\n    needs: prepare-windows",
                "  package-windows:\n"
                "    needs: prepare-windows\n"
                "    env:\n"
                "      RELEASE_CONTEXT: ${{ toJSON(secrets) }}",
                1,
            )
        return text.replace(
            "          ANGERONA_RELEASE_EVENT: ${{ github.event_name }}",
            "          ANGERONA_RELEASE_EVENT: ${{ github.event_name }}\n"
            "          RELEASE_CONTEXT: ${{ toJSON(secrets) }}",
            1,
        )

    root = _mutated_workflows(tmp_path, _mutate)
    assert any(
        "release workflow accesses the secrets context" in error
        for error in validate(root)
    )


def test_release_policy_rejects_root_defaults_and_bash_startup_control(
    tmp_path: Path,
) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\n\n"
            "defaults:\n  run:\n    shell: bash\n"
            "env:\n  BASH_ENV: /tmp/inert-startup-marker",
            1,
        ),
    )
    errors = validate(root)
    assert any("root schema is not exact" in error for error in errors)
    assert any("shell startup control" in error for error in errors)


def test_release_policy_rejects_extra_expression_named_candidate_upload(
    tmp_path: Path,
) -> None:
    extra = (
        "      - name: Inert candidate impersonation fixture\n"
        "        uses: actions/upload-artifact@"
        "ea165f8d65b6e75b540449e92b4886f43607fa02\n"
        "        with:\n"
        "          name: ${{ format('{0}{1}', "
        "'finalized-windows-', 'release-assets') }}\n"
        "          path: dist/Angerona\n\n"
    )
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace("  finalize-release-authority:\n", extra + "  finalize-release-authority:\n", 1),
    )
    errors = validate(root)
    assert any("step graph is not exact" in error for error in errors)
    assert any("artifact identities are not exact" in error for error in errors)
    assert any("security artifact identity must be literal" in error for error in errors)


def test_release_authority_uses_an_empty_environment_shell() -> None:
    _text, parsed = _workflow()
    shell = parsed["jobs"]["finalize-release-authority"]["steps"][0]["shell"]
    assert shell.startswith("/usr/bin/env -i ")
    assert "BASH_ENV" not in shell
    assert "/bin/bash --noprofile --norc" in shell


def test_release_policy_rejects_job_reuse_and_inherited_secrets(tmp_path: Path) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "  package-windows:\n    needs: prepare-windows",
            "  package-windows:\n"
            "    uses: example/signer/.github/workflows/sign.yml@"
            + "a" * 40
            + "\n    secrets: inherit\n    needs: prepare-windows",
            1,
        ),
    )
    errors = validate(root)
    assert any("job-level reusable workflow package-windows" in error for error in errors)
    assert any("passes job-level secrets" in error for error in errors)


@pytest.mark.parametrize(
    "condition",
    ("${{ !cancelled() }}", "${{ failure() }}", "${{ always() }}"),
)
def test_release_policy_rejects_failed_dependency_status_bypasses(
    tmp_path: Path, condition: str
) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "  package-windows:\n    needs: prepare-windows",
            "  package-windows:\n"
            "    needs: prepare-windows\n"
            f"    if: {condition}",
            1,
        ),
    )
    errors = validate(root)
    assert any("can bypass a failed gate" in error for error in errors)
    assert any("has a conditional gate" in error for error in errors)


def test_release_policy_rejects_expression_continue_on_error(tmp_path: Path) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "      - shell: pwsh\n"
            "        run: python -m pip install --require-hashes --no-deps "
            "-r requirements-release-hashed.txt",
            "      - shell: pwsh\n"
            "        continue-on-error: ${{ matrix.ignore_failure }}\n"
            "        run: python -m pip install --require-hashes --no-deps "
            "-r requirements-release-hashed.txt",
            1,
        ),
    )
    assert any("can continue after an error" in error for error in validate(root))


def test_release_policy_requires_structural_publish_needs(tmp_path: Path) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "    needs: [verify-release-source, package-windows, "
            "finalize-release-authority, build-posix]",
            "    # package-windows and finalize-release-authority appear only in a comment",
            1,
        ),
    )
    assert any("publish-release has invalid needs edges" in error for error in validate(root))


def test_release_policy_requires_executable_authority_failure(tmp_path: Path) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "          exit 1",
            "          # exit 1\n          exit 0",
            1,
        ),
    )
    assert any("does not end in an executable exit 1" in error for error in validate(root))


def test_release_policy_rejects_comment_only_artifact_claim(tmp_path: Path) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "          name: prepared-windows-publisher-request",
            "          name: finalized-windows-release-assets "
            "# prepared-windows-publisher-request",
            1,
        ),
    )
    errors = validate(root)
    assert any("must upload only the unsigned request" in error for error in errors)
    assert any("impersonates finalized authority" in error for error in errors)


def test_release_policy_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    root = _mutated_workflows(
        tmp_path,
        lambda text: text.replace(
            "  package-windows:\n    needs: prepare-windows",
            "  package-windows:\n"
            "    needs: verify-release-source\n"
            "    needs: prepare-windows",
            1,
        ),
    )
    assert any("found duplicate key 'needs'" in error for error in validate(root))


def test_external_signing_contract_is_explicit_about_unprovisioned_residual() -> None:
    contract = (
        ROOT / "docs" / "enterprise" / "RELEASE_SIGNING_BOUNDARY.md"
    ).read_text(encoding="utf-8")

    for required in (
        "Current state: publication disabled",
        "GitHub OIDC",
        "non-exportable",
        "must not check out, import, install, or execute candidate-controlled code",
        "two independently administered",
        "Windows publisher",
        "unsigned",
        "finalized-windows-release-assets",
        "GitHub artifact attestations",
        "do not replace",
    ):
        assert required in contract
