"""Deterministic static policy checks for repository GitHub Actions workflows."""
from __future__ import annotations

import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml


SHA = re.compile(r"^[0-9a-f]{40}$")
EXPORTABLE_SIGNING_MARKERS = (
    "ANGERONA_RELEASE_SIGNER_A",
    "ANGERONA_RELEASE_SIGNER_B",
    "ANGERONA_RELEASE_ROOT_POLICY_B64",
    "ANGERONA_RELEASE_ROOT_POLICY_SHA256",
    "ANGERONA_WINDOWS_SIGNING_PFX_B64",
    "ANGERONA_WINDOWS_SIGNING_PASSWORD",
    "ANGERONA_WINDOWS_SIGNING_CERT_SHA256",
)
EXPORTABLE_SIGNING_SECRET_NAME = re.compile(
    r"(?:^|_)(?:PFX(?:_B64)?|PRIVATE_KEY(?:_B64)?|SIGNING_PASSWORD|"
    r"CERT(?:IFICATE)?_PASSWORD|PUBLISHER_(?:KEY|PASSWORD))(?:_|$)",
    re.IGNORECASE,
)
GITHUB_EXPRESSION = re.compile(r"(?is)\$\{\{(?:(?!\}\}).)*\}\}")
SECRET_TOKEN = re.compile(r"(?i)(?<![A-Za-z0-9_])secrets(?![A-Za-z0-9_])")
LITERAL_SECRET = re.compile(
    r"(?i)(?<![A-Za-z0-9_])secrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|"
    r"\[\s*['\"]([^'\"]+)['\"]\s*\])"
)
FAILURE_BYPASS_STATUS = re.compile(r"(?i)\b(?:always|cancelled|failure)\s*\(")
EXPRESSION_MARKER = re.compile(r"\$\{\{")

_ISOLATED_AUTHORITY_SHELL = (
    "/usr/bin/env -i PATH=/usr/bin:/bin "
    "/bin/bash --noprofile --norc -euo pipefail {0}"
)
_RELEASE_JOB_SCHEMA: dict[str, tuple[frozenset[str], str, int]] = {
    "verify-release-source": (
        frozenset({
            "name", "runs-on", "timeout-minutes", "outputs", "permissions", "steps",
        }),
        "ubuntu-latest",
        10,
    ),
    "prepare-windows": (
        frozenset({
            "needs", "runs-on", "timeout-minutes", "outputs", "permissions", "steps",
        }),
        "windows-latest",
        60,
    ),
    "finalize-release-authority": (
        frozenset({
            "name", "needs", "runs-on", "timeout-minutes", "permissions", "steps",
        }),
        "ubuntu-latest",
        5,
    ),
    "package-windows": (
        frozenset({"needs", "runs-on", "timeout-minutes", "permissions", "steps"}),
        "windows-latest",
        40,
    ),
    "build-posix": (
        frozenset({
            "needs", "name", "runs-on", "timeout-minutes", "permissions", "strategy",
            "steps",
        }),
        "${{ matrix.os }}",
        60,
    ),
    "publish-release": (
        frozenset({"if", "needs", "runs-on", "timeout-minutes", "permissions", "steps"}),
        "ubuntu-latest",
        20,
    ),
}

# (kind, exact action slug or run-step name, exact shell, exact mapping keys).
_RELEASE_STEP_GRAPH: dict[
    str, tuple[tuple[str, str, str | None, frozenset[str]], ...]
] = {
    "verify-release-source": (
        ("uses", "actions/checkout", None, frozenset({"uses", "with"})),
        ("uses", "actions/setup-python", None, frozenset({"uses", "with"})),
        (
            "run",
            "Require immutable source visible from public main",
            "bash",
            frozenset({"name", "id", "shell", "env", "run"}),
        ),
    ),
    "prepare-windows": (
        ("uses", "actions/checkout", None, frozenset({"uses"})),
        ("uses", "actions/setup-python", None, frozenset({"uses", "with"})),
        (
            "run", "Resolve filesystem-safe artifact label", "pwsh",
            frozenset({"name", "id", "shell", "env", "run"}),
        ),
        ("run", "Install audited dependencies", "pwsh", frozenset({"name", "shell", "run"})),
        ("run", "Run release gates", "pwsh", frozenset({"name", "shell", "run"})),
        (
            "run", "Bundle verified offline conversation model", "pwsh",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Build one-file executables with embedded sidecar integrity", "pwsh",
            frozenset({"name", "shell", "env", "run"}),
        ),
        (
            "run", "Verify frozen application contents", "pwsh",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Bundle release installer and documentation", "pwsh",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Prepare unsigned payload and canonical signing request", "pwsh",
            frozenset({"name", "shell", "env", "run"}),
        ),
        (
            "uses", "actions/upload-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "uses", "actions/upload-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
    ),
    "finalize-release-authority": (
        (
            "run",
            "Stop before any release or publisher key enters this workflow",
            _ISOLATED_AUTHORITY_SHELL,
            frozenset({"name", "shell", "run"}),
        ),
    ),
    "package-windows": (
        ("uses", "actions/checkout", None, frozenset({"uses"})),
        ("uses", "actions/setup-python", None, frozenset({"uses", "with"})),
        ("run", "", "pwsh", frozenset({"shell", "run"})),
        ("uses", "actions/download-artifact", None, frozenset({"uses", "with"})),
        (
            "run", "Build and structurally verify unsigned MSIX request", "pwsh",
            frozenset({"name", "shell", "env", "run"}),
        ),
        (
            "run", "Prepare bounded unsigned Windows publisher request", "pwsh",
            frozenset({"name", "shell", "env", "run"}),
        ),
        (
            "uses", "actions/upload-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
    ),
    "build-posix": (
        ("uses", "actions/checkout", None, frozenset({"uses"})),
        ("uses", "actions/setup-python", None, frozenset({"uses", "with"})),
        (
            "run", "Resolve filesystem-safe artifact label", "bash",
            frozenset({"name", "id", "shell", "env", "run"}),
        ),
        (
            "run", "Download and verify locked platform wheels", "bash",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Install verified platform dependencies offline", "bash",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Run platform release gates", "bash",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Build native application", "bash",
            frozenset({"name", "shell", "run"}),
        ),
        (
            "run", "Verify and package native application", "bash",
            frozenset({"name", "shell", "env", "run"}),
        ),
        (
            "uses", "actions/upload-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
    ),
    "publish-release": (
        (
            "uses", "actions/checkout", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "run", "Fail if release source moved or left public main", "bash",
            frozenset({"name", "shell", "working-directory", "env", "run"}),
        ),
        (
            "uses", "actions/download-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "uses", "actions/download-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "uses", "actions/download-artifact", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "uses", "actions/attest-build-provenance", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "uses", "actions/attest-sbom", None,
            frozenset({"name", "uses", "with"}),
        ),
        (
            "run", "Final immutable tag and default-main check", "bash",
            frozenset({"name", "shell", "working-directory", "env", "run"}),
        ),
        (
            "uses", "softprops/action-gh-release", None,
            frozenset({"name", "uses", "with"}),
        ),
    ),
}


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader variant that refuses ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_workflow(text: str) -> Mapping[str, Any]:
    parsed = yaml.load(text, Loader=_UniqueKeyLoader)
    if not isinstance(parsed, Mapping):
        raise ValueError("workflow root must be a mapping")
    return parsed


def _scalars(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _scalars(child)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for child in value:
            yield from _scalars(child)


def _expression_uses_secret_token(value: str) -> bool:
    """Return whether a parsed scalar references the GitHub secrets context."""

    return any(SECRET_TOKEN.search(match.group(0)) for match in GITHUB_EXPRESSION.finditer(value))


def _key_values(value: Any, target: str) -> Iterator[Any]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and key.casefold() == target.casefold():
                yield child
            yield from _key_values(child, target)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for child in value:
            yield from _key_values(child, target)


def _needs(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return None


def _steps(job: Any) -> list[Mapping[str, Any]]:
    if not isinstance(job, Mapping):
        return []
    steps = job.get("steps")
    if not isinstance(steps, list) or not all(
        isinstance(step, Mapping) for step in steps
    ):
        return []
    return list(steps)


def _action_slug(step: Mapping[str, Any]) -> str | None:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return None
    action, separator, _ref = uses.rpartition("@")
    if not separator:
        return None
    return action.casefold()


def _release_step_identity(
    step: Mapping[str, Any],
) -> tuple[str, str, str | None, frozenset[str]]:
    has_uses = "uses" in step
    has_run = "run" in step
    if has_uses == has_run:
        return "invalid", "", None, frozenset(str(key) for key in step)
    if has_uses:
        return (
            "uses",
            _action_slug(step) or "",
            None,
            frozenset(str(key) for key in step),
        )
    name = step.get("name", "")
    return (
        "run",
        name if isinstance(name, str) else "",
        step.get("shell") if isinstance(step.get("shell"), str) else None,
        frozenset(str(key) for key in step),
    )


def _validate_closed_release_schema(
    label: str, document: Mapping[str, Any], errors: list[str]
) -> Mapping[str, Any] | None:
    trigger_key: object = True if True in document else "on"
    expected_root = {"name", trigger_key, "permissions", "concurrency", "jobs"}
    if set(document) != expected_root:
        errors.append(f"{label}: release workflow root schema is not exact")
    if document.get("name") != "Build & Release":
        errors.append(f"{label}: release workflow name is not exact")
    if document.get(trigger_key) != {
        "push": {"tags": ["v*"]},
        "workflow_dispatch": None,
    }:
        errors.append(f"{label}: release triggers are not exact")
    if document.get("permissions") != {"contents": "read"}:
        errors.append(f"{label}: release root permissions are not exact")
    if document.get("concurrency") != {
        "group": "release-${{ github.ref }}",
        "cancel-in-progress": False,
    }:
        errors.append(f"{label}: release concurrency is not exact")

    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping):
        errors.append(f"{label}: jobs mapping is missing")
        return None
    if set(jobs) != set(_RELEASE_JOB_SCHEMA):
        errors.append(f"{label}: release job set is not exact")
        return jobs

    expected_permissions = {
        "verify-release-source": {"contents": "read"},
        "prepare-windows": {"contents": "read"},
        "finalize-release-authority": {},
        "package-windows": {"contents": "read"},
        "build-posix": {"contents": "read"},
        "publish-release": {
            "contents": "write",
            "id-token": "write",
            "attestations": "write",
        },
    }
    for name, (expected_keys, runner, timeout) in _RELEASE_JOB_SCHEMA.items():
        job = jobs.get(name)
        if not isinstance(job, Mapping):
            errors.append(f"{label}: release job {name} structure is invalid")
            continue
        if frozenset(str(key) for key in job) != expected_keys:
            errors.append(f"{label}: release job {name} schema is not exact")
        if job.get("runs-on") != runner or job.get("timeout-minutes") != timeout:
            errors.append(f"{label}: release job {name} runner/timeout is not exact")
        if job.get("permissions") != expected_permissions[name]:
            errors.append(f"{label}: release job {name} permissions are not exact")
        steps = _steps(job)
        actual_graph = tuple(_release_step_identity(step) for step in steps)
        if actual_graph != _RELEASE_STEP_GRAPH[name]:
            errors.append(f"{label}: release job {name} step graph is not exact")
    return jobs


def _artifact_names(job: Any, action: str) -> list[str]:
    names: list[str] = []
    for step in _steps(job):
        uses = step.get("uses")
        settings = step.get("with")
        if (
            isinstance(uses, str)
            and action in uses.casefold()
            and isinstance(settings, Mapping)
            and isinstance(settings.get("name"), str)
        ):
            names.append(settings["name"])
    return names


def _validate_artifact_graph(
    label: str, jobs: Mapping[str, Any], errors: list[str]
) -> None:
    expected = {
        ("verify-release-source", "actions/upload-artifact"): (),
        ("verify-release-source", "actions/download-artifact"): (),
        ("prepare-windows", "actions/upload-artifact"): (
            "prepared-windows-payload",
            "prepared-release-signing-request",
        ),
        ("prepare-windows", "actions/download-artifact"): (),
        ("finalize-release-authority", "actions/upload-artifact"): (),
        ("finalize-release-authority", "actions/download-artifact"): (),
        ("package-windows", "actions/upload-artifact"): (
            "prepared-windows-publisher-request",
        ),
        ("package-windows", "actions/download-artifact"): (
            "prepared-windows-payload",
        ),
        ("build-posix", "actions/upload-artifact"): (
            "angerona-${{ matrix.artifact }}",
        ),
        ("build-posix", "actions/download-artifact"): (),
        ("publish-release", "actions/upload-artifact"): (),
        ("publish-release", "actions/download-artifact"): (
            "finalized-windows-release-assets",
            "angerona-linux-x86_64",
            "angerona-macos-arm64",
        ),
    }
    for (job_name, action), expected_names in expected.items():
        job = jobs.get(job_name)
        if not isinstance(job, Mapping):
            continue
        actual_names: list[str] = []
        for step in _steps(job):
            if _action_slug(step) != action:
                continue
            settings = step.get("with")
            name = settings.get("name") if isinstance(settings, Mapping) else None
            if not isinstance(name, str):
                errors.append(
                    f"{label}: {job_name} artifact identity must be a string"
                )
                continue
            actual_names.append(name)
        if tuple(actual_names) != expected_names:
            errors.append(
                f"{label}: {job_name} {action.rsplit('/', 1)[-1]} "
                "artifact identities are not exact"
            )

    # The one bounded matrix template is safe only because its complete matrix
    # is fixed here. All Windows authority identities are literal strings.
    build_posix = jobs.get("build-posix")
    if isinstance(build_posix, Mapping) and build_posix.get("strategy") != {
        "fail-fast": False,
        "matrix": {
            "include": [
                {
                    "os": "ubuntu-24.04",
                    "platform": "linux",
                    "artifact": "linux-x86_64",
                    "extension": "tar.gz",
                },
                {
                    "os": "macos-15",
                    "platform": "macos",
                    "artifact": "macos-arm64",
                    "extension": "zip",
                },
            ]
        },
    }:
        errors.append(f"{label}: platform artifact matrix is not exact")

    for name in ("prepare-windows", "package-windows", "publish-release"):
        job = jobs.get(name)
        if not isinstance(job, Mapping):
            continue
        for step in _steps(job):
            if _action_slug(step) not in {
                "actions/upload-artifact",
                "actions/download-artifact",
            }:
                continue
            settings = step.get("with")
            artifact_name = (
                settings.get("name") if isinstance(settings, Mapping) else None
            )
            if isinstance(artifact_name, str) and EXPRESSION_MARKER.search(artifact_name):
                errors.append(
                    f"{label}: {name} security artifact identity must be literal"
                )


def _authority_gate_error(job: Any) -> str | None:
    if not isinstance(job, Mapping):
        return "fail-closed release authority gate is missing"
    allowed_job_keys = {
        "name",
        "needs",
        "runs-on",
        "timeout-minutes",
        "permissions",
        "steps",
    }
    if set(job) != allowed_job_keys:
        return "release authority gate contains an unapproved execution surface"
    if job.get("permissions") != {} or _needs(job.get("needs")) != (
        "package-windows",
    ):
        return "release authority gate has invalid permissions or dependency custody"

    steps = _steps(job)
    if len(steps) != 1:
        return "release authority gate must contain exactly one stopping step"
    step = steps[0]
    if (
        set(step) != {"name", "shell", "run"}
        or step.get("shell") != _ISOLATED_AUTHORITY_SHELL
    ):
        return "release authority gate contains an unapproved step"
    run = step.get("run")
    if not isinstance(run, str):
        return "release authority gate has no executable stopping script"
    lines = [
        line.strip()
        for line in run.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(lines) < 2 or lines[0] != "set -euo pipefail" or lines[-1] != "exit 1":
        return "release authority gate does not end in an executable exit 1"
    static_echo = re.compile(r'^echo "[A-Za-z0-9][A-Za-z0-9 ./,:_-]*" >&2$')
    if any(static_echo.fullmatch(line) is None for line in lines[1:-1]):
        return "release authority gate contains a command other than static notice and exit"
    return None


def _validate_release(
    label: str, document: Mapping[str, Any], errors: list[str]
) -> None:
    # Release authority must never enter the repository workflow, irrespective
    # of where GitHub would inherit it from.  Inspect the parsed document so
    # comments are absent, while requiring expression syntax so an inert string
    # that merely discusses ``secrets`` is not mistaken for context access.
    if any(_expression_uses_secret_token(scalar) for scalar in _scalars(document)):
        errors.append(f"{label}: release workflow accesses the secrets context")

    for environment in _key_values(document, "env"):
        if not isinstance(environment, Mapping):
            errors.append(f"{label}: release environment mapping is invalid")
            continue
        for key in environment:
            upper = str(key).upper()
            if upper in {"BASH_ENV", "ENV"} or upper.startswith("BASH_FUNC_"):
                errors.append(
                    f"{label}: release workflow contains a shell startup control"
                )

    jobs = _validate_closed_release_schema(label, document, errors)
    if jobs is None:
        return

    required_jobs = {
        "verify-release-source",
        "prepare-windows",
        "package-windows",
        "finalize-release-authority",
        "build-posix",
        "publish-release",
    }
    if not required_jobs.issubset(jobs):
        errors.append(f"{label}: required release jobs are missing")
        return

    for name, job in jobs.items():
        if not isinstance(name, str) or not isinstance(job, Mapping):
            errors.append(f"{label}: release job structure is invalid")
            continue
        if "uses" in job:
            errors.append(f"{label}: job-level reusable workflow {name} is forbidden")
        if any(_expression_uses_secret_token(scalar) for scalar in _scalars(job)):
            errors.append(f"{label}: release job {name} accesses the secrets context")
        if any(key.casefold() == "secrets" for key in job if isinstance(key, str)):
            errors.append(f"{label}: release job {name} passes job-level secrets")

    expected_needs = {
        "prepare-windows": ("verify-release-source",),
        "package-windows": ("prepare-windows",),
        "finalize-release-authority": ("package-windows",),
        "build-posix": ("verify-release-source",),
        "publish-release": (
            "verify-release-source",
            "package-windows",
            "finalize-release-authority",
            "build-posix",
        ),
    }
    for name, expected in expected_needs.items():
        actual = _needs(jobs[name].get("needs"))
        if actual is None or len(actual) != len(expected) or set(actual) != set(expected):
            errors.append(f"{label}: release job {name} has invalid needs edges")

    authority_error = _authority_gate_error(jobs["finalize-release-authority"])
    if authority_error:
        errors.append(f"{label}: {authority_error}")

    for name in ("package-windows", "finalize-release-authority", "publish-release"):
        job = jobs[name]
        if any(True for _ in _key_values(job, "continue-on-error")):
            errors.append(f"{label}: downstream job {name} can continue after an error")
        if any(FAILURE_BYPASS_STATUS.search(value) for value in _scalars(job)):
            errors.append(f"{label}: downstream job {name} can bypass a failed gate")
    publisher_if = jobs["publish-release"].get("if")
    if publisher_if != "startsWith(github.ref, 'refs/tags/v')":
        errors.append(f"{label}: publication condition is not the exact tag-only guard")
    for name in ("package-windows", "finalize-release-authority"):
        if "if" in jobs[name]:
            errors.append(f"{label}: downstream job {name} has a conditional gate")

    _validate_artifact_graph(label, jobs, errors)

    prepare_uploads = _artifact_names(jobs["prepare-windows"], "actions/upload-artifact@")
    package_uploads = _artifact_names(jobs["package-windows"], "actions/upload-artifact@")
    publish_downloads = _artifact_names(
        jobs["publish-release"], "actions/download-artifact@"
    )
    if "prepared-windows-payload" not in prepare_uploads:
        errors.append(f"{label}: prepared Windows payload producer is missing")
    if "prepared-release-signing-request" not in prepare_uploads:
        errors.append(f"{label}: canonical signing-request producer is missing")
    if package_uploads != ["prepared-windows-publisher-request"]:
        errors.append(f"{label}: Windows package job must upload only the unsigned request")
    package_upload_step = next(
        (
            step
            for step in _steps(jobs["package-windows"])
            if isinstance(step.get("uses"), str)
            and "actions/upload-artifact@" in step["uses"].casefold()
        ),
        {},
    )
    upload_with = package_upload_step.get("with", {})
    upload_path = upload_with.get("path", "") if isinstance(upload_with, Mapping) else ""
    if not isinstance(upload_path, str) or not {
        "-unsigned.msix",
        "-unsigned.zip",
    }.issubset(set(re.findall(r"-unsigned\.(?:msix|zip)", upload_path))):
        errors.append(f"{label}: Windows package upload is not explicitly unsigned")
    if "finalized-windows-release-assets" not in publish_downloads:
        errors.append(f"{label}: publication does not download finalized Windows assets")
    if "prepared-windows-publisher-request" in publish_downloads:
        errors.append(f"{label}: publication downloads an untrusted Windows request")
    for name, job in jobs.items():
        if name != "publish-release" and "finalized-windows-release-assets" in _artifact_names(
            job, "actions/upload-artifact@"
        ):
            errors.append(f"{label}: repository job {name} impersonates finalized authority")


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    workflow_dir = root / ".github" / "workflows"
    for path in sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml"))):
        text = path.read_text(encoding="utf-8")
        label = path.relative_to(root).as_posix()
        try:
            document = _load_workflow(text)
        except (ValueError, yaml.YAMLError) as exc:
            errors.append(f"{label}: workflow YAML is invalid: {exc}")
            continue

        for marker in EXPORTABLE_SIGNING_MARKERS:
            if marker in text:
                errors.append(
                    f"{label}: exportable signing authority {marker} is forbidden"
                )
        for scalar in _scalars(document):
            for match in LITERAL_SECRET.finditer(scalar):
                secret_name = match.group(1) or match.group(2) or ""
                if EXPORTABLE_SIGNING_SECRET_NAME.search(secret_name):
                    errors.append(
                        f"{label}: exportable signing secret {secret_name} is forbidden"
                    )
        if re.search(r"(?m)^\s*pull_request_target\s*:", text):
            errors.append(f"{label}: pull_request_target is forbidden")
        permissions = document.get("permissions")
        if not isinstance(permissions, Mapping) or permissions.get("contents") != "read":
            errors.append(f"{label}: top-level contents: read permission required")
        if "concurrency" not in document:
            errors.append(f"{label}: concurrency policy required")

        jobs = document.get("jobs")
        if isinstance(jobs, Mapping):
            for name, job in jobs.items():
                if not isinstance(name, str) or not isinstance(job, Mapping):
                    continue
                if "runs-on" in job and "timeout-minutes" not in job:
                    errors.append(f"{label}: job {name} lacks timeout")
                encoded = "\n".join(_scalars(job))
                if (
                    "ossf/scorecard-action@" in encoded
                    and job.get("permissions", {}).get("id-token") != "write"
                ):
                    errors.append(
                        f"{label}: publishing Scorecard job {name} requires id-token: write"
                    )

        for uses in _key_values(document, "uses"):
            if not isinstance(uses, str):
                errors.append(f"{label}: action reference must be a string")
                continue
            if uses.startswith(("./", "docker://")):
                continue
            action, separator, ref = uses.rpartition("@")
            if not separator or not action or not SHA.fullmatch(ref):
                errors.append(f"{label}: action {uses} is not SHA-pinned")

        if re.search(r"(?m)^\s+(?:contents|packages|actions):\s*write\s*$", text):
            if (
                "pull_request:" in text
                and "if: startsWith(github.ref, 'refs/tags/v')" not in text
            ):
                errors.append(f"{label}: write token may be exposed to pull request code")
        if path.name == "release.yml":
            _validate_release(label, document, errors)
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate(root)
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
