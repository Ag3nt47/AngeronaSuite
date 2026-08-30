from __future__ import annotations

import hashlib
import inspect
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools import publish_github_update as publisher
from tools import publication_transport as transport
from tools import verify_published_readme_assets as verifier
from tools import windows_publication_runtime as windows_runtime


ROOT = Path(__file__).resolve().parents[1]


class _FixtureGitBoundary:
    """Inert orchestration fixture; transport custody has dedicated tests below."""

    credential_helper = Path("C:/inert-fixture/git-credential-manager.exe")

    def __init__(self, runner=None) -> None:
        self._runner = runner
        self.closed = False

    def run(self, root: Path, arguments, *, text: bool, timeout: float):
        if self._runner is not None:
            return self._runner(root, *arguments, text=text, timeout=timeout)
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=text,
            check=False,
            timeout=timeout,
        )

    def close(self) -> None:
        self.closed = True


@pytest.fixture(scope="module")
def shared_publication_git_boundary():
    """Stage the reviewed 191 MB runtime once for the three live-boundary tests."""

    boundary = transport.resolve_trusted_git_boundary(
        source_environment={
            "PATH": "C:/caller-selected-bin",
            "HTTPS_PROXY": "http://credential-bearing-proxy.invalid",
            "SSL_CERT_FILE": "C:/caller-selected-ca.pem",
            "INERT_API_SECRET": "must-not-cross",
            "GIT_PAGER": "caller-selected-pager",
        }
    )
    try:
        yield boundary
    finally:
        boundary.close()


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _committed_fixture(root: Path) -> tuple[str, bytes, bytes]:
    image = (ROOT / "assets" / "icons" / "backup_f_preview.png").read_bytes()
    readme = b"# Snapshot fixture\n\n![fixture](docs/fixture.png)\n"
    (root / "docs").mkdir(parents=True)
    (root / "README.md").write_bytes(readme)
    (root / "docs" / "fixture.png").write_bytes(image)
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "inert-fixture@example.invalid")
    _git(root, "config", "user.name", "Inert Fixture")
    _git(root, "add", "README.md", "docs/fixture.png")
    _git(root, "commit", "-m", "fixture")
    return _git(root, "rev-parse", "HEAD"), readme, image


def test_asset_verifier_uses_captured_commit_not_mutable_worktree(
    tmp_path: Path, monkeypatch, shared_publication_git_boundary
) -> None:
    commit, committed_readme, committed_image = _committed_fixture(tmp_path)
    (tmp_path / "README.md").write_text(
        "# Concurrent edit\n\n![wrong](docs/wrong.png)\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "fixture.png").write_bytes(b"not-the-committed-image")

    requested: list[str] = []

    def _download(url: str, **_kwargs) -> tuple[bytes, str]:
        requested.append(url)
        if url.endswith("/README.md"):
            return committed_readme, "text/plain"
        if url.endswith("/docs/fixture.png"):
            return committed_image, "image/png"
        raise AssertionError(f"unexpected public target: {url}")

    monkeypatch.setattr(verifier, "_download_exact", _download)
    verified = verifier.verify_published_assets(
        tmp_path,
        repository="Ag3nt47/AngeronaSuite",
        ref=commit,
        expected_commit=commit,
        attempts=1,
        timeout=1.0,
        git_boundary=shared_publication_git_boundary,
    )
    assert verified == ["docs/fixture.png"]
    assert any(url.endswith("/README.md") for url in requested)
    assert not any("wrong.png" in url for url in requested)


def test_publisher_rechecks_clean_snapshot_after_network_verification(
    tmp_path: Path, monkeypatch
) -> None:
    head, _readme, _image = _committed_fixture(tmp_path)
    _git(
        tmp_path,
        "remote",
        "add",
        "origin",
        "https://github.com/Ag3nt47/AngeronaSuite.git",
    )

    monkeypatch.setattr(publisher, "validate", lambda _root: [])
    monkeypatch.setattr(
        publisher,
        "resolve_trusted_git_boundary",
        _FixtureGitBoundary,
    )
    monkeypatch.setattr(publisher, "_remote_default_branch", lambda *_args: "main")
    monkeypatch.setattr(publisher, "_fetch_branch", lambda *_args: "origin/main")
    monkeypatch.setattr(publisher, "_assert_ancestor", lambda *_args: None)
    monkeypatch.setattr(publisher, "_remote_sha", lambda *_args: head)

    def _network_verification(root: Path, **_kwargs) -> list[str]:
        (root / "README.md").write_text("concurrent edit\n", encoding="utf-8")
        return ["docs/fixture.png"]

    monkeypatch.setattr(
        publisher,
        "verify_published_assets",
        _network_verification,
    )
    with pytest.raises(publisher.PublicationError, match="working tree changed"):
        publisher.publish(tmp_path, verify_only=True)


def test_asset_verifier_has_no_process_or_pathname_download_fallback() -> None:
    source = inspect.getsource(verifier)
    assert "_download_exact_with_windows_powershell" not in source
    assert "Invoke-WebRequest" not in source
    assert "mkstemp" not in source
    assert "subprocess.run" not in source


def test_user_module_shadow_is_unreachable_from_in_memory_https(
    tmp_path: Path, monkeypatch
) -> None:
    module = (
        tmp_path
        / "Documents"
        / "WindowsPowerShell"
        / "Modules"
        / "Microsoft.PowerShell.Utility"
        / "Microsoft.PowerShell.Utility.psm1"
    )
    module.parent.mkdir(parents=True)
    module.write_text("throw 'must never load'\n", encoding="utf-8")
    monkeypatch.setenv("PSModulePath", str(module.parent.parent))
    url = (
        "https://raw.githubusercontent.com/Ag3nt47/AngeronaSuite/"
        + "a" * 40
        + "/README.md"
    )

    class _Response:
        status = 200
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self) -> str:
            return url

        def read(self, _limit: int) -> bytes:
            return b"in-memory-response"

    class _Opener:
        def open(self, *_args, **_kwargs):
            return _Response()

    monkeypatch.setattr(verifier, "_private_https_opener", lambda: _Opener())
    payload, content_type = verifier._download_exact(
        url,
        timeout=1.0,
        allowed_content_types=frozenset({"text/plain"}),
        max_bytes=64,
    )
    assert payload == b"in-memory-response"
    assert content_type == "text/plain"
    assert module.read_text(encoding="utf-8") == "throw 'must never load'\n"


def test_temp_hardlink_swap_is_unreachable_without_path_handoff(
    tmp_path: Path, monkeypatch
) -> None:
    temporary = tmp_path / "caller-temp"
    temporary.mkdir()
    victim = tmp_path / "inert-victim.bin"
    victim.write_bytes(b"must remain unchanged")
    alias = temporary / "attacker-alias.bin"
    alias.hardlink_to(victim)
    monkeypatch.setenv("TEMP", str(temporary))
    before = sorted(path.name for path in temporary.iterdir())
    url = (
        "https://raw.githubusercontent.com/Ag3nt47/AngeronaSuite/"
        + "a" * 40
        + "/image.png"
    )

    class _Response:
        status = 200
        headers = {"Content-Type": "image/png"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self) -> str:
            return url

        def read(self, _limit: int) -> bytes:
            return b"bounded-memory-only"

    class _Opener:
        def open(self, *_args, **_kwargs):
            return _Response()

    monkeypatch.setattr(verifier, "_private_https_opener", lambda: _Opener())
    payload, _content_type = verifier._download_exact(
        url,
        timeout=1.0,
        max_bytes=64,
    )
    assert payload == b"bounded-memory-only"
    assert victim.read_bytes() == b"must remain unchanged"
    assert sorted(path.name for path in temporary.iterdir()) == before


@pytest.mark.parametrize(
    "name",
    (
        "HTTPS_PROXY",
        "http_proxy",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "OPENSSL_CONF",
        "SSLKEYLOGFILE",
    ),
)
def test_asset_https_rejects_ambient_transport_authority_before_open(
    name: str, monkeypatch
) -> None:
    for candidate in verifier._HTTPS_AUTHORITY_ENVIRONMENT:
        monkeypatch.delenv(candidate, raising=False)
        monkeypatch.delenv(candidate.upper(), raising=False)
    monkeypatch.setenv(name, "inert-ambient-authority")
    monkeypatch.setattr(
        verifier,
        "build_opener",
        lambda *_args: pytest.fail("transport must not open"),
    )
    with pytest.raises(verifier.PublishedAssetError, match="ambient HTTPS"):
        verifier._private_https_opener()


def test_asset_https_opener_explicitly_disables_proxy_discovery(monkeypatch) -> None:
    for candidate in verifier._HTTPS_AUTHORITY_ENVIRONMENT:
        monkeypatch.delenv(candidate, raising=False)
        monkeypatch.delenv(candidate.upper(), raising=False)
    context = object()
    captured: list[object] = []
    sentinel = object()
    monkeypatch.setattr(verifier, "_system_trust_context", lambda: context)

    def _build(*handlers):
        captured.extend(handlers)
        return sentinel

    monkeypatch.setattr(verifier, "build_opener", _build)
    assert verifier._private_https_opener() is sentinel
    proxy = next(item for item in captured if isinstance(item, verifier.ProxyHandler))
    https = next(item for item in captured if isinstance(item, verifier.HTTPSHandler))
    assert proxy.proxies == {}
    assert https._context is context


@pytest.mark.parametrize(
    "name",
    (
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_EXEC_PATH",
        "GIT_SSL_NO_VERIFY",
        "GIT_ASKPASS",
        "GIT_SSH_COMMAND",
        "GIT_OBJECT_DIRECTORY",
        "GIT_HTTP_USER_AGENT",
        "GIT_TRACE_CURL",
    ),
)
def test_git_boundary_rejects_ambient_authority(name: str) -> None:
    with pytest.raises(transport.PublicationTransportError, match="ambient Git"):
        transport.resolve_trusted_git_boundary(
            source_environment={name: "inert-override"}
        )


def test_git_boundary_uses_absolute_git_literal_argv_and_fresh_environment(
    monkeypatch,
    shared_publication_git_boundary,
) -> None:
    boundary = shared_publication_git_boundary
    captured: dict[str, object] = {}

    def _run(arguments, **kwargs):
        captured["arguments"] = list(arguments)
        captured["environment"] = dict(kwargs["env"])
        captured["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(transport.subprocess, "run", _run)
    try:
        result = boundary.run(
            ROOT,
            [
                "ls-remote",
                "--heads",
                transport.CANONICAL_GITHUB_ORIGIN,
                "refs/heads/main",
            ],
            text=False,
            timeout=5.0,
        )
        assert result.returncode == 0
        arguments = captured["arguments"]
        environment = captured["environment"]
        assert arguments[0] == str(boundary.executable)
        assert Path(arguments[0]).is_absolute()
        assert arguments[-4:] == [
            "ls-remote",
            "--heads",
            transport.CANONICAL_GITHUB_ORIGIN,
            "refs/heads/main",
        ]
        assert arguments[arguments.index("-C") + 1] == str(ROOT)
        if boundary.credential_helper is not None:
            quoted = transport._shell_quote_helper(boundary.credential_helper)
            assert f"credential.helper={quoted}" in arguments
        else:
            assert "credential.helper=" in arguments
        assert f"url.{transport.CANONICAL_GITHUB_ORIGIN}.insteadOf=" + (
            transport.CANONICAL_GITHUB_ORIGIN
        ) in arguments
        assert environment == boundary.environment
        assert captured["cwd"] == str(boundary.execution_directory)
        joined_environment = "\n".join(
            f"{key}={value}" for key, value in environment.items()
        )
        assert "caller-selected" not in joined_environment
        assert "must-not-cross" not in joined_environment
        assert "credential-bearing" not in joined_environment
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        if sys.platform == "win32":
            assert environment["GIT_EXEC_PATH"] == str(boundary.staged_runtime.git_exec_path)
            assert str(boundary.staged_runtime.root) in environment["PATH"]
            assert str(ROOT) not in environment["PATH"]
    finally:
        boundary.revalidate()


@pytest.mark.parametrize(
    "origin",
    (
        "https://github.com/Ag3nt47/AngeronaSuite",
        "https://github.com/Ag3nt47/AngeronaSuite.git/",
        "https://github.com/ag3nt47/AngeronaSuite.git",
        "https://github.com/Ag3nt47/angeronasuite.git",
        "https://GITHUB.com/Ag3nt47/AngeronaSuite.git",
        "https://github.com//Ag3nt47/AngeronaSuite.git",
        "https://github.com/Ag3nt47/AngeronaSuite.git ",
    ),
)
def test_publication_rejects_slug_equivalent_noncanonical_origins(origin: str) -> None:
    with pytest.raises(publisher.PublicationError, match="byte-for-byte"):
        publisher.require_canonical_publication_origin(origin, kind="fetch")


def test_publication_accepts_only_the_exact_canonical_origin() -> None:
    assert publisher.require_canonical_publication_origin(
        publisher.CANONICAL_ORIGIN,
        kind="fetch",
    ) == "Ag3nt47/AngeronaSuite"


def test_local_url_rewrite_is_rejected_even_when_origin_remains_canonical(
    tmp_path: Path,
    shared_publication_git_boundary,
) -> None:
    _committed_fixture(tmp_path)
    _git(
        tmp_path,
        "remote",
        "add",
        "origin",
        publisher.CANONICAL_ORIGIN,
    )
    _git(
        tmp_path,
        "config",
        "url.https://redirect.invalid/.insteadOf",
        publisher.CANONICAL_ORIGIN,
    )
    assert _git(tmp_path, "config", "--get", "remote.origin.url") == (
        publisher.CANONICAL_ORIGIN
    )
    token = publisher._ACTIVE_GIT_BOUNDARY.set(shared_publication_git_boundary)
    try:
        with pytest.raises(publisher.PublicationError, match="authority is forbidden"):
            publisher._assert_local_configuration_policy(tmp_path)
    finally:
        publisher._ACTIVE_GIT_BOUNDARY.reset(token)


def test_late_local_config_mutation_fails_before_fetch_or_push(
    tmp_path: Path, monkeypatch
) -> None:
    _committed_fixture(tmp_path)
    _git(
        tmp_path,
        "remote",
        "add",
        "origin",
        publisher.CANONICAL_ORIGIN,
    )
    fetches: list[str] = []
    monkeypatch.setattr(
        publisher,
        "resolve_trusted_git_boundary",
        _FixtureGitBoundary,
    )

    def _mutate_during_first_network_gate(*_args) -> str:
        _git(tmp_path, "config", "user.late-publication-mutation", "inert")
        return "main"

    monkeypatch.setattr(publisher, "_remote_default_branch", _mutate_during_first_network_gate)
    monkeypatch.setattr(
        publisher,
        "_fetch_branch",
        lambda *_args: fetches.append("fetch") or "origin/main",
    )
    with pytest.raises(publisher.PublicationError, match="configuration changed"):
        publisher.publish(tmp_path, verify_only=True)
    assert fetches == []


def test_remote_helpers_use_only_literal_canonical_transport(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def _git_result(_root, *arguments, **_kwargs):
        calls.append(tuple(arguments))
        if "--symref" in arguments:
            output = "ref: refs/heads/main\tHEAD\n" + "a" * 40 + "\tHEAD\n"
        elif "fetch" in arguments:
            output = ""
        else:
            output = "a" * 40 + "\trefs/heads/main\n"
        return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr="")

    monkeypatch.setattr(publisher, "_git", _git_result)
    assert publisher._remote_default_branch(ROOT, publisher.CANONICAL_ORIGIN) == "main"
    assert publisher._remote_sha(ROOT, publisher.CANONICAL_ORIGIN, "main") == "a" * 40
    assert publisher._fetch_branch(ROOT, publisher.CANONICAL_ORIGIN, "main") == (
        "refs/remotes/origin/main"
    )
    assert all(publisher.CANONICAL_ORIGIN in call for call in calls)
    assert all("origin" not in call for call in calls)
    with pytest.raises(publisher.PublicationError, match="literal canonical URL"):
        publisher._remote_sha(ROOT, "origin", "main")


def test_remote_url_query_rejects_trailing_bytes(
    tmp_path: Path, monkeypatch
) -> None:
    def _run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            [],
            0,
            stdout=publisher.CANONICAL_ORIGIN.encode("ascii") + b" \0",
            stderr=b"",
        )

    boundary = _FixtureGitBoundary(_run)
    token = publisher._ACTIVE_GIT_BOUNDARY.set(boundary)
    try:
        with pytest.raises(publisher.PublicationError, match="byte-exact"):
            publisher._single_remote_url(tmp_path, "origin", push=False)
    finally:
        publisher._ACTIVE_GIT_BOUNDARY.reset(token)


def _fixture_runtime_profile(source: Path) -> windows_runtime.RuntimeProfile:
    payloads = {
        "cmd/git.exe": b"reviewed-git-image",
        "mingw64/bin/git-credential-manager.exe": b"reviewed-gcm-image",
        "mingw64/libexec/git-core/git-remote-https.exe": b"reviewed-https-image",
        "usr/bin/msys-2.0.dll": b"reviewed-shell-runtime",
        "usr/bin/sh.exe": b"reviewed-shell-image",
    }
    directories: set[str] = set()
    records: list[windows_runtime.RuntimeFile] = []
    for relative, payload in payloads.items():
        path = source / Path(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        parent = path.parent
        while parent != source:
            directories.add(parent.relative_to(source).as_posix())
            parent = parent.parent
        records.append(
            windows_runtime.RuntimeFile(
                relative,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            )
        )
    ordered_directories = tuple(sorted(directories))
    ordered_records = tuple(sorted(records, key=lambda item: item.relative))
    return windows_runtime.RuntimeProfile(
        git_version="fixture",
        git_build_commit="0" * 40,
        directories=ordered_directories,
        files=ordered_records,
        total_bytes=sum(item.size for item in ordered_records),
        tree_sha256=windows_runtime._tree_digest(
            ordered_directories,
            ordered_records,
        ),
    )


def _fixture_hardlink_profile(
    source: Path,
    *,
    alias_sha256: str | None = None,
) -> windows_runtime.RuntimeProfile:
    profile = _fixture_runtime_profile(source)
    original = source / "cmd" / "git.exe"
    alias = source / "cmd" / "git-lfs.exe"
    alias.hardlink_to(original)
    git_record = next(
        record for record in profile.files if record.relative == "cmd/git.exe"
    )
    alias_record = windows_runtime.RuntimeFile(
        "cmd/git-lfs.exe",
        git_record.size,
        alias_sha256 or git_record.sha256,
    )
    files = tuple(sorted((*profile.files, alias_record), key=lambda item: item.relative))
    return windows_runtime.RuntimeProfile(
        git_version=profile.git_version,
        git_build_commit=profile.git_build_commit,
        directories=profile.directories,
        files=files,
        total_bytes=sum(item.size for item in files),
        tree_sha256=windows_runtime._tree_digest(profile.directories, files),
    )


def test_reviewed_windows_runtime_profile_is_closed_and_content_addressed() -> None:
    profile = windows_runtime.load_runtime_profile()
    assert profile.git_version == "2.55.0.windows.4"
    assert profile.git_build_commit == "a93524749d7806870fd2b4b00a3812da1d6e5f4a"
    assert len(profile.files) == 312
    assert profile.total_bytes == 191_289_767
    assert profile.tree_sha256 == windows_runtime._tree_digest(
        profile.directories,
        profile.files,
    )
    assert {item.relative for item in profile.files}.issuperset(
        {
            "cmd/git.exe",
            "mingw64/bin/git-credential-manager.exe",
            "mingw64/libexec/git-core/git-remote-https.exe",
            "usr/bin/msys-2.0.dll",
            "usr/bin/sh.exe",
        }
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Known Folder boundary")
def test_default_staging_parent_ignores_ambient_temp_authority(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ambient = (tmp_path / "caller-selected-temp").resolve()
    ambient.mkdir()
    monkeypatch.setenv("TEMP", str(ambient))
    monkeypatch.setenv("TMP", str(ambient))

    trusted = windows_runtime._trusted_temp_root()

    assert trusted != ambient
    assert not trusted.is_relative_to(ambient)
    assert trusted.name.casefold() == "temp"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle sharing boundary")
def test_pre_replaced_even_nominally_signed_git_fails_reviewed_digest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_runtime_profile(source)
    git = source / "cmd" / "git.exe"
    # A platform signature result is intentionally irrelevant: the reviewed
    # profile binds exact bytes, not merely any certificate Windows accepts.
    git.write_bytes(b"untrusted-git-img!")
    assert git.stat().st_size == next(
        item.size for item in profile.files if item.relative == "cmd/git.exe"
    )
    with pytest.raises(windows_runtime.WindowsRuntimeError, match="digest mismatch"):
        windows_runtime.stage_pinned_runtime(
            source.resolve(),
            profile=profile,
            staging_parent=tmp_path.resolve(),
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hard-link boundary")
def test_exact_profiled_hardlink_pair_stages_as_independent_copies(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_hardlink_profile(source)
    staged = windows_runtime.stage_pinned_runtime(
        source.resolve(),
        profile=profile,
        staging_parent=tmp_path.resolve(),
    )
    root = staged.root
    try:
        git = root / "cmd" / "git.exe"
        git_lfs = root / "cmd" / "git-lfs.exe"
        assert git.read_bytes() == b"reviewed-git-image"
        assert git_lfs.read_bytes() == b"reviewed-git-image"
        assert not os.path.samefile(git, git_lfs)
        assert git.stat().st_nlink == git_lfs.stat().st_nlink == 1
    finally:
        staged.close()
    assert not root.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hard-link boundary")
def test_profiled_source_with_outside_hardlink_alias_fails_closed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_runtime_profile(source)
    (tmp_path / "outside-git-alias.exe").hardlink_to(source / "cmd" / "git.exe")
    with pytest.raises(windows_runtime.WindowsRuntimeError, match="outside hard-link"):
        windows_runtime.stage_pinned_runtime(
            source.resolve(),
            profile=profile,
            staging_parent=tmp_path.resolve(),
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hard-link boundary")
def test_unprofiled_in_root_hardlink_alias_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    profile = _fixture_runtime_profile(source)
    (source / "unprofiled-git-alias.exe").hardlink_to(source / "cmd" / "git.exe")
    with pytest.raises(windows_runtime.WindowsRuntimeError, match="unprofiled hard-link"):
        windows_runtime.stage_pinned_runtime(
            source.resolve(),
            profile=profile,
            staging_parent=tmp_path.resolve(),
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hard-link boundary")
def test_profiled_hardlink_metadata_mismatch_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    profile = _fixture_hardlink_profile(source, alias_sha256="0" * 64)
    with pytest.raises(windows_runtime.WindowsRuntimeError, match="aliases disagree"):
        windows_runtime.stage_pinned_runtime(
            source.resolve(),
            profile=profile,
            staging_parent=tmp_path.resolve(),
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hard-link boundary")
def test_profiled_hardlink_alias_swap_is_denied_or_detected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_hardlink_profile(source)
    alias = source / "cmd" / "git-lfs.exe"
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"reviewed-git-image")
    original = windows_runtime._copy_hardlink_group_from_handle
    attempted = False
    replaced = False

    def _race(handle, destinations):
        nonlocal attempted, replaced
        attempted = True
        try:
            os.replace(replacement, alias)
        except OSError:
            pass
        else:
            replaced = True
        return original(handle, destinations)

    monkeypatch.setattr(windows_runtime, "_copy_hardlink_group_from_handle", _race)
    staged = None
    try:
        staged = windows_runtime.stage_pinned_runtime(
            source.resolve(),
            profile=profile,
            staging_parent=tmp_path.resolve(),
        )
    except windows_runtime.WindowsRuntimeError:
        assert replaced
    else:
        assert not replaced
    finally:
        if staged is not None:
            staged.close()
    assert attempted


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle sharing boundary")
@pytest.mark.parametrize(
    "relative",
    (
        "mingw64/bin/preloaded-sidecar.dll",
        "mingw64/libexec/git-core/extra-helper.exe",
    ),
)
def test_unreviewed_runtime_sidecar_or_helper_addition_fails(
    tmp_path: Path,
    relative: str,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_runtime_profile(source)
    extra = source / Path(*relative.split("/"))
    extra.write_bytes(b"unreviewed")
    with pytest.raises(windows_runtime.WindowsRuntimeError, match="file set changed"):
        windows_runtime.stage_pinned_runtime(
            source.resolve(),
            profile=profile,
            staging_parent=tmp_path.resolve(),
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle sharing boundary")
def test_source_copy_race_is_denied_by_retained_no_write_delete_handles(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_runtime_profile(source)
    victim = source / "cmd" / "git.exe"
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"reviewed-git-image")
    original = windows_runtime._copy_from_handle
    attempted = False

    def _race(handle, destination, record):
        nonlocal attempted
        if not attempted:
            attempted = True
            with pytest.raises(OSError):
                victim.write_bytes(b"untrusted-git-img!")
            with pytest.raises(OSError):
                os.replace(replacement, victim)
        return original(handle, destination, record)

    monkeypatch.setattr(windows_runtime, "_copy_from_handle", _race)
    staged = windows_runtime.stage_pinned_runtime(
        source.resolve(),
        profile=profile,
        staging_parent=tmp_path.resolve(),
    )
    root = staged.root
    try:
        assert attempted
        assert (root / "cmd" / "git.exe").read_bytes() == b"reviewed-git-image"
    finally:
        staged.close()
    assert not root.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL boundary")
def test_private_stage_acl_seals_files_and_handle_cleanup_is_exact(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    profile = _fixture_runtime_profile(source)
    staging_parent = tmp_path / "staging parent & metachar"
    staging_parent.mkdir()
    staged = windows_runtime.stage_pinned_runtime(
        source.resolve(),
        profile=profile,
        staging_parent=staging_parent.resolve(),
    )
    root = staged.root
    windows_runtime._assert_private_directory_acl(
        root,
        windows_runtime._current_user_sid(),
    )
    with pytest.raises(OSError):
        (root / "cmd" / "git.exe").write_bytes(b"replacement")
    with pytest.raises(OSError):
        (root / "mingw64" / "bin" / "unreviewed.dll").write_bytes(b"addition")
    staged.close()
    assert not root.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Git for Windows shell quoting")
def test_absolute_gcm_helper_quotes_whitespace_metacharacters_and_apostrophe() -> None:
    helper = Path(r"C:\Program Files\Git & Reviewer's Build\gcm.exe")
    quoted = transport._shell_quote_helper(helper)
    assert quoted == "!'C:/Program Files/Git & Reviewer'\\''s Build/gcm.exe'"
    # Git's documented ! form prevents the safely quoted path from being
    # rewritten as `git credential-<path>`.  Its shell still receives exactly
    # one executable token plus Git's bounded operation argument.
    assert shlex.split(quoted[1:] + " get", posix=True) == [
        helper.as_posix(),
        "get",
    ]
    assert transport._configuration_arguments(credential_helper=helper).count(
        f"credential.helper={quoted}"
    ) == 1
    assert transport._configuration_arguments(credential_helper=helper).count(
        f"credential.https://github.com.helper={quoted}"
    ) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Git for Windows helper parser")
def test_absolute_gcm_helper_reaches_git_shell_without_credential_prefix(
    tmp_path: Path,
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git for Windows is unavailable")

    helper = (tmp_path / "Review & Reviewer's missing helper.exe").resolve()
    assert not helper.exists()
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper()
        in {
            "COMSPEC",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "WINDIR",
        }
    }
    environment.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "LANG": "C",
        "LC_ALL": "C",
    })
    result = subprocess.run(
        [
            git,
            "--no-pager",
            *transport._configuration_arguments(credential_helper=helper),
            "credential",
            "reject",
        ],
        input="protocol=https\nhost=github.invalid\n\n",
        capture_output=True,
        text=True,
        check=False,
        env=environment,
        timeout=15,
    )

    error = result.stderr.replace("\\", "/")
    assert result.returncode == 0
    assert "credential-C:/" not in error
    assert helper.as_posix() in error
    assert " erase:" in error
