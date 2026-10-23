from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from angerona.updater import release_update as updates

ARCHIVE = b"inert test bytes: never extracted or executed"
NAME = "Angerona-v1.15.0-win64.zip"
CHECKSUM = hashlib.sha256(ARCHIVE).hexdigest().encode() + b"  " + NAME.encode() + b"\n"


def metadata() -> dict:
    return {
        "id": 15,
        "tag_name": "v1.15.0",
        "published_at": "2026-10-23T00:00:00Z",
        "draft": False,
        "prerelease": False,
        "html_url": "file:///not-authority",
        "zipball_url": "https://attacker.invalid/source.zip",
        "assets": [
            {
                "id": 151,
                "name": NAME,
                "size": len(ARCHIVE),
                "digest": "sha256:" + hashlib.sha256(ARCHIVE).hexdigest(),
                "browser_download_url": "https://attacker.invalid/do-not-use",
            },
            {
                "id": 152,
                "name": NAME + ".sha256",
                "size": len(CHECKSUM),
                "digest": "sha256:" + hashlib.sha256(CHECKSUM).hexdigest(),
            },
        ],
    }


def candidate() -> updates.ReleaseCandidate:
    return updates.select_release(metadata(), version="1.14.0")


def transport(url, target, expected, maximum, seconds):
    assert url.startswith("https://github.com/Ag3nt47/AngeronaSuite/releases/download/v1.15.0/")
    assert 0 < seconds <= updates.DOWNLOAD_SECONDS
    data = CHECKSUM if url.endswith(".sha256") else ARCHIVE
    assert len(data) == expected <= maximum
    target.write_bytes(data)


def staged(tmp_path, *, action="install"):
    selected = candidate()
    approval = updates.approve_release(selected, action=action, accepted=True)
    downloaded = updates.download_release(
        selected, approval, tmp_path / "stages", fetch=lambda _: metadata(), transport=transport
    )
    return downloaded, approval


def test_only_fixed_canonical_signed_asset_urls_and_identity_are_used():
    selected = candidate()
    assert (
        selected.url(selected.archive)
        == "https://github.com/Ag3nt47/AngeronaSuite/releases/download/v1.15.0/" + NAME
    )
    assert "attacker" not in str(selected) and "file:" not in str(selected)
    assert len(selected.identity) == 64
    assert (
        selected.identity != replace(selected, archive=replace(selected.archive, id=999)).identity
    )


@pytest.mark.parametrize(
    "tag", ["1.15.0", "v1.015.0", "v1.15.0-rc1", "v1.15.0/evil", "V1.15.0", "v1.14.0", "v0.1.0"]
)
def test_noncanonical_prerelease_or_nonnewer_tags_are_held(tag):
    document = metadata()
    document["tag_name"] = tag
    with pytest.raises(updates.ReleaseUpdateError):
        updates.select_release(document)


@pytest.mark.parametrize(
    "change",
    [
        "draft",
        "prerelease",
        "unsigned",
        "checksum_missing",
        "duplicate",
        "too_big",
        "bool_id",
        "digest",
        "zero_size",
        "release_id",
    ],
)
def test_incomplete_unsigned_and_malformed_assets_are_held(change):
    document = metadata()
    if change in {"draft", "prerelease"}:
        document[change] = True
    elif change == "unsigned":
        document["assets"][0]["name"] = "Angerona-v1.15.0-win64-unsigned.zip"
    elif change == "checksum_missing":
        document["assets"].pop()
    elif change == "duplicate":
        document["assets"].append(copy.deepcopy(document["assets"][0]))
    elif change == "too_big":
        document["assets"][0]["size"] = updates.MAX_ARCHIVE_BYTES + 1
    elif change == "bool_id":
        document["assets"][0]["id"] = True
    elif change == "digest":
        document["assets"][0]["digest"] = "md5:" + "0" * 32
    elif change == "zero_size":
        document["assets"][0]["size"] = 0
    else:
        document["id"] = True
    with pytest.raises(updates.ReleaseUpdateError):
        updates.select_release(document)


def test_decline_or_stale_approval_never_requests_payload_or_metadata(tmp_path):
    selected = candidate()
    no_request = lambda *args, **kwargs: pytest.fail("Consent must precede every download request")
    for approval in [
        None,
        updates.approve_release(selected, action="download", accepted=False),
        updates.ReleaseApproval("0" * 64, "install"),
    ]:
        with pytest.raises(updates.ReleaseUpdateError, match="Explicit approval"):
            updates.download_release(
                selected, approval, tmp_path, fetch=no_request, transport=no_request
            )
    assert not list(tmp_path.iterdir())


def test_changed_metadata_requires_fresh_review_before_payload(tmp_path):
    selected = candidate()
    changed = metadata()
    changed["assets"][0]["id"] += 1
    with pytest.raises(updates.ReleaseUpdateError, match="changed after review"):
        updates.download_release(
            selected,
            updates.approve_release(selected, action="install", accepted=True),
            tmp_path,
            fetch=lambda _: changed,
            transport=lambda *args: pytest.fail("No payload allowed"),
        )
    assert not list(tmp_path.iterdir())


def test_atomic_private_download_retains_original_zip_and_transport_only_receipt(tmp_path):
    download, _ = staged(tmp_path)
    assert download.archive.read_bytes() == ARCHIVE
    assert (download.directory / (NAME + ".sha256")).read_bytes() == CHECKSUM
    assert download.directory.name.startswith("release-")
    assert len(list((tmp_path / "stages").iterdir())) == 1
    receipt = json.loads((download.directory / "receipt.json").read_bytes())
    assert receipt["candidate_identity"] == download.candidate.identity
    assert "unverified" in receipt["install_trust"]


@pytest.mark.parametrize(
    "fault",
    ["network", "oversize", "truncated", "bad_checksum", "wrong_filename", "metadata_digest"],
)
def test_failed_download_removes_only_its_owned_stage(tmp_path, fault):
    retained = tmp_path / "stages" / "previous-reviewed-download"
    retained.mkdir(parents=True)
    (retained / "keep").write_text("preserve")

    def broken(url, target, expected, maximum, seconds):
        if url.endswith(".sha256"):
            if fault == "bad_checksum":
                target.write_bytes(b"0" * 64 + CHECKSUM[64:])
            elif fault == "wrong_filename":
                target.write_bytes(CHECKSUM.replace(NAME.encode(), b"X" * len(NAME)))
            else:
                target.write_bytes(CHECKSUM)
            return
        if fault == "network":
            target.write_bytes(b"partial")
            raise OSError("inert test network outage")
        target.write_bytes(
            ARCHIVE + b"x"
            if fault == "oversize"
            else ARCHIVE[:-1]
            if fault == "truncated"
            else b"x" * len(ARCHIVE)
            if fault == "metadata_digest"
            else ARCHIVE
        )

    selected = candidate()
    with pytest.raises((updates.ReleaseUpdateError, OSError)):
        updates.download_release(
            selected,
            updates.approve_release(selected, action="download", accepted=True),
            tmp_path / "stages",
            fetch=lambda _: metadata(),
            transport=broken,
        )
    assert list((tmp_path / "stages").iterdir()) == [retained]
    assert (retained / "keep").read_text() == "preserve"


def test_same_day_startup_reuses_shared_attempt_and_candidate_cache(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(updates.discovery, "local_source_revision", lambda _: "a" * 40)

    def fetch(path):
        calls.append(path)
        return (
            {"name": "main", "commit": {"sha": "b" * 40}} if path == "branches/main" else metadata()
        )

    first = updates.check_release_updates(tmp_path, tmp_path, fetch=fetch, now=100)
    second = updates.check_release_updates(tmp_path, tmp_path, fetch=fetch, now=101)
    manual_held = updates.check_release_updates(
        tmp_path, tmp_path, force=True, fetch=fetch, now=159
    )
    assert first.candidate == second.candidate == manual_held.candidate
    assert second.cached and manual_held.cached and len(calls) == 2
    updates.check_release_updates(tmp_path, tmp_path, force=True, fetch=fetch, now=160)
    assert len(calls) == 4
    updates.check_release_updates(tmp_path, tmp_path, fetch=fetch, now=160 + 86400)
    assert len(calls) == 6


def test_outage_is_cached_without_up_to_date_claim_or_retry_storm(tmp_path, monkeypatch):
    monkeypatch.setattr(updates.discovery, "local_source_revision", lambda _: "")
    calls = []

    def offline(path):
        calls.append(path)
        raise OSError("do not publish private details")

    first = updates.check_release_updates(tmp_path, tmp_path, fetch=offline, now=100)
    second = updates.check_release_updates(tmp_path, tmp_path, fetch=offline, now=101)
    assert len(calls) == 2 and first.report.status == second.report.status == "partial"
    assert second.cached and second.candidate is None
    assert "private details" not in second.report.summary()


def test_ui_shared_attempt_without_asset_cache_holds_download_without_network(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(updates.discovery, "local_source_revision", lambda _: "")
    fetch = lambda path: (
        {"name": "main", "commit": {"sha": "b" * 40}} if path == "branches/main" else metadata()
    )
    updates.discovery.daily_update_check(tmp_path, now=100, fetch=fetch)
    result = updates.check_release_updates(
        tmp_path, tmp_path, now=101, fetch=lambda _: pytest.fail("No repeat request")
    )
    assert result.cached and result.candidate is None and "No release-asset cache" in result.hold


def test_clock_rollback_and_corrupt_cache_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(updates.discovery, "local_source_revision", lambda _: "")
    fetch = lambda path: (
        {"name": "main", "commit": {"sha": "b" * 40}} if path == "branches/main" else metadata()
    )
    updates.check_release_updates(tmp_path, tmp_path, now=100, fetch=fetch)
    assert (
        updates.check_release_updates(tmp_path, tmp_path, now=99, fetch=fetch).report.status
        == "clock_rollback"
    )
    (tmp_path / "release-check.json").write_text('{"schema":"wrong"}')
    assert (
        updates.check_release_updates(
            tmp_path, tmp_path, now=101, fetch=lambda _: pytest.fail("No repeat request")
        ).report.status
        == "failed"
    )


def installed_fixture(tmp_path):
    root = tmp_path / "Program Files" / "Angerona"
    root.mkdir(parents=True)
    (root / "Install-Angerona-Release.ps1").write_text(
        "inert protected installer fixture; never execute"
    )
    (root / "release-authorization.json").write_text(
        json.dumps(
            {
                "statement": {
                    "schema": "angerona.release-authorization/v2",
                    "product": "Angerona",
                    "version": "1.14.0",
                }
            }
        )
    )
    powershell = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    powershell.write_bytes(b"inert executable fixture; never execute")
    return root, powershell


def test_missing_protected_installer_requires_signed_msix(tmp_path):
    download, approval = staged(tmp_path)
    with pytest.raises(updates.ReleaseUpdateError, match="signed Angerona MSIX"):
        updates.install_download(
            download,
            approval,
            paths=lambda: (tmp_path / "missing", tmp_path / "missingPS"),
            processes=lambda _: pytest.fail("No process query"),
            execute=lambda *a, **k: pytest.fail("No execution"),
        )


def test_download_approval_cannot_authorize_install(tmp_path):
    download, approval = staged(tmp_path, action="download")
    with pytest.raises(updates.ReleaseUpdateError, match="Explicit approval"):
        updates.install_download(
            download, approval, paths=lambda: pytest.fail("Consent before machine inspection")
        )


@pytest.mark.parametrize(
    "boundary", ["custody", "preflight", "running", "coverage", "install_failure", "tampered"]
)
def test_install_holds_without_privileged_launch_on_failed_preconditions(tmp_path, boundary):
    download, approval = staged(tmp_path)
    root, powershell = installed_fixture(tmp_path)
    calls = []

    def execute(ps, script, archive, *, preflight):
        assert (
            ps == powershell
            and script == root / "Install-Angerona-Release.ps1"
            and archive == download.archive
        )
        calls.append(preflight)
        return (
            1
            if boundary == "preflight"
            and preflight
            or boundary == "install_failure"
            and not preflight
            else 0
        )

    def processes(_):
        if boundary == "coverage":
            raise updates.ReleaseUpdateError("coverage denied")
        return (
            [updates.ProcessEvidence(123, str(root / "Angerona.exe"), 1000.25)]
            if boundary == "running"
            else []
        )

    if boundary == "tampered":
        download.archive.write_bytes(b"x" * len(ARCHIVE))
    with pytest.raises(updates.ReleaseUpdateError) as error:
        updates.install_download(
            download,
            approval,
            paths=lambda: (root, powershell),
            custody=lambda *_: boundary != "custody",
            processes=processes,
            execute=execute,
        )
    assert calls == (
        []
        if boundary in {"custody", "tampered"}
        else [True, False]
        if boundary == "install_failure"
        else [True]
    )
    if boundary == "running":
        assert "PID 123" in str(error.value) and "created 1000.250000" in str(error.value)


def test_inert_installer_delegation_preserves_verification_and_reports_health_unknown(tmp_path):
    download, approval = staged(tmp_path)
    root, powershell = installed_fixture(tmp_path)
    calls = []

    def execute(ps, script, archive, *, preflight):
        calls.append((ps, script, archive, preflight))
        return 0

    result = updates.install_download(
        download,
        approval,
        paths=lambda: (root, powershell),
        custody=lambda *_: True,
        processes=lambda _: [],
        execute=execute,
    )
    assert [row[-1] for row in calls] == [True, False]
    assert all(row[1] == root / "Install-Angerona-Release.ps1" for row in calls)
    assert result["status"] == "restart_requested" and result["runtime_health"] == "unverified"
    assert "observed" in result["message"]


def test_install_rechecks_actual_protected_version_before_preflight(tmp_path):
    download, approval = staged(tmp_path)
    root, powershell = installed_fixture(tmp_path)
    document = root / "release-authorization.json"
    document.write_text(
        json.dumps(
            {
                "statement": {
                    "schema": "angerona.release-authorization/v2",
                    "product": "Angerona",
                    "version": "1.15.0",
                }
            }
        )
    )
    with pytest.raises(updates.ReleaseUpdateError, match="no longer newer"):
        updates.install_download(
            download,
            approval,
            paths=lambda: (root, powershell),
            custody=lambda *_: True,
            processes=lambda _: pytest.fail("No process query"),
            execute=lambda *a, **k: pytest.fail("No installer execution"),
        )


def test_process_selection_uses_exact_paths_and_pid_creation_identity(tmp_path, monkeypatch):
    import psutil

    class InertProcess:
        def __init__(self, pid, path):
            self.pid, self.path = pid, path

        def exe(self):
            return self.path

        def name(self):
            return "Angerona.exe"

        def create_time(self):
            return 1234.5

    root = tmp_path / "installed"
    monkeypatch.setattr(
        psutil,
        "process_iter",
        lambda: [
            InertProcess(1, str(root / "Angerona.exe")),
            InertProcess(2, str(tmp_path / "Angerona.exe")),
        ],
    )
    assert updates.installed_processes(root) == [
        updates.ProcessEvidence(1, str(root / "Angerona.exe"), 1234.5)
    ]


def test_preflight_and_uac_bridge_use_sanitized_environment_and_quote_paths(monkeypatch, tmp_path):
    from angerona.core import privilege

    monkeypatch.setattr(
        privilege, "sanitized_child_environment", lambda **kwargs: {"SAFE": "environment"}
    )
    calls = []

    def inert_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(updates.subprocess, "run", inert_run)
    powershell = tmp_path / "system" / "powershell.exe"
    installer = tmp_path / "Program Files" / "Angerona's" / "Install-Angerona-Release.ps1"
    archive = tmp_path / "operator's downloads" / NAME
    assert updates._powershell_execute(powershell, installer, archive, preflight=True) == 0
    assert updates._powershell_execute(powershell, installer, archive, preflight=False) == 0
    assert calls[0][0][-1] == "-CustodyPreflightOnly" and "-ReleaseArchive" not in calls[0][0]
    script = base64.b64decode(calls[1][0][-1]).decode("utf-16-le")
    assert "-Verb RunAs" in script and "-WindowStyle Hidden" in script
    assert "Angerona''s" in script and "operator''s downloads" in script
    assert all(
        item[1]["env"]
        == {"SAFE": "environment", "PSModulePath": str(powershell.parent / "Modules")}
        for item in calls
    )


def test_installed_frozen_watchdog_holds_by_exact_path_pid_and_birth(tmp_path, monkeypatch):
    import psutil

    root = tmp_path / "installed"

    class Watchdog:
        def __init__(self, pid, path):
            self.pid, self.path = pid, path

        def name(self):
            return "frz_watchdog_v2.exe"

        def exe(self):
            return str(self.path)

        def create_time(self):
            return 1234.5

    monkeypatch.setattr(
        psutil,
        "process_iter",
        lambda: [
            Watchdog(12, root / "frz_watchdog_v2.exe"),
            Watchdog(13, tmp_path / "frz_watchdog_v2.exe"),
        ],
    )
    assert updates.installed_processes(root) == [
        updates.ProcessEvidence(12, str(root / "frz_watchdog_v2.exe"), 1234.5)
    ]


def test_denied_unrelated_process_executable_does_not_block_but_denied_candidate_holds(
    tmp_path, monkeypatch
):
    import psutil

    class DeniedProcess:
        pid = 123

        def __init__(self, name):
            self.label = name

        def name(self):
            return self.label

        def exe(self):
            raise psutil.AccessDenied(self.pid)

    monkeypatch.setattr(
        psutil, "process_iter", lambda: [DeniedProcess("unrelated-system-service.exe")]
    )
    assert updates.installed_processes(tmp_path) == []
    monkeypatch.setattr(psutil, "process_iter", lambda: [DeniedProcess("Angerona.exe")])
    with pytest.raises(updates.ReleaseUpdateError, match="identity coverage is denied"):
        updates.installed_processes(tmp_path)


def test_pending_unknown_install_receipt_blocks_other_stage_retry(tmp_path):
    download, approval = staged(tmp_path)
    root, powershell = installed_fixture(tmp_path)

    def unknown_execute(*args, preflight):
        if not preflight:
            receipt = json.loads((download.directory.parent / "install-state.json").read_bytes())
            assert (
                receipt["status"] == "pending"
                and receipt["candidate_identity"] == download.candidate.identity
            )
            raise TimeoutError("inert ambiguous installer")
        return 0

    with pytest.raises(TimeoutError):
        updates.install_download(
            download,
            approval,
            paths=lambda: (root, powershell),
            custody=lambda *_: True,
            processes=lambda _: [],
            execute=unknown_execute,
        )
    receipt = json.loads((download.directory.parent / "install-state.json").read_bytes())
    assert receipt["status"] == "unknown"
    other, other_approval = staged(tmp_path)
    with pytest.raises(updates.ReleaseUpdateError, match="operator recovery review"):
        updates.install_download(
            other, other_approval, paths=lambda: pytest.fail("No new machine inspection or launch")
        )


@pytest.mark.parametrize("previous_status", ["pending", "unknown", "recovery_required", "failed"])
def test_all_ambiguous_install_receipts_hold_retry_including_legacy_failed(
    tmp_path, previous_status
):
    download, approval = staged(tmp_path)
    state = {
        "schema": "angerona.release-install/v1",
        "repository": "Ag3nt47/AngeronaSuite",
        "status": previous_status,
    }
    (download.directory.parent / "install-state.json").write_text(json.dumps(state))
    with pytest.raises(updates.ReleaseUpdateError, match="operator recovery review"):
        updates.install_download(
            download,
            approval,
            paths=lambda: pytest.fail(
                "No machine inspection or installer launch on ambiguous retry"
            ),
        )


def test_nonzero_attempt_preserves_recovery_required_receipt_and_blocks_other_stage(tmp_path):
    download, approval = staged(tmp_path)
    root, powershell = installed_fixture(tmp_path)
    calls = []

    def partial_failure(*args, preflight):
        calls.append(preflight)
        return 0 if preflight else 1

    with pytest.raises(updates.ReleaseUpdateError, match="destination mutation is unknown"):
        updates.install_download(
            download,
            approval,
            paths=lambda: (root, powershell),
            custody=lambda *_: True,
            processes=lambda _: [],
            execute=partial_failure,
        )
    receipt_path = download.directory.parent / "install-state.json"
    receipt = json.loads(receipt_path.read_bytes())
    assert calls == [True, False] and receipt["status"] == "recovery_required"
    other, other_approval = staged(tmp_path)
    with pytest.raises(updates.ReleaseUpdateError, match="operator recovery review"):
        updates.install_download(
            other,
            other_approval,
            paths=lambda: pytest.fail("Partial mutation cannot authorize a new attempt"),
        )
    assert json.loads(receipt_path.read_bytes()) == receipt


def test_fixed_release_parent_lease_serializes_different_stages(tmp_path):
    from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError

    download, approval = staged(tmp_path)
    with ExclusiveFileLease(download.directory.parent / "install.lock"):
        with pytest.raises(ExclusiveFileLeaseError):
            updates.install_download(
                download, approval, paths=lambda: pytest.fail("No concurrent authority query")
            )


def test_protected_installed_version_metadata_is_bounded_and_never_grants_trust(tmp_path):
    root, powershell = installed_fixture(tmp_path)
    document = root / "release-authorization.json"
    document.write_text(
        json.dumps(
            {
                "statement": {
                    "schema": "angerona.release-authorization/v2",
                    "product": "Angerona",
                    "version": "1.13.0",
                }
            }
        )
    )
    assert (
        updates.installed_release_version(paths=lambda: (root, powershell), custody=lambda *_: True)
        == "1.13.0"
    )
    with pytest.raises(updates.ReleaseUpdateError, match="custody"):
        updates.installed_release_version(
            paths=lambda: (root, powershell), custody=lambda *_: False
        )
    document.write_bytes(b"x" * (256 * 1024 + 1))
    with pytest.raises(updates.ReleaseUpdateError, match="bounded"):
        updates.installed_release_version(paths=lambda: (root, powershell), custody=lambda *_: True)


@pytest.mark.parametrize("missing_digest", ["absent", None, ""])
def test_archive_metadata_sha256_is_required_before_approval_offer(missing_digest):
    document = metadata()
    if missing_digest == "absent":
        document["assets"][0].pop("digest")
    else:
        document["assets"][0]["digest"] = missing_digest
    with pytest.raises(updates.ReleaseUpdateError, match="SHA256 metadata digest is required"):
        updates.select_release(document)


def test_reviewed_archive_digest_rejects_equal_size_replacement_with_matching_checksum(tmp_path):
    document = metadata()
    document["assets"][1]["digest"] = None
    selected = updates.select_release(document)
    replaced_archive = b"x" * len(ARCHIVE)
    replaced_checksum = (
        hashlib.sha256(replaced_archive).hexdigest().encode() + b"  " + NAME.encode() + b"\n"
    )
    assert len(replaced_checksum) == len(CHECKSUM)

    def replaced(url, target, expected, maximum, seconds):
        target.write_bytes(replaced_checksum if url.endswith(".sha256") else replaced_archive)

    with pytest.raises(updates.ReleaseUpdateError, match="approved GitHub metadata digest"):
        updates.download_release(
            selected,
            updates.approve_release(selected, action="download", accepted=True),
            tmp_path,
            fetch=lambda _: document,
            transport=replaced,
        )
    assert not list(tmp_path.iterdir())


def test_absent_checksum_digest_still_requires_exact_checksum_filename(tmp_path):
    document = metadata()
    document["assets"][1]["digest"] = None
    selected = updates.select_release(document)

    def wrong_name(url, target, *args):
        target.write_bytes(
            CHECKSUM.replace(NAME.encode(), b"X" * len(NAME))
            if url.endswith(".sha256")
            else ARCHIVE
        )

    with pytest.raises(updates.ReleaseUpdateError, match="exact approved ZIP"):
        updates.download_release(
            selected,
            updates.approve_release(selected, action="download", accepted=True),
            tmp_path,
            fetch=lambda _: document,
            transport=wrong_name,
        )


@pytest.mark.parametrize("fault", ["none", "oversize", "truncated", "declared_size", "status"])
def test_inert_download_worker_checks_response_framing_without_network(
    tmp_path, monkeypatch, fault
):
    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Length": str(len(ARCHIVE))}

    class Pipe:
        result = "not completed"

        def send(self, result):
            self.result = result

        def close(self):
            pass

    response = Response(
        ARCHIVE + b"extra"
        if fault == "oversize"
        else ARCHIVE[:-1]
        if fault == "truncated"
        else ARCHIVE
    )
    if fault == "declared_size":
        response.headers = {"Content-Length": str(len(ARCHIVE) + 1)}
    if fault == "status":
        response.status = 302

    def inert_open(request, *, policy, timeout):
        assert request.full_url == candidate().url(candidate().archive)
        assert policy.allowed_hosts == frozenset(
            {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
        )
        assert "HTTPS_PROXY" not in updates.os.environ and timeout <= 20
        return response

    monkeypatch.setattr(
        updates.os, "environ", {"HTTPS_PROXY": "http://untrusted.invalid", "SAFE": "inert"}
    )
    monkeypatch.setattr(updates, "safe_urlopen", inert_open)
    pipe = Pipe()
    target = tmp_path / "original.zip"
    updates._fetch_worker(
        candidate().url(candidate().archive), str(target), len(ARCHIVE), 1024, 60, pipe
    )
    assert pipe.result is None if fault == "none" else pipe.result == "ReleaseUpdateError"
    if fault == "none":
        assert target.read_bytes() == ARCHIVE


def test_network_deadline_retires_only_owned_worker_with_no_network(tmp_path, monkeypatch):
    events = []

    class Pipe:
        def close(self):
            events.append("pipe_closed")

        def poll(self, seconds):
            assert seconds == 0.1
            return False

    class Worker:
        pid = None
        alive = False

        def start(self):
            self.pid, self.alive = 123, True
            events.append("started_owned")

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False
            events.append("terminated_owned")

        def join(self, seconds):
            events.append("joined_owned")

        def close(self):
            events.append("handle_closed")

    worker = Worker()

    class Context:
        def Pipe(self, **kwargs):
            return Pipe(), Pipe()

        def Process(self, **kwargs):
            assert kwargs["target"] is updates._fetch_worker
            return worker

    monkeypatch.setattr(updates.multiprocessing, "get_context", lambda mode: Context())
    with pytest.raises(updates.ReleaseUpdateError, match="total deadline"):
        updates.fetch_release_file(
            candidate().url(candidate().archive), tmp_path / "not_created", len(ARCHIVE), 1024, 0.1
        )
    assert "terminated_owned" in events and events[-1] == "handle_closed" and not worker.is_alive()


def test_unretired_network_worker_keeps_private_stage_for_explicit_review(tmp_path):
    selected = candidate()

    def unretired(*args):
        raise updates.DownloadRetirementError("inert child did not retire")

    with pytest.raises(updates.DownloadRetirementError):
        updates.download_release(
            selected,
            updates.approve_release(selected, action="download", accepted=True),
            tmp_path,
            fetch=lambda _: metadata(),
            transport=unretired,
        )
    retained = list(tmp_path.iterdir())
    assert len(retained) == 1 and retained[0].name.startswith(".downloading-")


def load_cli():
    path = Path(__file__).resolve().parents[1] / "tools" / "update_angerona.py"
    spec = importlib.util.spec_from_file_location("inert_update_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "interactive,answer,arguments",
    [
        (False, "yes", ["--install"]),
        (True, "no", []),
        (True, "yes", ["--check-only"]),
        (True, "yes", ["--json"]),
    ],
)
def test_cli_no_payload_for_decline_or_noninteractive_or_check_only(
    tmp_path, monkeypatch, interactive, answer, arguments
):
    from angerona.core import data_paths

    selected = candidate()
    check = updates.ReleaseCheck(
        updates.discovery.UpdateReport(
            "checked", 100, "1.14.0", release_tag=selected.tag, release_status="newer"
        ),
        selected,
    )
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(data_paths, "project_root", lambda: tmp_path)
    monkeypatch.setattr(updates, "check_release_updates", lambda *a, **k: check)
    monkeypatch.setattr(updates, "installed_release_version", lambda: "1.14.0")
    monkeypatch.setattr(
        updates,
        "download_release",
        lambda *a, **k: pytest.fail("No payload without eligible explicit consent"),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO())
    monkeypatch.setattr("sys.stdin.isatty", lambda: interactive)
    monkeypatch.setattr("builtins.input", lambda _: answer)
    assert load_cli().main(arguments) == 0


def test_cli_explicit_comparison_version_is_bound_through_approved_download(tmp_path, monkeypatch):
    from angerona.core import data_paths

    selected = candidate()
    check = updates.ReleaseCheck(
        updates.discovery.UpdateReport(
            "checked", 100, "1.13.0", release_tag=selected.tag, release_status="newer"
        ),
        selected,
    )
    calls = []
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(data_paths, "project_root", lambda: tmp_path)

    def checked(*args, version, **kwargs):
        calls.append(("check", version))
        return check

    def downloaded(candidate, approval, path, *, version):
        assert approval.action == "install" and approval.identity == selected.identity
        calls.append(("download", version))
        return updates.DownloadedRelease(candidate, path / "inert-stage", "0" * 64)

    monkeypatch.setattr(updates, "check_release_updates", checked)
    monkeypatch.setattr(updates, "download_release", downloaded)
    monkeypatch.setattr(
        updates,
        "installed_release_version",
        lambda: pytest.fail("Explicit version avoids ambiguous helper version"),
    )
    monkeypatch.setattr(
        updates,
        "install_download",
        lambda *args: {"message": "inert verified installer delegation"},
    )
    monkeypatch.setattr("sys.stdin", io.StringIO())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert load_cli().main(["--install", "--installed-version", "v1.13.0"]) == 0
    assert calls == [("check", "1.13.0"), ("download", "1.13.0")]
