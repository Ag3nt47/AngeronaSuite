from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from angerona.core.file_lease import ExclusiveFileLease
from angerona.updater import github_updater as updates

BASE = "a" * 40
TARGET = "b" * 40


def metadata(path: str) -> dict:
    if path == "branches/main":
        return {"name": "main", "commit": {"sha": TARGET}, "html_url": "https://attacker.invalid/main"}
    return {"tag_name": "v1.15.0", "draft": False, "prerelease": False,
            "html_url": "file:///malicious.exe"}


@pytest.mark.parametrize("value", ["v1.14.0rc1", "1.14", "1.14.0.1", "V1.14.0", "1.014.0", "1.14.-1", "v" + "9" * 1000 + ".1.1", 114])
def test_release_versions_reject_permissive_digit_parsing(value) -> None:
    with pytest.raises(ValueError):
        updates.version_tuple(value)


def test_metadata_links_are_generated_from_strict_validated_identity() -> None:
    report = updates.discover_updates(local_revision=BASE, version="1.14.0", fetch=metadata, now=10)
    assert report.available and report.release_status == "newer" and report.source_status == "different"
    assert report.source_url == f"https://github.com/Ag3nt47/AngeronaSuite/commit/{TARGET}"
    assert report.release_url == "https://github.com/Ag3nt47/AngeronaSuite/releases/tag/v1.15.0"
    assert "attacker" not in report.summary() and "file:" not in report.release_url


@pytest.mark.parametrize("bad", [[], None, "text", {"name": "main", "commit": []}, {"name": "main", "commit": {"sha": "b" * 39}}, {"name": "other", "commit": {"sha": TARGET}}])
def test_invalid_branch_data_is_unavailable_not_current(bad) -> None:
    report = updates.discover_updates(fetch=lambda path: bad if path == "branches/main" else metadata(path), now=10)
    assert report.source_status == "unavailable" and report.remote_revision == "" and report.status == "partial"


@pytest.mark.parametrize("bad", [[], None, {"tag_name": "v1.15.0", "draft": 0, "prerelease": False}, {"tag_name": "v1.15.0-evil", "draft": False, "prerelease": False}, {"tag_name": "v9.0.0", "draft": True, "prerelease": False}])
def test_invalid_release_data_cannot_offer_a_release(bad) -> None:
    report = updates.discover_updates(fetch=lambda path: metadata(path) if path == "branches/main" else bad, now=10)
    assert report.release_status == "unavailable" and report.release_url == ""


def test_unknown_install_revision_never_claims_source_up_to_date() -> None:
    report = updates.discover_updates(fetch=metadata, now=10)
    assert report.source_status == "unknown" and "cannot be established" in report.summary()


def test_duplicate_and_oversized_json_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        updates._json(b'{"tag_name":"v1.15.0","tag_name":"v9.0.0"}', 1024)
    with pytest.raises(ValueError, match="byte"):
        updates._json(b" " * 1025, 1024)
    with pytest.raises(ValueError, match="object"):
        updates._json(b"[]", 1024)


def test_daily_attempt_is_durable_before_network_and_failures_do_not_storm(tmp_path: Path) -> None:
    calls = []

    def offline(path):
        state = json.loads((tmp_path / "check.json").read_bytes())
        assert state["last_attempt"] == 100 and state["outcome"] == "checking"
        calls.append(path)
        raise OSError("private network diagnostic must not be copied into the report")

    first = updates.daily_update_check(tmp_path, now=100, fetch=offline)
    second = updates.daily_update_check(tmp_path, now=101, fetch=offline)
    assert first.status == "partial" and len(calls) == 2
    assert second.status == "not_due" and "private network" not in first.summary()
    assert updates.daily_update_check(tmp_path, force=True, now=159, fetch=offline).status == "not_due"
    called = []
    manual = updates.daily_update_check(tmp_path, force=True, now=160, fetch=lambda path: called.append(path) or metadata(path))
    assert manual.status == "checked" and len(called) == 2


def test_daily_interval_and_clock_rollback_are_explicit(tmp_path: Path) -> None:
    updates.daily_update_check(tmp_path, now=100, fetch=metadata)
    assert updates.daily_update_check(tmp_path, now=99, fetch=metadata).status == "clock_rollback"
    assert updates.daily_update_check(tmp_path, now=100 + updates.DAILY_SECONDS - 1, fetch=metadata).status == "not_due"
    assert updates.daily_update_check(tmp_path, now=100 + updates.DAILY_SECONDS, fetch=metadata).status == "checked"


def test_an_existing_process_lease_prevents_duplicate_requests(tmp_path: Path) -> None:
    with ExclusiveFileLease(tmp_path / "check.lock"):
        report = updates.daily_update_check(tmp_path, now=10, fetch=lambda path: pytest.fail("duplicate network request"))
    assert report.status == "busy"
    assert not (tmp_path / "check.json").exists()


def test_corrupt_state_is_visible_and_does_not_trigger_network(tmp_path: Path) -> None:
    (tmp_path / "check.json").write_bytes(b'{"schema":"wrong"}')
    report = updates.daily_update_check(tmp_path, force=True, now=10, fetch=lambda path: pytest.fail("corrupt state must fail closed"))
    assert report.status == "failed" and "unknown" in report.summary()


def test_no_published_release_is_distinct_from_no_updates() -> None:
    def fetch(path):
        if path == "releases/latest":
            raise urllib.error.HTTPError("https://api.github.com/", 404, "not found", {}, None)
        return metadata(path)

    report = updates.discover_updates(local_revision=TARGET, now=10, fetch=fetch)
    assert report.release_status == "none" and report.source_status == "same"
    assert "No published stable" in report.summary()


def test_compatibility_entrypoint_never_contacts_arbitrary_repository(monkeypatch) -> None:
    monkeypatch.setattr(updates, "discover_updates", lambda **kwargs: pytest.fail("unexpected request"))
    assert "failed" in updates.check_for_updates("attacker/Angerona")
