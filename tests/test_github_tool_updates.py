"""Daily GitHub-tool checks preserve each integration's authority boundary."""
from __future__ import annotations

import json

from angerona.core.curated_tools import ZERO_BREACH, _ASSET
from angerona.updater import github_tool_updates as updates


def _fetch(repository, endpoint):
    spec = next(row for row in updates.TOOL_SPECS if row[2] == repository)
    if endpoint == "releases/latest":
        return {
            "draft": False,
            "prerelease": False,
            "tag_name": "v" + ZERO_BREACH["version"],
            "target_commitish": ZERO_BREACH["commit"],
            "html_url": ZERO_BREACH["release"],
            "assets": [{
                "id": 748681535,
                "name": "zero-breach-toolkit.py",
                "size": ZERO_BREACH["bytes"],
                "digest": "sha256:" + ZERO_BREACH["sha256"],
                "browser_download_url": _ASSET,
            }],
        }
    assert endpoint == "branches/" + spec[3]
    return {"name": spec[3], "commit": {"sha": ZERO_BREACH["commit"] if spec[0] == "zero-breach" else "a" * 40}}


def test_daily_check_prepares_only_exact_reviewed_scanner_and_requests_data_review(tmp_path):
    installed = tmp_path / "community-tools" / "sigma"
    installed.mkdir(parents=True)
    (installed / "installed.json").write_text(json.dumps({"commit": "b" * 40}))
    calls = []

    def prepare(root, *, allow_download):
        calls.append((root, allow_download))
        return {"prepared_state": "ready", "tested_state": "verified", "tested": True,
                "message": "Synthetic metadata verified."}

    report = updates.check_and_apply_github_tools(
        tmp_path, now=123, fetch=_fetch, prepare_zero=prepare,
    )
    by_id = {row["tool_id"]: row for row in report.tools}
    assert report.status == "checked"
    assert calls == [(tmp_path, True)]
    assert by_id["zero-breach"]["state"] == "verified"
    assert by_id["zero-breach"]["tested"] is True
    assert by_id["sigma"]["state"] == "review-requested"
    assert by_id["atomic-red-team"]["state"] == "available"
    assert by_id["caldera"]["state"] == "monitored-external"
    assert report.requests == 1
    record = json.loads((tmp_path / "github-tool-updates" / "latest.json").read_bytes())
    assert record["schema"] == "angerona.github-tool-updates/v1"
    assert len(record["tools"]) == len(updates.TOOL_SPECS) == 8


def test_changed_zero_breach_release_is_recorded_but_never_executed(tmp_path):
    calls = []

    def changed_fetch(repository, endpoint):
        value = _fetch(repository, endpoint)
        if endpoint == "releases/latest":
            value = dict(value, tag_name="v3.0.3")
        return value

    report = updates.check_and_apply_github_tools(
        tmp_path,
        fetch=changed_fetch,
        prepare_zero=lambda *_args, **_kwargs: calls.append(True),
    )
    zero = next(row for row in report.tools if row["tool_id"] == "zero-breach")
    assert zero["state"] == "review-requested"
    assert zero["matches_reviewed_pin"] is False
    assert not calls
    assert report.requests == 1


def test_malformed_one_repository_does_not_hide_other_tool_results(tmp_path):
    def partial_fetch(repository, endpoint):
        if repository == "wazuh/wazuh":
            return {"name": "master", "commit": {"sha": "short"}}
        return _fetch(repository, endpoint)

    report = updates.check_and_apply_github_tools(
        tmp_path, apply_managed=False, fetch=partial_fetch,
    )
    assert report.status == "partial" and report.failures == 1
    assert next(row for row in report.tools if row["tool_id"] == "wazuh")["state"] == "failed"
    assert next(row for row in report.tools if row["tool_id"] == "zero-breach")["state"] == "current"
