"""Daily, cross-platform GitHub discovery for Angerona's maintained tools.

The updater distinguishes three integration contracts:

* the bundled Zero-Breach scanner may be prepared and self-tested only when
  GitHub's stable-release metadata exactly matches Angerona's reviewed pin;
* inert data adapters record a review request for a newer immutable commit;
* external server products are monitored, never silently replaced.

This keeps an upstream repository update from becoming execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import stat
import time
from types import SimpleNamespace
import urllib.parse
import urllib.request

from angerona.core.url_policy import host_policy, read_bounded, safe_urlopen
from angerona.updater.github_updater import version_tuple


MAX_METADATA_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 128 * 1024
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_GITHUB_POLICY = host_policy("maintained GitHub tool API", {"api.github.com"})
_SCHEMA = "angerona.github-tool-updates/v1"

# Branch names are part of the reviewed adapter contract. Discovery never
# follows a repository-supplied URL, archive name, command, or installer.
TOOL_SPECS = (
    ("zero-breach", "Zero-Breach Toolkit", "interplains/Zero-Breach-Toolkit", "main", "managed-scanner"),
    ("atomic-red-team", "Atomic Red Team", "redcanaryco/atomic-red-team", "master", "data"),
    ("sigma", "SigmaHQ rules", "SigmaHQ/sigma", "master", "data"),
    ("sysmon-modular", "Sysmon Modular", "olafhartong/sysmon-modular", "master", "data"),
    ("yara-x", "YARA-X", "VirusTotal/yara-x", "main", "data"),
    ("caldera", "MITRE Caldera", "mitre/caldera", "master", "external"),
    ("velociraptor", "Velociraptor", "Velocidex/velociraptor", "master", "external"),
    ("wazuh", "Wazuh", "wazuh/wazuh", "master", "external"),
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate GitHub metadata key")
        result[key] = value
    return result


def _github_json(repository: str, endpoint: str) -> dict:
    known = {row[2] for row in TOOL_SPECS}
    if repository not in known or not (
        endpoint == "releases/latest" or re.fullmatch(r"branches/[A-Za-z0-9._-]{1,64}", endpoint)
    ):
        raise ValueError("unsupported maintained-tool endpoint")
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    request = urllib.request.Request(
        f"https://api.github.com/repos/{quoted}/{endpoint}",
        headers={
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "User-Agent": "Angerona-GitHub-Tool-Updater/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with safe_urlopen(request, policy=_GITHUB_POLICY, timeout=15) as response:
        raw = read_bounded(response, MAX_METADATA_BYTES)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    if type(value) is not dict:
        raise ValueError("GitHub metadata must be an object")
    return value


def _branch_sha(document: dict, branch: str) -> str:
    commit = document.get("commit") if type(document) is dict else None
    sha = commit.get("sha") if type(commit) is dict else None
    if document.get("name") != branch or type(sha) is not str or not _SHA.fullmatch(sha):
        raise ValueError("invalid branch commit metadata")
    return sha


def _installed_commit(data_root: Path, tool_id: str) -> str:
    path = data_root / "community-tools" / tool_id / "installed.json"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ""
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1 or info.st_size > MAX_RECORD_BYTES
            or getattr(info, "st_file_attributes", 0) & 0x400):
        return ""
    try:
        document = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return ""
    commit = document.get("commit") if type(document) is dict else None
    return commit if type(commit) is str and _SHA.fullmatch(commit) else ""


def _zero_release(document: dict) -> dict:
    from angerona.core.curated_tools import ZERO_BREACH, _ASSET

    if (document.get("draft") is not False or document.get("prerelease") is not False
            or type(document.get("tag_name")) is not str):
        raise ValueError("invalid stable Zero-Breach release metadata")
    tag = document["tag_name"]
    version_tuple(tag)
    assets = document.get("assets")
    if type(assets) is not list or len(assets) > 64:
        raise ValueError("invalid Zero-Breach release asset inventory")
    candidates = [item for item in assets if type(item) is dict and item.get("name") == "zero-breach-toolkit.py"]
    if len(candidates) != 1:
        raise ValueError("Zero-Breach release has no unique Python asset")
    asset = candidates[0]
    match = _DIGEST.fullmatch(str(asset.get("digest", "")))
    result = {
        "tag": tag,
        "version": tag.removeprefix("v"),
        "commit": document.get("target_commitish", ""),
        "asset_id": asset.get("id"),
        "asset_bytes": asset.get("size"),
        "asset_sha256": match.group(1) if match else "",
        "asset_url": asset.get("browser_download_url", ""),
        "release_url": document.get("html_url", ""),
    }
    result["matches_reviewed_pin"] = (
        result["version"] == ZERO_BREACH["version"]
        and result["commit"] == ZERO_BREACH["commit"]
        and result["asset_bytes"] == ZERO_BREACH["bytes"]
        and result["asset_sha256"] == ZERO_BREACH["sha256"]
        and result["asset_url"] == _ASSET
    )
    return result


def _prepare_and_test_zero_breach(data_root: Path, *, allow_download: bool) -> dict:
    from angerona.core.curated_tools import CuratedToolService, ToolOperation

    cfg = SimpleNamespace(
        github_tools_enabled=True,
        github_tools_allow_download=allow_download is True,
        github_tools_job_limit_mib=256,
        github_tools_report_limit_mib=64,
        github_tools_report_count="unlimited",
    )
    service = CuratedToolService(data_root / "curated-tools", cfg=cfg)
    prepared = service.prepare(ToolOperation(timeout=300), allow_download=allow_download)
    tested = service.self_test(ToolOperation(timeout=300))
    return {
        "prepared_state": prepared.get("state", "unknown"),
        "tested_state": tested.get("state", "unknown"),
        "tested": tested.get("state") == "verified",
        "message": tested.get("message", "Zero-Breach metadata test completed."),
    }


def _write_record(data_root: Path, report: dict) -> Path:
    from angerona.core.source_sandbox import _absolute, _atomic_bytes_write, _ensure_directory

    # Runtime data_dir() is already custody-checked and resolved. Resolving here
    # also makes an explicit CLI path under macOS /tmp use its /private target.
    root = _absolute(Path(data_root).resolve() / "github-tool-updates")
    _ensure_directory(root)
    encoded = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_RECORD_BYTES:
        raise ValueError("GitHub tool update record exceeds its byte limit")
    path = root / "latest.json"
    _atomic_bytes_write(path, encoded, root=root, private=True)
    return path


@dataclass(frozen=True)
class GitHubToolUpdateReport:
    status: str
    checked_at: float
    tools: tuple[dict, ...]
    record_path: str = ""

    @property
    def requests(self) -> int:
        return sum(row.get("state") == "review-requested" for row in self.tools)

    @property
    def failures(self) -> int:
        return sum(row.get("state") in {"failed", "held"} for row in self.tools)

    def summary(self) -> str:
        verified = sum(row.get("tested") is True for row in self.tools)
        message = f"GitHub tools: checked {len(self.tools)} maintained integrations"
        if verified:
            message += f"; prepared and tested {verified} managed scanner"
        if self.requests:
            message += f"; {self.requests} immutable data update request(s) need review"
        if self.failures:
            message += f"; {self.failures} check/apply operation(s) held"
        return message + "."


def check_and_apply_github_tools(
    data_root: Path,
    *,
    allow_download: bool = True,
    apply_managed: bool = True,
    now: float | None = None,
    fetch=_github_json,
    prepare_zero=_prepare_and_test_zero_breach,
) -> GitHubToolUpdateReport:
    """Check every maintained repository and safely apply supported updates."""
    checked_at = time.time() if now is None else float(now)
    rows = []
    zero_release = None
    for tool_id, name, repository, branch, mode in TOOL_SPECS:
        row = {
            "tool_id": tool_id,
            "name": name,
            "repository": repository,
            "branch": branch,
            "mode": mode,
            "checked_at": checked_at,
        }
        try:
            row["remote_commit"] = _branch_sha(fetch(repository, "branches/" + branch), branch)
            if tool_id == "zero-breach":
                zero_release = _zero_release(fetch(repository, "releases/latest"))
                row.update(zero_release)
                if zero_release["matches_reviewed_pin"]:
                    if apply_managed:
                        row.update(prepare_zero(Path(data_root), allow_download=allow_download))
                        row["state"] = "verified" if row.get("tested") is True else "held"
                    else:
                        row["state"] = "current"
                else:
                    row.update(
                        state="review-requested",
                        message="A newer or changed stable release needs an Angerona pin review before execution.",
                    )
            elif mode == "data":
                installed = _installed_commit(Path(data_root), tool_id)
                row["installed_commit"] = installed
                row["state"] = (
                    "review-requested" if installed and installed != row["remote_commit"]
                    else "current" if installed else "available"
                )
                row["message"] = (
                    "A newer immutable data source is ready for explicit source review."
                    if row["state"] == "review-requested"
                    else "Data adapter commit checked; imported source remains non-executable."
                )
            else:
                row.update(
                    state="monitored-external",
                    message="External platform checked; Angerona does not replace its server or agent installation.",
                )
        except Exception as exc:
            row.update(state="failed", message=f"GitHub tool check failed ({type(exc).__name__}).")
        rows.append(row)
    status = "partial" if any(row["state"] in {"failed", "held"} for row in rows) else "checked"
    record = {
        "schema": _SCHEMA,
        "checked_at": checked_at,
        "status": status,
        "tools": rows,
    }
    path = ""
    try:
        path = str(_write_record(Path(data_root), record))
    except Exception:
        status = "partial"
    return GitHubToolUpdateReport(status, checked_at, tuple(rows), path)
