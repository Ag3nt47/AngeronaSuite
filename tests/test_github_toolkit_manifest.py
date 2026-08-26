from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "tools" / "github_toolkit.lock.json"


def test_github_toolkit_is_pinned_development_only_and_ignored() -> None:
    manifest = json.loads(LOCK.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert "runtime dependencies" in manifest["purpose"]
    assert len(manifest["github_assets"]) >= 3

    ids: set[str] = set()
    for asset in manifest["github_assets"]:
        assert asset["id"] not in ids
        ids.add(asset["id"])
        assert asset["repository"].startswith("https://github.com/")
        assert asset["url"].startswith(asset["repository"] + "/releases/download/")
        assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
        assert asset["version"]
        assert asset["license"]
        assert asset["executables"]

    assert "gitleaks" in ids
    gitleaks = next(
        asset for asset in manifest["github_assets"] if asset["id"] == "gitleaks"
    )
    executable_hash = gitleaks["executable_sha256"]["gitleaks.exe"]
    assert re.fullmatch(r"[0-9a-f]{64}", executable_hash)
    assert executable_hash != gitleaks["sha256"]

    bootstrap = (ROOT / "tools" / "bootstrap_github_toolkit.ps1").read_text(
        encoding="utf-8"
    )
    assert "executable_sha256" in bootstrap
    assert "Extracted $executable does not match its pinned SHA-256" in bootstrap
    assert "Installed $executable does not match its pinned SHA-256" in bootstrap

    for tool in manifest["python_tools"]:
        assert tool["repository"].startswith("https://github.com/")
        assert re.fullmatch(r"[^<>=!~\s]+==[^<>=!~\s]+", tool["requirement"])
        assert tool["license"]

    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/.dev-tools/" in ignored
