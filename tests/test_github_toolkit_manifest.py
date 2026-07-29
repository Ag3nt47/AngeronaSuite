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

    for tool in manifest["python_tools"]:
        assert tool["repository"].startswith("https://github.com/")
        assert re.fullmatch(r"[^<>=!~\s]+==[^<>=!~\s]+", tool["requirement"])
        assert tool["license"]

    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/.dev-tools/" in ignored
