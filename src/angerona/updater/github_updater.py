"""Check GitHub Releases for a newer version.

Compares the running ``__version__`` against the latest published release tag.
Read-only: it reports availability and the download URL; it does not silently
replace the running binary (that's a deliberate, user-initiated action).
"""
from __future__ import annotations

import json
import urllib.request

from angerona import __version__


def _norm(tag: str) -> tuple:
    tag = tag.lstrip("vV")
    parts = []
    for piece in tag.split("."):
        num = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


def check_for_updates(repo: str) -> str:
    """Return a human-readable status string for the Settings page."""
    if not repo or "/" not in repo or repo.startswith("your-user/"):
        return "Set your GitHub repo (user/name) in Settings first."
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "Angerona-Updater"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return f"Update check failed: {exc}"

    latest = data.get("tag_name", "")
    if not latest:
        return "No releases published yet."
    if _norm(latest) > _norm(__version__):
        return f"Update available: {latest} (you have v{__version__}). Download: {data.get('html_url', '')}"
    return f"Up to date (v{__version__})."
