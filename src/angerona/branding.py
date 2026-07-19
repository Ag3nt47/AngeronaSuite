"""branding.py — single source of truth for Angerona's app icon path.

The shield icon ships in assets/icons/ at the repo root. Path resolution
mirrors the same pattern modules/yara_scanner.py already uses for its
bundled yara64.exe/rules.yar (Path(__file__).resolve().parents[N] up to
the repo root) — this file just sits one level shallower (src/angerona/
instead of src/angerona/modules/), hence parents[2] instead of parents[3].

icon_path() returns None (never raises) if the asset is missing — e.g. a
stripped-down dev checkout — so callers can degrade gracefully to the old
solid-color placeholder instead of crashing on a missing file.
"""
from __future__ import annotations

from typing import Optional

from angerona.core.data_paths import resource_root

_REPO_ROOT = resource_root()
_ICON_DIR = _REPO_ROOT / "assets" / "icons"

ICON_ICO = _ICON_DIR / "angerona.ico"
ICON_PNG = _ICON_DIR / "angerona_icon.png"


def icon_path() -> Optional[str]:
    """Best available app icon file (.ico preferred — multi-resolution, so
    Windows picks the right size for titlebar/taskbar/alt-tab/tray itself),
    or None if the assets directory isn't present."""
    for cand in (ICON_ICO, ICON_PNG):
        if cand.exists():
            return str(cand)
    return None
