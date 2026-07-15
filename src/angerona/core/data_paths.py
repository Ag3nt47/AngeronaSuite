"""Canonical D-drive runtime locations for this Angerona installation."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def project_root() -> Path:
    override = os.environ.get("ANGERONA_HOME", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def data_dir(create: bool = True) -> Path:
    """Return the sole persistent runtime root.

    The installation lives on D:, so its portable default is a sibling
    ``runtime-data`` directory. ``ANGERONA_DATA`` remains an explicit override
    for packaged or custom deployments.
    """
    configured = os.environ.get("ANGERONA_DATA", "").strip()
    path = Path(configured).expanduser() if configured else project_root() / "runtime-data"
    path = path.resolve()
    os.environ.setdefault("ANGERONA_DATA", str(path))
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def runtime_temp_dir(create: bool = True) -> Path:
    path = data_dir(create=create) / "tmp"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def configure_runtime_environment() -> Path:
    """Pin app data, diagnostics, and inherited temp files to this D: install."""
    root = data_dir()
    tmp = runtime_temp_dir()
    os.environ.setdefault("ANGERONA_DIAG_DIR", str(project_root() / "diagnostics"))
    os.environ["TEMP"] = str(tmp)
    os.environ["TMP"] = str(tmp)
    return root
