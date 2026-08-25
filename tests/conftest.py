"""Repository-wide test isolation for Angerona runtime state.

Tests must never read, rewrite, harden, or delete the operator's real
``runtime-data`` tree.  A few older tests only isolated their SQLite file and
still resolved signing keys and diagnostics through the production data root.
That became visible once the launcher correctly protected the real tree.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

import pytest


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SESSION_ROOT = (
    _PROJECT_ROOT
    / ".tmp"
    / "pytest-runtime"
    / f"{os.getpid()}-{secrets.token_hex(6)}"
)
_BOOTSTRAP_ROOT = _SESSION_ROOT / "collection"
_BOOTSTRAP_ROOT.mkdir(parents=True, exist_ok=True)

# Apply a D-drive boundary before pytest imports test modules. Individual tests
# receive a separate child below, but collection-time imports are isolated too.
os.environ["ANGERONA_DATA"] = str(_BOOTSTRAP_ROOT)
os.environ["ANGERONA_PYTEST_SESSION_ROOT"] = str(_SESSION_ROOT)
os.environ["ANGERONA_DIAG_DIR"] = str(_BOOTSTRAP_ROOT / "diagnostics")
os.environ["TEMP"] = str(_BOOTSTRAP_ROOT / "tmp")
os.environ["TMP"] = str(_BOOTSTRAP_ROOT / "tmp")
# Process-level adoption probes must never attach the test supervisor to the
# operator's live Black Box and terminate it during fixture cleanup.
os.environ["ANGERONA_BLACKBOX_ENABLED"] = "0"
Path(os.environ["TEMP"]).mkdir(parents=True, exist_ok=True)


def _clear_data_path_caches() -> None:
    try:
        from angerona.core import data_paths

        data_paths._canonical_data_path.cache_clear()
        data_paths._ready_source_roots.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def isolate_angerona_runtime(request: pytest.FixtureRequest, monkeypatch):
    """Give every test an independent runtime, diagnostics, and temp root."""
    identity = hashlib.sha256(request.node.nodeid.encode("utf-8")).hexdigest()[:20]
    root = _SESSION_ROOT / identity
    temp = root / "tmp"
    temp.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setenv("ANGERONA_PYTEST_SESSION_ROOT", str(_SESSION_ROOT))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(root / "diagnostics"))
    monkeypatch.setenv("TEMP", str(temp))
    monkeypatch.setenv("TMP", str(temp))
    monkeypatch.setenv("ANGERONA_BLACKBOX_ENABLED", "0")
    _clear_data_path_caches()
    try:
        yield
    finally:
        _clear_data_path_caches()
