"""Initial source Core interpreter options exclude unsealed cwd import shadows."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from angerona import startup


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", ["module", "package"])
def test_initial_source_core_prefix_ignores_working_directory_shadow(tmp_path, kind):
    shadow = tmp_path / "working-directory"
    shadow.mkdir()
    marker = tmp_path / "shadow-executed"
    target = shadow / "angerona.py"
    if kind == "package":
        target = shadow / "angerona" / "__init__.py"
        target.parent.mkdir()
    target.write_text(
        "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('unexpected')\n"
        "raise RuntimeError('unsealed working-directory shadow executed')\n",
        encoding="utf-8",
    )
    command = startup._source_core_command(Path(sys.executable), ROOT, tmp_path / "data", frozen=False)
    assert command[-2:] == ("-m", "angerona")
    # Use only the exact production interpreter prefix. Importing the inert
    # package initializer cannot start a Core, dashboard, sensor or supervisor.
    probe = (
        "import angerona,json,sys;print(json.dumps({"
        "'origin':angerona.__file__,'isolated':sys.flags.isolated,"
        "'safe_path':getattr(sys.flags,'safe_path',None),'ignore_environment':sys.flags.ignore_environment}))"
    )
    result = subprocess.run(
        [*command[:-2], "-c", probe], cwd=shadow, env=dict(os.environ, PYTHONPATH=str(shadow)),
        capture_output=True, text=True, timeout=15, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert Path(observed["origin"]).resolve() == (ROOT / "src/angerona/__init__.py").resolve()
    assert observed["isolated"] == observed["ignore_environment"] == 1
    assert observed["safe_path"] is True or sys.version_info < (3, 11) and observed["safe_path"] is None
    assert not marker.exists()


@pytest.mark.parametrize("cache", [(), ("-B", "-X", "pycache_prefix=reviewed-private-cache")])
def test_initial_core_isolation_preserves_cache_options_and_frozen_command(tmp_path, monkeypatch, cache):
    monkeypatch.setattr(startup, "_source_fresh_cache_arguments", lambda *_: cache)
    executable = tmp_path / "python.exe"
    command = startup._source_core_command(executable, ROOT, tmp_path, frozen=False)
    assert command == (str(executable), *cache, "-I", "-m", "angerona")
    assert startup._source_core_command(executable, ROOT, tmp_path, frozen=True) == (str(executable),)
