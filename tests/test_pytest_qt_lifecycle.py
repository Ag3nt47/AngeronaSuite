"""The session fixture releases its own Qt state before interpreter shutdown."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from angerona.core.privilege import sanitized_child_environment


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("mode", ["owned", "borrowed", "test-exception"])
def test_session_application_cleanup_has_an_explicit_owned_boundary(tmp_path, mode):
    pytest.importorskip("PySide6.QtWidgets")
    script = r'''
import atexit, json, os, runpy, sys
from pathlib import Path
if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x8007)
journal = Path(sys.argv[2]).open('x', encoding='utf-8', buffering=1)
def record(kind):
    journal.write(json.dumps({'kind':kind}) + '\n')
    journal.flush()
atexit.register(record, 'python-atexit-end')
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QWidget
from shiboken6 import isValid
mode = sys.argv[1]
borrowed = QApplication([]) if mode == 'borrowed' else None
namespace = runpy.run_path('tests/conftest.py')
fixture = namespace['keep_qt_application_alive'].__wrapped__()
next(fixture)
app = QApplication.instance()
owner = QWidget()
timer = QTimer(owner)
timer.start(60000)
destroyed = []
app.destroyed.connect(lambda: destroyed.append('application'))
owner.destroyed.connect(lambda: destroyed.append('widget'))
timer.destroyed.connect(lambda: destroyed.append('timer'))
propagated = False
if mode == 'test-exception':
    try:
        fixture.throw(RuntimeError('inert original test failure'))
    except RuntimeError as exc:
        assert str(exc) == 'inert original test failure'
        propagated = True
else:
    try:
        next(fixture)
    except StopIteration:
        pass
if mode == 'borrowed':
    assert QApplication.instance() is borrowed
    assert isValid(app) and isValid(owner) and isValid(timer)
    assert not destroyed
else:
    assert QApplication.instance() is None
    assert not isValid(app) and not isValid(owner) and not isValid(timer)
    assert set(destroyed) == {'application', 'widget', 'timer'}
assert propagated == (mode == 'test-exception')
record('fixture-lifecycle-verified')
if borrowed is not None:
    # Only this explicitly retained owner tears down the borrowed application.
    borrowed.shutdown()
    assert QApplication.instance() is None
record('before-system-exit')
atexit.register(record, 'python-atexit-begin')
raise SystemExit(0)
'''
    journal = tmp_path / "shutdown.jsonl"
    environment = sanitized_child_environment(source={})
    environment.update({
        "QT_QPA_PLATFORM": "offscreen", "ANGERONA_BLACKBOX_ENABLED": "0",
        "TEMP": str(tmp_path), "TMP": str(tmp_path),
    })
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script, mode, str(journal)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert [json.loads(line)["kind"] for line in journal.read_text(encoding="utf-8").splitlines()] == [
        "fixture-lifecycle-verified", "before-system-exit", "python-atexit-begin", "python-atexit-end",
    ]
