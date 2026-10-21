"""Presentation filters must not revisit a destroyed enclosing dialog."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from angerona.core.privilege import sanitized_child_environment


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("chill", [False, True], ids=["full", "chill"])
@pytest.mark.parametrize("reparent", [False, True], ids=["delete-parent", "reparent-child"])
def test_presentation_timer_survives_dialog_teardown_without_native_override_errors(
    tmp_path, chill, reparent,
):
    script = r'''
import atexit, json, os, sys
from pathlib import Path
if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x8007)
journal = Path(sys.argv[3]).open('x', encoding='utf-8', buffering=1)
def record(kind):
    journal.write(json.dumps({'kind': kind}) + '\n')
    journal.flush()
atexit.register(record, 'python-atexit-end')
from PySide6.QtCore import QCoreApplication, QEvent, qInstallMessageHandler
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from shiboken6 import isValid
from angerona.core.background_pacing import get_pacing_controller
from angerona.gui.presentation_timer import PresentationTimer, set_chill_presentation

callback_errors, qt_messages = [], []
original_excepthook = sys.excepthook
def exception_hook(kind, value, traceback):
    callback_errors.append(kind.__name__)
    original_excepthook(kind, value, traceback)
sys.excepthook = exception_hook
def message_hook(kind, context, message):
    qt_messages.append(message)
    if original_message_hook is not None:
        original_message_hook(kind, context, message)
    else:
        print(message, file=sys.stderr, flush=True)
original_message_hook = qInstallMessageHandler(message_hook)

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
set_chill_presentation(sys.argv[1] == '1')
assert get_pacing_controller().chill_active() == (sys.argv[1] == '1')
dialog = QDialog()
owner = QWidget(dialog)
timer = PresentationTimer(owner)
timer.start(1000)
dialog.show()
app.processEvents()
assert timer.isActive() and timer._window is dialog
assert isValid(dialog) and isValid(owner) and isValid(timer)

retained = [dialog, owner, timer]
if sys.argv[2] == '1':
    # A stopped timer retains its previous window until the next start. Move
    # its still-live child, then destroy that cached window before restarting.
    # Restart must avoid calling removeEventFilter on the old invalid wrapper.
    timer.stop()
    replacement = QDialog()
    retained.append(replacement)
    owner.setParent(replacement)
    assert timer._window is dialog
    dialog.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(dialog) and isValid(owner) and isValid(timer)
    replacement.show()
    owner.show()
    timer.start(1000)
    app.processEvents()
    assert timer.isActive() and timer._window is replacement
    replacement.deleteLater()
else:
    dialog.deleteLater()

QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
assert all(not isValid(wrapper) for wrapper in retained)
assert not callback_errors, callback_errors
assert not any('Error calling Python override' in message for message in qt_messages)
record('native-wrappers-destroyed')
app.shutdown()
assert QApplication.instance() is None
assert not callback_errors, callback_errors
assert not any('Error calling Python override' in message for message in qt_messages)
qInstallMessageHandler(original_message_hook)
sys.excepthook = original_excepthook
record('shutdown-complete')
atexit.register(record, 'python-atexit-begin')
raise SystemExit(0)
'''
    journal = tmp_path / "presentation-timer-lifecycle.jsonl"
    environment = sanitized_child_environment(source={})
    environment.update({
        "QT_QPA_PLATFORM": "offscreen", "ANGERONA_BLACKBOX_ENABLED": "0",
        "ANGERONA_DATA": str(tmp_path / "data"),
        "TEMP": str(tmp_path), "TMP": str(tmp_path),
    })
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script, str(int(chill)),
         str(int(reparent)), str(journal)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    diagnostic = (result.returncode, result.stdout, result.stderr)
    assert result.returncode == 0, diagnostic
    # Some binding versions print and swallow an override exception while
    # returning native success. A clean exit alone cannot prove this regression.
    for forbidden in (
        "Error calling Python override", "Traceback (most recent call last)",
        "Internal C++ object",
    ):
        assert forbidden not in result.stderr, diagnostic
    assert [json.loads(line)["kind"] for line in journal.read_text(encoding="utf-8").splitlines()] == [
        "native-wrappers-destroyed", "shutdown-complete",
        "python-atexit-begin", "python-atexit-end",
    ], diagnostic


@pytest.mark.parametrize("chill", [False, True], ids=["full", "chill"])
def test_native_filter_dispatch_after_python_state_is_cleared_is_inert(tmp_path, chill):
    script = r'''
import atexit, json, os, sys
from pathlib import Path
if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x8007)
journal = Path(sys.argv[2]).open('x', encoding='utf-8', buffering=1)
def record(kind):
    journal.write(json.dumps({'kind': kind}) + '\n')
    journal.flush()
atexit.register(record, 'python-atexit-end')
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from shiboken6 import isValid
from angerona.core.background_pacing import get_pacing_controller
from angerona.gui.presentation_timer import PresentationTimer, set_chill_presentation

observed, callback_errors = [], []
original_excepthook = sys.excepthook
def exception_hook(kind, value, traceback):
    callback_errors.append(kind.__name__)
    original_excepthook(kind, value, traceback)
sys.excepthook = exception_hook

class ObservedTimer(PresentationTimer):
    def eventFilter(self, watched, event):
        # This external recorder survives instance-state clearing and proves
        # Qt invoked the override, rather than a direct call to the Python method.
        observed.append(event.type())
        return super().eventFilter(watched, event)

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
set_chill_presentation(sys.argv[1] == '1')
assert get_pacing_controller().chill_active() == (sys.argv[1] == '1')
dialog = QDialog()
owner = QWidget(dialog)
timer = ObservedTimer(owner)
timer.start(1000)
dialog.show()
app.processEvents()
assert timer.isActive() and timer._window is dialog

# Deterministic fault injection for the state boundary seen during cyclic
# collection: the native filter remains installed while Python attributes are
# gone. This does not claim to force a particular collector/destructor schedule.
QTimer.stop(timer)
observed.clear()
timer.__dict__.clear()
assert isValid(timer) and '_retired' not in timer.__dict__
for kind in (QEvent.Type.Hide, QEvent.Type.ActivationChange):
    QCoreApplication.sendEvent(owner, QEvent(kind))
assert observed == [QEvent.Type.Hide, QEvent.Type.ActivationChange], observed
assert not callback_errors, callback_errors
record('cleared-state-native-dispatch-verified')

dialog.deleteLater()
QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
assert not isValid(dialog) and not isValid(owner) and not isValid(timer)
assert not callback_errors, callback_errors
record('native-wrappers-destroyed')
app.shutdown()
assert QApplication.instance() is None
assert not callback_errors, callback_errors
sys.excepthook = original_excepthook
record('shutdown-complete')
atexit.register(record, 'python-atexit-begin')
raise SystemExit(0)
'''
    journal = tmp_path / "presentation-timer-cleared-state.jsonl"
    environment = sanitized_child_environment(source={})
    environment.update({
        "QT_QPA_PLATFORM": "offscreen", "ANGERONA_BLACKBOX_ENABLED": "0",
        "ANGERONA_DATA": str(tmp_path / "data"),
        "TEMP": str(tmp_path), "TMP": str(tmp_path),
    })
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script, str(int(chill)), str(journal)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    diagnostic = (result.returncode, result.stdout, result.stderr)
    assert result.returncode == 0, diagnostic
    for forbidden in (
        "Error calling Python override", "Traceback (most recent call last)",
        "Internal C++ object",
    ):
        assert forbidden not in result.stderr, diagnostic
    assert [json.loads(line)["kind"] for line in journal.read_text(encoding="utf-8").splitlines()] == [
        "cleared-state-native-dispatch-verified", "native-wrappers-destroyed",
        "shutdown-complete", "python-atexit-begin", "python-atexit-end",
    ], diagnostic
