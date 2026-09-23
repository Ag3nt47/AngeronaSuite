"""Optional Lab setup with explicit consent and bounded background progress."""
from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QVBoxLayout

from angerona.core import tool_analysis_jobs as jobs

_WORKERS = threading.BoundedSemaphore(1)
PURPOSE = (
    'Analysis Lab is optional. It checks a copy of your source for Python security issues '
    'and exposed secrets inside an offline, diskless virtual machine. It runs only when '
    'you request analysis. Monitoring, automatic defense, and Ollama do not need it.'
)
SETUP_DETAILS = (
    'Setup can download the reviewed QEMU 11.1.0 installer (about 197 MiB) and open its '
    'Windows administrator and license prompts. Keep its default install location. '
    'A second administrator prompt protects the Lab runtime. An existing matching QEMU '
    'installation is reused. Allow 2 GiB of free disk space. Each analysis uses one virtual CPU and 768 MiB of guest RAM; '
    'nothing stays running when analysis ends. Use a normal, non-administrator Angerona session. '
    'Windows on Intel/AMD is currently supported.'
)


class QEMUSetupDialog(QDialog):
    def __init__(self, parent=None, *, root=None):
        super().__init__(parent)
        self.setWindowTitle('Optional Analysis Lab setup')
        self.resize(650, 390)
        self._root = Path(root) if root is not None else jobs.default_root()
        self._busy = False
        self._progress = queue.Queue(maxsize=8)
        self._completion = queue.Queue(maxsize=1)
        layout = QVBoxLayout(self)
        for text in (PURPOSE, SETUP_DETAILS,
                     'After setup, use Prepare runtime and Check readiness. Skip changes nothing.'):
            label = QLabel(text)
            label.setWordWrap(True)
            label.setTextFormat(Qt.TextFormat.PlainText)
            layout.addWidget(label)
        self.install_button = QPushButton('Download and configure the optional Lab emulator')
        self.install_button.setAutoDefault(False)
        self.install_button.setEnabled(sys.platform == 'win32')
        self.install_button.clicked.connect(self._install)
        layout.addWidget(self.install_button)
        self.vmware_button = QPushButton('Separate VMware setup (not required for this Lab)…')
        self.vmware_button.setAutoDefault(False)
        self.vmware_button.setEnabled(sys.platform == 'win32')
        self.vmware_button.clicked.connect(self._vmware)
        layout.addWidget(self.vmware_button)
        self.status = QLabel('Optional setup is idle.')
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self.close_button = QPushButton('Skip / close')
        self.close_button.setDefault(True)
        self.close_button.clicked.connect(self.reject)
        layout.addWidget(self.close_button)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._poll)

    def _install(self):
        if self._busy or not _WORKERS.acquire(blocking=False):
            return
        self._busy = True
        self.install_button.setEnabled(False)
        self.vmware_button.setEnabled(False)
        self.close_button.setEnabled(False)
        updates, completion, root = self._progress, self._completion, self._root

        def progress(message):
            try:
                updates.put_nowait(str(message)[:2000])
            except queue.Full:
                pass

        def work():
            try:
                from angerona.core.analysis_qemu_setup import install_and_configure
                result = str(install_and_configure(root, jobs.AnalysisOperation(), progress))
            except Exception as exc:
                result = str(exc)[:2000] if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__
            finally:
                _WORKERS.release()
            completion.put_nowait(result)

        try:
            threading.Thread(target=work, name='analysis-lab-setup', daemon=True).start()
        except Exception:
            _WORKERS.release()
            self._busy = False
            self.install_button.setEnabled(True)
            self.vmware_button.setEnabled(True)
            self.close_button.setEnabled(True)
            raise
        self.status.setText('Preparing the requested setup. You can cancel in any native installer or UAC prompt.')
        self._timer.start()

    def _poll(self):
        for _ in range(8):
            try:
                self.status.setText(self._progress.get_nowait())
            except queue.Empty:
                break
        try:
            result = self._completion.get_nowait()
        except queue.Empty:
            return
        self._timer.stop()
        self._busy = False
        self.install_button.setEnabled(sys.platform == 'win32')
        self.vmware_button.setEnabled(sys.platform == 'win32')
        self.close_button.setEnabled(True)
        self.status.setText(result)

    def _vmware(self):
        from angerona.gui.analysis_vmware_setup import VMwareSetupDialog
        dialog = VMwareSetupDialog(self)
        dialog.exec()
        dialog.deleteLater()

    def reject(self):
        if self._busy:
            self.status.setText('Finish or cancel the native setup prompt first. Setup files remain protected until it exits.')
            return
        super().reject()

    def closeEvent(self, event):  # noqa: N802
        if self._busy:
            event.ignore()
            self.reject()
        else:
            super().closeEvent(event)
