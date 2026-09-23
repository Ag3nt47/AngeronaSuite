"""Optional, responsive VMware setup. Opening this dialog changes nothing."""
from __future__ import annotations

import queue
import sys
import threading

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout,
)

from angerona.core import analysis_vmware_setup as setup

_WORKERS = threading.BoundedSemaphore(1)


class VMwareSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Optional Analysis Lab setup")
        self.resize(660, 460)
        self._busy = False
        self._progress = queue.Queue(maxsize=8)
        self._completion = queue.Queue(maxsize=1)
        layout = QVBoxLayout(self)
        for text in (
            setup.PURPOSE,
            "Broadcom requires a free account and may require compliance approval. "
            "Open its official portal, download VMware Workstation for Windows, then select that installer here. "
            "Angerona does not collect your Broadcom password or accept its license for you.",
            setup.VALIDATION_NOTE,
        ):
            label = QLabel(text)
            label.setWordWrap(True)
            label.setTextFormat(Qt.TextFormat.PlainText)
            layout.addWidget(label)
        self.portal_button = QPushButton("Open official Broadcom download portal")
        self.help_button = QPushButton("Official download instructions")
        self.install_button = QPushButton("Choose and install downloaded VMware…")
        self.configure_button = QPushButton("Configure installed VMware service…")
        self.lab_button = QPushButton("Open Analysis Lab to prepare / check…")
        self.portal_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(setup.DOWNLOAD_URL)))
        self.help_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(setup.DOWNLOAD_HELP_URL)))
        self.install_button.clicked.connect(self._install)
        self.configure_button.clicked.connect(self._configure)
        self.lab_button.clicked.connect(self._open_lab)
        self._actions = (self.portal_button, self.help_button, self.install_button,
                         self.configure_button, self.lab_button)
        for button in self._actions:
            button.setAutoDefault(False)
            layout.addWidget(button)
        self.status = QLabel("Optional setup is idle. Skip leaves VMware and all virtual machines unchanged.")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        row.addStretch()
        self.close_button = QPushButton("Skip / close")
        self.close_button.setDefault(True)
        self.close_button.clicked.connect(self.reject)
        row.addWidget(self.close_button)
        layout.addLayout(row)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._poll)
        self._buttons()

    def _buttons(self):
        supported = sys.platform == "win32"
        for button in self._actions:
            button.setEnabled(supported and not self._busy)
        self.close_button.setEnabled(not self._busy)
        if not supported:
            self.status.setText("Analysis Lab currently supports Windows. Skip this step on macOS or Linux; VMware is not needed for Angerona protection.")

    def _start(self, work):
        if self._busy or not _WORKERS.acquire(blocking=False):
            return
        self._busy = True
        self._buttons()
        updates, completion = self._progress, self._completion

        def progress(message):
            try:
                updates.put_nowait(str(message)[:2000])
            except queue.Full:
                pass

        def run():
            try:
                result = (True, str(work(progress))[:4000])
            except Exception as exc:
                result = (False, f"{type(exc).__name__}: {exc}"[:4000])
            finally:
                _WORKERS.release()
            # A separate single-result channel cannot lose completion to a
            # full progress queue. Only one worker is admitted per dialog.
            completion.put_nowait(result)

        try:
            threading.Thread(target=run, name="vmware-setup", daemon=True).start()
        except Exception:
            _WORKERS.release()
            self._busy = False
            self._buttons()
            raise
        self.status.setText("Starting the requested setup action…")
        self._timer.start()

    def _poll(self):
        for _ in range(8):
            try:
                self.status.setText(self._progress.get_nowait())
            except queue.Empty:
                break
        try:
            ok, message = self._completion.get_nowait()
        except queue.Empty:
            return
        self._busy = False
        self._timer.stop()
        self._buttons()
        self.status.setText(message + ("\n\n" + setup.VALIDATION_NOTE if ok else ""))

    def _install(self):
        selected, _filter = QFileDialog.getOpenFileName(
            self, "Select the downloaded VMware Workstation installer", "", "Windows installer (*.exe)",
        )
        if not selected:
            return
        if QMessageBox.question(
            self, "Install optional VMware Workstation?",
            "Angerona will verify the selected installer and open its normal UAC and license prompts. "
            "Installation changes this computer and may require a restart. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self._start(lambda progress: setup.install_selected(selected, progress))

    def _configure(self):
        if QMessageBox.question(
            self, "Configure optional VMware service?",
            "Approve UAC to set VMware Authorization Service to Manual startup and start it now. "
            "This does not change an existing VM or start a VM. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self._start(setup.configure_service)

    def _open_lab(self):
        from angerona.gui.analysis_lab import AnalysisLabPanel

        dialog = QDialog(self)
        dialog.setWindowTitle("Analysis Lab — prepare and check")
        dialog.resize(940, 700)
        layout = QVBoxLayout(dialog)
        panel = AnalysisLabPanel(dialog)
        layout.addWidget(panel)
        dialog.finished.connect(lambda _result: panel.cancel_pending())
        dialog.exec()
        dialog.deleteLater()

    def reject(self):
        if self._busy:
            self.status.setText("Finish or cancel the native installer/UAC prompt first. Its verified file remains protected until it exits.")
            return
        super().reject()

    def closeEvent(self, event):  # noqa: N802
        if self._busy:
            event.ignore()
            self.reject()
        else:
            super().closeEvent(event)
