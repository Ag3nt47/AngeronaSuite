"""Presentation of cached Ollama startup stages; never probes from Qt."""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton


class OllamaStatusPanel(QFrame):
    def __init__(self, host_provider, parent=None, *, retry=False):
        super().__init__(parent)
        self._host_provider = host_provider
        self._rendered = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 8, 3)
        self.label = QLabel("Local AI startup: waiting")
        self.label.setTextFormat(Qt.PlainText)
        self.label.setWordWrap(True)
        layout.addWidget(self.label, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setMaximumWidth(140)
        self.progress.setFormat("%p%")
        layout.addWidget(self.progress)
        self.retry_button = None
        if retry:
            self.retry_button = QPushButton("Start / check Ollama")
            self.retry_button.clicked.connect(self.start_service)
            layout.addWidget(self.retry_button)
        self.setToolTip(
            "Percentage marks completed service startup stages, not elapsed time. "
            "100% means the verified local service answered its model inventory. "
            "Model approval and byte verification remain separate. Automatic "
            "containment works independently of Ollama."
        )
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh)
        self.refresh()

    def refresh(self):
        from angerona.core.ollama_lifecycle import startup_snapshot

        status = startup_snapshot(self._host_provider())
        # Reading an immutable in-memory snapshot causes no process, network or
        # filesystem work. Avoid relayout/repaint when the stage is unchanged.
        if status == self._rendered:
            return
        self._rendered = status
        self.progress.setValue(status.percent)
        self.label.setText(f"Local AI startup: {status.stage} — {status.detail}")
        color = "#fbbf24" if status.state in {"failed", "cancelled"} else "#94a3b8"
        if status.daemon_ready:
            color = "#4ade80"
        self.label.setStyleSheet(f"color:{color};")
        if self.retry_button is not None:
            self.retry_button.setEnabled(status.state != "starting")

    def start_service(self):
        from angerona.core.ollama_lifecycle import request_ollama_start

        request_ollama_start(self._host_provider())
        self.refresh()

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self.refresh()
        self._timer.start()

    def hideEvent(self, event):  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)
