"""Read-only selected-alert evidence preview for the dashboard."""
from __future__ import annotations

from html import escape

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QSizePolicy, QVBoxLayout


def _bounded_text(value: object, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… Open full details for the remaining evidence."


class AlertPreview(QFrame):
    """Contains no response actions; the existing detail dialog owns those."""

    open_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("AlertPreview")
        self.setMinimumWidth(280)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 8, 8)
        layout.setSpacing(6)
        heading = QHBoxLayout()
        self._title = QLabel("SELECTED ALERT")
        self._title.setObjectName("SectionTitle")
        self._title.setTextFormat(Qt.PlainText)
        heading.addWidget(self._title, 1)
        self._open = QPushButton("Open")
        self._open.setAccessibleName("Open full alert details")
        self._open.setEnabled(False)
        self._open.setToolTip("Open the full evidence and guarded response controls for this alert.")
        self._open.clicked.connect(lambda _checked=False: self.open_requested.emit())
        heading.addWidget(self._open)
        layout.addLayout(heading)
        self._source = QLabel("Select an alert to preview its evidence.")
        self._source.setTextFormat(Qt.PlainText)
        self._source.setWordWrap(True)
        self._source.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self._source.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self._source)
        self._metadata = QLabel("")
        self._metadata.setTextFormat(Qt.PlainText)
        self._metadata.setWordWrap(True)
        layout.addWidget(self._metadata)
        self._evidence = QPlainTextEdit()
        self._evidence.setReadOnly(True)
        # Keep several actual evidence lines visible after theme padding and
        # scrollbars, even when the surrounding dashboard is short.
        self._evidence.setMinimumHeight(160)
        self._evidence.setAccessibleName("Selected alert message and artifact paths")
        self._evidence.setPlaceholderText("The selected alert's message and supplied artifact paths appear here.")
        layout.addWidget(self._evidence, 1)
        self._display_key = None

    def clear(self) -> None:
        self._display_key = None
        self._source.setText("Select an alert to preview its evidence.")
        self._source.setToolTip("")
        self._metadata.clear()
        self._evidence.clear()
        self._open.setEnabled(False)

    def show_evidence(self, *, module: str, severity: str, timestamp: str,
                      message: str, paths: str) -> None:
        source = _bounded_text(module, 240)
        metadata = f"{severity} · {timestamp}"
        evidence = (
            _bounded_text(message, 12000)
            + "\n\nARTIFACT PATHS\n" + _bounded_text(paths, 8000)
        )
        key = (source, metadata, evidence)
        if key == self._display_key:
            return
        self._display_key = key
        self._source.setText(source)
        self._source.setToolTip("<qt>" + escape(source).replace("\n", "<br>") + "</qt>")
        self._metadata.setText(metadata)
        self._evidence.setPlainText(evidence)
        self._open.setEnabled(True)
