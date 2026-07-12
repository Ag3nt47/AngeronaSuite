"""ai_consult_dialog.py — reusable "Consult AI" UI (Anthropic-first, off-thread).

Provides:
  * AIConsultWorker  — QThread that runs engines.ai_consult.consult_ai() so the
    network round-trip never blocks the GUI.
  * AIConsultDialog  — a self-contained window that shows the AI's proposed
    solution/patch with "Save to computer…" and "Discard" buttons.

Used by the threat-intel "Consult AI" / "AI Proposed Solution" buttons and by the
alert-detail "Research" action.
"""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from angerona.engines.ai_consult import consult_ai, DEFAULT_SYSTEM


class AIConsultWorker(QThread):
    """Runs one consult_ai() call off the GUI thread."""

    done = Signal(dict)   # {"text", "provider", "error"}

    def __init__(self, prompt: str, system: str = DEFAULT_SYSTEM,
                 allow_local_fallback: bool = True, parent=None) -> None:
        super().__init__(parent)
        self._prompt = prompt
        self._system = system
        self._allow_local = allow_local_fallback

    def run(self) -> None:
        try:
            res = consult_ai(self._prompt, self._system,
                             allow_local_fallback=self._allow_local)
        except Exception as exc:   # defensive — consult_ai shouldn't raise
            res = {"text": "", "provider": None, "error": str(exc)}
        self.done.emit(res)


class AIConsultDialog(QDialog):
    """Non-modal window: consult an online AI (Claude first) for a comprehensive
    solution/patch, then Save to computer or Discard.

    Args:
        title:   window title.
        prompt:  the full user prompt sent to the AI.
        system:  system prompt (role framing).
        default_filename: suggested name when saving (e.g. "CVE-2024-1234_fix.md").
        allow_local_fallback: if False, only online providers are tried.
    """

    def __init__(self, title: str, prompt: str, *, system: str = DEFAULT_SYSTEM,
                 default_filename: str = "angerona_ai_solution.md",
                 allow_local_fallback: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(720, 560)
        if parent is not None:
            try:
                self.setStyleSheet(parent.styleSheet())
            except Exception:
                pass

        self._default_filename = default_filename
        self._worker: Optional[AIConsultWorker] = None

        lay = QVBoxLayout(self)
        self._status = QLabel("Consulting AI (Claude first, then fallbacks)…")
        self._status.setStyleSheet("color:#93c5fd; font-weight:600;")
        lay.addWidget(self._status)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(False)   # operator may tweak before saving
        self._output.setPlaceholderText("The AI's proposed solution will appear here…")
        lay.addWidget(self._output, 1)

        # Follow-up conversation bar — hidden until "Ask AI" is clicked. Lets the
        # operator keep talking to the AI about this alert/CVE in the same window.
        self._prompt_bar = QWidget()
        pbl = QHBoxLayout(self._prompt_bar)
        pbl.setContentsMargins(0, 0, 0, 0)
        self._prompt_input = QLineEdit()
        self._prompt_input.setPlaceholderText("Ask the AI a follow-up question… (Enter to send)")
        self._prompt_input.returnPressed.connect(self._send_followup)
        self._send_btn = QPushButton("Send")
        self._send_btn.clicked.connect(self._send_followup)
        pbl.addWidget(self._prompt_input, 1)
        pbl.addWidget(self._send_btn)
        self._prompt_bar.setVisible(False)
        lay.addWidget(self._prompt_bar)

        row = QHBoxLayout()
        self._btn_retry = QPushButton("Re-consult")
        self._btn_followup = QPushButton("💬  Ask AI")
        self._btn_followup.setToolTip("Open a prompt bar to keep talking to the AI about this.")
        self._btn_save = QPushButton("💾  Save to computer…")
        self._btn_save.setStyleSheet("background:#166534; color:#dcfce7; font-weight:700;")
        self._btn_discard = QPushButton("Discard")
        self._btn_retry.clicked.connect(self._start)
        self._btn_followup.clicked.connect(self._reveal_prompt)
        self._btn_save.clicked.connect(self._save)
        self._btn_discard.clicked.connect(self.reject)
        row.addWidget(self._btn_retry)
        row.addWidget(self._btn_followup)
        row.addStretch()
        row.addWidget(self._btn_discard)
        row.addWidget(self._btn_save)
        lay.addLayout(row)

        # Running transcript so follow-ups carry conversation context.
        self._thread_text = ""

        self._prompt = prompt
        self._system = system
        self._allow_local = allow_local_fallback
        self._set_running(True)
        self._start()

    # ── Flow ──────────────────────────────────────────────────────────────────
    def _set_running(self, running: bool) -> None:
        self._btn_save.setEnabled(not running)
        self._btn_retry.setEnabled(not running)
        if hasattr(self, "_send_btn"):
            self._send_btn.setEnabled(not running)
        if hasattr(self, "_btn_followup"):
            self._btn_followup.setEnabled(not running)

    def _start(self) -> None:
        self._set_running(True)
        self._status.setText("Consulting AI (Claude first, then fallbacks)…")
        self._worker = AIConsultWorker(self._prompt, self._system,
                                       self._allow_local, self)
        self._worker.done.connect(self._on_done)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_done(self, res: dict) -> None:
        self._set_running(False)
        if res.get("text"):
            prov = res.get("provider", "?")
            self._status.setText(f"✓ Answer from: {prov}  —  click 💬 Ask AI to follow up")
            self._output.setPlainText(res["text"])
            # Seed the conversation transcript for context-aware follow-ups.
            self._thread_text = f"User: {self._prompt}\nAssistant: {res['text']}"
        else:
            self._status.setText("⚠ No AI answer")
            self._output.setPlainText(
                "Could not get an AI response.\n\n"
                f"Detail: {res.get('error')}\n\n"
                "Set ANTHROPIC_API_KEY (or another provider key) in Settings ▸ API Keys, "
                "or ensure local Ollama is running.")

    # ── Follow-up conversation ───────────────────────────────────────────────
    def _reveal_prompt(self) -> None:
        self._prompt_bar.setVisible(True)
        self._prompt_input.setFocus()

    def _send_followup(self) -> None:
        q = self._prompt_input.text().strip()
        if not q:
            return
        self._prompt_input.clear()
        self._output.appendPlainText(f"\n\n──────────\n🗨  You: {q}\n")
        self._status.setText("Asking AI…")
        self._set_running(True)
        # Carry prior turns as context so the AI answers coherently.
        base = self._thread_text or f"User: {self._prompt}"
        followup_prompt = base + f"\n\nUser: {q}\nAssistant:"
        self._fu_worker = AIConsultWorker(followup_prompt, self._system,
                                          self._allow_local, self)
        self._fu_worker.done.connect(lambda res, qq=q: self._on_followup_done(res, qq))
        self._fu_worker.finished.connect(self._fu_worker.deleteLater)
        self._fu_worker.start()

    def _on_followup_done(self, res: dict, question: str) -> None:
        self._set_running(False)
        text = res.get("text") or f"(no answer — {res.get('error')})"
        prov = res.get("provider", "?")
        self._status.setText(f"✓ Answer from: {prov}")
        self._output.appendPlainText(f"🤖  AI ({prov}): {text}")
        self._thread_text = (self._thread_text or f"User: {self._prompt}") \
            + f"\n\nUser: {question}\nAssistant: {text}"

    def _save(self) -> None:
        text = self._output.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Save", "Nothing to save yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save AI solution", self._default_filename,
            "Markdown (*.md);;PowerShell (*.ps1);;Text (*.txt);;All files (*.*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            QMessageBox.information(self, "Saved", f"Saved to:\n{path}")
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", str(exc))
