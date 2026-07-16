"""gui/setup_wizard.py — one-swoop Setup Wizard.

Walks a new operator through every configurable area of Angerona in a single
flow — appearance, local/online AI, voice, the Signal mobile bridge, the Teams
bot, trusted apps, and startup — one step at a time, each with Next / Skip / Back
and a Finish that saves everything at once.

The step definitions are pure data (:data:`STEPS`) so the flow is testable
without a display; the Qt dialog is import-guarded so this module imports (and
self-tests) even where PySide6 is absent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Field:
    kind: str            # "check" | "text" | "password_env" | "combo" | "action"
    key: str             # Config attribute (or env var for password_env; action id)
    label: str
    placeholder: str = ""
    options: tuple = ()   # for "combo"
    note: str = ""


@dataclass(frozen=True)
class Step:
    title: str
    intro: str
    fields: tuple = ()


# ── The wizard content (data-driven) ──────────────────────────────────────────
STEPS: "tuple[Step, ...]" = (
    Step("Welcome to Angerona",
         "Let's get you set up. Each step is optional — press Skip to leave it as "
         "is, or Next to apply. Everything stays local unless you turn on a cloud "
         "feature. You can change any of this later in Settings."),
    Step("Appearance",
         "Pick a look. You can fine-tune colours in Settings.",
         (Field("combo", "theme", "Theme", options=("cyber", "crt", "slate")),
          Field("text", "accent", "Accent colour (hex, optional)", "#1f9cff"))),
    Step("Local AI (ARIA's brain)",
         "ARIA answers from a local model (Ollama). Point it at your Ollama server "
         "and model. No key needed; nothing leaves your machine.",
         (Field("text", "ollama_host", "Ollama host", "http://localhost:11434"),
          Field("text", "ollama_model", "Model", "llama3",
                note="Run 'ollama serve' and 'ollama pull llama3' if you haven't."))),
    Step("Voice",
         "Let ARIA speak her replies (built-in Windows voice — no install). For "
         "hands-free 'hey aria' commands, install vosk + sounddevice later.",
         (Field("check", "aria_voice_enabled", "Enable voice (ARIA speaks replies)"),)),
    Step("Talk to ARIA from your phone (Signal)",
         "End-to-end encrypted remote control + chat over Signal. Requires signal-"
         "cli installed and your number registered.",
         (Field("check", "mobile_enabled", "Enable the Signal mobile bridge"),
          Field("text", "mobile_signal_cli", "signal-cli path", "C:\\signal-cli\\bin\\signal-cli.bat"),
          Field("text", "mobile_host_number", "This machine's Signal number", "+1..."),
          Field("text", "mobile_dest_number", "Your phone number", "+1..."))),
    Step("Microsoft Teams bot",
         "Chat with ARIA inside Teams. Needs an Azure Bot registration (App ID + "
         "secret) and a tunnel to this machine. The secret is stored in .env.",
         (Field("check", "teams_bot_enabled", "Enable the Teams bot"),
          Field("text", "teams_app_id", "Azure App (client) ID", "xxxxxxxx-xxxx-…"),
          Field("password_env", "ANGERONA_TEAMS_APP_PASSWORD", "App password (→ .env)"),
          Field("text", "teams_allowed_users", "Allowed Teams user(s)", "your AAD id / name"))),
    Step("Trusted apps",
         "Stop the memory/behaviour scanners from flagging the everyday programs "
         "you run (browsers, Electron apps, etc.).",
         (Field("action", "trust_running", "Trust the apps I'm running now"),)),
    Step("Startup & responsiveness",
         "Launch Angerona at logon, and start in Eco Mode (heavy scanners paused) "
         "for a fast, responsive boot.",
         (Field("check", "autostart_enabled", "Start Angerona with Windows"),
          Field("check", "eco_mode", "Start in Eco Mode"))),
    Step("You're set",
         "That's it — you can revisit any of this in Settings. Want a quick guided "
         "tour of the dashboard? Finish, then press 'Take the tour' on the header "
         "(❔ HELP ▸ Tour)."),
)


def collect(step: Step, values: dict) -> dict:
    """Given a step and a {key: raw_value} map from the UI, return the subset of
    Config assignments to apply (pure; used by the dialog and by tests)."""
    out: dict[str, Any] = {}
    for f in step.fields:
        if f.kind == "action" or f.kind == "password_env":
            continue
        if f.key in values:
            out[f.key] = values[f.key]
    return out


def self_test() -> "tuple[bool, str]":
    try:
        assert len(STEPS) >= 6, "has multiple steps"
        keys = [f.key for s in STEPS for f in s.fields]
        # every config-bound field maps to a known Config attribute
        from angerona.core.config import Config
        cfg = Config()
        for s in STEPS:
            for f in s.fields:
                if f.kind in ("check", "text", "combo"):
                    assert hasattr(cfg, f.key), f"Config has {f.key}"
        # collect() picks up editable fields, skips actions/secrets
        appearance = next(s for s in STEPS if s.title == "Appearance")
        got = collect(appearance, {"theme": "slate", "accent": "#123456"})
        assert got == {"theme": "slate", "accent": "#123456"}, "collect returns edits"
        teams = next(s for s in STEPS if "Teams" in s.title)
        got2 = collect(teams, {"teams_app_id": "abc", "ANGERONA_TEAMS_APP_PASSWORD": "s"})
        assert "ANGERONA_TEAMS_APP_PASSWORD" not in got2, "secret not in config assignments"
        return True, (f"{len(STEPS)} steps; {len(keys)} fields; all config-bound fields exist "
                      "on Config; collect() applies edits and never returns the .env secret.")
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Qt dialog (import-guarded) ────────────────────────────────────────────────
try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel,
                                   QLineEdit, QPushButton, QStackedWidget, QVBoxLayout,
                                   QWidget)
    _HAVE_QT = True
except Exception:  # pragma: no cover
    _HAVE_QT = False


if _HAVE_QT:

    class SetupWizard(QDialog):
        """Multi-step setup dialog. Reads Config, writes it back on Finish."""

        def __init__(self, config, apply_theme_fn=None, trust_running_fn=None, parent=None):
            super().__init__(parent)
            self._cfg = config
            self._apply_theme = apply_theme_fn
            self._trust_running = trust_running_fn
            self._widgets: list[dict] = []     # per-step {key: widget}
            self.launch_tour = False

            self.setWindowTitle("Angerona — Setup")
            self.setMinimumWidth(560)
            self.setModal(True)
            root = QVBoxLayout(self)

            self._stack = QStackedWidget()
            root.addWidget(self._stack, 1)
            for step in STEPS:
                self._stack.addWidget(self._build_page(step))

            self._progress = QLabel("")
            self._progress.setStyleSheet("color:#94a3b8; font-size:11px;")
            root.addWidget(self._progress)

            row = QHBoxLayout()
            self._back = QPushButton("← Back")
            self._skip = QPushButton("Skip")
            self._next = QPushButton("Next →")
            self._back.clicked.connect(lambda: self._go(-1))
            self._skip.clicked.connect(lambda: self._go(+1, apply=False))
            self._next.clicked.connect(lambda: self._go(+1, apply=True))
            row.addWidget(self._back)
            row.addStretch()
            row.addWidget(self._skip)
            row.addWidget(self._next)
            root.addLayout(row)
            self._sync()

        def _build_page(self, step: Step) -> QWidget:
            w = QWidget()
            lay = QVBoxLayout(w)
            title = QLabel(step.title)
            title.setStyleSheet("font-size:18px; font-weight:800;")
            lay.addWidget(title)
            intro = QLabel(step.intro)
            intro.setWordWrap(True)
            intro.setStyleSheet("color:#cbd5e1;")
            lay.addWidget(intro)
            wmap: dict = {}
            for f in step.fields:
                if f.kind == "check":
                    cb = QCheckBox(f.label)
                    cb.setChecked(bool(getattr(self._cfg, f.key, False)))
                    lay.addWidget(cb)
                    wmap[f.key] = cb
                elif f.kind == "combo":
                    lay.addWidget(QLabel(f.label))
                    combo = QComboBox()
                    combo.addItems(list(f.options))
                    cur = str(getattr(self._cfg, f.key, ""))
                    i = combo.findText(cur)
                    if i >= 0:
                        combo.setCurrentIndex(i)
                    lay.addWidget(combo)
                    wmap[f.key] = combo
                elif f.kind == "text":
                    lay.addWidget(QLabel(f.label))
                    le = QLineEdit(str(getattr(self._cfg, f.key, "")))
                    le.setPlaceholderText(f.placeholder)
                    lay.addWidget(le)
                    wmap[f.key] = le
                elif f.kind == "password_env":
                    lay.addWidget(QLabel(f.label))
                    le = QLineEdit()
                    le.setEchoMode(QLineEdit.Password)
                    le.setPlaceholderText("stored in .env — never in settings.json")
                    lay.addWidget(le)
                    wmap[("ENV", f.key)] = le
                elif f.kind == "action":
                    btn = QPushButton(f.label)
                    btn.clicked.connect(lambda _=False, fid=f.key: self._do_action(fid))
                    lay.addWidget(btn)
                if f.note:
                    n = QLabel(f.note)
                    n.setWordWrap(True)
                    n.setStyleSheet("color:#94a3b8; font-size:11px;")
                    lay.addWidget(n)
            lay.addStretch()
            self._widgets.append(wmap)
            return w

        def _do_action(self, action_id: str) -> None:
            if action_id == "trust_running" and callable(self._trust_running):
                try:
                    self._trust_running()
                    self._progress.setText("Trusted your currently-running apps.")
                except Exception as exc:
                    self._progress.setText(f"Could not trust apps: {exc}")

        def _apply_page(self, idx: int) -> None:
            wmap = self._widgets[idx]
            from angerona.core.config import write_env_keys
            for key, widget in wmap.items():
                try:
                    if isinstance(key, tuple) and key[0] == "ENV":
                        val = widget.text()
                        if val:
                            write_env_keys({key[1]: val})
                    elif isinstance(widget, QCheckBox):
                        setattr(self._cfg, key, widget.isChecked())
                    elif isinstance(widget, QComboBox):
                        setattr(self._cfg, key, widget.currentText())
                    elif isinstance(widget, QLineEdit):
                        setattr(self._cfg, key, widget.text().strip())
                except Exception:
                    pass

        def _go(self, delta: int, apply: bool = True) -> None:
            idx = self._stack.currentIndex()
            if delta > 0 and apply:
                self._apply_page(idx)
            nxt = idx + delta
            if nxt >= len(STEPS):
                return self._finish()
            if nxt < 0:
                return
            self._stack.setCurrentIndex(nxt)
            self._sync()

        def _sync(self) -> None:
            idx = self._stack.currentIndex()
            self._progress.setText(f"Step {idx + 1} of {len(STEPS)}")
            self._back.setEnabled(idx > 0)
            self._next.setText("Finish ✓" if idx == len(STEPS) - 1 else "Next →")
            self._skip.setVisible(idx not in (0, len(STEPS) - 1))

        def _finish(self) -> None:
            try:
                if self._apply_theme:
                    self._apply_theme(self._cfg.theme)
            except Exception:
                pass
            try:
                self._cfg.save()
            except Exception:
                pass
            self.accept()


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[setup_wizard] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
