"""upgrade_console.py — Advanced Management Console.

A tabbed operator console adapted from the mobile "Angerona GUI Upgrades" drop
and wired into the real suite:

  * Mobile Integration — configure host/operator/PIN + notification window,
    persist to ``.env`` via ``config.write_env_keys``, and run a real delivery
    test through the mobile bridge when one is available.
  * AI Sandbox & Models — store custom-provider API keys to ``.env`` (never
    hard-coded), check/switch the local Ollama model, and push AI-proposed code
    into a chosen sandbox file (operator picks the file; confirmation required).
  * Watchdog Hub / Telemetry Hub — LIVE module health + recent bus events pulled
    from the running ModuleManager/EventBus. When the console is opened
    standalone (no manager), the panels say so plainly instead of showing
    fabricated numbers.

Launch: ``launch_upgrade_console(manager, config, bus, parent)`` — mirrors
``launch_sandbox_editor``. All widgets tolerate a None manager/bus/config so the
window also runs standalone for layout work.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QSlider, QTextEdit, QVBoxLayout, QWidget,
)

# Env keys this console reads/writes (persisted to .env by config.write_env_keys).
_ENV_MOBILE = {
    "host": "ANGERONA_MOBILE_HOST",
    "operator": "ANGERONA_MOBILE_OPERATOR",
    "pin": "ANGERONA_MOBILE_PIN",
    "window": "ANGERONA_MOBILE_NOTIFY_WINDOW",
}
_PROVIDER_ENV = {
    "OpenAI Custom": "OPENAI_API_KEY",
    "Anthropic Custom": "ANTHROPIC_API_KEY",
    "HuggingFace Local": "HUGGINGFACE_API_KEY",
    "Groq": "GROQ_API_KEY",
    "Google Gemini": "GOOGLE_API_KEY",
}


class AngeronaUpgradeConsole(QMainWindow):
    def __init__(self, manager=None, config=None, bus=None, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.config = config
        self.bus = bus
        self.setWindowTitle("Project Angerona — Advanced Management Console")
        self.resize(860, 620)

        from PySide6.QtWidgets import QTabWidget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._init_mobile_tab()
        self._init_ai_sandbox_tab()
        self._init_watchdog_tab()
        self._init_telemetry_tab()

    # ── helpers ──────────────────────────────────────────────────────────────
    def _persist_env(self, updates: dict) -> bool:
        """Persist KEY=VALUE pairs to .env via the canonical config helper if
        available; always mirror into os.environ so modules pick them up live."""
        updates = {k: v for k, v in updates.items() if v}
        for k, v in updates.items():
            os.environ[k] = v
        try:
            from angerona.core.config import write_env_keys
            write_env_keys(updates)
            return True
        except Exception:
            return False   # env still updated live, just not persisted

    def _data_dir(self) -> Path:
        try:
            return Path(getattr(self.config, "data_dir", None) or os.getcwd())
        except Exception:
            return Path(os.getcwd())

    # ── 1. Mobile Integration ────────────────────────────────────────────────
    def _init_mobile_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)

        inst = QGroupBox("Mobile Installation & Path Setup")
        il = QVBoxLayout(inst)
        il.addWidget(QLabel(
            "1. Map the notification transport (ntfy / Pushover / Signal / SMS gateway).\n"
            "2. Enter the Host Number and destination Operator identifier.\n"
            "3. Enter the Hardware PIN / device code for the local security module.\n"
            "4. Use 'Test Mobile Integration' to send a real test alert and confirm delivery."))
        layout.addWidget(inst)

        form = QGroupBox("Configuration"); fl = QFormLayout(form)
        self.host_num_input = QLineEdit(os.environ.get(_ENV_MOBILE["host"], ""))
        self.operator_dest_input = QLineEdit(os.environ.get(_ENV_MOBILE["operator"], ""))
        self.hardware_pin_input = QLineEdit(os.environ.get(_ENV_MOBILE["pin"], ""))
        self.hardware_pin_input.setEchoMode(QLineEdit.Password)
        self.noti_time_input = QLineEdit(os.environ.get(_ENV_MOBILE["window"], "00:00-24:00"))
        fl.addRow("Host Number:", self.host_num_input)
        fl.addRow("Operator Destination:", self.operator_dest_input)
        fl.addRow("Hardware PIN / Code:", self.hardware_pin_input)
        fl.addRow("Notification Window:", self.noti_time_input)
        layout.addWidget(form)

        row = QHBoxLayout()
        test_btn = QPushButton("Test Mobile Integration"); test_btn.clicked.connect(self._test_mobile)
        save_btn = QPushButton("Save Notification Settings"); save_btn.clicked.connect(self._save_mobile)
        row.addWidget(test_btn); row.addWidget(save_btn)
        layout.addLayout(row)

        self.tabs.addTab(tab, "Mobile Integration")

    def _save_mobile(self):
        persisted = self._persist_env({
            _ENV_MOBILE["host"]: self.host_num_input.text().strip(),
            _ENV_MOBILE["operator"]: self.operator_dest_input.text().strip(),
            _ENV_MOBILE["pin"]: self.hardware_pin_input.text().strip(),
            _ENV_MOBILE["window"]: self.noti_time_input.text().strip(),
        })
        QMessageBox.information(self, "Saved",
                               "Notification settings saved to .env." if persisted
                               else "Settings applied for this session (could not write .env).")

    def _test_mobile(self):
        if not self.host_num_input.text().strip() or not self.hardware_pin_input.text().strip():
            QMessageBox.critical(self, "Test Failed",
                                 "Reason: missing Hardware PIN or Host Number.\n"
                                 "Fix: provide a valid destination and PIN, then retry.")
            return
        # Try a real send through whatever mobile bridge the suite exposes.
        sent, detail = self._try_mobile_send()
        if sent:
            QMessageBox.information(self, "Test Passed",
                                   f"Status: PASS\n{detail}")
        else:
            QMessageBox.warning(self, "Test Inconclusive",
                                f"Status: NOT SENT\nReason: {detail}\n"
                                "Fix: confirm the mobile bridge is configured/enabled, then retry.")

    def _try_mobile_send(self) -> tuple[bool, str]:
        """Best-effort real delivery via the suite's mobile bridge module."""
        msg = "Angerona test alert — mobile integration check."
        # Preferred: a live module instance from the manager.
        try:
            mods = getattr(self.manager, "modules", {}) or {}
            for m in mods.values():
                for meth in ("send_test", "send_alert", "notify", "send"):
                    fn = getattr(m, meth, None)
                    if callable(fn) and "mobile" in type(m).__module__.lower():
                        fn(msg)
                        return True, "Test notification dispatched via mobile bridge."
        except Exception as exc:
            return False, f"mobile bridge error: {exc}"
        # Fallback: import the module directly.
        try:
            from angerona.modules import mobile_bridge  # type: ignore
            for meth in ("send_test", "send_alert", "notify", "send"):
                fn = getattr(mobile_bridge, meth, None)
                if callable(fn):
                    fn(msg)
                    return True, "Test notification dispatched via mobile_bridge."
        except Exception:
            pass
        return False, "no mobile bridge available/enabled in this session"

    # ── 2. AI Sandbox & Models ───────────────────────────────────────────────
    def _init_ai_sandbox_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)

        keyg = QGroupBox("AI Provider & Custom API Keys"); kl = QFormLayout(keyg)
        self.custom_provider = QComboBox()
        self.custom_provider.addItems(["Ollama (Local)"] + list(_PROVIDER_ENV.keys()))
        self.api_key_input = QLineEdit(); self.api_key_input.setEchoMode(QLineEdit.Password)
        save_key_btn = QPushButton("Save API Key"); save_key_btn.clicked.connect(self._save_api_key)
        kl.addRow("Provider:", self.custom_provider)
        kl.addRow("API Key / Endpoint Token:", self.api_key_input)
        kl.addRow("", save_key_btn)
        layout.addWidget(keyg)

        modg = QGroupBox("Local LLM Control (Ollama)"); ml = QHBoxLayout(modg)
        self.model_box = QComboBox(); self.model_box.setEditable(True)
        self.model_box.addItems(self._list_ollama_models())
        check_btn = QPushButton("Check for Updates"); check_btn.clicked.connect(self._check_model)
        ml.addWidget(QLabel("Model:")); ml.addWidget(self.model_box); ml.addWidget(check_btn)
        layout.addWidget(modg)

        sbg = QGroupBox("AI Sandbox — Implement Code"); sl = QVBoxLayout(sbg)
        self.ai_proposed_code = QTextEdit()
        self.ai_proposed_code.setPlaceholderText("# Paste AI-generated solution code here...")
        impl_btn = QPushButton("Implement Code into a Sandbox File…")
        impl_btn.setStyleSheet("background-color: #2b579a; color: white; font-weight: bold;")
        impl_btn.clicked.connect(self._implement_code)
        sl.addWidget(QLabel("AI Proposed Code:")); sl.addWidget(self.ai_proposed_code); sl.addWidget(impl_btn)
        layout.addWidget(sbg)

        self.tabs.addTab(tab, "AI Sandbox & Models")

    def _save_api_key(self):
        provider = self.custom_provider.currentText()
        key = self.api_key_input.text().strip()
        env = _PROVIDER_ENV.get(provider)
        if provider.startswith("Ollama"):
            QMessageBox.information(self, "Local Provider",
                                   "Ollama runs locally at 127.0.0.1:11434 — no API key required.")
            return
        if not env or not key:
            QMessageBox.warning(self, "Nothing Saved", "Select a cloud provider and enter a key.")
            return
        ok = self._persist_env({env: key})
        self.api_key_input.clear()
        QMessageBox.information(self, "Saved",
                               f"{provider} key saved to .env as {env}." if ok
                               else f"{provider} key applied for this session (could not write .env).")

    def _list_ollama_models(self) -> list:
        try:
            import json, urllib.request
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            names = [m.get("name") for m in data.get("models", []) if m.get("name")]
            if names:
                return names
        except Exception:
            pass
        return ["llama3:8b", "mistral:7b", "phi3:latest"]

    def _check_model(self):
        model = self.model_box.currentText().strip()
        try:
            import json, urllib.request
            req = urllib.request.Request("http://127.0.0.1:11434/api/show",
                                         data=json.dumps({"name": model}).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as r:
                r.read()
            QMessageBox.information(self, "Model Status",
                                   f"'{model}' is installed locally. To update, run:\n"
                                   f"    ollama pull {model}")
        except Exception:
            QMessageBox.warning(self, "Model Status",
                               f"Could not reach Ollama or '{model}' is not installed.\n"
                               f"Install/update with:\n    ollama pull {model}")

    def _implement_code(self):
        code = self.ai_proposed_code.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "Nothing to Implement", "The code window is empty.")
            return
        default = str(self._data_dir() / "sandbox_full.py")
        path, _ = QFileDialog.getSaveFileName(self, "Choose sandbox file to append to",
                                              default, "Python (*.py)")
        if not path:
            return
        if QMessageBox.question(
                self, "Confirm", f"Append the proposed code to:\n{path}?") != QMessageBox.Yes:
            return
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"\n\n# --- Implemented via Advanced Console {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                f.write(code + "\n")
            QMessageBox.information(self, "Implemented", f"Code appended to {path}.")
            self.ai_proposed_code.clear()
        except Exception as exc:
            QMessageBox.critical(self, "Write Error", f"Could not write to target file:\n{exc}")

    # ── 3. Watchdog Hub (live) ───────────────────────────────────────────────
    def _init_watchdog_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        g = QGroupBox("Watchdog / Supervisor Status"); self._wd_form = QFormLayout(g)
        self._wd_status = QLabel("—")
        self._wd_form.addRow("Supervisor module:", self._wd_status)
        layout.addWidget(g)

        lg = QGroupBox("Recent Events"); ll = QVBoxLayout(lg)
        self.wd_logs = QTextEdit(); self.wd_logs.setReadOnly(True)
        ll.addWidget(self.wd_logs); layout.addWidget(lg)

        self.tabs.addTab(tab, "Watchdog Hub")
        self._refresh_watchdog()
        self._wd_timer = QTimer(self); self._wd_timer.timeout.connect(self._refresh_watchdog)
        self._wd_timer.start(3000)

    # ── live ecosystem diagnostics helpers ───────────────────────────────────
    def _eco_status(self, component):
        """Read a resilience component's status_<component>.json, if present."""
        try:
            import json
            from angerona.resilience import diagnostics as _diag
            return json.loads((_diag.diag_dir() / f"status_{component}.json").read_text(encoding="utf-8"))
        except Exception:
            return None

    def _eco_hb(self, component):
        """Classify a resilience component's heartbeat (alive/suspended/dead/...)."""
        try:
            from angerona.resilience import heartbeat as _hb
            return _hb.HeartbeatReader(component).classify(stale_after_s=3.0)
        except Exception:
            return "unknown"

    def _refresh_watchdog(self):
        # Prefer the standalone ecosystem: heartbeat + status diagnostic.
        st = self._eco_status("watchdog")
        hbst = self._eco_hb("watchdog")
        core_st = self._eco_status("core")
        if st or hbst not in ("unknown", "dead") or core_st:
            wd_line = (f"heartbeat={hbst}, pid={(st or {}).get('pid','?')}, "
                       f"rss={(st or {}).get('rss_mb','?')}MB, state={(st or {}).get('state','?')}"
                       if (st or hbst != "unknown")
                       else "no standalone watchdog running (build the Go watchdog binary)")
            self._wd_status.setText(wd_line)
            if core_st:
                self.wd_logs.append(f"core: frames_ingested={core_st.get('frames_ingested','?')}, "
                                    f"supervised={core_st.get('supervised')}, "
                                    f"safe_mode={core_st.get('safe_mode')}")
            return
        # Fall back to the in-process module view.
        mods = getattr(self.manager, "modules", None)
        if not mods:
            self._wd_status.setText("No standalone watchdog running and no live manager connected.")
            return
        wd = None
        for name, m in mods.items():
            if "watchdog" in name.lower() or "watchdog" in type(m).__module__.lower():
                wd = (name, m); break
        if wd:
            name, m = wd
            self._wd_status.setText(f"{name}: status={getattr(m,'status','?')}, "
                                    f"health={getattr(m,'health','?')}%")
        else:
            self._wd_status.setText(f"{len(mods)} modules supervised (no dedicated watchdog module found).")

    # ── 4. Telemetry Hub (live) ──────────────────────────────────────────────
    def _init_telemetry_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        mg = QGroupBox("Sensor Telemetry (live)"); grid = QGridLayout(mg)
        grid.addWidget(QLabel("Modules running:"), 0, 0); self._t_running = QLabel("—"); grid.addWidget(self._t_running, 0, 1)
        grid.addWidget(QLabel("Bus events (ring):"), 0, 2); self._t_events = QLabel("—"); grid.addWidget(self._t_events, 0, 3)
        layout.addWidget(mg)

        tg = QGroupBox("Resource Boundary Hints (advisory)"); tl = QFormLayout(tg)
        cpu = QSlider(Qt.Horizontal); cpu.setRange(5, 50); cpu.setValue(20)
        ram = QSlider(Qt.Horizontal); ram.setRange(50, 500); ram.setValue(250)
        tl.addRow("Max CPU target (%):", cpu); tl.addRow("Max memory hint (MB):", ram)
        layout.addWidget(tg)

        sg = QGroupBox("Live Event Stream"); sl = QVBoxLayout(sg)
        self.term_stream = QTextEdit(); self.term_stream.setReadOnly(True)
        self.term_stream.setStyleSheet("background-color: #0b0b0b; color: #00ff88; font-family: Consolas, monospace;")
        sl.addWidget(self.term_stream); layout.addWidget(sg)

        self.tabs.addTab(tab, "Telemetry Hub")
        self._last_ts = 0.0
        self._t_timer = QTimer(self); self._t_timer.timeout.connect(self._refresh_telemetry)
        self._t_timer.start(1500)

    def _refresh_telemetry(self):
        # Live standalone scanner status takes priority if the ecosystem is up.
        sc = self._eco_status("scanner") if hasattr(self, "_eco_status") else None
        if sc:
            self._t_running.setText(f"scanner {sc.get('state','?')} "
                                    f"(pid {sc.get('pid','?')}, {sc.get('rss_mb','?')}MB)")
            self._t_events.setText(f"fwd={sc.get('events_forwarded','?')} "
                                   f"drop={sc.get('dropped','?')} "
                                   f"bp={sc.get('ring_backpressure','?')}")
            return
        mods = getattr(self.manager, "modules", None)
        if mods:
            running = sum(1 for m in mods.values() if getattr(m, "status", "") == "running")
            self._t_running.setText(f"{running}/{len(mods)}")
        else:
            self._t_running.setText("n/a (standalone)")
        if self.bus is not None:
            try:
                recent = self.bus.recent(50)
                self._t_events.setText(str(len(recent)))
                for ev in recent:
                    if getattr(ev, "ts", 0) > self._last_ts:
                        self._last_ts = ev.ts
                        self.term_stream.append(
                            f"[{getattr(ev,'time_str','')}] {getattr(ev,'module','')}: {getattr(ev,'message','')}")
            except Exception:
                self._t_events.setText("n/a")
        else:
            self._t_events.setText("n/a (no bus)")


def launch_upgrade_console(manager=None, config=None, bus=None, parent=None) -> AngeronaUpgradeConsole:
    """Embed entry point: build + show the console over an existing app.
    Mirrors ``launch_sandbox_editor``. Tolerates None manager/config/bus."""
    win = AngeronaUpgradeConsole(manager=manager, config=config, bus=bus, parent=parent)
    win.show()
    return win


def _standalone() -> int:
    app = QApplication.instance() or QApplication([])
    try:
        from angerona.core.config import Config
        cfg = Config()
    except Exception:
        cfg = None
    win = AngeronaUpgradeConsole(config=cfg)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(_standalone())
