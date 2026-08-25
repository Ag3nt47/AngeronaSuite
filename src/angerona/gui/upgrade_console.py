"""upgrade_console.py — Advanced Management Console.

A tabbed operator console adapted from the mobile "Angerona GUI Upgrades" drop
and wired into the real suite:

  * Mobile Integration — show privacy-minimized readiness, route configuration
    to canonical Settings, and run an operator-confirmed delivery test.
  * AI Sandbox & Models — show read-only provider readiness, route credential
    changes to canonical Settings, check/switch the local Ollama model, and push
    AI-proposed code into an operator-chosen sandbox file.
  * Watchdog Hub / Telemetry Hub — LIVE module health + recent bus events pulled
    from the running ModuleManager/EventBus. When the console is opened
    standalone (no manager), the panels say so plainly instead of showing
    fabricated numbers.

Launch: ``launch_upgrade_console(manager, config, bus, parent)`` — mirrors
``launch_sandbox_editor``. All widgets tolerate a None manager/bus/config so the
window also runs standalone for layout work.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox,
    QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPushButton,
    QSlider, QTextEdit, QVBoxLayout, QWidget,
)

from angerona.gui.animations import begin_loading, finish_loading

_UPGRADE_UI_POOL: QThreadPool | None = None


def _upgrade_ui_pool() -> QThreadPool:
    """Return a pool reserved for bounded, operator-facing console requests.

    Scanner and telemetry work uses Qt's global pool elsewhere in the suite.
    Keeping the two console request slots separate prevents a busy global pool
    from delaying model discovery or a model check indefinitely.  The pool has
    module lifetime so deleting a console never waits for its request.
    """
    global _UPGRADE_UI_POOL
    if _UPGRADE_UI_POOL is None:
        pool = QThreadPool()
        pool.setMaxThreadCount(2)
        pool.setExpiryTimeout(10_000)
        _UPGRADE_UI_POOL = pool
    return _UPGRADE_UI_POOL


class _UpgradeWorkerBridge(QObject):
    """Keep worker result delivery alive until every submitted job finishes.

    The console can be deleted while a request is still running.  Parenting this
    bridge to the application, rather than the console or QRunnable, gives the
    signal source a stable lifetime.  Qt automatically drops the connection to
    a deleted console, and the bridge deletes itself after its final job.
    """

    _worker_finished = Signal(str, int, object)
    result_ready = Signal(str, int, object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pending = 0
        self._console_closed = False
        self._worker_finished.connect(
            self._deliver_result,
            Qt.ConnectionType.QueuedConnection,
        )

    def track_submission(self) -> None:
        self._pending += 1

    def submission_failed(self, operation: str, token: int, result: object) -> None:
        """Balance a job that the thread pool rejected before it could run."""
        self._complete_one(operation, token, result)

    def console_closed(self) -> None:
        self._console_closed = True
        self._delete_when_idle()

    @Slot(str, int, object)
    def _deliver_result(self, operation: str, token: int, result: object) -> None:
        self._complete_one(operation, token, result)

    def _complete_one(self, operation: str, token: int, result: object) -> None:
        self._pending = max(0, self._pending - 1)
        # Emitting remains safe after the console is deleted: Qt disconnects a
        # destroyed receiver automatically, while this bridge remains alive.
        self.result_ready.emit(operation, token, result)
        self._delete_when_idle()

    def _delete_when_idle(self) -> None:
        if self._console_closed and self._pending == 0:
            self.deleteLater()


class _UpgradeWorker(QRunnable):
    """One-shot background call whose result is routed back through Qt."""

    def __init__(
        self,
        operation: str,
        token: int,
        call: Callable,
        bridge: _UpgradeWorkerBridge,
        *args,
    ) -> None:
        super().__init__()
        self._operation = operation
        self._token = token
        self._call = call
        self._args = args
        self._bridge = bridge

    @Slot()
    def run(self) -> None:
        try:
            result = self._call(*self._args)
        except Exception as exc:
            result = {"error": str(exc)}
        try:
            self._bridge._worker_finished.emit(
                self._operation,
                self._token,
                result,
            )
        except RuntimeError:
            # QApplication shutdown may destroy the bridge while a bounded
            # network call is still unwinding.  There is no UI left to update.
            pass


class AngeronaUpgradeConsole(QMainWindow):
    def __init__(
        self,
        manager=None,
        config=None,
        bus=None,
        parent=None,
        *,
        model_pack_manager=None,
        pack_change_callback: Callable[[], object] | None = None,
    ):
        super().__init__(parent)
        self.manager = manager
        self.config = config
        self.bus = bus
        self._async_pool = _upgrade_ui_pool()
        self._async_bridge = _UpgradeWorkerBridge(QApplication.instance())
        self._async_bridge.result_ready.connect(self._handle_async_result)
        self._accept_async_results = True
        self._async_token = 0
        self._pack_change_callback = pack_change_callback
        self.model_pack_manager = (
            model_pack_manager or self._build_model_pack_manager()
        )
        self._pack_status_in_flight = False
        self._pack_status_token = 0
        self._pack_operation_in_flight = False
        self._pack_operation_token = 0
        self._pack_operation_name = ""
        self._watchdog_refresh_in_flight = False
        self._watchdog_refresh_token = 0
        self._telemetry_refresh_in_flight = False
        self._telemetry_refresh_token = 0
        self._pack_snapshot: dict = {}
        self._loading_tokens: dict[tuple[str, int], str] = {}
        self.setWindowTitle("Project Angerona — Advanced Management Console")
        self.resize(860, 620)

        from PySide6.QtWidgets import QTabWidget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._init_mobile_tab()
        self._init_ai_sandbox_tab()
        self._init_watchdog_tab()
        self._init_telemetry_tab()
        from angerona.gui.context_info import attach_context_info
        self._context_info = attach_context_info(
            self.tabs, "advanced-console"
        )

    # ── helpers ──────────────────────────────────────────────────────────────
    def _data_dir(self) -> Path:
        try:
            from angerona.core.data_paths import data_dir
            return Path(getattr(self.config, "data_dir", None) or data_dir())
        except Exception:
            from angerona.core.data_paths import data_dir
            return data_dir()

    def _build_model_pack_manager(self):
        from angerona.core.model_pack_manager import ModelPackManager

        def update_model(model: str) -> None:
            if self.config is None:
                raise RuntimeError("configuration is unavailable")
            self.config.ollama_model = model
            self.config.save()

        return ModelPackManager(
            data_dir=self._data_dir(),
            ollama_host=str(
                getattr(self.config, "ollama_host", "http://localhost:11434")
            ),
            config_current=lambda: str(
                getattr(self.config, "ollama_model", "llama3")
            ),
            config_update=update_model,
        )

    # ── 1. Mobile Integration ────────────────────────────────────────────────
    def _init_mobile_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)

        status_box = QGroupBox("Mobile Response Bridge (read-only status)")
        status_layout = QVBoxLayout(status_box)
        enabled = bool(getattr(self.config, "mobile_enabled", False))
        cli_ready = bool(str(
            getattr(self.config, "mobile_signal_cli", "") or ""
        ).strip())
        destination_ready = bool(str(
            getattr(self.config, "mobile_dest_number", "") or ""
        ).strip())
        status_info = QLabel(
            "Configuration is owned only by Settings > Mobile Integration. "
            "This operations view never displays phone numbers, group IDs, "
            "PINs, tokens, or transport secrets."
        )
        status_info.setWordWrap(True)
        status_layout.addWidget(status_info)
        for label, ready in (
            ("Bridge enabled", enabled),
            ("Signal client configured", cli_ready),
            ("Destination configured", destination_ready),
        ):
            value = QLabel(f"{'PASS' if ready else 'NOT SET'}  {label}")
            value.setStyleSheet("color:#22c55e;" if ready else "color:#94a3b8;")
            status_layout.addWidget(value)
        layout.addWidget(status_box)

        row = QHBoxLayout()
        open_settings = QPushButton("Open Settings > Mobile Integration")
        open_settings.clicked.connect(
            lambda: self._open_settings_tab("Mobile Integration")
        )
        test_btn = QPushButton("Send confirmed test notification")
        test_btn.setEnabled(enabled and cli_ready and destination_ready)
        test_btn.clicked.connect(self._test_mobile)
        row.addWidget(open_settings)
        row.addWidget(test_btn)
        layout.addLayout(row)
        layout.addStretch()
        self.tabs.addTab(tab, "Mobile Integration")

    def _test_mobile(self):
        answer = QMessageBox.question(
            self,
            "Send test notification?",
            "This explicitly sends one test message to the configured mobile "
            "destination. No event evidence is included. Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        sent, detail = self._try_mobile_send()
        if sent:
            QMessageBox.information(self, "Test Passed", f"Status: PASS\n{detail}")
        else:
            QMessageBox.warning(
                self,
                "Test Inconclusive",
                f"Status: NOT SENT\nReason: {detail}\n"
                "Fix: confirm the mobile bridge is configured/enabled, then retry.",
            )
        return

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

        keyg = QGroupBox("Cloud Provider Credentials (read-only)")
        kl = QVBoxLayout(keyg)
        key_info = QLabel(
            "Credential editing is centralized in Settings ▸ API Keys. "
            "This console shows readiness without revealing secret values."
        )
        key_info.setWordWrap(True)
        kl.addWidget(key_info)
        from angerona.core.provider_credentials import (
            PROVIDER_CREDENTIALS,
            credential_values,
        )
        for provider in PROVIDER_CREDENTIALS:
            configured = bool(credential_values(provider.provider_id))
            status = QLabel(
                f"{'✓' if configured else '○'}  {provider.label}: "
                f"{'configured' if configured else 'not configured'}"
            )
            status.setStyleSheet(
                "color:#22c55e;" if configured else "color:#94a3b8;"
            )
            kl.addWidget(status)
        open_keys = QPushButton("Open Settings ▸ API Keys")
        open_keys.clicked.connect(self._open_api_key_settings)
        kl.addWidget(open_keys)
        layout.addWidget(keyg)

        modg = QGroupBox("Governed ARIA Model & Runbook Packs")
        pack_layout = QVBoxLayout(modg)
        pack_help = QLabel(
            "Only bundled, digest-pinned, data-only defensive packs are shown. "
            "Angerona verifies resource admission and the Ollama manifest; this "
            "console accepts no custom model name, URL, Modelfile, or command."
        )
        pack_help.setWordWrap(True)
        pack_layout.addWidget(pack_help)
        choose = QHBoxLayout()
        self.model_box = QComboBox()
        self.model_box.setEditable(False)
        for pack_id, pack in sorted(self.model_pack_manager.catalog.items()):
            self.model_box.addItem(f"{pack.title} ({pack.version})", pack_id)
        self.model_box.currentIndexChanged.connect(self._refresh_pack_selection)
        choose.addWidget(QLabel("Curated pack:"))
        choose.addWidget(self.model_box, 1)
        pack_layout.addLayout(choose)
        self._model_status = QLabel("Loading curated pack admission and status…")
        self._model_status.setWordWrap(True)
        self._model_status.setStyleSheet("color:#93c5fd;")
        pack_layout.addWidget(self._model_status)
        self._pack_plan = QTextEdit()
        self._pack_plan.setReadOnly(True)
        self._pack_plan.setMaximumHeight(132)
        self._pack_plan.setPlaceholderText("Admission details will appear here.")
        pack_layout.addWidget(self._pack_plan)
        actions = QHBoxLayout()
        self._pack_install_btn = QPushButton("Install")
        self._pack_activate_btn = QPushButton("Activate")
        self._pack_rollback_btn = QPushButton("Roll Back")
        self._pack_remove_btn = QPushButton("Remove")
        for button, action in (
            (self._pack_install_btn, "install"),
            (self._pack_activate_btn, "activate"),
            (self._pack_rollback_btn, "rollback"),
            (self._pack_remove_btn, "remove"),
        ):
            button.setEnabled(False)
            button.clicked.connect(
                lambda _checked=False, selected=action: self._confirm_pack_operation(
                    selected
                )
            )
            actions.addWidget(button)
        pack_layout.addLayout(actions)
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
        self._start_pack_status()

    def _open_settings_tab(self, tab: str) -> None:
        owner = self.parentWidget()
        while owner is not None:
            show_settings = getattr(owner, "_show_settings", None)
            if callable(show_settings):
                self.close()
                show_settings(tab)
                return
            owner = owner.parentWidget()
        QMessageBox.information(
            self,
            "Open Settings",
            f"Open the main Angerona window, then choose Settings > {tab}.",
        )

    def _open_api_key_settings(self) -> None:
        self._open_settings_tab("API Keys")

    def _model_pack_snapshot(self) -> dict:
        """Read signed state and resource admission off the Qt thread."""
        from dataclasses import asdict

        manager = self.model_pack_manager
        state = manager.state()
        installed = state.get("installed", {})
        batch_plans = getattr(manager, "admission_plans", None)
        plans = (
            batch_plans()
            if callable(batch_plans)
            else {
                pack_id: manager.admission_plan(pack_id)
                for pack_id in manager.catalog
            }
        )
        packs = {}
        for pack_id, pack in sorted(manager.catalog.items()):
            plan = plans[pack_id]
            packs[pack_id] = {
                "id": pack.id,
                "title": pack.title,
                "version": pack.version,
                "description": pack.description,
                "managed_model": pack.model.managed_name,
                "manifest_digest": pack.model.manifest_digest,
                "runbooks": [runbook.title for runbook in pack.runbooks],
                "installed": pack.id in installed,
                "active": state.get("active_pack") == pack.id,
                "admission": asdict(plan),
            }
        return {
            "active_pack": state.get("active_pack"),
            "can_rollback": bool(state.get("activation_history")),
            "packs": packs,
        }

    def _start_pack_status(self) -> None:
        if (
            not self._accept_async_results
            or self._pack_status_in_flight
            or self._pack_operation_in_flight
        ):
            return
        token = self._new_async_token()
        self._pack_status_token = token
        self._pack_status_in_flight = True
        self._set_pack_buttons_enabled(False)
        self._loading_tokens[("pack_status", token)] = begin_loading(
            "Checking governed model-pack admission…"
        )
        worker = _UpgradeWorker(
            "pack_status",
            token,
            self._model_pack_snapshot,
            self._async_bridge,
        )
        self._async_bridge.track_submission()
        try:
            self._async_pool.start(worker)
        except Exception as exc:
            self._async_bridge.submission_failed(
                "pack_status", token, {"error": str(exc)}
            )

    def _selected_pack_id(self) -> str:
        value = self.model_box.currentData()
        return str(value) if isinstance(value, str) else ""

    def _set_pack_buttons_enabled(self, enabled: bool) -> None:
        for button in (
            self._pack_install_btn,
            self._pack_activate_btn,
            self._pack_rollback_btn,
            self._pack_remove_btn,
        ):
            button.setEnabled(enabled)

    def _refresh_pack_selection(self, _index: int | None = None) -> None:
        row = (self._pack_snapshot.get("packs", {}) or {}).get(
            self._selected_pack_id()
        )
        if not isinstance(row, dict):
            self._set_pack_buttons_enabled(False)
            return
        admission = row.get("admission", {})
        deficits = admission.get("deficits", []) if isinstance(admission, dict) else []
        admitted = bool(admission.get("admitted")) if isinstance(admission, dict) else False
        installed = bool(row.get("installed"))
        active = bool(row.get("active"))
        state = "active" if active else "installed" if installed else "not installed"
        admission_text = "admitted" if admitted else "denied"
        self._model_status.setText(
            f"{row.get('id')} — {state}; resource admission {admission_text}."
        )
        requirements = admission.get("requirements", {}) if isinstance(admission, dict) else {}
        available = admission.get("available", {}) if isinstance(admission, dict) else {}
        runbooks = ", ".join(row.get("runbooks", [])) or "none"
        detail = [
            str(row.get("description", "")),
            f"Managed model: {row.get('managed_model', '')}",
            f"Manifest: {row.get('manifest_digest', '')}",
            f"Required bytes: RAM {requirements.get('ram_bytes', '?')}; "
            f"VRAM {requirements.get('vram_bytes', '?')}; "
            f"disk {requirements.get('disk_bytes', '?')}",
            f"Available bytes: RAM {available.get('ram_bytes', '?')}; "
            f"VRAM {available.get('vram_bytes', '?')}; "
            f"disk {available.get('disk_bytes', '?')}",
            f"Runbooks: {runbooks}",
        ]
        if deficits:
            detail.append("Admission deficits: " + "; ".join(map(str, deficits)))
        self._pack_plan.setPlainText("\n".join(detail))
        idle = not self._pack_operation_in_flight and not self._pack_status_in_flight
        self._pack_install_btn.setEnabled(idle and admitted and not installed)
        self._pack_activate_btn.setEnabled(idle and installed and not active)
        self._pack_rollback_btn.setEnabled(
            idle and bool(self._pack_snapshot.get("can_rollback"))
        )
        self._pack_remove_btn.setEnabled(idle and installed and not active)

    def _confirm_pack_operation(self, action: str) -> None:
        pack_id = self._selected_pack_id()
        subject = "the previous governed model" if action == "rollback" else pack_id
        if not subject:
            return
        answer = QMessageBox.question(
            self,
            f"{action.title()} governed pack?",
            f"{action.title()} {subject}? This uses only the bundled curated "
            "catalog and records an authenticated receipt.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._start_pack_operation(action, pack_id)

    def _start_pack_operation(self, action: str, pack_id: str = "") -> bool:
        if not self._accept_async_results or self._pack_operation_in_flight:
            self._model_status.setText("A governed model-pack operation is already running.")
            return False
        if action not in {"install", "activate", "rollback", "remove"}:
            self._model_status.setText("Unknown governed model-pack operation refused.")
            return False
        if action != "rollback" and pack_id not in self.model_pack_manager.catalog:
            self._model_status.setText("Pack ID is not in the trusted bundled catalog.")
            return False
        token = self._new_async_token()
        operation = f"pack_{action}"
        self._pack_operation_token = token
        self._pack_operation_name = operation
        self._pack_operation_in_flight = True
        self._set_pack_buttons_enabled(False)
        self._model_status.setText(f"{action.title()} in progress…")
        self._loading_tokens[(operation, token)] = begin_loading(
            f"{action.title()} governed ARIA model pack…"
        )
        worker = _UpgradeWorker(
            operation,
            token,
            self._run_pack_operation,
            self._async_bridge,
            action,
            pack_id,
        )
        self._async_bridge.track_submission()
        try:
            self._async_pool.start(worker)
        except Exception as exc:
            self._async_bridge.submission_failed(
                operation, token, {"error": str(exc)}
            )
        return True

    def _run_pack_operation(self, action: str, pack_id: str) -> dict:
        manager = self.model_pack_manager
        operations = {
            "install": manager.install,
            "activate": manager.activate,
            "rollback": manager.rollback,
            "remove": manager.remove,
        }
        operation = operations[action]
        receipt = operation() if action == "rollback" else operation(pack_id)
        self._rebuild_pack_runbooks()
        return receipt

    def _rebuild_pack_runbooks(self) -> int:
        """Rebuild data-only runbook search after a successful lifecycle change."""
        # When embedded in the main window, the callback rebuilds and swaps the
        # authoritative ARIA index.  Building a second console-only index first
        # doubled all Markdown reads/parsing and the duplicate was never queried.
        # Standalone consoles still build their own local index below.
        if callable(self._pack_change_callback):
            result = self._pack_change_callback()
            return int(result) if isinstance(result, int) else 0

        from angerona.core.data_paths import project_root
        from angerona.core.runbook_rag import RunbookRAG

        root = project_root()
        roots = [
            str(root / "docs"),
            str(root / "playbooks"),
            str(self._data_dir() / "runbooks"),
            *(str(path) for path in self.model_pack_manager.runbook_roots()),
        ]
        replacement = RunbookRAG(roots)
        count = replacement.build()
        self._pack_rag = replacement
        return count

    def _new_async_token(self) -> int:
        self._async_token += 1
        return self._async_token

    @Slot(str, int, object)
    def _handle_async_result(self, operation: str, token: int, result: object) -> None:
        """Apply worker results on the owning Qt thread only."""
        finish_loading(self._loading_tokens.pop((operation, token), None))
        if operation == "watchdog_status":
            if token != self._watchdog_refresh_token:
                return
            self._watchdog_refresh_in_flight = False
            if self._accept_async_results:
                self._apply_watchdog_snapshot(
                    result if isinstance(result, dict) else {}
                )
            return
        if operation == "telemetry_status":
            if token != self._telemetry_refresh_token:
                return
            self._telemetry_refresh_in_flight = False
            if self._accept_async_results:
                self._apply_telemetry_snapshot(
                    result if isinstance(result, dict) else {}
                )
            return
        if operation == "pack_status":
            if token != self._pack_status_token:
                return
            self._pack_status_in_flight = False
            if not self._accept_async_results:
                return
            if isinstance(result, dict) and "error" in result:
                self._model_status.setText(
                    f"Governed pack status unavailable: {result['error']}"
                )
                self._set_pack_buttons_enabled(False)
                return
            self._pack_snapshot = result if isinstance(result, dict) else {}
            self._refresh_pack_selection()
            return
        if not operation.startswith("pack_") or token != self._pack_operation_token:
            return
        if operation != self._pack_operation_name:
            return
        self._pack_operation_in_flight = False
        if not self._accept_async_results:
            return
        if isinstance(result, dict) and "error" in result:
            self._model_status.setText(f"Operation refused or failed: {result['error']}")
            self._refresh_pack_selection()
            return
        action = operation.removeprefix("pack_")
        self._model_status.setText(
            f"{action.title()} completed with an authenticated receipt. Refreshing status…"
        )
        self._start_pack_status()

    def closeEvent(self, event) -> None:
        """Ignore late worker results and stop periodic refreshes after close."""
        self._accept_async_results = False
        for loading_token in self._loading_tokens.values():
            finish_loading(loading_token)
        self._loading_tokens.clear()
        for name in ("_wd_initial_timer", "_wd_timer", "_t_timer"):
            timer = getattr(self, name, None)
            if timer is not None:
                timer.stop()
        self._async_bridge.console_closed()
        super().closeEvent(event)

    def _implement_code(self):
        import ast
        code = self.ai_proposed_code.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "Nothing to Implement", "The code window is empty.")
            return
        try:
            ast.parse(code)
        except SyntaxError as exc:
            QMessageBox.critical(
                self, "Invalid Proposal",
                f"The proposed Python is not syntactically valid:\n{exc}",
            )
            return
        if QMessageBox.question(
                self, "Stage proposal",
                "Save this untrusted AI proposal to the review staging area?\n\n"
                "It will not be appended to application code or executed."
        ) != QMessageBox.Yes:
            return
        try:
            import hashlib
            digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
            staged = self._data_dir() / "staged_patches"
            staged.mkdir(parents=True, exist_ok=True)
            path = staged / f"ai-proposal-{digest[:16]}.py.review"
            path.write_text(code + "\n", encoding="utf-8")
            QMessageBox.information(
                self, "Proposal staged",
                f"Saved for review only:\n{path}\n\nSHA-256: {digest}",
            )
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
        self.wd_logs.document().setMaximumBlockCount(1000)
        self._last_wd_line = ""
        ll.addWidget(self.wd_logs); layout.addWidget(lg)

        self.tabs.addTab(tab, "Watchdog Hub")
        # The first status read imports the resilience stack and touches its
        # diagnostic files.  Defer that cold work until after construction so
        # opening this operator window never waits on storage or AV scanning.
        self._wd_initial_timer = QTimer(self)
        self._wd_initial_timer.setSingleShot(True)
        self._wd_initial_timer.timeout.connect(self._refresh_watchdog)
        self._wd_initial_timer.start(0)
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

    def _watchdog_snapshot(self) -> dict:
        """Read watchdog diagnostics off the Qt thread."""
        return {
            "watchdog": self._eco_status("watchdog"),
            "heartbeat": self._eco_hb("watchdog"),
            "core": self._eco_status("core"),
        }

    def _refresh_watchdog(self):
        """Schedule one watchdog snapshot without queueing timer backlog."""
        if not self._accept_async_results or self._watchdog_refresh_in_flight:
            return
        token = self._new_async_token()
        self._watchdog_refresh_token = token
        self._watchdog_refresh_in_flight = True
        worker = _UpgradeWorker(
            "watchdog_status",
            token,
            self._watchdog_snapshot,
            self._async_bridge,
        )
        self._async_bridge.track_submission()
        try:
            self._async_pool.start(worker)
        except Exception as exc:
            self._async_bridge.submission_failed(
                "watchdog_status", token, {"error": str(exc)}
            )

    def _apply_watchdog_snapshot(self, snapshot: dict) -> None:
        """Render a completed watchdog snapshot on the owning Qt thread."""
        # Prefer the standalone ecosystem: heartbeat + status diagnostic.
        st = snapshot.get("watchdog")
        hbst = snapshot.get("heartbeat", "unknown")
        core_st = snapshot.get("core")
        if st or hbst not in ("unknown", "dead") or core_st:
            wd_line = (f"heartbeat={hbst}, pid={(st or {}).get('pid','?')}, "
                       f"rss={(st or {}).get('rss_mb','?')}MB, state={(st or {}).get('state','?')}"
                       if (st or hbst != "unknown")
                       else "no standalone watchdog running (build the Go watchdog binary)")
            self._wd_status.setText(wd_line)
            if core_st:
                line = (f"core: frames_ingested={core_st.get('frames_ingested','?')}, "
                        f"supervised={core_st.get('supervised')}, "
                        f"safe_mode={core_st.get('safe_mode')}")
                if line != self._last_wd_line:
                    self.wd_logs.append(line)
                    self._last_wd_line = line
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
        # Sliders with a live value label that updates as you drag.
        cpu = QSlider(Qt.Horizontal); cpu.setRange(5, 50); cpu.setValue(20)
        cpu_val = QLabel("20%")
        cpu.valueChanged.connect(lambda v: cpu_val.setText(f"{v}%"))
        cpu_row = QHBoxLayout(); cpu_row.addWidget(cpu); cpu_row.addWidget(cpu_val)
        cpu_w = QWidget(); cpu_w.setLayout(cpu_row)

        ram = QSlider(Qt.Horizontal); ram.setRange(50, 500); ram.setValue(250)
        ram_val = QLabel("250 MB")
        ram.valueChanged.connect(lambda v: ram_val.setText(f"{v} MB"))
        ram_row = QHBoxLayout(); ram_row.addWidget(ram); ram_row.addWidget(ram_val)
        ram_w = QWidget(); ram_w.setLayout(ram_row)

        tl.addRow("Max CPU target:", cpu_w); tl.addRow("Max memory hint:", ram_w)
        layout.addWidget(tg)

        sg = QGroupBox("Live Event Stream"); sl = QVBoxLayout(sg)
        self.term_stream = QTextEdit(); self.term_stream.setReadOnly(True)
        self.term_stream.document().setMaximumBlockCount(2000)
        self.term_stream.setStyleSheet("background-color: #0b0b0b; color: #00ff88; font-family: Consolas, monospace;")
        sl.addWidget(self.term_stream); layout.addWidget(sg)

        self.tabs.addTab(tab, "Telemetry Hub")
        self._last_ts = 0.0
        self._t_timer = QTimer(self); self._t_timer.timeout.connect(self._refresh_telemetry)
        self._t_timer.start(1500)

    def _telemetry_snapshot(self) -> dict:
        """Read scanner diagnostics off the Qt thread."""
        return {"scanner": self._eco_status("scanner")}

    def _refresh_telemetry(self):
        """Schedule one scanner snapshot without queueing timer backlog."""
        if not self._accept_async_results or self._telemetry_refresh_in_flight:
            return
        token = self._new_async_token()
        self._telemetry_refresh_token = token
        self._telemetry_refresh_in_flight = True
        worker = _UpgradeWorker(
            "telemetry_status",
            token,
            self._telemetry_snapshot,
            self._async_bridge,
        )
        self._async_bridge.track_submission()
        try:
            self._async_pool.start(worker)
        except Exception as exc:
            self._async_bridge.submission_failed(
                "telemetry_status", token, {"error": str(exc)}
            )

    def _apply_telemetry_snapshot(self, snapshot: dict) -> None:
        """Render a completed scanner snapshot on the owning Qt thread."""
        # Live standalone scanner status takes priority if the ecosystem is up.
        sc = snapshot.get("scanner")
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


def launch_upgrade_console(
    manager=None,
    config=None,
    bus=None,
    parent=None,
    *,
    model_pack_manager=None,
    pack_change_callback: Callable[[], object] | None = None,
) -> AngeronaUpgradeConsole:
    """Embed entry point: build + show the console over an existing app.
    Mirrors ``launch_sandbox_editor``. Tolerates None manager/config/bus."""
    win = AngeronaUpgradeConsole(
        manager=manager,
        config=config,
        bus=bus,
        parent=parent,
        model_pack_manager=model_pack_manager,
        pack_change_callback=pack_change_callback,
    )
    win.show()
    return win


def _standalone() -> int:
    app = QApplication.instance() or QApplication([])
    try:
        from angerona.core.config import Config
        cfg = Config.load()
    except Exception:
        cfg = None
    win = AngeronaUpgradeConsole(config=cfg)
    from angerona.gui.header_controls import show_with_window_reveal
    show_with_window_reveal(win, config=cfg, color="#c084fc")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(_standalone())
