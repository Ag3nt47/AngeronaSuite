"""top_talkers.py — live "who is my machine talking to" panel.

Situational-awareness view: aggregates every established outbound connection by
owning process, flags untrusted external destinations, and (best-effort) enriches
each remote IP with an ASN/hostname. Refreshes on a timer; the fastest way to
eyeball data-exfil or an unexpected talker.

psutil only for the connection walk; enrichment reuses core.net_interfaces.
"""
from __future__ import annotations

import socket
import weakref
from collections import defaultdict
from typing import Callable, Optional

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

try:
    import psutil
except Exception:   # pragma: no cover
    psutil = None

try:
    from angerona.core.net_interfaces import is_untrusted_external, interface_type_for_local_ip
except Exception:   # pragma: no cover
    def is_untrusted_external(ip: str) -> bool:  # type: ignore
        return bool(ip) and not ip.startswith(("127.", "10.", "192.168.", "169.254."))

    def interface_type_for_local_ip(ip: str) -> str:  # type: ignore
        return "Physical"


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "no PTR"


def _collect_top_talkers(resolve_hostnames: bool) -> dict:
    """Collect and enrich one connection snapshot away from the Qt thread."""
    if psutil is None:
        return {"error": "psutil unavailable — cannot enumerate connections."}

    by_pid: dict = defaultdict(lambda: {
        "name": "?",
        "conns": 0,
        "ext": 0,
        "remotes": [],
        "remote_ips": [],
        "iface": "",
    })
    total_ext = 0
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        return {"error": f"Could not read connections: {exc}"}

    for conn in conns:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        pid = conn.pid or 0
        rec = by_pid[pid]
        rec["conns"] += 1
        remote_ip = conn.raddr.ip
        rec["remotes"].append(f"{remote_ip}:{conn.raddr.port}")
        rec["remote_ips"].append(remote_ip)
        if not rec["iface"]:
            try:
                local_ip = conn.laddr.ip if conn.laddr else ""
                rec["iface"] = interface_type_for_local_ip(local_ip)
            except Exception:
                rec["iface"] = ""
        if is_untrusted_external(remote_ip):
            rec["ext"] += 1
            total_ext += 1

    for pid, rec in by_pid.items():
        if pid:
            try:
                rec["name"] = psutil.Process(pid).name()
            except Exception:
                rec["name"] = "?"
        else:
            rec["name"] = "(system)"

    rows = []
    ordered = sorted(
        by_pid.items(),
        key=lambda item: -item[1]["ext"] or -item[1]["conns"],
    )
    for pid, rec in ordered:
        top = rec["remotes"][0] if rec["remotes"] else ""
        if top and resolve_hostnames:
            top = f"{top}  ({_rdns(rec['remote_ips'][0])})"
        rows.append({
            "pid": pid,
            "name": rec["name"],
            "conns": rec["conns"],
            "ext": rec["ext"],
            "top": top,
            "iface": rec["iface"],
        })
    return {"rows": rows, "process_count": len(by_pid), "total_ext": total_ext}


class _TopTalkersWorkerSignals(QObject):
    finished = Signal(object)


class _TopTalkersWorker(QRunnable):
    """One-shot collector. Its signal is delivered back on the Qt thread."""

    def __init__(self, resolve_hostnames: bool) -> None:
        super().__init__()
        self._resolve_hostnames = resolve_hostnames
        self.signals = _TopTalkersWorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            snapshot = _collect_top_talkers(self._resolve_hostnames)
        except Exception as exc:
            snapshot = {"error": f"Could not collect connections: {exc}"}
        self.signals.finished.emit(snapshot)


class _AskAiWorkerSignals(QObject):
    finished = Signal(int, object)


class _AskAiWorker(QRunnable):
    """Run one potentially slow local-AI request without touching Qt widgets."""

    def __init__(
        self,
        token: int,
        request: Callable[[str, int, str], str],
        name: str,
        pid: int,
        dest: str,
    ) -> None:
        super().__init__()
        self._token = token
        self._request = request
        self._name = name
        self._pid = pid
        self._dest = dest
        self.signals = _AskAiWorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self._request(self._name, self._pid, self._dest)
        except Exception as exc:
            result = f"Local AI request failed: {exc}"
        self.signals.finished.emit(self._token, result)


class TopTalkersDialog(QDialog):
    """Per-process outbound connection view, refreshed live."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Top Talkers — outbound network awareness")
        self.setMinimumSize(860, 520)
        if parent is not None:
            try:
                self.setStyleSheet(parent.styleSheet())
            except Exception:
                pass

        root = QVBoxLayout(self)
        head = QLabel("Who is this machine talking to? Established outbound connections "
                      "grouped by process. External (untrusted) destinations are flagged red. "
                      "Double-click a process for Allow / Block / Ask-AI actions.")
        head.setWordWrap(True)
        head.setStyleSheet("color:#cbd5e1;")
        root.addWidget(head)

        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#93c5fd; font-weight:600;")
        root.addWidget(self.summary)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Process", "PID", "Conns", "External", "Top remote", "Interface"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.cellDoubleClicked.connect(self._on_process)   # row → actions
        root.addWidget(self.table, 1)

        row = QHBoxLayout()
        self._resolve_chk = QPushButton("Resolve hostnames: off")
        self._resolve_chk.setCheckable(True)
        self._resolve_chk.toggled.connect(
            lambda on: self._resolve_chk.setText(f"Resolve hostnames: {'on' if on else 'off'}"))
        row.addWidget(self._resolve_chk)
        row.addStretch()
        refresh = QPushButton("Refresh now")
        refresh.clicked.connect(self.refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)

        # Running jobs belong to the application pool, so closing this dialog
        # never waits on a slow OS connection walk or PTR lookup.
        self._pool = QThreadPool.globalInstance()
        self._refresh_in_flight = False
        self._ai_in_flight = False
        self._ai_request_token = 0
        self._ai_context: Optional[dict] = None
        self._accept_results = True
        self.finished.connect(self._stop_refreshes)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(4000)
        self.refresh()

    # ── Data ──────────────────────────────────────────────────────────────────
    def refresh(self) -> None:
        if psutil is None:
            self.summary.setText("psutil unavailable — cannot enumerate connections.")
            return
        if not self._accept_results or self._refresh_in_flight:
            return
        self._refresh_in_flight = True
        worker = _TopTalkersWorker(self._resolve_chk.isChecked())
        worker.signals.finished.connect(self._apply_snapshot)
        try:
            self._pool.start(worker)
        except Exception as exc:
            self._refresh_in_flight = False
            self.summary.setText(f"Could not start connection refresh: {exc}")

    @Slot(object)
    def _apply_snapshot(self, snapshot: object) -> None:
        """Render a completed snapshot; Qt widgets are touched only here."""
        self._refresh_in_flight = False
        if not self._accept_results or not isinstance(snapshot, dict):
            return
        error = snapshot.get("error")
        if error:
            self.summary.setText(str(error))
            return
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for rec in snapshot.get("rows", []):
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(rec["name"]))
            self.table.setItem(r, 1, self._num(rec["pid"]))
            self.table.setItem(r, 2, self._num(rec["conns"]))
            ext_item = self._num(rec["ext"])
            if rec["ext"]:
                ext_item.setForeground(QColor("#ef4444"))
            self.table.setItem(r, 3, ext_item)
            self.table.setItem(r, 4, QTableWidgetItem(rec["top"]))
            self.table.setItem(r, 5, QTableWidgetItem(rec["iface"]))
        self.table.setSortingEnabled(True)
        self.summary.setText(
            f"{snapshot.get('process_count', 0)} process(es) with live outbound connections · "
            f"{snapshot.get('total_ext', 0)} connection(s) to untrusted external hosts")

    @Slot(int)
    def _stop_refreshes(self, _result: int) -> None:
        self._accept_results = False
        self._timer.stop()
        if self._ai_context is not None:
            self._ai_context["abandoned"] = True

    # ── per-process actions ──────────────────────────────────────────────────
    def _on_process(self, row: int, _col: int) -> None:
        try:
            name = self.table.item(row, 0).text()
            pid = int(self.table.item(row, 1).data(Qt.DisplayRole))
            dest_item = self.table.item(row, 4)
            dest = dest_item.text() if dest_item else ""
        except Exception:
            return
        self._process_actions(pid, name, dest)

    def _process_actions(self, pid: int, name: str, dest: str) -> None:
        from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                       QPushButton, QMessageBox)
        dlg = QDialog(self); dlg.setWindowTitle(f"Process actions — {name} (PID {pid})")
        dlg.resize(480, 200)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(f"<b>{name}</b>  (PID {pid})<br>Top remote: {dest or '—'}"))
        lay.addWidget(QLabel("Choose an action for this process's network activity:"))
        ai_status = QLabel("")
        ai_status.setStyleSheet("color:#93c5fd;")
        lay.addWidget(ai_status)
        rowb = QHBoxLayout()
        b_allow = QPushButton("✓ Allow"); b_block = QPushButton("⛔ Block")
        b_ai = QPushButton("🤖 Ask AI"); b_close = QPushButton("Close")
        for b in (b_allow, b_block, b_ai, b_close):
            rowb.addWidget(b)
        lay.addLayout(rowb)

        def _allow():
            self._record_list("talker_allowlist.json", pid, name, dest)
            QMessageBox.information(dlg, "Allowed", f"{name} (PID {pid}) added to the allowlist.")

        def _block():
            if QMessageBox.question(
                    dlg, "Block",
                    f"Block {name} (PID {pid})?\n\nThis records it to the blocklist and "
                    "terminates the process to stop its current connections.") != QMessageBox.Yes:
                return
            self._record_list("talker_blocklist.json", pid, name, dest)
            killed = False
            try:
                import psutil
                psutil.Process(pid).terminate()
                killed = True
            except Exception:
                pass
            QMessageBox.information(dlg, "Blocked",
                                   f"{name} added to the blocklist"
                                   + (" and terminated." if killed else " (could not terminate)."))
            self.refresh()

        def _ai():
            self._start_ai_request(name, pid, dest, dlg, b_ai, ai_status)

        b_allow.clicked.connect(_allow)
        b_block.clicked.connect(_block)
        b_ai.clicked.connect(_ai)
        b_close.clicked.connect(dlg.accept)
        dlg.exec()

    def _start_ai_request(
        self,
        name: str,
        pid: int,
        dest: str,
        action_dialog: QDialog,
        button: QPushButton,
        status: QLabel,
    ) -> bool:
        """Start one Ask-AI action and return immediately to the Qt event loop."""
        if not self._accept_results:
            return False
        if self._ai_in_flight:
            status.setText("An AI recommendation is already in progress.")
            return False

        self._ai_request_token += 1
        token = self._ai_request_token
        self._ai_in_flight = True
        self._ai_context = {
            "token": token,
            "dialog": weakref.ref(action_dialog),
            "button": weakref.ref(button),
            "status": weakref.ref(status),
            "abandoned": False,
        }
        button.setEnabled(False)
        button.setText("Asking AI…")
        status.setText("Contacting local AI…")
        action_dialog.finished.connect(
            lambda _result, request_token=token: self._abandon_ai_result(request_token)
        )

        worker = _AskAiWorker(token, self._ask_ai, name, pid, dest)
        worker.signals.finished.connect(self._handle_ai_result)
        try:
            self._pool.start(worker)
        except Exception as exc:
            self._ai_in_flight = False
            self._ai_context = None
            button.setEnabled(True)
            button.setText("🤖 Ask AI")
            status.setText(f"Could not start AI request: {exc}")
            return False
        return True

    @Slot(int, object)
    def _handle_ai_result(self, token: int, result: object) -> None:
        """Apply an AI result on Qt only if its action dialog is still valid."""
        context = self._ai_context
        if context is None or token != context.get("token"):
            return
        self._ai_in_flight = False
        self._ai_context = None
        if not self._accept_results or context.get("abandoned"):
            return

        dialog = self._live_widget(context["dialog"])
        button = self._live_widget(context["button"])
        status = self._live_widget(context["status"])
        if dialog is None or button is None or status is None:
            return

        button.setEnabled(True)
        button.setText("🤖 Ask AI")
        status.setText("Recommendation ready.")
        QMessageBox.information(dialog, "AI recommendation", str(result))

    def _abandon_ai_result(self, token: int) -> None:
        context = self._ai_context
        if context is not None and token == context.get("token"):
            # Keep the request marked in-flight until its worker actually exits,
            # but never target widgets belonging to this closed dialog.
            context["abandoned"] = True

    @staticmethod
    def _live_widget(ref: weakref.ReferenceType):
        widget = ref()
        if widget is None:
            return None
        try:
            from shiboken6 import isValid
            return widget if isValid(widget) else None
        except Exception:
            return widget

    def _record_list(self, fname: str, pid: int, name: str, dest: str) -> None:
        import json, time
        from pathlib import Path
        try:
            from angerona.core.data_paths import data_dir
            root = data_dir() / "shared_logs"
            root.mkdir(parents=True, exist_ok=True)
            p = root / fname
            data = []
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    data = []
            data.append({"pid": pid, "name": name, "dest": dest,
                         "when": time.strftime("%Y-%m-%d %H:%M:%S")})
            p.write_text(json.dumps(data[-500:], indent=2), encoding="utf-8")
        except Exception:
            pass

    def _ask_ai(self, name: str, pid: int, dest: str) -> str:
        """Best-effort local-Ollama recommendation for this process/connection."""
        import os
        prompt = (f"A Windows process '{name}' (PID {pid}) has an outbound network "
                  f"connection to {dest or 'unknown'}. In 2-3 sentences, assess whether "
                  f"this looks benign or suspicious and recommend allow or block.")
        try:
            import json, urllib.request
            body = json.dumps({"model": os.environ.get("ANGERONA_OLLAMA_MODEL", "llama3"),
                               "prompt": prompt, "stream": False}).encode()
            req = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            return data.get("response", "").strip() or "(no response from local AI)"
        except Exception as exc:
            return (f"Local AI (Ollama) unavailable: {exc}\n\n"
                    f"Heuristic: '{name}' → {dest or 'unknown'}. Check the destination's "
                    "reputation; block if it is an unfamiliar external host.")

    @staticmethod
    def _num(v: int) -> QTableWidgetItem:
        it = QTableWidgetItem()
        it.setData(Qt.DisplayRole, int(v))
        return it

    @staticmethod
    def _rdns(ip: str) -> str:
        return _rdns(ip)
