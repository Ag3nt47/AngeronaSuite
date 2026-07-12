"""top_talkers.py — live "who is my machine talking to" panel.

Situational-awareness view: aggregates every established outbound connection by
owning process, flags untrusted external destinations, and (best-effort) enriches
each remote IP with an ASN/hostname. Refreshes on a timer; the fastest way to
eyeball data-exfil or an unexpected talker.

psutil only for the connection walk; enrichment reuses core.net_interfaces.
"""
from __future__ import annotations

import socket
from collections import defaultdict
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QHeaderView, QLabel, QPushButton, QTableWidget,
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

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(4000)
        self.refresh()

    # ── Data ──────────────────────────────────────────────────────────────────
    def refresh(self) -> None:
        if psutil is None:
            self.summary.setText("psutil unavailable — cannot enumerate connections.")
            return
        by_pid: dict = defaultdict(lambda: {"name": "?", "conns": 0, "ext": 0,
                                            "remotes": [], "iface": ""})
        total_ext = 0
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as exc:
            self.summary.setText(f"Could not read connections: {exc}")
            return
        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            pid = c.pid or 0
            rec = by_pid[pid]
            rec["conns"] += 1
            rip = c.raddr.ip
            rec["remotes"].append(f"{rip}:{c.raddr.port}")
            if not rec["iface"]:
                try:
                    rec["iface"] = interface_type_for_local_ip(c.laddr.ip if c.laddr else "")
                except Exception:
                    rec["iface"] = ""
            if is_untrusted_external(rip):
                rec["ext"] += 1
                total_ext += 1

        # names
        for pid, rec in by_pid.items():
            if pid:
                try:
                    rec["name"] = psutil.Process(pid).name()
                except Exception:
                    rec["name"] = "?"
            else:
                rec["name"] = "(system)"

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for pid, rec in sorted(by_pid.items(), key=lambda kv: -kv[1]["ext"] or -kv[1]["conns"]):
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(rec["name"]))
            self.table.setItem(r, 1, self._num(pid))
            self.table.setItem(r, 2, self._num(rec["conns"]))
            ext_item = self._num(rec["ext"])
            if rec["ext"]:
                ext_item.setForeground(QColor("#ef4444"))
            self.table.setItem(r, 3, ext_item)
            top = rec["remotes"][0] if rec["remotes"] else ""
            if top and self._resolve_chk.isChecked():
                top = f"{top}  ({self._rdns(top.rsplit(':', 1)[0])})"
            self.table.setItem(r, 4, QTableWidgetItem(top))
            self.table.setItem(r, 5, QTableWidgetItem(rec["iface"]))
        self.table.setSortingEnabled(True)
        self.summary.setText(
            f"{len(by_pid)} process(es) with live outbound connections · "
            f"{total_ext} connection(s) to untrusted external hosts")

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
            QMessageBox.information(dlg, "AI recommendation", self._ask_ai(name, pid, dest))

        b_allow.clicked.connect(_allow)
        b_block.clicked.connect(_block)
        b_ai.clicked.connect(_ai)
        b_close.clicked.connect(dlg.accept)
        dlg.exec()

    def _record_list(self, fname: str, pid: int, name: str, dest: str) -> None:
        import json, time
        from pathlib import Path
        try:
            root = Path(__file__).resolve().parents[3] / "shared_logs"
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
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "no PTR"
