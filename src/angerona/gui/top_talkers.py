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
                      "grouped by process. External (untrusted) destinations are flagged red.")
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
