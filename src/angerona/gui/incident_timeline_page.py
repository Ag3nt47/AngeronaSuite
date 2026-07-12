"""gui/incident_timeline_page.py — Incident kill-chain timeline viewer.

Renders the incidents built by core.incident_timeline as expandable kill-chains:
each incident shows its actor/process, severity, progress along the ATT&CK chain,
and the ordered tactic → technique stages. Double-click a technique to open its
MITRE ATT&CK page. Pure viewer over the live EventBus; no host change.
"""
from __future__ import annotations

import webbrowser

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTreeWidget,
    QTreeWidgetItem, QComboBox, QMessageBox,
)

from angerona.core.incident_timeline import build_timeline, write_timeline

_SEV_COLOR = {"CRITICAL": "#f87171", "HIGH": "#fb923c",
              "MEDIUM": "#facc15", "LOW": "#9fb3c8"}


class IncidentTimelineDialog(QDialog):
    def __init__(self, bus, parent=None) -> None:
        super().__init__(parent)
        self._bus = bus
        self.setWindowTitle("Incident Kill-Chain Timeline")
        self.resize(760, 620)
        try:
            if parent is not None:
                self.setStyleSheet(parent._qss())
        except Exception:
            pass

        lay = QVBoxLayout(self)
        title = QLabel("Incident Kill-Chain Timeline")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        lay.addWidget(QLabel(
            "Related alerts grouped per process and laid out along the ATT&CK chain "
            "(Recon → … → Impact). Double-click a technique for its MITRE page."))

        bar = QHBoxLayout()
        self._sev = QComboBox()
        self._sev.addItems(["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._sev.currentIndexChanged.connect(self._refresh)
        bar.addWidget(QLabel("Filter:"))
        bar.addWidget(self._sev)
        bar.addStretch()
        rb = QPushButton("↻ Refresh"); rb.clicked.connect(self._refresh)
        eb = QPushButton("⬇ Export JSON"); eb.clicked.connect(self._export)
        bar.addWidget(rb); bar.addWidget(eb)
        lay.addLayout(bar)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Incident / Stage", "Detail", "MITRE"])
        self._tree.setColumnWidth(0, 340)
        self._tree.itemDoubleClicked.connect(self._on_double)
        lay.addWidget(self._tree)

        self._status = QLabel("")
        self._status.setStyleSheet("color:#9fb3c8;")
        lay.addWidget(self._status)

        close = QPushButton("Close"); close.clicked.connect(self.accept)
        lay.addWidget(close)

        self._refresh()

    def _refresh(self) -> None:
        self._tree.clear()
        try:
            incidents = build_timeline(self._bus)
        except Exception as exc:
            self._status.setText(f"Could not build timeline: {exc}")
            return
        sev_filter = self._sev.currentText()
        shown = 0
        for inc in incidents:
            if sev_filter != "All severities" and inc["severity"] != sev_filter:
                continue
            shown += 1
            head = QTreeWidgetItem([
                f"{inc['actor']}  (pid {inc['pid']})",
                f"{inc['severity']} · {inc['progress_pct']}% of chain · "
                f"{inc['event_count']} events · {inc['first_seen']}→{inc['last_seen']}",
                "",
            ])
            color = _SEV_COLOR.get(inc["severity"], "#9fb3c8")
            head.setForeground(0, Qt.GlobalColor.white)
            for c in (0, 1):
                f = head.font(c); f.setBold(True); head.setFont(c, f)
            head.setData(0, Qt.ItemDataRole.UserRole, ("chain", inc.get("chain", "")))
            for st in inc["stages"]:
                snode = QTreeWidgetItem([f"▸ {st['tactic_name']}", "", st["tactic"]])
                for t in st["techniques"]:
                    tnode = QTreeWidgetItem([
                        f"     {t['label']}", t.get("sample", ""), t["tid"]])
                    tnode.setData(0, Qt.ItemDataRole.UserRole, ("tid", t["tid"]))
                    snode.addChild(tnode)
                head.addChild(snode)
            self._tree.addTopLevelItem(head)
            head.setExpanded(True)
        self._status.setText(
            f"{shown} incident(s). Kill-chains reconstructed from live alerts."
            if shown else "No incidents yet — nothing has chained together.")

    def _on_double(self, item, _col) -> None:
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        kind, val = data
        if kind == "tid" and val:
            base = val.split(".")[0]
            sub = val.split(".")[1] if "." in val else None
            url = f"https://attack.mitre.org/techniques/{base}/"
            if sub:
                url += f"{sub}/"
            webbrowser.open(url)

    def _export(self) -> None:
        try:
            path = write_timeline(self._bus)
            QMessageBox.information(self, "Exported",
                                    f"Incident timeline written to:\n{path}")
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
