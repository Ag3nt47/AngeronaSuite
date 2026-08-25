"""top_talkers.py — live "who is my machine talking to" panel.

Situational-awareness view: aggregates every established outbound connection by
owning process, flags untrusted external destinations, and (best-effort) enriches
each remote IP with an ASN/hostname. Refreshes on a timer; the fastest way to
eyeball data-exfil or an unexpected talker.

psutil only for the connection walk; enrichment reuses core.net_interfaces.
"""
from __future__ import annotations

import ipaddress
import os
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

from angerona.core.url_policy import OLLAMA_SERVICE_POLICY, read_bounded, safe_urlopen
from angerona.core.ollama_lifecycle import effective_keep_alive


_TOP_TALKERS_POOL: QThreadPool | None = None


def _top_talkers_pool() -> QThreadPool:
    """Return the small pool reserved for interactive network-panel work.

    The suite's global Qt pool also runs scanners and other periodic jobs.  On
    a busy machine those jobs can occupy every global worker and leave an
    operator's Refresh or Ask-AI click queued for an unbounded amount of time.
    A module-lifetime pool keeps this panel responsive without tying worker
    lifetime to a dialog that the operator may close while a request unwinds.
    """
    global _TOP_TALKERS_POOL
    if _TOP_TALKERS_POOL is None:
        pool = QThreadPool()
        pool.setMaxThreadCount(4)
        pool.setExpiryTimeout(10_000)
        _TOP_TALKERS_POOL = pool
    return _TOP_TALKERS_POOL

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
        "create_time": None,
        "exe": "",
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
                process = psutil.Process(pid)
                rec["name"] = process.name()
                rec["create_time"] = float(process.create_time())
                rec["exe"] = process.exe() or ""
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
            "remote_ip": rec["remote_ips"][0] if rec["remote_ips"] else "",
            "iface": rec["iface"],
            "create_time": rec["create_time"],
            "exe": rec["exe"],
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
        close.clicked.connect(self.close)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)

        # Running jobs belong to a module-lifetime pool, so closing this dialog
        # never waits on a slow OS connection walk or PTR lookup.
        self._pool = _top_talkers_pool()
        self._refresh_in_flight = False
        self._ai_in_flight = False
        self._ai_request_token = 0
        self._ai_context: Optional[dict] = None
        self._accept_results = True
        self._render_key: tuple | None = None
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
        rows = list(snapshot.get("rows", []))
        render_key = tuple(
            (
                rec.get("name"), rec.get("pid"), rec.get("conns"), rec.get("ext"),
                rec.get("top"), rec.get("iface"),
                rec.get("remote_ip"), rec.get("create_time"), rec.get("exe"),
            )
            for rec in rows
        )
        summary = (
            f"{snapshot.get('process_count', 0)} process(es) with live outbound connections · "
            f"{snapshot.get('total_ext', 0)} connection(s) to untrusted external hosts"
        )
        if render_key == self._render_key:
            if self.summary.text() != summary:
                self.summary.setText(summary)
            return
        self._render_key = render_key
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for rec in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(rec["name"]))
            pid_item = self._num(rec["pid"])
            pid_item.setData(Qt.UserRole, dict(rec))
            self.table.setItem(r, 1, pid_item)
            self.table.setItem(r, 2, self._num(rec["conns"]))
            ext_item = self._num(rec["ext"])
            if rec["ext"]:
                ext_item.setForeground(QColor("#ef4444"))
            self.table.setItem(r, 3, ext_item)
            self.table.setItem(r, 4, QTableWidgetItem(rec["top"]))
            self.table.setItem(r, 5, QTableWidgetItem(rec["iface"]))
        self.table.setSortingEnabled(True)
        self.summary.setText(summary)

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
            pid_item = self.table.item(row, 1)
            pid = int(pid_item.data(Qt.DisplayRole))
            snapshot = pid_item.data(Qt.UserRole)
            dest_item = self.table.item(row, 4)
            dest = dest_item.text() if dest_item else ""
        except Exception:
            return
        if not isinstance(snapshot, dict):
            return
        self._process_actions(pid, name, dest, snapshot)

    def _process_actions(self, pid: int, name: str, dest: str, snapshot: dict) -> None:
        from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                       QPushButton, QMessageBox)
        dlg = QDialog(self); dlg.setWindowTitle(f"Process actions — {name} (PID {pid})")
        dlg.resize(480, 200)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(f"<b>{name}</b>  (PID {pid})<br>Top remote: {dest or '—'}"))
        lay.addWidget(QLabel(
            "Choose an analyst note or submit exact containment to Adversary Combat:"
        ))
        ai_status = QLabel("")
        ai_status.setStyleSheet("color:#93c5fd;")
        lay.addWidget(ai_status)
        rowb = QHBoxLayout()
        b_allow = QPushButton("✓ Mark reviewed")
        b_block = QPushButton("⛔ Contain via Combat")
        b_ai = QPushButton("🤖 Ask AI"); b_close = QPushButton("Close")
        for b in (b_allow, b_block, b_ai, b_close):
            rowb.addWidget(b)
        lay.addLayout(rowb)

        def _allow():
            self._record_list("talker_reviews.json", pid, name, dest)
            QMessageBox.information(
                dlg,
                "Reviewed",
                f"{name} (PID {pid}) recorded as analyst-reviewed. "
                "This note does not create a security exclusion.",
            )

        def _block():
            if QMessageBox.question(
                    dlg, "Contain via Adversary Combat",
                    f"Contain {name} (PID {pid}) and its exact remote peer?\n\n"
                    "The live PID birth time, executable, and connection will be "
                    "revalidated before a signed Combat request is accepted.") != QMessageBox.Yes:
                return
            submitted, message = self._submit_combat_containment(snapshot)
            QMessageBox.information(
                dlg,
                "Combat request submitted" if submitted else "Containment refused",
                message,
            )
            self.refresh()

        def _ai():
            self._start_ai_request(name, pid, dest, dlg, b_ai, ai_status)

        b_allow.clicked.connect(_allow)
        b_block.clicked.connect(_block)
        b_ai.clicked.connect(_ai)
        b_close.clicked.connect(dlg.close)
        dlg.exec()

    def _combat_module(self):
        parent = self.parent()
        manager = getattr(parent, "manager", None) if parent is not None else None
        return (
            getattr(manager, "modules", {}).get("Adversary Combat")
            if manager is not None
            else None
        )

    def _submit_combat_containment(self, snapshot: dict) -> tuple[bool, str]:
        """Publish one exact, signed operator-confirmed response contract."""
        if psutil is None or not isinstance(snapshot, dict):
            return False, "Live process telemetry is unavailable; no action was taken."
        pid = snapshot.get("pid")
        created = snapshot.get("create_time")
        executable = str(snapshot.get("exe") or "")
        remote_raw = snapshot.get("remote_ip")
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or not isinstance(created, (int, float))
            or isinstance(created, bool)
            or float(created) <= 0
            or not executable
        ):
            return False, "The selected row lacks an exact process identity; no action was taken."
        try:
            remote_ip = str(ipaddress.ip_address(str(remote_raw)))
            process = psutil.Process(pid)
            live_created = float(process.create_time())
            live_executable = process.exe() or ""
            if (
                abs(live_created - float(created)) > 0.001
                or os.path.normcase(os.path.abspath(live_executable))
                != os.path.normcase(os.path.abspath(executable))
            ):
                return False, "The PID now belongs to a different process; no action was taken."
            connection_is_live = any(
                conn.pid == pid
                and conn.status == psutil.CONN_ESTABLISHED
                and bool(conn.raddr)
                and str(conn.raddr.ip) == remote_ip
                for conn in psutil.net_connections(kind="inet")
            )
            if not connection_is_live:
                return False, "The selected remote connection is no longer live; no action was taken."
        except Exception as exc:
            return False, f"Live identity revalidation failed; no action was taken ({exc})."

        combat = self._combat_module()
        bus = getattr(combat, "_bus", None) if combat is not None else None
        policy = combat.policy() if combat is not None else None
        if (
            combat is None
            or getattr(combat, "status", "") != "running"
            or policy is None
            or not policy.enabled
            or bus is None
        ):
            return False, "Adversary Combat is not armed; no action was taken."

        from angerona.core.eventbus import Event, Severity
        from angerona.core.response_contract import process_and_remote_response

        response = process_and_remote_response(
            pid,
            live_created,
            remote_ip,
            isolate_program=True,
            activate_deception=True,
        )
        if not response:
            return False, "The exact response contract could not be built; no action was taken."
        bus.publish(Event(
            "Top Talkers Operator",
            f"Operator-confirmed live talker containment: PID {pid} to {remote_ip}",
            Severity.HIGH,
            details={
                "pid": pid,
                "process_create_time": live_created,
                "exe": live_executable,
                "remote_ip": remote_ip,
                "active_attack": True,
                "detector_policy": "operator-confirmed-exact-live-talker",
                **response,
            },
        ))
        return True, (
            "The signed request was submitted to Adversary Combat. It will block the "
            "exact peer/program and contain only the revalidated process instance. "
            "Review Action history for the verified receipt and Undo controls."
        )

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
            # Interactive work runs ahead of periodic connection snapshots.
            self._pool.start(worker, 10)
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
            body = json.dumps({
                "model": os.environ.get("ANGERONA_OLLAMA_MODEL", "llama3"),
                "prompt": prompt,
                "stream": False,
                "keep_alive": effective_keep_alive("30m"),
            }).encode()
            req = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            with safe_urlopen(req, policy=OLLAMA_SERVICE_POLICY, timeout=20) as r:
                data = json.loads(read_bounded(r).decode("utf-8", "ignore"))
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
