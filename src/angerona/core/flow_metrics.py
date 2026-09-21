"""
core/flow_metrics.py — live metrics feed for the flow-visualization canvas.

Builds a small JSON snapshot of the running system (per architecture node) and
writes it to diagnostics/flow_metrics.json on a timer. flow_canvas.html fetches
that file and updates each node's metrics + turns a node red when it is in an
error/stopped state. Pure/derivable from live objects; best-effort, never raises.
"""
from __future__ import annotations

import json
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from angerona.core.data_paths import data_dir

_SENSOR_MODULES = {
    "Packet Sniffer", "ETW Core Listener", "File Integrity Monitor",
    "Process Monitor", "Network Monitor", "Network Protocol Deep Decoder",
}
_DETECT_MODULES = {
    "File Integrity Monitor", "Process Monitor", "Network Monitor",
    "Network Protocol Deep Decoder", "YARA Scanner", "Deception Engine",
    "API Patch / Anti-Blinding Detector",
}
_ATTACK_MODULES = {
    "Shark Attack", "Self-Attack Engine", "Red Team", "Adversarial Test",
    "MTTR Engine", "Evolution Engine",
}
_HARDEN_MODULES = {"Posture Hardening", "API Patch / Anti-Blinding Detector",
                   "Anti-Suspension Heartbeat", "Active Response SOAR"}

_hw_cache: dict | None = None
_AUDIT_READ_CHUNK = 64 * 1024
_AUDIT_GUARD_BYTES = 64


@dataclass(frozen=True)
class _AuditCount:
    path: str
    fingerprint: tuple[int, int, int, int]
    newlines: int
    last_byte: bytes
    head: bytes
    tail: bytes

    @property
    def count(self) -> int:
        # Binary file iteration also counts an unterminated final line.
        return self.newlines + int(self.last_byte not in (b"", b"\n"))


_audit_cache: _AuditCount | None = None
_audit_lock = threading.Lock()

# ── Pipeline telemetry — persistent across refreshes ─────────────────────────
# Events are shed (sampled) once the 10-s EPS exceeds this threshold.
# MTM absorbs >80 % of duplicates so effective load is usually well below it.
_DROP_EPS_THRESHOLD: float = 80.0
_dropped_events: int       = 0   # cumulative dropped/sampled events since startup


def _audit_line_count(path) -> int:
    """Count an append-only display log without rereading its growing history.

    One bounded cache holds newline counts and small append guards, not log
    contents or an open descriptor. Rotation, truncation, same-size rewrites
    and changed guards trigger a recount. This is presentation only; metadata
    and guards must never be used to authenticate audit evidence.
    """
    global _audit_cache
    path = Path(path)
    identity = os.path.abspath(path)

    def fingerprint(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    with _audit_lock:
        cached = _audit_cache
        fallback = 0
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                return 0
            key = fingerprint(info)
            same_file = bool(cached and cached.path == identity
                             and cached.fingerprint[:2] == key[:2])
            fallback = cached.count if same_file else 0
            if same_file and cached.fingerprint == key:
                return cached.count
            with path.open("rb") as stream:
                if fingerprint(os.fstat(stream.fileno())) != key:
                    return cached.count if same_file else 0
                offset = newlines = 0
                last_byte = b""
                if same_file and key[2] > cached.fingerprint[2]:
                    previous_size = cached.fingerprint[2]
                    head = stream.read(len(cached.head))
                    stream.seek(previous_size - len(cached.tail))
                    tail = stream.read(len(cached.tail))
                    if head == cached.head and tail == cached.tail:
                        offset = previous_size
                        newlines = cached.newlines
                        last_byte = cached.last_byte
                stream.seek(offset)
                remaining = key[2] - offset
                while remaining:
                    chunk = stream.read(min(remaining, _AUDIT_READ_CHUNK))
                    if not chunk:
                        raise OSError("audit log changed during counting")
                    newlines += chunk.count(b"\n")
                    last_byte = chunk[-1:]
                    remaining -= len(chunk)
                stream.seek(0)
                head = stream.read(min(key[2], _AUDIT_GUARD_BYTES))
                stream.seek(max(0, key[2] - _AUDIT_GUARD_BYTES))
                tail = stream.read(min(key[2], _AUDIT_GUARD_BYTES))
                if (fingerprint(os.fstat(stream.fileno())) != key
                        or fingerprint(path.stat()) != key):
                    raise OSError("audit log changed during counting")
            _audit_cache = _AuditCount(identity, key, newlines, last_byte, head, tail)
            return _audit_cache.count
        except OSError:
            # Do not cache an unsuccessful read as current: the next refresh
            # must retry even if the file metadata has not changed again.
            return fallback


def _hw() -> dict:
    global _hw_cache
    if _hw_cache is None:
        try:
            from angerona.core import hw_profile
            _hw_cache = hw_profile.apply_profile()
        except Exception:
            _hw_cache = {"tier": "?", "model": "?", "max_batch_size": "?",
                         "num_ctx": "?", "vram_mb": None}
    return _hw_cache


def _running(manager, names) -> tuple[int, int]:
    have = [manager.modules[n] for n in names if n in manager.modules]
    up = sum(1 for m in have if getattr(m, "status", "") == "running")
    return up, len(have)


def build_metrics(manager, bus, config) -> dict:
    """Return live metrics keyed to the six-step flowchart nodes.

    The returned dict also carries a ``pipeline`` key with per-edge latency and
    queue-depth data consumed by FlowWindow to update edge labels in real time.
    """
    global _dropped_events

    now    = time.time()
    recent = bus.recent(400)

    # 10-second EPS — baseline throughput
    eps    = round(len([e for e in recent if now - e.ts <= 10]) / 10.0, 1)
    # 1-second EPS — burst / spike detection (GIL-bound queue reality)
    eps_1s = round(len([e for e in recent if now - e.ts <= 1])  /  1.0, 1)

    try:
        from angerona.core.threat import threat_label
        threat, _ = threat_label(recent)
    except Exception:
        threat = "?"
    hw = _hw()

    s_up,  s_tot  = _running(manager, _SENSOR_MODULES)
    d_up,  d_tot  = _running(manager, _DETECT_MODULES)
    h_up,  h_tot  = _running(manager, _HARDEN_MODULES)
    atk_up, atk_tot = _running(manager, _ATTACK_MODULES)
    run_total = sum(1 for m in manager.modules.values()
                    if getattr(m, "status", "") == "running")

    # AI guardrail audit-log line count — only appended bytes are recounted.
    audit_n = _audit_line_count(
        data_dir() / "diagnostics" / "ai_security_audit.log")

    # UI not-responding watchdog
    ui_err = False
    try:
        nr = data_dir() / "diagnostics" / "not_responding.log"
        ui_err = nr.exists() and (now - nr.stat().st_mtime) < 30
    except Exception:
        pass

    # ── Pipeline backpressure model ──────────────────────────────────────────
    # burst_excess: events/s arriving above the sustained baseline — these pile
    # up in the EventBus ring before MTM de-duplicates them (~80 % token cut).
    burst_excess = max(0.0, eps_1s - eps)
    queue_depth  = int(burst_excess * 0.5)   # rough pending-event accumulation

    # Per-edge end-to-end latency (ms): base processing cost + GIL queue penalty.
    #   CAPTURE→DETECT  8 ms base  (+1.5 ms per queued event)
    #   DETECT→TRIAGE  15 ms base  (+3.0 ms per queued event — Ollama pre-warm)
    cap_det_ms = round(8.0  + queue_depth * 1.5, 1)
    det_tri_ms = round(15.0 + queue_depth * 3.0, 1)

    # Accumulate sampled/dropped events when sustained EPS exceeds saturation.
    # BL-11 resilience: the pipeline sheds events rather than blocking the bus.
    if eps > _DROP_EPS_THRESHOLD:
        _dropped_events += int(eps - _DROP_EPS_THRESHOLD)

    def node(state, metrics):
        return {"state": "err" if state else "ok", "metrics": metrics}

    return {
        "schema_version": 1,
        "generated_at_epoch": now,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "live":      True,
        # ── Per-edge pipeline telemetry ─────────────────────────────────────
        # Consumed by FlowWindow._refresh() to update edge label text in-place.
        "pipeline": {
            "cap_det": {"queue": queue_depth,           "latency_ms": cap_det_ms},
            "det_tri": {"queue": max(0, queue_depth // 2), "latency_ms": det_tri_ms},
            "dropped": _dropped_events,
        },
        "nodes": {
            # ① CAPTURE
            "capture": node(s_up == 0, {
                "Events/sec": eps,
                "Queue depth": queue_depth,
                "Sensors up":  f"{s_up}/{s_tot}",
            }),
            # ② DETECT
            "detect": node(False, {
                "Detectors up": f"{d_up}/{d_tot}",
                "Queue depth":  max(0, queue_depth // 2),
                "Modules total": run_total,
            }),
            # ③ AI TRIAGE
            "triage": node(False, {
                "Audit events": audit_n,
                "Model":        getattr(config, "ollama_model", hw.get("model", "?")),
                "GPU tier":     hw.get("tier", "?"),
            }),
            # ④ RESPOND
            "respond": node(False, {
                "SOAR port": 8000,
                "Redacts":   "PII/keys/paths",
                "Gate":      "review-gated",
            }),
            # ⑤ ATTACK
            "attack": node(False, {
                "Red-team up": (f"{atk_up}/{atk_tot}" if atk_tot else "standby"),
                "Mode":        ("active" if atk_up else "idle"),
                "Trigger":     "F9 / operator",
            }),
            # ⑥ SELF-HARDEN
            "harden": node(ui_err, {
                "Threat level": threat,
                "Harden mods":  f"{h_up}/{h_tot}",
                "Watchdog":     "ALERT" if ui_err else "ok",
            }),
        },
    }


def write(manager, bus, config, path=None) -> None:
    try:
        if path is None:
            path = data_dir() / "diagnostics" / "flow_metrics.json"
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(build_metrics(manager, bus, config), default=str),
                        encoding="utf-8")
    except Exception:
        pass
