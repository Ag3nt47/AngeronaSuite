"""verify.py — Continuous-Verification Gate helper (Test-Driven Defense).

Runs ONE technique's non-destructive footprint, then watches the shared
flight-recorder ledger (written by the RUNNING app's detection modules) to see
whether a detector caught it, and prints exactly one bounded JSON receipt. The
receipt binds a fresh parent nonce, this verifier's SHA-256, inert marker digest,
exact technique/test identity, complete-window count, and the detector event's
independently verifiable HMAC. Errors exit non-zero and can never certify state.

Invoked by the Posture Hardening (HARD) Judgment loop as a hidden subprocess:
    The parent launches this exact source via isolated Python and supplies a
    fresh ``--nonce``. Direct text markers are intentionally unsupported.

SAFETY: identical model to red_team.py — drops a single INERT, benignly-named
marker in Angerona's D: drill sandbox (watched by File Integrity Monitor) and
deletes it afterward. Nothing real is touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from angerona.core import report_attest


_RECEIPT_SCHEMA = "angerona.judgment.receipt.v2"
_TEST_IDENTITY = "angerona.inert-marker-and-durable-recorder.v2"
_NONCE = re.compile(r"[0-9a-f]{32}")

# technique id (MITRE or engine key) -> (human label, marker filename template)
_TECH = {
    "T1003":     ("Credential Access", "_verify_lsass_dump_{h}.txt"),
    "T1546.003": ("WMI Persistence",   "_verify_wmi_subscription_{h}.txt"),
    "T1070":     ("Defense Evasion",   "_verify_amsi_bypass_{h}.txt"),
    "T1547.001": ("Persistence",       "_verify_runkey_{h}.txt"),
    "T1055":     ("EDR Bypass",        "_verify_parent_spoof_{h}.txt"),
    "T1071.001": ("C2 Beacon",         "_verify_beacon_{h}.txt"),
    "T1083":     ("Deception Probe",   "_verify_canary_probe_{h}.txt"),
}


def _documents() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir() / "drill-sandbox"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Angerona continuous-verification gate.")
    ap.add_argument("technique_id")
    ap.add_argument("--verify", action="store_true",
                    help="Accepted for compatibility; verification is the only mode.")
    ap.add_argument("--settle", type=float, default=40.0,
                    help="How long to wait for the running defense to react (s).")
    ap.add_argument("--nonce", required=True,
                    help="Fresh parent challenge bound into marker and receipt.")
    args = ap.parse_args(argv)
    tid = args.technique_id
    if _NONCE.fullmatch(args.nonce) is None:
        return 2

    label, tmpl = _TECH.get(tid, ("Generic technique", "_verify_generic_{h}.txt"))
    started = time.time()
    verifier_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def emit(
        outcome: str,
        *,
        marker_name: str = "",
        marker_sha256: str = "0" * 64,
        events_examined: int = 0,
        event=None,
    ) -> None:
        receipt = {
            "schema": _RECEIPT_SCHEMA,
            "nonce": args.nonce,
            "technique_id": tid,
            "outcome": outcome,
            "test_identity": _TEST_IDENTITY,
            "verifier_sha256": verifier_sha256,
            "marker_name": marker_name,
            "marker_sha256": marker_sha256,
            "started_at": started,
            "completed_at": time.time(),
            "events_examined": int(events_examined),
            "event": event,
        }
        print(json.dumps(report_attest.attest(receipt), sort_keys=True, default=str))

    try:
        from angerona.core.config import Config
        from angerona.core.storage import FlightRecorder
    except Exception:
        emit("ERROR")
        return 2

    cfg = Config.load()
    docs = _documents()
    marker = docs / tmpl.format(h=args.nonce[:12])
    marker_payload = (
        f"ANGERONA verification probe for {tid} ({label}); "
        f"nonce={args.nonce}. Inert drill artifact.\n"
    ).encode("utf-8")
    marker_sha256 = hashlib.sha256(marker_payload).hexdigest()
    try:
        docs.mkdir(parents=True, exist_ok=True)
        with marker.open("xb") as stream:
            stream.write(marker_payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        emit(
            "ERROR",
            marker_name=marker.name,
            marker_sha256=marker_sha256,
        )
        return 2

    name = marker.name
    detected_event = None
    coverage_error = False
    events_examined = 0
    deadline = started + max(4.0, min(float(args.settle), 120.0))
    try:
        while time.time() < deadline and detected_event is None and not coverage_error:
            time.sleep(2.0)
            try:
                rec = FlightRecorder(cfg.db_path)
                try:
                    events, total = rec.bounded_events_in_window(
                        started - 2.0,
                        time.time(),
                        limit=10_000,
                    )
                finally:
                    rec.close()
            except Exception:
                coverage_error = True
                break
            events_examined = total
            if total != len(events):
                coverage_error = True
                break
            for ev in events:
                if (ev.details or {}).get("_ledger_integrity") in {
                    "invalid",
                    "legacy-unsigned",
                }:
                    coverage_error = True
                    break
                msg = ev.message or ""
                if ev.ts >= started - 2 and (name in msg or str(marker) in msg):
                    detected_event = {
                        "module": ev.module,
                        "message": ev.message,
                        "severity": int(ev.severity),
                        "ts": ev.ts,
                        "details": ev.details or {},
                        "hmac_sig": ev.hmac_sig,
                    }
                    break
    finally:
        try:
            marker.unlink(missing_ok=True)
        except Exception:
            pass

    if coverage_error:
        emit(
            "ERROR",
            marker_name=name,
            marker_sha256=marker_sha256,
            events_examined=events_examined,
        )
        return 2
    emit(
        "BLOCKED" if detected_event is not None else "SUCCESS",
        marker_name=name,
        marker_sha256=marker_sha256,
        events_examined=events_examined,
        event=detected_event,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
