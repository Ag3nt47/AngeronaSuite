"""verify.py — Continuous-Verification Gate helper (Test-Driven Defense).

Runs ONE technique's non-destructive footprint, then watches the shared
flight-recorder ledger (written by the RUNNING app's detection modules) to see
whether a detector caught it, and prints exactly one line to stdout:

    VERIFICATION_RESULT: BLOCKED     — a detector fired → the mitigation holds
    VERIFICATION_RESULT: SUCCESS     — the footprint slipped past → fix failed
    VERIFICATION_RESULT: ERROR (...) — could not run the check

Invoked by the Posture Hardening (HARD) Judgment loop as a hidden subprocess:
    python -m angerona.shark.verify <technique_id> [--settle SECONDS]

SAFETY: identical model to red_team.py — drops a single INERT, benignly-named
marker in Documents (so File Integrity Monitor can notice it) and deletes it
afterward. Nothing real is touched.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from pathlib import Path

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
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    return home / "Documents"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Angerona continuous-verification gate.")
    ap.add_argument("technique_id")
    ap.add_argument("--verify", action="store_true",
                    help="Accepted for compatibility; verification is the only mode.")
    ap.add_argument("--settle", type=float, default=40.0,
                    help="How long to wait for the running defense to react (s).")
    args = ap.parse_args(argv)
    tid = args.technique_id

    label, tmpl = _TECH.get(tid, ("Generic technique", "_verify_generic_{h}.txt"))
    try:
        from angerona.core.config import Config
        from angerona.core.storage import FlightRecorder
    except Exception as exc:
        print(f"VERIFICATION_RESULT: ERROR (imports: {exc})")
        return 2

    cfg = Config.load()
    docs = _documents()
    marker = docs / tmpl.format(h=uuid.uuid4().hex[:8])
    t0 = time.time()
    try:
        docs.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            f"ANGERONA verification probe for {tid} ({label}). Inert drill artifact.\n",
            encoding="utf-8")
    except Exception as exc:
        print(f"VERIFICATION_RESULT: ERROR (marker drop: {exc})")
        return 2

    name = marker.name
    detected = False
    deadline = t0 + max(4.0, args.settle)
    try:
        while time.time() < deadline and not detected:
            time.sleep(2.0)
            try:
                rec = FlightRecorder(cfg.db_path)
                try:
                    events = rec.recent(600)
                finally:
                    rec.close()
            except Exception:
                events = []
            for ev in events:
                msg = ev.message or ""
                if ev.ts >= t0 - 2 and (name in msg or str(marker) in msg):
                    detected = True
                    break
    finally:
        try:
            marker.unlink(missing_ok=True)
        except Exception:
            pass

    print(f"VERIFICATION_RESULT: {'BLOCKED' if detected else 'SUCCESS'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
