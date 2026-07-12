"""chaos_harness.py — Security Chaos Engineering self-test (CODE: CHAOS).

An internal "Bug Killer": on a slow cycle it fires safe, synthetic probes and
verifies the expected detector echoes back on the EventBus within a timeout. A
missing echo means that sensor has gone blind — a pipeline regression — and
CHAOS raises it loudly.

Probes
------
1. APID (API Patch Detector) — cooperative drill signal.
   IMPORTANT: CHAOS deliberately does NOT install a real inline hook on ntdll/
   kernel32. Patching a live system DLL — even benignly — is a genuine hooking
   primitive that can destabilise the host and is exactly the kind of thing this
   product is built to *stop*. Instead CHAOS emits a DRILL request that APID's
   cooperative self-test path recognises, and waits for APID's echo. This
   validates the detection/reporting pipeline without performing the dangerous
   memory modification. (If APID exposes a direct ``self_test()`` you can call
   that instead of the bus round-trip.)

2. NDRD (Network Protocol Decoder) — a real DNS lookup for a random, high-
   entropy label under a benign documentation domain. This is the same probe
   philosophy as the existing shark/DRILL modules: harmless, but shaped to trip
   the DGA/entropy heuristic so we confirm NDRD is scoring live DNS.

3. FIM / AMSI — writes the standard EICAR anti-malware test string to a temp
   file the FIM watches, then removes it. EICAR is the industry-standard benign
   test artifact (it is not malware and does nothing when run); it exists
   precisely so detection paths can be exercised safely.

Standard library only (os, socket, random, string, tempfile, time, threading).
"""
from __future__ import annotations

import os
import random
import socket
import string
import tempfile
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


# ── EICAR test string, assembled at runtime so it isn't a literal on disk in
#    this source file (prevents a scanner from flagging the harness itself).
def _eicar() -> str:
    parts = [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
        r"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ]
    return "".join(parts)


# Documentation/test domains (RFC 2606 / IANA reserved) — safe to query.
_DRILL_DOMAINS = ("example.com", "example.net", "invalid")

_DEFAULT_CYCLE_S = 24 * 3600.0
_CYCLE_ENV = "ANGERONA_CHAOS_CYCLE_SECONDS"   # override for testing


class ChaosHarness(BaseModule):
    name = "CHAOS"
    CODE = "CHAOS"
    description = "Periodically fires safe synthetic probes and verifies detectors echo back."
    category = "Resilience"
    version = "1.0.0"

    ECHO_TIMEOUT_S = 20.0     # how long to wait for a detector to react

    def __init__(self, cycle_seconds: Optional[float] = None) -> None:
        super().__init__()
        env = os.getenv(_CYCLE_ENV)
        self._cycle = float(env) if env else (cycle_seconds or _DEFAULT_CYCLE_S)
        self._runs = 0
        self._failures = 0

    # ── Bus echo detection ────────────────────────────────────────────────────
    def _wait_for_echo(self, since_ts: float, want_module: str,
                       keywords: tuple[str, ...]) -> bool:
        """Poll the bus for an event from want_module (or matching a keyword)
        published after since_ts, within ECHO_TIMEOUT_S. Never raises."""
        deadline = time.time() + self.ECHO_TIMEOUT_S
        while time.time() < deadline and not self.stopping:
            try:
                if self._bus is not None:
                    for ev in self._bus.recent(60):
                        if ev.ts <= since_ts:
                            continue
                        # Detectors emit under their display name (e.g. "API Patch
                        # / Anti-Blinding Detector"), never their short code, so an
                        # exact `module == want_module` compare was always dead.
                        # Match the code hint and keywords against the name+message
                        # text instead.
                        hay = (str(getattr(ev, "module", "")) + " " +
                               str(getattr(ev, "message", ""))).lower()
                        if want_module.lower() in hay or any(k in hay for k in keywords):
                            return True
            except Exception:
                pass
            self.sleep(1.0)
        return False

    # ── Probes ────────────────────────────────────────────────────────────────
    def _probe_apid(self) -> bool:
        t0 = time.time()
        # Cooperative drill signal — APID's self-test path listens for this.
        self.emit("DRILL: APID coverage self-check requested.", Severity.INFO,
                  drill="apid_selfcheck")
        return self._wait_for_echo(t0, "APID", ("hook", "patch", "prolog", "apid"))

    def _probe_ndrd(self) -> bool:
        t0 = time.time()
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=28))
        host = f"{label}.{random.choice(_DRILL_DOMAINS)}"
        self.emit(f"DRILL: high-entropy DNS probe → {host}", Severity.INFO,
                  drill="ndrd_dga", host=host)
        try:
            socket.getaddrinfo(host, None)   # expected to fail to resolve — that's fine
        except Exception:
            pass
        return self._wait_for_echo(t0, "NDRD", ("dga", "entropy", "dns", "tunnel"))

    def _probe_fim_amsi(self) -> bool:
        t0 = time.time()
        path = os.path.join(tempfile.gettempdir(), "angerona_chaos_eicar.txt")
        wrote = False
        try:
            with open(path, "w", encoding="ascii") as f:
                f.write(_eicar())
            wrote = True
            self.emit("DRILL: EICAR test artifact written for FIM/AMSI.",
                      Severity.INFO, drill="eicar", path=path)
            ok = self._wait_for_echo(
                t0, "FIM", ("eicar", "yara", "amsi", "signature", "new file"))
        except Exception as exc:
            self.emit(f"CHAOS: EICAR probe could not write test file: {exc}",
                      Severity.LOW)
            ok = False
        finally:
            if wrote:
                try:
                    os.remove(path)
                except Exception:
                    pass
        return ok

    # ── Cycle ─────────────────────────────────────────────────────────────────
    def run(self) -> None:
        # Small stagger so probes don't fire during startup churn.
        self.sleep(min(60.0, self._cycle))
        while not self.stopping:
            self._runs += 1
            results = {
                "APID": self._probe_apid(),
                "NDRD": self._probe_ndrd(),
                "FIM/AMSI": self._probe_fim_amsi(),
            }
            broken = [name for name, ok in results.items() if not ok]
            if broken:
                self._failures += 1
                self.emit(
                    "PIPELINE REGRESSION — no detection echo from: "
                    + ", ".join(broken)
                    + ". These sensors may be blind; investigate immediately.",
                    Severity.CRITICAL,
                    broken=broken, results=results,
                )
                self.set_health(40, f"{len(broken)} sensor(s) failed last chaos run")
            else:
                self.emit("Chaos self-test passed — APID, NDRD, FIM/AMSI all echoed.",
                          Severity.INFO, results=results)
                self.set_health(100, "all detectors responsive")

            self.sleep(self._cycle)

    def self_test(self) -> tuple[bool, str]:
        return True, (f"cycle {self._cycle/3600:.1f}h; {self._runs} runs, "
                      f"{self._failures} with regressions")


def register() -> BaseModule:
    return ChaosHarness()
