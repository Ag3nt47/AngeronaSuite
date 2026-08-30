"""chaos_harness.py — Security Chaos Engineering self-test (CODE: CHAOS).

An internal "Bug Killer": on a slow cycle it fires safe, synthetic probes and
verifies the expected detector echoes back on the EventBus within a timeout. A
missing echo means that sensor has gone blind — a pipeline regression — and
CHAOS raises it loudly.

Probes
------
1. APID (API Patch Detector) — cooperative drill signal plus a complete live
   prologue observation made by the enrolled APID detector object.
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
   the DGA/entropy heuristic. The current NDRD input is shared-bus descriptive
   telemetry, so this leg deliberately remains unassured until an object-bound
   OS/network collector observes the query.

3. FIM — writes a unique inert text marker to one temporarily watched path and
   requires FIM to read and hash that exact file, then removes it.

4. AMSI — asks an enabled native AMSI provider to scan the standard benign
   EICAR health string in memory. Observation-only AMSI remains unassured.

No live API patching, executable payload, or hostile network target is used.
"""
from __future__ import annotations

import hashlib
import math
import os
import random
import secrets
import socket
import string
import tempfile
import time
from typing import Optional

from angerona.core.assurance_receipts import (
    AssuranceChallenge,
    AssuranceReceiptBroker,
    assurance_target_digest,
)
from angerona.core.module_base import BaseModule, Severity
from angerona.core.threat import event_disposition


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
    version = "1.13.0"

    ECHO_TIMEOUT_S = 20.0     # how long to wait for a detector to react

    def __init__(self, cycle_seconds: Optional[float] = None) -> None:
        super().__init__()
        env = os.getenv(_CYCLE_ENV)
        self._cycle = float(env) if env else (cycle_seconds or _DEFAULT_CYCLE_S)
        self._runs = 0
        self._failures = 0
        self._source_epoch = secrets.token_hex(16)
        self._assurance_broker: AssuranceReceiptBroker | None = None

    def bind_manager(self, manager) -> None:
        broker = getattr(manager, "assurance_receipt_broker", None)
        if isinstance(broker, AssuranceReceiptBroker):
            self._assurance_broker = broker

    # ── Bus echo detection ────────────────────────────────────────────────────
    def _challenge_digest(self, probe_id: str, probe_kind: str, target: str) -> str:
        payload = (
            "angerona-chaos-receipt-v1\0"
            f"{self._source_epoch}\0{probe_id}\0{probe_kind}\0{target}"
        ).encode("utf-8", errors="strict")
        return hashlib.sha256(payload).hexdigest()

    def _register_challenge(
        self,
        probe_kind: str,
        target_ref: str,
        evidence_digest: str = "",
        *,
        probe_id: str | None = None,
    ) -> AssuranceChallenge | None:
        broker = self._assurance_broker
        if broker is None:
            return None
        issued_at = time.time()
        token = probe_id or secrets.token_hex(16)
        target_digest = assurance_target_digest(
            probe_kind, target_ref, evidence_digest
        )
        challenge = AssuranceChallenge(
            probe_id=token,
            probe_kind=probe_kind,
            challenge_digest=self._challenge_digest(
                token, probe_kind, target_digest
            ),
            target_digest=target_digest,
            target_ref=target_ref,
            issued_at=issued_at,
            expires_at=issued_at + self.ECHO_TIMEOUT_S,
        )
        return challenge if broker.register_challenge(self, challenge) else None

    def _wait_for_echo(self, challenge: AssuranceChallenge | None) -> bool:
        """Accept only an object-bound, one-time detector receipt."""
        if challenge is None:
            return False
        broker = self._assurance_broker
        if broker is None:
            return False
        deadline = time.monotonic() + self.ECHO_TIMEOUT_S
        while time.monotonic() < deadline and not self.stopping:
            try:
                bus = self._bus
                if bus is None or not bus.integrity_enabled:
                    return False
                for ev in bus.recent(120):
                    try:
                        event_ts = float(ev.ts)
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if (
                        not math.isfinite(event_ts)
                        or event_ts < challenge.issued_at - 1.0
                        or event_ts > challenge.expires_at + 2.0
                        or ev.module == self.name
                        or not bus.verify(ev)
                        or event_disposition(ev) == "practice"
                    ):
                        continue
                    details = ev.details if isinstance(ev.details, dict) else {}
                    if (
                        details.get("probe_id") == challenge.probe_id
                        and details.get("probe_kind") == challenge.probe_kind
                        and ev.module == details.get("responder_module")
                        and broker.verify_and_consume(self, details)
                    ):
                        return True
            except Exception:
                pass
            self.sleep(1.0)
        return False

    # ── Probes ────────────────────────────────────────────────────────────────
    def _probe_apid(self) -> bool:
        challenge = self._register_challenge(
            "apid", "ntdll-kernel32-prologues-v1"
        )
        if challenge is None:
            return False
        # Cooperative drill signal — APID's self-test path listens for this.
        self.emit(
            "DRILL: APID coverage self-check requested.",
            Severity.INFO,
            drill="apid_selfcheck",
            assurance_challenge_version=1,
            probe_id=challenge.probe_id,
            probe_kind=challenge.probe_kind,
            challenge_digest=challenge.challenge_digest,
            target_digest=challenge.target_digest,
            target_ref=challenge.target_ref,
            chaos_epoch=self._source_epoch,
        )
        return self._wait_for_echo(challenge)

    def _probe_ndrd(self) -> bool:
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=28))
        host = f"{label}.{random.choice(_DRILL_DOMAINS)}"
        challenge = self._register_challenge("ndrd", host.casefold())
        if challenge is None:
            return False
        # Tell the sensor side this indicator is ours, so NDRD scores it as a
        # DRILL echo instead of raising a real HIGH threat on our own probe.
        try:
            from angerona.core import self_ioc
            self_ioc.register_domain(host, ttl=self.ECHO_TIMEOUT_S + 60.0)
        except Exception:
            pass
        self.emit(
            f"DRILL: high-entropy DNS probe → {host}",
            Severity.INFO,
            drill="ndrd_dga",
            host=host,
            assurance_challenge_version=1,
            probe_id=challenge.probe_id,
            probe_kind=challenge.probe_kind,
            challenge_digest=challenge.challenge_digest,
            target_digest=challenge.target_digest,
            target_ref=challenge.target_ref,
            chaos_epoch=self._source_epoch,
        )
        try:
            socket.getaddrinfo(host, None)   # expected to fail to resolve — that's fine
        except Exception:
            pass
        # NDRD currently consumes shared bus claims rather than an object-bound
        # OS DNS feed. It intentionally issues no assurance receipt from this
        # announcement, so this remains unassured unless genuine telemetry sees it.
        return self._wait_for_echo(challenge)

    def _probe_fim(self) -> bool:
        probe_id = secrets.token_hex(16)
        path = os.path.join(
            tempfile.gettempdir(), f"angerona_chaos_fim_{probe_id}.txt"
        )
        content = f"Angerona inert FIM assurance marker {probe_id}\n"
        content_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        challenge = self._register_challenge(
            "fim",
            os.path.abspath(path),
            content_digest,
            probe_id=probe_id,
        )
        if challenge is None:
            return False
        wrote = False
        watched = False
        try:
            from angerona.modules.file_integrity import register_runtime_watch

            watched = register_runtime_watch(tempfile.gettempdir())
            if not watched:
                return False
            with open(path, "x", encoding="ascii") as f:
                f.write(content)
            wrote = True
            self.emit(
                "DRILL: inert assurance marker written for FIM.",
                Severity.INFO,
                drill="fim_marker",
                path=path,
                assurance_challenge_version=1,
                probe_id=challenge.probe_id,
                probe_kind=challenge.probe_kind,
                challenge_digest=challenge.challenge_digest,
                target_digest=challenge.target_digest,
                target_ref=challenge.target_ref,
                chaos_epoch=self._source_epoch,
            )
            ok = self._wait_for_echo(challenge)
        except Exception as exc:
            self.emit(
                f"CHAOS: FIM assurance marker could not be written: {exc}",
                Severity.LOW,
            )
            ok = False
        finally:
            if wrote:
                try:
                    os.remove(path)
                except Exception:
                    pass
            if watched:
                try:
                    from angerona.modules.file_integrity import unregister_runtime_watch

                    unregister_runtime_watch(tempfile.gettempdir())
                except Exception:
                    pass
        return ok

    def _probe_amsi(self) -> bool:
        evidence_digest = hashlib.sha256(_eicar().encode("ascii")).hexdigest()
        challenge = self._register_challenge(
            "amsi", "eicar-health-check", evidence_digest
        )
        if challenge is None:
            return False
        self.emit(
            "DRILL: AMSI provider health observation requested.",
            Severity.INFO,
            drill="amsi_provider_health",
            assurance_challenge_version=1,
            probe_id=challenge.probe_id,
            probe_kind=challenge.probe_kind,
            challenge_digest=challenge.challenge_digest,
            target_digest=challenge.target_digest,
            target_ref=challenge.target_ref,
            chaos_epoch=self._source_epoch,
        )
        return self._wait_for_echo(challenge)

    # ── Cycle ─────────────────────────────────────────────────────────────────
    def run(self) -> None:
        # Small stagger so probes don't fire during startup churn.
        self.sleep(min(60.0, self._cycle))
        while not self.stopping:
            self._runs += 1
            results = {
                "APID": self._probe_apid(),
                "NDRD": self._probe_ndrd(),
                "FIM": self._probe_fim(),
                "AMSI": self._probe_amsi(),
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
                self.emit("Chaos self-test passed — APID, NDRD, FIM, AMSI all proved.",
                          Severity.INFO, results=results)
                self.set_health(100, "all detectors responsive")

            self.sleep(self._cycle)

    def self_test(self) -> tuple[bool, str]:
        return True, (f"cycle {self._cycle/3600:.1f}h; {self._runs} runs, "
                      f"{self._failures} with regressions")


def register() -> BaseModule:
    return ChaosHarness()
