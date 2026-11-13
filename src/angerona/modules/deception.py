"""Active deception — admitted-canary mutation/deletion monitoring (DEC).

Monitors admitted tripwire files for content mutation or deletion. Windows new
file/directory/attribute mutations are held pending an object-relative provider;
exact preexisting static canaries remain read-only observable. Ordinary POSIX
deployment can re-stage bounded honeytokens from the attack feed. Registry
lures remain held for exclusive ownership. This module proves file mutation/deletion
coverage only. It never calls a plain read a detection: native audited-read and
registry-read visibility require a separately configured OS audit source.
"""
from __future__ import annotations

import hashlib
import os
import random
import tempfile
import time
import uuid
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity
from angerona.core import deception_io

CANARY_NAMES = ["passwords.txt", "wallet.dat", "backup_keys.txt"]

# Exact capability result; this is neither fixture success nor live coverage.
DECEPTION_WINDOWS_CREATION_HELD = (
    "Windows native canary creation is held pending a reviewed object-relative provider; "
    "this diagnostic does not verify native deployment or live monitoring"
)

_STATIC_CANARY_BYTES = "# Do not modify — security canary.\n".encode("utf-8")
_DYNAMIC_CANARY_BYTES = (
    "# HONEYTOKEN — decoy credentials. File mutation or deletion "
    "is logged; audited reads require the configured OS audit source.\n"
    "username=svc_admin\npassword=Winter2026!\n"
).encode("utf-8")

# Alluring lures used when re-staging — names chosen to match what a
# credential-hunting / persistence-seeking adversary tends to probe for.
_RESTAGE_LURES = ["aws_credentials.txt", "id_rsa", "vpn_config.ovpn",
                  "lsass_dump.bak", "domain_admin_creds.txt", "kdbx_master.txt"]

# Attack-feed keywords that mean "a trap/phase is burned → re-stage".
_BURN_KEYWORDS = ("discovery", "lateral", "credential", "lsass", "cred",
                  "recon", "enumerat", "wmi", "persistence")


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _user_folder_deception_enabled() -> bool:
    """Personal-folder and registry decoys require explicit informed opt-in."""
    return os.environ.get("ANGERONA_USER_FOLDER_DECEPTION", "0").strip().casefold() in {
        "1", "true", "yes", "on",
    }


class DeceptionModule(BaseModule):
    name = "Active Deception"
    description = (
        "Monitors admitted canaries for file mutation/deletion; Windows new "
        "deployment is held. Audited reads need an external OS source."
    )
    category = "Deception"
    version = "1.14.0"

    def __init__(self) -> None:
        super().__init__()
        self._canaries: dict[str, float] = {}
        self._canary_evidence: dict[str, tuple[int, int, int, int, str]] = {}
        self._user_scope = _user_folder_deception_enabled()
        # Personal-folder resolution is lazy and token-bound in the worker.
        self._base = None if self._user_scope else _repo_root() / "deception" / "static"
        self._shared = _repo_root() / "shared_logs"
        self._feed = self._shared / "attack_feed.log"
        self._soar = self._shared / "soar_events.json"
        self._feed_pos = 0
        self._feed_identity: tuple[int, int, int, int, int] | None = None
        self._restage_count = 0
        self._restage_attempts = 0
        self._canary_hold_reasons: list[str] = []
        self._canary_hold_details: list[str] = []
        self._registry_lure_held = "Legacy registry lures are held until exclusive key ownership is available"
        self._legacy_export_held = "Legacy shared-log export is held; authenticated EventBus alerts remain active"

    @staticmethod
    def _canary_snapshot(path: Path) -> tuple[float, tuple[int, int, int, int, str]]:
        observed = deception_io.snapshot(path)
        return observed.mtime, observed.evidence

    def _remember_snapshot(self, observed: deception_io.Snapshot) -> None:
        if self._base is None:
            self._base = observed.path.parent
        key = str(observed.path)
        self._canaries[key] = observed.mtime
        self._canary_evidence[key] = observed.evidence

    def _enroll_canary(self, path: Path) -> None:
        self._remember_snapshot(deception_io.snapshot(path))

    def _plant(self, *, diagnostic_errors: list[str] | None = None) -> None:
        for position, name in enumerate(CANARY_NAMES, 1):
            try:
                deception_io.create_canary(self._base, name, _STATIC_CANARY_BYTES,
                    personal=self._user_scope, adopt_static=True, on_admitted=self._remember_snapshot)
            except Exception as error:
                reason = f"slot{position}:{type(error).__name__[:80]}"
                if len(self._canary_hold_reasons) < len(CANARY_NAMES):
                    self._canary_hold_reasons.append(reason)
                if isinstance(error, deception_io.CanaryHeld) and len(self._canary_hold_details) < 8:
                    self._canary_hold_details.append(str(error)[:240])
                if diagnostic_errors is not None and len(diagnostic_errors) < len(CANARY_NAMES):
                    diagnostic_errors.append(reason)
                continue

    def self_test(self) -> tuple[bool, str]:
        """Exercise disposable planting only where new deployment is available."""
        if os.name == "nt":
            return False, DECEPTION_WINDOWS_CREATION_HELD
        try:
            with tempfile.TemporaryDirectory(prefix="angerona-deception-selftest-") as temp:
                root = Path(temp).resolve()
                probe = DeceptionModule()
                probe._user_scope = False  # Never resolve operator Documents during diagnostics.
                probe._base = root / "static"
                errors: list[str] = []
                probe._plant(diagnostic_errors=errors)
                if errors:
                    return False, "disposable canary enrollment failed: " + "; ".join(errors)[:300]
                paths = [Path(path).absolute() for path in probe._canaries]
                if len(paths) != len(CANARY_NAMES):
                    return False, (
                        f"canary count contract failed: expected={len(CANARY_NAMES)}; "
                        f"observed={len(paths)}"
                    )
                if not all(path.parent == probe._base.absolute() for path in paths):
                    return False, "canary path contract failed"
                if {path.name for path in paths} != set(CANARY_NAMES):
                    return False, "canary names contract failed"
                expected = "# Do not modify — security canary.\n"
                for position, path in enumerate(paths, 1):
                    observed = deception_io.snapshot(path)
                    if (observed.evidence[2] != len(expected.encode("utf-8"))
                            or observed.evidence[-1] != hashlib.sha256(expected.encode("utf-8")).hexdigest()):
                        return False, f"canary content contract failed: slot{position}"
        except Exception as exc:
            return False, f"disposable canary fixture failed: {type(exc).__name__[:80]}"
        return True, "disposable secret-free canary lifecycle passed"

    def run(self) -> None:
        self._plant()
        if self._canary_hold_reasons:
            self.set_health(35 if self._canaries else 0,
                f"Canary deployment held/partial: {len(self._canaries)} admitted; "
                "inspect slot custody; audited file/registry read telemetry is unavailable")
        else:
            self.set_health(70 if len(self._canaries) == len(CANARY_NAMES) else 45,
                "file mutation/deletion visibility active; audited file/registry "
                "read telemetry is unavailable in this module")
        self.emit(
            f"Admitted {len(self._canaries)} canary files for mutation/deletion "
            "observation; audited reads are not claimed.",
            Severity.INFO,
            coverage="file-mutation-and-deletion",
            deployment_mode=("windows-new-mutations-held" if os.name == "nt" else "ordinary-local-create"),
            new_deployment_available=os.name != "nt",
            read_visibility=False,
            evidence_path=str(self._base),
            held_slots=list(self._canary_hold_reasons),
            hold_details=list(self._canary_hold_details),
            registry_lures="held-exclusive-ownership-unavailable",
            legacy_export="held-authenticated-eventbus-preserved",
        )
        while not self.stopping:
            self.sleep(5)
            self._check_canaries()
            self._watch_attack_feed()

    # ── static + dynamic trap monitoring ─────────────────────────────────────
    def _check_canaries(self) -> None:
        unreadable = 0
        for path, baseline in list(self._canaries.items()):
            try:
                mtime, evidence = self._canary_snapshot(Path(path))
            except FileNotFoundError:
                self.emit(f"Canary file DELETED: {path}", Severity.CRITICAL, path=path)
                self._soar_isolation(path, "canary deleted")
                self._canaries.pop(path, None)
                self._canary_evidence.pop(path, None)
                continue
            except Exception:
                unreadable += 1
                continue
            expected = self._canary_evidence.get(path)
            if mtime != baseline or expected is None or evidence != expected:
                self.emit(f"Canary file TOUCHED: {path}", Severity.CRITICAL, path=path)
                self._soar_isolation(path, "canary touched")
                self._canaries[path] = mtime
                self._canary_evidence[path] = evidence
        remaining = len(self._canaries)
        if remaining == 0:
            self.set_health(
                0,
                "canary mutation/deletion visibility unavailable: zero canaries remain",
            )
        elif unreadable:
            self.set_health(
                35,
                f"canary visibility unavailable for {unreadable} object(s); "
                f"{remaining} trap(s) remain enrolled",
            )
        elif remaining < len(CANARY_NAMES):
            self.set_health(
                45,
                f"partial canary mutation/deletion visibility: {remaining}/"
                f"{len(CANARY_NAMES)} baseline traps remain",
            )
        else:
            self.set_health(
                70,
                "file mutation/deletion visibility active; audited file/registry "
                "read telemetry is unavailable in this module",
            )

    def _watch_attack_feed(self) -> None:
        """Tail attack_feed.log; a discovery / lateral / credential-hunt entry means
        a trap is 'burned' → autonomously re-stage fresh traps mapped to the probe."""
        try:
            stat = self._feed.stat()
            identity = (
                int(getattr(stat, "st_dev", 0)),
                int(getattr(stat, "st_ino", 0)),
                int(stat.st_size),
                int(stat.st_mtime_ns),
                int(stat.st_ctime_ns),
            )
            # Keep the five-second canary/detection cadence, but do not reopen
            # an unchanged file on every pass.  Size + high-resolution times +
            # file identity also detect truncation and atomic replacement.
            if identity == self._feed_identity:
                return
            if stat.st_size < self._feed_pos:
                self._feed_pos = 0
            with open(self._feed, encoding="utf-8") as f:
                f.seek(self._feed_pos)
                lines = f.readlines()
                self._feed_pos = f.tell()
            # Record the pre-open identity only after a successful read.  If a
            # writer appends concurrently, the next pass observes a new stamp
            # and resumes from the exact text-stream cookie above.
            self._feed_identity = identity
        except Exception:
            return
        for ln in lines:
            if any(k in ln.lower() for k in _BURN_KEYWORDS):
                self._restage(ln.strip()[:160])

    # ── autonomous re-staging ────────────────────────────────────────────────
    def _restage(self, context: str) -> None:
        if self._restage_attempts >= 12:
            return
        self._restage_attempts += 1  # Partial/held attempts cannot grow storage forever.
        lure = random.choice(_RESTAGE_LURES)
        hexid = uuid.uuid4().hex[:8]
        name = f"{Path(lure).stem}_{hexid}{Path(lure).suffix or '.txt'}"
        try:
            observed = deception_io.create_canary(self._base, name, _DYNAMIC_CANARY_BYTES,
                personal=self._user_scope, on_admitted=self._remember_snapshot)
            self._restage_count += 1
            self.emit(f"🍯 Re-staged honeytoken '{name}' (trap burned by: {context})",
                      Severity.INFO, artifact=str(observed.path), registry_lure="held")
        except Exception as error:
            if len(self._canary_hold_reasons) < 8:
                self._canary_hold_reasons.append("restage:" + type(error).__name__[:80])
            if isinstance(error, deception_io.CanaryHeld) and len(self._canary_hold_details) < 8:
                self._canary_hold_details.append(str(error)[:240])
            return
        self._plant_fake_registry_cred(name)

    def _plant_fake_registry_cred(self, name: str) -> None:
        """No reg ADD /f: unknown existing values and native search order are refused."""
        self._registry_lure_held = "Legacy registry lures are held until exclusive key ownership is available"

    def _soar_isolation(self, artifact: str, reason: str) -> None:
        """Keep original EventBus detection; never append through legacy paths."""
        self._legacy_export_held = "Legacy shared-log export is held; authenticated EventBus alerts remain active"
