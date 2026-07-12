"""Active deception — canary files/honeytokens + DYNAMIC re-staging (DEC).

Plants tripwire files and alerts the moment anything touches them. Beyond the
static canaries, this module now watches the red-team attack feed: when an
attacker triggers discovery / lateral-movement / credential-hunting activity, a
trap is considered 'burned', so the module autonomously RE-STAGES fresh, highly
alluring honeytokens (and, on Windows, fake registry credentials) mapped to what
the adversary is actively probing. Any interaction with a registered trap raises
a zero-trust SOAR isolation recommendation to shared_logs/soar_events.json.
"""
from __future__ import annotations

import ctypes
import json
import os
import random
import subprocess
import sys
import time
import uuid
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

CANARY_NAMES = ["passwords.txt", "wallet.dat", "backup_keys.txt"]

# Keep decoys OUT OF SIGHT. HIDDEN alone still shows when the user has
# "show hidden files" on; HIDDEN|SYSTEM stays invisible unless they also disable
# "hide protected operating-system files" — so honeytokens don't clutter the
# desktop/Documents view while remaining fully effective as tripwires.
_FILE_ATTRIBUTE_HIDDEN = 0x02
_FILE_ATTRIBUTE_SYSTEM = 0x04


def _hide_file(path) -> None:
    """Best-effort: mark a decoy hidden+system so the user never sees it."""
    if not sys.platform.startswith("win"):
        return
    try:
        ctypes.windll.kernel32.SetFileAttributesW(
            str(path), _FILE_ATTRIBUTE_HIDDEN | _FILE_ATTRIBUTE_SYSTEM)
    except Exception:
        pass

# Alluring lures used when re-staging — names chosen to match what a
# credential-hunting / persistence-seeking adversary tends to probe for.
_RESTAGE_LURES = ["aws_credentials.txt", "id_rsa", "vpn_config.ovpn",
                  "lsass_dump.bak", "domain_admin_creds.txt", "kdbx_master.txt"]

# Attack-feed keywords that mean "a trap/phase is burned → re-stage".
_BURN_KEYWORDS = ("discovery", "lateral", "credential", "lsass", "cred",
                  "recon", "enumerat", "wmi", "persistence")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


class DeceptionModule(BaseModule):
    name = "Active Deception"
    description = "Plants canaries/honeytokens and DYNAMICALLY re-stages fresh traps when one is burned."
    category = "Deception"

    def __init__(self) -> None:
        super().__init__()
        self._canaries: dict[str, float] = {}
        self._base = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents"
        self._shared = _repo_root() / "shared_logs"
        self._feed = self._shared / "attack_feed.log"
        self._soar = self._shared / "soar_events.json"
        self._feed_pos = 0
        self._restage_count = 0

    def _plant(self) -> None:
        self._base.mkdir(parents=True, exist_ok=True)
        for nm in CANARY_NAMES:
            p = self._base / nm
            try:
                if not p.exists():
                    p.write_text("# Do not modify — security canary.\n", encoding="utf-8")
                _hide_file(p)
                self._canaries[str(p)] = p.stat().st_mtime
            except Exception:
                continue

    def run(self) -> None:
        self._plant()
        self.emit(f"Planted {len(self._canaries)} canary files.", Severity.INFO)
        try:
            self._shared.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        while not self.stopping:
            self.sleep(5)
            self._check_canaries()
            self._watch_attack_feed()

    # ── static + dynamic trap monitoring ─────────────────────────────────────
    def _check_canaries(self) -> None:
        for path, baseline in list(self._canaries.items()):
            try:
                mtime = os.stat(path).st_mtime
            except FileNotFoundError:
                self.emit(f"Canary file DELETED: {path}", Severity.CRITICAL, path=path)
                self._soar_isolation(path, "canary deleted")
                self._canaries.pop(path, None)
                continue
            except Exception:
                continue
            if mtime != baseline:
                self.emit(f"Canary file TOUCHED: {path}", Severity.CRITICAL, path=path)
                self._soar_isolation(path, "canary touched")
                self._canaries[path] = mtime

    def _watch_attack_feed(self) -> None:
        """Tail attack_feed.log; a discovery / lateral / credential-hunt entry means
        a trap is 'burned' → autonomously re-stage fresh traps mapped to the probe."""
        try:
            if not self._feed.exists():
                return
            if self._feed.stat().st_size < self._feed_pos:
                self._feed_pos = 0
            with open(self._feed, encoding="utf-8") as f:
                f.seek(self._feed_pos)
                lines = f.readlines()
                self._feed_pos = f.tell()
        except Exception:
            return
        for ln in lines:
            if any(k in ln.lower() for k in _BURN_KEYWORDS):
                self._restage(ln.strip()[:160])

    # ── autonomous re-staging ────────────────────────────────────────────────
    def _restage(self, context: str) -> None:
        if self._restage_count >= 12:          # cap dynamically-created traps
            return
        lure = random.choice(_RESTAGE_LURES)
        hexid = uuid.uuid4().hex[:8]
        name = f"{Path(lure).stem}_{hexid}{Path(lure).suffix or '.txt'}"
        p = self._base / name
        try:
            p.write_text("# HONEYTOKEN — decoy credentials. Any access is logged & isolated.\n"
                         "username=svc_admin\npassword=Winter2026!\n", encoding="utf-8")
            _hide_file(p)
            self._canaries[str(p)] = p.stat().st_mtime   # register so touch → SOAR
            self._restage_count += 1
            self.emit(f"🍯 Re-staged honeytoken '{name}' (trap burned by: {context})",
                      Severity.INFO, artifact=str(p))
        except Exception:
            return
        self._plant_fake_registry_cred(name)

    def _plant_fake_registry_cred(self, name: str) -> None:
        """Windows only: drop a fake credential under a decoy HKCU key. Any read of
        it (by the mutated shark_attack cred-hunt) is a definitive tripwire."""
        if not sys.platform.startswith("win"):
            return
        try:
            subprocess.run(
                ["reg", "add", r"HKCU\Software\Angerona\HoneyCreds", "/v", name,
                 "/t", "REG_SZ", "/d", "svc_admin:Winter2026!", "/f"],
                capture_output=True, timeout=8)
        except Exception:
            pass

    def _soar_isolation(self, artifact: str, reason: str) -> None:
        """Any trap interaction → zero-trust isolation recommendation for SOAR."""
        ev = {"ts": time.time(), "type": "TRAP_INTERACTION", "severity": "Critical",
              "artifact": artifact, "reason": reason,
              "recommend": "zero-trust isolate + suspend actor", "auto_applied": False}
        try:
            self._shared.mkdir(parents=True, exist_ok=True)
            with open(self._soar, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass
