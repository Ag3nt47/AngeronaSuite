"""Active deception — canary-file mutation/deletion + dynamic re-staging (DEC).

Plants tripwire files and alerts the moment anything touches them. Beyond the
static canaries, this module watches the red-team attack feed: when an
attacker triggers discovery / lateral-movement / credential-hunting activity, a
trap is considered 'burned', so the module autonomously RE-STAGES fresh, highly
alluring honeytokens (and, on Windows, fake registry credentials) mapped to what
the adversary is actively probing. This module proves file mutation/deletion
coverage only. It never calls a plain read a detection: native audited-read and
registry-read visibility require a separately configured OS audit source.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import random
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

CANARY_NAMES = ["passwords.txt", "wallet.dat", "backup_keys.txt"]
_MAX_CANARY_BYTES = 64 * 1024

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
        "Plants canaries/honeytokens, detects file mutation/deletion, and "
        "dynamically re-stages traps; audited reads need an external OS source."
    )
    category = "Deception"
    version = "1.12.1"

    def __init__(self) -> None:
        super().__init__()
        self._canaries: dict[str, float] = {}
        self._canary_evidence: dict[str, tuple[int, int, int, int, str]] = {}
        self._user_scope = _user_folder_deception_enabled()
        self._base = (
            Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents"
            if self._user_scope
            else _repo_root() / "deception" / "static"
        )
        self._shared = _repo_root() / "shared_logs"
        self._feed = self._shared / "attack_feed.log"
        self._soar = self._shared / "soar_events.json"
        self._feed_pos = 0
        self._feed_identity: tuple[int, int, int, int, int] | None = None
        self._restage_count = 0

    @staticmethod
    def _canary_snapshot(path: Path) -> tuple[float, tuple[int, int, int, int, str]]:
        """Return a bounded identity/content snapshot without following links."""
        before = os.lstat(path)
        attributes = int(getattr(before, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or bool(attributes & 0x400)
            or int(before.st_size) > _MAX_CANARY_BYTES
        ):
            raise OSError("canary object is unsafe or oversized")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                int(opened.st_dev) != int(before.st_dev)
                or int(opened.st_ino) != int(before.st_ino)
                or int(opened.st_size) != int(before.st_size)
            ):
                raise OSError("canary identity changed while opening")
            digest = hashlib.sha256()
            remaining = _MAX_CANARY_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(16 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                raise OSError("canary content exceeded its bound")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named = os.lstat(path)
        identity = (int(after.st_dev), int(after.st_ino))
        if (
            identity != (int(before.st_dev), int(before.st_ino))
            or identity != (int(named.st_dev), int(named.st_ino))
            or int(after.st_size) != int(named.st_size)
            or int(after.st_mtime_ns) != int(named.st_mtime_ns)
        ):
            raise OSError("canary changed while being sampled")
        evidence = (
            identity[0],
            identity[1],
            int(after.st_size),
            int(after.st_mtime_ns),
            digest.hexdigest(),
        )
        return float(after.st_mtime), evidence

    def _enroll_canary(self, path: Path) -> None:
        mtime, evidence = self._canary_snapshot(path)
        key = str(path)
        # Preserve the historical float map for compatible diagnostics while
        # keeping the real authorization evidence private and non-lossy.
        self._canaries[key] = mtime
        self._canary_evidence[key] = evidence

    def _plant(self) -> None:
        self._base.mkdir(parents=True, exist_ok=True)
        for nm in CANARY_NAMES:
            p = self._base / nm
            try:
                if not p.exists():
                    p.write_text("# Do not modify — security canary.\n", encoding="utf-8")
                _hide_file(p)
                self._enroll_canary(p)
            except Exception:
                continue

    def self_test(self) -> tuple[bool, str]:
        """Plant only inert namespaced fixtures in a disposable directory."""
        original_base = self._base
        original_canaries = self._canaries
        original_evidence = self._canary_evidence
        try:
            with tempfile.TemporaryDirectory(prefix="angerona-deception-selftest-") as temp:
                root = Path(temp).resolve()
                self._base = root / "static"
                self._canaries = {}
                self._canary_evidence = {}
                self._plant()
                paths = [Path(path).resolve() for path in self._canaries]
                ok = bool(
                    len(paths) == len(CANARY_NAMES)
                    and all(path.parent == self._base.resolve() for path in paths)
                    and {path.name for path in paths} == set(CANARY_NAMES)
                    and all(
                        path.read_text(encoding="utf-8")
                        == "# Do not modify — security canary.\n"
                        for path in paths
                    )
                )
        except Exception as exc:
            return False, f"disposable canary fixture failed: {exc}"
        finally:
            self._base = original_base
            self._canaries = original_canaries
            self._canary_evidence = original_evidence
        return (
            ok,
            "disposable secret-free canary lifecycle passed"
            if ok else "canary path/content contract failed",
        )

    def run(self) -> None:
        self._plant()
        self.set_health(
            70 if len(self._canaries) == len(CANARY_NAMES) else 45,
            "file mutation/deletion visibility active; audited file/registry "
            "read telemetry is unavailable in this module",
        )
        self.emit(
            f"Planted {len(self._canaries)} canary files with mutation/deletion "
            "coverage; audited reads are not claimed.",
            Severity.INFO,
            coverage="file-mutation-and-deletion",
            read_visibility=False,
            evidence_path=str(self._base),
        )
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
        if self._restage_count >= 12:          # cap dynamically-created traps
            return
        lure = random.choice(_RESTAGE_LURES)
        hexid = uuid.uuid4().hex[:8]
        name = f"{Path(lure).stem}_{hexid}{Path(lure).suffix or '.txt'}"
        p = self._base / name
        try:
            p.write_text(
                "# HONEYTOKEN — decoy credentials. File mutation or deletion "
                "is logged; audited reads require the configured OS audit source.\n"
                "username=svc_admin\npassword=Winter2026!\n",
                encoding="utf-8",
            )
            _hide_file(p)
            self._enroll_canary(p)   # register identity/content so replacement → SOAR
            self._restage_count += 1
            self.emit(f"🍯 Re-staged honeytoken '{name}' (trap burned by: {context})",
                      Severity.INFO, artifact=str(p))
        except Exception:
            return
        self._plant_fake_registry_cred(name)

    def _plant_fake_registry_cred(self, name: str) -> None:
        """Place a Windows registry lure without claiming read-observer coverage."""
        if not self._user_scope or not sys.platform.startswith("win"):
            return
        try:
            subprocess.run(
                ["reg", "add", r"HKCU\Software\Angerona\HoneyCreds", "/v", name,
                 "/t", "REG_SZ", "/d", "svc_admin:Winter2026!", "/f"],
                capture_output=True, timeout=8)
        except Exception:
            pass

    def _soar_isolation(self, artifact: str, reason: str) -> None:
        """A proven trap mutation/deletion → an isolation recommendation."""
        ev = {"ts": time.time(), "type": "TRAP_INTERACTION", "severity": "Critical",
              "artifact": artifact, "reason": reason,
              "recommend": "zero-trust isolate + suspend actor", "auto_applied": False}
        try:
            self._shared.mkdir(parents=True, exist_ok=True)
            with open(self._soar, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass
