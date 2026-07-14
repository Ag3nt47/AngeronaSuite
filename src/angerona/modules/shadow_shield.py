"""shadow_shield.py — Ransomware file shielding: VSS + delta cache (CODE: SHDW).

Active file protection with two recovery layers:

1. Delta version cache (fast, primary)
   A short-horizon version store. A polling loop copies recently-modified files
   from the protected directories into a hidden cache, keeping the last N
   versions of each. When RANS detects an active encryption event it calls
   ``trigger_rollback(before_ts=...)`` and we restore the newest cached version
   that predates the encryption burst — recovering the clean copy in place.

2. Volume Shadow Copy (heavier, fallback)
   Periodically requests a quiet VSS snapshot via WMI ``Win32_ShadowCopy.Create``
   (PowerShell fallback). This is the deeper safety net; full extraction from a
   shadow is surfaced to the operator/GUI rather than done automatically.

SAFETY: this module only *creates* snapshots and *restores* files. It never
deletes shadow copies — ``vssadmin delete shadows`` is a ransomware technique,
not a defensive one, and is intentionally absent here.

The delta cache is best-effort (polling can't intercept every write); VSS is the
stronger guarantee. Windows-only operations degrade gracefully (health note, no
crash) on non-Windows or non-elevated hosts.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


def _data_base() -> Path:
    base = os.environ.get("ANGERONA_DATA") or os.path.join(
        os.environ.get("LOCALAPPDATA", str(Path.home())), "Angerona"
    )
    return Path(base)


PROTECTED_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
]

POLL_S           = 15.0             # full Documents/Desktop stat-walk cadence; 15s
                                    # (was 5s) cuts steady CPU ~3x. The delta cache
                                    # is best-effort — VSS snapshots + the RANS
                                    # detector are the real ransomware net — so a
                                    # slightly wider window costs little protection.
RETAIN_VERSIONS  = 6                 # versions kept per file
MAX_FILE_BYTES   = 50 * 1024 * 1024  # don't cache files larger than 50 MB
VSS_INTERVAL_S   = 3600.0            # request a shadow at most hourly
SKIP_EXT         = {".tmp", ".part", ".crdownload"}


class ShadowShield(BaseModule):
    name = "Shadow Shield"
    CODE = "SHDW"
    description = "Ransomware file shielding via a delta version cache and VSS snapshots."
    category = "Response"
    version = "1.0.0"

    def __init__(self) -> None:
        super().__init__()
        self._cache_dir = _data_base() / "shadow_cache"
        self._seen_mtime: dict[str, int] = {}
        self._last_vss = 0.0
        self._snapshots = 0
        self._rollbacks = 0

    # ── Cache helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _key(path: str) -> str:
        return hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()

    def _keydir(self, path: str) -> Path:
        return self._cache_dir / self._key(path)

    def _protected_files(self):
        for d in PROTECTED_DIRS:
            if not os.path.isdir(d):
                continue
            for root, dirs, files in os.walk(d):
                for fn in files:
                    if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                        continue
                    yield os.path.join(root, fn)

    def _cache_version(self, path: str) -> None:
        """Copy the current bytes of `path` into the version cache, pruning old
        versions. Stores an index sidecar mapping cache filename → source path."""
        try:
            st = os.stat(path)
            if st.st_size > MAX_FILE_BYTES:
                return
            mtime_ns = st.st_mtime_ns
            if self._seen_mtime.get(path) == mtime_ns:
                return  # unchanged since last poll
            kd = self._keydir(path)
            kd.mkdir(parents=True, exist_ok=True)
            # Record the true source path once (rollback needs it).
            idx = kd / "_source.txt"
            if not idx.exists():
                idx.write_text(path, encoding="utf-8")
            dst = kd / f"{mtime_ns}.bak"
            shutil.copy2(path, dst)
            self._seen_mtime[path] = mtime_ns
            self._prune(kd)
        except (FileNotFoundError, PermissionError):
            return
        except Exception:
            return

    def _prune(self, kd: Path) -> None:
        try:
            versions = sorted(kd.glob("*.bak"), key=lambda p: p.stat().st_mtime)
            for old in versions[:-RETAIN_VERSIONS]:
                old.unlink(missing_ok=True)
        except Exception:
            pass

    # ── Rollback (called by RANS / SOAR) ─────────────────────────────────────
    def trigger_rollback(self, before_ts: Optional[float] = None,
                         paths: Optional[list[str]] = None) -> dict:
        """Restore cached file versions in place.

        Args:
            before_ts: if given, restore the newest cached version whose mtime is
                       *older* than this timestamp — i.e. the last clean copy from
                       before an encryption event. If None, restore the newest.
            paths:     limit to these source paths; None = every cached file.

        Returns {'restored': [...], 'failed': [...]}. Never raises.
        """
        restored, failed = [], []
        try:
            keydirs = ([self._keydir(p) for p in paths] if paths
                       else [d for d in self._cache_dir.iterdir() if d.is_dir()])
        except Exception:
            keydirs = []

        cutoff_ns = int(before_ts * 1e9) if before_ts else None
        for kd in keydirs:
            try:
                src_idx = kd / "_source.txt"
                if not src_idx.exists():
                    continue
                src = src_idx.read_text(encoding="utf-8").strip()
                versions = sorted(kd.glob("*.bak"),
                                  key=lambda p: int(p.stem), reverse=True)
                chosen = None
                for v in versions:
                    if cutoff_ns is None or int(v.stem) < cutoff_ns:
                        chosen = v
                        break
                if chosen is None:
                    failed.append(src)
                    continue
                os.makedirs(os.path.dirname(src), exist_ok=True)
                shutil.copy2(chosen, src)
                restored.append(src)
            except Exception:
                failed.append(str(kd))

        self._rollbacks += 1
        self.emit(
            f"Rollback executed: {len(restored)} file(s) restored, {len(failed)} failed.",
            Severity.HIGH if restored else Severity.MEDIUM,
            restored=restored[:50], failed=failed[:50], before_ts=before_ts,
        )
        return {"restored": restored, "failed": failed}

    # ── VSS ───────────────────────────────────────────────────────────────────
    def _take_vss_snapshot(self, drive: str = "C:\\") -> Optional[str]:
        """Request a ClientAccessible shadow via WMI (PowerShell). Best-effort;
        returns the ShadowID string on success. Requires elevation."""
        try:
            ps = (f"(Get-WmiObject -List Win32_ShadowCopy)"
                  f".Create('{drive}','ClientAccessible') | "
                  f"Select-Object -ExpandProperty ShadowID")
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=90,
            )
            sid = (out.stdout or "").strip()
            if out.returncode == 0 and sid:
                self._snapshots += 1
                self.emit(f"VSS snapshot created ({sid}).", Severity.INFO, shadow_id=sid)
                return sid
            self.set_health(70, f"VSS create returned rc={out.returncode} "
                                f"(elevation required?): {(out.stderr or '').strip()[:120]}")
            return None
        except FileNotFoundError:
            self.set_health(60, "PowerShell/VSS unavailable on this host.")
            return None
        except Exception as exc:
            self.set_health(70, f"VSS snapshot error: {exc}")
            return None

    def list_shadow_snapshots(self) -> list[dict]:
        """Enumerate existing shadows for operator-driven recovery in the GUI."""
        try:
            ps = ("Get-WmiObject Win32_ShadowCopy | "
                  "Select-Object ID, InstallDate, DeviceObject | ConvertTo-Json")
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=30,
            )
            import json
            data = json.loads(out.stdout or "[]")
            return data if isinstance(data, list) else [data]
        except Exception:
            return []

    # ── Loop ──────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self.emit("Shadow Shield active — protecting Documents & Desktop.", Severity.INFO)
        while not self.stopping:
            count = 0
            for path in self._protected_files():
                if self.stopping:
                    break
                self._cache_version(path)
                count += 1

            now = time.time()
            if now - self._last_vss >= VSS_INTERVAL_S:
                self._last_vss = now
                self._take_vss_snapshot()

            if self.health >= 90:
                self.set_health(100, f"watching {count} files; "
                                     f"{self._snapshots} snapshots, {self._rollbacks} rollbacks")
            self.sleep(POLL_S)

    def self_test(self) -> tuple[bool, str]:
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            return True, f"cache ready; {self._snapshots} VSS snapshots this session"
        except Exception as exc:
            return False, f"cache dir unavailable: {exc}"


def register() -> ShadowShield:
    return ShadowShield()
