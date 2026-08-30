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
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


def _data_base() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


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
    version = "1.13.0"

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

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _canonical_protected_path(raw_path: str) -> Path | None:
        """Resolve one target and prove it remains under a protected root."""
        try:
            target = Path(raw_path).expanduser().resolve(strict=False)
            roots = tuple(
                Path(value).expanduser().resolve(strict=False)
                for value in PROTECTED_DIRS
            )
        except (OSError, RuntimeError, ValueError):
            return None
        if not any(target == root or root in target.parents for root in roots):
            return None
        return target

    def prepare_rollback_artifact(
        self, path: str, *, before_ts: float
    ) -> dict | None:
        """Bind one restore authorization to an exact cached file version.

        The returned descriptor is inert metadata.  ``restore_rollback_artifact``
        revalidates its path, cache key, version, size, and digest immediately
        before replacing the destination.
        """
        target = self._canonical_protected_path(path)
        if target is None:
            return None
        try:
            cutoff_ns = int(float(before_ts) * 1e9)
            key = self._key(str(target))
            keydir = (self._cache_dir / key).resolve(strict=True)
            if keydir.parent != self._cache_dir.resolve(strict=False):
                return None
            source = (keydir / "_source.txt").read_text(encoding="utf-8").strip()
            source_path = self._canonical_protected_path(source)
            if source_path != target:
                return None
            candidates = sorted(
                (
                    item
                    for item in keydir.glob("*.bak")
                    if item.is_file()
                    and not item.is_symlink()
                    and item.stem.isdigit()
                    and int(item.stem) < cutoff_ns
                ),
                key=lambda item: int(item.stem),
                reverse=True,
            )
            if not candidates:
                return None
            backup = candidates[0]
            digest = self._sha256(backup)
            size = int(backup.stat().st_size)
            version = backup.stem
        except (OSError, RuntimeError, TypeError, ValueError, OverflowError):
            return None
        artifact_id = hashlib.sha256(
            f"{target}\0{key}\0{version}\0{size}\0{digest}".encode("utf-8")
        ).hexdigest()
        return {
            "artifact_id": artifact_id,
            "source_path": str(target),
            "cache_key": key,
            "version_mtime_ns": version,
            "size": size,
            "sha256": digest,
        }

    def restore_rollback_artifact(self, artifact: dict) -> dict:
        """Restore exactly one previously bound cache artifact, or fail closed."""
        expected_keys = {
            "artifact_id", "source_path", "cache_key", "version_mtime_ns",
            "size", "sha256",
        }
        if not isinstance(artifact, dict) or set(artifact) != expected_keys:
            return {"restored": [], "failed": ["invalid artifact descriptor"]}
        target = self._canonical_protected_path(str(artifact.get("source_path") or ""))
        if target is None:
            return {"restored": [], "failed": ["target outside protected roots"]}
        key = str(artifact.get("cache_key") or "")
        version = str(artifact.get("version_mtime_ns") or "")
        digest = str(artifact.get("sha256") or "").casefold()
        try:
            size = int(artifact.get("size"))
        except (TypeError, ValueError, OverflowError):
            return {"restored": [], "failed": [str(target)]}
        expected_id = hashlib.sha256(
            f"{target}\0{key}\0{version}\0{size}\0{digest}".encode("utf-8")
        ).hexdigest()
        if (
            key != self._key(str(target))
            or not version.isdigit()
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or artifact.get("artifact_id") != expected_id
        ):
            return {"restored": [], "failed": [str(target)]}
        temporary: Path | None = None
        try:
            keydir = (self._cache_dir / key).resolve(strict=True)
            if keydir.parent != self._cache_dir.resolve(strict=False):
                raise ValueError("cache directory escaped")
            source = (keydir / "_source.txt").read_text(encoding="utf-8").strip()
            if self._canonical_protected_path(source) != target:
                raise ValueError("cache source changed")
            backup = (keydir / f"{version}.bak").resolve(strict=True)
            if backup.parent != keydir or backup.is_symlink() or not backup.is_file():
                raise ValueError("cache version is not a regular bound file")
            if backup.stat().st_size != size or self._sha256(backup) != digest:
                raise ValueError("cache version identity changed")
            target.parent.mkdir(parents=True, exist_ok=True)
            if self._canonical_protected_path(str(target.parent / target.name)) != target:
                raise ValueError("destination binding changed")
            temporary = target.parent / f".{target.name}.angerona-{uuid.uuid4().hex}.tmp"
            shutil.copy2(backup, temporary)
            if temporary.stat().st_size != size or self._sha256(temporary) != digest:
                raise ValueError("restore staging verification failed")
            os.replace(temporary, target)
            if target.stat().st_size != size or self._sha256(target) != digest:
                raise ValueError("restore postcondition failed")
        except (OSError, RuntimeError, TypeError, ValueError):
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            return {"restored": [], "failed": [str(target)]}
        self._rollbacks += 1
        self.emit(
            "Scoped rollback executed: one authorized file version restored.",
            Severity.HIGH,
            restored=[str(target)],
            failed=[],
            artifact_id=expected_id,
            version_mtime_ns=version,
        )
        return {"restored": [str(target)], "failed": [], "artifact_id": expected_id}

    # ── Rollback (called by RANS / SOAR) ─────────────────────────────────────
    def trigger_rollback(self, before_ts: Optional[float] = None,
                         paths: Optional[list[str]] = None) -> dict:
        """Retired unsafe bulk rollback entry point; never mutates host files.

        Cache pathnames and ``_source.txt`` metadata are not response authority.
        Callers must enumerate a reviewed artifact with ``list_artifacts`` and
        pass that exact signed/digested artifact to ``restore_artifact``.  This
        compatibility method remains so older integrations fail closed instead
        of silently regaining the former pathname-based mutation behavior.
        """
        requested = [str(path) for path in (paths or [])][:50]
        self.emit(
            "Legacy bulk rollback refused: select one exact cache artifact and "
            "use the scoped restore workflow.",
            Severity.HIGH,
            restored=[],
            failed=requested,
            before_ts=before_ts,
            response_authorized=False,
            proposal_only=True,
            remediation="Review list_artifacts() evidence and call restore_artifact().",
        )
        return {
            "restored": [],
            "failed": requested,
            "refused": True,
            "reason": "legacy pathname rollback retired; exact artifact required",
        }

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
