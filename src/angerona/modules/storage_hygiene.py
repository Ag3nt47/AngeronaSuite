"""storage_hygiene.py — Storage Hygiene Enforcer (Code: SHYG).

Purpose
    Keeps Angerona's runtime data off the system drive. The suite resolves its
    data root from ``ANGERONA_DATA`` (falling back to this installation's
    ``runtime-data`` directory on D:). Stray data can still land at the old
    default location if something writes there before the env is applied. SHYG
    detects that spill and migrates it to the configured root, so nothing keeps
    accumulating on C:.

Behaviour (safe by default)
    * DETECT + ALERT (default): finds Angerona data sitting at the default C:
      location while the configured root is elsewhere, and raises an event. It
      does NOT move anything unless auto-migration is enabled.
    * MIGRATE (opt-in): set ``ANGERONA_STORAGE_AUTOMIGRATE=1`` to have SHYG move
      the stray items to the configured root automatically (collision-safe:
      existing names are preserved with a timestamp suffix, never overwritten).
    * PURGE (operator-gated): ``purge_stray(confirm=True)`` deletes the residual
      C: spill directory. It is NEVER called automatically — destructive removal
      always requires an explicit, confirmed operator action.

The legacy C: path is treated only as a spill source and is never the normal
default for this installation.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

from angerona.core.config import _data_dir
from angerona.core.module_base import BaseModule, Severity


def default_c_location() -> Path:
    """Legacy per-user spill location checked for collision-safe migration:
    ``%LOCALAPPDATA%\\Angerona`` (or ~/Angerona off-Windows)."""
    base = os.environ.get("LOCALAPPDATA", str(Path.home()))
    return Path(base) / "Angerona"


def canonical_root() -> Path:
    """The configured data root (D: runtime-data by default)."""
    return Path(_data_dir())


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except Exception:
        return str(a).rstrip("\\/").lower() == str(b).rstrip("\\/").lower()


def find_stray(source: Path, dest: Path) -> bool:
    """True if `source` exists, differs from `dest`, and actually holds data."""
    if not source.exists() or not source.is_dir():
        return False
    if _same_path(source, dest):
        return False
    try:
        return any(source.iterdir())
    except Exception:
        return False


def _collision_safe_dest(dest_dir: Path, name: str) -> Path:
    """Return a destination path under dest_dir that won't clobber an existing
    entry — appends a timestamp suffix if `name` already exists."""
    target = dest_dir / name
    if not target.exists():
        return target
    stamp = time.strftime("%Y%m%d-%H%M%S")
    stem, suffix = os.path.splitext(name)
    return dest_dir / f"{stem}.spilled-{stamp}{suffix}"


def migrate_stray(source: Path, dest: Path, dry_run: bool = False) -> dict:
    """Move every item from `source` into `dest` (collision-safe). Returns a
    report dict: {moved: [...], errors: [...], dry_run: bool}. Never overwrites."""
    report: dict = {"moved": [], "errors": [], "dry_run": dry_run,
                    "source": str(source), "dest": str(dest)}
    if not find_stray(source, dest):
        return report
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        report["errors"].append(f"cannot create dest {dest}: {exc}")
        return report
    for item in list(source.iterdir()):
        target = _collision_safe_dest(dest, item.name)
        try:
            if not dry_run:
                shutil.move(str(item), str(target))
            report["moved"].append({"from": str(item), "to": str(target)})
        except Exception as exc:
            report["errors"].append(f"{item}: {exc}")
    return report


class StorageHygieneModule(BaseModule):
    CODE = "SHYG"
    NAME = "Storage Hygiene Enforcer"
    name = "Storage Hygiene Enforcer"
    description = ("Detects Angerona data spilled to the default C: location and "
                   "keeps it on the configured data root. Detect+alert by default; "
                   "opt-in auto-migrate; operator-gated purge.")
    category = "Maintenance"
    version = "1.0.0"

    _INTERVAL = 15 * 60.0     # re-check every 15 min

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._advised_unset = False
        self._migrations = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    @staticmethod
    def _automigrate_enabled() -> bool:
        return (os.environ.get("ANGERONA_STORAGE_AUTOMIGRATE", "") or "").strip() in ("1", "true", "yes", "on")

    # ── operator-gated destructive purge (never auto-called) ─────────────────
    def purge_stray(self, confirm: bool = False) -> dict:
        """Delete the residual C: spill directory. Requires confirm=True. This is
        destructive and is only ever invoked by an explicit operator action."""
        source = default_c_location()
        dest = canonical_root()
        if _same_path(source, dest):
            return {"ok": False, "error": "C: location is the canonical root — refusing to purge"}
        if not source.exists():
            return {"ok": True, "purged": False, "note": "nothing to purge"}
        if not confirm:
            return {"ok": False, "error": "purge requires confirm=True (operator confirmation)"}
        try:
            shutil.rmtree(source)
            self.emit(f"Storage hygiene: operator-confirmed purge of stray C: data at {source}.",
                      Severity.MEDIUM, purged=str(source))
            return {"ok": True, "purged": True, "path": str(source)}
        except Exception as exc:
            self.last_error = str(exc)
            return {"ok": False, "error": str(exc)}

    # ── one hygiene pass ─────────────────────────────────────────────────────
    def _pass(self) -> None:
        source = default_c_location()
        dest = canonical_root()

        if _same_path(source, dest):
            # An explicit legacy override points back to C:; never auto-delete.
            if not self._advised_unset:
                self._advised_unset = True
                self.emit("Storage hygiene: data root was explicitly set to the legacy "
                          "C: location. Point ANGERONA_DATA to the D: runtime-data folder.",
                          Severity.LOW, data_root=str(dest))
            self.set_health(70, "data root explicitly points to legacy C: location")
            return

        if not find_stray(source, dest):
            self.set_health(100, "no stray C: data — clean")
            return

        # There IS stray data on C: while the configured root is elsewhere.
        if self._automigrate_enabled():
            report = migrate_stray(source, dest)
            moved = len(report["moved"])
            errs = len(report["errors"])
            self._migrations += moved
            sev = Severity.MEDIUM if errs else Severity.INFO
            self.emit(f"Storage hygiene: migrated {moved} stray item(s) from {source} to the "
                      f"configured root{f' ({errs} error(s))' if errs else ''}.",
                      sev, moved=moved, errors=report["errors"][:5], dest=str(dest))
            self.set_health(100 if not errs else 70,
                            f"migrated {moved} item(s)" + (f", {errs} error(s)" if errs else ""))
        else:
            # Detect + alert only (safe default).
            try:
                items = [p.name for p in source.iterdir()]
            except Exception:
                items = []
            self.emit(f"Storage hygiene: {len(items)} Angerona item(s) found on C: at {source} "
                      f"while the configured root is {dest}. Set ANGERONA_STORAGE_AUTOMIGRATE=1 to "
                      f"auto-relocate, or call purge_stray(confirm=True) after review.",
                      Severity.MEDIUM, stray_items=items[:20], source=str(source), dest=str(dest))
            self.set_health(75, f"{len(items)} stray C: item(s) awaiting migration/review")

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        mode = "auto-migrate" if self._automigrate_enabled() else "detect+alert"
        self.emit(f"SHYG online — storage hygiene ({mode}).", Severity.INFO)
        while not self.stopping:
            try:
                self._pass()
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, f"hygiene pass error: {exc}")
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Offline, sandboxed: verify stray detection, collision-safe migration,
        and same-path no-op — without touching any real C:/data location."""
        import tempfile
        base = Path(tempfile.mkdtemp(prefix="shyg_selftest_"))
        try:
            src = base / "c_spill"
            dst = base / "f_root"
            src.mkdir()
            (src / "cache.log").write_text("stray", encoding="utf-8")
            (src / "sub").mkdir()
            (src / "sub" / "x.bin").write_text("data", encoding="utf-8")
            # collision: dest already has a 'cache.log'
            dst.mkdir()
            (dst / "cache.log").write_text("existing", encoding="utf-8")

            detected = find_stray(src, dst)
            dry = migrate_stray(src, dst, dry_run=True)
            dry_ok = len(dry["moved"]) == 2 and src.exists() and any(src.iterdir())

            report = migrate_stray(src, dst)
            moved_ok = len(report["moved"]) == 2 and not report["errors"]
            # original dest file preserved (not overwritten), spill copy present
            preserved = (dst / "cache.log").read_text(encoding="utf-8") == "existing"
            spill_present = any(p.name.startswith("cache.spilled-") for p in dst.iterdir())
            src_drained = not any(src.iterdir())

            noop = migrate_stray(dst, dst)          # same path → no action
            noop_ok = noop["moved"] == []

            ok = all([detected, dry_ok, moved_ok, preserved, spill_present, src_drained, noop_ok])
            return (ok, "detect + collision-safe migrate + same-path no-op verified (sandboxed)"
                    if ok else f"failed: detected={detected} dry_ok={dry_ok} moved_ok={moved_ok} "
                               f"preserved={preserved} spill={spill_present} drained={src_drained} "
                               f"noop_ok={noop_ok}")
        finally:
            shutil.rmtree(base, ignore_errors=True)


def register() -> StorageHygieneModule:
    return StorageHygieneModule()
