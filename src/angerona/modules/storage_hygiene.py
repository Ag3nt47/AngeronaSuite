"""storage_hygiene.py — Storage Hygiene Enforcer (Code: SHYG).

Purpose
    Keeps Angerona's runtime data off the system drive. The suite resolves its
    data root from ``ANGERONA_DATA`` (falling back to this installation's
    ``runtime-data`` directory on D:). Stray data can still land at the old
    default location if something writes there before the env is applied. SHYG
    detects that spill and produces a reviewed relocation proposal.

Behaviour (safe by default)
    * DETECT + ALERT (default): finds Angerona data sitting at the default C:
      location while the configured root is elsewhere, and raises an event. It
      does NOT move anything unless auto-migration is enabled.
    * MIGRATE (retired): the former privileged pathname move is rejected because
      cross-platform handle-bound execution cannot be proven race-free. Dry-run
      proposals remain available for reviewed, unelevated external execution.
    * PURGE (retired): ``purge_stray`` retains a safe compatibility surface but
      never deletes a pathname.

The legacy C: path is treated only as a spill source and is never the normal
default for this installation.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
import threading
import time
from pathlib import Path

from angerona.core.config import _data_dir
from angerona.core.module_base import BaseModule, Severity


def default_c_location() -> Path:
    """Return the legacy spill root from an OS identity authority.

    Environment variables are deliberately excluded: an elevated launch can
    inherit attacker-controlled ``LOCALAPPDATA``/``HOME`` values and turn a
    hygiene pass into a privileged pathname operation on arbitrary content.
    """
    if sys.platform == "win32":
        from angerona.core.privilege import _windows_known_folder

        return _windows_known_folder(0x1C) / "Angerona"  # CSIDL_LOCAL_APPDATA
    import pwd

    return Path(pwd.getpwuid(os.getuid()).pw_dir) / "Angerona"


def canonical_root() -> Path:
    """The configured data root (D: runtime-data by default)."""
    return Path(_data_dir())


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except Exception:
        return str(a).rstrip("\\/").lower() == str(b).rstrip("\\/").lower()


def _is_link_or_reparse(path: Path) -> bool:
    """Inspect *path* without following it.

    Windows junctions are not consistently reported by ``Path.is_symlink``;
    the reparse attribute is the authoritative signal there.
    """
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _existing_path_has_reparse(path: Path) -> bool:
    """Return True when any existing component redirects path traversal."""
    current = Path(os.path.abspath(path))
    while True:
        if os.path.lexists(current) and _is_link_or_reparse(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _tree_has_reparse(root: Path) -> bool:
    """Inspect a migration tree without following links or junctions."""
    if _existing_path_has_reparse(root):
        return True
    try:
        root_info = root.lstat()
    except OSError:
        return True
    if stat.S_ISREG(root_info.st_mode):
        return False
    if not stat.S_ISDIR(root_info.st_mode):
        return True
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            # An unreadable source is unsafe to move or delete while elevated.
            return True
        for entry in entries:
            try:
                info = entry.lstat()
            except OSError:
                return True
            if _is_link_or_reparse(entry):
                return True
            if stat.S_ISDIR(info.st_mode):
                pending.append(entry)
    return False


def _roots_overlap(source: Path, dest: Path) -> bool:
    """Reject self/ancestor moves before ``shutil.move`` can recurse."""
    try:
        source_resolved = source.resolve(strict=False)
        dest_resolved = dest.resolve(strict=False)
        return (
            source_resolved == dest_resolved
            or source_resolved in dest_resolved.parents
            or dest_resolved in source_resolved.parents
        )
    except (OSError, RuntimeError):
        return True


def _migration_safety_error(source: Path, dest: Path) -> str | None:
    if _roots_overlap(source, dest):
        return "source and destination overlap"
    if _existing_path_has_reparse(dest):
        return "destination traverses a link or reparse point"
    if _tree_has_reparse(source):
        return "source contains or traverses a link, reparse point, or unreadable entry"
    return None


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    """Stable metadata used to reject a root replaced during assessment."""
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_mtime_ns),
        int(getattr(info, "st_file_attributes", 0) or 0),
    )


def _root_still_bound(source: Path, expected: tuple[int, ...]) -> tuple[bool, str]:
    try:
        current = source.lstat()
    except OSError as exc:
        return False, f"legacy spill root identity unavailable: {exc}"
    attributes = int(getattr(current, "st_file_attributes", 0) or 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(current.st_mode) or bool(attributes & reparse):
        return False, "legacy spill root became a link or reparse point"
    if not stat.S_ISDIR(current.st_mode):
        return False, "legacy spill root is no longer a directory"
    if _directory_identity(current) != expected:
        return False, "legacy spill root object changed during inspection"
    return True, ""


def inspect_stray(source: Path, dest: Path) -> dict[str, object]:
    """Return a fail-closed, non-mutating assessment of the spill root.

    ``clean`` is reported only after the fixed OS-derived source can be
    inspected.  Permission failures, special files and reparse points remain
    distinct from absence so the monitor cannot turn collection failure green.
    """
    result: dict[str, object] = {
        "status": "unavailable",
        "source": str(source),
        "dest": str(dest),
        "items": [],
        "reason": "inspection not completed",
    }
    if _same_path(source, dest):
        result.update(status="same-root", reason="source and destination are identical")
        return result
    try:
        info = source.lstat()
    except FileNotFoundError:
        result.update(status="clean", reason="legacy spill root does not exist")
        return result
    except OSError as exc:
        result["reason"] = f"legacy spill root metadata unavailable: {exc}"
        return result
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(info.st_mode) or bool(attributes & reparse):
        result.update(status="unsafe", reason="legacy spill root is a link or reparse point")
        return result
    if not stat.S_ISDIR(info.st_mode):
        result.update(status="unsafe", reason="legacy spill root is not a directory")
        return result
    source_identity = _directory_identity(info)
    safety_error = _migration_safety_error(source, dest)
    if safety_error:
        result.update(status="unsafe", reason=safety_error)
        return result
    still_bound, reason = _root_still_bound(source, source_identity)
    if not still_bound:
        result.update(status="unsafe", reason=reason)
        return result
    try:
        items: list[str] = []
        with os.scandir(source) as entries:
            for entry in entries:
                if len(items) >= 1000:
                    result.update(
                        status="unavailable",
                        reason="legacy spill root exceeds bounded enumeration coverage",
                    )
                    return result
                items.append(entry.name)
    except OSError as exc:
        result["reason"] = f"legacy spill root enumeration unavailable: {exc}"
        return result
    still_bound, reason = _root_still_bound(source, source_identity)
    if not still_bound:
        result.update(status="unsafe", reason=reason)
        return result
    result["items"] = items[:1000]
    if items:
        result.update(status="stray", reason=f"{len(items)} spill item(s) present")
    else:
        result.update(status="clean", reason="legacy spill root is empty")
    return result


def find_stray(source: Path, dest: Path) -> bool:
    """Compatibility predicate; callers needing health must use inspect_stray."""
    return inspect_stray(source, dest)["status"] == "stray"


def _collision_safe_dest(dest_dir: Path, name: str) -> Path:
    """Return a destination path under dest_dir that won't clobber an existing
    entry — appends a timestamp suffix if `name` already exists."""
    target = dest_dir / name
    if not os.path.lexists(target):
        return target
    stamp = time.strftime("%Y%m%d-%H%M%S")
    stem, suffix = os.path.splitext(name)
    for serial in range(1, 10_000):
        candidate = dest_dir / f"{stem}.spilled-{stamp}-{serial}{suffix}"
        if not os.path.lexists(candidate):
            return candidate
    raise RuntimeError("could not allocate a collision-safe migration name")


def migrate_stray(source: Path, dest: Path, dry_run: bool = False) -> dict:
    """Propose spill moves without performing privileged pathname mutation.

    The former ``shutil.move`` implementation could not bind validation to the
    subsequently opened objects across every supported platform.  Execution is
    therefore retired; a reviewed, unelevated, handle-safe external workflow
    may consume a dry-run proposal.
    """
    report: dict = {"moved": [], "errors": [], "dry_run": dry_run,
                    "source": str(source), "dest": str(dest)}
    assessment = inspect_stray(source, dest)
    status = str(assessment["status"])
    if status in {"unsafe", "unavailable"}:
        report["errors"].append(
            f"unsafe migration refused: {assessment['reason']}"
        )
        return report
    if status != "stray":
        return report
    if not dry_run:
        report["errors"].append(
            "automatic storage mutation retired: reviewed unelevated "
            "handle-safe external execution is required"
        )
        return report
    for name in assessment["items"]:
        item = source / str(name)
        target = _collision_safe_dest(dest, item.name)
        report["moved"].append({"from": str(item), "to": str(target)})
    return report


class StorageHygieneModule(BaseModule):
    CODE = "SHYG"
    NAME = "Storage Hygiene Enforcer"
    name = "Storage Hygiene Enforcer"
    description = ("Detects Angerona data spilled to the default C: location and "
                   "proposes relocation to the configured root. Privileged pathname "
                   "migration/purge is retired until handle-safe execution is available.")
    category = "Maintenance"
    version = "1.12.1"

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
        """Refuse legacy pathname deletion; retained as an explicit safe API."""
        try:
            source = default_c_location()
            dest = canonical_root()
        except Exception as exc:
            return {"ok": False, "error": f"path authority unavailable: {exc}"}
        assessment = inspect_stray(source, dest)
        status = str(assessment["status"])
        if status == "same-root":
            return {"ok": False, "error": "C: location is the canonical root — refusing to purge"}
        if status in {"unsafe", "unavailable"}:
            return {
                "ok": False,
                "error": f"unsafe purge refused: {assessment['reason']}",
            }
        if status == "clean":
            return {"ok": True, "purged": False, "note": "nothing to purge"}
        if not confirm:
            return {"ok": False, "error": "purge requires confirm=True (operator confirmation)"}
        return {
            "ok": False,
            "error": (
                "unsafe purge retired: reviewed unelevated handle-safe external "
                "execution is required"
            ),
            "path": str(source),
        }

    # ── one hygiene pass ─────────────────────────────────────────────────────
    def _pass(self) -> None:
        try:
            source = default_c_location()
            dest = canonical_root()
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(30, f"storage path authority unavailable: {exc}")
            self.emit(
                f"Storage hygiene cannot resolve an OS-authoritative spill path: {exc}",
                Severity.HIGH,
                disposition="health",
                collection_status="unavailable",
            )
            return

        assessment = inspect_stray(source, dest)
        status = str(assessment["status"])
        if status == "same-root":
            # An explicit legacy override points back to C:; never auto-delete.
            if not self._advised_unset:
                self._advised_unset = True
                self.emit("Storage hygiene: data root was explicitly set to the legacy "
                          "C: location. Point ANGERONA_DATA to the D: runtime-data folder.",
                          Severity.LOW, data_root=str(dest))
            self.set_health(70, "data root explicitly points to legacy C: location")
            return

        if status in {"unsafe", "unavailable"}:
            reason = str(assessment["reason"])
            self.emit(
                f"Storage hygiene inspection is {status}: {reason}",
                Severity.HIGH,
                disposition="health",
                collection_status=status,
                source=str(source),
                dest=str(dest),
            )
            self.set_health(30, f"spill inspection {status}: {reason}")
            return

        if status == "clean":
            self.set_health(100, "no stray C: data — clean")
            return

        # There IS stray data on C: while the configured root is elsewhere.
        if self._automigrate_enabled():
            report = migrate_stray(source, dest)
            proposed = len(assessment["items"])
            self.emit(
                "Storage hygiene automatic mutation is retired; "
                f"{proposed} item(s) require a reviewed unelevated handle-safe workflow.",
                Severity.MEDIUM,
                proposed=proposed,
                errors=report["errors"][:5],
                source=str(source),
                dest=str(dest),
            )
            self.set_health(60, f"{proposed} stray item(s); automatic mutation retired")
        else:
            # Detect + alert only (safe default).
            try:
                items = list(assessment["items"])
            except Exception:  # pragma: no cover - bounded engine output
                items = []
            self.emit(f"Storage hygiene: {len(items)} Angerona item(s) found on C: at {source} "
                      f"while the configured root is {dest}. Generate a dry-run relocation "
                      "proposal and execute it only through a reviewed unelevated handle-safe workflow.",
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
        """Verify detection/proposal and that execution/deletion remain retired."""
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
            retired = report["moved"] == [] and bool(report["errors"])
            # Source/destination remain byte-for-byte untouched.
            preserved = (dst / "cache.log").read_text(encoding="utf-8") == "existing"
            spill_present = (src / "cache.log").read_text(encoding="utf-8") == "stray"
            src_preserved = len(list(src.iterdir())) == 2

            noop = migrate_stray(dst, dst)          # same path → no action
            noop_ok = noop["moved"] == []

            ok = all([detected, dry_ok, retired, preserved, spill_present, src_preserved, noop_ok])
            return (ok, "detect + dry-run proposal + retired mutation verified (sandboxed)"
                    if ok else f"failed: detected={detected} dry_ok={dry_ok} retired={retired} "
                               f"preserved={preserved} spill={spill_present} src={src_preserved} "
                               f"noop_ok={noop_ok}")
        finally:
            shutil.rmtree(base, ignore_errors=True)


def register() -> StorageHygieneModule:
    return StorageHygieneModule()
