"""Local, safety-gated host adaptation and configuration-drift service.

The service deliberately separates observation, planning, simulation, and
execution.  An audit or sandbox run can never mutate the host.  A profile can
only reach the Windows Firewall broker after an immutable plan is previewed,
bound to an explicit approval, checked against current state, and backed up for
one-click rollback. Context rules are proposal-only.

No profile kills processes, stops services, or edits routes.  Those operations
have much larger recovery surfaces and remain outside this workbench.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import platform
import socket
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Iterable, Mapping, Sequence

import psutil

from angerona.core.privilege import (
    sanitized_child_environment,
    trusted_powershell_path,
    trusted_windows_directories,
)
from angerona.core.durable_outbox import load_or_create_outbox_key


SCHEMA_VERSION = 1
MAX_SERVICES = 4_000
MAX_PORTS = 2_000
MAX_FIREWALL_RULES = 10_000
MAX_ACTIVITY = 500
MAX_EXCEPTIONS = 1_000
MAX_TRIGGERS = 100
MAX_FEEDBACK_REVIEWS = 5_000
MAX_TRANSACTIONS = 200
FEEDBACK_MIN_DISTINCT = 3
PLAN_TTL_SECONDS = 10 * 60
SNAPSHOT_RETENTION = 10
MAX_FIREWALL_ARTIFACT_BYTES = 256 * 1024 * 1024


class AdaptationError(RuntimeError):
    """Base error for a safely refused adaptation operation."""


class IntegrityError(AdaptationError):
    """Persisted state failed its local digest check."""


class CircuitBreakerOpen(AdaptationError):

    """A host change was refused by the persistent adaptation breaker."""


class AutomationAuthorizationChanged(AdaptationError):
    """Automation or its environmental authorization changed before mutation."""


@dataclass(frozen=True)
class FirewallAction:
    """One closed-catalog firewall mutation (never arbitrary script input)."""

    profiles: tuple[str, ...]
    enabled: bool
    inbound: str
    outbound: str


@dataclass(frozen=True)
class AdaptationProfile:
    profile_id: str
    name: str
    intent: str
    description: str
    actions: tuple[FirewallAction, ...]
    drastic: bool = False
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdaptationPlan:
    plan_id: str
    profile_id: str
    created_at: str
    expires_at: str
    host_id: str
    precondition_digest: str
    actions: tuple[FirewallAction, ...]
    drastic: bool
    warnings: tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class AdaptationReceipt:
    plan_id: str
    profile_id: str
    applied_at: str
    snapshot_id: str
    authorization: str
    commands: tuple[str, ...]
    receipt_digest: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False, default=str,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _scope_address(address: str) -> str:
    address = str(address or "")
    if address in {"0.0.0.0", "::", "*"}:
        return "wildcard"
    if address.startswith("127.") or address == "::1":
        return "loopback"
    return "interface"


def _safe_text(value: Any, limit: int = 300) -> str:
    return str("" if value is None else value).replace("\r", " ").replace("\n", " ")[:limit]


PROFILES: dict[str, AdaptationProfile] = {
    "balanced": AdaptationProfile(
        "balanced",
        "Balanced host",
        "Everyday protection",
        "Enable every Windows Firewall profile, block unsolicited inbound traffic, "
        "and allow outbound traffic.",
        (FirewallAction(("Domain", "Private", "Public"), True, "Block", "Allow"),),
        warnings=("Existing explicit allow/block rules remain in force.",),
    ),
    "public": AdaptationProfile(
        "public",
        "Public network",
        "Untrusted Wi-Fi or public LAN",
        "Harden the active public posture while leaving trusted Domain and Private "
        "profile defaults unchanged.",
        (FirewallAction(("Public",), True, "Block", "Allow"),),
        warnings=("This does not reclassify the Windows network category.",),
    ),
    "lockdown": AdaptationProfile(
        "lockdown",
        "Emergency lockdown",
        "Short-lived containment",
        "Enable all firewall profiles and default-deny both inbound and outbound "
        "traffic. Existing explicit allow rules may still permit traffic.",
        (FirewallAction(("Domain", "Private", "Public"), True, "Block", "Block"),),
        drastic=True,
        warnings=(
            "Outbound connectivity can stop immediately.",
            "Use only with local console access and verify rollback before applying.",
        ),
    ),
}

# This is an automation selection order, not a substitute for comparing the
# actual firewall pre/postconditions.  Public and balanced impose the same
# defaults on the Public profile; lockdown is strictly more restrictive.
PROFILE_STRENGTH = {"balanced": 1, "public": 1, "lockdown": 2}


class HostAdaptationService:
    """Capture, compare, simulate, and safely broker host adaptation profiles."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.root = (self.data_dir / "adaptation").resolve()
        try:
            self.root.relative_to(self.data_dir)
        except ValueError as exc:
            raise AdaptationError("adaptation root escaped the configured data directory") from exc
        self.snapshots_dir = (self.root / "snapshots").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or self.snapshots_dir.is_symlink():
            raise AdaptationError("adaptation storage may not traverse a symbolic link")
        self._store_key = load_or_create_outbox_key(self.root / "adaptation.key")
        self._clock = clock
        self._lock = threading.RLock()
        # UI apply/rollback and the context monitor share one service. Keep the
        # entire snapshot→mutate→receipt transaction exclusive so two valid
        # plans cannot both pass a precondition before either records its change.
        self._mutation_lock = threading.RLock()
        self._store_warnings: dict[str, str] = {}
        self.baseline_path = self.root / "golden-baseline.json"
        self.exceptions_path = self.root / "exceptions.json"
        self.state_path = self.root / "state.json"
        self.activity_path = self.root / "activity.json"
        self.transactions_path = self.root / "transactions.json"
        self.security_baseline_manifest_path = (
            self.snapshots_dir / "host-security-baseline.json"
        )
        self.security_baseline_firewall_path = (
            self.snapshots_dir / "host-security-baseline.wfw"
        )
        self._reconcile_incomplete_transactions()

    # ── Persistence and integrity ──────────────────────────────────────────
    def _envelope(self, kind: str, body: Any) -> dict[str, Any]:
        payload = {
            "schema": f"angerona.host-adaptation.{kind}/v{SCHEMA_VERSION}",
            "body": body,
        }
        payload["sha256"] = _digest(payload)
        payload["hmac_sha256"] = hmac.new(
            self._store_key, _canonical(payload), hashlib.sha256
        ).hexdigest()
        return payload

    def _verify_envelope(self, payload: Any, kind: str) -> Any:
        if not isinstance(payload, dict):
            raise IntegrityError(f"{kind} store is not a JSON object")
        supplied = payload.get("sha256")
        supplied_hmac = payload.get("hmac_sha256")
        authenticated = {
            key: value for key, value in payload.items() if key != "hmac_sha256"
        }
        unsigned = {
            key: value for key, value in authenticated.items() if key != "sha256"
        }
        expected_schema = f"angerona.host-adaptation.{kind}/v{SCHEMA_VERSION}"
        valid_hmac = isinstance(supplied_hmac, str) and hmac.compare_digest(
            supplied_hmac,
            hmac.new(self._store_key, _canonical(authenticated), hashlib.sha256).hexdigest(),
        )
        if (
            payload.get("schema") != expected_schema
            or supplied != _digest(unsigned)
            or not valid_hmac
        ):
            raise IntegrityError(f"{kind} store failed its schema or digest check")
        return payload.get("body")

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temp_name, 0o600)
            except OSError:
                pass
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def _exclusive_write(path: Path, payload: bytes) -> None:
        """Create one immutable artifact without following a pre-placed target."""
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            info = path.stat()
            if not path.is_file() or getattr(info, "st_nlink", 1) != 1:
                raise IntegrityError("immutable artifact is not a single regular file")
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise

    @staticmethod
    def _bounded_file_bytes(path: Path, *, max_bytes: int) -> bytes:
        """Read one stable regular file through a bounded no-follow descriptor."""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(str(path), flags)
        except OSError as exc:
            raise IntegrityError(f"store could not be opened safely: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            attributes = int(getattr(info, "st_file_attributes", 0))
            if (
                not stat.S_ISREG(info.st_mode)
                or getattr(info, "st_nlink", 1) != 1
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise IntegrityError("store is not a single regular file")
            if info.st_size <= 0 or info.st_size > max_bytes:
                raise IntegrityError(f"store is empty or exceeds {max_bytes} bytes")
            remaining = info.st_size
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise IntegrityError("store changed while it was read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise IntegrityError("store grew while it was read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @staticmethod
    def _bounded_file_sha256(
        path: Path, *, max_bytes: int = MAX_FIREWALL_ARTIFACT_BYTES
    ) -> str:
        """Hash one stable, bounded regular file without following links."""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(str(path), flags)
        except OSError as exc:
            raise IntegrityError(f"recovery artifact could not be opened safely: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            attributes = int(getattr(info, "st_file_attributes", 0))
            if (
                not stat.S_ISREG(info.st_mode)
                or getattr(info, "st_nlink", 1) != 1
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise IntegrityError("recovery artifact is not a single regular file")
            if info.st_size <= 0 or info.st_size > max_bytes:
                raise IntegrityError(
                    f"recovery artifact is empty or exceeds {max_bytes} bytes"
                )
            digest = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise IntegrityError("recovery artifact changed while it was read")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise IntegrityError("recovery artifact grew while it was read")
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    @classmethod
    def _exclusive_copy_bounded(
        cls,
        source: Path,
        target: Path,
        *,
        max_bytes: int = MAX_FIREWALL_ARTIFACT_BYTES,
    ) -> str:
        """Copy a bounded recovery artifact into a new immutable target."""
        source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
        source_fd = os.open(str(source), source_flags)
        target_fd: int | None = None
        created = False
        try:
            source_info = os.fstat(source_fd)
            attributes = int(getattr(source_info, "st_file_attributes", 0))
            if (
                not stat.S_ISREG(source_info.st_mode)
                or getattr(source_info, "st_nlink", 1) != 1
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise IntegrityError("recovery source is not a single regular file")
            if source_info.st_size <= 0 or source_info.st_size > max_bytes:
                raise AdaptationError(
                    f"firewall recovery export is empty or exceeds {max_bytes} bytes"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target_fd = os.open(
                str(target),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            created = True
            digest = hashlib.sha256()
            remaining = source_info.st_size
            while remaining:
                chunk = os.read(source_fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise IntegrityError("recovery source changed while it was copied")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(target_fd, view)
                    if written <= 0:
                        raise OSError("short write while preserving recovery artifact")
                    view = view[written:]
                remaining -= len(chunk)
            if os.read(source_fd, 1):
                raise IntegrityError("recovery source grew while it was copied")
            os.fsync(target_fd)
            target_info = os.fstat(target_fd)
            if (
                not stat.S_ISREG(target_info.st_mode)
                or getattr(target_info, "st_nlink", 1) != 1
                or target_info.st_size != source_info.st_size
            ):
                raise IntegrityError("immutable recovery copy failed validation")
            return digest.hexdigest()
        except Exception:
            if target_fd is not None:
                os.close(target_fd)
                target_fd = None
            if created:
                try:
                    target.unlink()
                except OSError:
                    pass
            raise
        finally:
            os.close(source_fd)
            if target_fd is not None:
                os.close(target_fd)

    def _save_store_exclusive(self, path: Path, kind: str, body: Any) -> None:
        encoded = json.dumps(
            self._envelope(kind, body), indent=2, ensure_ascii=False, default=str
        ).encode("utf-8")
        with self._lock:
            self._exclusive_write(path, encoded)

    def _save_store(self, path: Path, kind: str, body: Any) -> None:
        encoded = json.dumps(
            self._envelope(kind, body), indent=2, ensure_ascii=False, default=str
        ).encode("utf-8")
        with self._lock:
            self._atomic_write(path, encoded)

    def _load_store(self, path: Path, kind: str, default: Any) -> Any:
        with self._lock:
            if not path.exists():
                return default
            try:
                encoded = self._bounded_file_bytes(path, max_bytes=16 * 1024 * 1024)
                payload = json.loads(encoded.decode("utf-8"))
                if isinstance(payload, dict) and "hmac_sha256" not in payload:
                    unsigned = {
                        key: value for key, value in payload.items() if key != "sha256"
                    }
                    expected_schema = (
                        f"angerona.host-adaptation.{kind}/v{SCHEMA_VERSION}"
                    )
                    if (
                        payload.get("schema") == expected_schema
                        and payload.get("sha256") == _digest(unsigned)
                    ):
                        # Pre-v1.12 adjacent digests provided corruption checks,
                        # not authority. Never import their baseline, triggers,
                        # automation, or exceptions as trusted state.
                        self._store_warnings[kind] = (
                            "legacy digest-only store was quarantined logically; "
                            "review and explicitly recreate it"
                        )
                        return default
                return self._verify_envelope(payload, kind)
            except IntegrityError:
                raise
            except Exception as exc:
                raise IntegrityError(f"could not read {kind} store: {exc}") from exc

    def store_warnings(self) -> dict[str, str]:
        return dict(self._store_warnings)

    # ── Crash-durable mutation journal ──────────────────────────────────────
    def transactions(self) -> list[dict[str, Any]]:
        rows = self._load_store(self.transactions_path, "transactions", [])
        if not isinstance(rows, list):
            raise IntegrityError("adaptation transaction journal is not a list")
        if len(rows) > MAX_TRANSACTIONS:
            raise IntegrityError("adaptation transaction journal exceeds its bound")
        return [dict(row) for row in rows if isinstance(row, dict)]

    def _save_transaction_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        transaction_id = str(record.get("transaction_id") or "")
        if not transaction_id.startswith("txn-"):
            raise IntegrityError("adaptation transaction identity is invalid")
        with self._lock:
            rows = self.transactions()
            updated = dict(record)
            updated["updated_at"] = _utc_now()
            found = False
            for index, row in enumerate(rows):
                if row.get("transaction_id") == transaction_id:
                    rows[index] = updated
                    found = True
                    break
            if not found:
                rows.append(updated)
            self._save_store(
                self.transactions_path,
                "transactions",
                rows[-MAX_TRANSACTIONS:],
            )
        return updated

    def _begin_transaction(
        self,
        kind: str,
        *,
        snapshot_id: str,
        authorization: str,
        before_firewall: Mapping[str, Any] | None,
        plan: AdaptationPlan | None = None,
        target_firewall: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "transaction_id": f"txn-{uuid.uuid4().hex}",
            "kind": _safe_text(kind, 60),
            "status": "PREPARED",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "host_id": self.host_id(),
            "snapshot_id": _safe_text(snapshot_id, 160),
            "authorization": _safe_text(authorization, 160),
            "plan": asdict(plan) if plan is not None else None,
            "plan_digest": plan.digest if plan is not None else "",
            "profile_id": plan.profile_id if plan is not None else "",
            "drastic": bool(plan.drastic) if plan is not None else False,
            "before_firewall_digest": (
                _digest(before_firewall) if before_firewall else ""
            ),
            "target_firewall_digest": (
                _digest(target_firewall) if target_firewall else ""
            ),
            "after_firewall_digest": "",
            "commands": [],
            "receipt_digest": "",
            "error": "",
            "rollback_error": "",
        }
        return self._save_transaction_record(record)

    def _transition_transaction(
        self, transaction_id: str, status: str, **updates: Any
    ) -> dict[str, Any]:
        allowed = {
            "PREPARED", "MUTATING", "VERIFIED", "COMMITTED",
            "ROLLED_BACK", "NEEDS_REVIEW",
        }
        if status not in allowed:
            raise IntegrityError("adaptation transaction status is invalid")
        with self._lock:
            rows = self.transactions()
            record = next(
                (row for row in rows if row.get("transaction_id") == transaction_id),
                None,
            )
            if record is None:
                raise IntegrityError("adaptation transaction disappeared")
            record.update({key: value for key, value in updates.items()})
            record["status"] = status
            return self._save_transaction_record(record)

    def _lock_breaker_for_review(self, reason: str, transaction_id: str) -> None:
        with self._lock:
            state = self.state()
            breaker = dict(self._default_state()["breaker"])
            breaker.update(state.get("breaker") or {})
            breaker["locked"] = True
            breaker["reason"] = _safe_text(
                f"Recovery review required for {transaction_id}: {reason}", 500
            )
            state["breaker"] = breaker
            self._save_state(state)
        self.log_activity("transaction.needs_review", "critical", breaker["reason"])

    def _mark_transaction_needs_review(
        self,
        transaction_id: str,
        *,
        error: object,
        rollback_error: object = "",
    ) -> None:
        reason = _safe_text(error, 1000)
        self._transition_transaction(
            transaction_id,
            "NEEDS_REVIEW",
            error=reason,
            rollback_error=_safe_text(rollback_error, 1000),
        )
        self._lock_breaker_for_review(reason, transaction_id)

    def _reconcile_incomplete_transactions(self) -> None:
        """Classify crash-interrupted mutations before new apply authority exists."""
        if not self.transactions_path.exists():
            return
        pending = [
            row for row in self.transactions()
            if row.get("status") in {"PREPARED", "MUTATING", "VERIFIED"}
        ]
        if not pending:
            return
        try:
            current = self._firewall()
            if not current.get("supported") or current.get("complete") is not True:
                raise AdaptationError(
                    current.get("reason") or "fresh firewall state is incomplete"
                )
            current_digest = _digest(current)
        except Exception as exc:
            for record in pending:
                self._mark_transaction_needs_review(
                    str(record.get("transaction_id")), error=exc
                )
            return
        for record in pending:
            transaction_id = str(record.get("transaction_id"))
            before = str(record.get("before_firewall_digest") or "")
            after = str(
                record.get("after_firewall_digest")
                or record.get("target_firewall_digest")
                or ""
            )
            if before and hmac.compare_digest(current_digest, before):
                self._transition_transaction(
                    transaction_id,
                    "ROLLED_BACK",
                    error="startup reconciliation observed the exact pre-mutation state",
                )
                continue
            if after and hmac.compare_digest(current_digest, after):
                try:
                    with self._lock:
                        state = self.state()
                        if record.get("kind") == "apply":
                            state["active_profile_id"] = _safe_text(
                                record.get("profile_id"), 80
                            )
                        else:
                            state["active_profile_id"] = ""
                        self._save_state(state)
                    self._transition_transaction(
                        transaction_id,
                        "COMMITTED",
                        error="startup reconciliation verified the exact postcondition",
                    )
                    continue
                except Exception as exc:
                    self._mark_transaction_needs_review(
                        transaction_id, error=exc
                    )
                    continue
            self._mark_transaction_needs_review(
                transaction_id,
                error="startup state matches neither authenticated precondition nor postcondition",
            )

    def _default_state(self) -> dict[str, Any]:
        return {
            "revision": 0,
            "automation_enabled": False,
            "auto_apply": False,
            "triggers": [],
            "active_profile_id": "",
            "last_trigger_signature": "",
            "last_applied_context_signature": "",
            "adaptive_weights": {},
            "feedback_reviews": [],
            "breaker": {
                "locked": False,
                "reason": "",
                "events": [],
                "window_seconds": 15 * 60,
                "min_interval_seconds": 120,
                "max_changes": 3,
                "max_drastic_changes": 2,
            },
        }

    def state(self) -> dict[str, Any]:
        saved = self._load_store(self.state_path, "state", {})
        state = self._default_state()
        if isinstance(saved, dict):
            for key in state:
                if key in saved:
                    state[key] = saved[key]
        if not isinstance(state.get("triggers"), list):
            state["triggers"] = []
        if not isinstance(state.get("adaptive_weights"), dict):
            state["adaptive_weights"] = {}
        if not isinstance(state.get("feedback_reviews"), list):
            state["feedback_reviews"] = []
        state["adaptive_weights"] = self._feedback_weights(
            state["feedback_reviews"]
        )
        if not isinstance(state.get("breaker"), dict):
            state["breaker"] = self._default_state()["breaker"]
        # v1.12 migration: context monitoring is proposal-only. A legacy or
        # hand-edited auto_apply flag never regains unattended mutation authority.
        state["auto_apply"] = False
        return state

    def _save_state(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            saved = self._load_store(self.state_path, "state", {})
            current_revision = int(
                saved.get("revision", 0) if isinstance(saved, dict) else 0
            )
            body = dict(state)
            body["revision"] = max(
                current_revision, int(body.get("revision", 0) or 0)
            ) + 1
            body["adaptive_weights"] = self._feedback_weights(
                body.get("feedback_reviews", [])
            )
            self._save_store(self.state_path, "state", body)

    def _update_state(
        self,
        updates: Mapping[str, Any],
        *,
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Atomically update selected fields without persisting a stale body."""
        with self._lock:
            state = self.state()
            if (
                expected_revision is not None
                and int(state.get("revision", 0)) != int(expected_revision)
            ):
                return None
            state.update(dict(updates))
            self._save_state(state)
            return self.state()

    @staticmethod
    def _feedback_weights(reviews: Any) -> dict[str, float]:
        if not isinstance(reviews, list):
            return {}
        by_category: dict[str, set[str]] = {}
        for review in reviews:
            if not isinstance(review, dict) or not review.get("active"):
                continue
            category = _safe_text(review.get("category"), 60).casefold()
            fingerprint = _safe_text(review.get("fingerprint"), 80)
            if category and fingerprint:
                by_category.setdefault(category, set()).add(fingerprint)
        weights: dict[str, float] = {}
        for category, fingerprints in by_category.items():
            count = len(fingerprints)
            if count >= FEEDBACK_MIN_DISTINCT:
                # A few independent, explicitly reviewed examples may tune a
                # category, but never suppress more than 25% of its score.
                weights[category] = round(
                    max(0.75, 1.0 - (count - FEEDBACK_MIN_DISTINCT + 1) * 0.05),
                    4,
                )
        return weights

    # ── Audit collectors ───────────────────────────────────────────────────
    def host_id(self) -> str:
        identity = f"{platform.node()}|{uuid.getnode()}|{platform.system()}"
        return hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:24]

    def _hardware(self) -> dict[str, Any]:
        memory = psutil.virtual_memory()
        disks: list[dict[str, Any]] = []
        seen: set[str] = set()
        try:
            for part in psutil.disk_partitions(all=False):
                mount = str(part.mountpoint)
                if not mount or mount in seen:
                    continue
                seen.add(mount)
                try:
                    usage = psutil.disk_usage(mount)
                    total = int(usage.total)
                except (OSError, PermissionError):
                    total = 0
                disks.append({
                    "mount": _safe_text(mount, 160),
                    "filesystem": _safe_text(part.fstype, 40),
                    "total_bytes": total,
                })
        except Exception:
            pass
        return {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "logical_cpus": int(psutil.cpu_count(logical=True) or 0),
            "physical_cpus": int(psutil.cpu_count(logical=False) or 0),
            "memory_bytes": int(memory.total),
            "disks": sorted(disks, key=lambda row: row["mount"].casefold())[:128],
        }

    @staticmethod
    def _quality(
        *,
        complete: bool,
        available: bool = True,
        truncated: bool = False,
        error: str = "",
        skipped: int = 0,
    ) -> dict[str, Any]:
        return {
            "complete": bool(complete),
            "available": bool(available),
            "truncated": bool(truncated),
            "error": _safe_text(error, 500),
            "skipped": max(0, int(skipped)),
        }

    def _collect_services(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        errors: list[str] = []
        skipped = 0
        truncated = False
        iterator = getattr(psutil, "win_service_iter", None)
        if not callable(iterator):
            return rows, self._quality(
                complete=False, available=False,
                error="Windows service enumeration is unavailable.",
            )
        try:
            for service in iterator():
                if len(rows) >= MAX_SERVICES:
                    truncated = True
                    break
                try:
                    item = service.as_dict()
                    binpath = str(item.get("binpath") or "").strip()
                    executable = binpath
                    if binpath.startswith('"'):
                        executable = binpath[1:].partition('"')[0]
                    elif binpath:
                        executable = binpath.partition(" ")[0]
                    username = str(item.get("username") or "").strip().casefold()
                    built_in_accounts = {
                        "localsystem": "local-system",
                        "local system": "local-system",
                        "nt authority\\system": "local-system",
                        "nt authority\\localservice": "local-service",
                        "nt authority\\networkservice": "network-service",
                    }
                    built_in_id = built_in_accounts.get(username)
                    account_type = (
                        "built-in" if built_in_id else
                        "custom" if username else "unknown"
                    )
                    rows.append({
                        "name": _safe_text(item.get("name"), 180),
                        "display_name": _safe_text(item.get("display_name"), 240),
                        "status": _safe_text(item.get("status"), 40).lower(),
                        "start_type": _safe_text(item.get("start_type"), 40).lower(),
                        "executable_name": _safe_text(
                            PureWindowsPath(executable).name, 240
                        ).casefold(),
                        "command_sha256": hashlib.sha256(
                            " ".join(binpath.casefold().split()).encode(
                                "utf-8", "replace"
                            )
                        ).hexdigest() if binpath else "",
                        "account_type": account_type,
                        "account_id": built_in_id or (
                            hashlib.sha256(username.encode("utf-8", "replace")).hexdigest()[:20]
                            if account_type == "custom" else "unknown"
                        ),
                    })
                except Exception as exc:
                    skipped += 1
                    if len(errors) < 3:
                        errors.append(_safe_text(exc, 120))
                    continue
        except Exception as exc:
            errors.append(_safe_text(exc, 200))
        complete = not truncated and not errors and skipped == 0
        return (
            sorted(rows, key=lambda row: row["name"].casefold()),
            self._quality(
                complete=complete, truncated=truncated,
                error="; ".join(errors), skipped=skipped,
            ),
        )

    def _services(self) -> list[dict[str, Any]]:
        """Compatibility wrapper for callers that only need service rows."""
        return self._collect_services()[0]

    def _collect_ports(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        process_names: dict[int, str] = {}
        errors: list[str] = []
        skipped = 0
        truncated = False
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as exc:
            return [], self._quality(
                complete=False, available=False, error=_safe_text(exc, 500)
            )
        for connection in connections:
            protocol = "tcp" if int(getattr(connection, "type", 0)) == socket.SOCK_STREAM else "udp"
            if protocol == "tcp" and connection.status != psutil.CONN_LISTEN:
                continue
            if not connection.laddr:
                continue
            try:
                address = str(connection.laddr.ip)
                port = int(connection.laddr.port)
            except Exception as exc:
                skipped += 1
                if len(errors) < 3:
                    errors.append(_safe_text(exc, 120))
                continue
            family_value = int(getattr(connection, "family", 0) or 0)
            address_family = "ipv6" if family_value == socket.AF_INET6 else "ipv4"
            address_id = hashlib.sha256(
                address.casefold().encode("utf-8", "replace")
            ).hexdigest()[:16]
            pid = int(connection.pid or 0)
            if pid and pid not in process_names:
                try:
                    process_names[pid] = _safe_text(psutil.Process(pid).name(), 160).casefold()
                except Exception as exc:
                    process_names[pid] = "unknown"
                    if len(errors) < 3:
                        errors.append(f"process {pid}: {_safe_text(exc, 100)}")
            process_name = process_names.get(pid, "unknown")
            key = (
                f"{protocol}|{address_family}|{_scope_address(address)}|"
                f"{address_id}|{port}|{process_name}"
            )
            if key in rows:
                continue
            if len(rows) >= MAX_PORTS:
                truncated = True
                break
            rows[key] = {
                "key": key,
                "protocol": protocol,
                "address_family": address_family,
                "local_address_id": address_id,
                "scope": _scope_address(address),
                "port": port,
                "process": process_name,
                "pid_observed": pid,
            }
        complete = not truncated and not errors and skipped == 0
        return (
            [rows[key] for key in sorted(rows)],
            self._quality(
                complete=complete, truncated=truncated,
                error="; ".join(errors), skipped=skipped,
            ),
        )

    def _ports(self) -> list[dict[str, Any]]:
        """Compatibility wrapper for callers that only need listener rows."""
        return self._collect_ports()[0]

    @staticmethod
    def _run_readonly(args: Sequence[str], timeout: float = 8.0) -> str:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            list(args), capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False,
            creationflags=flags,
            env=sanitized_child_environment(),
        )
        if completed.returncode != 0:
            detail = _safe_text(completed.stderr or completed.stdout, 500)
            raise AdaptationError(detail or f"command exited {completed.returncode}")
        return completed.stdout

    @staticmethod
    def _powershell_path() -> str:
        candidate = trusted_powershell_path().resolve()
        if not candidate.is_file():
            raise AdaptationError("trusted Windows PowerShell executable is unavailable")
        return str(candidate)

    @staticmethod
    def _netsh_path() -> str:
        _windows, system32 = trusted_windows_directories()
        root = system32.resolve()
        candidate = (root / "netsh.exe").resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise AdaptationError("trusted netsh path escaped System32") from exc
        if not candidate.is_file():
            raise AdaptationError("trusted netsh executable is unavailable")
        return str(candidate)

    def _firewall(self) -> dict[str, Any]:
        if platform.system() != "Windows":
            return {
                "supported": False,
                "complete": False,
                "truncated": False,
                "provider": "none",
                "reason": "Profile mutation is currently brokered only through Windows Firewall.",
                "profiles": [],
                "rules": [],
            }
        script = (
            "$ErrorActionPreference='Stop';"
            "$app=@{};Get-NetFirewallApplicationFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$app[[string]$_.InstanceID]="
            "[PSCustomObject]@{Program=[string]::Join(',',@($_.Program));"
            "Package=[string]::Join(',',@($_.Package))}};"
            "$addr=@{};Get-NetFirewallAddressFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$addr[[string]$_.InstanceID]="
            "[PSCustomObject]@{LocalAddress=[string]::Join(',',@($_.LocalAddress));"
            "RemoteAddress=[string]::Join(',',@($_.RemoteAddress))}};"
            "$port=@{};Get-NetFirewallPortFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$port[[string]$_.InstanceID]="
            "[PSCustomObject]@{Protocol=[string]::Join(',',@($_.Protocol));"
            "LocalPort=[string]::Join(',',@($_.LocalPort));"
            "RemotePort=[string]::Join(',',@($_.RemotePort));"
            "IcmpType=[string]::Join(',',@($_.IcmpType));"
            "DynamicTarget=[string]::Join(',',@($_.DynamicTarget))}};"
            "$iface=@{};Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$iface[[string]$_.InstanceID]="
            "[PSCustomObject]@{InterfaceAlias=[string]::Join(',',@($_.InterfaceAlias))}};"
            "$iftype=@{};Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$iftype[[string]$_.InstanceID]="
            "[PSCustomObject]@{InterfaceType=[string]::Join(',',@($_.InterfaceType))}};"
            "$svc=@{};Get-NetFirewallServiceFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$svc[[string]$_.InstanceID]="
            "[PSCustomObject]@{Service=[string]::Join(',',@($_.Service))}};"
            "$sec=@{};Get-NetFirewallSecurityFilter -PolicyStore ActiveStore "
            "-ErrorAction Stop|ForEach-Object{$sec[[string]$_.InstanceID]="
            "[PSCustomObject]@{LocalUser=[string]::Join(',',@($_.LocalUser));"
            "RemoteUser=[string]::Join(',',@($_.RemoteUser));"
            "RemoteMachine=[string]::Join(',',@($_.RemoteMachine));"
            "Authentication=[string]::Join(',',@($_.Authentication));"
            "Encryption=[string]::Join(',',@($_.Encryption));"
            "OverrideBlockRules=[string]::Join(',',@($_.OverrideBlockRules))}};"
            "$p=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {"
            "[PSCustomObject]@{Name=[string]$_.Name;Enabled=[string]$_.Enabled;"
            "DefaultInboundAction=[string]$_.DefaultInboundAction;"
            "DefaultOutboundAction=[string]$_.DefaultOutboundAction;"
            "PolicyStore=[string]$_.PolicyStore;"
            "PolicyStoreSourceType=[string]$_.PolicyStoreSourceType}});"
            f"$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | "
            f"Select-Object -First {MAX_FIREWALL_RULES + 1} | ForEach-Object {{"
            "$id=[string]$_.InstanceID;"
            "[PSCustomObject]@{Name=[string]$_.Name;DisplayName=[string]$_.DisplayName;"
            "Group=[string]$_.Group;"
            "Enabled=[string]$_.Enabled;Direction=[string]$_.Direction;"
            "Action=[string]$_.Action;Profile=[string]$_.Profile;"
            "EdgeTraversalPolicy=[string]$_.EdgeTraversalPolicy;"
            "LooseSourceMapping=[string]$_.LooseSourceMapping;"
            "LocalOnlyMapping=[string]$_.LocalOnlyMapping;"
            "PolicyStoreSource=[string]$_.PolicyStoreSource;"
            "PolicyStoreSourceType=[string]$_.PolicyStoreSourceType;"
            "ApplicationFilter=$app[$id];AddressFilter=$addr[$id];PortFilter=$port[$id];"
            "InterfaceFilter=$iface[$id];InterfaceTypeFilter=$iftype[$id];"
            "ServiceFilter=$svc[$id];SecurityFilter=$sec[$id]}});"
            "[PSCustomObject]@{Profiles=$p;Rules=$r}|ConvertTo-Json -Depth 6 -Compress"
        )
        try:
            raw = self._run_readonly(
                [self._powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script]
            )
            payload = json.loads(raw or "{}")
            if not isinstance(payload, dict):
                raise AdaptationError("Firewall collector returned an invalid document.")
            profile_payload = payload.get("Profiles") or []
            if isinstance(profile_payload, dict):
                profile_payload = [profile_payload]
            rule_payload = payload.get("Rules") or []
            if isinstance(rule_payload, dict):
                rule_payload = [rule_payload]
            profiles: list[dict[str, Any]] = []
            parse_errors: list[str] = []
            for item in profile_payload if isinstance(profile_payload, list) else []:
                if not isinstance(item, dict):
                    parse_errors.append("invalid profile row")
                    continue
                enabled_text = str(item.get("Enabled", "")).strip()
                inbound = str(item.get("DefaultInboundAction", "")).strip()
                outbound = str(item.get("DefaultOutboundAction", "")).strip()
                if enabled_text not in {"True", "False"}:
                    parse_errors.append(
                        f"{_safe_text(item.get('Name'), 40)} Enabled={enabled_text or 'unknown'}"
                    )
                    enabled: bool | None = None
                else:
                    enabled = enabled_text == "True"
                if inbound not in {"Allow", "Block"} or outbound not in {"Allow", "Block"}:
                    parse_errors.append(
                        f"{_safe_text(item.get('Name'), 40)} firewall defaults are not explicit"
                    )
                profiles.append({
                    "name": _safe_text(item.get("Name"), 40),
                    "enabled": enabled,
                    "inbound": _safe_text(inbound, 40),
                    "outbound": _safe_text(outbound, 40),
                    "policy_store": _safe_text(item.get("PolicyStore"), 160),
                    "policy_store_source_type": _safe_text(
                        item.get("PolicyStoreSourceType"), 80
                    ),
                })
            truncated = len(rule_payload) > MAX_FIREWALL_RULES
            rules: list[dict[str, Any]] = []

            def filter_row(
                source: Mapping[str, Any],
                source_name: str,
                fields: tuple[tuple[str, str], ...],
            ) -> dict[str, str]:
                raw_filter = source.get(source_name)
                if not isinstance(raw_filter, dict):
                    parse_errors.append(
                        f"firewall rule is missing {source_name} evidence"
                    )
                    return {target: "" for _provider, target in fields}
                return {
                    target: _safe_text(raw_filter.get(provider), 2_000)
                    for provider, target in fields
                }

            for item in rule_payload[:MAX_FIREWALL_RULES]:
                if not isinstance(item, dict):
                    parse_errors.append("invalid rule row")
                    continue
                enabled_text = str(item.get("Enabled", "")).strip()
                action = str(item.get("Action", "")).strip()
                direction = str(item.get("Direction", "")).strip()
                if enabled_text not in {"True", "False"}:
                    parse_errors.append("firewall rule has an unknown enabled state")
                    enabled = None
                else:
                    enabled = enabled_text == "True"
                if action not in {"Allow", "Block"} or direction not in {
                    "Inbound", "Outbound"
                }:
                    parse_errors.append("firewall rule has an unknown action or direction")
                name = _safe_text(item.get("Name"), 240)
                if not name:
                    name = "anonymous-" + _digest(item)[:20]
                rules.append({
                    "name": name,
                    "display_name": _safe_text(item.get("DisplayName"), 300),
                    "group": _safe_text(item.get("Group"), 300),
                    "enabled": enabled,
                    "direction": _safe_text(direction, 40),
                    "action": _safe_text(action, 40),
                    "profile": _safe_text(item.get("Profile"), 100),
                    "edge_traversal": _safe_text(
                        item.get("EdgeTraversalPolicy"), 80
                    ),
                    "loose_source_mapping": _safe_text(
                        item.get("LooseSourceMapping"), 80
                    ),
                    "local_only_mapping": _safe_text(
                        item.get("LocalOnlyMapping"), 80
                    ),
                    "policy_store_source": _safe_text(
                        item.get("PolicyStoreSource"), 300
                    ),
                    "policy_store_source_type": _safe_text(
                        item.get("PolicyStoreSourceType"), 80
                    ),
                    "application": filter_row(
                        item, "ApplicationFilter",
                        (("Program", "program"), ("Package", "package")),
                    ),
                    "address": filter_row(
                        item, "AddressFilter",
                        (("LocalAddress", "local"), ("RemoteAddress", "remote")),
                    ),
                    "port": filter_row(
                        item, "PortFilter",
                        (
                            ("Protocol", "protocol"),
                            ("LocalPort", "local"),
                            ("RemotePort", "remote"),
                            ("IcmpType", "icmp_type"),
                            ("DynamicTarget", "dynamic_target"),
                        ),
                    ),
                    "interface": filter_row(
                        item, "InterfaceFilter", (("InterfaceAlias", "alias"),)
                    ),
                    "interface_type": filter_row(
                        item, "InterfaceTypeFilter", (("InterfaceType", "type"),)
                    ),
                    "service": filter_row(
                        item, "ServiceFilter", (("Service", "name"),)
                    ),
                    "security": filter_row(
                        item, "SecurityFilter",
                        (
                            ("LocalUser", "local_user"),
                            ("RemoteUser", "remote_user"),
                            ("RemoteMachine", "remote_machine"),
                            ("Authentication", "authentication"),
                            ("Encryption", "encryption"),
                            ("OverrideBlockRules", "override_block_rules"),
                        ),
                    ),
                })
            complete = bool(profiles) and not truncated and not parse_errors
            return {
                "supported": bool(profiles),
                "complete": complete,
                "truncated": truncated,
                "provider": "Windows Firewall",
                "reason": (
                    "; ".join(parse_errors[:5])
                    if parse_errors else
                    "Firewall rule inventory exceeded its safe bound."
                    if truncated else
                    "" if profiles else "No firewall profiles were returned."
                ),
                "profiles": sorted(profiles, key=lambda row: row["name"]),
                "rules": sorted(rules, key=lambda row: row["name"].casefold()),
            }
        except Exception as exc:
            return {
                "supported": False,
                "complete": False,
                "truncated": False,
                "provider": "Windows Firewall",
                "reason": _safe_text(exc, 500),
                "profiles": [],
                "rules": [],
            }

    @staticmethod
    def _wts_remote_session_active() -> tuple[bool, str]:
        """Inspect every Windows Terminal Services session, not only this one."""
        try:
            import ctypes
            from ctypes import wintypes

            class WTS_SESSION_INFO(ctypes.Structure):
                _fields_ = [
                    ("SessionId", wintypes.DWORD),
                    ("pWinStationName", wintypes.LPWSTR),
                    ("State", ctypes.c_int),
                ]

            wts = ctypes.windll.wtsapi32
            sessions = ctypes.POINTER(WTS_SESSION_INFO)()
            count = wintypes.DWORD()
            if not wts.WTSEnumerateSessionsW(
                wintypes.HANDLE(0), 0, 1, ctypes.byref(sessions), ctypes.byref(count)
            ):
                raise ctypes.WinError()
            try:
                for index in range(min(int(count.value), 256)):
                    item = sessions[index]
                    if int(item.State) not in {0, 1, 3}:  # Active, Connected, Shadow
                        continue
                    protocol_buffer = wintypes.LPWSTR()
                    protocol_bytes = wintypes.DWORD()
                    ok = wts.WTSQuerySessionInformationW(
                        wintypes.HANDLE(0),
                        item.SessionId,
                        16,  # WTSClientProtocolType
                        ctypes.byref(protocol_buffer),
                        ctypes.byref(protocol_bytes),
                    )
                    if not ok:
                        continue
                    try:
                        protocol = ctypes.cast(
                            protocol_buffer, ctypes.POINTER(wintypes.USHORT)
                        ).contents.value
                    finally:
                        wts.WTSFreeMemory(protocol_buffer)
                    station = str(item.pWinStationName or "").casefold()
                    if protocol == 2 or station.startswith(("rdp-", "ica-")):
                        return True, ""
            finally:
                wts.WTSFreeMemory(sessions)
            if int(count.value) > 256:
                return False, "remote-session inventory exceeded 256 sessions"
            return False, ""
        except Exception as exc:
            return False, f"WTS remote-session status: {_safe_text(exc, 180)}"

    @staticmethod
    def _remote_control_agent_active() -> tuple[bool, str]:
        """Conservatively detect common console-sharing agent processes."""
        names = {
            "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe",
            "rustdesk.exe", "screenconnect.clientservice.exe", "connectwisecontrol.client.exe",
            "splashtopremote.exe", "srmanager.exe", "logmein.exe", "bomgar-scc.exe",
            "dwagent.exe", "meshagent.exe",
        }
        try:
            for index, process in enumerate(psutil.process_iter(["name"])):
                if index >= 4096:
                    return False, "remote-control process inventory exceeded 4096 entries"
                name = str((process.info or {}).get("name") or "").casefold()
                if name in names:
                    return True, ""
            return False, ""
        except Exception as exc:
            return False, f"remote-control agent status: {_safe_text(exc, 180)}"

    @staticmethod
    def _remote_session_state() -> tuple[bool, str]:
        """Return host-wide remote-operator state without retaining peer details."""
        if any(
            bool(os.environ.get(name))
            for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
        ):
            return True, ""
        session_name = str(os.environ.get("SESSIONNAME") or "").strip().casefold()
        if session_name.startswith("rdp-"):
            return True, ""
        if platform.system() != "Windows":
            return False, ""
        try:
            import ctypes

            if bool(ctypes.windll.user32.GetSystemMetrics(0x1000)):
                return True, ""
        except Exception as exc:
            return False, f"remote-session status: {_safe_text(exc, 180)}"
        wts_active, wts_error = HostAdaptationService._wts_remote_session_active()
        if wts_active:
            return True, ""
        agent_active, agent_error = HostAdaptationService._remote_control_agent_active()
        if agent_active:
            return True, ""
        return False, "; ".join(error for error in (wts_error, agent_error) if error)

    def capture_context(self) -> dict[str, Any]:
        interfaces = []
        vpn_active = False
        errors: list[str] = []
        truncated = False
        try:
            from angerona.core.net_interfaces import VIRTUAL_VPN, classify_interfaces
            classes = classify_interfaces()
            stats = psutil.net_if_stats()
            for name in sorted(set(classes) | set(stats)):
                kind = classes.get(name, "Physical")
                up = bool(stats.get(name) and stats[name].isup)
                vpn_active = vpn_active or (kind == VIRTUAL_VPN and up)
                interfaces.append({"name": _safe_text(name, 160), "type": kind, "up": up})
        except Exception as exc:
            errors.append(f"interfaces: {_safe_text(exc, 180)}")

        ssid = ""
        category = "Unknown"
        remote_session, remote_error = self._remote_session_state()
        if remote_error:
            errors.append(remote_error)
        if platform.system() == "Windows":
            try:
                output = self._run_readonly(
                    [self._netsh_path(), "wlan", "show", "interfaces"], timeout=5.0
                )
                for line in output.splitlines():
                    key, separator, value = line.partition(":")
                    if separator and key.strip().casefold() == "ssid":
                        ssid = _safe_text(value.strip(), 160)
                        break
            except Exception as exc:
                errors.append(f"SSID: {_safe_text(exc, 180)}")
            try:
                script = (
                    "$ErrorActionPreference='Stop';"
                    "Get-NetConnectionProfile | Where-Object {$_.IPv4Connectivity -ne 'Disconnected' "
                    "-or $_.IPv6Connectivity -ne 'Disconnected'} | Select-Object "
                    "-ExpandProperty NetworkCategory"
                )
                values = {
                    line.strip()
                    for line in self._run_readonly(
                    [self._powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script],
                    timeout=5.0,
                    ).splitlines()
                    if line.strip() in {"Public", "Private", "DomainAuthenticated"}
                }
                # Any active public attachment must win. Selecting an arbitrary
                # first connection can otherwise hide a simultaneous untrusted
                # network behind a trusted Ethernet or VPN profile.
                for candidate in ("Public", "Private", "DomainAuthenticated"):
                    if candidate in values:
                        category = candidate
                        break
            except Exception as exc:
                errors.append(f"network category: {_safe_text(exc, 180)}")
        if len(interfaces) > 256:
            truncated = True
        quality = self._quality(
            complete=not errors and not truncated,
            truncated=truncated,
            error="; ".join(errors),
        )
        return {
            "captured_at": _utc_now(),
            "ssid": ssid,
            "network_category": category,
            "vpn_active": vpn_active,
            "remote_session": remote_session,
            "interfaces": interfaces[:256],
            "collector": quality,
        }

    def capture_snapshot(self) -> dict[str, Any]:
        """Capture bounded local state. This method never writes or mutates it."""
        services, services_quality = self._collect_services()
        ports, ports_quality = self._collect_ports()
        network = self.capture_context()
        firewall = self._firewall()
        return {
            "schema": f"angerona.host-snapshot/v{SCHEMA_VERSION}",
            "captured_at": _utc_now(),
            "host_id": self.host_id(),
            "hardware": self._hardware(),
            "services": services,
            "ports": ports,
            "network": network,
            "firewall": firewall,
            "collector_status": {
                "services": services_quality,
                "ports": ports_quality,
                "network": dict(network.get("collector") or {}),
                "firewall": self._quality(
                    complete=bool(firewall.get("complete")),
                    available=bool(firewall.get("supported")),
                    truncated=bool(firewall.get("truncated")),
                    error=str(firewall.get("reason") or ""),
                ),
            },
        }

    # ── Baseline, drift, exceptions, and feedback ──────────────────────────
    def save_baseline(self, snapshot: Mapping[str, Any]) -> None:
        if snapshot.get("host_id") != self.host_id():
            raise AdaptationError("refusing a golden baseline captured from another host")
        quality = snapshot.get("collector_status")
        required = ("services", "ports", "network", "firewall")
        if not isinstance(quality, Mapping) or any(
            not isinstance(quality.get(name), Mapping)
            or quality[name].get("complete") is not True
            for name in required
        ):
            raise AdaptationError(
                "refusing to baseline incomplete host collectors: "
                + ", ".join(
                    name
                    for name in required
                    if not isinstance(quality, Mapping)
                    or not isinstance(quality.get(name), Mapping)
                    or quality[name].get("complete") is not True
                )
            )
        self._save_store(self.baseline_path, "baseline", dict(snapshot))
        self.log_activity("baseline.saved", "success", "Golden baseline replaced by operator.")

    def load_baseline(self) -> dict[str, Any] | None:
        value = self._load_store(self.baseline_path, "baseline", None)
        return value if isinstance(value, dict) else None

    def list_exceptions(self) -> list[dict[str, Any]]:
        body = self._load_store(self.exceptions_path, "exceptions", [])
        return list(body) if isinstance(body, list) else []

    def add_exception(
        self,
        finding: Mapping[str, Any],
        reason: str,
        *,
        tune_feedback: bool = False,
    ) -> dict[str, Any]:
        category = _safe_text(finding.get("category"), 60).casefold()
        key = _safe_text(finding.get("key"), 500)
        reason = _safe_text(reason, 500).strip()
        if not category or not key or not reason:
            raise ValueError("an exception requires a finding category, key, and reason")
        fingerprint = self._finding_fingerprint(
            category,
            key,
            _safe_text(finding.get("change"), 40),
            finding.get("baseline"),
            finding.get("current"),
        )
        entry = {
            "id": fingerprint,
            "category": category,
            "key": key,
            "finding_fingerprint": fingerprint,
            "reason": reason,
            "created_at": _utc_now(),
            "source_finding": _safe_text(finding.get("id"), 80),
        }
        with self._lock:
            existing_entries = self.list_exceptions()
            duplicate = next(
                (
                    item for item in existing_entries
                    if item.get("finding_fingerprint") == fingerprint
                    or item.get("id") == fingerprint
                ),
                None,
            )
            state = self.state()
            reviews = list(state.get("feedback_reviews") or [])
            already_reviewed = any(
                item.get("fingerprint") == fingerprint for item in reviews
                if isinstance(item, dict)
            )
            if tune_feedback and (
                bool(finding.get("excluded")) or duplicate is not None or already_reviewed
            ):
                raise ValueError("this exact finding has already been excluded or reviewed")
            entries = [
                item for item in existing_entries
                if item.get("finding_fingerprint") != fingerprint
                and item.get("id") != fingerprint
            ]
            entries.append(entry)
            self._save_store(
                self.exceptions_path, "exceptions", entries[-MAX_EXCEPTIONS:]
            )
            if tune_feedback:
                reviews.append({
                    "fingerprint": fingerprint,
                    "category": category,
                    "reviewed_at": _utc_now(),
                    "active": True,
                })
                state["feedback_reviews"] = reviews[-MAX_FEEDBACK_REVIEWS:]
                self._save_state(state)
        self.log_activity(
            "finding.dismissed" if tune_feedback else "exception.added",
            "success",
            f"{category}: {key} — {reason}",
        )
        return entry

    def remove_exception(self, exception_id: str) -> bool:
        with self._lock:
            entries = self.list_exceptions()
            removed = next(
                (item for item in entries if item.get("id") == exception_id), None
            )
            kept = [item for item in entries if item.get("id") != exception_id]
            if len(kept) == len(entries):
                return False
            self._save_store(self.exceptions_path, "exceptions", kept)
            if removed:
                fingerprint = removed.get("finding_fingerprint") or removed.get("id")
                state = self.state()
                reviews = []
                for item in state.get("feedback_reviews") or []:
                    review = dict(item) if isinstance(item, dict) else {}
                    if review.get("fingerprint") == fingerprint:
                        review["active"] = False
                    if review:
                        reviews.append(review)
                state["feedback_reviews"] = reviews
                self._save_state(state)
        self.log_activity("exception.removed", "success", exception_id)
        return True

    @staticmethod
    def _indexed(rows: Iterable[Mapping[str, Any]], field: str) -> dict[str, dict[str, Any]]:
        return {
            str(row.get(field, "")): dict(row)
            for row in rows if str(row.get(field, ""))
        }

    @staticmethod
    def _collector_comparable(
        baseline: Mapping[str, Any], current: Mapping[str, Any], collector: str
    ) -> bool:
        """Legacy snapshots remain comparable; explicit partial reads do not."""
        for snapshot in (baseline, current):
            status = (snapshot.get("collector_status") or {}).get(collector)
            if isinstance(status, Mapping) and not status.get("complete", False):
                return False
        return True

    def _finding(
        self, category: str, key: str, change: str, before: Any, after: Any,
        severity: str, base_score: float, weights: Mapping[str, Any],
        exceptions: set[str],
    ) -> dict[str, Any]:
        multiplier = max(0.25, min(2.0, float(weights.get(category, 1.0))))
        fingerprint = self._finding_fingerprint(category, key, change, before, after)
        excluded = fingerprint in exceptions
        score = 0.0 if excluded else round(base_score * multiplier, 2)
        return {
            "id": fingerprint,
            "category": category,
            "key": key,
            "change": change,
            "baseline": before,
            "current": after,
            "severity": severity,
            "score": score,
            "excluded": excluded,
        }

    @staticmethod
    def _finding_fingerprint(
        category: str, key: str, change: str, before: Any, after: Any
    ) -> str:
        return hashlib.sha256(_canonical({
            "category": category,
            "key": key,
            "change": change,
            "baseline": before,
            "current": after,
        })).hexdigest()[:24]

    def compare(
        self, baseline: Mapping[str, Any], current: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        if baseline.get("host_id") != current.get("host_id"):
            raise AdaptationError("baseline and current audit identify different hosts")
        state = self.state()
        weights = state.get("adaptive_weights", {})
        exceptions = {
            str(item.get("finding_fingerprint") or "")
            for item in self.list_exceptions()
            if item.get("finding_fingerprint")
        }
        findings: list[dict[str, Any]] = []

        old_hw = dict(baseline.get("hardware") or {})
        new_hw = dict(current.get("hardware") or {})
        for key in ("system", "release", "machine", "logical_cpus", "physical_cpus", "memory_bytes"):
            if old_hw.get(key) != new_hw.get(key):
                findings.append(self._finding(
                    "hardware", key, "changed", old_hw.get(key), new_hw.get(key),
                    "high", 12.0, weights, exceptions,
                ))
        old_disks = self._indexed(old_hw.get("disks") or [], "mount")
        new_disks = self._indexed(new_hw.get("disks") or [], "mount")
        self._compare_maps(findings, "hardware", "disk:", old_disks, new_disks,
                           "medium", 5.0, weights, exceptions)

        if self._collector_comparable(baseline, current, "services"):
            old_services = self._indexed(baseline.get("services") or [], "name")
            new_services = self._indexed(current.get("services") or [], "name")
            self._compare_maps(findings, "services", "", old_services, new_services,
                               "medium", 3.0, weights, exceptions)

        # PID is useful audit context but intentionally excluded from drift
        # equality: a known listener restarting with a new PID is not a new
        # exposure. Protocol/scope/port/process are already bound into ``key``.
        if self._collector_comparable(baseline, current, "ports"):
            old_ports = {
                key: {field: value for field, value in row.items() if field != "pid_observed"}
                for key, row in self._indexed(baseline.get("ports") or [], "key").items()
            }
            new_ports = {
                key: {field: value for field, value in row.items() if field != "pid_observed"}
                for key, row in self._indexed(current.get("ports") or [], "key").items()
            }
            self._compare_maps(findings, "ports", "", old_ports, new_ports,
                               "high", 5.0, weights, exceptions)

        if self._collector_comparable(baseline, current, "firewall"):
            old_firewall = baseline.get("firewall") or {}
            new_firewall = current.get("firewall") or {}
            old_fw = self._indexed(old_firewall.get("profiles") or [], "name")
            new_fw = self._indexed(new_firewall.get("profiles") or [], "name")
            self._compare_maps(findings, "firewall", "profile:", old_fw, new_fw,
                               "critical", 10.0, weights, exceptions)
            old_rules = self._indexed(old_firewall.get("rules") or [], "name")
            new_rules = self._indexed(new_firewall.get("rules") or [], "name")
            self._compare_maps(findings, "firewall", "rule:", old_rules, new_rules,
                               "critical", 10.0, weights, exceptions)

        if self._collector_comparable(baseline, current, "network"):
            old_net = self._indexed((baseline.get("network") or {}).get("interfaces") or [], "name")
            new_net = self._indexed((current.get("network") or {}).get("interfaces") or [], "name")
            self._compare_maps(findings, "network", "interface:", old_net, new_net,
                               "medium", 3.0, weights, exceptions)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            findings,
            key=lambda row: (row["excluded"], order.get(row["severity"], 9), row["category"], row["key"]),
        )

    def _compare_maps(
        self,
        findings: list[dict[str, Any]],
        category: str,
        prefix: str,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        severity: str,
        score: float,
        weights: Mapping[str, Any],
        exceptions: set[str],
    ) -> None:
        for identity in sorted(set(before) | set(after), key=str.casefold):
            old = before.get(identity)
            new = after.get(identity)
            if old == new:
                continue
            change = "added" if old is None else "removed" if new is None else "changed"
            key = f"{prefix}{identity}"
            findings.append(self._finding(
                category, key, change, old, new, severity, score,
                weights, exceptions,
            ))

    def audit(self) -> dict[str, Any]:
        current = self.capture_snapshot()
        baseline = self.load_baseline()
        findings = self.compare(baseline, current) if baseline else []
        active = [row for row in findings if not row["excluded"]]
        incomplete_collectors = [
            name for name in ("services", "ports", "firewall", "network")
            if not bool(
                ((current.get("collector_status") or {}).get(name) or {}).get(
                    "complete", False
                )
            )
        ]
        skipped_collectors = []
        if baseline:
            skipped_collectors = [
                name for name in ("services", "ports", "firewall", "network")
                if not self._collector_comparable(baseline, current, name)
            ]
        report = {
            "schema": f"angerona.host-audit/v{SCHEMA_VERSION}",
            "generated_at": _utc_now(),
            "baseline_exists": baseline is not None,
            "baseline_captured_at": baseline.get("captured_at", "") if baseline else "",
            "current": current,
            "findings": findings,
            "active_findings": len(active),
            "excluded_findings": len(findings) - len(active),
            "risk_score": min(100.0, round(sum(float(row["score"]) for row in active), 2)),
            "risk_score_complete": not incomplete_collectors and not skipped_collectors,
            "incomplete_collectors": incomplete_collectors,
            "skipped_incomplete_collectors": skipped_collectors,
        }
        self.log_activity(
            "audit.completed", "success",
            f"{len(active)} active drift findings; risk {report['risk_score']:.1f}/100.",
        )
        return report

    def export_report(self, report: Mapping[str, Any], destination: str | Path, format: str) -> Path:
        target = Path(destination).expanduser().resolve()
        fmt = format.strip().lower()
        if fmt not in {"json", "csv"}:
            raise ValueError("audit export format must be json or csv")
        expected = f".{fmt}"
        if target.suffix.casefold() != expected:
            target = target.with_suffix(expected)
        if fmt == "json":
            encoded = json.dumps(report, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        else:
            output = io.StringIO(newline="")
            writer = csv.writer(output)
            writer.writerow([
                "finding_id", "severity", "category", "change", "key", "score",
                "excluded", "baseline", "current",
            ])
            for item in report.get("findings", []):
                writer.writerow([self._csv_cell(value) for value in [
                    item.get("id", ""), item.get("severity", ""),
                    item.get("category", ""), item.get("change", ""),
                    item.get("key", ""), item.get("score", 0),
                    item.get("excluded", False),
                    json.dumps(item.get("baseline"), ensure_ascii=False, default=str),
                    json.dumps(item.get("current"), ensure_ascii=False, default=str),
                ]])
            encoded = output.getvalue().encode("utf-8-sig")
        self._atomic_write(target, encoded)
        self.log_activity("audit.exported", "success", f"{fmt.upper()}: {target}")
        return target

    @staticmethod
    def _csv_cell(value: Any) -> Any:
        """Neutralize spreadsheet formulas without changing numeric columns."""
        if not isinstance(value, str):
            return value
        stripped = value.lstrip()
        if stripped.startswith(("=", "+", "-", "@")):
            return "'" + value
        return value

    # ── Profiles, dry-run, sandbox, apply, and rollback ────────────────────
    @staticmethod
    def profiles() -> tuple[AdaptationProfile, ...]:
        return tuple(PROFILES.values())

    @staticmethod
    def _action_script(action: FirewallAction) -> str:
        allowed_profiles = {"Domain", "Private", "Public"}
        if not action.profiles or not set(action.profiles).issubset(allowed_profiles):
            raise AdaptationError("profile contains an unsupported firewall target")
        if action.inbound not in {"Allow", "Block"} or action.outbound not in {"Allow", "Block"}:
            raise AdaptationError("profile contains an unsupported firewall default")
        profile_arg = ",".join(action.profiles)
        enabled = "True" if action.enabled else "False"
        return (
            "$ErrorActionPreference='Stop';"
            f"Set-NetFirewallProfile -Profile {profile_arg} -Enabled {enabled} "
            f"-DefaultInboundAction {action.inbound} "
            f"-DefaultOutboundAction {action.outbound} -ErrorAction Stop"
        )

    @classmethod
    def command_stack(cls, plan: AdaptationPlan) -> tuple[str, ...]:
        executable = (
            cls._powershell_path()
            if platform.system() == "Windows" else "powershell.exe"
        )
        return tuple(
            f'"{executable}" -NoProfile -NonInteractive -Command "'
            + cls._action_script(action).replace('"', '\\"') + '"'
            for action in plan.actions
        )

    def build_plan(
        self,
        profile_id: str,
        snapshot: Mapping[str, Any] | None = None,
    ) -> AdaptationPlan:
        profile = PROFILES.get(profile_id)
        if profile is None:
            raise ValueError("unknown adaptation profile")
        current = dict(snapshot or self.capture_snapshot())
        if current.get("host_id") != self.host_id():
            raise AdaptationError("profile preview was captured from another host")
        firewall = current.get("firewall") or {}
        if not firewall.get("supported"):
            raise AdaptationError(
                firewall.get("reason") or "Windows Firewall profile management is unavailable"
            )
        if firewall.get("complete") is False:
            raise AdaptationError(
                firewall.get("reason") or
                "Windows Firewall state is incomplete; adaptation is refused"
            )
        created_epoch = self._clock()
        created = datetime.fromtimestamp(created_epoch, timezone.utc).replace(microsecond=0)
        expires = datetime.fromtimestamp(
            created_epoch + PLAN_TTL_SECONDS, timezone.utc
        ).replace(microsecond=0)
        core = {
            "profile_id": profile.profile_id,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "host_id": self.host_id(),
            "precondition_digest": _digest(firewall),
            "actions": [asdict(action) for action in profile.actions],
            "drastic": profile.drastic,
            "warnings": list(profile.warnings),
        }
        digest = _digest(core)
        return AdaptationPlan(
            plan_id=f"adapt-{digest[:24]}", digest=digest,
            actions=profile.actions, warnings=profile.warnings,
            profile_id=profile.profile_id, created_at=core["created_at"],
            expires_at=core["expires_at"], host_id=core["host_id"],
            precondition_digest=core["precondition_digest"], drastic=profile.drastic,
        )

    @staticmethod
    def _verify_plan(plan: AdaptationPlan) -> None:
        core = asdict(plan)
        supplied_digest = core.pop("digest")
        core.pop("plan_id")
        if supplied_digest != _digest(core) or plan.plan_id != f"adapt-{supplied_digest[:24]}":
            raise IntegrityError("adaptation plan has been altered")
        profile = PROFILES.get(plan.profile_id)
        if profile is None or plan.actions != profile.actions or plan.drastic != profile.drastic:
            raise IntegrityError("adaptation plan no longer matches the closed profile catalog")

    def sandbox(self, profile_id: str, snapshot: Mapping[str, Any] | None = None) -> dict[str, Any]:
        current = dict(snapshot or self.capture_snapshot())
        plan = self.build_plan(profile_id, current)
        return self.simulate_plan(plan, current)

    def simulate_plan(
        self, plan: AdaptationPlan, snapshot: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Simulate the exact immutable plan that may later be approved."""
        self._verify_plan(plan)
        current = dict(snapshot or self.capture_snapshot())
        if current.get("host_id") != plan.host_id:
            raise AdaptationError("sandbox snapshot belongs to another host")
        if _digest(current.get("firewall") or {}) != plan.precondition_digest:
            raise AdaptationError("sandbox snapshot no longer matches the immutable plan")
        before = self._indexed((current.get("firewall") or {}).get("profiles") or [], "name")
        after = {key: dict(value) for key, value in before.items()}
        changes = []
        for action in plan.actions:
            for profile_name in action.profiles:
                old = dict(after.get(profile_name, {"name": profile_name}))
                new = dict(old)
                new.update({
                    "enabled": action.enabled,
                    "inbound": action.inbound,
                    "outbound": action.outbound,
                })
                after[profile_name] = new
                if old != new:
                    changes.append({"profile": profile_name, "before": old, "after": new})
        return {
            "schema": f"angerona.adaptation-sandbox/v{SCHEMA_VERSION}",
            "simulated_at": _utc_now(),
            "host_mutated": False,
            "profile_id": plan.profile_id,
            "plan_id": plan.plan_id,
            "commands": list(self.command_stack(plan)),
            "changes": changes,
            "warnings": list(plan.warnings),
        }

    def breaker_status(self) -> dict[str, Any]:
        state = self.state()
        breaker = dict(self._default_state()["breaker"])
        breaker.update(state.get("breaker") or {})
        now = self._clock()
        window = max(60, int(breaker.get("window_seconds", 900)))
        events = [
            event for event in breaker.get("events", [])
            if now - float(event.get("epoch", 0)) <= window
        ]
        breaker["events"] = events
        return breaker

    def _check_breaker(self, drastic: bool) -> None:
        with self._lock:
            state = self.state()
            breaker = self.breaker_status()
            events = breaker["events"]
            if breaker.get("locked"):
                raise CircuitBreakerOpen(
                    str(breaker.get("reason") or "adaptation posture is locked")
                )
            now = self._clock()
            if events and now - float(events[-1].get("epoch", 0)) < int(
                breaker.get("min_interval_seconds", 120)
            ):
                raise CircuitBreakerOpen("adaptation rate limit is cooling down")
            drastic_count = sum(bool(item.get("drastic")) for item in events)
            if len(events) >= int(breaker.get("max_changes", 3)) or (
                drastic and drastic_count >= int(breaker.get("max_drastic_changes", 2))
            ):
                breaker["locked"] = True
                breaker["reason"] = "Repeated defensive changes opened the circuit breaker."
                state["breaker"] = breaker
                self._save_state(state)
                self.log_activity("breaker.opened", "blocked", breaker["reason"])
                raise CircuitBreakerOpen(breaker["reason"])

    def _record_change(
        self, plan: AdaptationPlan, *, transaction_id: str = ""
    ) -> None:
        with self._lock:
            state = self.state()
            breaker = self.breaker_status()
            events = list(breaker["events"])
            events.append({
                "epoch": self._clock(), "at": _utc_now(),
                "profile_id": plan.profile_id, "drastic": plan.drastic,
                "transaction_id": _safe_text(transaction_id, 80),
            })
            breaker["events"] = events[-20:]
            drastic_count = sum(bool(item.get("drastic")) for item in events)
            if (
                len(events) >= int(breaker.get("max_changes", 3))
                or drastic_count >= int(breaker.get("max_drastic_changes", 2))
            ):
                breaker["locked"] = True
                breaker["reason"] = (
                    "Drastic-change threshold reached; posture locked for review."
                    if drastic_count >= int(breaker.get("max_drastic_changes", 2))
                    else "Change threshold reached; posture locked for review."
                )
            state["breaker"] = breaker
            state["active_profile_id"] = plan.profile_id
            self._save_state(state)

    def reset_breaker(self) -> None:
        unresolved = [
            row for row in self.transactions()
            if row.get("status") == "NEEDS_REVIEW"
        ]
        if unresolved:
            raise CircuitBreakerOpen(
                "complete or resolve the recorded recovery transaction before "
                "resetting the adaptation breaker"
            )
        with self._lock:
            state = self.state()
            state["breaker"] = self._default_state()["breaker"]
            self._save_state(state)
        self.log_activity("breaker.reset", "success", "Operator reset the adaptation breaker.")

    def _snapshot_path(self, snapshot_id: str, suffix: str) -> Path:
        if not snapshot_id.startswith("snap-") or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in snapshot_id):
            raise AdaptationError("invalid snapshot identity")
        candidate = (self.snapshots_dir / f"{snapshot_id}{suffix}").resolve()
        if candidate.parent != self.snapshots_dir:
            raise AdaptationError("snapshot path escaped its data directory")
        return candidate

    def _security_baseline(self) -> dict[str, Any] | None:
        manifest_exists = self.security_baseline_manifest_path.exists()
        artifact_exists = self.security_baseline_firewall_path.exists()
        if not manifest_exists and not artifact_exists:
            return None
        if manifest_exists != artifact_exists:
            raise IntegrityError("host security baseline is incomplete")
        manifest = self._load_store(
            self.security_baseline_manifest_path, "security-baseline", None
        )
        if not isinstance(manifest, dict) or manifest.get("host_id") != self.host_id():
            raise IntegrityError("host security baseline belongs to another host")
        artifact = self.security_baseline_firewall_path
        digest = self._bounded_file_sha256(artifact)
        if not hmac.compare_digest(digest, str(manifest.get("firewall_sha256") or "")):
            raise IntegrityError("host security baseline artifact failed authentication")
        return manifest

    def security_baseline_status(self) -> dict[str, Any]:
        """Describe only the component state Angerona can actually restore."""
        if platform.system().casefold() != "windows":
            return {
                "available": False,
                "supported": False,
                "restorable_components": [],
                "observational_only": [
                    "hardware", "services", "listening-ports", "network-context"
                ],
                "detail": "Immutable Windows Firewall recovery is unsupported on this host.",
            }
        manifest = self._security_baseline()
        if manifest is None:
            return {
                "available": False,
                "supported": True,
                "restorable_components": ["windows-firewall-policy"],
                "observational_only": [
                    "hardware", "services", "listening-ports", "network-context"
                ],
                "detail": "Capture is required before the first profile change.",
            }
        return {
            "available": True,
            "supported": True,
            "baseline_id": manifest.get("baseline_id"),
            "captured_at": manifest.get("captured_at"),
            "restorable_components": list(manifest.get("restorable_components") or ()),
            "observational_only": list(manifest.get("observational_only") or ()),
            "firewall_sha256": manifest.get("firewall_sha256"),
            "detail": "Immutable original firewall policy is available for verified restore.",
        }

    def _ensure_security_baseline(
        self,
        *,
        source_snapshot_id: str,
        current: Mapping[str, Any],
        firewall_file: Path,
    ) -> dict[str, Any]:
        existing = self._security_baseline()
        if existing is not None:
            return existing
        baseline_id = "host-security-baseline-v1"
        artifact_created = False
        try:
            digest = self._exclusive_copy_bounded(
                firewall_file, self.security_baseline_firewall_path
            )
            artifact_created = True
            manifest = {
                "baseline_id": baseline_id,
                "captured_at": _utc_now(),
                "host_id": self.host_id(),
                "source_snapshot_id": source_snapshot_id,
                "firewall_file": self.security_baseline_firewall_path.name,
                "firewall_sha256": digest,
                "firewall": current.get("firewall") or {},
                "network_context": current.get("network") or {},
                "restorable_components": ["windows-firewall-policy"],
                "observational_only": [
                    "hardware", "services", "listening-ports", "network-context"
                ],
                "replacement_allowed": False,
            }
            self._save_store_exclusive(
                self.security_baseline_manifest_path,
                "security-baseline",
                manifest,
            )
        except Exception:
            # Remove only the exact artifact this transaction created. A
            # pre-existing target is never opened or overwritten.
            if artifact_created and not self.security_baseline_manifest_path.exists():
                try:
                    self.security_baseline_firewall_path.unlink()
                except OSError:
                    pass
            raise
        self.log_activity(
            "security_baseline.captured",
            "success",
            f"{baseline_id}; restorable=windows-firewall-policy",
        )
        return manifest

    def _capture_rollback_snapshot(
        self,
        plan: AdaptationPlan,
        current: Mapping[str, Any],
        *,
        purpose: str = "pre-adaptation",
    ) -> str:
        snapshot_id = f"snap-{int(self._clock())}-{plan.plan_id[-10:]}"
        firewall_file = self._snapshot_path(snapshot_id, ".wfw")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            [self._netsh_path(), "advfirewall", "export", str(firewall_file)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=20, check=False, creationflags=flags,
            env=sanitized_child_environment(),
        )
        if completed.returncode != 0 or not firewall_file.is_file():
            raise AdaptationError(
                "Could not create the required Windows Firewall rollback snapshot: "
                + _safe_text(completed.stderr or completed.stdout, 500)
            )
        manifest = {
            "snapshot_id": snapshot_id,
            "captured_at": _utc_now(),
            "host_id": self.host_id(),
            "plan": asdict(plan),
            "firewall_file": firewall_file.name,
            "firewall_sha256": self._bounded_file_sha256(firewall_file),
            "network": current.get("network") or {},
            "firewall": current.get("firewall") or {},
            "purpose": _safe_text(purpose, 120),
            "status": "ready",
        }
        self._save_store(
            self._snapshot_path(snapshot_id, ".json"), "rollback-snapshot", manifest
        )
        self._prune_snapshots()
        return snapshot_id

    def capture_security_baseline(self, *, approved: bool) -> dict[str, Any]:
        """Explicitly capture the immutable original firewall recovery point."""
        if not approved:
            raise PermissionError("explicit security-baseline approval is required")
        if not self._mutation_lock.acquire(blocking=False):
            raise AdaptationError("another adaptation or rollback transaction is active")
        try:
            existing = self._security_baseline()
            if existing is not None:
                return self.security_baseline_status()
            current = self.capture_snapshot()
            firewall = current.get("firewall") or {}
            quality = (current.get("collector_status") or {}).get("firewall") or {}
            if (
                not firewall.get("supported")
                or firewall.get("complete") is not True
                or quality.get("complete") is not True
            ):
                raise AdaptationError(
                    "a complete Windows Firewall capture is required for a restorable baseline"
                )
            plan = self.build_plan("balanced", current)
            snapshot_id = self._capture_rollback_snapshot(
                plan, current, purpose="host-security-baseline-enrollment"
            )
            self._ensure_security_baseline(
                source_snapshot_id=snapshot_id,
                current=current,
                firewall_file=self._snapshot_path(snapshot_id, ".wfw"),
            )
            return self.security_baseline_status()
        finally:
            self._mutation_lock.release()

    def _prune_snapshots(self) -> None:
        manifests = sorted(
            self.snapshots_dir.glob("snap-*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for manifest_path in manifests[SNAPSHOT_RETENTION:]:
            snapshot_id = manifest_path.stem
            for path in (manifest_path, self._snapshot_path(snapshot_id, ".wfw")):
                try:
                    path.unlink()
                except OSError:
                    pass

    def list_snapshots(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(
            self.snapshots_dir.glob("snap-*.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )[:SNAPSHOT_RETENTION]:
            try:
                body = self._load_store(path, "rollback-snapshot", {})
                if isinstance(body, dict):
                    rows.append(body)
            except IntegrityError:
                continue
        return rows

    def _execute_actions(self, plan: AdaptationPlan) -> tuple[str, ...]:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        executed = []
        for action in plan.actions:
            script = self._action_script(action)
            completed = subprocess.run(
                [self._powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=20, check=False, creationflags=flags,
                env=sanitized_child_environment(),
            )
            if completed.returncode != 0:
                raise AdaptationError(
                    "Firewall broker refused an action: "
                    + _safe_text(completed.stderr or completed.stdout, 500)
                )
            executed.append(self.command_stack(plan)[len(executed)])
        return tuple(executed)

    @staticmethod
    def _verify_profile_postconditions(
        plan: AdaptationPlan, firewall: Mapping[str, Any]
    ) -> None:
        if not firewall.get("supported") or firewall.get("complete") is False:
            raise AdaptationError(
                firewall.get("reason") or
                "fresh Windows Firewall state is unavailable after apply"
            )
        profiles = HostAdaptationService._indexed(
            firewall.get("profiles") or [], "name"
        )
        mismatches: list[str] = []
        for action in plan.actions:
            for name in action.profiles:
                observed = profiles.get(name)
                if not observed:
                    mismatches.append(f"{name} missing")
                    continue
                if observed.get("enabled") is not action.enabled:
                    mismatches.append(f"{name} enabled")
                if observed.get("inbound") != action.inbound:
                    mismatches.append(f"{name} inbound")
                if observed.get("outbound") != action.outbound:
                    mismatches.append(f"{name} outbound")
        if mismatches:
            raise AdaptationError(
                "Firewall postcondition mismatch: " + ", ".join(mismatches[:12])
            )

    @staticmethod
    def _plan_relaxes_current(
        plan: AdaptationPlan, firewall: Mapping[str, Any]
    ) -> bool:
        profiles = HostAdaptationService._indexed(
            firewall.get("profiles") or [], "name"
        )
        for action in plan.actions:
            for name in action.profiles:
                observed = profiles.get(name) or {}
                if observed.get("enabled") is True and not action.enabled:
                    return True
                if observed.get("inbound") == "Block" and action.inbound == "Allow":
                    return True
                if observed.get("outbound") == "Block" and action.outbound == "Allow":
                    return True
        return False

    def apply_plan(
        self,
        plan: AdaptationPlan,
        *,
        approved: bool,
        approved_plan_id: str,
        authorization: str = "operator-confirmed",
        snapshot_provider: Callable[[AdaptationPlan, Mapping[str, Any]], str] | None = None,
        executor: Callable[[AdaptationPlan], Sequence[str]] | None = None,
        postcondition_provider: Callable[[], Mapping[str, Any]] | None = None,
        pre_execute_check: Callable[[AdaptationPlan, Mapping[str, Any]], None] | None = None,
    ) -> AdaptationReceipt:
        if not self._mutation_lock.acquire(blocking=False):
            raise AdaptationError("another adaptation or rollback transaction is active")
        try:
            return self._apply_plan_locked(
                plan,
                approved=approved,
                approved_plan_id=approved_plan_id,
                authorization=authorization,
                snapshot_provider=snapshot_provider,
                executor=executor,
                postcondition_provider=postcondition_provider,
                pre_execute_check=pre_execute_check,
            )
        finally:
            self._mutation_lock.release()

    def _apply_plan_locked(
        self,
        plan: AdaptationPlan,
        *,
        approved: bool,
        approved_plan_id: str,
        authorization: str = "operator-confirmed",
        snapshot_provider: Callable[[AdaptationPlan, Mapping[str, Any]], str] | None = None,
        executor: Callable[[AdaptationPlan], Sequence[str]] | None = None,
        postcondition_provider: Callable[[], Mapping[str, Any]] | None = None,
        pre_execute_check: Callable[[AdaptationPlan, Mapping[str, Any]], None] | None = None,
    ) -> AdaptationReceipt:
        self._verify_plan(plan)
        if not approved or approved_plan_id != plan.plan_id:
            raise PermissionError("approval is not bound to this exact adaptation plan")
        expires = datetime.fromisoformat(plan.expires_at).timestamp()
        if self._clock() >= expires:
            raise AdaptationError("adaptation plan expired; preview it again")
        if plan.host_id != self.host_id():
            raise AdaptationError("adaptation plan belongs to another host")
        if self._security_baseline() is None:
            raise AdaptationError(
                "an explicitly enrolled immutable firewall recovery baseline is "
                "required before the first profile change"
            )
        self._check_breaker(plan.drastic)
        current = self.capture_snapshot()
        if _digest(current.get("firewall") or {}) != plan.precondition_digest:
            raise AdaptationError("firewall state changed after preview; build a fresh plan")
        provider = snapshot_provider or self._capture_rollback_snapshot
        snapshot_id = provider(plan, current)
        if not snapshot_id:
            raise AdaptationError("rollback provider returned no snapshot identity")
        transaction = self._begin_transaction(
            "apply",
            snapshot_id=snapshot_id,
            authorization=authorization,
            before_firewall=current.get("firewall") or {},
            plan=plan,
        )
        transaction_id = str(transaction["transaction_id"])
        mutation_started = False
        try:
            if pre_execute_check is not None:
                pre_execute_check(plan, current)
            self._transition_transaction(transaction_id, "MUTATING")
            mutation_started = True
            commands = tuple(executor(plan)) if executor else self._execute_actions(plan)
            if not commands:
                raise AdaptationError("profile executor returned no completed actions")
            postcondition = (
                postcondition_provider() if postcondition_provider else self._firewall()
            )
            self._verify_profile_postconditions(plan, postcondition)
            self._transition_transaction(
                transaction_id,
                "VERIFIED",
                commands=list(commands),
                after_firewall_digest=_digest(postcondition),
            )
        except Exception as primary_exc:
            if not mutation_started:
                self._transition_transaction(
                    transaction_id, "ROLLED_BACK", error=_safe_text(primary_exc, 1000)
                )
                raise
            rollback_error: Exception | None = None
            if snapshot_provider is None:
                try:
                    self.rollback(snapshot_id, approved=True, authorization="automatic-failure-recovery")
                except Exception as rollback_exc:
                    rollback_error = rollback_exc
                    self.log_activity(
                        "rollback.failed", "error",
                        f"Automatic recovery after apply failure also failed: {rollback_exc}",
                    )
            else:
                rollback_error = AdaptationError(
                    "custom snapshot provider has no automatic rollback authority"
                )
            if rollback_error is not None:
                self._mark_transaction_needs_review(
                    transaction_id,
                    error=primary_exc,
                    rollback_error=rollback_error,
                )
                raise AdaptationError(
                    "profile apply failed and rollback also failed; adaptation is "
                    f"locked for recovery review: {rollback_error}"
                ) from primary_exc
            self._transition_transaction(
                transaction_id,
                "ROLLED_BACK",
                error=_safe_text(primary_exc, 1000),
            )
            raise
        body = {
            "plan_id": plan.plan_id,
            "profile_id": plan.profile_id,
            "applied_at": _utc_now(),
            "snapshot_id": snapshot_id,
            "authorization": _safe_text(authorization, 160),
            "commands": commands,
        }
        receipt = AdaptationReceipt(receipt_digest=_digest(body), **body)
        try:
            self._record_change(plan, transaction_id=transaction_id)
            self._transition_transaction(
                transaction_id,
                "COMMITTED",
                receipt_digest=receipt.receipt_digest,
            )
        except Exception as exc:
            # An unrecorded host mutation violates the transaction contract.
            # Production applies always own a real rollback artifact, so restore
            # it before surfacing the bookkeeping failure.
            if snapshot_provider is None:
                try:
                    self.rollback(
                        snapshot_id, approved=True,
                        authorization="automatic-receipt-failure-recovery",
                    )
                except Exception as rollback_exc:
                    self._mark_transaction_needs_review(
                        transaction_id,
                        error=exc,
                        rollback_error=rollback_exc,
                    )
                    raise AdaptationError(
                        "profile changed but receipt state failed, and automatic rollback "
                        f"also failed: {rollback_exc}"
                    ) from exc
                self._transition_transaction(
                    transaction_id,
                    "ROLLED_BACK",
                    error=_safe_text(exc, 1000),
                )
            raise AdaptationError(
                f"profile receipt could not be committed: {exc}"
            ) from exc
        self.log_activity(
            "profile.applied", "success",
            f"{plan.profile_id}; plan {plan.plan_id}; rollback {snapshot_id}; {authorization}",
        )
        return receipt

    def rollback(
        self,
        snapshot_id: str,
        *,
        approved: bool,
        authorization: str = "operator-confirmed",
        executor: Callable[[Path], bool] | None = None,
        postcondition_provider: Callable[[], Mapping[str, Any]] | None = None,
    ) -> bool:
        if not self._mutation_lock.acquire(blocking=False):
            raise AdaptationError("another adaptation or rollback transaction is active")
        try:
            return self._rollback_locked(
                snapshot_id, approved=approved,
                authorization=authorization, executor=executor,
                postcondition_provider=postcondition_provider,
            )
        finally:
            self._mutation_lock.release()

    def _rollback_locked(
        self,
        snapshot_id: str,
        *,
        approved: bool,
        authorization: str = "operator-confirmed",
        executor: Callable[[Path], bool] | None = None,
        postcondition_provider: Callable[[], Mapping[str, Any]] | None = None,
    ) -> bool:
        if not approved:
            raise PermissionError("explicit rollback approval is required")
        manifest_path = self._snapshot_path(snapshot_id, ".json")
        manifest = self._load_store(manifest_path, "rollback-snapshot", None)
        if not isinstance(manifest, dict) or manifest.get("host_id") != self.host_id():
            raise IntegrityError("rollback manifest is missing or belongs to another host")
        firewall_file = self._snapshot_path(snapshot_id, ".wfw")
        if not firewall_file.is_file():
            raise IntegrityError("rollback firewall artifact is missing")
        if not hmac.compare_digest(
            self._bounded_file_sha256(firewall_file),
            str(manifest.get("firewall_sha256") or ""),
        ):
            raise IntegrityError("rollback firewall artifact failed its digest check")
        before_firewall: Mapping[str, Any] = {}
        try:
            observed_before = self._firewall()
            if observed_before.get("supported") and observed_before.get("complete") is True:
                before_firewall = observed_before
        except Exception:
            pass
        transaction = self._begin_transaction(
            "rollback",
            snapshot_id=snapshot_id,
            authorization=authorization,
            before_firewall=before_firewall,
            target_firewall=manifest.get("firewall") or {},
        )
        transaction_id = str(transaction["transaction_id"])
        try:
            self._transition_transaction(transaction_id, "MUTATING")
            if executor is not None:
                ok = bool(executor(firewall_file))
            else:
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                completed = subprocess.run(
                    [self._netsh_path(), "advfirewall", "import", str(firewall_file)],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=30, check=False, creationflags=flags,
                    env=sanitized_child_environment(),
                )
                ok = completed.returncode == 0
                if not ok:
                    raise AdaptationError(
                        "Windows Firewall rollback failed: "
                        + _safe_text(completed.stderr or completed.stdout, 500)
                    )
            if not ok:
                raise AdaptationError("rollback broker reported failure")
            restored: Mapping[str, Any] | None = None
            if executor is None or postcondition_provider is not None:
                restored = (
                    postcondition_provider() if postcondition_provider else self._firewall()
                )
                self._verify_restore_postconditions(
                    manifest.get("firewall") or {}, restored
                )
            self._transition_transaction(
                transaction_id,
                "VERIFIED",
                after_firewall_digest=_digest(
                    restored if restored is not None else manifest.get("firewall") or {}
                ),
                verification=(
                    "fresh-postcondition" if restored is not None else "broker-only"
                ),
            )
            manifest["status"] = "restored"
            manifest["restored_at"] = _utc_now()
            manifest["restore_authorization"] = _safe_text(authorization, 160)
            self._save_store(manifest_path, "rollback-snapshot", manifest)
            with self._lock:
                state = self.state()
                state["active_profile_id"] = ""
                self._save_state(state)
            self._transition_transaction(transaction_id, "COMMITTED")
            # A successful exact rollback resolves earlier ambiguous mutations
            # that reference this recovery point. The breaker stays locked
            # until the operator reviews and explicitly resets it.
            for record in self.transactions():
                if (
                    record.get("transaction_id") != transaction_id
                    and record.get("status") == "NEEDS_REVIEW"
                    and record.get("snapshot_id") == snapshot_id
                ):
                    self._transition_transaction(
                        str(record.get("transaction_id")),
                        "ROLLED_BACK",
                        error="operator completed the exact authenticated rollback",
                    )
        except Exception as exc:
            try:
                self._mark_transaction_needs_review(
                    transaction_id, error=exc
                )
            except Exception:
                self._lock_breaker_for_review(str(exc), transaction_id)
            raise
        self.log_activity("profile.rolled_back", "success", f"{snapshot_id}; {authorization}")
        return True

    @staticmethod
    def _verify_restore_postconditions(
        expected: Mapping[str, Any], restored: Mapping[str, Any]
    ) -> None:
        """Require the canonical effective firewall policy to match the snapshot."""
        for label, document in (("snapshot", expected), ("restored", restored)):
            if not document.get("supported") or document.get("complete") is False:
                raise AdaptationError(
                    document.get("reason")
                    or f"{label} Windows Firewall state is incomplete"
                )

        def canonical(document: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
            # Compare the full normalized effective policy. Rule identity alone
            # is insufficient: changing a program, service, port, address,
            # protocol, interface, edge, or IPsec filter can radically widen
            # an allow rule without changing its name.
            profiles = tuple(sorted(
                json.dumps(
                    dict(row), sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True, default=str,
                )
                for row in document.get("profiles") or []
                if isinstance(row, Mapping)
            ))
            rules = tuple(sorted(
                json.dumps(
                    dict(row), sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True, default=str,
                )
                for row in document.get("rules") or []
                if isinstance(row, Mapping)
            ))
            return {"profiles": profiles, "rules": rules}

        expected_state = canonical(expected)
        restored_state = canonical(restored)
        mismatches = [
            name for name in ("profiles", "rules")
            if expected_state[name] != restored_state[name]
        ]
        if mismatches:
            raise AdaptationError(
                "Firewall rollback postcondition mismatch: " + ", ".join(mismatches)
            )

    def restore_security_baseline(
        self,
        *,
        approved: bool,
        authorization: str = "operator-confirmed-security-baseline",
        executor: Callable[[Path], bool] | None = None,
        postcondition_provider: Callable[[], Mapping[str, Any]] | None = None,
        snapshot_provider: Callable[[AdaptationPlan, Mapping[str, Any]], str] | None = None,
    ) -> dict[str, Any]:
        """Restore the immutable firewall baseline with a pre-restore recovery point."""
        if not approved:
            raise PermissionError("explicit host security-baseline restore approval is required")
        if not self._mutation_lock.acquire(blocking=False):
            raise AdaptationError("another adaptation or rollback transaction is active")
        try:
            manifest = self._security_baseline()
            if manifest is None:
                raise AdaptationError("no restorable host security baseline is available")
            current = self.capture_snapshot()
            plan = self.build_plan("balanced", current)
            pre_restore_snapshot_id = (
                snapshot_provider(plan, current)
                if snapshot_provider is not None
                else self._capture_rollback_snapshot(
                    plan, current, purpose="pre-security-baseline-restore"
                )
            )
            if not pre_restore_snapshot_id:
                raise AdaptationError("pre-restore snapshot provider returned no identity")
            artifact = self.security_baseline_firewall_path
            transaction = self._begin_transaction(
                "security-baseline-restore",
                snapshot_id=pre_restore_snapshot_id,
                authorization=authorization,
                before_firewall=current.get("firewall") or {},
                plan=plan,
                target_firewall=manifest.get("firewall") or {},
            )
            transaction_id = str(transaction["transaction_id"])
            mutation_started = False
            try:
                self._transition_transaction(transaction_id, "MUTATING")
                mutation_started = True
                if executor is not None:
                    restored_ok = bool(executor(artifact))
                else:
                    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    completed = subprocess.run(
                        [self._netsh_path(), "advfirewall", "import", str(artifact)],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=30,
                        check=False,
                        creationflags=flags,
                        env=sanitized_child_environment(),
                    )
                    restored_ok = completed.returncode == 0
                    if not restored_ok:
                        raise AdaptationError(
                            "Windows Firewall security-baseline restore failed: "
                            + _safe_text(completed.stderr or completed.stdout, 500)
                        )
                if not restored_ok:
                    raise AdaptationError("security-baseline restore broker reported failure")
                restored = (
                    postcondition_provider()
                    if postcondition_provider is not None
                    else self._firewall()
                )
                self._verify_restore_postconditions(
                    manifest.get("firewall") or {}, restored
                )
                self._transition_transaction(
                    transaction_id,
                    "VERIFIED",
                    after_firewall_digest=_digest(restored),
                )
            except Exception as primary_exc:
                if not mutation_started:
                    self._transition_transaction(
                        transaction_id,
                        "ROLLED_BACK",
                        error=_safe_text(primary_exc, 1000),
                    )
                    raise
                rollback_error: Exception | None = None
                if snapshot_provider is None:
                    try:
                        self._rollback_locked(
                            pre_restore_snapshot_id,
                            approved=True,
                            authorization="automatic-baseline-restore-failure-recovery",
                        )
                    except Exception as rollback_exc:
                        rollback_error = rollback_exc
                        self.log_activity(
                            "security_baseline.restore_rollback_failed",
                            "critical",
                            str(rollback_exc),
                        )
                else:
                    rollback_error = AdaptationError(
                        "custom snapshot provider has no automatic rollback authority"
                    )
                if rollback_error is not None:
                    self._mark_transaction_needs_review(
                        transaction_id,
                        error=primary_exc,
                        rollback_error=rollback_error,
                    )
                    raise AdaptationError(
                        "security-baseline restore failed and rollback also failed; "
                        f"adaptation is locked for recovery review: {rollback_error}"
                    ) from primary_exc
                self._transition_transaction(
                    transaction_id,
                    "ROLLED_BACK",
                    error=_safe_text(primary_exc, 1000),
                )
                raise
            with self._lock:
                state = self.state()
                state["active_profile_id"] = ""
                self._save_state(state)
            self._transition_transaction(transaction_id, "COMMITTED")
            restored_at = _utc_now()
            self.log_activity(
                "security_baseline.restored",
                "success",
                f"{manifest.get('baseline_id')}; pre-restore={pre_restore_snapshot_id}; "
                f"{_safe_text(authorization, 160)}",
            )
            return {
                "baseline_id": manifest.get("baseline_id"),
                "restored_at": restored_at,
                "pre_restore_snapshot_id": pre_restore_snapshot_id,
                "restored_components": list(
                    manifest.get("restorable_components") or ()
                ),
            }
        finally:
            self._mutation_lock.release()

    # ── Context triggers and autonomous feedback loop ──────────────────────
    def set_automation(self, enabled: bool, auto_apply: bool = False) -> None:
        with self._lock:
            state = self.state()
            state["automation_enabled"] = bool(enabled)
            # Context signals such as SSID/VPN/category are not authenticated
            # liveness proofs. They may propose an exact profile, but may not
            # mutate a firewall unattended or risk severing remote management.
            state["auto_apply"] = False
            state["last_trigger_signature"] = ""
            self._save_state(state)
        self.log_activity(
            "automation.configured", "review" if auto_apply else "success",
            f"enabled={bool(enabled)} auto_apply=False"
            + ("; unattended apply request refused" if auto_apply else ""),
        )

    def add_trigger(self, kind: str, value: str, profile_id: str) -> dict[str, Any]:
        kind = kind.strip().casefold()
        value = _safe_text(value, 160).strip()
        if kind not in {"public_network", "vpn_active", "ssid"}:
            raise ValueError("unsupported context trigger")
        if kind == "ssid" and not value:
            raise ValueError("an SSID trigger requires an exact network name")
        if kind != "ssid":
            value = "true"
        if profile_id not in PROFILES:
            raise ValueError("unknown adaptation profile")
        identity = hashlib.sha256(f"{kind}|{value}|{profile_id}".encode()).hexdigest()[:20]
        rule = {
            "id": f"trigger-{identity}", "kind": kind, "value": value,
            "profile_id": profile_id, "created_at": _utc_now(), "enabled": True,
        }
        with self._lock:
            state = self.state()
            rules = [item for item in state["triggers"] if item.get("id") != rule["id"]]
            rules.append(rule)
            state["triggers"] = rules[-MAX_TRIGGERS:]
            self._save_state(state)
        self.log_activity("trigger.added", "success", f"{kind} -> {profile_id}")
        return rule

    def remove_trigger(self, rule_id: str) -> bool:
        with self._lock:
            state = self.state()
            rules = list(state["triggers"])
            state["triggers"] = [item for item in rules if item.get("id") != rule_id]
            if len(state["triggers"]) == len(rules):
                return False
            self._save_state(state)
        self.log_activity("trigger.removed", "success", rule_id)
        return True

    @staticmethod
    def _trigger_matches(rule: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
        if not rule.get("enabled", True):
            return False
        kind = rule.get("kind")
        if kind == "public_network":
            return context.get("network_category") == "Public"
        if kind == "vpn_active":
            return context.get("vpn_active") is True
        if kind == "ssid":
            return bool(context.get("ssid")) and context.get("ssid") == rule.get("value")
        return False

    def evaluate_context(self, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        current = dict(self.capture_context() if context is None else context)
        state = self.state()
        return self._evaluate_context_with_state(current, state)

    def _evaluate_context_with_state(
        self, current: Mapping[str, Any], state: Mapping[str, Any]
    ) -> dict[str, Any]:
        matches = [
            dict(rule) for rule in state["triggers"]
            if self._trigger_matches(rule, current)
        ]
        # Never let a more specific but weaker SSID rule override a restrictive
        # public/VPN rule.  On equal posture, Public category wins while the host
        # is public; otherwise an exact SSID remains the useful tie-breaker.
        priority = (
            {"public_network": 0, "ssid": 1, "vpn_active": 2}
            if current.get("network_category") == "Public"
            else {"ssid": 0, "vpn_active": 1, "public_network": 2}
        )
        matches.sort(key=lambda row: (
            -PROFILE_STRENGTH.get(str(row.get("profile_id")), 0),
            priority.get(str(row.get("kind")), 9),
            str(row.get("created_at", "")),
            str(row.get("id", "")),
        ))
        signature = _digest({
            "ssid": current.get("ssid", ""),
            "network_category": current.get("network_category", "Unknown"),
            "vpn_active": bool(current.get("vpn_active")),
            "match": matches[0].get("id") if matches else "",
        })
        return {"context": current, "matches": matches, "signature": signature}

    def _validate_automatic_authorization(
        self,
        rule_id: str,
        profile_id: str,
        expected_signature: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = dict(self.capture_context() if context is None else context)
        if isinstance(current.get("collector"), Mapping) and not current[
            "collector"
        ].get("complete", False):
            raise AutomationAuthorizationChanged(
                "network context collector is incomplete"
            )
        if current.get("remote_session") is True:
            raise AutomationAuthorizationChanged(
                "automatic firewall mutation is blocked during a remote operator session"
            )
        with self._lock:
            state = self.state()
            if not state.get("automation_enabled") or not state.get("auto_apply"):
                raise AutomationAuthorizationChanged(
                    "automatic apply was disabled before mutation"
                )
            evaluation = self._evaluate_context_with_state(current, state)
            matches = evaluation["matches"]
            if (
                evaluation["signature"] != expected_signature
                or not matches
                or matches[0].get("id") != rule_id
                or matches[0].get("profile_id") != profile_id
            ):
                raise AutomationAuthorizationChanged(
                    "context trigger changed before mutation"
                )
            return evaluation

    def run_automatic_cycle(self) -> dict[str, Any]:
        with self._lock:
            state = self.state()
            if not state.get("automation_enabled"):
                return {"status": "disabled"}
        context = self.capture_context()
        with self._lock:
            state = self.state()
            if not state.get("automation_enabled"):
                return {"status": "disabled"}
            evaluation = self._evaluate_context_with_state(context, state)
            revision = int(state.get("revision", 0))
        if isinstance(context.get("collector"), Mapping) and not context[
            "collector"
        ].get("complete", False):
            return {"status": "context-incomplete", **evaluation}
        matches = evaluation["matches"]
        if not matches:
            # A no-match is a real context transition. Clear the proposal
            # de-duplication marker so returning to the prior SSID/category/VPN
            # can propose again. Keep the separately tracked last-applied
            # signature intact so automation never fights an operator by
            # repeatedly reapplying an already-applied posture.
            if state.get("last_trigger_signature"):
                if self._update_state(
                    {"last_trigger_signature": ""},
                    expected_revision=revision,
                ) is None:
                    return {"status": "configuration-changed", **evaluation}
            return {"status": "no-match", **evaluation}
        rule = matches[0]
        signature = evaluation["signature"]
        if signature == state.get("last_trigger_signature"):
            return {"status": "stable", **evaluation}
        updated = self._update_state(
            {"last_trigger_signature": signature}, expected_revision=revision
        )
        if updated is None:
            return {"status": "configuration-changed", **evaluation}
        state = updated
        if not state.get("auto_apply"):
            self.log_activity(
                "trigger.proposed", "review",
                f"{rule.get('kind')} matched; proposed {rule.get('profile_id')}",
            )
            return {"status": "proposed", "rule": rule, **evaluation}
        if signature == state.get("last_applied_context_signature"):
            return {"status": "already-applied", "rule": rule, **evaluation}
        snapshot = self.capture_snapshot()
        # Bind automation to the context in the same snapshot as the plan. An
        # SSID/VPN/category can change while deeper collection runs; stale
        # context must never authorize a later firewall mutation.
        try:
            fresh = self._validate_automatic_authorization(
                str(rule.get("id")), str(rule.get("profile_id")), signature,
                context=snapshot.get("network") or {},
            )
        except AutomationAuthorizationChanged:
            self._update_state({"last_trigger_signature": ""})
            self.log_activity(
                "trigger.context_changed", "blocked",
                "Context changed while the adaptation plan was being prepared.",
            )
            return {"status": "context-changed", "rule": rule, **evaluation}
        plan = self.build_plan(str(rule["profile_id"]), snapshot)
        if plan.drastic:
            self.log_activity(
                "trigger.drastic_refused", "review",
                "Emergency Lockdown requires a fresh exact-plan operator confirmation.",
            )
            return {"status": "manual-review", "rule": rule, **fresh}
        if self._plan_relaxes_current(plan, snapshot.get("firewall") or {}):
            self.log_activity(
                "trigger.relaxation_refused", "review",
                "Automatic adaptation would relax the current firewall posture.",
            )
            return {"status": "manual-review", "rule": rule, **fresh}

        def final_guard(
            guarded_plan: AdaptationPlan, current: Mapping[str, Any]
        ) -> None:
            self._validate_automatic_authorization(
                str(rule.get("id")), str(rule.get("profile_id")), signature
            )
            if self._plan_relaxes_current(
                guarded_plan, current.get("firewall") or {}
            ):
                raise AutomationAuthorizationChanged(
                    "automatic apply would relax the current firewall posture"
                )

        try:
            receipt = self.apply_plan(
                plan, approved=True, approved_plan_id=plan.plan_id,
                authorization=f"pre-authorized-trigger:{rule['id']}",
                pre_execute_check=final_guard,
            )
        except AutomationAuthorizationChanged as exc:
            self._update_state({"last_trigger_signature": ""})
            self.log_activity("trigger.authorization_changed", "blocked", str(exc))
            return {"status": "configuration-changed", "rule": rule, **evaluation}
        self._update_state({"last_applied_context_signature": signature})
        return {"status": "applied", "rule": rule, "receipt": asdict(receipt), **evaluation}

    # ── Activity feedback ──────────────────────────────────────────────────
    def log_activity(self, action: str, result: str, detail: str) -> None:
        entry = {
            "at": _utc_now(), "action": _safe_text(action, 100),
            "result": _safe_text(result, 40), "detail": _safe_text(detail, 1_000),
        }
        try:
            with self._lock:
                rows = self._load_store(self.activity_path, "activity", [])
                if not isinstance(rows, list):
                    rows = []
                rows.append(entry)
                self._save_store(self.activity_path, "activity", rows[-MAX_ACTIVITY:])
        except Exception:
            # Adaptation safety must never depend on presentation/audit logging.
            pass

    def activity(self) -> list[dict[str, Any]]:
        rows = self._load_store(self.activity_path, "activity", [])
        return list(reversed(rows)) if isinstance(rows, list) else []


def self_test() -> tuple[bool, str]:
    """Dependency-light sanity check used by Angerona's module self-test sweep."""
    try:
        with tempfile.TemporaryDirectory(prefix="angerona-adaptation-") as folder:
            service = HostAdaptationService(folder)
            finding = {
                "id": "demo", "category": "ports", "key": "tcp|wildcard|9000|demo",
            }
            service.add_exception(finding, "known local development listener")
            assert service.list_exceptions()[0]["category"] == "ports"
            rule = service.add_trigger("vpn_active", "", "public")
            result = service.evaluate_context({
                "ssid": "", "network_category": "Private", "vpn_active": True,
            })
            assert result["matches"][0]["id"] == rule["id"]
        return True, "OK - integrity stores, exceptions, and context matching are healthy."
    except Exception as exc:
        return False, f"ERROR - {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[host_adaptation] self_test: {'PASS' if ok else 'FAIL'} - {detail}")
    raise SystemExit(0 if ok else 1)
