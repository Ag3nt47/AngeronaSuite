"""core/remediation_log.py — persistent, queryable audit ledger for every
remediation action Angerona takes or considers.

Stored in the same SQLite database as the FlightRecorder
(``flight-recorder.db``) under a separate ``remediation_log`` table so that
the full action history survives restarts and can be queried alongside events.

Schema (one row per action slot per call to apply_remediation):
  id           INTEGER PK AUTOINCREMENT
  ts           REAL     — Unix epoch of the decision
  trigger      TEXT     — module or context that triggered the call
                          (e.g. "PostureHardening", "console", "selftest")
  mitre        TEXT     — MITRE technique ID (T1003, etc.) or "-"
  action_key   TEXT     — e.g. "quarantine_file", "registry_hardening", or
                          "none" if no vetted action matched
  action_title TEXT     — human-readable title of the action
  outcome      TEXT     — one of: applied / skipped / dry_run / error / rolled_back
  verified     INTEGER  — 1 = post-apply verify passed, 0 = failed, -1 = not run
  host_level   INTEGER  — 1 if the action modifies OS state (registry/service/FW)
  record_json  TEXT     — full dict returned by action.apply() or the plan entry

Design notes
  * Written from any thread (remediation may run in a module daemon thread).
  * Read-only ``recent()`` / ``by_mitre()`` / ``stats()`` queries are safe to
    call from the GUI thread (short-lived lock).
  * Capped at MAX_ROWS (newest kept) — amortised trim every PRUNE_EVERY inserts,
    matching FlightRecorder discipline.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
import weakref
from pathlib import Path
from typing import List

from angerona.core.remediation_receipts import (
    GENESIS_HASH,
    create_receipt,
    verify_receipt,
)

MAX_ROWS = 10_000
PRUNE_EVERY = 500
MAX_TRANSACTION_RECORD_BYTES = 64 * 1024
MAX_TRANSACTION_FIELD_CHARS = 256
TRANSACTION_STATES = frozenset(
    {"PREPARED", "MUTATING", "APPLIED", "ROLLED_BACK", "RECOVERY_REQUIRED"}
)
UNRESOLVED_TRANSACTION_STATES = frozenset(
    {"PREPARED", "MUTATING", "RECOVERY_REQUIRED"}
)
_OWNER_CAPABILITY_BYTES = 32
_OWNER_CAPABILITY_DOMAIN = b"angerona-remediation-owner-v1\0"
_RECOVERY_CAPABILITY_BYTES = 32
_RECOVERY_CAPABILITY_DOMAIN = b"angerona-remediation-recovery-v1\0"
_RECOVERY_COORDINATOR_BYTES = 32
_RECOVERY_COORDINATOR_DOMAIN = b"angerona-remediation-coordinator-v1\0"
_RECOVERY_COORDINATOR_MINT = object()
_RECOVERY_PROOF_MINT = object()

_ORDINARY_TERMINAL_RESULTS = {
    "applied": ("APPLIED", "applied", 1),
    "apply_failed_no_change": ("ROLLED_BACK", "apply_failed", 0),
    "rolled_back": ("ROLLED_BACK", "rolled_back", 0),
    "recovery_required": ("RECOVERY_REQUIRED", "recovery_required", 0),
    "rollback_failed": ("RECOVERY_REQUIRED", "rollback_failed", 0),
}
_RECOVERY_TERMINAL_RESULTS = {
    "reconciled_applied": ("APPLIED", "reconciled_applied", 1),
    "reconciled_rolled_back": ("ROLLED_BACK", "reconciled_rolled_back", 1),
}

_SINGLETON: "RemediationLog | None" = None
_INIT_LOCK = threading.Lock()


class RemediationCircuitOpen(RuntimeError):
    """Raised when durable unresolved state forbids a new mutation."""

    circuit_open = True

    def __init__(self, rows: list[tuple[int, str]]) -> None:
        self.transaction_ids = tuple(int(row[0]) for row in rows)
        self.states = tuple(str(row[1]) for row in rows)
        detail = ", ".join(
            f"{transaction_id}:{state}"
            for transaction_id, state in zip(self.transaction_ids, self.states)
        )
        super().__init__(f"durable remediation circuit is active ({detail})")


class RemediationCustodyError(RuntimeError):
    """The SQLite pathname no longer proves one local, single-link object."""


class TransactionOwnerCapability:
    """Opaque in-memory authority for one ordinary transaction state graph.

    The random secret is never serialised, logged, or returned by inspection
    APIs. Only its domain-separated SHA-256 digest is retained while the
    transaction is live. Terminal transitions retire the in-memory secret.
    """

    __slots__ = ("_retired", "_secret", "_transaction_id")

    def __init__(self, transaction_id: int, secret: bytes) -> None:
        if len(secret) != _OWNER_CAPABILITY_BYTES:
            raise ValueError("invalid remediation transaction owner capability")
        self._transaction_id = int(transaction_id)
        self._secret = bytearray(secret)
        self._retired = False

    @property
    def transaction_id(self) -> int:
        """Public journal identity; this does not expose transition authority."""
        return self._transaction_id

    def _proof(self) -> tuple[int, str]:
        if self._retired:
            raise RuntimeError("remediation transaction owner capability is unavailable")
        digest = hashlib.sha256(
            _OWNER_CAPABILITY_DOMAIN + bytes(self._secret)
        ).hexdigest()
        return self._transaction_id, digest

    def _retire(self) -> None:
        for index in range(len(self._secret)):
            self._secret[index] = 0
        self._retired = True

    def __repr__(self) -> str:
        return (
            "TransactionOwnerCapability("
            f"transaction_id={self._transaction_id}, secret=<redacted>)"
        )

    def __reduce__(self):
        raise TypeError("remediation transaction owner capabilities cannot be serialized")


class RecoveryCapability:
    """One-use, in-memory authority for an exact reconciliation claim.

    SQLite retains only a digest bound to the transaction identity and the
    retained-record digest.  The secret is never included in inspection data,
    logs, records, or a serializable representation.
    """

    __slots__ = ("_retired", "_secret", "_transaction_id")

    def __init__(self, transaction_id: int, secret: bytes) -> None:
        if type(secret) is not bytes or len(secret) != _RECOVERY_CAPABILITY_BYTES:
            raise ValueError("invalid remediation recovery capability")
        self._transaction_id = int(transaction_id)
        self._secret = bytearray(secret)
        self._retired = False

    @property
    def transaction_id(self) -> int:
        """Public journal identity; this does not expose finish authority."""
        return self._transaction_id

    def _proof(self, record_sha256: str) -> tuple[int, str]:
        if self._retired:
            raise RuntimeError("remediation recovery capability is unavailable")
        try:
            record_digest = bytes.fromhex(record_sha256)
        except ValueError as exc:
            raise RuntimeError("remediation recovery record binding is invalid") from exc
        if len(record_digest) != hashlib.sha256().digest_size:
            raise RuntimeError("remediation recovery record binding is invalid")
        transaction_binding = self._transaction_id.to_bytes(8, "big", signed=False)
        digest = hashlib.sha256(
            _RECOVERY_CAPABILITY_DOMAIN
            + transaction_binding
            + record_digest
            + bytes(self._secret)
        ).hexdigest()
        return self._transaction_id, digest

    def _retire(self) -> None:
        for index in range(len(self._secret)):
            self._secret[index] = 0
        self._retired = True

    def __repr__(self) -> str:
        return (
            "RecoveryCapability("
            f"transaction_id={self._transaction_id}, secret=<redacted>)"
        )

    def __copy__(self):
        raise TypeError("remediation recovery capabilities cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("remediation recovery capabilities cannot be copied")

    def __reduce__(self):
        raise TypeError("remediation recovery capabilities cannot be serialized")


class _RecoveryCoordinatorCapability:
    """Process-local authority for one exact store and action registry.

    This is deliberately private.  It is minted once by a ``RemediationLog``
    for the reviewed coordinator in ``remediation_actions`` and is never
    returned by a public inspection or recovery API.  Arbitrary introspective
    Python already executing inside Angerona's process is outside this
    in-process boundary; isolating hostile extensions requires a helper-process
    authority boundary.
    """

    __slots__ = ("_registry", "_registry_binding", "_secret", "_store_ref")

    def __init__(self, mint, store: "RemediationLog", registry: tuple[object, ...]):
        if mint is not _RECOVERY_COORDINATOR_MINT:
            raise TypeError("recovery coordinator capabilities are internally minted")
        if type(registry) is not tuple or not registry:
            raise ValueError("an exact non-empty recovery action registry is required")
        secret = secrets.token_bytes(_RECOVERY_COORDINATOR_BYTES)
        if type(secret) is not bytes or len(secret) != _RECOVERY_COORDINATOR_BYTES:
            raise RuntimeError("secure remediation coordinator capability failed")
        binding = []
        seen_keys: set[str] = set()
        seen_objects: set[int] = set()
        for action in registry:
            action_id = id(action)
            action_key = _bounded_transaction_field(
                getattr(action, "key", ""), "recovery action key"
            )
            if action_id in seen_objects or action_key in seen_keys:
                raise ValueError("recovery action registry must have exact unique entries")
            seen_objects.add(action_id)
            seen_keys.add(action_key)
            binding.append((action_id, action_key, bool(getattr(action, "reversible", False))))
        self._store_ref = weakref.ref(store)
        self._registry = registry
        self._registry_binding = tuple(binding)
        self._secret = bytearray(secret)

    def _require_store(self, store: "RemediationLog") -> None:
        if self._store_ref() is not store:
            raise RuntimeError("recovery coordinator is bound to a different store")
        for action, (action_id, action_key, reversible) in zip(
            self._registry, self._registry_binding
        ):
            if (
                id(action) != action_id
                or str(getattr(action, "key", "")) != action_key
                or bool(getattr(action, "reversible", False)) is not reversible
            ):
                raise RuntimeError("recovery action registry changed after binding")

    def _action_binding(self, action: object) -> tuple[str, bool]:
        for candidate, (_, action_key, reversible) in zip(
            self._registry, self._registry_binding
        ):
            if candidate is action:
                return action_key, reversible
        raise RuntimeError("recovery action is outside the bound registry")

    def _digest(self) -> str:
        store = self._store_ref()
        if store is None:
            raise RuntimeError("recovery coordinator store is unavailable")
        registry_bytes = json.dumps(
            self._registry_binding, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(
            _RECOVERY_COORDINATOR_DOMAIN
            + id(store).to_bytes(16, "big", signed=False)
            + registry_bytes
            + bytes(self._secret)
        ).hexdigest()

    def __repr__(self) -> str:
        return "_RecoveryCoordinatorCapability(store=<bound>, secret=<redacted>)"

    def __copy__(self):
        raise TypeError("recovery coordinator capabilities cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("recovery coordinator capabilities cannot be copied")

    def __reduce__(self):
        raise TypeError("recovery coordinator capabilities cannot be serialized")


class _VerifiedRecoveryProof:
    """Immutable-in-use witness issued only after the coordinator verifies state."""

    __slots__ = (
        "_action_key",
        "_coordinator_digest",
        "_encoded_record",
        "_record_sha256",
        "_result",
        "_retired",
        "_transaction_id",
    )

    def __init__(
        self,
        mint,
        *,
        coordinator_digest: str,
        transaction_id: int,
        action_key: str,
        record_sha256: str,
        result: str,
        encoded_record: str,
    ) -> None:
        if mint is not _RECOVERY_PROOF_MINT:
            raise TypeError("verified recovery proofs are internally minted")
        self._coordinator_digest = str(coordinator_digest)
        self._transaction_id = int(transaction_id)
        self._action_key = str(action_key)
        self._record_sha256 = str(record_sha256)
        self._result = str(result)
        self._encoded_record = str(encoded_record)
        self._retired = False

    def _retire(self) -> None:
        self._retired = True

    def __repr__(self) -> str:
        return (
            "_VerifiedRecoveryProof("
            f"transaction_id={self._transaction_id}, proof=<redacted>)"
        )

    def __copy__(self):
        raise TypeError("verified recovery proofs cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("verified recovery proofs cannot be copied")

    def __reduce__(self):
        raise TypeError("verified recovery proofs cannot be serialized")


def _canonical_db_path(db_path: Path) -> Path:
    requested = Path(os.path.abspath(Path(db_path).expanduser()))
    resolved = requested.resolve(strict=False)
    if os.path.normcase(str(requested)) != os.path.normcase(str(resolved)):
        raise RemediationCustodyError(
            "remediation database path traverses a link or reparse point"
        )
    _require_local_disk(resolved)
    return resolved


def _require_local_disk(path: Path) -> None:
    if os.name != "nt":
        return
    anchor = path.anchor
    if not anchor or anchor.startswith("\\\\"):
        raise RemediationCustodyError("remediation database must use a local disk")
    try:
        import ctypes

        drive_type = int(ctypes.windll.kernel32.GetDriveTypeW(str(anchor)))
    except Exception as exc:
        raise RemediationCustodyError(
            "remediation database drive type could not be proven"
        ) from exc
    if drive_type != 3:  # DRIVE_FIXED
        raise RemediationCustodyError("remediation database must use a fixed local disk")


def _safe_object_identity(
    path: Path, *, directory: bool = False, single_link: bool = False
) -> tuple[int, int]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise RemediationCustodyError(
            f"remediation custody object is unavailable: {path.name}"
        ) from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or attributes & 0x400:
        raise RemediationCustodyError(
            f"remediation custody object is a link/reparse point: {path.name}"
        )
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise RemediationCustodyError("remediation database parent is not a directory")
    elif not stat.S_ISREG(info.st_mode):
        raise RemediationCustodyError("remediation database object is not a regular file")
    if single_link and int(info.st_nlink) != 1:
        raise RemediationCustodyError(
            "remediation database custody requires exactly one filesystem link"
        )
    return int(info.st_dev), int(info.st_ino)


def init_log(db_path: Path) -> "RemediationLog":
    """Create (or return) the process-wide singleton, bound to *db_path*."""
    global _SINGLETON
    requested = _canonical_db_path(db_path)
    with _INIT_LOCK:
        if _SINGLETON is None:
            _SINGLETON = RemediationLog(requested)
        elif _SINGLETON._path != requested:
            raise RuntimeError(
                "remediation log is already bound to a different canonical database"
            )
    return _SINGLETON


def get_log() -> "RemediationLog | None":
    """Return the singleton, or None if ``init_log`` has not been called yet."""
    return _SINGLETON


class RemediationLog:
    """SQLite-backed audit ledger for vetted remediation actions."""

    def __init__(self, db_path: Path) -> None:
        self._path = _canonical_db_path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._parent_identity = _safe_object_identity(self._path.parent, directory=True)
        before_identity = None
        if self._path.exists():
            before_identity = _safe_object_identity(self._path, single_link=True)
        self._db = sqlite3.connect(str(self._path), check_same_thread=False)
        try:
            self._db_identity = _safe_object_identity(self._path, single_link=True)
            if before_identity is not None and before_identity != self._db_identity:
                raise RemediationCustodyError(
                    "remediation database object changed while it was opened"
                )
        except Exception:
            self._db.close()
            raise
        self._lock = threading.Lock()
        self._writes = 0
        self._recovery_coordinator: _RecoveryCoordinatorCapability | None = None
        self._recovery_coordinator_digest = ""
        self._recovery_proofs: dict[int, _VerifiedRecoveryProof] = {}
        self._init_schema()

    def _assert_db_custody_locked(self) -> None:
        if _canonical_db_path(self._path) != self._path:
            raise RemediationCustodyError("remediation database canonical path changed")
        if _safe_object_identity(self._path.parent, directory=True) != self._parent_identity:
            raise RemediationCustodyError("remediation database parent identity changed")
        if _safe_object_identity(self._path, single_link=True) != self._db_identity:
            raise RemediationCustodyError("remediation database object identity changed")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{self._path}{suffix}")
            try:
                os.lstat(sidecar)
            except FileNotFoundError:
                continue
            _safe_object_identity(sidecar, single_link=True)

    # ── schema ───────────────────────────────────────────────────────────────
    def _init_schema(self) -> None:
        with self._lock:
            self._assert_db_custody_locked()
            self._db.execute("PRAGMA journal_mode=WAL")
            # Transaction custody is a safety boundary, not telemetry.  FULL
            # makes a successful SQLite commit wait for the journal/WAL fsync.
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA busy_timeout=3000")
            synchronous = self._db.execute("PRAGMA synchronous").fetchone()
            if not synchronous or int(synchronous[0]) < 2:
                raise RuntimeError("remediation transaction journal is not fsync-backed")
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_log (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts           REAL    NOT NULL,
                    trigger      TEXT    NOT NULL DEFAULT '',
                    mitre        TEXT    NOT NULL DEFAULT '-',
                    action_key   TEXT    NOT NULL DEFAULT 'none',
                    action_title TEXT    NOT NULL DEFAULT '',
                    outcome      TEXT    NOT NULL DEFAULT 'dry_run',
                    verified     INTEGER NOT NULL DEFAULT -1,
                    host_level   INTEGER NOT NULL DEFAULT 0,
                    record_json  TEXT,
                    receipt_json TEXT,
                    receipt_hash TEXT
                )
                """
            )
            columns = {
                str(row[1])
                for row in self._db.execute(
                    "PRAGMA table_info(remediation_log)"
                ).fetchall()
            }
            if "receipt_json" not in columns:
                self._db.execute(
                    "ALTER TABLE remediation_log ADD COLUMN receipt_json TEXT"
                )
            if "receipt_hash" not in columns:
                self._db.execute(
                    "ALTER TABLE remediation_log ADD COLUMN receipt_hash TEXT"
                )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_remlog_ts    ON remediation_log(ts)"
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_remlog_mitre ON remediation_log(mitre)"
            )
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_remlog_receipt_hash "
                "ON remediation_log(receipt_hash) WHERE receipt_hash IS NOT NULL"
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_transactions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_ts  REAL    NOT NULL,
                    updated_ts  REAL    NOT NULL,
                    trigger     TEXT    NOT NULL CHECK(length(trigger) <= 256),
                    mitre       TEXT    NOT NULL CHECK(length(mitre) <= 256),
                    action_key  TEXT    NOT NULL CHECK(length(action_key) <= 256),
                    action_title TEXT   NOT NULL CHECK(length(action_title) <= 256),
                    host_level  INTEGER NOT NULL CHECK(host_level IN (0, 1)),
                    state       TEXT    NOT NULL CHECK(state IN (
                        'PREPARED', 'MUTATING', 'APPLIED', 'ROLLED_BACK',
                        'RECOVERY_REQUIRED'
                    )),
                    owner_capability_sha256 TEXT CHECK(
                        owner_capability_sha256 IS NULL OR
                        length(owner_capability_sha256) = 64
                    ),
                    record_json TEXT    NOT NULL CHECK(length(record_json) <= 65536)
                )
                """
            )
            transaction_columns = {
                str(row[1])
                for row in self._db.execute(
                    "PRAGMA table_info(remediation_transactions)"
                ).fetchall()
            }
            if "owner_capability_sha256" not in transaction_columns:
                # Existing terminal rows need no owner. Existing unresolved
                # rows remain conservatively locked because no capability can
                # be reconstructed after restart.
                self._db.execute(
                    "ALTER TABLE remediation_transactions "
                    "ADD COLUMN owner_capability_sha256 TEXT "
                    "CHECK(owner_capability_sha256 IS NULL OR "
                    "length(owner_capability_sha256) = 64)"
                )
            if "action_title" not in transaction_columns:
                self._db.execute(
                    "ALTER TABLE remediation_transactions "
                    "ADD COLUMN action_title TEXT NOT NULL DEFAULT '' "
                    "CHECK(length(action_title) <= 256)"
                )
            if "host_level" not in transaction_columns:
                self._db.execute(
                    "ALTER TABLE remediation_transactions "
                    "ADD COLUMN host_level INTEGER NOT NULL DEFAULT 0 "
                    "CHECK(host_level IN (0, 1))"
                )
            self._db.execute(
                """
                CREATE TRIGGER IF NOT EXISTS remtx_require_owner_on_insert
                BEFORE INSERT ON remediation_transactions
                WHEN NEW.owner_capability_sha256 IS NULL
                  OR length(NEW.owner_capability_sha256) != 64
                BEGIN
                    SELECT RAISE(ABORT, 'transaction owner digest is required');
                END
                """
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_remtx_state "
                "ON remediation_transactions(state, id)"
            )
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_remtx_owner_capability "
                "ON remediation_transactions(owner_capability_sha256) "
                "WHERE owner_capability_sha256 IS NOT NULL"
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_reconciliation_claims (
                    claim_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id INTEGER NOT NULL UNIQUE,
                    claimed_ts    REAL    NOT NULL,
                    record_sha256 TEXT    NOT NULL CHECK(length(record_sha256) = 64),
                    recovery_capability_sha256 TEXT NOT NULL
                        CHECK(length(recovery_capability_sha256) = 64)
                )
                """
            )
            claim_columns = {
                str(row[1])
                for row in self._db.execute(
                    "PRAGMA table_info(remediation_reconciliation_claims)"
                ).fetchall()
            }
            if "recovery_capability_sha256" not in claim_columns:
                # A claim created by an older build remains permanently
                # fail-closed after restart: its random authority never
                # existed and must not be reconstructed from retained data.
                self._db.execute(
                    "ALTER TABLE remediation_reconciliation_claims "
                    "ADD COLUMN recovery_capability_sha256 TEXT "
                    "CHECK(recovery_capability_sha256 IS NULL OR "
                    "length(recovery_capability_sha256) = 64)"
                )
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_remrec_capability "
                "ON remediation_reconciliation_claims(recovery_capability_sha256) "
                "WHERE recovery_capability_sha256 IS NOT NULL"
            )
            self._db.execute(
                """
                CREATE TRIGGER IF NOT EXISTS remrec_require_capability_on_insert
                BEFORE INSERT ON remediation_reconciliation_claims
                WHEN NEW.recovery_capability_sha256 IS NULL
                  OR length(NEW.recovery_capability_sha256) != 64
                BEGIN
                    SELECT RAISE(ABORT, 'recovery capability digest is required');
                END
                """
            )
            self._db.commit()
            self._assert_db_custody_locked()

    def _receipt_head_locked(self) -> str:
        prior = self._db.execute(
            """
            SELECT receipt_hash FROM remediation_log
            WHERE receipt_hash IS NOT NULL AND receipt_hash != ''
            ORDER BY id DESC LIMIT 1
            """
        ).fetchone()
        return str(prior[0]) if prior and prior[0] else GENESIS_HASH

    def _insert_receipt_locked(
        self,
        *,
        ts: float,
        trigger: str,
        mitre: str,
        action_key: str,
        action_title: str,
        outcome: str,
        verified: int,
        host_level: bool,
        record_json: str,
        receipt_json: str,
        receipt_hash: str,
    ) -> None:
        self._db.execute(
            """
            INSERT INTO remediation_log
              (ts, trigger, mitre, action_key, action_title,
               outcome, verified, host_level, record_json,
               receipt_json, receipt_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ts,
                trigger,
                mitre,
                action_key,
                action_title,
                outcome,
                int(verified),
                int(bool(host_level)),
                record_json,
                receipt_json,
                receipt_hash,
            ),
        )

    # ── durable mutation custody ─────────────────────────────────────────────
    def prepare_transaction(
        self,
        *,
        trigger: str,
        mitre: str,
        action_key: str,
        action_title: str,
        host_level: bool,
        record: dict,
    ) -> TransactionOwnerCapability:
        """Fsync PREPARED and return its sole, opaque in-memory owner authority."""
        trigger = _bounded_transaction_field(trigger, "trigger")
        mitre = _bounded_transaction_field(mitre or "-", "mitre")
        action_key = _bounded_transaction_field(action_key, "action_key")
        action_title = _bounded_transaction_field(action_title, "action_title")
        if type(host_level) is not bool:
            raise TypeError("remediation transaction host_level must be a boolean")
        encoded = _encode_transaction_record(record)
        owner_secret = secrets.token_bytes(_OWNER_CAPABILITY_BYTES)
        if type(owner_secret) is not bytes or len(owner_secret) != _OWNER_CAPABILITY_BYTES:
            raise RuntimeError("secure remediation owner capability generation failed")
        owner_digest = hashlib.sha256(
            _OWNER_CAPABILITY_DOMAIN + owner_secret
        ).hexdigest()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._assert_db_custody_locked()
                active = self._db.execute(
                    """
                    SELECT id, state
                    FROM remediation_transactions
                    WHERE state IN ('PREPARED', 'MUTATING', 'RECOVERY_REQUIRED')
                    ORDER BY id ASC
                    LIMIT 8
                    """
                ).fetchall()
                if active:
                    raise RemediationCircuitOpen(
                        [(int(row[0]), str(row[1])) for row in active]
                    )
                self._prune_transactions_locked()
                now = time.time()
                cursor = self._db.execute(
                    """
                    INSERT INTO remediation_transactions
                      (created_ts, updated_ts, trigger, mitre, action_key,
                       action_title, host_level, state,
                       owner_capability_sha256, record_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, ?)
                    """,
                    (
                        now,
                        now,
                        trigger,
                        mitre,
                        action_key,
                        action_title,
                        int(host_level),
                        owner_digest,
                        encoded,
                    ),
                )
                transaction_id = int(cursor.lastrowid)
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return TransactionOwnerCapability(transaction_id, owner_secret)

    def transition_transaction(
        self,
        owner: TransactionOwnerCapability,
        *,
        state: str,
        record: dict,
    ) -> None:
        """Enter MUTATING under the ordinary owner capability.

        Terminal states are deliberately unavailable here.  They must use
        :meth:`finish_transaction`, which binds the terminal state and proof
        receipt in one SQLite commit.
        """
        if type(owner) is not TransactionOwnerCapability:
            raise TypeError("an exact transaction owner capability is required")
        target = str(state).upper()
        if target != "MUTATING":
            raise ValueError("invalid remediation transaction state transition")
        transaction_id, owner_digest = owner._proof()
        encoded = _encode_transaction_record(record)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._assert_db_custody_locked()
                cursor = self._db.execute(
                    """
                    UPDATE remediation_transactions
                    SET state = 'MUTATING', updated_ts = ?, record_json = ?
                    WHERE id = ? AND state = 'PREPARED'
                      AND owner_capability_sha256 = ?
                      AND NOT EXISTS (
                        SELECT 1 FROM remediation_reconciliation_claims
                        WHERE transaction_id = remediation_transactions.id
                      )
                    """,
                    (
                        time.time(),
                        encoded,
                        transaction_id,
                        owner_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "remediation transaction owner, state, or custody is unavailable"
                    )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def finish_transaction(
        self,
        owner: TransactionOwnerCapability,
        *,
        result: str,
        record: dict,
    ) -> dict:
        """Atomically commit one fixed ordinary result and its proof receipt."""
        if type(owner) is not TransactionOwnerCapability:
            raise TypeError("an exact transaction owner capability is required")
        completion = _ORDINARY_TERMINAL_RESULTS.get(str(result))
        if completion is None:
            raise ValueError("invalid ordinary remediation completion result")
        target, outcome, verified = completion
        normalized = _normalized_terminal_record(record, result=str(result))
        encoded = _encode_transaction_record(normalized)
        transaction_id, owner_digest = owner._proof()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._assert_db_custody_locked()
                row = self._db.execute(
                    """
                    SELECT trigger, mitre, action_key, action_title, host_level,
                           state, owner_capability_sha256
                    FROM remediation_transactions
                    WHERE id = ?
                    """,
                    (transaction_id,),
                ).fetchone()
                if (
                    row is None
                    or str(row[5]) != "MUTATING"
                    or str(row[6] or "") != owner_digest
                ):
                    raise RuntimeError(
                        "remediation transaction owner, state, or custody is unavailable"
                    )
                claimed = self._db.execute(
                    """
                    SELECT 1 FROM remediation_reconciliation_claims
                    WHERE transaction_id = ?
                    """,
                    (transaction_id,),
                ).fetchone()
                if claimed is not None:
                    raise RuntimeError("remediation transaction custody is unavailable")

                ts = time.time()
                previous_hash = self._receipt_head_locked()
                receipt, chain_hash = create_receipt(
                    ts=ts,
                    trigger=str(row[0]),
                    mitre=str(row[1]) or "-",
                    action_key=str(row[2]),
                    outcome=outcome,
                    verified=verified,
                    host_level=bool(row[4]),
                    record=normalized,
                    previous_hash=previous_hash,
                )
                receipt_json = json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"), default=str
                )
                updated = self._db.execute(
                    """
                    UPDATE remediation_transactions
                    SET state = ?, updated_ts = ?, record_json = ?,
                        owner_capability_sha256 = NULL
                    WHERE id = ? AND state = 'MUTATING'
                      AND owner_capability_sha256 = ?
                      AND NOT EXISTS (
                        SELECT 1 FROM remediation_reconciliation_claims
                        WHERE transaction_id = remediation_transactions.id
                      )
                    """,
                    (target, ts, encoded, transaction_id, owner_digest),
                )
                if updated.rowcount != 1:
                    raise RuntimeError(
                        "remediation terminal update lost its owner capability"
                    )
                self._insert_receipt_locked(
                    ts=ts,
                    trigger=str(row[0]),
                    mitre=str(row[1]) or "-",
                    action_key=str(row[2]),
                    action_title=str(row[3]),
                    outcome=outcome,
                    verified=verified,
                    host_level=bool(row[4]),
                    record_json=encoded,
                    receipt_json=receipt_json,
                    receipt_hash=chain_hash,
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        owner._retire()
        return {
            "receipt_id": receipt.get("receipt_id"),
            "receipt_hash": chain_hash,
            "receipt_authenticated": "_angerona_hmac" in receipt,
            "record": normalized,
        }

    def reconcile_incomplete_transactions(self) -> list[dict]:
        """Compatibility alias for read-only unresolved-state inspection.

        Ordinary callers never promote or abandon PREPARED/MUTATING state.
        Only the separately authorized reconciliation API may claim a row.
        """
        return self.unresolved_transactions()

    def unresolved_transactions(self, limit: int = 100) -> list[dict]:
        bounded = max(1, min(100, int(limit)))
        with self._lock:
            self._assert_db_custody_locked()
            rows = self._db.execute(
                """
                SELECT id, created_ts, updated_ts, trigger, mitre, action_key,
                       state, record_json
                FROM remediation_transactions
                WHERE state IN ('PREPARED', 'MUTATING', 'RECOVERY_REQUIRED')
                ORDER BY id ASC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
            claims = {
                int(row[0])
                for row in self._db.execute(
                    "SELECT transaction_id FROM remediation_reconciliation_claims"
                ).fetchall()
            }
        results = [_transaction_row_to_dict(row) for row in rows]
        for result in results:
            if result["transaction_id"] in claims:
                result["stored_state"] = result["state"]
                result["state"] = "RECONCILING"
                result["recovery_active"] = True
        return results

    def transaction(self, transaction_id: int) -> dict | None:
        with self._lock:
            self._assert_db_custody_locked()
            row = self._db.execute(
                """
                SELECT id, created_ts, updated_ts, trigger, mitre, action_key,
                       state, record_json
                FROM remediation_transactions
                WHERE id = ?
                """,
                (int(transaction_id),),
            ).fetchone()
            claim = self._db.execute(
                """
                SELECT 1 FROM remediation_reconciliation_claims
                WHERE transaction_id = ?
                """,
                (int(transaction_id),),
            ).fetchone()
        if not row:
            return None
        result = _transaction_row_to_dict(row)
        if claim:
            result["stored_state"] = result["state"]
            result["state"] = "RECONCILING"
            result["recovery_active"] = True
        return result

    def _bind_recovery_coordinator(
        self, action_registry: tuple[object, ...]
    ) -> _RecoveryCoordinatorCapability:
        """Mint once for the module-private reviewed recovery coordinator."""
        if type(action_registry) is not tuple:
            raise TypeError("an exact recovery action registry tuple is required")
        with self._lock:
            self._assert_db_custody_locked()
            if self._recovery_coordinator is None:
                coordinator = _RecoveryCoordinatorCapability(
                    _RECOVERY_COORDINATOR_MINT, self, action_registry
                )
                self._recovery_coordinator = coordinator
                self._recovery_coordinator_digest = coordinator._digest()
            else:
                coordinator = self._recovery_coordinator
                if len(coordinator._registry) != len(action_registry) or any(
                    expected is not supplied
                    for expected, supplied in zip(
                        coordinator._registry, action_registry
                    )
                ):
                    raise RuntimeError(
                        "remediation recovery coordinator is already bound to "
                        "a different action registry"
                    )
                self._require_recovery_coordinator(coordinator)
            return coordinator

    def _require_recovery_coordinator(
        self, coordinator: _RecoveryCoordinatorCapability
    ) -> None:
        if type(coordinator) is not _RecoveryCoordinatorCapability:
            raise TypeError("an exact remediation recovery coordinator is required")
        if coordinator is not self._recovery_coordinator:
            raise RuntimeError("remediation recovery coordinator is unavailable")
        coordinator._require_store(self)
        if not secrets.compare_digest(
            self._recovery_coordinator_digest, coordinator._digest()
        ):
            raise RuntimeError("remediation recovery coordinator is unavailable")

    def _claim_reconciliation(
        self,
        coordinator: _RecoveryCoordinatorCapability,
        transaction_id: int,
    ) -> dict:
        """Privately claim one row for the exact reviewed coordinator."""
        self._require_recovery_coordinator(coordinator)
        wanted = int(transaction_id)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._assert_db_custody_locked()
                self._require_recovery_coordinator(coordinator)
                row = self._db.execute(
                    """
                    SELECT id, created_ts, updated_ts, trigger, mitre, action_key,
                           state, record_json
                    FROM remediation_transactions
                    WHERE id = ?
                    """,
                    (wanted,),
                ).fetchone()
                if row is None:
                    self._db.commit()
                    return {"claimed": False, "transaction": None}
                current = _transaction_row_to_dict(row)
                existing = self._db.execute(
                    """
                    SELECT 1
                    FROM remediation_reconciliation_claims
                    WHERE transaction_id = ?
                    """,
                    (wanted,),
                ).fetchone()
                if existing is not None:
                    current["stored_state"] = current["state"]
                    current["state"] = "RECONCILING"
                    current["recovery_active"] = True
                    self._db.commit()
                    return {"claimed": False, "transaction": current}
                if current["state"] != "RECOVERY_REQUIRED":
                    self._db.commit()
                    return {"claimed": False, "transaction": current}
                record_sha256 = hashlib.sha256(
                    str(row[7]).encode("utf-8")
                ).hexdigest()
                recovery_secret = secrets.token_bytes(_RECOVERY_CAPABILITY_BYTES)
                if (
                    type(recovery_secret) is not bytes
                    or len(recovery_secret) != _RECOVERY_CAPABILITY_BYTES
                ):
                    raise RuntimeError("secure remediation recovery capability failed")
                capability = RecoveryCapability(wanted, recovery_secret)
                _, capability_digest = capability._proof(record_sha256)
                self._db.execute(
                    """
                    INSERT INTO remediation_reconciliation_claims
                      (transaction_id, claimed_ts, record_sha256,
                       recovery_capability_sha256)
                    VALUES (?, ?, ?, ?)
                    """,
                    (wanted, time.time(), record_sha256, capability_digest),
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        current["stored_state"] = current["state"]
        current["state"] = "RECONCILING"
        current["recovery_active"] = True
        return {
            "claimed": True,
            "capability": capability,
            "transaction": current,
        }

    def _validate_recovery_claim_locked(
        self,
        capability: RecoveryCapability,
    ) -> tuple[tuple, tuple, str]:
        if type(capability) is not RecoveryCapability:
            raise TypeError("an exact remediation recovery capability is required")
        if capability._retired:
            raise RuntimeError("remediation recovery capability is unavailable")
        transaction_id = capability.transaction_id
        row = self._db.execute(
            """
            SELECT trigger, mitre, action_key, action_title, host_level,
                   state, record_json
            FROM remediation_transactions
            WHERE id = ?
            """,
            (int(transaction_id),),
        ).fetchone()
        claim = self._db.execute(
            """
            SELECT claim_id, record_sha256,
                   recovery_capability_sha256
            FROM remediation_reconciliation_claims
            WHERE transaction_id = ?
            """,
            (int(transaction_id),),
        ).fetchone()
        if row is None or claim is None:
            raise RuntimeError("reconciliation claim is unavailable")
        expected_digest = str(claim[1])
        proof_transaction_id, supplied_digest = capability._proof(expected_digest)
        if proof_transaction_id != transaction_id or not secrets.compare_digest(
            str(claim[2] or ""), supplied_digest
        ):
            raise RuntimeError("reconciliation capability is unavailable")
        if str(row[5]) != "RECOVERY_REQUIRED":
            raise RuntimeError("reconciliation transaction state changed")
        current_digest = hashlib.sha256(str(row[6]).encode("utf-8")).hexdigest()
        if not secrets.compare_digest(current_digest, expected_digest):
            raise RuntimeError("reconciliation retained record changed")
        return row, claim, supplied_digest

    def _issue_verified_recovery_proof(
        self,
        coordinator: _RecoveryCoordinatorCapability,
        capability: RecoveryCapability,
        *,
        action: object,
        operation: str,
        evidence: dict,
    ) -> _VerifiedRecoveryProof:
        """Issue one fixed completion witness after coordinator verification.

        The caller cannot select a journal outcome or replacement record.  The
        store rebuilds the terminal record from the exact retained record and a
        narrow verified evidence object; finish accepts only this exact witness.
        """
        self._require_recovery_coordinator(coordinator)
        action_key, reversible = coordinator._action_binding(action)
        if operation == "verified_rollback":
            if not reversible:
                raise RuntimeError("irreversible recovery cannot assert rollback")
            if not isinstance(evidence, dict) or evidence.get("ok") is not True:
                raise RuntimeError("verified rollback evidence is required")
            result = "reconciled_rolled_back"
        elif operation == "verified_postcondition":
            if reversible:
                raise RuntimeError("reversible recovery requires exact rollback")
            if not isinstance(evidence, dict) or evidence.get("verified") is not True:
                raise RuntimeError("verified postcondition evidence is required")
            result = "reconciled_applied"
        else:
            raise ValueError("invalid verified recovery operation")

        with self._lock:
            self._assert_db_custody_locked()
            self._require_recovery_coordinator(coordinator)
            row, claim, _ = self._validate_recovery_claim_locked(capability)
            transaction_id = capability.transaction_id
            if str(row[2]) != action_key:
                raise RuntimeError("recovery action does not match retained control")
            if transaction_id in self._recovery_proofs:
                raise RuntimeError("a verified recovery proof is already active")
            retained_record = _decode_transaction_record(str(row[6]))
            if result == "reconciled_rolled_back":
                retained_record.update(
                    {
                        "recovery_operation": "verified_rollback",
                        "rollback": dict(evidence),
                        "rollback_verified": True,
                    }
                )
            else:
                retained_record.update(
                    {
                        "recovery_operation": "verified_postcondition",
                        "postcondition_verified": True,
                    }
                )
            normalized = _normalized_terminal_record(retained_record, result=result)
            encoded = _encode_transaction_record(normalized)
            proof = _VerifiedRecoveryProof(
                _RECOVERY_PROOF_MINT,
                coordinator_digest=coordinator._digest(),
                transaction_id=transaction_id,
                action_key=action_key,
                record_sha256=str(claim[1]),
                result=result,
                encoded_record=encoded,
            )
            self._recovery_proofs[transaction_id] = proof
            return proof

    def _finish_reconciliation(
        self,
        coordinator: _RecoveryCoordinatorCapability,
        capability: RecoveryCapability,
        proof: _VerifiedRecoveryProof,
    ) -> dict:
        """Atomically commit the exact coordinator-issued verified witness."""
        self._require_recovery_coordinator(coordinator)
        if type(capability) is not RecoveryCapability:
            raise TypeError("an exact remediation recovery capability is required")
        if capability._retired:
            raise RuntimeError("remediation recovery capability is unavailable")
        if type(proof) is not _VerifiedRecoveryProof:
            raise TypeError("an exact verified recovery proof is required")
        if proof._retired:
            raise RuntimeError("verified recovery proof is unavailable")
        if proof._transaction_id != capability.transaction_id:
            raise RuntimeError("verified recovery proof is bound to another claim")
        completion = _RECOVERY_TERMINAL_RESULTS.get(proof._result)
        if completion is None:
            raise RuntimeError("verified recovery proof has no terminal result")
        target, outcome, verified = completion
        normalized = _decode_transaction_record(proof._encoded_record)
        encoded = _encode_transaction_record(normalized)
        transaction_id = capability.transaction_id
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._assert_db_custody_locked()
                self._require_recovery_coordinator(coordinator)
                row, claim, supplied_digest = self._validate_recovery_claim_locked(
                    capability
                )
                if self._recovery_proofs.get(transaction_id) is not proof:
                    raise RuntimeError("verified recovery proof is unavailable")
                if (
                    proof._action_key != str(row[2])
                    or proof._record_sha256 != str(claim[1])
                    or not secrets.compare_digest(
                        proof._coordinator_digest, coordinator._digest()
                    )
                ):
                    raise RuntimeError("verified recovery proof binding changed")

                ts = time.time()
                previous_hash = self._receipt_head_locked()
                receipt, chain_hash = create_receipt(
                    ts=ts,
                    trigger="explicit_reconciliation",
                    mitre=str(row[1]) or "-",
                    action_key=str(row[2]),
                    outcome=outcome,
                    verified=verified,
                    host_level=bool(row[4]),
                    record=normalized,
                    previous_hash=previous_hash,
                )
                receipt_json = json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"), default=str
                )
                updated = self._db.execute(
                    """
                    UPDATE remediation_transactions
                    SET state = ?, updated_ts = ?, record_json = ?
                    WHERE id = ? AND state = 'RECOVERY_REQUIRED'
                      AND EXISTS (
                        SELECT 1 FROM remediation_reconciliation_claims
                        WHERE transaction_id = remediation_transactions.id
                          AND recovery_capability_sha256 = ?
                      )
                    """,
                    (target, ts, encoded, transaction_id, supplied_digest),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("reconciliation transaction update lost its claim")
                self._insert_receipt_locked(
                    ts=ts,
                    trigger="explicit_reconciliation",
                    mitre=str(row[1]) or "-",
                    action_key=str(row[2]),
                    action_title=str(row[3]),
                    outcome=outcome,
                    verified=verified,
                    host_level=bool(row[4]),
                    record_json=encoded,
                    receipt_json=receipt_json,
                    receipt_hash=chain_hash,
                )
                deleted = self._db.execute(
                    """
                    DELETE FROM remediation_reconciliation_claims
                    WHERE transaction_id = ? AND claim_id = ?
                      AND recovery_capability_sha256 = ?
                    """,
                    (transaction_id, int(claim[0]), supplied_digest),
                )
                if deleted.rowcount != 1:
                    raise RuntimeError("reconciliation claim release failed")
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        self._recovery_proofs.pop(transaction_id, None)
        proof._retire()
        capability._retire()
        return {
            "receipt_id": receipt.get("receipt_id"),
            "receipt_hash": chain_hash,
            "receipt_authenticated": "_angerona_hmac" in receipt,
            "record": normalized,
        }

    def close(self) -> None:
        """Close this direct log instance (primarily for restart verification)."""
        with self._lock:
            self._db.close()

    def _prune_transactions_locked(self) -> None:
        count = int(
            self._db.execute("SELECT COUNT(*) FROM remediation_transactions").fetchone()[0]
        )
        excess = count - MAX_ROWS + 1
        if excess <= 0:
            return
        self._db.execute(
            """
            DELETE FROM remediation_transactions
            WHERE id IN (
                SELECT id FROM remediation_transactions
                WHERE state IN ('APPLIED', 'ROLLED_BACK')
                ORDER BY id ASC
                LIMIT ?
            )
            """,
            (excess,),
        )
        remaining = int(
            self._db.execute("SELECT COUNT(*) FROM remediation_transactions").fetchone()[0]
        )
        if remaining >= MAX_ROWS:
            raise RuntimeError("remediation transaction journal is full of unresolved state")

    # ── write ─────────────────────────────────────────────────────────────────
    def log(
        self,
        *,
        trigger: str = "",
        mitre: str = "-",
        action_key: str = "none",
        action_title: str = "",
        outcome: str = "dry_run",
        verified: int = -1,
        host_level: bool = False,
        record: dict | None = None,
    ) -> dict:
        """Append one remediation-action entry.

        outcome values:
          ``applied``     — action ran and verify passed
          ``rolled_back`` — action ran but verify failed; was rolled back
          ``skipped``     — matched but not applied (host-level gate or apply=False)
          ``dry_run``     — plan-only call; no action attempted
          ``error``       — action raised an exception
        """
        with self._lock:
            self._assert_db_custody_locked()
            ts = time.time()
            prior = self._db.execute(
                """
                SELECT receipt_hash
                FROM remediation_log
                WHERE receipt_hash IS NOT NULL AND receipt_hash != ''
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
            previous_hash = str(prior[0]) if prior and prior[0] else GENESIS_HASH
            receipt, chain_hash = create_receipt(
                ts=ts,
                trigger=trigger,
                mitre=mitre or "-",
                action_key=action_key,
                outcome=outcome,
                verified=verified,
                host_level=host_level,
                record=record,
                previous_hash=previous_hash,
            )
            self._db.execute(
                """
                INSERT INTO remediation_log
                  (ts, trigger, mitre, action_key, action_title,
                   outcome, verified, host_level, record_json,
                   receipt_json, receipt_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    ts, trigger, mitre or "-", action_key,
                    action_title, outcome, int(verified), int(bool(host_level)),
                    json.dumps(record, default=str) if record is not None else None,
                    json.dumps(receipt, sort_keys=True, default=str),
                    chain_hash,
                ),
            )
            self._db.commit()
            self._writes += 1
            if self._writes >= PRUNE_EVERY:
                self._writes = 0
                self._prune_locked()
            return {
                "receipt_id": receipt.get("receipt_id"),
                "receipt_hash": chain_hash,
                "receipt_authenticated": "_angerona_hmac" in receipt,
            }

    def _prune_locked(self) -> None:
        try:
            row = self._db.execute(
                "SELECT MAX(id) FROM remediation_log"
            ).fetchone()
            if row and row[0] and row[0] > MAX_ROWS:
                self._db.execute(
                    "DELETE FROM remediation_log WHERE id <= ?",
                    (row[0] - MAX_ROWS,),
                )
                self._db.commit()
        except Exception:
            pass

    # ── read ──────────────────────────────────────────────────────────────────
    def recent(self, limit: int = 50) -> List[dict]:
        """Return the most recent *limit* entries, newest-first."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT ts, trigger, mitre, action_key, action_title,
                       outcome, verified, host_level, record_json,
                       receipt_json, receipt_hash
                FROM   remediation_log
                ORDER  BY id DESC
                LIMIT  ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def by_mitre(self, tid: str, limit: int = 50) -> List[dict]:
        """Return entries for a specific MITRE technique ID (case-insensitive)."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT ts, trigger, mitre, action_key, action_title,
                       outcome, verified, host_level, record_json,
                       receipt_json, receipt_hash
                FROM   remediation_log
                WHERE  lower(mitre) = lower(?)
                ORDER  BY id DESC
                LIMIT  ?
                """,
                (tid, limit),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def stats(self) -> dict:
        """Aggregate counts by outcome."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT outcome, COUNT(*) as n
                FROM   remediation_log
                GROUP  BY outcome
                """
            ).fetchall()
            total = self._db.execute(
                "SELECT COUNT(*) FROM remediation_log"
            ).fetchone()[0]
        counts = {r[0]: r[1] for r in rows}
        return {"total": total, **counts}

    def verify_receipt_chain(self, limit: int = MAX_ROWS) -> dict:
        """Verify the retained proof chain from its oldest checkpoint."""
        bounded = max(1, min(MAX_ROWS, int(limit)))
        with self._lock:
            legacy = self._db.execute(
                "SELECT COUNT(*) FROM remediation_log WHERE receipt_json IS NULL"
            ).fetchone()[0]
            rows = self._db.execute(
                """
                SELECT id, record_json, receipt_json, receipt_hash
                FROM remediation_log
                WHERE receipt_json IS NOT NULL
                ORDER BY id ASC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        if not rows:
            return {
                "valid": True,
                "verified_receipts": 0,
                "legacy_rows": int(legacy),
                "head_hash": "",
                "reason": "no proof receipts recorded yet",
            }

        try:
            first_receipt = json.loads(rows[0][2])
            expected = str(
                first_receipt.get("previous_receipt_hash") or GENESIS_HASH
            )
        except Exception:
            return {
                "valid": False,
                "verified_receipts": 0,
                "legacy_rows": int(legacy),
                "broken_id": int(rows[0][0]),
                "head_hash": "",
                "reason": "first receipt is not valid JSON",
            }

        verified_count = 0
        head_hash = ""
        for row_id, record_json, receipt_json, stored_hash in rows:
            try:
                record = json.loads(record_json) if record_json else None
                receipt = json.loads(receipt_json)
            except Exception:
                return {
                    "valid": False,
                    "verified_receipts": verified_count,
                    "legacy_rows": int(legacy),
                    "broken_id": int(row_id),
                    "head_hash": head_hash,
                    "reason": "receipt or bound action record is not valid JSON",
                }
            result = verify_receipt(
                receipt,
                record=record,
                expected_previous_hash=expected,
                stored_hash=str(stored_hash or ""),
            )
            if not result.valid:
                return {
                    "valid": False,
                    "verified_receipts": verified_count,
                    "legacy_rows": int(legacy),
                    "broken_id": int(row_id),
                    "head_hash": head_hash,
                    "reason": result.reason,
                }
            verified_count += 1
            expected = result.receipt_hash
            head_hash = result.receipt_hash
        return {
            "valid": True,
            "verified_receipts": verified_count,
            "legacy_rows": int(legacy),
            "head_hash": head_hash,
            "reason": "retained receipt chain verified",
        }


# ── helpers ───────────────────────────────────────────────────────────────────
def _bounded_transaction_field(value: str, label: str) -> str:
    result = str(value).strip()
    if not result or len(result) > MAX_TRANSACTION_FIELD_CHARS:
        raise ValueError(f"remediation transaction {label} is empty or over its bound")
    return result


def _encode_transaction_record(record: dict) -> str:
    if not isinstance(record, dict):
        raise TypeError("remediation transaction record must be a mapping")
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > MAX_TRANSACTION_RECORD_BYTES:
        raise ValueError("remediation transaction record exceeds its 64 KiB bound")
    return encoded


def _normalized_terminal_record(record: dict, *, result: str) -> dict:
    """Return one authoritative record for a fixed terminal result token."""
    if not isinstance(record, dict):
        raise TypeError("remediation transaction record must be a mapping")
    normalized = dict(record)
    if result in {"applied", "reconciled_applied"}:
        normalized.update(
            {
                "ok": True,
                "transaction_state": "applied",
                "recovery_required": False,
                "verified": True,
                "rollback_succeeded": False,
                "rollback_failed": False,
            }
        )
    elif result in {
        "apply_failed_no_change",
        "rolled_back",
        "reconciled_rolled_back",
    }:
        normalized.update(
            {
                "ok": False,
                "transaction_state": "rolled_back",
                "recovery_required": False,
                "verified": result == "reconciled_rolled_back",
                "rollback_succeeded": True,
                "rollback_failed": False,
            }
        )
    elif result in {"recovery_required", "reconciliation_failed"}:
        normalized.update(
            {
                "transaction_state": "recovery_required",
                "recovery_required": True,
                "verified": False,
                "rollback_succeeded": False,
                "rollback_failed": False,
            }
        )
    elif result == "rollback_failed":
        normalized.update(
            {
                "transaction_state": "rollback_failed",
                "recovery_required": True,
                "verified": False,
                "rollback_succeeded": False,
                "rollback_failed": True,
            }
        )
    else:
        raise ValueError("invalid remediation terminal record result")
    return normalized


def _decode_transaction_record(encoded: str) -> dict:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > MAX_TRANSACTION_RECORD_BYTES:
        raise ValueError("remediation transaction record is invalid or oversized")
    record = json.loads(encoded)
    if not isinstance(record, dict):
        raise ValueError("remediation transaction record is not a mapping")
    return record


def _transaction_row_to_dict(row) -> dict:
    (
        transaction_id,
        created_ts,
        updated_ts,
        trigger,
        mitre,
        action_key,
        state,
        record_json,
    ) = row
    return {
        "transaction_id": int(transaction_id),
        "created_ts": float(created_ts),
        "updated_ts": float(updated_ts),
        "trigger": str(trigger),
        "mitre": str(mitre),
        "action_key": str(action_key),
        "state": str(state),
        "record": _decode_transaction_record(record_json),
    }


def _row_to_dict(r) -> dict:
    (
        ts, trigger, mitre, action_key, action_title, outcome, verified,
        host_level, rj, receipt_json, receipt_hash,
    ) = r
    record_valid = True
    try:
        record = json.loads(rj) if rj else None
    except Exception:
        record = None
        record_valid = False
    receipt_present = bool(receipt_json)
    try:
        receipt = json.loads(receipt_json) if receipt_json else None
        if receipt is not None and not isinstance(receipt, dict):
            receipt = None
    except Exception:
        receipt = None
    authenticity = None
    if receipt_present and (receipt is None or not record_valid):
        authenticity = False
    elif receipt is not None:
        expected_previous = str(
            receipt.get("previous_receipt_hash") or GENESIS_HASH
        )
        authenticity = verify_receipt(
            receipt,
            record=record,
            expected_previous_hash=expected_previous,
            stored_hash=str(receipt_hash or ""),
        ).valid
    return {
        "ts": ts,
        "trigger": trigger,
        "mitre": mitre,
        "action_key": action_key,
        "action_title": action_title,
        "outcome": outcome,
        "verified": None if verified == -1 else bool(verified),
        "host_level": bool(host_level),
        "record": record,
        "receipt_id": receipt.get("receipt_id") if receipt else None,
        "receipt_hash": receipt_hash or None,
        # This is an actual signature/hash/record-binding verification, not
        # merely the presence of a user-controlled signature field.
        "receipt_authenticity": authenticity,
    }
