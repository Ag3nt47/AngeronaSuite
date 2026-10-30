"""Optional bounded recorder witnessing, separate from the protection writer.

Only an explicitly composed authenticated SDK client can contact an authority.
Archived signatures commit stored bytes, not producer trust or kernel health.
Missing history, ambiguous commits and storage limits hold this optional worker;
they never repair records, rotate host keys or stop the protection graph.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time

from .file_lease import ExclusiveFileLease
from .independent_high_water import HighWaterRejected, HighWaterUnavailable
from .personal_sentinel_authority import (
    Ed25519PrivateSigner, Ed25519PublicVerifier, PersonalSentinelAuthorityClient,
    require_independent_ed25519_enrollment,
)
from .recorder_epoch import (
    MAX_EPOCH_BYTES, MAX_EPOCH_ROWS, MAX_ROW_BYTES, EpochClaim, EpochReceipt, EpochRejected,
    RowCommitment, admit_successor, canonical, claim_rows, commit_rows, parse_claim, parse_receipt,
    rows_root, verify_receipt, verify_row_range,
)
from .startup_recovery import private_directory, private_repair_file

ARCHIVE_SCHEMA = "angerona.recorder-epoch-archive.v1"
ARCHIVE_LIMIT = 16 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_ARCHIVES = 128
_EPOCH_NAME = re.compile(r"epoch-([0-9]{19})\.json\Z")
_fsync = os.fsync
_replace = os.replace
_close_fd = os.close
_connect_sqlite = sqlite3.connect
_RETIREMENT_HOLDS = []


class WitnessHeld(RuntimeError):
    pass


class StorageHeld(WitnessHeld):
    pass


class BudgetHeld(WitnessHeld):
    pass


class _Stopped(RuntimeError):
    pass


class _MetadataCloseHeld(WitnessHeld):
    pass


@dataclass
class _MetadataOwner:
    descriptor: int | None = None
    ambiguous_descriptor: int | None = None
    close_proven: bool = False


@dataclass(frozen=True)
class RecorderEpochStatus:
    state: str = "starting"
    reason: str = "Optional recorder witness is starting"
    revision: int = 0
    archive_bytes: int = 0
    archive_limit_bytes: int = ARCHIVE_LIMIT
    history_epochs: int = 0
    pending: bool = False
    last_sealed_epoch: int = 0
    last_sealed_row: int = 0
    observed_database_tail: int = 0
    unsealed_backlog: bool = False
    last_checked_epoch: int = 0
    checked_first_id: int = 0
    checked_last_id: int = 0
    verified_rows: int = 0
    missing_rows: int = 0
    changed_rows: int = 0
    unexpected_rows: int = 0
    known_missing_rows: int = 0
    verification_backlog_epochs: int = 0
    history_ranges_checked_this_cycle: int = 0
    history_check_budget_exhausted: bool = False
    last_verification_monotonic: float | None = None
    oldest_history_check_monotonic: float | None = None
    last_authority_monotonic: float | None = None
    authority_head_checked: bool = False
    thread_retired: bool = False
    cleanup_proven: bool = True
    sqlite_runtime_limits_available: bool = False
    producer_authenticity_verified: bool = False
    physical_independence_verified: bool = False
    protection_authority: bool = False


@dataclass(frozen=True)
class _ArchiveRecord:
    claim: EpochClaim
    index: tuple[RowCommitment, ...]
    receipt: EpochReceipt | None


def _plain(path: Path, *, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or not directory and info.st_nlink != 1):
        raise WitnessHeld("Recorder witness path is redirected or has uncertain ownership")
    return info


def _no_alias(path: Path):
    for item in (path, *path.parents):
        if os.path.lexists(item):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise WitnessHeld("Recorder witness cannot traverse a redirected path")


class RecorderEpochWorker:
    """One retained reader/archiver, with an immutable memory-only status view."""
    def __init__(self, *, db_path, archive_dir, client=None, on_status=None, interval=60.0,
                 archive_limit_bytes=ARCHIVE_LIMIT):
        self.db_path, self.archive_dir = Path(db_path), Path(archive_dir)
        if (not self.db_path.is_absolute() or not self.archive_dir.is_absolute()
                or ".." in self.db_path.parts or ".." in self.archive_dir.parts):
            raise ValueError("Recorder witness requires explicit absolute paths")
        if (type(interval) not in (int, float) or not math.isfinite(interval) or not 1 <= interval <= 3600
                or type(archive_limit_bytes) is not int or not 4096 <= archive_limit_bytes <= 64 * 1024 * 1024
                or on_status is not None and not callable(on_status)):
            raise ValueError("Recorder witness controls exceed their bounds")
        # Do not touch lazy enrollment/key/transport properties on the caller.
        # Exact provider admission happens on this worker before any operation.
        self.client, self.on_status, self.interval = client, on_status, float(interval)
        self.archive_limit_bytes = archive_limit_bytes
        self._status = RecorderEpochStatus(state="disabled" if client is None else "starting",
            reason="No recorder authority is configured" if client is None else "Optional recorder witness is starting",
            archive_limit_bytes=archive_limit_bytes)
        self._stop, self._wake, self._retired = threading.Event(), threading.Event(), threading.Event()
        self._thread = None
        self._db = self._lease = None
        self._db_ready = False
        self._db_schema = None
        self._cleanup_proven = True
        self._owner = None
        self._known = {}
        self._checked = {}
        self._missing = {}
        self._verify_cursor = 0
        self._io_deadline = 0.0
        self._client_admitted = False
        self._metadata_owners = []

    @property
    def thread(self):
        return self._thread

    def latest_status(self) -> RecorderEpochStatus:
        return self._status

    def start(self):
        if self.client is None:
            return False
        if (self._thread is not None or self._stop.is_set()
                or any(holder.archive_dir == self.archive_dir for holder in _RETIREMENT_HOLDS)):
            raise RuntimeError("Recorder witness cannot be restarted")
        self._thread = threading.Thread(target=self._run, name="RecorderEpochWitness", daemon=False)
        try:
            self._thread.start()
        except BaseException:
            self.request_stop()
            raise
        return True

    def request_cycle(self):
        if self._stop.is_set() or self._retired.is_set():
            return False
        self._wake.set()
        return True

    def request_stop(self):
        self._stop.set()
        self._wake.set()

    def stop(self, timeout=3.0):
        self.request_stop()
        if self._thread is None:
            return True
        try:
            self._thread.join(max(0.0, timeout))
        except RuntimeError:
            return False
        retired = self._retired.is_set() and not self._thread.is_alive()
        if retired:
            self._status = replace(self._status, thread_retired=True,
                state="stopped" if self._cleanup_proven else "retirement-held",
                reason="Recorder witness reader and archive lease retired" if self._cleanup_proven else
                       "Recorder witness resource cleanup remains unproven; retain its owner")
        return retired and self._cleanup_proven

    def _publish(self, state, reason, **updates):
        self._status = replace(self._status, state=state, reason=reason[:240],
                               revision=self._status.revision + 1, **updates)
        if self.on_status is not None:
            try:
                self.on_status(self._status)
            except Exception:
                pass  # Observer delivery grants no mutation or witness authority.

    def _checkpoint(self):
        if threading.get_ident() != self._owner:
            raise WitnessHeld("Recorder witness I/O escaped its retained owner")
        if self._stop.is_set():
            raise _Stopped()
        if time.monotonic() >= self._io_deadline:
            raise BudgetHeld("Recorder witness cooperative I/O budget was exhausted")

    def _admit_client(self):
        if self._client_admitted:
            return
        from .recorder_integrity import ConfiguredWitnessProvider

        allowed = (PersonalSentinelAuthorityClient, ConfiguredWitnessProvider)
        if type(self.client) not in allowed:
            raise WitnessHeld("Recorder witness client is not an explicitly composed trusted SDK provider")
        if (type(self.client.response_verifier) is not Ed25519PublicVerifier
                or type(self.client) is PersonalSentinelAuthorityClient
                and type(self.client.request_signer) is not Ed25519PrivateSigner):
            raise WitnessHeld("Recorder witness requires independent asymmetric enrollment")
        if type(self.client) is PersonalSentinelAuthorityClient:
            try:
                require_independent_ed25519_enrollment(
                    request_verifier=self.client.request_signer.public_verifier(),
                    response_verifier=self.client.response_verifier)
            except ValueError as exc:
                raise WitnessHeld("Recorder request and authority keys are not independently enrolled") from exc
        self._client_admitted = True

    @contextmanager
    def _metadata_fd(self, path, flags, mode=0o600):
        owner = _MetadataOwner()
        self._metadata_owners.append(owner)
        try:
            owner.descriptor = os.open(path, flags, mode)
        except BaseException:
            self._metadata_owners.remove(owner)
            raise
        try:
            yield owner.descriptor
        finally:
            descriptor, owner.descriptor = owner.descriptor, None
            try:
                _close_fd(descriptor)
            except BaseException as exc:
                # The number may already have been closed/reused. Retain the
                # diagnostic owner, fence all further I/O and never retry it.
                owner.ambiguous_descriptor = descriptor
                self._cleanup_proven = False
                self.request_stop()
                raise _MetadataCloseHeld("Recorder metadata descriptor retirement remains unproven") from exc
            else:
                owner.close_proven = True
                self._metadata_owners.remove(owner)

    def _inventory(self):
        _no_alias(self.archive_dir)
        if not private_directory(self.archive_dir, create=False):
            raise WitnessHeld("Recorder witness archive is not private")
        total, epochs = 0, []
        with os.scandir(self.archive_dir) as items:
            for count, item in enumerate(items, 1):
                self._checkpoint()
                if count > MAX_ARCHIVES + 3:
                    raise StorageHeld("Recorder witness archive exceeds its entry bound; review archive storage")
                path = self.archive_dir / item.name
                info = _plain(path)
                if not private_repair_file(path):
                    raise WitnessHeld("Recorder witness metadata is not private")
                if item.name not in {".writer.lock", "pending.json", "write.tmp"}:
                    match = _EPOCH_NAME.fullmatch(item.name)
                    if match is None:
                        raise WitnessHeld("Recorder witness archive contains an unknown entry")
                    epochs.append((int(match.group(1)), path))
                maximum = 1 if item.name == ".writer.lock" else MAX_METADATA
                if not 0 <= info.st_size <= maximum:
                    raise StorageHeld("Recorder witness metadata exceeds its byte bound")
                total += info.st_size
                if total > self.archive_limit_bytes:
                    raise StorageHeld("Recorder witness archive budget is full; review storage or export policy")
        if len(epochs) > MAX_ARCHIVES:
            raise StorageHeld("Recorder witness epoch count is full; authenticated history was preserved")
        return total, sorted(epochs)

    def _read_metadata(self, path):
        self._checkpoint()
        before = _plain(path)
        if not 1 <= before.st_size <= MAX_METADATA or not private_repair_file(path):
            raise WitnessHeld("Recorder witness metadata is unavailable or oversized")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with self._metadata_fd(path, flags) as descriptor:
            held = os.fstat(descriptor)
            raw = os.read(descriptor, MAX_METADATA + 1)
            after = _plain(path)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                    or (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or held.st_nlink != 1):
                raise WitnessHeld("Recorder witness metadata changed during its bounded read")
        if len(raw) > MAX_METADATA:
            raise WitnessHeld("Recorder witness metadata exceeds its byte bound")
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise WitnessHeld("Recorder witness metadata has duplicate keys")
                value[key] = item
            return value
        try:
            value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                               parse_constant=lambda _v: (_ for _ in ()).throw(ValueError()))
            if (type(value) is not dict or set(value) != {"schema", "installation_id", "client_instance_id", "claim", "index", "receipt"}
                    or value["schema"] != ARCHIVE_SCHEMA or value["installation_id"] != self.client.installation_id
                    or value["client_instance_id"] != self.client.client_instance_id
                    or type(value["index"]) is not list or not 1 <= len(value["index"]) <= MAX_EPOCH_ROWS):
                raise WitnessHeld("Recorder witness metadata identity/schema differs")
            claim = parse_claim(value["claim"])
            index = tuple(RowCommitment(*row) for row in value["index"] if type(row) is list and len(row) == 2)
            if (len(index) != len(value["index"]) or len(index) != claim.count or rows_root(index) != claim.rows_root
                    or index[0].row_id != claim.first_id or index[-1].row_id != claim.last_id):
                raise WitnessHeld("Recorder witness row index differs from its claim")
            receipt = None if value["receipt"] is None else parse_receipt(value["receipt"])
            if receipt is not None:
                verify_receipt(receipt, self.client.response_verifier, installation_id=self.client.installation_id,
                               client_instance_id=self.client.client_instance_id)
                if receipt.claim != claim:
                    raise WitnessHeld("Recorder witness receipt differs from its exact claim")
            return _ArchiveRecord(claim, index, receipt), raw
        except WitnessHeld:
            raise
        except Exception as exc:
            raise WitnessHeld("Recorder witness metadata is corrupt; originals were preserved") from exc

    def _document(self, record):
        raw = canonical(dict(schema=ARCHIVE_SCHEMA, installation_id=self.client.installation_id,
            client_instance_id=self.client.client_instance_id, claim=asdict(record.claim),
            index=[[row.row_id, row.digest] for row in record.index],
            receipt=None if record.receipt is None else asdict(record.receipt)))
        if len(raw) > MAX_METADATA:
            raise StorageHeld("Recorder witness metadata exceeds its byte bound")
        return raw

    def _write_new(self, path, raw):
        self._checkpoint()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with self._metadata_fd(path, flags) as descriptor:
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise OSError("Recorder witness write made no progress")
                view = view[count:]
            _fsync(descriptor)
        if not private_repair_file(path):
            raise WitnessHeld("Recorder witness created metadata without private custody")

    def _resync(self, path):
        before = _plain(path)
        with self._metadata_fd(path, os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)) as descriptor:
            held = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino) or held.st_nlink != 1:
                raise WitnessHeld("Recorder witness resync identity differs")
            _fsync(descriptor)

    def _load(self):
        total, names = self._inventory()
        records, tip = [], None
        for expected, (epoch, path) in enumerate(names, 1):
            if epoch != expected:
                raise WitnessHeld("Recorder witness historical archive is missing an epoch")
            record, _raw = self._read_metadata(path)
            if record.receipt is None or record.claim.epoch != epoch:
                raise WitnessHeld("Recorder witness archive lacks its independent receipt")
            admit_successor(record.claim, tip)
            digest = record.receipt.digest()
            if epoch in self._known and self._known[epoch] != digest:
                raise WitnessHeld("Recorder witness archived history forked")
            tip = record.receipt
            records.append(record)
        if any(epoch > len(records) for epoch in self._known):
            raise WitnessHeld("Recorder witness archive rolled back during this process")
        pending = None
        if os.path.lexists(self.archive_dir / "pending.json"):
            pending, _raw = self._read_metadata(self.archive_dir / "pending.json")
            if pending.receipt is not None:
                raise WitnessHeld("Recorder witness pending record has an unexpected receipt")
        self._known.update({record.claim.epoch: record.receipt.digest() for record in records})
        self._status = replace(self._status, archive_bytes=total, history_epochs=len(records), pending=pending is not None,
            last_sealed_epoch=0 if tip is None else tip.claim.epoch,
            last_sealed_row=0 if tip is None else tip.claim.last_id,
            verification_backlog_epochs=len(records) - len(self._checked))
        return total, records, tip, pending

    def _database(self):
        if self._db is None:
            _no_alias(self.db_path)
            _plain(self.db_path)
            connection = _connect_sqlite(self.db_path.as_uri() + "?mode=ro", uri=True, timeout=.05, isolation_level=None)
            self._db = connection
        if not self._db_ready:
            # Retain the exact connection even when admission fails, but never
            # reuse it as admitted on a later cycle. All configuration and
            # schema checks must complete before any recorder read proceeds.
            connection = self._db
            # setlimit is available from Python 3.11. SQL projections below
            # bound every returned field on supported Python 3.10 as well.
            # Runtime length limits are additional protection, not a reason to
            # silently disable witnessing on the older supported interpreter.
            set_limit = getattr(connection, "setlimit", None)
            category = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", None)
            has_runtime_limits = callable(set_limit) and type(category) is int
            if has_runtime_limits:
                set_limit(category, MAX_ROW_BYTES * 4)
            self._status = replace(self._status, sqlite_runtime_limits_available=has_runtime_limits)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA cache_size=-1024")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.set_progress_handler(lambda: int(self._stop.is_set() or time.monotonic() >= self._io_deadline), 1000)
            self._db_schema = self._schema_fingerprint(connection)
            self._db_ready = True
        return self._db

    def _schema_fingerprint(self, connection):
        table = connection.execute(
            "SELECT type, substr(sql,1,16385) FROM main.sqlite_schema WHERE name='events' AND tbl_name='events'").fetchone()
        if (table is None or table[0] != "table" or type(table[1]) is not str
                or len(table[1]) > 16384 or "VIRTUAL" in table[1].upper()):
            raise WitnessHeld("Recorder witness requires the actual ordinary events table")
        # Project before materialization: arbitrary column defaults and long
        # names/types must not escape these metadata bounds. SQLite's PK index
        # origin distinguishes INTEGER PRIMARY KEY DESC and WITHOUT ROWID from
        # a genuine INTEGER PRIMARY KEY alias for the table's integer rowid.
        columns = tuple(connection.execute(
            'SELECT cid,substr(name,1,257),length(name),substr(type,1,65),length(type),'
            '"notnull",pk,hidden FROM pragma_table_xinfo(\'events\',\'main\') LIMIT 65'))
        indices = tuple(connection.execute(
            'SELECT seq,substr(name,1,257),length(name),"unique",origin,partial '
            "FROM pragma_index_list('events','main') LIMIT 65"))
        # sqlite_schema rows are read from the snapshot too: restoring a
        # schema cookie must not hide new index SQL behind SQLite's cached
        # pragma metadata. Automatic indices legitimately have NULL SQL.
        index_definitions = tuple(connection.execute(
            'SELECT substr(name,1,257),length(name),substr(sql,1,16385),length(sql) '
            "FROM main.sqlite_schema WHERE tbl_name='events' AND type='index' ORDER BY name LIMIT 65"))
        if (not 1 <= len(columns) <= 64 or len(indices) > 64
                or len(index_definitions) > 64
                or any(type(row[1]) is not str or row[2] > 256
                       or type(row[3]) is not str or row[4] > 64 for row in columns)
                or any(type(row[1]) is not str or row[2] > 256 for row in indices)
                or any(type(row[0]) is not str or row[1] > 256
                       or row[2] is not None and (type(row[2]) is not str or row[3] > 16384)
                       for row in index_definitions)):
            raise WitnessHeld("Recorder table metadata exceeds its bounded ordinary schema")
        primary = [row for row in columns if row[6]]
        if (len(primary) != 1 or primary[0][1] != 'id' or primary[0][3].strip().upper() != 'INTEGER'
                or primary[0][6] != 1 or primary[0][7] != 0
                or any(row[4] == 'pk' for row in indices)):
            raise WitnessHeld("Recorder witness requires id to be an INTEGER PRIMARY KEY rowid alias")
        return table[1], columns, indices, index_definitions

    def _read_rows(self, first, last=None, *, capture=False):
        self._checkpoint()
        connection = self._database()
        connection.execute("BEGIN")
        try:
            # Schema cookies are writable. Re-read bounded metadata in this
            # committed snapshot rather than trusting a cached schema_version.
            if self._schema_fingerprint(connection) != self._db_schema:
                raise WitnessHeld("Recorder table schema changed after admission; witnessing is held")
            # SQLite affinity alone does not exclude hostile BLOB/text values
            # in nominally numeric payload columns. The proven rowid alias
            # makes MAX and the invalid-ID seek indexed, without whole-DB scans.
            tail = connection.execute("SELECT MAX(id) FROM main.events").fetchone()[0]
            invalid_id = connection.execute("SELECT id FROM main.events WHERE id<1 ORDER BY id LIMIT 1").fetchone()
            if invalid_id is not None:
                raise WitnessHeld("Recorder row ID floor is malformed")
            if tail is None:
                tail = 0
            if type(tail) is not int or not 0 <= tail <= 2**63 - 1:
                raise WitnessHeld("Recorder row ID floor is malformed")
            terminal = tail if last is None else last
            fields = ",".join(f"typeof({name}),length(CAST({name} AS BLOB)),substr(CAST({name} AS BLOB),1,{MAX_ROW_BYTES + 1})"
                              for name in ("module", "message", "details", "hmac_sig"))
            cursor = connection.execute(f"SELECT id,CASE WHEN typeof(ts) IN ('integer','real') THEN ts ELSE NULL END,"
                f"CASE WHEN typeof(severity)='integer' THEN severity ELSE NULL END,{fields} "
                "FROM main.events WHERE id>=? AND id<=? ORDER BY id LIMIT ?",
                                        (first, terminal, MAX_EPOCH_ROWS + 1))
            rows, size, more = [], 0, False
            for number, raw in enumerate(cursor):
                self._checkpoint()
                if number == MAX_EPOCH_ROWS:
                    if capture:
                        more = True
                        break
                    raise WitnessHeld("Recorder range has unexpected excess rows")
                values = []
                for index, name in enumerate(("module", "message", "details", "hmac_sig")):
                    kind, length, encoded = raw[3 + index * 3:6 + index * 3]
                    if name == "details" and kind == "null":
                        values.append(None)
                        continue
                    if kind != "text" or type(length) is not int or not 0 <= length <= MAX_ROW_BYTES or type(encoded) is not bytes or len(encoded) != length:
                        raise WitnessHeld("Recorder field is malformed or exceeds its bounded projection")
                    values.append(encoded.decode("utf-8", "strict"))
                row = (raw[0], raw[1], values[0], raw[2], values[1], values[2], values[3])
                row_size = len(canonical(row))
                if size + row_size > MAX_EPOCH_BYTES:
                    if capture and rows:
                        more = True
                        break
                    raise BudgetHeld("Recorder range exceeds its cooperative byte budget")
                size += row_size
                rows.append(row)
            connection.execute("COMMIT")
            return tuple(rows), tail, more
        except BaseException:
            connection.execute("ROLLBACK")
            raise

    def _verify_one(self, records):
        if not records:
            return
        record = records[self._verify_cursor % len(records)]
        rows, _tail, _more = self._read_rows(record.claim.first_id, record.claim.last_id)
        result = verify_row_range(record.receipt, record.index, rows, self.client.response_verifier,
            installation_id=self.client.installation_id, client_instance_id=self.client.client_instance_id)
        checked = time.monotonic()
        self._checked[record.claim.epoch] = checked
        self._missing[record.claim.epoch] = result.missing_rows
        self._status = replace(self._status, last_checked_epoch=record.claim.epoch,
            checked_first_id=record.claim.first_id, checked_last_id=record.claim.last_id,
            verified_rows=result.verified_rows, missing_rows=result.missing_rows,
            changed_rows=result.changed_rows, unexpected_rows=result.unexpected_rows,
            known_missing_rows=sum(self._missing.values()), last_verification_monotonic=checked,
            oldest_history_check_monotonic=min(self._checked.values()),
            verification_backlog_epochs=len(records) - len(self._checked))
        if result.state == "record-mismatch":
            raise WitnessHeld("Independently sealed recorder bytes changed; witness append is held")
        self._verify_cursor += 1

    def _verify_history(self, records):
        checked, exhausted = 0, False
        # At most 40,960 row slots per cycle, with a cooperative five-second
        # shared local-I/O budget. These are separate committed snapshots;
        # their timestamps/backlog do not claim one global current DB image.
        for _index in range(min(10, len(records))):
            try:
                self._verify_one(records)
            except BudgetHeld:
                exhausted = True
                break
            except sqlite3.OperationalError:
                if self._stop.is_set():
                    raise _Stopped()
                if time.monotonic() < self._io_deadline:
                    raise
                exhausted = True
                break
            checked += 1
        self._status = replace(self._status, history_ranges_checked_this_cycle=checked,
                               history_check_budget_exhausted=exhausted)

    def _finalize(self, pending, receipt, total):
        if receipt.claim != pending.claim:
            raise WitnessHeld("Recorder authority receipt differs from the durable pending claim")
        record = _ArchiveRecord(pending.claim, pending.index, receipt)
        raw = self._document(record)
        target = self.archive_dir / f"epoch-{receipt.claim.epoch:019d}.json"
        temporary = self.archive_dir / "write.tmp"
        if os.path.lexists(target):
            stored, _raw = self._read_metadata(target)
            if stored != record:
                raise WitnessHeld("Recorder archive destination conflicts with the committed receipt")
            self._resync(target)
        else:
            if not os.path.lexists(temporary):
                if total + len(raw) > self.archive_limit_bytes:
                    raise StorageHeld("Recorder witness lacks its reserved archive write space")
                self._write_new(temporary, raw)
            else:
                stored, _raw = self._read_metadata(temporary)
                if stored != record:
                    raise WitnessHeld("Recorder archive write recovery conflicts with its exact pending receipt")
                self._resync(temporary)
            _replace(temporary, target)
        # Only transaction scratch is removed. Historical epoch originals are
        # never retired or pruned by this worker.
        if os.path.lexists(temporary):
            stored, _raw = self._read_metadata(temporary)
            if stored != record:
                raise WitnessHeld("Recorder transaction scratch conflicts with its durable archive")
            temporary.unlink()
        (self.archive_dir / "pending.json").unlink()
        self._known[record.claim.epoch] = receipt.digest()

    def _step(self):
        self._io_deadline = time.monotonic() + 5.0
        self._checkpoint()
        self._admit_client()
        _no_alias(self.archive_dir)
        if not self.archive_dir.exists():
            if not private_directory(self.archive_dir, create=True):
                raise WitnessHeld("Recorder witness private archive could not be created")
        if self._lease is None:
            self._lease = ExclusiveFileLease(self.archive_dir / ".writer.lock")
        total, records, tip, pending = self._load()
        self._verify_history(records)
        if self._stop.is_set():
            raise _Stopped()
        remote = self.client.read_recorder_head()
        self._io_deadline = time.monotonic() + 5.0
        self._status = replace(self._status, last_authority_monotonic=time.monotonic(), authority_head_checked=True)
        if pending is not None:
            if tip is not None and pending.claim == tip.claim:
                if pending.index != records[-1].index or remote != tip:
                    raise WitnessHeld("Recorder completed pending state conflicts with current authority")
                self._finalize(pending, tip, total)
            else:
                admit_successor(pending.claim, tip)
                if remote == tip:
                    self._checkpoint()
                    receipt = self.client.append_recorder_epoch(pending.claim)
                    self._io_deadline = time.monotonic() + 5.0
                elif remote is not None and remote.claim == pending.claim:
                    receipt = remote
                else:
                    raise WitnessHeld("Recorder authority is ahead, behind or forked from exact pending state")
                self._finalize(pending, receipt, total)
            total, records, tip, pending = self._load()
        elif remote != tip:
            raise WitnessHeld("Recorder authority differs from local history and no exact pending commit can reconcile it")
        if os.path.lexists(self.archive_dir / "write.tmp"):
            raise WitnessHeld("Recorder witness has unexplained write scratch; originals were preserved")
        self._checkpoint()
        rows, tail, more = self._read_rows(1 if tip is None else tip.claim.last_id + 1, capture=True)
        self._status = replace(self._status, observed_database_tail=tail, unsealed_backlog=more)
        if rows:
            if len(records) >= MAX_ARCHIVES:
                raise StorageHeld("Recorder witness epoch count is full; review export or explicit archive policy")
            index = commit_rows(rows)
            record = _ArchiveRecord(claim_rows(index, current=tip), index, None)
            raw = self._document(record)
            # Reserve both the durable pending original and the complete final
            # receipt/index write before the remote append can commit.
            if total + len(raw) * 2 + 4096 > self.archive_limit_bytes:
                raise StorageHeld("Recorder witness archive budget is full; protection continues and no history was deleted")
            self._write_new(self.archive_dir / "pending.json", raw)
            self._status = replace(self._status, pending=True)
            self._checkpoint()
            receipt = self.client.append_recorder_epoch(record.claim)
            # A STOP arriving during RPC may leave this exact durable pending
            # claim for restart reconciliation; it is never discarded/reset.
            self._io_deadline = time.monotonic() + 5.0
            self._finalize(record, receipt, total + len(raw))
            total, records, tip, _pending = self._load()
        self._publish("coverage-loss" if self._status.known_missing_rows else "current",
            "Signed history includes unavailable rows; surviving bytes remain checked" if self._status.known_missing_rows else
            "Fresh authority head and bounded recorder witnessing completed; historical checking remains scoped",
            archive_bytes=total, history_epochs=len(records), pending=False,
            last_sealed_epoch=0 if tip is None else tip.claim.epoch, last_sealed_row=0 if tip is None else tip.claim.last_id,
            verification_backlog_epochs=len(records) - len(self._checked))

    def _run(self):
        self._owner = threading.get_ident()
        try:
            while not self._stop.is_set():
                self._status = replace(self._status, authority_head_checked=False)
                try:
                    self._step()
                except _Stopped:
                    break
                except _MetadataCloseHeld as exc:
                    self._publish("retirement-held", str(exc), cleanup_proven=False)
                    break
                except StorageHeld as exc:
                    self._publish("storage-held", str(exc))
                except BudgetHeld as exc:
                    self._publish("budget-held", str(exc))
                except HighWaterUnavailable:
                    self._publish("authority-unavailable", "Recorder authority is unavailable; pending metadata and history were preserved")
                except HighWaterRejected:
                    self._publish("authority-held", "Recorder authority rejected a claim or freshness proof; no history was reset")
                except (WitnessHeld, EpochRejected) as exc:
                    self._publish("integrity-held", str(exc))
                except Exception:
                    self._publish("witness-unavailable", "Optional recorder witnessing failed; originals were preserved and protection continues")
                self._wake.wait(self.interval)
                self._wake.clear()
        finally:
            for resource in (self._db, self._lease):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        self._cleanup_proven = False
            if not self._cleanup_proven:
                _RETIREMENT_HOLDS.append(self)
            self._publish("retiring" if self._cleanup_proven else "retirement-held",
                          "Recorder witness resources closed; owning reader exit is pending" if self._cleanup_proven else
                          "Recorder witness resource cleanup remains unproven; retain its owner",
                          thread_retired=False, cleanup_proven=self._cleanup_proven)
            self._retired.set()
