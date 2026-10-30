"""Optional witnessing with real temporary SQLite and explicit test Ed authority."""
from __future__ import annotations

from dataclasses import replace
import itertools
import json
import sqlite3
import threading
import time
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.personal_sentinel_authority import (
    Ed25519PrivateSigner, Ed25519PublicVerifier, InProcessSentinelTransport,
    PersonalSentinelAuthority, PersonalSentinelAuthorityClient,
)
from angerona.core.recorder_epoch import MAX_EPOCH_ROWS, MAX_ROW_BYTES, claim_rows, commit_rows
from angerona.core import recorder_epoch_worker as worker_module


NOW = 1_800_000_000.0


def wait_for(worker, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = worker.latest_status()
        if predicate(status):
            return status
        time.sleep(.005)
    pytest.fail("Recorder witness did not reach expected state: " + repr(worker.latest_status()))


def cycle(worker, predicate):
    revision = worker.latest_status().revision
    assert worker.request_cycle()
    return wait_for(worker, lambda status: status.revision > revision and predicate(status))


@pytest.fixture
def stack(tmp_path):
    database = tmp_path / "records.db"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts REAL,module TEXT,severity INTEGER,message TEXT,details TEXT,hmac_sig TEXT)")
    connection.commit()
    request = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="host-request")
    signer = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="independent-authority")
    authority = PersonalSentinelAuthority(tmp_path / "authority.json", installation_id="a" * 32,
        client_instance_id="b" * 32, request_verifier=request.public_verifier(), response_signer=signer,
        response_verifier=signer.public_verifier(), enable_recorder_epochs=True, max_nonces=128, clock=lambda: NOW)
    nonces = itertools.count(1)
    client = PersonalSentinelAuthorityClient(installation_id="a" * 32, client_instance_id="b" * 32,
        request_signer=request, response_verifier=signer.public_verifier(),
        transport=InProcessSentinelTransport(authority, test_only=True), allow_test_transport=True,
        clock=lambda: NOW, nonce_factory=lambda: f"{next(nonces):043d}")
    result = SimpleNamespace(database=database, connection=connection, request=request, signer=signer,
        authority=authority, client=client, archive=tmp_path / "archive", workers=[], expected_held=set())
    try:
        yield result
    finally:
        for worker in result.workers:
            if id(worker) in result.expected_held:
                assert not worker.stop(10) and not worker.thread.is_alive()
            else:
                assert worker.stop(10), "actual retained epoch worker did not retire"
        connection.close()
        result.authority.close()


def append(stack, message="event", count=1, hmac_sig="c" * 64):
    stack.connection.executemany("INSERT INTO events(ts,module,severity,message,details,hmac_sig) VALUES(?,?,?,?,?,?)",
        [(NOW, "Fixture", int(Severity.MEDIUM), message, '{"x":1}', hmac_sig)] * count)
    stack.connection.commit()


def start(stack, **kwargs):
    worker = worker_module.RecorderEpochWorker(db_path=stack.database, archive_dir=stack.archive,
        client=stack.client, interval=3600, **kwargs)
    stack.workers.append(worker)
    assert worker.start()
    return worker


def test_unconfigured_worker_has_no_thread_files_or_network(tmp_path):
    worker = worker_module.RecorderEpochWorker(db_path=tmp_path / "not-created.db",
        archive_dir=tmp_path / "not-created-archive", client=None)
    assert worker.start() is False and worker.thread is None
    assert worker.latest_status().state == "disabled"
    assert not (tmp_path / "not-created-archive").exists() and worker.stop()


def test_lazy_known_provider_resolves_credentials_only_on_its_owned_worker(stack, monkeypatch):
    from angerona.core.recorder_integrity import ConfiguredWitnessProvider, DEFAULTS

    append(stack)
    values = {**DEFAULTS, "recorder_witness_installation_id": "a" * 32,
              "recorder_witness_client_id": "b" * 32, "recorder_witness_enabled": True}
    provider = ConfiguredWitnessProvider(values, stack.database.parent)
    main_thread, resolutions = threading.get_ident(), []
    def resolve(_self):
        resolutions.append(threading.get_ident())
        return stack.client
    monkeypatch.setattr(ConfiguredWitnessProvider, "_resolve", resolve)
    worker = worker_module.RecorderEpochWorker(db_path=stack.database, archive_dir=stack.archive,
        client=provider, interval=3600)
    stack.workers.append(worker)
    assert resolutions == [] and not stack.archive.exists()
    worker.start()
    wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    assert resolutions and all(value != main_thread for value in resolutions)


def test_provider_name_or_duck_methods_cannot_adopt_untrusted_client(stack):
    calls = []
    class Lookalike:
        @property
        def response_verifier(self):
            calls.append("untrusted property")
            return stack.signer.public_verifier()
    Lookalike.__name__ = "ConfiguredWitnessProvider"
    Lookalike.__module__ = "angerona.core.recorder_integrity"
    worker = worker_module.RecorderEpochWorker(db_path=stack.database, archive_dir=stack.archive,
        client=Lookalike(), interval=3600)
    stack.workers.append(worker)
    assert calls == []
    worker.start()
    status = wait_for(worker, lambda status: status.state == "integrity-held")
    assert "explicitly composed" in status.reason and calls == [] and not stack.archive.exists()


def test_direct_sdk_rejects_same_actual_request_and_authority_key_under_different_labels(stack):
    stack.client.response_verifier = Ed25519PublicVerifier(stack.request._private_key.public_key(),
                                                          key_id="different-authority-label")
    class NoRequest:
        def exchange(self, _body):
            pytest.fail("non-independent enrollment reached an authority")
    stack.client.transport = NoRequest()
    worker = start(stack)
    status = wait_for(worker, lambda status: status.state == "integrity-held")
    assert "not independently enrolled" in status.reason and not stack.archive.exists()


def test_python310_connection_without_runtime_limit_api_still_uses_bounded_sql_and_witnesses(stack, monkeypatch):
    class LegacyConnection(sqlite3.Connection):
        def __getattribute__(self, name):
            if name == "setlimit":
                raise AttributeError("modeled Python 3.10 API surface")
            return super().__getattribute__(name)
    connect = worker_module._connect_sqlite
    def legacy_connect(*args, **kwargs):
        return connect(*args, **kwargs, factory=LegacyConnection)
    monkeypatch.setattr(worker_module, "_connect_sqlite", legacy_connect)
    append(stack)
    worker = start(stack)
    status = wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    assert status.sqlite_runtime_limits_available is False
    # The supplemental API is absent, but the actual read-only connection and
    # all numeric/text projections still reject hostile values before sealing.
    stack.connection.execute("UPDATE events SET ts=?", (sqlite3.Binary(b"x" * (MAX_ROW_BYTES + 1)),))
    stack.connection.commit()
    cycle(worker, lambda status: status.state == "integrity-held")
    assert stack.client.read_recorder_head().claim.epoch == 1


def test_failed_database_setup_is_fully_readmitted_on_same_retained_connection(stack, monkeypatch):
    progress_calls, connections = [], []
    class FailOnceConnection(sqlite3.Connection):
        def set_progress_handler(self, callback, steps):
            progress_calls.append(steps)
            if len(progress_calls) == 1:
                raise sqlite3.OperationalError("modeled one-time progress-handler setup failure")
            return super().set_progress_handler(callback, steps)
    connect = worker_module._connect_sqlite
    def failing_connect(*args, **kwargs):
        connection = connect(*args, **kwargs, factory=FailOnceConnection)
        connections.append(connection)
        return connection
    monkeypatch.setattr(worker_module, "_connect_sqlite", failing_connect)
    append(stack)
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "witness-unavailable")
    assert stack.client.read_recorder_head() is None
    assert not tuple(stack.archive.glob("epoch-*.json"))
    cycle(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    assert progress_calls == [1000, 1000] and len(connections) == 1
    assert stack.client.read_recorder_head().claim.epoch == 1


def test_failed_events_table_admission_cannot_be_bypassed_by_retry(stack):
    append(stack)
    stack.connection.execute("ALTER TABLE events RENAME TO actual_events")
    stack.connection.execute("CREATE VIEW events AS SELECT * FROM actual_events")
    stack.connection.commit()
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "integrity-held")
    for _attempt in range(2):
        status = cycle(worker, lambda status: status.state == "integrity-held")
        assert "ordinary events table" in status.reason
        assert stack.client.read_recorder_head() is None
        assert not tuple(stack.archive.glob("epoch-*.json"))
        assert not (stack.archive / "pending.json").exists()
    # A genuine operator repair can be admitted on the retained connection;
    # retries do not silently treat the previously rejected view as a table.
    stack.connection.execute("DROP VIEW events")
    stack.connection.execute("ALTER TABLE actual_events RENAME TO events")
    stack.connection.commit()
    cycle(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    assert stack.client.read_recorder_head().claim.epoch == 1


def test_40000_row_history_uses_indexed_seeks_with_bounded_vm_work(stack, monkeypatch):
    append(stack, count=40_000)
    vm_instructions = []
    class BudgetedConnection(sqlite3.Connection):
        def set_progress_handler(self, callback, steps):
            def bounded_progress():
                vm_instructions.append(steps)
                # The former CASE/MAX aggregates exceed this limit on their
                # first full-table scan. Ten bounded history reads fit here.
                return int(sum(vm_instructions) > 50_000 or callback())
            return super().set_progress_handler(bounded_progress, steps)
    connect = worker_module._connect_sqlite
    monkeypatch.setattr(worker_module, "_connect_sqlite",
        lambda *args, **kwargs: connect(*args, **kwargs, factory=BudgetedConnection))
    worker = worker_module.RecorderEpochWorker(db_path=stack.database, archive_dir=stack.archive,
        client=stack.client, interval=3600)
    # Exercise actual production SQL with real SQLite under an inert current
    # owner. No authority request/archive/thread is needed for a VM work bound.
    worker._owner = threading.get_ident()
    worker._io_deadline = time.monotonic() + 10
    try:
        for index in range(10):
            first = index * 4000 + 1
            rows, tail, more = worker._read_rows(first, first)
            assert len(rows) == 1 and rows[0][0] == first and tail == 40_000 and not more
        assert vm_instructions and sum(vm_instructions) <= 50_000
        for statement in ("SELECT MAX(id) FROM main.events",
                          "SELECT id FROM main.events WHERE id<1 ORDER BY id LIMIT 1",
                          "SELECT id FROM main.events WHERE id>=1 AND id<=1 ORDER BY id LIMIT 4097"):
            plan = " ".join(row[3] for row in worker._db.execute("EXPLAIN QUERY PLAN " + statement)).upper()
            assert "SEARCH" in plan and "SCAN" not in plan
    finally:
        if worker._db is not None:
            worker._db.close()


@pytest.mark.parametrize("id_definition,suffix", [
    ("id INTEGER PRIMARY KEY DESC", ""),
    ("id INTEGER,", ",PRIMARY KEY(id,ts)"),
    ("id INTEGER PRIMARY KEY", " WITHOUT ROWID"),
    ("id INT PRIMARY KEY", ""),
    ("id TEXT PRIMARY KEY", ""),
    ("id", ""),
])
def test_non_rowid_alias_schemas_remain_held_across_retries(stack, id_definition, suffix):
    stack.connection.execute("DROP TABLE events")
    # The composite fixture's comma is a marker so its table constraint stays
    # inside the closing parenthesis; all other suffixes follow the table.
    composite = suffix.startswith(",PRIMARY")
    head = id_definition.rstrip(",")
    columns = head + ",ts REAL,module TEXT,severity INTEGER,message TEXT,details TEXT,hmac_sig TEXT"
    sql = "CREATE TABLE events(" + columns + (suffix if composite else "") + ")" + ("" if composite else suffix)
    stack.connection.execute(sql)
    stack.connection.commit()
    worker = start(stack)
    for _attempt in range(2):
        status = (wait_for(worker, lambda value: value.state == "integrity-held") if _attempt == 0 else
                  cycle(worker, lambda value: value.state == "integrity-held"))
        assert "rowid alias" in status.reason
        assert stack.client.read_recorder_head() is None
        assert not (stack.archive / "pending.json").exists()


@pytest.mark.parametrize("invalid_id", [0, -1])
def test_indexed_id_floor_seek_rejects_zero_or_negative_id_even_with_a_positive_tail(stack, invalid_id):
    append(stack)
    stack.connection.execute("INSERT INTO events(id,ts,module,severity,message,details,hmac_sig) VALUES(?,?,?,?,?,?,?)",
        (invalid_id, NOW, "Fixture", 30, "non-positive identity", "{}", "c" * 64))
    stack.connection.commit()
    worker = start(stack)
    status = wait_for(worker, lambda value: value.state == "integrity-held")
    assert "ID floor" in status.reason and stack.client.read_recorder_head() is None
    assert not (stack.archive / "pending.json").exists()


@pytest.mark.parametrize("replacement", ["view", "new-rowid-table", "index"])
def test_each_read_rechecks_schema_metadata_even_after_schema_cookie_replay(stack, replacement):
    append(stack)
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    schema_version = stack.connection.execute("PRAGMA schema_version").fetchone()[0]
    if replacement == "index":
        stack.connection.execute("CREATE INDEX altered_message_index ON events(message)")
    else:
        stack.connection.execute("ALTER TABLE events RENAME TO original_events")
        if replacement == "view":
            stack.connection.execute("CREATE VIEW events AS SELECT * FROM original_events")
        else:
            stack.connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY,ts REAL,module TEXT,severity INTEGER,message TEXT,details TEXT,hmac_sig TEXT)")
            stack.connection.execute("INSERT INTO events SELECT * FROM original_events")
    stack.connection.execute("PRAGMA schema_version=" + str(schema_version))
    stack.connection.commit()
    status = cycle(worker, lambda value: value.state == "integrity-held")
    assert "schema" in status.reason or "ordinary events table" in status.reason
    assert stack.client.read_recorder_head().claim.epoch == 1
    assert not (stack.archive / "pending.json").exists()


def test_real_witness_archives_metadata_only_and_preserves_database_and_host_key(stack):
    append(stack, "private event text that must stay local")
    key = stack.database.parent / "bus.key"
    key.write_bytes(b"original fixture host key")
    rows_before = tuple(stack.connection.execute("SELECT * FROM events ORDER BY id"))
    main_thread = threading.get_ident()
    observer_threads = []
    worker = start(stack, on_status=lambda _status: observer_threads.append(threading.get_ident()))
    status = wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    assert status.history_epochs == 1 and status.verification_backlog_epochs == 1
    assert status.authority_head_checked and status.physical_independence_verified is False
    assert status.producer_authenticity_verified is status.protection_authority is False
    files = tuple(stack.archive.glob("epoch-*.json"))
    assert len(files) == 1 and not (stack.archive / "pending.json").exists()
    archive = json.loads(files[0].read_bytes())
    assert archive["receipt"]["claim"]["count"] == 1 and len(archive["index"]) == 1
    assert "private event text" not in files[0].read_text()
    assert stack.client.read_recorder_head().claim.epoch == 1
    assert tuple(stack.connection.execute("SELECT * FROM events ORDER BY id")) == rows_before
    assert key.read_bytes() == b"original fixture host key"
    assert observer_threads and all(value != main_thread for value in observer_threads)
    assert worker.thread.daemon is False
    assert worker.stop(5) and worker.latest_status().thread_retired


def test_periodic_control_coalesces_manual_refresh_and_reports_scoped_history_backlog(stack):
    append(stack, count=MAX_EPOCH_ROWS + 2)
    worker = start(stack)
    first = wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == MAX_EPOCH_ROWS)
    assert first.unsealed_backlog and first.verification_backlog_epochs == 1
    second = cycle(worker, lambda status: status.state == "current" and status.last_sealed_row == MAX_EPOCH_ROWS + 2)
    assert second.last_checked_epoch == 1 and second.verified_rows == MAX_EPOCH_ROWS
    assert not second.unsealed_backlog and second.verification_backlog_epochs == 1
    third = cycle(worker, lambda status: status.state == "current" and status.verification_backlog_epochs == 0)
    assert third.verification_backlog_epochs == 0 and third.oldest_history_check_monotonic is not None
    assert third.history_ranges_checked_this_cycle == 2
    assert third.last_verification_monotonic >= third.oldest_history_check_monotonic


def test_valid_large_capture_seals_byte_bounded_prefix_and_keeps_catching_up(stack, monkeypatch):
    # Exercise the production split without allocating multi-megabyte fixtures.
    monkeypatch.setattr(worker_module, "MAX_EPOCH_BYTES", 1024)
    append(stack, "bounded event " * 10, count=10)
    worker = start(stack)
    first = wait_for(worker, lambda status: status.state == "current" and status.last_sealed_epoch == 1)
    assert 0 < first.last_sealed_row < 10 and first.unsealed_backlog
    second = cycle(worker, lambda status: status.state == "current" and status.last_sealed_epoch == 2)
    assert first.last_sealed_row < second.last_sealed_row <= 10
    assert len(tuple(stack.archive.glob("epoch-*.json"))) == 2


@pytest.mark.parametrize("restart", [False, True])
def test_remote_commit_reply_loss_reconciles_exact_pending_without_duplicate_epoch(stack, restart):
    append(stack)
    original = stack.client.transport
    class LoseAppendReply:
        lost = False
        def exchange(self, body):
            response = original.exchange(body)
            if json.loads(body)["operation"] == "recorder-append" and not self.lost:
                self.lost = True
                raise OSError("modeled reply loss after real durable authority commit")
            return response
    stack.client.transport = LoseAppendReply()
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "authority-unavailable" and status.pending)
    pending_original = (stack.archive / "pending.json").read_bytes()
    assert json.loads(pending_original)["receipt"] is None
    stack.client.transport = original
    assert stack.client.read_recorder_head().claim.epoch == 1
    if restart:
        assert worker.stop(5)
        worker = start(stack)
        wait_for(worker, lambda status: status.state == "current" and status.last_sealed_epoch == 1)
    else:
        cycle(worker, lambda status: status.state == "current" and status.last_sealed_epoch == 1)
    assert not (stack.archive / "pending.json").exists()
    assert len(tuple(stack.archive.glob("epoch-*.json"))) == 1
    assert stack.client.read_recorder_head().claim.epoch == 1


@pytest.mark.parametrize("failure", ["fsync", "rename"])
def test_local_publication_failure_keeps_pending_and_recovers_only_matching_signed_head(stack, monkeypatch, failure):
    append(stack)
    sync, rename = worker_module._fsync, worker_module._replace
    calls = []
    def failing_sync(descriptor):
        calls.append("fsync")
        if failure == "fsync" and len(calls) == 2:
            raise OSError("modeled final archive fsync failure")
        return sync(descriptor)
    def failing_rename(source, destination):
        if failure == "rename":
            raise OSError("modeled archive rename failure")
        return rename(source, destination)
    monkeypatch.setattr(worker_module, "_fsync", failing_sync)
    monkeypatch.setattr(worker_module, "_replace", failing_rename)
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "witness-unavailable" and status.pending)
    assert (stack.archive / "pending.json").exists() and (stack.archive / "write.tmp").exists()
    assert stack.client.read_recorder_head().claim.epoch == 1
    assert worker.stop(5)
    monkeypatch.setattr(worker_module, "_fsync", sync)
    monkeypatch.setattr(worker_module, "_replace", rename)
    recovered = start(stack)
    wait_for(recovered, lambda status: status.state == "current" and status.last_sealed_epoch == 1)
    assert not (stack.archive / "pending.json").exists() and not (stack.archive / "write.tmp").exists()
    assert stack.client.read_recorder_head().claim.epoch == 1


def test_outage_does_not_create_pending_or_block_other_recorder_writes(stack):
    append(stack)
    original = stack.client.transport
    class Offline:
        def exchange(self, _body):
            raise OSError("modeled authority outage")
    stack.client.transport = Offline()
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "authority-unavailable")
    assert not (stack.archive / "pending.json").exists()
    append(stack, "protection writer still operates")
    stack.client.transport = original
    cycle(worker, lambda status: status.state == "current" and status.last_sealed_row == 2)


def test_legitimate_pruning_is_explicit_loss_while_surviving_signed_rows_remain_verified(stack):
    append(stack, count=3)
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 3)
    stack.connection.execute("DELETE FROM events WHERE id=2")
    stack.connection.commit()
    result = cycle(worker, lambda status: status.state == "coverage-loss")
    assert result.missing_rows == result.known_missing_rows == 1 and result.verified_rows == 2
    assert result.changed_rows == 0 and result.last_checked_epoch == 1
    assert len(tuple(stack.archive.glob("epoch-*.json"))) == 1


def test_retagged_historical_row_with_real_stolen_host_key_still_stops_new_witness_appends(stack):
    host = BusAuthority(b"k" * 32)
    original = Event("Fixture", "event", Severity.MEDIUM, ts=NOW, details={"x": 1})
    append(stack, hmac_sig=host.sign(original))
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    forged = replace(original, message="forged history")
    signature = host.sign(forged)
    assert host.verify(replace(forged, hmac_sig=signature))
    stack.connection.execute("UPDATE events SET message=?,hmac_sig=? WHERE id=1", (forged.message, signature))
    stack.connection.commit()
    append(stack, "unsealed later row")
    status = cycle(worker, lambda status: status.state == "integrity-held" and status.changed_rows == 1)
    assert status.last_sealed_epoch == 1 and status.last_sealed_row == 1
    assert stack.client.read_recorder_head().claim.epoch == 1 and not (stack.archive / "pending.json").exists()


def test_remote_ahead_without_pending_never_rebaselines_or_overwrites_history(stack):
    append(stack)
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    original_file, = stack.archive.glob("epoch-*.json")
    original_bytes = original_file.read_bytes()
    append(stack, "different authorized client advanced remotely")
    rows = tuple(stack.connection.execute("SELECT * FROM events WHERE id=2"))
    head = stack.client.read_recorder_head()
    stack.client.append_recorder_epoch(claim_rows(commit_rows(rows), current=head))
    status = cycle(worker, lambda status: status.state == "integrity-held")
    assert "no exact pending" in status.reason and original_file.read_bytes() == original_bytes
    assert len(tuple(stack.archive.glob("epoch-*.json"))) == 1


def test_corrupt_or_missing_historical_metadata_never_becomes_a_clean_baseline(stack):
    append(stack)
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "current" and status.last_sealed_row == 1)
    path, = stack.archive.glob("epoch-*.json")
    document = json.loads(path.read_bytes())
    document["index"][0][1] = "d" * 64
    path.write_text(json.dumps(document), encoding="utf-8")
    cycle(worker, lambda status: status.state == "integrity-held")
    assert stack.client.read_recorder_head().claim.epoch == 1
    assert path.exists() and json.loads(path.read_bytes())["index"][0][1] == "d" * 64


def test_archive_storage_budget_holds_only_optional_witness_without_deleting_history(stack):
    append(stack)
    worker = start(stack, archive_limit_bytes=4096)
    status = wait_for(worker, lambda status: status.state == "storage-held")
    assert "protection continues" in status.reason
    assert not (stack.archive / "pending.json").exists() and stack.client.read_recorder_head() is None
    assert status.archive_bytes <= status.archive_limit_bytes
    append(stack, "writer remains independent")
    assert stack.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2


def test_oversized_sqlite_field_is_held_before_archive_or_authority_append(stack):
    append(stack, "x" * (MAX_ROW_BYTES + 1))
    worker = start(stack)
    status = wait_for(worker, lambda status: status.state == "integrity-held")
    assert "bounded projection" in status.reason
    assert stack.client.read_recorder_head() is None and not (stack.archive / "pending.json").exists()
    assert stack.connection.execute("SELECT length(message) FROM events").fetchone()[0] == MAX_ROW_BYTES + 1


@pytest.mark.parametrize("field", ["ts", "severity"])
def test_malicious_numeric_column_blob_is_not_returned_as_an_unbounded_python_value(stack, field):
    append(stack)
    # These are fixed fixture-owned column names, never imported SQL text.
    stack.connection.execute(f"UPDATE events SET {field}=?", (sqlite3.Binary(b"x" * (MAX_ROW_BYTES + 1)),))
    stack.connection.commit()
    worker = start(stack)
    wait_for(worker, lambda status: status.state == "integrity-held")
    assert stack.client.read_recorder_head() is None and not (stack.archive / "pending.json").exists()


def test_malicious_noninteger_id_schema_never_materializes_its_blob_as_maximum_id(stack):
    stack.connection.execute("DROP TABLE events")
    stack.connection.execute("CREATE TABLE events(id TEXT,ts REAL,module TEXT,severity INTEGER,message TEXT,details TEXT,hmac_sig TEXT)")
    stack.connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
        (sqlite3.Binary(b"x" * (MAX_ROW_BYTES + 1)), NOW, "Fixture", 30, "event", "{}", "c" * 64))
    stack.connection.commit()
    worker = start(stack)
    status = wait_for(worker, lambda status: status.state == "integrity-held")
    assert "rowid alias" in status.reason and stack.client.read_recorder_head() is None
    assert not (stack.archive / "pending.json").exists()


def test_stop_retains_inflight_owned_reader_and_source_database_until_real_exit(stack):
    append(stack)
    original = stack.client.transport
    entered, release = threading.Event(), threading.Event()
    class BlockedRead:
        def exchange(self, body):
            entered.set()
            assert release.wait(5)
            return original.exchange(body)
    stack.client.transport = BlockedRead()
    worker = start(stack)
    try:
        assert entered.wait(5)
        assert worker.stop(.01) is False and worker.thread.is_alive()
        assert worker.latest_status().thread_retired is False
        append(stack, "original writer remains usable while owned witness drains")
    finally:
        release.set()
        assert worker.stop(5)
    assert worker.latest_status().thread_retired and worker.latest_status().cleanup_proven


def test_second_local_writer_cannot_replace_the_single_archive_owner(stack):
    append(stack)
    first = start(stack)
    wait_for(first, lambda status: status.state == "current")
    second = start(stack)
    wait_for(second, lambda status: status.state == "witness-unavailable")
    assert second.latest_status().last_sealed_epoch == 0
    assert len(tuple(stack.archive.glob("epoch-*.json"))) == 1
    assert stack.client.read_recorder_head().claim.epoch == 1


def test_metadata_close_uncertainty_is_sticky_without_retrying_a_reused_descriptor(stack, monkeypatch):
    append(stack)
    real_close = worker_module._close_fd
    calls = []
    def ambiguous(descriptor):
        calls.append(descriptor)
        # Model a close which took effect before its error became observable.
        real_close(descriptor)
        raise OSError("modeled ambiguous metadata descriptor close")
    monkeypatch.setattr(worker_module, "_close_fd", ambiguous)
    worker = start(stack)
    stack.expected_held.add(id(worker))
    status = wait_for(worker, lambda status: status.state == "retirement-held")
    worker.thread.join(5)
    assert not worker.thread.is_alive() and not worker.stop()
    assert not status.cleanup_proven and not worker.latest_status().cleanup_proven
    assert len(calls) == 1 and len(worker._metadata_owners) == 1
    owner, = worker._metadata_owners
    assert owner.descriptor is None and owner.ambiguous_descriptor == calls[0] and not owner.close_proven
    assert worker in worker_module._RETIREMENT_HOLDS
    for _ in range(2):
        assert worker.stop() is False
    assert len(calls) == 1
    replacement = worker_module.RecorderEpochWorker(db_path=stack.database, archive_dir=stack.archive,
        client=stack.client, interval=3600)
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        replacement.start()


def test_native_metadata_creation_uncertainty_retains_worker_before_any_authority_append(stack, monkeypatch):
    from angerona.core.recorder_metadata_custody import MetadataCreationUncertain
    append(stack)
    retained = SimpleNamespace(raw_handle=900, descriptor=None, transfer_pending=True)
    calls = []
    def uncertain(path, flags, mode):
        calls.append((path.name, flags, mode))
        raise MetadataCreationUncertain(retained)
    monkeypatch.setattr(worker_module, "open_private_metadata", uncertain)
    worker = start(stack)
    stack.expected_held.add(id(worker))
    wait_for(worker, lambda status: status.state == "retirement-held")
    worker.thread.join(5)
    assert not worker.thread.is_alive() and not worker.stop()
    assert worker._creation_owners == [retained] and calls[0][0] == ".writer.lock" and len(calls) == 1
    assert stack.client.read_recorder_head() is None and not (stack.archive / "pending.json").exists()
    append(stack, "protection writer remains usable while optional native creation is held")
    assert stack.connection.execute("SELECT count(*) FROM events").fetchone()[0] == 2
    replacement = worker_module.RecorderEpochWorker(db_path=stack.database, archive_dir=stack.archive,
        client=stack.client, interval=3600)
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        replacement.start()
