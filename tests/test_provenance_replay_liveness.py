"""Replay makes bounded, honest progress without stranding stopped generations."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from types import SimpleNamespace

from angerona.modules import provenance_graph


def _ledger(tmp_path, count=7):
    path = tmp_path / "events.db"
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, "
            "module TEXT, message TEXT, details TEXT)"
        )
        db.executemany(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?)",
            ((i, float(i), "sensor", "synthetic", json.dumps({"pid": i + 100}))
             for i in range(1, count + 1)),
        )
    module = provenance_graph.ProvenanceGraphModule()
    module._db_path = path
    module._DB_PAGE = 3
    # Row-limit assertions must not depend on test-host load.
    module._DB_SLICE_SECONDS = 60.0
    return module


def test_replay_pages_resume_without_skipping_or_reingesting(tmp_path):
    module = _ledger(tmp_path)
    seen = []
    module.graph.ingest = lambda _module, _message, details, _ts: seen.append(details["pid"])

    assert module._rebuild_from_db() == 3
    assert module._last_db_id == 3
    assert module._db_replay_pending
    module._update_source_health(3)
    assert module.health == 80
    assert "3/7" in module.health_note
    assert "complete" not in module.health_note
    assert module._rebuild_from_db() == 3
    assert module._rebuild_from_db() == 1
    assert module._rebuild_from_db() == 0
    assert seen == list(range(101, 108))
    assert not module._db_replay_pending
    module._update_source_health(0)
    assert module.health == 100


def test_replay_watermark_stays_finite_when_writer_appends(tmp_path):
    module = _ledger(tmp_path, count=4)
    module._DB_PAGE = 2
    assert module._rebuild_from_db() == 2
    assert module._db_replay_target == 4
    with closing(sqlite3.connect(module._db_path)) as db, db:
        db.execute("INSERT INTO events VALUES (5, 5.0, 'sensor', 'later', '{}')")

    assert module._rebuild_from_db() == 2
    assert module._last_db_id == module._db_replay_target == 4
    assert module._db_latest_id == 5
    assert module._db_replay_pending
    assert module._rebuild_from_db() == 1
    assert module._last_db_id == module._db_replay_target == 5


def test_stop_interrupts_current_page_without_advancing_unexamined_rows(tmp_path):
    module = _ledger(tmp_path)
    seen = []

    def ingest(*args):
        seen.append(args)
        module.stop()

    module.graph.ingest = ingest
    assert module._rebuild_from_db() == 1
    assert len(seen) == 1
    assert module._last_db_id == 1
    assert module._db_replay_pending
    assert module._rebuild_from_db() == 0
    assert module._last_db_id == 1


def test_replay_keeps_original_generation_stop_token(tmp_path):
    module = _ledger(tmp_path)
    original_stop = module.generation_stop_event()

    def ingest(*_args):
        original_stop.set()
        # Even an independently installed new generation token cannot revive
        # the old in-progress replay.
        module._stop = threading.Event()

    module.graph.ingest = ingest
    assert module._rebuild_from_db() == 1
    assert module._last_db_id == 1
    assert not module.stopping


def test_time_budget_yields_and_preserves_next_record(tmp_path, monkeypatch):
    module = _ledger(tmp_path)
    module._DB_SLICE_SECONDS = 0.25
    ticks = iter((100.0, 100.3))
    monkeypatch.setattr(provenance_graph.time, "monotonic", lambda: next(ticks))
    assert module._rebuild_from_db() == 1
    assert module._last_db_id == 1
    assert module._db_replay_pending


def test_malformed_rows_keep_gap_and_rejection_accounting_across_slices(tmp_path):
    module = _ledger(tmp_path, count=5)
    module._DB_PAGE = 2
    with closing(sqlite3.connect(module._db_path)) as db, db:
        db.execute("DELETE FROM events WHERE id = 2")
        db.execute("UPDATE events SET details = 'invalid-json' WHERE id = 3")
    assert module._rebuild_from_db() == 2
    assert module._last_db_id == 3
    assert module._db_gaps == module._db_rejected == 1
    module._update_source_health(2)
    assert module.health == 75
    assert "ledger catch-up at 3/5" in module.health_note
    assert module._rebuild_from_db() == 2
    assert module._last_db_id == 5
    assert module._db_gaps == module._db_rejected == 1


def test_removed_captured_range_stays_visible(tmp_path):
    module = _ledger(tmp_path)
    assert module._rebuild_from_db() == 3
    with closing(sqlite3.connect(module._db_path)) as db, db:
        db.execute("DELETE FROM events WHERE id > 4")
    assert module._rebuild_from_db() == 1
    assert module._last_db_id == 4
    assert module._db_source_resets == 1
    module._update_source_health(1)
    assert module.health == 75
    assert "1 source reset" in module.health_note


def test_source_replacement_replays_new_identity_from_start(tmp_path):
    module = _ledger(tmp_path)
    assert module._rebuild_from_db() == 3
    replacement = tmp_path / "replacement.db"
    with closing(sqlite3.connect(replacement)) as db, db:
        db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, module TEXT, message TEXT, details TEXT)")
        db.execute("INSERT INTO events VALUES (1, 1.0, 'new', 'new source', '{}')")
    replacement.replace(module._db_path)
    assert module._rebuild_from_db() == 1
    assert module._last_db_id == 1
    assert module._db_source_resets == 1
    assert not module._db_replay_pending


def test_run_marks_completed_slice_without_claiming_complete_coverage(tmp_path, monkeypatch):
    module = _ledger(tmp_path)
    from angerona.core import config
    monkeypatch.setattr(config, "Config", lambda: SimpleNamespace(db_path=module._db_path))
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    sleeps = []

    def sleep(interval):
        sleeps.append(interval)
        module.mark_cycle_complete(interval_seconds=interval)
        module.stop()

    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert sleeps == [module._CATCHUP_INTERVAL]
    assert module.first_cycle_complete
    assert module.health == 80
    assert "3/7" in module.health_note
    assert module._last_db_id == 3


def test_cancelled_run_does_not_publish_completed_slice(tmp_path, monkeypatch):
    module = _ledger(tmp_path)
    from angerona.core import config
    monkeypatch.setattr(config, "Config", lambda: SimpleNamespace(db_path=module._db_path))
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    module.graph.ingest = lambda *_args: module.stop()
    module.run()
    assert module._last_db_id == 1
    assert not module.first_cycle_complete
