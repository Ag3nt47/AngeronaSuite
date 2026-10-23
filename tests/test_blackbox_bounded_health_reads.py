"""Black Box file bounds preserve evidence gaps and fresh live failures."""
from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt

import blackbox_recorder as blackbox


class TracedStream:
    """A short-reading, read-only stream with observable closure and faults."""

    def __init__(self, data, *, piece=7, fail_after=None, mutate=None):
        self.data = data
        self.piece = piece
        self.fail_after = fail_after
        self.mutate = mutate
        self.position = 0
        self.requests = []
        self.request_positions = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def read(self, size):
        assert not self.closed
        assert 0 < size <= blackbox.MAX_DIAGNOSTIC_READ_BYTES
        self.requests.append(size)
        self.request_positions.append(self.position)
        if self.fail_after is not None and self.position >= self.fail_after:
            raise OSError("inert read interruption after an accepted prefix")
        if self.mutate is not None and len(self.requests) == 2:
            self.data = self.mutate(self.data)
        end = self.position + min(size, self.piece)
        result = self.data[self.position:end]
        self.position += len(result)
        return result


class ReadOnlyPath:
    def __init__(self, stream=None, *, failure=None):
        self.stream = stream
        self.failure = failure
        self.modes = []

    def open(self, mode):
        self.modes.append(mode)
        assert mode == "rb"
        if self.failure is not None:
            raise self.failure
        return self.stream

    def stat(self):
        raise AssertionError("A path-size shortcut cannot prove pseudo-file contents")


def status_path(monkeypatch, stream):
    path = ReadOnlyPath(stream)
    monkeypatch.setattr(blackbox.SuiteHealthWorker, "_pick_status", staticmethod(lambda: path))
    return path


@pytest.mark.parametrize("piece", [1, 7, 65_536])
def test_status_small_reads_preserve_complete_dictionary_and_close(monkeypatch, piece):
    expected = {"modules": [{"name": "Live", "last_error": "literal <b>text</b>"}]}
    stream = TracedStream(json.dumps(expected).encode(), piece=piece)
    path = status_path(monkeypatch, stream)
    assert blackbox.SuiteHealthWorker._read_status() == expected
    assert stream.closed and path.modes == ["rb"]
    assert stream.position == len(stream.data)
    assert stream.requests and max(stream.requests) <= blackbox.MAX_DIAGNOSTIC_READ_BYTES


@pytest.mark.parametrize("failure", [FileNotFoundError("inert"), PermissionError("inert")])
def test_status_open_failure_remains_unknown_without_creating_a_file(monkeypatch, failure):
    path = ReadOnlyPath(failure=failure)
    monkeypatch.setattr(blackbox.SuiteHealthWorker, "_pick_status", staticmethod(lambda: path))
    assert blackbox.SuiteHealthWorker._read_status() == {}
    assert path.modes == ["rb"]


@pytest.mark.parametrize("extra", [0, 1])
def test_default_status_cap_keeps_small_requests_and_the_existing_acceptance_limit(monkeypatch, extra):
    raw = b'{"observed":true}'
    limit = blackbox.MAX_STATUS_BYTES
    stream = TracedStream(raw + b" " * (limit - len(raw) + extra), piece=65_536)
    status_path(monkeypatch, stream)
    assert blackbox.SuiteHealthWorker._read_status() == ({"observed": True} if extra == 0 else {})
    assert max(stream.requests) <= 65_536
    assert stream.position == limit + extra and stream.closed


@pytest.mark.parametrize("extra,accepted", [(0, True), (1, False), (500, False)])
def test_status_exact_cap_and_oversize_sentinel(monkeypatch, extra, accepted):
    monkeypatch.setattr(blackbox, "MAX_STATUS_BYTES", 64)
    monkeypatch.setattr(blackbox, "MAX_DIAGNOSTIC_READ_BYTES", 16)
    stream = TracedStream(b'{"observed":true}' + b" " * (47 + extra), piece=5)
    assert len(stream.data) == 64 + extra
    status_path(monkeypatch, stream)
    result = blackbox.SuiteHealthWorker._read_status()
    assert result == ({"observed": True} if accepted else {})
    assert stream.position == (64 if accepted else 65)
    assert stream.closed
    assert max(stream.requests) <= 16
    assert all(position + size <= 65 for position, size in
               zip(stream.request_positions, stream.requests))
    if accepted:
        assert stream.requests[-1] == 1


@pytest.mark.parametrize("raw", [b"", b"{", b"null", b"[]", b'"text"', b"\xff"])
def test_status_invalid_or_nondictionary_evidence_remains_unknown(monkeypatch, raw):
    stream = TracedStream(raw)
    status_path(monkeypatch, stream)
    assert blackbox.SuiteHealthWorker._read_status() == {}
    assert stream.closed


def test_partial_status_read_failure_never_parses_valid_prefix(monkeypatch):
    stream = TracedStream(b'{"valid_prefix":true}', piece=100, fail_after=1)
    status_path(monkeypatch, stream)
    parsed = []

    def forbidden_parse(_raw):
        parsed.append(True)
        raise AssertionError("A partially failed read must never reach the JSON parser")

    monkeypatch.setattr(blackbox.json, "loads", forbidden_parse)
    assert blackbox.SuiteHealthWorker._read_status() == {}
    assert parsed == [] and stream.closed


@pytest.mark.parametrize("mutation", ["append", "truncate"])
def test_status_consumes_changes_through_eof_without_accepting_incomplete_json(monkeypatch, mutation):
    raw = b'{"module":"original"}'
    mutate = (lambda prior: prior + b" trailing bytes") if mutation == "append" else (
        lambda prior: prior[:4]
    )
    stream = TracedStream(raw, piece=2, mutate=mutate)
    status_path(monkeypatch, stream)
    assert blackbox.SuiteHealthWorker._read_status() == {}
    assert len(stream.requests) >= 2 and stream.closed


def test_status_append_at_cap_is_rejected_by_the_sentinel(monkeypatch):
    raw = b'{"at_cap":true}'
    monkeypatch.setattr(blackbox, "MAX_STATUS_BYTES", len(raw))
    stream = TracedStream(raw, piece=len(raw), mutate=lambda prior: prior + b" ")
    status_path(monkeypatch, stream)
    assert blackbox.SuiteHealthWorker._read_status() == {}
    assert stream.position == len(raw) + 1 and stream.requests[-1] == 1
    assert stream.closed


@pytest.mark.parametrize("shape", ["dictionary", "list"])
def test_both_historical_schemas_retain_rows_and_diagnostic_only_context(monkeypatch, shape):
    failures = [{"module": "Earlier", "detail": "literal <img src=none>"}]
    value = {"failures": failures, "passed": 3, "failed": 1, "generated": "fixture"}
    if shape == "list":
        value = failures
    stream = TracedStream(json.dumps(value).encode())
    path = ReadOnlyPath(stream)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", path)
    rows, meta, note = blackbox._read_selftest_report()
    assert rows == [{"name": "Earlier", "detail": "literal <img src=none>",
                     "src": "selftest (historical)"}]
    assert meta == (value if shape == "dictionary" else {})
    assert "1 failure record(s)" in note
    assert "does not establish current module health" in note
    assert stream.closed and path.modes == ["rb"]


@pytest.mark.parametrize("extra,accepted", [(0, True), (1, False), (500, False)])
def test_history_has_an_independent_cap_and_one_sentinel(monkeypatch, extra, accepted):
    monkeypatch.setattr(blackbox, "MAX_STATUS_BYTES", 1)
    monkeypatch.setattr(blackbox, "MAX_SELFTEST_BYTES", 64)
    monkeypatch.setattr(blackbox, "MAX_DIAGNOSTIC_READ_BYTES", 16)
    raw = b'[{"module":"Earlier","detail":"observed"}]'
    stream = TracedStream(raw + b" " * (64 - len(raw) + extra), piece=5)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    rows, _meta, note = blackbox._read_selftest_report()
    assert bool(rows) is accepted
    assert ("exceeds" in note) is not accepted
    assert stream.position == (64 if accepted else 65)
    assert all(position + size <= 65 for position, size in
               zip(stream.request_positions, stream.requests))
    assert stream.closed
    if accepted:
        assert stream.requests[-1] == 1


def test_oversize_history_is_never_parsed_or_read_completely(monkeypatch):
    monkeypatch.setattr(blackbox, "MAX_SELFTEST_BYTES", 64)
    monkeypatch.setattr(blackbox, "MAX_DIAGNOSTIC_READ_BYTES", 16)
    stream = TracedStream(b" " * 4096)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))

    def forbidden_parse(_raw):
        raise AssertionError("Oversize history must be rejected before parsing")

    monkeypatch.setattr(blackbox.json, "loads", forbidden_parse)
    rows, meta, note = blackbox._read_selftest_report()
    assert rows == [] and meta == {} and "exceeds" in note
    assert stream.position == 65 and stream.closed


def test_partial_history_read_failure_keeps_the_complete_prefix_unaccepted(monkeypatch):
    raw = b'[{"module":"Earlier","detail":"prefix must not be admitted"}]'
    stream = TracedStream(raw, piece=len(raw), fail_after=1)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))

    def forbidden_parse(_raw):
        raise AssertionError("Partial read failure must not admit historical rows")

    monkeypatch.setattr(blackbox.json, "loads", forbidden_parse)
    rows, meta, note = blackbox._read_selftest_report()
    assert rows == [] and meta == {} and "could not be read" in note
    assert stream.closed


@pytest.mark.parametrize("raw", [b"", b"{", b"null", b"{}", b'{"failures":null}',
                                  b'{"failures":"invalid"}', b'"text"'])
def test_invalid_history_is_an_explicit_gap_not_a_healthy_report(monkeypatch, raw):
    stream = TracedStream(raw)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    rows, meta, note = blackbox._read_selftest_report()
    assert rows == [] and meta == {}
    assert note.startswith("Unavailable:")
    assert "current module health is separate" in note
    assert stream.closed


def test_history_display_limits_are_explicit_and_rows_remain_plain_data(monkeypatch):
    failures = [None] + [{"name": "N" * 300, "detail": "D" * 2500} for _ in range(501)]
    stream = TracedStream(json.dumps(failures).encode(), piece=65_536)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    rows, _meta, note = blackbox._read_selftest_report()
    assert len(rows) == 500
    assert all(len(row["name"]) == 200 and len(row["detail"]) == 2000 for row in rows)
    assert "501 failure record(s)" in note and "first 500" in note
    assert "1 malformed row(s) omitted (incomplete evidence)" in note
    assert stream.closed


@pytest.mark.parametrize("shape", [[], {"failures": []}])
def test_empty_supported_history_does_not_claim_current_health(monkeypatch, shape):
    stream = TracedStream(json.dumps(shape).encode())
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    rows, _meta, note = blackbox._read_selftest_report()
    assert rows == [] and "0 failure record(s)" in note
    assert "does not establish current module health" in note


def test_historical_utf8_replacement_policy_is_retained(monkeypatch):
    stream = TracedStream(b'[{"module":"Earlier","detail":"bad byte: \xff"}]')
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    rows, _meta, note = blackbox._read_selftest_report()
    assert rows[0]["detail"] == "bad byte: \ufffd"
    assert "Loaded historical report" in note
    assert stream.closed


def configure_live_health(monkeypatch):
    process = SimpleNamespace(
        oneshot=nullcontext, status=lambda: blackbox.psutil.STATUS_RUNNING,
        cpu_percent=lambda interval: 0.0,
        memory_info=lambda: SimpleNamespace(rss=64), create_time=lambda: 500.0,
    )
    monkeypatch.setattr(blackbox, "find_angerona_pid", lambda: 101)
    monkeypatch.setattr(blackbox.psutil, "Process", lambda _pid: process)
    monkeypatch.setattr(blackbox.time, "time", lambda: 1000.0)
    snapshot = {
        "pid": 101, "process_started_at": 500.0, "generated_ts": 970.0,
        "heartbeat_interval_s": 30.0,
        "event_bus": {"delivery_mode": "inline", "revision": 1, "subscriber_count": 1,
                      "deliveries": 1, "failures": 0, "budget_violations": 0},
        "modules": [{"name": "Live", "last_error": "fresh literal <b>failure</b>"}],
        "counts": {"modules": 1},
    }
    worker = blackbox.SuiteHealthWorker()
    monkeypatch.setattr(worker, "_read_status", lambda: snapshot)
    return worker, snapshot


@pytest.mark.parametrize("issue", ["missing", "denied", "oversize", "invalid"])
def test_historical_gap_is_visible_and_preserves_fresh_failures(monkeypatch, issue):
    worker, _snapshot = configure_live_health(monkeypatch)
    if issue == "missing":
        path = ReadOnlyPath(failure=FileNotFoundError("inert missing report"))
    elif issue == "denied":
        path = ReadOnlyPath(failure=PermissionError("inert denial"))
    else:
        monkeypatch.setattr(blackbox, "MAX_SELFTEST_BYTES", 64)
        path = ReadOnlyPath(TracedStream(b" " * 100 if issue == "oversize" else b"{"))
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", path)
    health = worker._collect()
    assert health["state"] == "RUNNING" and health["bus_state"] == "OBSERVED"
    assert health["bus_fresh"] is True
    assert health["failed"] == [{"name": "Live", "detail": "fresh literal <b>failure</b>",
                                  "src": "status"}]
    assert health["selftest_history_note"].startswith("Unavailable:")
    tab = blackbox.HealthTab()
    try:
        tab.on_health(health)
        assert tab.history_lbl.textFormat() == Qt.PlainText
        assert "Unavailable:" in tab.history_lbl.text()
        assert health["selftest_history_note"] in tab.snapshot_text()
        assert tab.fail_table.rowCount() == 1
        assert tab.fail_table.item(0, 0).text() == "Live"
        assert tab.fail_table.item(0, 1).text() == "fresh literal <b>failure</b>"
        assert tab.state_lbl.text() == "STATE: RUNNING"
    finally:
        tab.close()
        tab.deleteLater()


def test_full_historical_display_retains_the_concurrent_fresh_live_failure(monkeypatch):
    worker, _snapshot = configure_live_health(monkeypatch)
    failures = [{"module": f"Earlier-{index:03d}", "detail": "historical observation"}
                for index in range(500)]
    stream = TracedStream(json.dumps({"failures": failures}).encode(), piece=65_536)
    path = ReadOnlyPath(stream)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", path)

    health = worker._collect()

    assert health["state"] == "RUNNING" and health["bus_state"] == "OBSERVED"
    assert health["bus_fresh"] is True
    assert len(health["failed"]) == 501
    assert health["failed"][:500] == [
        {"name": row["module"], "detail": row["detail"], "src": "selftest (historical)"}
        for row in failures
    ]
    assert health["failed"][500] == {
        "name": "Live", "detail": "fresh literal <b>failure</b>", "src": "status",
    }
    assert "500 failure record(s)" in health["selftest_history_note"]
    assert "does not establish current module health" in health["selftest_history_note"]
    assert stream.closed and path.modes == ["rb"]


def test_stale_live_rows_stay_excluded_while_history_retains_its_source(monkeypatch):
    worker, snapshot = configure_live_health(monkeypatch)
    snapshot["generated_ts"] = 800.0
    stream = TracedStream(b'[{"module":"Earlier","detail":"historical observation"}]')
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    health = worker._collect()
    assert health["bus_state"] == "STALE" and health["bus_fresh"] is False
    assert health["failed"] == [{"name": "Earlier", "detail": "historical observation",
                                  "src": "selftest (historical)"}]


@pytest.mark.parametrize("issue", ["missing", "oversize", "invalid"])
def test_log_history_gap_is_diagnostic_only_without_critical_overlay(monkeypatch, issue):
    if issue == "missing":
        path = ReadOnlyPath(failure=FileNotFoundError("fixture"))
    else:
        monkeypatch.setattr(blackbox, "MAX_SELFTEST_BYTES", 64)
        path = ReadOnlyPath(TracedStream(b" " * 100 if issue == "oversize" else b"{"))
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", path)
    blocks, overlays = [], []
    worker = blackbox.LogTailWorker()
    worker.block.connect(lambda text, severity, _hints: blocks.append((text, severity)))
    worker.exception_at.connect(overlays.append)
    worker._emit_selftest()
    assert len(blocks) == 1 and "diagnostic only" in blocks[0][0]
    assert "Unavailable:" in blocks[0][0] and blocks[0][1] == "info"
    assert overlays == []


@pytest.mark.parametrize("shape", ["dictionary", "list"])
def test_log_history_uses_both_schemas_and_bounds_rendered_rows(monkeypatch, shape):
    failures = [{"name": "Earlier", "detail": "D" * 2500}]
    value = {"failures": failures, "passed": 3, "failed": 1, "generated": "fixture"}
    if shape == "list":
        value = failures
    stream = TracedStream(json.dumps(value).encode())
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", ReadOnlyPath(stream))
    blocks = []
    worker = blackbox.LogTailWorker()
    worker.block.connect(lambda text, *_args: blocks.append(text))
    worker._emit_selftest()
    assert len(blocks) == 1 and "Historical selftest:" in blocks[0]
    assert "Earlier: " + "D" * 2000 in blocks[0]
    assert "D" * 2001 not in blocks[0]
    assert stream.closed


def test_readers_never_modify_original_diagnostic_bytes_or_mtime(monkeypatch, tmp_path):
    path = tmp_path / "diagnostic.json"
    original = b'{"failures":[{"module":"Earlier","detail":"observed"}]}'
    path.write_bytes(original)
    prior = path.stat()
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", path)
    monkeypatch.setattr(blackbox.SuiteHealthWorker, "_pick_status", staticmethod(lambda: path))
    assert blackbox.SuiteHealthWorker._read_status() == json.loads(original)
    assert blackbox._read_selftest_report()[0][0]["name"] == "Earlier"
    blackbox.LogTailWorker()._emit_selftest()
    assert path.read_bytes() == original
    assert path.stat().st_mtime_ns == prior.st_mtime_ns
    assert sorted(item.name for item in tmp_path.iterdir()) == ["diagnostic.json"]
