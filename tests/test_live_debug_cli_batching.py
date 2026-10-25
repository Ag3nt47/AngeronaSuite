"""Bounded CLI sink work and explicit file-custody failures; no live host reader."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from angerona.core.live_debug import LiveDebugError, MAX_FRAME_BYTES, PROTOCOL


@pytest.fixture
def cli():
    source = Path(os.environ.get('ANGERONA_CLI_CANDIDATE', Path(__file__).resolve().parents[1] / 'tools/live_debug.py'))
    spec = importlib.util.spec_from_file_location('bounded_cli_candidate', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(number, *, kind='diagnostic', message='inert'):
    return dict(protocol=PROTOCOL, kind=kind, seq=number, message=message)


def hello(cursor):
    return dict(protocol=PROTOCOL, kind='hello', seq=0, run_id='a' * 32,
                status={'cursor': cursor})


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'


class Output(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0
        self.blocks = []

    def write(self, text):
        self.blocks.append(text)
        return super().write(text)

    def flush(self):
        self.flushes += 1
        return super().flush()


def test_cli_capture_batches_native_opens_and_stdout_flushes_without_changing_frames(cli, tmp_path, monkeypatch):
    records = [hello(200), *(row(index) for index in range(1, 201))]
    output, opened, closed = Output(), [], []
    target = tmp_path / 'views.jsonl'
    actual_open = cli.os.open
    def counted_open(path, *args, **kwargs):
        if Path(path) == target:
            opened.append(path)
        return actual_open(path, *args, **kwargs)
    monkeypatch.setattr(cli.os, 'open', counted_open)
    monkeypatch.setattr(cli.sys, 'stdout', output)
    monkeypatch.setattr(cli.time, 'monotonic', lambda: 100.0)
    class Client:
        def __init__(self, *_args): self.rows = iter(records)
        def connect(self): pass
        def read(self, timeout): return next(self.rows)
        def close(self): closed.append(True)
    assert cli.main(['--pid', '123', '--output', str(target)], client_factory=Client) == 0
    expected = b''.join(map(encoded, records))
    assert output.getvalue().encode('ascii') == target.read_bytes() == expected
    assert closed == [True]
    assert len(opened) <= 4, f'Per-record capture reopen remains: {len(opened)}'
    assert output.flushes <= 4, f'Per-record stdout flush remains: {output.flushes}'


def test_batch_rotation_preserves_whole_frames_order_and_exact_byte_limits(cli, tmp_path):
    target = tmp_path / 'views.jsonl'
    writer = cli.RotatingViewLog(target, max_bytes=MAX_FRAME_BYTES, backups=2)
    records = [row(index, message='x' * 700) for index in range(80)]
    writer.write_many(records)
    paths = [target.with_name(target.name + suffix) for suffix in ('.2', '.1', '')]
    present = [path for path in paths if path.exists()]
    assert len(present) == 2
    assert all(path.stat().st_size <= MAX_FRAME_BYTES for path in present)
    assert b''.join(path.read_bytes() for path in present) == b''.join(map(encoded, records))


@pytest.mark.parametrize('kind', ['records', 'bytes', 'frame', 'nonfinite'])
def test_invalid_batch_is_refused_before_any_append(cli, tmp_path, kind):
    target = tmp_path / 'views.jsonl'
    writer = cli.RotatingViewLog(target)
    records = ([row(index) for index in range(101)] if kind == 'records' else
               [row(index, message='x' * 8000) for index in range(10)] if kind == 'bytes' else
               [row(1, message='x' * MAX_FRAME_BYTES)] if kind == 'frame' else
               [dict(row(1), counter=float('nan'))])
    with pytest.raises((LiveDebugError, ValueError)):
        writer.write_many(records)
    assert not target.exists()


@pytest.mark.parametrize('change', ['regular', 'nlink', 'reparse', 'identity', 'named-identity'])
def test_held_append_refuses_changed_file_custody_before_writing(cli, tmp_path, monkeypatch, change):
    target = tmp_path / 'views.jsonl'
    writer = cli.RotatingViewLog(target)
    writer.write(row(0))
    before = target.read_bytes()
    expected = writer._check(target)
    fstat, lstat = cli.os.fstat, cli.Path.lstat
    def altered(info, *, named=False):
        values = {name: getattr(info, name) for name in ('st_mode', 'st_nlink', 'st_dev', 'st_ino', 'st_size')}
        values['st_file_attributes'] = getattr(info, 'st_file_attributes', 0)
        if change == 'regular': values['st_mode'] = stat.S_IFDIR
        if change == 'nlink': values['st_nlink'] = 2
        if change == 'reparse': values['st_file_attributes'] |= 0x400
        if change == 'identity' or (change == 'named-identity' and named): values['st_ino'] += 1
        return SimpleNamespace(**values)
    if change == 'named-identity':
        monkeypatch.setattr(cli.Path, 'lstat', lambda path, *a, **k: altered(lstat(path, *a, **k), named=True) if path == target else lstat(path, *a, **k))
    else:
        monkeypatch.setattr(cli.os, 'fstat', lambda descriptor: altered(fstat(descriptor)))
    with pytest.raises(LiveDebugError, match='identity'):
        writer._append_segment((encoded(row(1)),), expected)
    assert target.read_bytes() == before


def test_append_rechecks_header_on_held_file_after_prior_validation(cli, tmp_path):
    target = tmp_path / 'views.jsonl'
    writer = cli.RotatingViewLog(target)
    writer.write(row(0))
    expected = writer._check(target)
    invalid = target.read_bytes().replace(PROTOCOL.encode(), b'x' * len(PROTOCOL), 1)
    target.write_bytes(invalid)
    with pytest.raises(LiveDebugError, match='live-debug JSONL'):
        writer._append_segment((encoded(row(1)),), expected)
    assert target.read_bytes() == invalid


def test_absent_file_creation_race_never_appends_to_competing_file(cli, tmp_path):
    target = tmp_path / 'views.jsonl'
    writer = cli.RotatingViewLog(target)
    competing = encoded(row(91))
    target.write_bytes(competing)
    with pytest.raises(FileExistsError):
        writer._append_segment((encoded(row(1)),), None)
    assert target.read_bytes() == competing


def test_new_segment_refuses_link_added_after_previous_segment(cli, tmp_path, monkeypatch):
    target = tmp_path / 'views.jsonl'
    alias = tmp_path / 'alias.jsonl'
    writer = cli.RotatingViewLog(target, max_bytes=MAX_FRAME_BYTES)
    append = writer._append_segment
    calls = []
    def first_segment(frames, expected):
        append(frames, expected)
        calls.append(len(frames))
        if len(calls) == 1:
            os.link(target, alias)
    monkeypatch.setattr(writer, '_append_segment', first_segment)
    records = [row(index, message='x' * 700) for index in range(80)]
    with pytest.raises(LiveDebugError, match='unsafe'):
        writer.write_many(records)
    assert len(calls) == 1
    assert 0 < calls[0] < len(records)
    assert target.read_bytes() == alias.read_bytes() == b''.join(map(encoded, records[:calls[0]]))


def test_idle_heartbeat_and_read_error_flush_prefix_in_original_order(cli, tmp_path, monkeypatch):
    target, output = tmp_path / 'views.jsonl', Output()
    monkeypatch.setattr(cli.sys, 'stdout', output)
    monkeypatch.setattr(cli.time, 'monotonic', lambda: 100.0)
    sequence = [hello(8), row(1), row(2), None, row(3), row(3, kind='heartbeat'), row(4)]
    class Client:
        def __init__(self, *_args): self.index = 0
        def connect(self): pass
        def read(self, timeout):
            if self.index == 4:
                assert [json.loads(line)['seq'] for line in target.read_text().splitlines()] == [0, 1, 2]
            if self.index == 6:
                assert json.loads(target.read_text().splitlines()[-1])['kind'] == 'heartbeat'
            if self.index == len(sequence): raise LiveDebugError('inert read failed')
            value = sequence[self.index]
            self.index += 1
            return value
        def close(self): pass
    assert cli.main(['--pid', '123', '--follow', '--output', str(target)], client_factory=Client) == 2
    emitted = [json.loads(line) for line in output.getvalue().splitlines()]
    assert emitted[:-1] == [record for record in sequence if record is not None]
    assert emitted[-1]['kind'] == 'client_error' and 'inert read failed' in emitted[-1]['reason']
    assert target.read_bytes() == b''.join(encoded(record) for record in sequence if record is not None)


def test_interrupt_pending_capture_failure_is_explicit_not_uncaught_or_replayed(cli, tmp_path, monkeypatch):
    output, calls = Output(), []
    monkeypatch.setattr(cli.sys, 'stdout', output)
    monkeypatch.setattr(cli.time, 'monotonic', lambda: 100.0)
    original = cli.RotatingViewLog.write_many
    def capture(writer, records):
        records = list(records)
        calls.append(records)
        if len(calls) > 1: raise OSError('inert interrupted sink failure')
        original(writer, records)
    monkeypatch.setattr(cli.RotatingViewLog, 'write_many', capture)
    class Client:
        def __init__(self, *_args): self.rows = iter([hello(5), row(1)])
        def connect(self): pass
        def read(self, timeout):
            try: return next(self.rows)
            except StopIteration: raise KeyboardInterrupt
        def close(self): pass
    assert cli.main(['--pid', '123', '--follow', '--output', str(tmp_path/'views.jsonl')], client_factory=Client) == 2
    emitted = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [record.get('seq') for record in emitted[:-1]] == [0, 1]
    assert emitted[-1]['kind'] == 'client_error' and 'sink failure' in emitted[-1]['reason']
    assert len(calls) == 2


def test_mutable_source_record_cannot_change_deferred_capture(cli, tmp_path, monkeypatch):
    target, output = tmp_path/'views.jsonl', Output()
    monkeypatch.setattr(cli.sys, 'stdout', output)
    monkeypatch.setattr(cli.time, 'monotonic', lambda: 100.0)
    original = row(1, message='original')
    class Client:
        def __init__(self, *_args): self.index = 0
        def connect(self): pass
        def read(self, timeout):
            self.index += 1
            if self.index == 1: return hello(2)
            if self.index == 2: return original
            original['message'] = 'changed later'
            return row(2)
        def close(self): pass
    assert cli.main(['--pid','123','--output',str(target)], client_factory=Client) == 0
    assert json.loads(target.read_text().splitlines()[1])['message'] == 'original'
    assert output.getvalue().encode('ascii') == target.read_bytes()


def test_interrupt_with_closed_stdout_keeps_clean_broken_pipe_exit(cli, monkeypatch):
    closed = []
    class BrokenOutput(Output):
        def write(self, text):
            if self.blocks:
                raise BrokenPipeError('inert downstream closed during interrupt')
            return super().write(text)
    output = BrokenOutput()
    monkeypatch.setattr(cli.sys, 'stdout', output)
    monkeypatch.setattr(cli.time, 'monotonic', lambda: 100.0)
    class Client:
        def __init__(self, *_args): self.rows = iter([hello(5), row(1)])
        def connect(self): pass
        def read(self, timeout):
            try: return next(self.rows)
            except StopIteration: raise KeyboardInterrupt
        def close(self): closed.append(True)
    assert cli.main(['--pid','123','--follow'], client_factory=Client) == 0
    assert [json.loads(line) for line in output.getvalue().splitlines()] == [hello(5)]
    assert closed == [True]
