"""Existing diagnostic output is untrusted input, even below the frame size."""
import json

import pytest

from angerona.core.live_debug import LiveDebugError, MAX_FRAME_BYTES, PROTOCOL
from tools import live_debug as cli


@pytest.mark.parametrize("payload", [
    '{"protocol":"' + PROTOCOL + '","x":' + '[' * 10000 + '0' + ']' * 10000 + '}',
    '{"protocol":"' + PROTOCOL + '","x":' + '[' * 12 + '0' + ']' * 12 + '}',
    '{"protocol":"' + PROTOCOL + '","counter":NaN}',
    '{"protocol":"' + PROTOCOL + '","protocol":"' + PROTOCOL + '"}',
    json.dumps(dict(protocol=PROTOCOL, message="x" * 9000)),
])
def test_existing_header_requires_finite_unique_bounded_diagnostic_frame(tmp_path, payload):
    path = tmp_path / "views.jsonl"
    path.write_text(payload + "\n", encoding="utf-8")
    assert path.stat().st_size < MAX_FRAME_BYTES
    before = path.read_bytes()
    with pytest.raises(LiveDebugError, match="live-debug JSONL"):
        cli.RotatingViewLog(path)
    assert path.read_bytes() == before


def test_deep_header_cli_returns_sanitized_error_before_opening_a_pipe(tmp_path, capsys):
    path = tmp_path / "views.jsonl"
    path.write_text('{"protocol":"' + PROTOCOL + '","x":' + '[' * 10000 + '0' + ']' * 10000 + '}\n')
    code = cli.main(["--pid", "123", "--output", str(path)],
                    client_factory=lambda *_args: pytest.fail("Invalid output must fail before connecting"))
    assert code == 2
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows) == 1 and rows[0]["kind"] == "client_error"
    assert rows[0]["advisory_only"] is True


def test_existing_valid_advisory_annotation_header_remains_appendable(tmp_path):
    path = tmp_path / "views.jsonl"
    first = dict(protocol=PROTOCOL, kind="annotation", advisory_only=True, note="reviewed local view")
    path.write_text(json.dumps(first) + "\n", encoding="utf-8")
    cli.RotatingViewLog(path).write(dict(protocol=PROTOCOL, kind="diagnostic", message="bounded view"))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0] == first and len(rows) == 2
