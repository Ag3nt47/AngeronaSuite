import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import blackbox_recorder as blackbox


def test_blackbox_accepts_both_selftest_report_shapes() -> None:
    rows = [{"module": "Scanner", "detail": "failed"}]

    assert blackbox._selftest_failures(rows) == rows
    assert blackbox._selftest_failures({"failures": rows}) == rows
    assert blackbox._selftest_failures({"failures": "invalid"}) == []
    assert blackbox._selftest_failures(None) == []
