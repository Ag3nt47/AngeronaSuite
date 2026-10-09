from angerona.modules import storage_hygiene as hygiene


def test_oversized_nested_tree_reports_incomplete_coverage(tmp_path, monkeypatch):
    source = tmp_path / "legacy"
    nested = source / "nested"
    nested.mkdir(parents=True)
    for index in range(8):
        (nested / str(index)).write_bytes(b"preserve")
    monkeypatch.setattr(hygiene, "_TREE_MAX_ENTRIES", 4)
    result = hygiene.inspect_stray(source, tmp_path / "runtime")
    assert result["status"] == "unavailable"
    assert "bounded inspection coverage" in result["reason"]
    assert len(list(nested.iterdir())) == 8


def test_expired_budget_cannot_report_clean(tmp_path, monkeypatch):
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "item").write_bytes(b"preserve")
    monkeypatch.setattr(hygiene, "_TREE_MAX_SECONDS", 0.0)
    result = hygiene.inspect_stray(source, tmp_path / "runtime")
    assert result["status"] == "unavailable"
    assert "bounded" in result["reason"]


def test_complete_small_tree_keeps_stray_and_clean_distinct(tmp_path):
    source = tmp_path / "legacy"
    source.mkdir()
    destination = tmp_path / "runtime"
    # Materialize the fresh fixture before taking an inspection baseline. On
    # the Windows test host, a transient attribute flag settled on enumeration;
    # production still rejects metadata changes during its own inspection.
    assert list(source.iterdir()) == []
    assessment = hygiene.inspect_stray(source, destination)
    assert assessment["status"] == "clean", assessment["reason"]
    (source / "proof").write_bytes(b"preserve")
    assessment = hygiene.inspect_stray(source, destination)
    assert assessment["status"] == "stray", assessment["reason"]
