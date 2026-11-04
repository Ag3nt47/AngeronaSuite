"""Synthetic private report custody only: no toolkit execution or host evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from angerona.core import curated_tools as tools


@pytest.fixture
def service(tmp_path, monkeypatch):
    # The export destination and installation are separate inert fixture roots.
    bundle = tools.resource_root() / "assets" / "integrations" / "zero_breach"
    monkeypatch.setattr(tools, "resource_root", lambda: tmp_path / "installation")
    return tools.CuratedToolService(tmp_path / "managed-tools", bundle=bundle)


def recorded(service, *, state="complete", retired=True):
    with service._transaction(tools.ToolOperation()) as root:
        job = service._new_job(root)
        tools._atomic_bytes_write(job / "report.json", b'{"fixture":"untrusted output"}', root=root)
        tools._atomic_bytes_write(job / "stdout.log", b"literal fixture output\n", root=root)
        service._save(root, job, {"state": state, "native_retired": retired})
    return job


def receipt_hash(job):
    return hashlib.sha256((job / "receipt.json").read_bytes()).hexdigest()


def original_bytes(job):
    return {name: (job / name).read_bytes() for name in ("report.json", "stdout.log", "receipt.json")}


def test_count_quota_has_actionable_hold_and_does_not_admit_or_delete(service, monkeypatch):
    # Exercise quota admission after genuine offline bundle verification. An
    # absent installation must keep failing before any job slot is consumed.
    prepared = service.prepare(tools.ToolOperation(), allow_download=False)
    assert prepared["verified"] is True
    service.cfg = SimpleNamespace(github_tools_report_count=8)
    jobs = [recorded(service) for _ in range(8)]
    before = {job.name: original_bytes(job) for job in jobs}
    monkeypatch.setattr(service, "_preflight_scan", lambda _root: None)
    monkeypatch.setattr(service, "_run", lambda *_args: pytest.fail("Quota must hold before native launch"))
    operation = tools.ToolOperation()
    with pytest.raises(tools.ToolStorageHeld) as held:
        service.scan(tools.ToolScanRequest(), operation)
    assert held.value.storage_hold == {
        "kind": "report-count", "retained_reports": 8, "report_limit": 8,
        "used_bytes": held.value.storage_hold["used_bytes"], "limit_bytes": 64 * 1024**2,
        "automatic_deletion": False,
    }
    assert "Export alone does not free slots" in str(held.value)
    assert {job.name: original_bytes(job) for job in jobs} == before
    assert len(list((service._root() / "jobs").iterdir())) == 8
    progress = service.progress_snapshot()
    assert progress["operation_id"] == operation.operation_id
    assert progress["state"] == "not-started" and not progress["native_started"]
    assert progress["owner_retired"] is True and progress["remaining_s"] is None
    assert progress["overall_percent"] is None


def test_review_returns_bounded_metadata_and_no_deletion(service):
    job = recorded(service)
    before = original_bytes(job)
    result = service.review_reports(tools.ToolOperation())
    assert result["storage"]["retained_reports"] == 1
    assert result["storage"]["report_limit"] == "unlimited"
    row, = result["storage_reports"]
    assert row["job_id"] == job.name and row["receipt_sha256"] == receipt_hash(job)
    assert row["can_export"] is row["can_delete"] is True
    assert len(row["preview"]) <= 16000 and row["preview_omitted_characters"] == 0
    assert original_bytes(job) == before


@pytest.mark.parametrize("change", ["output", "receipt-type", "unretired", "unknown"])
def test_review_preserves_unresolved_changed_and_unknown_outputs(service, change):
    job = recorded(service, retired=change != "unretired")
    if change == "output":
        (job / "report.json").write_bytes(b"operator addition")
    elif change == "receipt-type":
        tools._atomic_bytes_write(job / "receipt.json", b"[]", root=service._root())
    elif change == "unknown":
        (job / "operator-note.txt").write_bytes(b"keep me")
    before = {path.name: path.read_bytes() for path in job.iterdir() if path.is_file()}
    row, = service.review_reports(tools.ToolOperation())["storage_reports"]
    assert row["can_export"] is row["can_delete"] is False
    assert row["state"] == "needs-review"
    assert {path.name: path.read_bytes() for path in job.iterdir() if path.is_file()} == before


def test_export_copies_exact_recorded_files_and_manifest_without_freeing_slot(service, tmp_path):
    job = recorded(service)
    before = original_bytes(job)
    result = service.export_report(tools.ToolOperation(), job_id=job.name,
                                   expected_receipt=receipt_hash(job), destination=str(tmp_path))
    assert result["state"] == "exported" and "does not free" in result["message"]
    target = Path(result["export_file"])
    assert target.parent.parent == tmp_path and target.parent.name.startswith("Angerona-scanner-export-")
    with zipfile.ZipFile(target) as archive:
        assert set(archive.namelist()) == set(before) | {"export-manifest.json"}
        manifest = json.loads(archive.read("export-manifest.json"))
        assert manifest["job_id"] == job.name and manifest["receipt_sha256"] == receipt_hash(job)
        for name, raw in before.items():
            assert archive.read(name) == raw
            assert manifest["files"][name] == {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    assert original_bytes(job) == before
    assert service.review_reports(tools.ToolOperation())["storage"]["retained_reports"] == 1


@pytest.mark.parametrize("changed", ["receipt", "output"])
def test_export_revalidates_selection_before_creating_output(service, tmp_path, changed):
    job = recorded(service)
    selected = receipt_hash(job)
    if changed == "receipt":
        tools._atomic_bytes_write(job / "receipt.json", (job / "receipt.json").read_bytes() + b" ", root=service._root())
    else:
        (job / "report.json").write_bytes(b"edited")
    with pytest.raises(tools.ToolError, match="changed"):
        service.export_report(tools.ToolOperation(), job_id=job.name,
                              expected_receipt=selected, destination=str(tmp_path))
    assert not list(tmp_path.glob("Angerona-scanner-export-*"))
    assert job.exists()


def test_export_rejects_managed_and_installed_destinations(service, tmp_path):
    job = recorded(service)
    installed = tmp_path / "installation"
    installed.mkdir()
    for destination in (service._root(), job, installed):
        with pytest.raises(tools.ToolError, match="outside managed scanner and installed source"):
            service.export_report(tools.ToolOperation(), job_id=job.name,
                                  expected_receipt=receipt_hash(job), destination=str(destination))
    assert original_bytes(job)


def test_incomplete_export_explains_partial_copy_location_and_preserves_originals(service, tmp_path):
    job = recorded(service)
    before = original_bytes(job)

    def fail(_message):
        raise OSError("synthetic destination failure")

    with pytest.raises(tools.ToolError, match="partial private export may remain") as error:
        service.export_report(tools.ToolOperation(), progress=fail, job_id=job.name,
                              expected_receipt=receipt_hash(job), destination=str(tmp_path))
    folders = list(tmp_path.glob("Angerona-scanner-export-*"))
    assert len(folders) == 1 and str(folders[0]) in str(error.value)
    assert original_bytes(job) == before


def test_selected_delete_revalidates_each_receipt_and_preserves_other_reports(service):
    jobs = [recorded(service) for _ in range(3)]
    unrelated = original_bytes(jobs[2])
    result = service.clear_reports(tools.ToolOperation(), expected={job.name: receipt_hash(job) for job in jobs[:2]})
    assert result["removed_reports"] == 2 and result["retained_reports"] == 0
    assert not jobs[0].exists() and not jobs[1].exists()
    assert original_bytes(jobs[2]) == unrelated


def test_selected_delete_refuses_changed_receipt_without_touching_outputs(service):
    job = recorded(service)
    selected = receipt_hash(job)
    tools._atomic_bytes_write(job / "receipt.json", (job / "receipt.json").read_bytes() + b" ", root=service._root())
    before = original_bytes(job)
    result = service.clear_reports(tools.ToolOperation(), expected={job.name: selected})
    assert result["removed_reports"] == 0 and result["retained_reports"] == 1
    assert original_bytes(job) == before


def test_missing_selected_report_does_not_delete_another_report(service):
    job = recorded(service)
    before = original_bytes(job)
    result = service.clear_reports(tools.ToolOperation(), expected={"f" * 32: "a" * 64})
    assert result["removed_reports"] == 0 and result["retained_reports"] == 1
    assert original_bytes(job) == before


def test_aggregate_inventory_hold_keeps_install_and_exact_report_review_available(service, monkeypatch):
    assert service.prepare(tools.ToolOperation(), allow_download=False)["verified"] is True
    jobs = [recorded(service) for _ in range(3)]
    before = {job.name: original_bytes(job) for job in jobs}
    monkeypatch.setattr(tools, "MAX_ENTRIES", 9)  # Three 4-entry sets exceed this fixture ceiling.

    state = service.status()
    assert state["installed"] is state["verified"] is True
    assert state["latest_report"]["job_id"] == jobs[-1].name
    assert state["disk_bytes"] is None and "entry limit" in state["storage_inventory_error"]
    with service._transaction(tools.ToolOperation()) as root:
        with pytest.raises(tools.ToolError, match="entry limit"):
            service._new_job(root)

    review = service.review_reports(tools.ToolOperation())
    assert review["storage"]["used_bytes"] is None
    assert "entry limit" in review["storage"]["inventory_gap"]
    rows = {row["job_id"]: row for row in review["storage_reports"]}
    assert set(rows) == set(before) and all(row["can_delete"] for row in rows.values())
    with pytest.raises(tools.ToolError, match="entry limit"):
        service.clear_reports(tools.ToolOperation())
    assert {job.name: original_bytes(job) for job in jobs} == before

    target = jobs[0]
    deleted = service.clear_reports(tools.ToolOperation(), expected={target.name: rows[target.name]["receipt_sha256"]})
    assert deleted["removed_reports"] == 1 and not target.exists()
    assert {job.name: original_bytes(job) for job in jobs[1:]} == {job.name: before[job.name] for job in jobs[1:]}
    refreshed = service.review_reports(tools.ToolOperation())["storage"]
    assert refreshed["inventory_gap"] is None and refreshed["used_bytes"] > 0


def test_unknown_immediate_entry_blocks_bulk_and_exact_delete(service):
    job = recorded(service)
    before = original_bytes(job)
    note = job.parent / "operator-note.txt"
    tools._atomic_bytes_write(note, b"preserve", root=service._root())
    review = service.review_reports(tools.ToolOperation())
    assert review["storage"]["unknown_entries"] is True and review["storage"]["used_bytes"] is None
    row, = review["storage_reports"]
    assert row["can_export"] is True and row["can_delete"] is False
    for expected in (None, {job.name: row["receipt_sha256"]}):
        with pytest.raises(tools.ToolError, match="Unknown scanner directories"):
            service.clear_reports(tools.ToolOperation(), expected=expected)
    assert original_bytes(job) == before and note.read_bytes() == b"preserve"


def test_explicit_one_run_count_admits_one_record_then_original_limit_holds(service):
    # Synthetic retained outputs only; the actual offline installation and job
    # admission run, but no scanner/native process is started by this test.
    service.cfg = SimpleNamespace(github_tools_report_count=8)
    assert service.prepare(tools.ToolOperation(), allow_download=False)["verified"] is True
    jobs = [recorded(service) for _ in range(8)]
    before = {job.name: original_bytes(job) for job in jobs}
    operation = tools.ToolOperation(report_count_limit=9)
    with service._transaction(operation) as root:
        with service._owned_job(root, operation) as extra:
            tools._atomic_bytes_write(extra / "report.json", b'{"fixture":"extra"}', root=root)
            result = service._save(root, extra, {"state": "complete", "native_retired": True})
    assert operation.report_count_limit is None
    assert result["report_storage"] == {"report_count": 9, "finite_report_limit": 32,
        "inventory_entry_limit": tools.MAX_ENTRIES,
        "count_kind": "soft-admission", "selection": "one-run", "retained_before": 8,
        "limit_bytes": 64 * 1024**2, "automatic_deletion": False}
    assert json.loads((extra / "receipt.json").read_bytes())["report_storage"] == result["report_storage"]
    assert service.status()["report_storage_policy"]["report_count"] == 8
    with service._transaction(operation) as root:
        with pytest.raises(tools.ToolStorageHeld) as held:
            with service._owned_job(root, operation):
                pytest.fail("Reusing the operation must not retain one-run consent")
    assert held.value.storage_hold["retained_reports"] == 9
    assert held.value.storage_hold["report_limit"] == 8
    assert {job.name: original_bytes(job) for job in jobs} == before
    assert len(list((service._root() / "jobs").iterdir())) == 9


def test_reviewed_count_race_refuses_extra_slot_without_extending_consent(service):
    assert service.prepare(tools.ToolOperation(), allow_download=False)["verified"] is True
    service.cfg = SimpleNamespace(github_tools_report_count=9)
    jobs = [recorded(service) for _ in range(9)]  # Another admitted report won before this attempt.
    service.cfg.github_tools_report_count = 8
    before = {job.name: original_bytes(job) for job in jobs}
    operation = tools.ToolOperation(report_count_limit=9)  # Approved when the review observed eight.
    with service._transaction(operation) as root:
        with pytest.raises(tools.ToolStorageHeld) as held:
            with service._owned_job(root, operation):
                pytest.fail("The current count already consumes the exact approved limit")
    assert held.value.storage_hold["report_limit"] == 9
    assert held.value.storage_hold["retained_reports"] == 9
    assert operation.report_count_limit is None
    assert {job.name: original_bytes(job) for job in jobs} == before


def test_unlimited_admits_beyond_32_and_all_pages_retain_exact_export_delete(service, tmp_path):
    assert service.status()["report_storage_policy"]["report_count"] == "unlimited"
    jobs = [recorded(service) for _ in range(tools.MAX_REPORTS_LIMIT)]
    with service._transaction(tools.ToolOperation()) as root:
        with pytest.raises(tools.ToolStorageHeld) as held:
            service._new_job(root, report_count_limit=32)
    assert held.value.storage_hold["kind"] == "report-count"
    assert held.value.storage_hold["report_limit"] == 32

    jobs += [recorded(service), recorded(service)]
    assert len(jobs) == 34
    before = {job.name: original_bytes(job) for job in jobs}
    latest = service.status()["latest_report"]
    assert latest["report_storage"]["report_count"] == "unlimited"
    assert latest["report_storage"]["retained_before"] == 33
    service.cfg = SimpleNamespace(github_tools_report_count=8)  # Hide no admitted evidence.
    first = service.review_reports(tools.ToolOperation())
    second = service.review_reports(tools.ToolOperation(), page=1)
    assert len(first["storage_reports"]) == 32 and len(second["storage_reports"]) == 2
    for page, review in enumerate((first, second)):
        storage = review["storage"]
        assert storage["retained_reports"] == 34 and storage["report_limit"] == 8
        assert storage["finite_report_limit"] == 32 and storage["inventory_entry_limit"] == tools.MAX_ENTRIES
        assert (storage["page"], storage["page_count"]) == (page, 2)
        assert storage["unknown_entries"] is False
    rows = {row["job_id"]: row for page in (first, second) for row in page["storage_reports"]}
    assert set(rows) == {job.name for job in jobs}
    assert all(row["can_delete"] is row["can_export"] is True for row in rows.values())
    with pytest.raises(tools.ToolError, match="larger than 32"):
        service.clear_reports(tools.ToolOperation())
    assert {job.name: original_bytes(job) for job in jobs} == before
    chosen = next(job for job in jobs if job.name == second["storage_reports"][-1]["job_id"])
    exported = service.export_report(tools.ToolOperation(), job_id=chosen.name,
        expected_receipt=rows[chosen.name]["receipt_sha256"], destination=str(tmp_path))
    with zipfile.ZipFile(exported["export_file"]) as archive:
        for name, raw in before[chosen.name].items():
            assert archive.read(name) == raw
    deleted = service.clear_reports(tools.ToolOperation(), expected={chosen.name: rows[chosen.name]["receipt_sha256"]})
    assert deleted["removed_reports"] == 1 and not chosen.exists()
    assert {job.name: original_bytes(job) for job in jobs if job != chosen} == {
        key: value for key, value in before.items() if key != chosen.name
    }


@pytest.mark.parametrize("count_override", [None, 9])
@pytest.mark.parametrize("size,kind", [(4 * 1024**2, "output-reserve"), (15 * 1024**2 // 2, "report-bytes")])
def test_unlimited_and_one_run_count_keep_independent_report_byte_guards(service, size, kind, count_override):
    assert service.prepare(tools.ToolOperation(), allow_download=False)["verified"] is True
    service.cfg = SimpleNamespace(github_tools_report_limit_mib=8)
    jobs = [recorded(service) for _ in range(8)]
    with service._transaction(tools.ToolOperation()) as root:
        if kind == "report-bytes":
            # Aggregate retained bytes, not one oversized source-writer call.
            # The last job's3.5MiB report plus2MiB per log fits the unchanged
            # per-file caps, captured retained allowance and log reserve.
            job = jobs[-1]
            sizes = {"report.json": size - 2 * tools.MAX_LOG_BYTES,
                     "stdout.log": tools.MAX_LOG_BYTES, "stderr.log": tools.MAX_LOG_BYTES}
            assert sum(sizes.values()) == size and all(0 < count <= 4 * 1024**2 for count in sizes.values())
            from angerona.core.curated_tool_worker import _WriteBudget
            _rows, used = tools._inventory(root / "jobs", byte_limit=8 * 1024**2)
            # Completed jobs release their in-memory allowances. Use the real,
            # inert constructor with a conservative allowance after all eight
            # small receipts, without installing any global writer hooks.
            budget = _WriteBudget(job, 256 * 1024**2, retained_allowance=8 * 1024**2 - used)
            assert sizes["report.json"] <= budget.retained_limit
            for name, count in sizes.items():
                tools._atomic_bytes_write(job / name, b"x" * count, root=root)
            service._save(root, job, {"state": "complete", "native_retired": True})
        else:
            tools._atomic_bytes_write(jobs[0] / "report.json", b"x" * size, root=root)
            service._save(root, jobs[0], {"state": "complete", "native_retired": True})

    def retained_outputs():
        return {job.name: {name: (job / name).read_bytes()
                for name in ("report.json", "stdout.log", "stderr.log", "receipt.json") if (job / name).exists()}
                for job in jobs}

    before = retained_outputs()
    operation = tools.ToolOperation(report_count_limit=count_override)
    with service._transaction(operation) as root:
        with pytest.raises(tools.ToolStorageHeld) as held:
            with service._owned_job(root, operation):
                pytest.fail("Count consent must not relax independent byte admission")
    assert held.value.storage_hold["kind"] == kind
    assert held.value.storage_hold["report_limit"] == ("unlimited" if count_override is None else count_override)
    assert held.value.storage_hold["limit_bytes"] == 8 * 1024**2
    assert operation.report_count_limit is None
    assert retained_outputs() == before
    assert {path.name for path in (service._root() / "jobs").iterdir()} == set(before)


@pytest.mark.parametrize("count_override", [None, 32])
def test_unlimited_and_one_run_keep_unknown_entry_and_free_space_guards(service, monkeypatch, count_override):
    assert service.prepare(tools.ToolOperation(), allow_download=False)["verified"] is True
    with service._transaction(tools.ToolOperation()) as root:
        tools._private(root / "jobs")
        tools._atomic_bytes_write(root / "jobs" / "operator-note.txt", b"preserve unknown evidence", root=root)
        with pytest.raises(tools.ToolStorageHeld) as held:
            service._new_job(root, report_count_limit=count_override)
    assert held.value.storage_hold["kind"] == "unknown-entries"
    note = service._root() / "jobs" / "operator-note.txt"
    before = note.read_bytes()
    # Inert negative observation only: skip privilege/image observations so the
    # unchanged free-space branch itself must refuse before any scanner launch.
    monkeypatch.setattr(tools, "_require_user", lambda: {})
    monkeypatch.setattr(service, "_python", lambda: None)
    monkeypatch.setattr(tools.shutil, "disk_usage", lambda _root: type("Disk", (), {"free": 0})())
    monkeypatch.setattr(service, "_run", lambda *_args, **_kwargs: pytest.fail("Free-space hold must precede native launch"))
    with pytest.raises(tools.ToolError, match="3 GiB"):
        service.scan(tools.ToolScanRequest(), tools.ToolOperation(report_count_limit=count_override))
    assert note.read_bytes() == before
    assert len(list(note.parent.iterdir())) == 1


def test_unlimited_holds_before_creating_job_at_managed_inventory_limit(service, monkeypatch):
    job = recorded(service)
    before = original_bytes(job)
    with service._transaction(tools.ToolOperation()) as root:
        rows, _used = tools._inventory(root / "jobs")
        monkeypatch.setattr(tools, "MAX_ENTRIES", len(rows) + len(tools._JOB_DIRECTORIES) + len(tools._REPORT_NAMES) - 1)
        with pytest.raises(tools.ToolStorageHeld) as held:
            service._new_job(root)
        assert held.value.storage_hold["kind"] == "inventory-entries"
        assert held.value.storage_hold["report_limit"] == "unlimited"
        assert {path.name for path in (root / "jobs").iterdir()} == {job.name}
    assert original_bytes(job) == before


@pytest.mark.parametrize("value", [True, False, 0, 33, 9.0, "9", "unlimited"])
def test_per_run_report_count_rejects_nonliteral_or_out_of_cap_values(service, value):
    with pytest.raises(ValueError, match="report count"):
        tools.ToolOperation(report_count_limit=value)
    with service._transaction(tools.ToolOperation()) as root:
        with pytest.raises(tools.ToolError, match="per-run report count"):
            service._new_job(root, report_count_limit=value)
        assert not (root / "jobs").exists()
