from __future__ import annotations

import io
import json
import struct
import threading
import zipfile

import pytest

from angerona.core import github_tool_catalog as catalog
from angerona.core.file_lease import ExclusiveFileLease


@pytest.fixture(autouse=True)
def unprivileged_fixture(monkeypatch):
    # Hosted Windows and Linux CI can be elevated; these tests use isolated roots.
    monkeypatch.setattr(catalog, "_require_unprivileged", lambda: None)


def source_zip(files=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in (files or {"README.md": "Harmless source review fixture."}).items():
            entry = zipfile.ZipInfo("placeholder")
            entry.filename = "example-" + "a" * 40 + "/" + name
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, value)
    return buffer.getvalue()


def plan():
    return catalog.ImportPlan("example/fixture", "main", "a" * 40, "MIT")


def saved(tmp_path, files=None):
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    row = library.store_source(plan(), source_zip(files), catalog.ImportOperation())
    return library, row


@pytest.mark.parametrize("url", [
    "http://github.com/owner/repo", "https://github.com.example/owner/repo",
    "https://user:password@github.com/owner/repo", "https://github.com:443/owner/repo",
    "https://github.com/owner/repo?token=example", "https://github.com/owner/repo#part",
    "https://github.com/owner/repo/tree/main", "file:///tmp/repo", "git@github.com:owner/repo",
    "https://github.com/owner/..", "https://github.com/owner/%2e%2e",
])
def test_repository_url_is_public_and_canonical(url):
    with pytest.raises(ValueError):
        catalog.repository_identity(url)


def test_repository_normalizes_display_identity():
    assert catalog.repository_identity("https://github.com/Example/Fixture.git/") == "example/fixture"


def test_resolve_pins_revision_and_import_download_uses_only_sha(tmp_path, monkeypatch):
    calls = []

    def download(url, limit, operation):
        calls.append(url)
        if url.endswith("/commits/main"):
            return json.dumps({"sha": "a" * 40}).encode()
        if url.startswith("https://codeload.github.com/"):
            return source_zip()
        return json.dumps({"full_name": "Example/Fixture", "private": False,
                           "license": {"spdx_id": "MIT"}}).encode()

    monkeypatch.setattr(catalog, "_download", download)
    selected = catalog.resolve_import("https://github.com/example/fixture", "main", catalog.ImportOperation())
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    row = library.import_source(selected, catalog.ImportOperation())
    assert row["commit"] == "a" * 40
    assert calls[-1] == "https://codeload.github.com/example/fixture/zip/" + "a" * 40
    assert row["state"] == "review_only"


@pytest.mark.parametrize("metadata", [
    {"full_name": "other/repo", "private": False},
    {"full_name": "example/fixture", "private": True},
    {"full_name": "example/fixture"}, [],
])
def test_resolution_rejects_ambiguous_origin(metadata, monkeypatch):
    monkeypatch.setattr(catalog, "_download", lambda *_args: json.dumps(metadata).encode())
    with pytest.raises(ValueError):
        catalog.resolve_import("https://github.com/example/fixture", "main", catalog.ImportOperation())


def test_import_keeps_source_inert_and_preview_literal(tmp_path):
    library, row = saved(tmp_path, {"README.md": "<script>untrusted text</script>",
                                   "source.py": "SOURCE_DATA_ONLY = True\n"})
    assert set(library.files(row["id"])) == {"README.md", "source.py"}
    assert library.preview(row["id"], "README.md") == "<script>untrusted text</script>"
    assert {path.suffix for path in library.root.iterdir()} == {".json", ".zip", ".lock"}
    assert not (library.root / "source.py").exists()
    assert catalog.GitHubToolCatalog(library.root).list_imports() == [row]


@pytest.mark.parametrize("name", ["../outside.txt", "/absolute.txt", "dir\\file.txt", "NUL.txt",
                                  "file:stream", "file. ", "dir/../file", "a//file", "a\u202etxt"])
def test_unsafe_archive_names_never_publish(tmp_path, name):
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    with pytest.raises(ValueError):
        library.store_source(plan(), source_zip({name: "inert"}), catalog.ImportOperation())
    assert library.list_imports() == []


def test_case_and_parent_collisions_rejected(tmp_path):
    for files in ({"Readme": "a", "README": "b"}, {"a": "a", "a/b": "b"}):
        library = catalog.GitHubToolCatalog(tmp_path / "library")
        with pytest.raises(ValueError):
            library.store_source(plan(), source_zip(files), catalog.ImportOperation())
        assert library.list_imports() == []


def test_special_archive_member_is_not_extracted(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        member = zipfile.ZipInfo("root/link")
        member.external_attr = (0o120777 << 16)
        archive.writestr(member, "ordinary-text-target")
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    with pytest.raises(ValueError):
        library.store_source(plan(), buffer.getvalue(), catalog.ImportOperation())


def test_zip_directory_is_bounded_before_parser_allocation(monkeypatch):
    content = bytearray(source_zip())
    position = content.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", content, position + 8, catalog.MAX_ENTRIES + 1, catalog.MAX_ENTRIES + 1)
    monkeypatch.setattr(catalog.zipfile, "ZipFile", lambda *_args: pytest.fail("parser allocated entries"))
    with pytest.raises(ValueError, match="metadata"):
        catalog._open_archive(bytes(content))


def test_actual_archive_and_cache_limits_are_enforced(tmp_path, monkeypatch):
    raw = source_zip()
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    monkeypatch.setattr(catalog, "MAX_ARCHIVE_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="budget"):
        library.store_source(plan(), raw, catalog.ImportOperation())
    monkeypatch.setattr(catalog, "MAX_ARCHIVE_BYTES", len(raw) + 1)
    monkeypatch.setattr(catalog, "MAX_CACHE_BYTES", 1)
    with pytest.raises(ValueError, match="cache limit"):
        library.store_source(plan(), raw, catalog.ImportOperation())
    assert library.list_imports() == []


def test_excessive_compression_ratio_is_rejected(tmp_path):
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    with pytest.raises(ValueError, match="compression ratio"):
        library.store_source(plan(), source_zip({"repeated.txt": "x" * 1024 * 1024}),
                             catalog.ImportOperation())


def test_transport_has_no_redirect_or_ambient_credentials(monkeypatch):
    calls = []

    class Response:
        status = 200
        headers = {"Content-Length": "2"}

        def __enter__(self):
            self.stream = io.BytesIO(b"{}")
            return self

        def __exit__(self, *_args):
            return None

        def geturl(self):
            return "https://api.github.com/repos/example/fixture"

        def read1(self, count):
            return self.stream.read(count)

    class Opener:
        def open(self, request, *, timeout):
            assert request.get_header("Authorization") is None
            assert timeout == 10
            return Response()

    def build(*handlers):
        calls.extend(handlers)
        return Opener()

    monkeypatch.setattr(catalog.urllib.request, "build_opener", build)
    assert catalog._download("https://api.github.com/repos/example/fixture", 10,
                             catalog.ImportOperation()) == b"{}"
    assert calls[0].proxies == {}
    assert isinstance(calls[1], catalog._NoRedirect)
    with pytest.raises(ValueError, match="redirected"):
        calls[1].redirect_request(None, None, 302, "", {}, "https://example.invalid/")


def test_transport_rejects_oversized_declared_response(monkeypatch):
    class Response:
        status = 200
        headers = {"Content-Length": "99999"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def geturl(self):
            return "https://api.github.com/repos/example/fixture"

        def read1(self, count):
            pytest.fail("oversized body was read")

    class Opener:
        def open(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(catalog.urllib.request, "build_opener", lambda *_args: Opener())
    with pytest.raises(ValueError, match="download limit"):
        catalog._download("https://api.github.com/repos/example/fixture", 10,
                          catalog.ImportOperation())


def test_invalid_index_cannot_redirect_archive_read(tmp_path):
    library, _row = saved(tmp_path)
    index_path = library.root / "index.json"
    entries = json.loads(index_path.read_text())
    entries[0]["id"] = "../outside"
    index_path.write_text(json.dumps(entries))
    with pytest.raises(ValueError, match="identity"):
        library.list_imports()


def test_cancellation_before_index_seal_cannot_publish_ready(tmp_path, monkeypatch):
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    operation = catalog.ImportOperation()
    original = catalog._atomic_bytes_write

    def write(path, content, *, root):
        original(path, content, root=root)
        if path.suffix == ".zip":
            assert operation.cancel()

    monkeypatch.setattr(catalog, "_atomic_bytes_write", write)
    with pytest.raises(catalog.ImportCancelled):
        library.store_source(plan(), source_zip(), operation)
    assert library.list_imports() == []
    assert any(path.suffix == ".zip" for path in library.root.iterdir())


def test_durable_save_boundary_reports_too_late_to_cancel(tmp_path, monkeypatch):
    library = catalog.GitHubToolCatalog(tmp_path / "library")
    operation = catalog.ImportOperation()
    original = catalog._atomic_bytes_write

    def write(path, content, *, root):
        if path.name == "index.json":
            assert not operation.cancel()
        original(path, content, root=root)

    monkeypatch.setattr(catalog, "_atomic_bytes_write", write)
    row = library.store_source(plan(), source_zip(), operation)
    assert library.list_imports() == [row]


def test_revocation_persists_and_dedup_does_not_reapprove(tmp_path):
    library, row = saved(tmp_path)
    library.set_review_state(row["id"], "reviewed", catalog.ImportOperation())
    assert library.list_imports()[0]["state"] == "reviewed"
    library.set_review_state(row["id"], "revoked", catalog.ImportOperation())
    reimported = library.store_source(plan(), source_zip(), catalog.ImportOperation())
    assert reimported["state"] == "revoked"
    with pytest.raises(ValueError, match="permanent"):
        library.set_review_state(row["id"], "reviewed", catalog.ImportOperation())


def test_changed_archive_blocks_preview_and_review(tmp_path):
    library, row = saved(tmp_path)
    (library.root / (row["id"] + ".zip")).write_bytes(source_zip({"README.md": "changed"}))
    with pytest.raises(ValueError, match="SHA-256"):
        library.preview(row["id"], "README.md")
    with pytest.raises(ValueError, match="SHA-256"):
        library.set_review_state(row["id"], "reviewed", catalog.ImportOperation())
    # Withdrawing trust remains possible even when the archived bytes are broken.
    library.set_review_state(row["id"], "revoked", catalog.ImportOperation())
    assert library.list_imports()[0]["state"] == "revoked"


def test_preview_bounds_and_binary_metadata(tmp_path):
    library, row = saved(tmp_path, {"binary": b"\x00\xff", "empty": "", "text": "one\u202etwo"})
    assert "Binary" in library.preview(row["id"], "binary")
    assert library.preview(row["id"], "empty") == ""
    assert "\u202e" not in library.preview(row["id"], "text")
    with pytest.raises(ValueError):
        library.preview(row["id"], "not-in-archive")


def test_library_cannot_use_redirected_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError):
        catalog.GitHubToolCatalog(alias).store_source(plan(), source_zip(), catalog.ImportOperation())
    assert list(outside.iterdir()) == []


def test_second_writer_refuses_instead_of_forking_index(tmp_path):
    library, _row = saved(tmp_path)
    with ExclusiveFileLease(library.root / "library.lock"):
        with pytest.raises(ValueError, match="busy"):
            library.list_imports()


def test_cancelled_review_does_not_change_state(tmp_path):
    library, row = saved(tmp_path)
    operation = catalog.ImportOperation()
    operation.cancel()
    with pytest.raises(catalog.ImportCancelled):
        library.set_review_state(row["id"], "reviewed", operation)
    assert library.list_imports()[0]["state"] == "review_only"


def test_no_execution_capability_or_backend_fallback():
    assert "no verified disposable-VM" in catalog.analysis_readiness()
    assert not hasattr(catalog.GitHubToolCatalog, "run")
    assert not hasattr(catalog.GitHubToolCatalog, "execute")


def test_cancel_wait_is_nonblocking_while_download_work_is_pending():
    operation = catalog.ImportOperation()
    pending = threading.Event()
    thread = threading.Thread(target=lambda: pending.wait(1))
    thread.start()
    try:
        assert operation.cancel()
        with pytest.raises(catalog.ImportCancelled):
            operation.check()
    finally:
        pending.set()
        thread.join()
