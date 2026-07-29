import io
import stat
import zipfile

import pytest

from angerona.connectors.voice import (
    _approved_model_url,
    _extract_verified_model_archive,
)
from angerona.core.archive_safety import safe_archive_path, validate_zip_members


@pytest.mark.parametrize(
    "name",
    (
        "../escape",
        "/absolute",
        r"folder\escape",
        "C:/drive",
        "file.txt:stream",
        "NUL",
        "folder/COM1.log",
        "folder/trailing.",
        "folder/trailing ",
        "folder/\x00hidden",
        "folder/\u0065\u0301.txt",
        "folder//file.txt",
        "folder/./file.txt",
    ),
)
def test_archive_paths_reject_traversal_and_windows_aliases(name):
    with pytest.raises(ValueError):
        safe_archive_path(name)


def test_zip_metadata_rejects_case_collisions_and_special_files():
    first = zipfile.ZipInfo("Model/file.bin")
    second = zipfile.ZipInfo("model/FILE.bin")
    with pytest.raises(ValueError, match="colliding"):
        validate_zip_members(
            (first, second),
            max_files=10,
            max_member_bytes=100,
            max_total_bytes=200,
            max_ratio=10,
        )

    symlink = zipfile.ZipInfo("model/link")
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ValueError, match="special"):
        validate_zip_members(
            (symlink,),
            max_files=10,
            max_member_bytes=100,
            max_total_bytes=200,
            max_ratio=10,
        )


def _model_zip(*, unsafe: bool = False) -> zipfile.ZipFile:
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vosk-model-small-en-us-0.15/am/final.mdl", b"model")
        if unsafe:
            archive.writestr("vosk-model-small-en-us-0.15/COM1.log", b"alias")
    memory.seek(0)
    bundle = zipfile.ZipFile(memory)
    bundle._test_memory = memory
    return bundle


def test_voice_model_extraction_is_bounded_and_prevalidates_all_members(tmp_path):
    with _model_zip() as bundle:
        _extract_verified_model_archive(bundle, tmp_path / "safe")
    assert (
        tmp_path
        / "safe"
        / "vosk-model-small-en-us-0.15"
        / "am"
        / "final.mdl"
    ).read_bytes() == b"model"

    unsafe_root = tmp_path / "unsafe"
    unsafe_root.mkdir()
    with _model_zip(unsafe=True) as bundle:
        with pytest.raises(ValueError, match="unsafe archive path"):
            _extract_verified_model_archive(bundle, unsafe_root)
    assert list(unsafe_root.rglob("*")) == []


@pytest.mark.parametrize(
    "url",
    (
        "http://alphacephei.com/model.zip",
        "https://example.invalid/model.zip",
        "file:///etc/passwd",
        "https://user:secret@alphacephei.com/model.zip",
        "https://alphacephei.com:444/model.zip",
        "https://alphacephei.com:invalid/model.zip",
    ),
)
def test_voice_model_download_cannot_leave_pinned_https_origin(url):
    with pytest.raises(RuntimeError, match="speech model URL"):
        _approved_model_url(url)
    assert _approved_model_url(
        "https://alphacephei.com/vosk/models/model.zip"
    ) == "https://alphacephei.com/vosk/models/model.zip"
