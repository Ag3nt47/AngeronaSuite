"""The ransomware content proof keeps exact results with reused window counts."""

from __future__ import annotations

import hashlib
import os

import pytest

from angerona.modules import ransomware_heuristics as ransomware


@pytest.mark.parametrize("complete", [True, False])
def test_full_window_histogram_reuse_matches_partial_read_path(
    tmp_path, monkeypatch, complete,
) -> None:
    data = b"A" * 65536 + bytes(range(256)) * 256 + b"B" * 8192
    path = tmp_path / "bounded-proof.bin"
    path.write_bytes(data)
    ranges = (((0, len(data)),) if complete else
              ((0, 65536), (len(data) - 65536, 65536)))

    real_histogram = ransomware._byte_histogram
    histogram_calls = []

    def counted_histogram(chunk):
        histogram_calls.append(len(chunk))
        return real_histogram(chunk)

    with path.open("rb") as file:
        with monkeypatch.context() as patch:
            patch.setattr(ransomware, "_byte_histogram", counted_histogram)
            direct = ransomware.RansomwareHeuristicsModule._read_content_sample(
                file.fileno(), ranges, complete=complete,
            )

        # Full OS reads admit the reuse branch. A capped read forces the
        # original accumulation branch across the same authenticated ranges.
        real_read = os.read

        def short_read(descriptor, size):
            return real_read(descriptor, min(size, 16384))

        with monkeypatch.context() as patch:
            patch.setattr(ransomware.os, "read", short_read)
            fragmented = ransomware.RansomwareHeuristicsModule._read_content_sample(
                file.fileno(), ranges, complete=complete,
            )

    assert direct == fragmented
    assert direct.ranges == ranges
    assert direct.size == sum(length for _offset, length in ranges)
    if complete:
        assert histogram_calls == [65536, 65536, 8192, 8192]
        assert direct.entropy == 8.0
        assert direct.sha256 == hashlib.sha256(data).hexdigest()
    else:
        assert histogram_calls == [65536, 65536]
