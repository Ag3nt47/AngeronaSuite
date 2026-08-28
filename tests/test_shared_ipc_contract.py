from __future__ import annotations

import hashlib
from pathlib import Path

from angerona.resilience import ipc_ring


ROOT = Path(__file__).resolve().parents[1]


def test_shared_ipc_contract_is_pinned_to_reference_implementation() -> None:
    prose = (ROOT / "shared-ipc" / "CONTRACT.md").read_text(encoding="utf-8")

    assert f"version (**{ipc_ring._VERSION}**)" in prose
    assert f"slot_count (default {ipc_ring.DEFAULT_SLOT_COUNT})" in prose
    assert f"slot_size (default **{ipc_ring.DEFAULT_SLOT_SIZE}**)" in prose
    assert f'`"{ipc_ring._REC_FMT}"` header' in prose
    assert "seq u64" in prose
    assert f"{hashlib.sha256().digest_size}-byte HMAC-SHA256 tag" in prose
    assert ipc_ring._FRAME_AAD[:-1].decode("ascii") in prose
    assert "<data>/ipc_ring.key" in prose
    assert "seq u32" not in prose
    assert 'Record = `"<HHI"`' not in prose
