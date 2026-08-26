from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.core.defense_memory as memory_module
from angerona.core.defense_memory import (
    BUILTIN_DEFENSE_MEMORY_SHA256,
    DEFENSE_MEMORY_SOURCE,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_MARKDOWN_CHARS,
    DefenseMemoryError,
    bundled_defense_memory,
    canonical_sha256,
    load_defense_memory,
)
from angerona.core.runbook_rag import Hit, RunbookRAG
from angerona.gui.main_window import MainWindow


ASSET = Path("assets/angerona_defense_memory.json")


def _write_document(tmp_path: Path, document: dict, name: str = "memory.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_bundled_memory_is_load_once_pinned_bounded_and_data_only() -> None:
    first = bundled_defense_memory()
    second = bundled_defense_memory()
    markdown = first.to_markdown()

    assert first is second
    assert first.schema_version == 1
    assert first.memory_id == "angerona-defense-memory"
    assert 1 <= len(first.entries) <= MAX_ENTRIES
    assert ASSET.stat().st_size <= MAX_FILE_BYTES
    assert len(markdown) <= MAX_MARKDOWN_CHARS
    assert "system prompt" not in markdown.casefold()
    assert "-----begin" not in markdown.casefold()
    assert "password=" not in markdown.casefold()
    assert "```" not in markdown
    assert all(
        name not in markdown.casefold()
        for name in (" cia ", " nsa ", " fsb ", " gru ", " gchq ")
    )

    raw = json.loads(ASSET.read_text(encoding="utf-8"))
    assert canonical_sha256(raw) == BUILTIN_DEFENSE_MEMORY_SHA256
    assert raw["governance"] == {
        "classification": "defensive-reference",
        "authority": "read-only",
        "contains_live_data": False,
        "contains_secrets": False,
        "contains_executable_actions": False,
        "contains_offensive_procedures": False,
        "agency_attribution": "prohibited",
    }


@pytest.mark.parametrize(
    ("question", "expected_heading"),
    [
        (
            "what capabilities does Angerona have and how do I use the dashboard",
            "Angerona capability map and operator workflow",
        ),
        (
            "how should I harden SSH remote access",
            "SSH Surface / Key / Tunnel Guard",
        ),
        (
            "what do I do if Windows event logs were erased or cleared",
            "Audit-log clearing and telemetry continuity defense",
        ),
        (
            "should I trust Wi-Fi or use an intermediate personal firewall router",
            "Personal Sentinel Gateway intermediate firewall",
        ),
    ],
)
def test_memory_retrieves_requested_defensive_topics(
    question: str,
    expected_heading: str,
) -> None:
    rag = RunbookRAG()
    rag.add_document(
        bundled_defense_memory().to_markdown(), source=DEFENSE_MEMORY_SOURCE
    )

    hits = rag.query(question, k=3)

    assert hits
    assert hits[0].source == DEFENSE_MEMORY_SOURCE
    assert hits[0].heading == expected_heading


def test_digest_duplicate_schema_and_content_tampering_fail_closed(
    tmp_path: Path,
) -> None:
    original = json.loads(ASSET.read_text(encoding="utf-8"))

    altered = json.loads(json.dumps(original))
    altered["entries"][0]["summary"] += " altered"
    altered_path = _write_document(tmp_path, altered, "altered.json")
    with pytest.raises(DefenseMemoryError, match="digest"):
        load_defense_memory(
            altered_path, expected_sha256=BUILTIN_DEFENSE_MEMORY_SHA256
        )

    unknown = json.loads(json.dumps(original))
    unknown["entries"][0]["prompt"] = "not permitted"
    unknown_path = _write_document(tmp_path, unknown, "unknown.json")
    with pytest.raises(DefenseMemoryError, match="strict schema"):
        load_defense_memory(
            unknown_path, expected_sha256=canonical_sha256(unknown)
        )

    wrong_type = json.loads(json.dumps(original))
    wrong_type["schema_version"] = True
    wrong_type["governance"]["contains_live_data"] = 0
    wrong_type_path = _write_document(tmp_path, wrong_type, "wrong-type.json")
    with pytest.raises(DefenseMemoryError, match="schema version"):
        load_defense_memory(
            wrong_type_path, expected_sha256=canonical_sha256(wrong_type)
        )

    sensitive = json.loads(json.dumps(original))
    sensitive["entries"][0]["summary"] = "password=must-not-enter-memory"
    sensitive_path = _write_document(tmp_path, sensitive, "sensitive.json")
    with pytest.raises(DefenseMemoryError, match="inert defensive boundary"):
        load_defense_memory(
            sensitive_path, expected_sha256=canonical_sha256(sensitive)
        )

    too_many = json.loads(json.dumps(original))
    template = {
        "id": "bounded-entry-0",
        "title": "Bounded defensive entry",
        "summary": "A small defensive reference used to exercise the count bound.",
        "keywords": ["bounded", "defensive", "reference"],
        "guidance": [
            "Review defensive evidence.",
            "Keep authority narrow.",
        ],
        "limits": ["This reference is advisory."],
        "tradecraft_mappings": [],
    }
    too_many["entries"] = []
    for index in range(MAX_ENTRIES + 1):
        row = json.loads(json.dumps(template))
        row["id"] = f"bounded-entry-{index}"
        too_many["entries"].append(row)
    too_many_path = _write_document(tmp_path, too_many, "too-many.json")
    with pytest.raises(DefenseMemoryError, match="entries"):
        load_defense_memory(
            too_many_path, expected_sha256=canonical_sha256(too_many)
        )

    too_deep = json.loads(json.dumps(original))
    too_deep["unexpected"] = [[[[[[["bounded"]]]]]]]
    too_deep_path = _write_document(tmp_path, too_deep, "too-deep.json")
    with pytest.raises(DefenseMemoryError, match="depth"):
        load_defense_memory(
            too_deep_path, expected_sha256=canonical_sha256(too_deep)
        )

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":1,"schema_version":1}', encoding="utf-8"
    )
    with pytest.raises(DefenseMemoryError, match="duplicate"):
        load_defense_memory(
            duplicate, expected_sha256=BUILTIN_DEFENSE_MEMORY_SHA256
        )

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_FILE_BYTES + 1))
    with pytest.raises(DefenseMemoryError, match="file-size"):
        load_defense_memory(
            oversized, expected_sha256=BUILTIN_DEFENSE_MEMORY_SHA256
        )


def test_loader_uses_bounded_descriptor_read_and_enforces_resource_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    document = json.loads(ASSET.read_text(encoding="utf-8"))
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = _write_document(allowed, document)
    outside = _write_document(tmp_path, document, "outside.json")

    def reject_unbounded_read(_path: Path) -> bytes:
        raise AssertionError("Path.read_bytes must not cross the bounded-read boundary")

    monkeypatch.setattr(Path, "read_bytes", reject_unbounded_read)
    loaded = load_defense_memory(
        source,
        expected_sha256=canonical_sha256(document),
        allowed_root=allowed,
    )
    assert loaded.memory_id == "angerona-defense-memory"
    with pytest.raises(DefenseMemoryError, match="outside its resource root"):
        load_defense_memory(
            outside,
            expected_sha256=canonical_sha256(document),
            allowed_root=allowed,
        )


def test_loader_rejects_link_and_opened_identity_swap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    document = json.loads(ASSET.read_text(encoding="utf-8"))
    digest = canonical_sha256(document)
    source = _write_document(tmp_path, document, "source.json")
    alternate = _write_document(tmp_path, document, "alternate.json")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(source)
    except OSError:
        link = None
    if link is not None:
        with pytest.raises(DefenseMemoryError, match="unsafe"):
            load_defense_memory(link, expected_sha256=digest, allowed_root=tmp_path)

    original_open = memory_module.os.open

    def swapped_open(_path, flags):
        return original_open(alternate, flags)

    monkeypatch.setattr(memory_module.os, "open", swapped_open)
    with pytest.raises(DefenseMemoryError, match="changed while opening"):
        load_defense_memory(source, expected_sha256=digest, allowed_root=tmp_path)


def test_main_window_rebuild_adds_only_the_verified_in_memory_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "operator.md").write_text(
        "# Operator note\nLocal-only operator material.", encoding="utf-8"
    )
    # Resolve and pin the read-only bundle before redirecting only the runbook
    # roots used by this isolated rebuild.
    bundled_defense_memory()
    monkeypatch.setattr("angerona.core.data_paths.project_root", lambda: tmp_path)
    owner = SimpleNamespace(
        config=SimpleNamespace(data_dir=tmp_path),
        aria_model_packs=None,
        _aria_rag=None,
    )

    count = MainWindow._rebuild_aria_rag(owner)

    assert count >= len(bundled_defense_memory().entries)
    memory_hits = owner._aria_rag.query("SSH event log clearing router", k=10)
    assert any(hit.source == DEFENSE_MEMORY_SOURCE for hit in memory_hits)
    assert sum(
        chunk.source == DEFENSE_MEMORY_SOURCE
        for chunk in owner._aria_rag._chunks
    ) == len(bundled_defense_memory().entries)
    assert any(chunk.source == "operator.md" for chunk in owner._aria_rag._chunks)


def test_cloud_fallback_receives_only_pinned_memory_excerpts(
    monkeypatch,
) -> None:
    class MixedRag:
        def query(self, _question: str, k: int = 3):
            assert k == 3
            return [
                Hit(
                    9.0,
                    "operator-private.md",
                    "Private operator runbook",
                    "OPERATOR_FILE_CONTENT_MUST_STAY_LOCAL",
                ),
                Hit(
                    8.0,
                    DEFENSE_MEMORY_SOURCE,
                    "SSH Surface / Key / Tunnel Guard",
                    "PINNED_MEMORY_EXCERPT_FOR_CLOUD",
                ),
                Hit(
                    7.0,
                    "data-dir-runbooks/live.txt",
                    "Live local note",
                    "DATA_DIR_CONTENT_MUST_STAY_LOCAL",
                ),
            ]

    local_payloads: list[str] = []
    cloud_payloads: list[str] = []

    def local_call(payload, *_args, **_kwargs):
        local_payloads.append(payload["prompt"])
        return {"error": "offline"}

    def cloud_call(prompt: str, **_kwargs):
        cloud_payloads.append(prompt)
        return {"text": "bounded answer", "provider": "test"}

    monkeypatch.setattr("angerona.engines.ollama_client.call", local_call)
    monkeypatch.setattr("angerona.engines.ai_consult.consult_ai", cloud_call)
    owner = SimpleNamespace(
        _aria_rag=MixedRag(),
        _last_posture={"score": 80, "label": "Guarded"},
        _ARIA_ARCH="LOCAL_ARCHITECTURE_REFERENCE",
        _ARIA_COACH="LOCAL_COACH_REFERENCE",
        _aria_context=lambda: "LIVE_TELEMETRY_MUST_STAY_LOCAL",
        aria_awareness=None,
        config=SimpleNamespace(
            aria_persona="aria",
            ollama_model="llama3",
            ollama_host=None,
            ollama_keep_alive="30m",
            aria_cloud_fallback=True,
        ),
    )

    answer = MainWindow._aria_converse(owner, "How should I review SSH posture?")

    assert "bounded answer" in answer
    assert local_payloads
    assert "OPERATOR_FILE_CONTENT_MUST_STAY_LOCAL" in local_payloads[0]
    assert "LIVE_TELEMETRY_MUST_STAY_LOCAL" in local_payloads[0]
    assert len(cloud_payloads) == 1
    cloud = cloud_payloads[0]
    assert "PINNED_MEMORY_EXCERPT_FOR_CLOUD" in cloud
    assert DEFENSE_MEMORY_SOURCE in cloud
    assert "OPERATOR_FILE_CONTENT_MUST_STAY_LOCAL" not in cloud
    assert "DATA_DIR_CONTENT_MUST_STAY_LOCAL" not in cloud
    assert "LIVE_TELEMETRY_MUST_STAY_LOCAL" not in cloud
    assert "LOCAL_ARCHITECTURE_REFERENCE" not in cloud
    assert "Personal Sentinel Gateway intermediate firewall" not in cloud
    assert len(cloud) < 2500
    assert ASSET.read_text(encoding="utf-8") not in cloud
