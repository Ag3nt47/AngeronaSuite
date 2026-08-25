from __future__ import annotations

import math

from angerona.core.runbook_rag import RunbookRAG


def _reference_bm25(rag: RunbookRAG, query_terms: list[str], chunk) -> float:
    """The pre-index implementation, retained as an exact behaviour oracle."""
    if not chunk.tokens:
        return 0.0
    frequencies: dict[str, int] = {}
    for term in chunk.tokens:
        frequencies[term] = frequencies.get(term, 0) + 1
    score = 0.0
    for term in query_terms:
        frequency = frequencies.get(term, 0)
        if frequency == 0:
            continue
        document_frequency = rag._df.get(term, 0)
        inverse_frequency = math.log(
            1
            + (
                rag._n - document_frequency + 0.5
            ) / (document_frequency + 0.5)
        )
        denominator = frequency + rag._K1 * (
            1
            - rag._B
            + rag._B * len(chunk.tokens) / (rag._avgdl or 1)
        )
        score += (
            inverse_frequency
            * (frequency * (rag._K1 + 1))
            / denominator
        )
    return score


def test_runbook_rag_preindexed_bm25_is_exactly_equivalent() -> None:
    rag = RunbookRAG()
    rag.add_document(
        "# Containment\nIsolate isolate the endpoint and preserve evidence.\n"
        "## Recovery\nRestore from a verified backup and rotate credentials.",
        "incident.md",
    )
    rag.add_document(
        "# Triage\nPreserve the endpoint timeline and inspect credentials.",
        "triage.md",
    )

    terms = ["isolate", "endpoint", "credentials", "isolate"]
    for chunk in rag._chunks:
        assert chunk.term_freq
        assert chunk.length_norm > 0
        assert rag._bm25(terms, chunk) == _reference_bm25(rag, terms, chunk)

    before = [(hit.score, hit.source, hit.heading) for hit in rag.query(
        "isolate endpoint credentials isolate", k=3
    )]
    after = [(hit.score, hit.source, hit.heading) for hit in rag.query(
        "isolate endpoint credentials isolate", k=3
    )]
    assert after == before
