"""core/runbook_rag.py — local Runbook RAG over your own markdown playbooks.

ARIA answers "how do we handle ransomware?" from *your* procedures, not from a
model's imagination. It indexes the markdown under your docs/ folders, chunks
each file by heading, and ranks chunks with BM25 — pure Python, no numpy, no
embeddings, no network. The answer is a set of citations back to your own docs
(file + heading), so every reply is grounded and auditable.

Local-first and additive: nothing is indexed until you call :meth:`build`, and
the module is wired into nothing at import. If there are no docs, queries return
an empty result with an honest note rather than fabricating an answer.

    HARD SCOPE: retrieval only. This module never executes a runbook step, never
    calls a model, and never leaves the machine. It hands ARIA passages; any
    action stays gated in the assistant.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")

# Tiny English stop-list so common words don't dominate scoring.
_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are",
    "we", "our", "do", "does", "how", "what", "with", "this", "that", "it",
    "as", "at", "by", "be", "from", "you", "your", "if", "when", "which",
}


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP and len(t) > 1]


@dataclass
class Chunk:
    source: str          # relative file path
    heading: str         # nearest heading, or "(intro)"
    text: str            # raw chunk body
    tokens: list[str] = field(default_factory=list, repr=False)


@dataclass
class Hit:
    score: float
    source: str
    heading: str
    excerpt: str


class RunbookRAG:
    """BM25 retrieval index over markdown playbooks.

    Usage::

        rag = get_rag(["F:/Angerona/docs", "F:/Angerona/playbooks"])
        rag.build()
        for hit in rag.query("how do we handle ransomware", k=3):
            print(hit.source, hit.heading, round(hit.score, 2))
        print(rag.answer("ransomware containment steps"))
    """

    # BM25 parameters (standard defaults).
    _K1 = 1.5
    _B = 0.75

    def __init__(self, roots: Iterable[str] | None = None,
                 exts: tuple[str, ...] = (".md", ".markdown", ".txt")) -> None:
        self.roots = [str(r) for r in (roots or [])]
        self.exts = exts
        self._chunks: list[Chunk] = []
        self._df: dict[str, int] = {}        # document frequency per term
        self._avgdl: float = 0.0
        self._n: int = 0
        self.last_error: str = ""

    # ── Index build ───────────────────────────────────────────────────────────
    def build(self) -> int:
        """(Re)build the index from the configured roots. Returns chunk count.
        Never raises on a bad file — it is skipped and noted."""
        chunks: list[Chunk] = []
        for root in self.roots:
            p = Path(root)
            if not p.exists():
                continue
            for fp in sorted(p.rglob("*")):
                if fp.is_file() and fp.suffix.lower() in self.exts:
                    try:
                        rel = os.path.relpath(str(fp), root)
                        chunks.extend(self._split(fp.read_text(encoding="utf-8", errors="replace"), rel))
                    except Exception as exc:
                        self.last_error = f"{fp}: {exc}"
        self._ingest(chunks)
        return self._n

    def add_document(self, text: str, source: str) -> None:
        """Index an in-memory document (used by tests / dynamic content)."""
        self._ingest(self._chunks + self._split(text, source))

    @staticmethod
    def _split(text: str, source: str) -> list[Chunk]:
        """Split a markdown document into heading-scoped chunks."""
        chunks: list[Chunk] = []
        heading = "(intro)"
        buf: list[str] = []

        def flush() -> None:
            body = "\n".join(buf).strip()
            if body:
                chunks.append(Chunk(source, heading, body, _tokenize(heading + " " + body)))

        for line in text.splitlines():
            m = _HEADING_RE.match(line.strip())
            if m:
                flush()
                heading = m.group(2).strip() or "(section)"
                buf = []
            else:
                buf.append(line)
        flush()
        return chunks

    def _ingest(self, chunks: list[Chunk]) -> None:
        self._chunks = chunks
        self._n = len(chunks)
        self._df = {}
        total_len = 0
        for c in chunks:
            total_len += len(c.tokens)
            for term in set(c.tokens):
                self._df[term] = self._df.get(term, 0) + 1
        self._avgdl = (total_len / self._n) if self._n else 0.0

    # ── Query ─────────────────────────────────────────────────────────────────
    def query(self, text: str, k: int = 5) -> list[Hit]:
        """Return the top-``k`` chunks by BM25 score for the query text."""
        q_terms = _tokenize(text)
        if not q_terms or self._n == 0:
            return []
        scored: list[Hit] = []
        for c in self._chunks:
            s = self._bm25(q_terms, c)
            if s > 0:
                scored.append(Hit(s, c.source, c.heading, self._excerpt(c.text, q_terms)))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:k]

    def _bm25(self, q_terms: list[str], c: Chunk) -> float:
        if not c.tokens:
            return 0.0
        dl = len(c.tokens)
        tf: dict[str, int] = {}
        for t in c.tokens:
            tf[t] = tf.get(t, 0) + 1
        score = 0.0
        for term in q_terms:
            f = tf.get(term, 0)
            if f == 0:
                continue
            df = self._df.get(term, 0)
            # BM25 idf with +1 so it never goes negative on very common terms.
            idf = math.log(1 + (self._n - df + 0.5) / (df + 0.5))
            denom = f + self._K1 * (1 - self._B + self._B * dl / (self._avgdl or 1))
            score += idf * (f * (self._K1 + 1)) / denom
        return score

    @staticmethod
    def _excerpt(text: str, q_terms: set[str] | list[str], width: int = 240) -> str:
        """A short passage centred on the first query-term hit."""
        terms = set(q_terms)
        low = text.lower()
        pos = -1
        for t in terms:
            i = low.find(t)
            if i != -1 and (pos == -1 or i < pos):
                pos = i
        if pos == -1:
            snippet = text[:width]
        else:
            start = max(0, pos - width // 3)
            snippet = text[start:start + width]
        snippet = " ".join(snippet.split())
        return (("… " if pos > width // 3 else "") + snippet + (" …" if len(text) > width else "")).strip()

    def answer(self, text: str, k: int = 3) -> str:
        """A grounded, citation-first answer assembled from the top chunks.
        Never fabricates: if nothing matches, says so."""
        hits = self.query(text, k=k)
        if not hits:
            if self._n == 0:
                return ("No runbooks are indexed yet. Point RunbookRAG at your docs/ "
                        "playbooks and call build().")
            return "No matching procedure found in your runbooks for that question."
        lines = [f"From your runbooks ({len(hits)} match{'es' if len(hits) > 1 else ''}):"]
        for i, h in enumerate(hits, 1):
            lines.append(f"\n{i}. {h.source} › {h.heading}\n   {h.excerpt}")
        return "\n".join(lines)

    def health_pct(self) -> int:
        return 100 if self._n > 0 else 50

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Build an index over two synthetic playbooks and verify that a
        ransomware question retrieves the ransomware runbook (not phishing),
        heading scoping works, and an unmatched query returns nothing."""
        try:
            rag = RunbookRAG()
            rag.add_document(
                "# Ransomware Response\n"
                "When ransomware is detected, isolate the host from the network, "
                "identify the ransomware family, and preserve encrypted samples. "
                "Do not pay. Restore from known-good backups.\n"
                "## Containment\n"
                "Pull the network cable or trigger firewall isolation immediately.",
                source="ransomware.md",
            )
            rag.add_document(
                "# Phishing Response\n"
                "When a phishing email is reported, quarantine the message, "
                "reset the recipient credentials, and hunt for similar lures.",
                source="phishing.md",
            )
            assert rag._n == 3, f"expected 3 chunks, got {rag._n}"

            hits = rag.query("how do we handle a ransomware infection", k=3)
            assert hits, "ransomware query must return hits"
            assert hits[0].source == "ransomware.md", "ransomware doc must rank first"

            # heading scoping: containment question should surface the Containment section
            chits = rag.query("network isolation containment", k=3)
            assert any(h.heading == "Containment" for h in chits), "heading-scoped chunk retrieved"

            # phishing question should prefer the phishing doc
            phits = rag.query("phishing email credential reset", k=2)
            assert phits and phits[0].source == "phishing.md", "phishing doc ranks first for its query"

            # unmatched query → empty, and answer() is honest
            assert rag.query("quantum chromodynamics", k=3) == [], "no false positives"
            assert "No matching" in rag.answer("quantum chromodynamics"), "honest miss"

            # empty index → graceful
            assert RunbookRAG().query("anything") == [], "empty index safe"
            assert "No runbooks" in RunbookRAG().answer("anything"), "empty index honest"

            return True, ("OK — 3 chunks from 2 playbooks; ransomware query ranks "
                          "ransomware.md first; Containment heading retrieved; phishing "
                          "query ranks phishing.md first; unmatched query returns nothing; "
                          "empty index degrades honestly.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory (mirrors gpu_entropy.get_pipeline) ───────────────────────
_RAG: Optional[RunbookRAG] = None


def init_rag(roots: Iterable[str]) -> RunbookRAG:
    """Create/replace the shared index and build it. Call once if you opt in."""
    global _RAG
    _RAG = RunbookRAG(roots)
    _RAG.build()
    return _RAG


def get_rag(roots: Iterable[str] | None = None) -> RunbookRAG:
    """Return the shared index, lazily creating an empty one if needed."""
    global _RAG
    if _RAG is None:
        _RAG = RunbookRAG(roots)
    return _RAG


if __name__ == "__main__":
    ok, detail = RunbookRAG().self_test()
    print(f"[runbook_rag] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
