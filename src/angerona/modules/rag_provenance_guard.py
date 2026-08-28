"""Observe-only validator for explicitly configured future RAG sources."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time

from angerona.core.eventbus import Severity
from angerona.core.module_base import BaseModule
from angerona.core.rag_provenance import (
    RAGProvenanceBundle,
    RAGProvenanceError,
    VerifierLike,
    canonical_sha256,
    content_sha256,
    load_rag_provenance_manifest,
)


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


class RAGProvenanceGuardModule(BaseModule):
    CODE = "RAGP"
    NAME = "RAG Provenance Guard"
    name = NAME
    description = (
        "Root-confined, digest-bound, signature-injectable provenance validation "
        "and inert taint labeling for future retrieval sources."
    )
    category = "AI Security"
    version = "1.0.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "An explicitly configured provenance manifest and source root",
        "A caller-owned verifier for publisher-signed trust tiers",
    )

    def __init__(
        self,
        *,
        manifest_path: str | Path | None = None,
        source_root: str | Path | None = None,
        expected_manifest_sha256: str | None = None,
        signature_verifier: VerifierLike | None = None,
        interval_seconds: float = 300.0,
    ) -> None:
        super().__init__()
        self._manifest_path = Path(manifest_path) if manifest_path is not None else None
        self._source_root = Path(source_root) if source_root is not None else None
        self._expected_manifest_sha256 = expected_manifest_sha256
        self._signature_verifier = signature_verifier
        self._interval = max(30.0, min(3600.0, float(interval_seconds)))
        self._last_marker = ""
        self._last_bundle: RAGProvenanceBundle | None = None

    @staticmethod
    def _details(**extra: object) -> dict[str, object]:
        details: dict[str, object] = {
            "response_authorized": False,
            "response_authority": "observe-only",
            "capability_mode": "observe",
            "authority": "data-only",
            "rag_index_mutated": False,
            "defense_memory_mutated": False,
            "excerpt_emitted": False,
        }
        details.update(extra)
        return details

    def observe_once(self) -> dict[str, object]:
        if self._manifest_path is None or self._source_root is None:
            self.set_health(55, "No RAG provenance manifest configured; existing indexes are untouched.")
            return {
                "state": "not-configured",
                "sources": 0,
                "total_bytes": 0,
                "response_authorized": False,
            }
        try:
            bundle = load_rag_provenance_manifest(
                self._manifest_path,
                source_root=self._source_root,
                expected_manifest_sha256=self._expected_manifest_sha256,
                signature_verifier=self._signature_verifier,
            )
        except RAGProvenanceError as exc:
            self._last_bundle = None
            self.set_health(25, "Configured RAG provenance failed closed.")
            marker = f"invalid:{type(exc).__name__}:{str(exc)}"
            if marker != self._last_marker:
                self._last_marker = marker
                self.emit(
                    "Configured RAG source provenance failed strict admission.",
                    Severity.HIGH,
                    **self._details(
                        finding_code="rag_provenance.admission_failed",
                        provenance_state="untrusted",
                        rejection_type=type(exc).__name__,
                        rejection_reason=str(exc)[:160],
                    ),
                )
            return {
                "state": "untrusted",
                "sources": 0,
                "total_bytes": 0,
                "response_authorized": False,
            }
        self._last_bundle = bundle
        signed = sum(item.signature_verified for item in bundle.sources)
        marker = f"valid:{bundle.manifest_sha256}:{len(bundle.sources)}:{signed}"
        if marker != self._last_marker:
            self._last_marker = marker
            self.emit(
                "Configured RAG provenance validated as inert data-only sources.",
                Severity.INFO,
                **self._details(
                    finding_code="rag_provenance.validated",
                    provenance_state="validated",
                    manifest_id=bundle.manifest_id,
                    manifest_sha256=bundle.manifest_sha256,
                    manifest_pinned=bundle.manifest_pinned,
                    source_count=len(bundle.sources),
                    signed_source_count=signed,
                    total_bytes=bundle.total_bytes,
                    taint_labels=sorted({item.taint_label for item in bundle.sources}),
                ),
            )
        self.set_health(
            90 if bundle.manifest_pinned else 75,
            f"{len(bundle.sources)} bounded source(s) validated; no index mutation performed.",
        )
        return {
            "state": "validated",
            "sources": len(bundle.sources),
            "signed_sources": signed,
            "total_bytes": bundle.total_bytes,
            "manifest_pinned": bundle.manifest_pinned,
            "response_authorized": False,
        }

    def self_test(self) -> tuple[bool, str]:
        try:
            with tempfile.TemporaryDirectory(prefix="angerona-rag-provenance-") as temp:
                root = Path(temp)
                content = b"# Defensive reference\nReview evidence before action.\n"
                source = root / "reference.md"
                source.write_bytes(content)
                document = {
                    "schema": "angerona.rag-provenance.v1",
                    "manifest_id": "selftest-manifest",
                    "version": "1.0.0",
                    "sources": [{
                        "source_id": "defensive-reference",
                        "relative_path": "reference.md",
                        "media_type": "text/markdown",
                        "trust_tier": "builtin-pinned",
                        "content_sha256": content_sha256(content),
                        "publisher": "angerona",
                        "signature": "",
                    }],
                }
                manifest = root / "manifest.json"
                manifest.write_text(json.dumps(document), encoding="utf-8")
                bundle = load_rag_provenance_manifest(
                    manifest,
                    source_root=root,
                    expected_manifest_sha256=canonical_sha256(document),
                )
                if len(bundle.sources) != 1 or not bundle.manifest_pinned:
                    return False, "pinned RAG provenance did not validate"
                excerpt = bundle.excerpts[0]
                if (
                    excerpt.instructions_active
                    or excerpt.response_authorized
                    or excerpt.authority != "data-only"
                ):
                    return False, "inert excerpt authority boundary failed"
        except Exception as exc:
            return False, f"RAG provenance bounded self-test failed: {exc}"
        return True, "root confinement, digest pinning, and inert excerpt boundary verified"

    def run(self) -> None:
        initial = self.observe_once()
        self.emit(
            "RAG Provenance Guard online; validation does not register or index sources.",
            Severity.INFO,
            **self._details(
                finding_code="rag_provenance.guard.online",
                provenance_state=initial["state"],
            ),
        )
        while not self.stopping:
            self.sleep(self._interval)
            if not self.stopping:
                self.observe_once()


__all__ = ["RAGProvenanceGuardModule"]
