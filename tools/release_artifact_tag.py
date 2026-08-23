"""Derive a deterministic filesystem-safe label for manual release builds."""
from __future__ import annotations

import hashlib
import os
import re


_MAX_TAG_LENGTH = 80
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_DASH_RUN = re.compile(r"-{2,}")


def resolve_artifact_tag(ref_name: str, event_name: str) -> str:
    """Keep release tags unchanged; sanitize manual-dispatch branch names.

    A short digest is appended whenever normalization changes a manual ref so
    branches such as ``feature/a`` and ``feature-a`` cannot overwrite the same
    artifact name. The result is a single path component of bounded length.
    """
    raw = str(ref_name)
    if event_name == "push":
        return raw
    if event_name != "workflow_dispatch":
        raise ValueError("unsupported release event")

    normalized = _DASH_RUN.sub("-", _UNSAFE.sub("-", raw)).strip("._-")
    if not normalized:
        normalized = "manual"
    changed = normalized != raw or len(normalized) > _MAX_TAG_LENGTH
    if not changed:
        return normalized

    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    prefix_limit = _MAX_TAG_LENGTH - len(digest) - 1
    prefix = normalized[:prefix_limit].rstrip("._-") or "manual"
    return f"{prefix}-{digest}"


def main() -> int:
    event_name = os.environ.get("ANGERONA_RELEASE_EVENT", "")
    ref_name = os.environ.get("ANGERONA_RELEASE_REF", "")
    if not event_name or not ref_name:
        raise SystemExit("release event and ref environment variables are required")
    print(resolve_artifact_tag(ref_name, event_name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
