"""Offline command: verify an Angerona update bundle against a trust store."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from angerona.core.release_assurance import verify_update_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("trust_store", type=Path,
                        help="JSON object mapping publisher IDs to base64 Ed25519 public keys")
    args = parser.parse_args()
    raw = json.loads(args.trust_store.read_text(encoding="utf-8"))
    trust = {
        name: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        for name, value in raw.items()
    }
    result = verify_update_bundle(args.bundle, trust)
    print(json.dumps({
        "valid": result.valid, "errors": result.errors,
        "publisher_id": result.publisher_id,
        "version": result.manifest.version if result.manifest else None,
    }, sort_keys=True))
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
