"""Validate and optionally export the stable v12 built-in capability inventory."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from angerona.core.eventbus import EventBus  # noqa: E402
from angerona.core.module_contract import (  # noqa: E402
    CONTRACT_SCHEMA_ID,
    CONTRACT_SCHEMA_VERSION,
)
from angerona.core.module_manager import ModuleManager  # noqa: E402


class _InventoryConfig:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        raise RuntimeError("inventory export is read-only")


def build_inventory() -> dict:
    previous_data = os.environ.get("ANGERONA_DATA")
    previous_db = os.environ.get("EDR_DB_PATH")
    temporary = tempfile.TemporaryDirectory(prefix="angerona-v12-inventory-")
    root = Path(temporary.name)
    os.environ["ANGERONA_DATA"] = str(root)
    os.environ["EDR_DB_PATH"] = str(root / "flight-recorder.db")
    try:
        manager = ModuleManager(EventBus(), _InventoryConfig(), target_platform="windows")
        manager.discover()
    finally:
        # Some legacy modules initialize a process-global rotating log handler
        # at import time. This is a standalone CLI, so close it before removing
        # the isolated inventory root.
        logging.shutdown()
        if previous_data is None:
            os.environ.pop("ANGERONA_DATA", None)
        else:
            os.environ["ANGERONA_DATA"] = previous_data
        if previous_db is None:
            os.environ.pop("EDR_DB_PATH", None)
        else:
            os.environ["EDR_DB_PATH"] = previous_db
        temporary.cleanup()
    if manager.discovery_errors:
        raise RuntimeError("; ".join(manager.discovery_errors))
    rows = []
    for record in manager.capability_inventory():
        contract = dict(record.get("contract") or {})
        rows.append(
            {
                "capability_id": record["capability_id"],
                "name": record["name"],
                "category": record["category"],
                "implementation_version": record["implementation_version"],
                "metadata_level": record["metadata_level"],
                "metadata_gaps": list(record["metadata_gaps"]),
                "maturity": record["maturity"],
                "mode": contract.get("mode", "unknown"),
                "supported_platforms": list(record["supported_platforms"]),
                "platform_requirements": list(contract.get("platform_requirements", ())),
                "response_authority": record["response_authority"],
                "permissions": list(contract.get("permissions", ())),
                "egress": contract.get("egress", "undeclared"),
                "retention": contract.get("retention", "undeclared"),
                "self_test": record["self_test"],
                "source": record.get("origin", "builtin"),
                "assurance_score": record["assurance_score"],
                "assurance_dimensions": list(
                    (record.get("assurance") or {}).get("dimensions", ())
                ),
                "assurance_reasons": list(
                    (record.get("assurance") or {}).get("reasons", ())
                ),
            }
        )
    rows.sort(key=lambda row: row["capability_id"])
    if len(rows) != 84:
        raise RuntimeError(f"expected 84 built-in capabilities, discovered {len(rows)}")
    identifiers = [row["capability_id"] for row in rows]
    if len(set(identifiers)) != len(identifiers):
        raise RuntimeError("capability inventory contains duplicate identifiers")
    native = sum(row["metadata_level"] == "native" for row in rows)
    return {
        "schema": "angerona.release-capability-inventory.v12",
        "contract_schema": CONTRACT_SCHEMA_ID,
        "contract_schema_version": CONTRACT_SCHEMA_VERSION,
        "assurance_schema": "angerona.capability-assurance.v1",
        "scope": "built-in modules on the Windows target contract",
        "assurance_snapshot_note": (
            "Export is read-only and does not start modules; runtime deductions therefore "
            "describe the intentionally stopped inventory process."
        ),
        "capability_count": len(rows),
        "native_contract_count": native,
        "compatibility_adapter_count": len(rows) - native,
        "capabilities": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    document = build_inventory()
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        target = args.output if args.output.is_absolute() else ROOT / args.output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded, encoding="utf-8")
    print(
        f"PASS: {document['capability_count']} capabilities; "
        f"{document['native_contract_count']} native contracts; "
        f"{document['compatibility_adapter_count']} compatibility adapters"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
