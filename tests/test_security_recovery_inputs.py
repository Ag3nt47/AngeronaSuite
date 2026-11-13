"""Independent recovery inventory/pin consistency; no launcher is executed."""
import hashlib
import importlib.util
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_reviewed_recovery_inventory_matches_authoritative_builder_and_batch_pins():
    path = ROOT / "tools" / "build_startup_recovery_manifest.py"
    spec = importlib.util.spec_from_file_location("security_recovery_manifest_fixture", path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    assert {"src/angerona/resilience/control_authority.py",
            "src/angerona/resilience/deadman.py", "src/angerona/resilience/peer_alerts.py"} <= set(builder.FILES)
    raw, pins = builder.build_manifest(ROOT)
    actual = builder.canonical_text((ROOT / builder.MANIFEST).read_bytes())
    assert actual == raw
    batch = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")
    for variable, expected in (("manifestSha", pins["manifest_sha256"]),
                               ("manifestBlob", pins["manifest_blob_sha1"]),
                               ("verifierSha", pins["verifier_sha256"]),
                               ("verifierBlob", pins["verifier_blob_sha1"])):
        values = re.findall(r"\$" + variable + r"='([0-9a-f]+)'", batch)
        assert values == [expected]
    assert pins["manifest_sha256"] == hashlib.sha256(actual).hexdigest()
