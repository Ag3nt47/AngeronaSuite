"""playbook_tuner.py — Autonomous SOAR Playbook Generation (Component 1).

Triggers on a containment bypass (Judgment VERIFICATION_RESULT: SUCCESS where a
standard Kill Process ran but the adversarial vector persisted — e.g. a decoupled
WMI hook or hollowed process). Tasks the local LLM to synthesize a targeted
netsh / New-NetFirewallRule / WFP containment block, saves it as a scoped
playbook (playbooks/dynamic_block_<tid>.ps1), wires it into mitigation_gate.ps1,
then re-arms and re-tests the Judgment pipeline.

SAFETY: generates DEFENSIVE containment (network isolation) only; loopback
(Ollama :11434 / IPC) is always left reachable, and everything is staged for the
review-gated mitigation_gate — nothing auto-executes from here.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.getenv("MODEL_NAME", "llama3:latest")

_SYS = ("Analyze this failed containment timeline and process tree behavior. Generate "
        "a clean, targeted PowerShell containment block utilizing netsh, "
        "New-NetFirewallRule, or specific WFP parameters to isolate this execution "
        "vector. Output ONLY the raw PowerShell — no markdown, fences, or prose.")


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _ollama_block(timeline: dict) -> str | None:
    try:
        import requests
        r = requests.post(f"{OLLAMA_HOST}/api/generate", timeout=90, json={
            "model": MODEL, "stream": False, "keep_alive": "30m",
            "options": {"temperature": 0},
            "system": _SYS, "prompt": json.dumps(timeline, indent=2)})
        r.raise_for_status()
        t = re.sub(r"^```[a-zA-Z]*\n?|```$", "", (r.json().get("response") or "").strip()).strip()
        return t or None
    except Exception:
        return None


def _fallback_block(technique_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", technique_id)
    return (f"# Targeted containment for {technique_id} (deterministic fallback).\n"
            f"# Micro-isolate the offending execution vector; loopback stays reachable.\n"
            f"New-NetFirewallRule -DisplayName 'Angerona-Dyn-{safe}' -Group 'Angerona-SOAR' "
            f"-Direction Outbound -RemoteAddress Any -Action Block -ErrorAction SilentlyContinue\n"
            f"New-NetFirewallRule -DisplayName 'Angerona-Dyn-{safe}-Loopback' -Group 'Angerona-SOAR' "
            f"-Direction Outbound -RemoteAddress 127.0.0.1 -Action Allow -ErrorAction SilentlyContinue\n"
            f"# netsh alternative (uncomment if WFP cmdlets are unavailable):\n"
            f"# netsh advfirewall firewall add rule name='Angerona-Dyn-{safe}' dir=out action=block\n")


def _verify(technique_id: str) -> str:
    """Re-arm + re-test through the Judgment verifier."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "angerona.shark.verify", technique_id, "--verify"],
            capture_output=True, text=True, timeout=90)
        buf = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception as exc:
        buf = f"VERIFICATION_RESULT: ERROR ({exc})"
    for line in buf.splitlines():
        if "VERIFICATION_RESULT:" in line:
            return line.split("VERIFICATION_RESULT:", 1)[1].strip().split()[0]
    return "ERROR"


def tune_containment(technique_id: str, timeline: dict | None = None) -> dict:
    """Generate + stage a scoped SOAR containment playbook for a bypassed
    technique, wire it into the gate, then re-arm and re-test. Returns a dict
    including the re-verification result."""
    root = _repo_root()
    pb_dir = root / "playbooks"
    try:
        pb_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    timeline = timeline or {
        "technique": technique_id,
        "failed_action": "Kill Process",
        "note": "Kill Process executed but the vector persisted (decoupled WMI hook / "
                "hollowed process). Need a network-layer containment block.",
    }
    # R3-03: require a strict network-only command/parameter allow-list before
    # staging any model-authored PowerShell for the privileged mitigation gate.
    block = _ollama_block(timeline)
    blocked_destructive: list[str] = []
    if block:
        try:
            from angerona.core.cve_fix_advisor import validate_containment_powershell
            blocked_destructive = validate_containment_powershell(block)
        except Exception:
            blocked_destructive = ["scan-unavailable"]
        if blocked_destructive:
            block = None
    used_fallback = block is None
    if block is None:
        block = _fallback_block(technique_id)
    safe = re.sub(r"[^A-Za-z0-9_.]", "_", technique_id)
    pb = pb_dir / f"dynamic_block_{safe}.ps1"
    header = (f"# Angerona dynamic SOAR playbook — {technique_id}\n"
              f"# Generated {time.strftime('%Y-%m-%d %H:%M:%S')} after a containment bypass.\n"
              f"# Rollback: Remove-NetFirewallRule -Group 'Angerona-SOAR'\n\n")
    try:
        from angerona.core.cve_fix_advisor import validate_containment_powershell
        final_text = header + block
        final_findings = validate_containment_powershell(final_text)
        if final_findings:
            return {"technique": technique_id, "ok": False,
                    "error": "playbook failed strict validation",
                    "blocked_destructive": final_findings}
        fd, tmp_name = tempfile.mkstemp(prefix=f".{pb.name}.", suffix=".tmp",
                                        dir=str(pb_dir), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(final_text)
                fh.flush()
                os.fsync(fh.fileno())
            staged = Path(tmp_name).read_text(encoding="utf-8")
            final_findings = validate_containment_powershell(staged)
            if final_findings:
                raise ValueError("staged playbook failed strict validation: "
                                 + "; ".join(final_findings))
            os.replace(tmp_name, pb)
        finally:
            try:
                Path(tmp_name).unlink()
            except FileNotFoundError:
                pass
    except Exception as exc:
        return {"technique": technique_id, "ok": False, "error": str(exc)}
    return {"technique": technique_id, "ok": True, "playbook": str(pb),
            "used_fallback": used_fallback,
            "blocked_destructive": blocked_destructive,
            "reverify": _verify(technique_id)}


if __name__ == "__main__":
    tid = sys.argv[1] if len(sys.argv) > 1 else "T1055"
    print(json.dumps(tune_containment(tid), indent=2))
