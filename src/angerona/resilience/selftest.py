"""selftest.py — ecosystem self-test initiated by the Angerona core.

Proves the decoupled ecosystem is genuinely wired end-to-end, safely:

  1. Liveness — every component's shared-memory heartbeat is fresh (not frozen).
  2. Loop integrity — the core writes a ping nonce; the scanner echoes it back in
     its status diagnostic (proves core → scanner → BlackBox-diagnostics path).
  3. Resource limits — each component's reported RSS is within its budget.
  4. Dry-run resurrection — the respawn mechanism is exercised on a THROWAWAY
     component, so the self-healing path is proven WITHOUT crashing anything real.

Any failure is written to ``diagnostics/selftest_failures.json`` for the BlackBox.
Returns a structured report.
"""
from __future__ import annotations

import os
import sys
import time
from typing import Optional

from angerona.resilience import heartbeat as hb
from angerona.resilience import ipc_ring
from angerona.resilience import diagnostics as diag
from angerona.resilience.supervisor import ProcessSupervisor

_DEFAULT_RSS_BUDGET_MB = {"core": 400.0, "scanner": 80.0, "watchdog": 8.0}


def _ping_scanner(nonce: str, timeout: float) -> bool:
    ping = ipc_ring._data_dir() / "ipc" / "scanner.ping"
    try:
        ping.parent.mkdir(parents=True, exist_ok=True)
        ping.write_text(nonce, encoding="utf-8")
    except Exception:
        return False
    deadline = time.time() + timeout
    status = diag.diag_dir() / "status_scanner.json"
    while time.time() < deadline:
        try:
            import json
            data = json.loads(status.read_text(encoding="utf-8"))
            if data.get("last_ping") == nonce:
                return True
        except Exception:
            pass
        time.sleep(0.15)
    return False


def _dry_run_resurrection() -> bool:
    """Exercise the respawn path on a throwaway process — no real component is
    harmed. Spawns a quick-exit dummy, flags it dead, confirms a tick respawns it."""
    sup = ProcessSupervisor(poll_interval=0.1)
    c = sup.add("selftest_dummy", [sys.executable, "-c", "import time; time.sleep(2)"],
                stale_after_s=0.5, max_failures=99,
                running_probe=lambda: c.proc is not None and c.proc.poll() is None)
    sup._spawn(c)
    started_deadline = time.time() + 3.0
    while time.time() < started_deadline and not sup._is_running(c):
        time.sleep(0.05)
    before = c.restarts
    first = c.proc
    if first is not None:
        first.terminate()
        try:
            first.wait(timeout=2.0)
        except Exception:
            first.kill()
    c._dead = True
    deadline = time.time() + 3.0
    while time.time() < deadline:
        sup.tick(); time.sleep(0.05)
        if c.restarts > before:
            break
    ok = c.restarts > before
    sup.stop(terminate_children=True)
    return ok


def run_ecosystem_selftest(components: Optional[list[str]] = None, timeout: float = 5.0,
                           rss_budget_mb: Optional[dict] = None) -> dict:
    components = components or ["core", "scanner"]
    budget = {**_DEFAULT_RSS_BUDGET_MB, **(rss_budget_mb or {})}
    report: dict = {"ts": time.time(), "checks": {}, "failures": [], "passed": False}

    # 1. Liveness
    for name in components:
        state = hb.HeartbeatReader(name).classify(stale_after_s=3.0)
        report["checks"][f"liveness:{name}"] = state
        if state not in ("alive",):
            report["failures"].append(f"{name} not alive (state={state})")

    # 2. Loop integrity (only meaningful if the scanner is expected)
    if "scanner" in components:
        nonce = f"ping-{int(time.time()*1000)%100000}"
        loop_ok = _ping_scanner(nonce, timeout)
        report["checks"]["loop_integrity:scanner"] = loop_ok
        if not loop_ok:
            report["failures"].append("scanner did not echo ping nonce within timeout")

    # 3. Resource limits (best-effort; missing status is not a hard fail)
    for name in components:
        try:
            import json
            sp = diag.diag_dir() / f"status_{name}.json"
            data = json.loads(sp.read_text(encoding="utf-8"))
            rss = data.get("rss_mb")
            if rss is not None:
                report["checks"][f"rss_mb:{name}"] = rss
                if rss > budget.get(name, 1e9):
                    report["failures"].append(f"{name} RSS {rss}MB exceeds budget {budget.get(name)}MB")
        except Exception:
            report["checks"][f"rss_mb:{name}"] = "unavailable"

    # 4. Dry-run resurrection
    dr = _dry_run_resurrection()
    report["checks"]["dry_run_resurrection"] = dr
    if not dr:
        report["failures"].append("dry-run resurrection did not respawn the throwaway component")

    report["passed"] = not report["failures"]
    for f in report["failures"]:
        diag.record_selftest_failure("ecosystem_selftest", f, component="core")
    return report


def self_test() -> tuple[bool, str]:
    """Verify the self-test primitives themselves in isolation: the dry-run
    resurrection must succeed, and a ping to an absent scanner must fail cleanly
    (no exception)."""
    import tempfile, shutil
    prev = os.environ.get("ANGERONA_DATA")
    prev_diag = os.environ.get("ANGERONA_DIAG_DIR")
    workdir = tempfile.mkdtemp(prefix="est_selftest_")
    os.environ["ANGERONA_DATA"] = workdir
    os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")
    try:
        dr_ok = _dry_run_resurrection()
        # No scanner running → ping must return False without raising.
        ping_absent_ok = _ping_scanner("nobody", timeout=0.5) is False
        # A full run with no live components should report failures, not crash.
        rep = run_ecosystem_selftest(components=["core"], timeout=0.3)
        structured_ok = isinstance(rep, dict) and "checks" in rep and rep["passed"] is False
        ok = dr_ok and ping_absent_ok and structured_ok
        return ok, ("dry-run resurrection + absent-ping handling + structured report "
                    "verified" if ok else
                    f"failed: dry_run={dr_ok} ping_absent={ping_absent_ok} structured={structured_ok}")
    finally:
        for k, v in (("ANGERONA_DATA", prev), ("ANGERONA_DIAG_DIR", prev_diag)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
