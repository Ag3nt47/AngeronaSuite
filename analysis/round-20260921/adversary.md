# Defensive adversarial review — 2026-09-21

Scope: the isolated `AngeronaSuite-module-review-20260921` worktree. Product source
was read only. Reproductions used in-memory objects without starting sensors,
running model requests, changing host controls, or touching runtime data. The
parent owns remediation, validation, and publication.

Two new LOW findings were reproduced against the initial reviewed tree. Neither
requires or demonstrates arbitrary code execution. Both defeat the operator's
expectation that a disabled capability stops consuming resources. Findings are
OPEN in this discovery report; the parent must record subsequent patch results.

`analysis/loop/state.json` records completed historical cycle34/round3. Its
`PRIOR_FINDINGS.md`, historical red-team reports, cycle34 round3 closure, and
cycle27 module shard reports were consulted. Historical round3 reports are not
overwritten by this separately scoped session report.

## R20260921-01 — Retained subscribers continue work after module disablement

- **Severity:** LOW
- **Status:** OPEN at discovery
- **Components:** `src/angerona/modules/network_protocol_decoder.py:206`;
  `src/angerona/modules/provenance_graph.py:521`;
  `src/angerona/modules/speculative_triage.py:96,105`;
  `src/angerona/modules/flight_cache.py:58,189`;
  `src/angerona/core/module_base.py:675`;
  `src/angerona/core/eventbus.py:265,301`.

### Description and impact

EventBus retains a subscribed bound method for the process lifetime.
`BaseModule.stop()` sets a stop event and status but does not unsubscribe.
NDRD, PROV and SPEC callbacks do not check that state: NDRD continues DNS scoring
and may emit observations, PROV continues graph ingestion, and SPEC continues
marker classification, cooldown updates and queue insertion while stopped.
SPEC's queue survives stop/start, so disablement-time markers remain eligible
for processing by later workers.

MEMC correctly closes its SQLite connection and prevents writes. However,
`FlightCache.put()` serializes `details` before checking `_closed`; retained
callbacks therefore continue paying serialization costs after disablement.
This is a smaller instance of the same missing callback admission gate.

The issue affects a module that has subscribed at least once and is then
disabled or paused; it does not prove never-started modules subscribe. State is
bounded in the reviewed DNS, graph and prewarm consumers. Existing central
subscription deduplication prevents duplicate callbacks after restart and is
credited. No host mutation or model call was performed by the reproduction.

### Exact inert reproduction

Run from the worktree with Python `-B` and `src` first on `sys.path`:

```python
import sys
sys.path.insert(0, "src")
from angerona.core.eventbus import EventBus, Event, Severity
from angerona.modules.network_protocol_decoder import NetworkProtocolDecoderModule
from angerona.modules.provenance_graph import ProvenanceGraphModule
from angerona.modules.speculative_triage import SpeculativeTriageModule

bus = EventBus()
ndrd = NetworkProtocolDecoderModule()
prov = ProvenanceGraphModule()
spec = SpeculativeTriageModule()
for mod in (ndrd, prov, spec):
    mod.bind(bus)
    # Equivalent to the subscription retained after the first normal run.
    bus.subscribe(mod._on_event)
    mod.stop()

bus.publish(Event(
    module="fixture", message="benign fixture", severity=Severity.INFO,
    details={"protocol": "dns", "qname": "www.example.com",
             "pid": 4242, "process_create_time": 1.0},
))
bus.publish(Event(
    module="fixture", message="Unknown process spawn", severity=Severity.INFO,
    details={"pid": 4243,
             "path": r"C:\Users\x\AppData\Local\Temp\a.exe"},
))
print({
    "all_stopped": all(m.stopping and m.status == "stopped"
                       for m in (ndrd, prov, spec)),
    "disabled_dns_seen": ndrd.stats()["dns_seen"],
    "disabled_graph_nodes": len(prov.graph.nodes),
    "disabled_prewarm_queue": spec._q.qsize(),
})
```

Observed: `all_stopped=True`, `disabled_dns_seen=1`,
`disabled_graph_nodes=3`, `disabled_prewarm_queue=1`.

### Recommendation and regression requirements

Check module running/stop state before callback parsing, serialization or queue
admission. Preserve the existing one-subscription rule. Make SPEC admission
generation-aware, or clear stale pending work during generation retirement, so
disabled-period work cannot leak into the next activation. A shared admission
helper is acceptable if it preserves the different standalone analysis APIs.

Regress: stopped callbacks produce zero counter/graph/queue changes; the running
generation still processes exactly one event; restart does not multiply delivery;
MEMC performs zero detail serialization after stop; SPEC cannot run a marker
accepted while disabled after re-enable. Include a bounded in-flight callback vs
stop race where practical. The patch applier owns these module edits.

## R20260921-02 — Staged startup revives an operator-disabled module

- **Severity:** LOW
- **Status:** OPEN at discovery
- **Component:** `src/angerona/core/module_manager.py:421-450,480-515`.

### Description and impact

`start_enabled()` snapshots enabled modules into critical/staged lists before
starting them. Subsequent `mod.start()` calls do not recheck registered object,
enabled policy or availability and do not hold `_module_control_lock`.
First-cycle waiting can make this interval lengthy. Disabling a queued module
during an earlier module's startup stops it and persists `False`, but the stale
startup list subsequently starts it anyway. The result is a running worker whose
manager reports it disabled. This can retain unwanted CPU use and activate a
previously selected optional capability contrary to an operator's current choice.

The ordinary `set_enabled()` and watchdog restart paths already use the manager
control lock and check policy. The defect is confined to stale staged startup;
the reproduction does not imply a remote attacker can change configuration.

### Exact inert reproduction

```python
import sys
sys.path.insert(0, "src")
from types import SimpleNamespace
from angerona.core.module_manager import ModuleManager
from angerona.core.module_base import BaseModule
from angerona.core.eventbus import EventBus

calls = []
config = SimpleNamespace(module_states={}, save=lambda: None)
mgr = ModuleManager(EventBus(), config, target_platform="windows")

class Fixture(BaseModule):
    def __init__(self, name):
        super().__init__()
        self.name = name
    def start(self):
        calls.append(("start", self.name))
        self.status = "running"
    def stop(self):
        calls.append(("stop", self.name))
        super().stop()
    def wait_for_first_cycle(self, timeout):
        if self.name == "fixture-first":
            mgr.set_enabled("fixture-second", False)
        return True

mgr.modules = {n: Fixture(n)
               for n in ("fixture-first", "fixture-second")}
mgr.start_enabled(min_settle=0)
print({"calls": calls,
       "second_enabled": mgr.is_enabled("fixture-second"),
       "second_status": mgr.modules["fixture-second"].status})
```

Observed calls: `start first`, `stop second`, `start second`;
`second_enabled=False`, `second_status='running'`.

### Recommendation and regression requirements

Immediately before each start, acquire the manager lifecycle lock, revalidate
the registered instance and current enabled/applicable policy, then start only
that admitted instance. Add a manager startup/shutdown generation so `stop_all()`
invalidates an already waiting startup sequence. Do not hold the manager lock
during first-cycle waits. Root owns this manager change together with machine
eligibility. Regress queued disablement, replacement, unavailable capability,
shutdown during a wait, and ordinary ordered startup.

## Coverage and limits

AST inventory and targeted security-pattern/lifecycle searches covered all **87
Python files** under `src/angerona/modules`, including **84 direct BaseModule
implementations**. This is inventory screening, not a claim of full manual review
of every line or a guarantee that every module is defect-free.

Manual context review focused on BaseModule lifecycle, ModuleManager discovery
and startup, platform availability, EventBus delivery, NDRD, PROV, SPEC, MEMC,
ELAT, Evolution, Dynamic Resource, Canary, Detection Runtime, Adversary Combat
admission, Purple Guard admission, SSH Surface Guard admission, Identity Session
Guard admission, Temporal Tradecraft admission, Remote Bridge receiving,
Forensics command construction, Shadow Shield identifiers, and driver/platform
PowerShell invocations. Safe source screening also covered package-wide dynamic
execution, deserialization and shell patterns.

Screened managed modules (file stems):

```text
adversary_combat, ai_model_integrity, ai_triage, amsi_bridge, api_patch_detector,
app_control_monitor, arp_watchdog, audit_log_guard, authentication_extension_guard,
av_telemetry_bridge, beacon_detector, behavioral_tuner, canary_drill, chaos_harness,
cloud_escalation, compliance_mapper, counter_agentic, daily_briefing, deception,
detection_runtime, driver_provenance_guard, dynamic_resource, ebpf_sensor,
etw_listener, etw_realtime_sensor, evidence_lattice, evolution_engine,
exposure_graph_guard, fast_path, file_integrity, fleet_health_monitor, flight_cache,
forensics, frz_heartbeat, hardware_crypto, hermetic_packager, identity_session_guard,
immutable_recovery_guard, intel_sync, ipc_guard, kernel_bridge, kernel_posture_ledger,
linux_observe, lsass_guard, macos_observe, mem_inject_scanner, memory_timemachine,
mobile_bridge, network_monitor, network_protocol_decoder, network_trust_monitor,
packet_sniffer, peripheral_dma_guard, persistence_sweep, platform_attestation_guard,
posture_hardening, process_egress_guard, process_monitor, provenance_graph,
purple_guard, rag_provenance_guard, ransomware_heuristics, release_transparency_guard,
remote_bridge, resource_governor, self_healer, self_integrity, shadow_shield,
shadowcopy_guard, siem_forwarder, smart_deception, soar, soar_engine,
speculative_triage, ssh_surface_guard, storage_hygiene, sys_bridge, sysmon_listener,
temporal_tradecraft_correlator, usb_monitor, watchdog_monitor, wfp_controller,
wlan_monitor, yara_scanner
```

The other three files are `__init__.py`, `packet_sniffer_worker.py`, and
`remediation_actions.py`. OS availability alone currently does not establish
hardware/integration applicability. That requested feature is owned by root;
temporary failure of a relevant sensor must remain visible as degraded coverage
instead of being silently reclassified as inapplicable.

## Prior controls rechecked

| Prior finding | Current code evidence | Disposition |
|---|---|---|
| A-01 autonomous generated Python | `engines/self_compiler.py:120-140` always stages/refuses hot loading, even after a clean denylist scan | Resolved for execution path |
| A-02 MCP wildcard CORS/no guard | `engines/mcp_server.py:77-98` retains loopback Host guard and optional bearer check; no wildcard CORS found | Existing mitigation remains; bearer is optional |
| A-05 forensics shell/PID interpolation | `modules/forensics.py:398-410` uses argv-list `netstat`, integer PID and Python filtering | Resolved |
| A-07 path SHA-1 | `modules/shadow_shield.py:95-96` uses SHA-256 | Resolved |
| A-04 admitted external code runs in-process | `core/module_manager.py:288-331` verifies manifest/digest/publisher and executes verified snapshot, still with process authority | Known architectural residual remains |
| A-06 broad ExecutionPolicy bypass | `modules/driver_provenance_guard.py:716-738` still invokes Bypass for a fixed read-only script using trusted PowerShell and a timeout | Known residual remains; no new injection claimed |

Prior controls verified resolved/mitigated: **4**. Prior findings verified still
open: **2**. Other historical findings were read for context but are not counted
as newly verified by this bounded pass.

| New finding severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 2 |
| INFO | 0 |

## Independent follow-up of selection and lifecycle patches

A bounded read-only follow-up reviewed `module_usage.py`, manager selection,
startup/shutdown generations, GUI/headless reconciliation, shared counters,
Eco wakeup admission, and the headless Chill controller. No new eligibility or
counting regression was confirmed: disabled/unsupported/unused optional
integrations are excluded, while failed/paused expected sensors remain visible.
Unknown kernel installation status does not suppress expected protection.

Two additional call sites exposed the same R20260921-02 authority defect:
headless Chill wake/maintenance directly started previously selected objects,
and console `module <name> restart` directly stopped/started disabled objects.
Both were sent immediately to root. Root routed Chill starts through the shared
manager admission helper during the review; an inert recheck then produced
`starts=0, enabled=False, status=stopped` for a disabled candidate. Before the
console fix, its inert reproduction returned `restarted` with
`starts=1, enabled=False, status=running`; root accepted that final remediation.
These are additional entry points for the existing LOW finding, not new
independently counted findings. Final regression results and console closure
remain the parent/bug-hunter validation responsibility. Callback patches were
outside this follow-up to avoid duplicating the patch agent's work.

Coordinating review closure: console restart now refuses disabled or
unconfigured modules and calls the same current-policy admission helper used
by GUI/headless wake and repair paths. The isolated console, stale staged
startup, replacement-object, shutdown and Eco-wake regressions pass in
`tests/test_machine_module_usage.py`. See `findings-after.json` and the round
README for final aggregate gates; the discovery findings above retain their
original before-patch status and evidence.
