# Prior findings (do NOT re-report unless still unfixed)

From the comprehensive security self-assessment (analysis/Angerona_Security_Assessment_v2.0). The red-team agent should VERIFY these against the current code, and only re-raise one if it is genuinely still exploitable.

| ID | Title | Component | Status |
|---|---|---|---|
| A-01 | Autonomous execution of AI-generated Python (syntax-check only) | engines/self_compiler.py, modules/evolution_engine.py | MITIGATED — off by default (`ANGERONA_SELF_EVOLVE`) + static denylist scan in `hot_reload_capability` |
| A-02 | MCP server: wildcard CORS + no auth | engines/mcp_server.py | MITIGATED — wildcard CORS removed; `_guard()` loopback-Host check + optional bearer token |
| A-03 | CVE fix advisor executes AI-generated PowerShell | core/cve_fix_advisor.py | MITIGATED — `scan_powershell` destructive denylist at analyze + apply |
| A-04 | External/drop-in extension execution boundary | core/module_manager.py, core/capability_manifest.py | OPEN architectural residual — external discovery is explicit opt-in and publisher/digest/manifest verified, and the verified byte snapshot executes; an admitted extension still runs in-process with the suite token, so a packaged administrator-owned root and stronger isolation remain relevant |
| A-05 | shell=True with interpolated PID in forensics | modules/forensics.py | MITIGATED — argv-list netstat + Python filter, no shell |
| A-06 | Broad `PowerShell -ExecutionPolicy Bypass` usage | engines/*, modules/* | OPEN — centralize/allowlist/log PowerShell execution |
| A-07 | SHA-1 used for a path identifier (non-security) | modules/shadow_shield.py | RESOLVED — path identifiers use SHA-256 consistently |
| R6-03 | Process-handle and executable-file lease across response mutation | modules/adversary_combat.py | OPEN defense-in-depth — process birth/executable state is revalidated, but the operating-system process handle and bounded executable-file identity lease are not retained through the complete path-wide action |

## Cycle 23 retained dependency

| ID | Title | Status |
|---|---|---|
| C23-R2-01 | Independent freshness for authenticated audit/network state | DEFERRED external dependency — the strict injected high-water contract and fail-visible behind/fork/clone/offline/migration/crash states are shipped, but no separately administered monotonic server or policy-bound hardware authority is bundled. Default state remains `local-authenticity-only`; do not promote the Personal Sentinel compact receipt, another same-host HMAC file, or an in-memory fixture to independent custody. |

## Cycle 34 retained boundaries

| ID | Title | Status |
|---|---|---|
| C34-EXT-01 | Independent anti-rollback witness for DetectionForge authority | DEFERRED external dependency — state, checkpoint, anchor, registry governance, receipt history, and transaction recovery are locally authenticated, but a privileged rollback of the complete detection root together with its local key can roll back all software witnesses. Independent service or hardware custody is required. |
| C34-MIG-01 | Ambiguous legacy detection-state migration | FAIL-CLOSED operational boundary — published-v2 and floorless-v3 histories migrate only when the complete authenticated transition chain, times, predecessors, receipt identities, head, and active set agree. Truncated or contradictory history requires operator recovery; do not add a permissive migration fallback. |
| C34-GOV-01 | Missing governance anchor compatibility | FAIL-CLOSED prepublication/WIP boundary — only a genuinely legacy manifest with no governance record can mint its first anchor. An already governed root whose anchor is missing is not silently treated as legacy and requires operator recovery. |
| C34-FLT-01 | Fleet Fabric deployment and retention boundary | OPEN architectural residual — Fleet remains a local lab with no remote transport, dispatch, HA, distributed quota authority, or production mTLS coordinator. Health custody retains at most 5,000 rows of at most 8 KiB each; after pruned-history restart, quota state begins conservatively and refills from elapsed trusted time. |

## Cycle 34 fixed publication-bound findings

| ID | Title | Status |
|---|---|---|
| C34-LEASE-01 | Promotion owner-lease alias, lifecycle, path, and fork bypass cluster | FIXED — the lifetime lease captures creator PID plus exact canonical registry/state/quality paths, governance configuration, policy, clock, transition capability, authority, and runtime identities. Checks run under the coordinator lock; POSIX children discard inherited descriptors without unlocking the parent. Exact sibling references remain supported, and the final bounded re-attack was clean. |

Recently added (already present — do not propose as "new"): core/alert_ack.py + threat-level exclusion, gui/resolve_center.py, gui/red_team_console.py (intensity/campaign/history), gui/incident_timeline_page.py, gui/attack_heatmap.py (Coverage/Top tabs), core/cve_ignore.py, core/cve_fix_advisor.py, core/ir_bundle.py, modules/daily_briefing.py, modules/lsass_guard/beacon_detector/shadowcopy_guard/usb_monitor.

Round 2 visionary addition (already present — do not re-propose):
`modules/evidence_lattice.py` (ELAT), entity-scoped fusion of MEDIUM evidence
across three modules and two sensor domains; local/EventBus-only and no response.

Round 3 visionary addition (already present — do not re-propose):
`core/telemetry_contracts.py` (TECT), a bounded deadline/echo validation engine,
integrated into `modules/canary_drill.py` with strict ETWG EID 4688 source
matching, late/missing outcomes, and no response or host action.

Cycle 23 additions (already present — do not re-propose):
`modules/audit_log_guard.py`, `modules/ssh_surface_guard.py`,
`modules/network_trust_monitor.py`, the Personal Sentinel pinned attestation
client, sanitized Live Defense Activity card, governed ARIA Defense Memory, and
the injected independent-high-water client/store contract. The actual Personal
Sentinel appliance/server/routing role, firmware attestation, and independent
monotonic authority remain proposal/deployment work rather than shipped code.
